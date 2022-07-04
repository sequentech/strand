#![allow(dead_code)]

// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

// use generic_array::{typenum::U32, GenericArray};
// use rayon::prelude::*;

use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::Ciphertext;
use crate::zkp::{ChaumPedersen, Zkp};

pub struct KeymakerT<C: Ctx> {
    num_trustees: usize,
    threshold: usize,
    coefficients: Vec<C::X>,
    commitments: Vec<C::E>,
    shares: Vec<C::X>,
    external_shares: Vec<C::X>,
    v_key_factors: Vec<C::E>,
    ctx: C,
}

impl<C: Ctx> KeymakerT<C> {
    pub fn gen(num_trustees: usize, threshold: usize, ctx: &C) -> KeymakerT<C> {
        let mut coefficients = vec![];
        let mut commitments = vec![];
        let mut shares = vec![];
        let external_shares = vec![C::X::mul_identity(); num_trustees];
        let v_key_factors = vec![];

        // a degree n polynomial is determined by n + 1 points
        // a degree n polynomial has n + 1 coefficients
        // thus, the number of coefficients = threshold
        for _ in 0..threshold {
            let coeff = ctx.rnd_exp();
            let commitment = ctx.gmod_pow(&coeff);
            coefficients.push(coeff);
            commitments.push(commitment);
        }
        for i in 0..num_trustees {
            // i + 1: trustees start at 1
            let share = Self::eval_poly(i + 1, threshold, &coefficients, ctx);
            shares.push(share);
        }

        KeymakerT {
            num_trustees,
            threshold,
            coefficients,
            commitments,
            shares,
            external_shares,
            v_key_factors,
            ctx: (*ctx).clone(),
        }
    }

    fn eval_poly(trustee: usize, threshold: usize, coefficients: &[C::X], ctx: &C) -> C::X {
        let mut sum = coefficients[0].clone();
        let mut power = C::X::mul_identity();
        let trustee_exp = ctx.exp_from_u64(trustee as u64);

        for coefficient in coefficients.iter().take(threshold).skip(1) {
            power = power.mul(&trustee_exp).modulo(ctx.exp_modulus());
            sum = sum.add(&coefficient.mul(&power).modulo(ctx.exp_modulus()));
        }
        sum.modulo(ctx.exp_modulus())
    }

    fn add_external_share(
        &mut self,
        source: usize,
        share: C::X,
        commitments: &[C::E],
        self_position: usize,
    ) -> bool {
        let vkf =
            Self::verification_key_factor(commitments, self.threshold, self_position, &self.ctx);
        let check = self.ctx.gmod_pow(&share);
        let ok = check == vkf;
        if ok {
            self.external_shares[source] = share;
            self.v_key_factors.push(vkf);
        }
        ok
    }

    fn verification_key_factor(
        sender_commitments: &[C::E],
        threshold: usize,
        receiver_trustee: usize,
        ctx: &C,
    ) -> C::E {
        let mut accum = C::E::mul_identity();
        // trustees start at 1
        let t = receiver_trustee + 1;
        for (i, commitment) in sender_commitments.iter().enumerate().take(threshold) {
            let power = t.pow(i as u32);
            let power_element = ctx.exp_from_u64(power as u64);

            accum = accum
                .mul(&commitment.mod_pow(&power_element, ctx.modulus()))
                .modulo(ctx.modulus());
        }

        accum
    }

    fn secret_share(&self) -> C::X {
        let mut sum = C::X::add_identity();
        for i in 0..self.num_trustees {
            sum = sum.add(&self.external_shares[i]);
        }

        sum.modulo(self.ctx.exp_modulus())
    }

    fn decryption_factor(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let zkp = Zkp::new(&self.ctx);
        let share = self.secret_share();
        let v_key = self.verification_key();
        let factor = c.gr.mod_pow(&share, self.ctx.modulus());
        let proof = zkp.decryption_proof(&share, &v_key, &factor, &c.mhr, &c.gr, label);
        // let ok = zkp.decryption_verify(&v_key, &factor, None, &c.mhr, &c.gr, &proof, label);
        // assert!(ok);
        (factor, proof)
    }

    fn verification_key(&self) -> C::E {
        assert_eq!(self.v_key_factors.len(), self.num_trustees);
        let mut key = C::E::mul_identity();
        for next in &self.v_key_factors {
            key = key.mul(next).modulo(self.ctx.modulus());
        }

        key
    }

    pub fn lagrange(trustee: usize, present: &[usize], ctx: &C) -> C::X {
        let mut numerator = C::X::mul_identity();
        let mut denominator = C::X::mul_identity();
        let trustee_exp = ctx.exp_from_u64(trustee as u64);

        for p in present {
            if *p == trustee {
                continue;
            }
            let present_exp = ctx.exp_from_u64(*p as u64);
            // we add exp_modulus to avoid calculating a modulus with negative numbers
            // which can be implementation specific (also, the num_bigint backend does not support it)
            let diff_exp = present_exp
                .add(ctx.exp_modulus())
                .sub(&trustee_exp)
                .modulo(ctx.exp_modulus());

            numerator = numerator.mul(&present_exp).modulo(ctx.exp_modulus());
            denominator = denominator.mul(&diff_exp).modulo(ctx.exp_modulus());
        }

        numerator.div(&denominator, ctx.exp_modulus())
    }
}

#[cfg(any(test, feature = "wasmtest"))]
pub(crate) mod tests {
    use crate::context::{Ctx, Element};
    use crate::elgamal::{Ciphertext, PublicKey};
    use crate::threshold::*;

    pub(crate) fn test_threshold_generic<C: Ctx>(
        ctx: &C,
        num_trustees: usize,
        threshold: usize,
        data: C::P,
    ) {
        let zkp = Zkp::new(ctx);
        let mut pk = C::E::mul_identity();
        let mut trustees = Vec::new();
        for _ in 0..num_trustees {
            let trustee = KeymakerT::gen(num_trustees, threshold, ctx);
            pk = pk.mul(&trustee.commitments[0]).modulo(&ctx.modulus());
            trustees.push(trustee);
        }

        // distribute shares, including to ourselves
        for i in 0..num_trustees as usize {
            for j in 0..num_trustees as usize {
                let share = trustees[i].shares[j].clone();
                let commitments = trustees[i].commitments.clone();
                let ok = trustees[j].add_external_share(i, share, &commitments, j);
                assert!(ok);
            }
        }

        let pk = PublicKey::from_element(&pk, ctx);
        let plaintext = ctx.encode(&data).unwrap();

        let c: Ciphertext<C> = pk.encrypt(&plaintext);
        // sanity check: all trustees present for decryption works
        let mut divider = C::E::mul_identity();
        for i in 0..num_trustees {
            divider = divider
                .mul(&c.gr.mod_pow(&trustees[i].coefficients[0], &ctx.modulus()))
                .modulo(&ctx.modulus());
        }
        let decrypted = c.mhr.div(&divider, &ctx.modulus()).modulo(&ctx.modulus());
        let decoded = ctx.decode(&decrypted);

        assert_eq!(data, decoded);

        let present = vec![1, 4, 5];
        let mut divider = C::E::mul_identity();

        for i in 0..present.len() {
            let v_key = trustees[present[i] - 1].verification_key();
            let (base, proof) = trustees[present[i] - 1].decryption_factor(&c, &[]);
            let ok = zkp.verify_decryption(&v_key, &base, &c.mhr, &c.gr, &proof, &vec![]);
            assert!(ok);

            let lagrange = KeymakerT::lagrange(present[i], &present, ctx);

            let next = base.mod_pow(&lagrange, &ctx.modulus());
            divider = divider.mul(&next).modulo(&ctx.modulus())
        }

        let decrypted = c.mhr.div(&divider, &ctx.modulus()).modulo(&ctx.modulus());
        let decoded = ctx.decode(&decrypted);

        assert_eq!(data, decoded);

        let present = vec![1, 4];
        let mut divider = C::E::mul_identity();

        for i in 0..present.len() {
            let v_key = trustees[present[i] - 1].verification_key();
            let (base, proof) = trustees[present[i] - 1].decryption_factor(&c, &[]);
            let ok = zkp.verify_decryption(&v_key, &base, &c.mhr, &c.gr, &proof, &vec![]);
            assert!(ok);

            let lagrange = KeymakerT::lagrange(present[i], &present, ctx);

            let next = base.mod_pow(&lagrange, &ctx.modulus());
            divider = divider.mul(&next).modulo(&ctx.modulus())
        }

        let decrypted = c.mhr.div(&divider, &ctx.modulus()).modulo(&ctx.modulus());
        let decoded = ctx.decode(&decrypted);

        assert_ne!(data, decoded);
    }
}
