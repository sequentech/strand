#![allow(dead_code)]

// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

// use generic_array::{typenum::U32, GenericArray};
// use rayon::prelude::*;

use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::Ciphertext;
use crate::zkp::{ChaumPedersen, Zkp};
use crate::threshold;

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
        let mut shares = vec![];
        let external_shares = vec![C::X::mul_identity(); num_trustees];
        let v_key_factors = vec![];

        let (coefficients, commitments) = threshold::gen_coefficients(threshold, ctx);

        for i in 0..num_trustees {
            // i + 1: trustees start at 1
            let share = threshold::eval_poly(i + 1, threshold, &coefficients, ctx);
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

    fn add_external_share(
        &mut self,
        source: usize,
        share: C::X,
        commitments: &[C::E],
        self_position: usize,
    ) -> bool {
        let vkf =
            threshold::verification_key_factor(commitments, self.threshold, self_position, &self.ctx);
        let check = self.ctx.gmod_pow(&share);
        let ok = check == vkf;
        if ok {
            self.external_shares[source] = share;
            self.v_key_factors.push(vkf);
        }
        ok
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

}

#[cfg(any(test, feature = "wasmtest"))]
pub(crate) mod tests {
    use crate::context::{Ctx, Element};
    use crate::elgamal::{Ciphertext, PublicKey};
    use crate::threshold_test::*;
    use crate::threshold;

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

        let all = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let present = &all[0..threshold];
        let mut divider = C::E::mul_identity();

        for i in 0..present.len() {
            let v_key = trustees[present[i] - 1].verification_key();
            let (base, proof) = trustees[present[i] - 1].decryption_factor(&c, &[]);
            let ok = zkp.verify_decryption(&v_key, &base, &c.mhr, &c.gr, &proof, &vec![]);
            assert!(ok);

            let lagrange = threshold::lagrange(present[i], &present, ctx);

            let next = base.mod_pow(&lagrange, &ctx.modulus());
            divider = divider.mul(&next).modulo(&ctx.modulus())
        }

        let decrypted = c.mhr.div(&divider, &ctx.modulus()).modulo(&ctx.modulus());
        let decoded = ctx.decode(&decrypted);

        assert_eq!(data, decoded);

        let present = &all[0..threshold - 1];
        let mut divider = C::E::mul_identity();

        for i in 0..present.len() {
            let v_key = trustees[present[i] - 1].verification_key();
            let (base, proof) = trustees[present[i] - 1].decryption_factor(&c, &[]);
            let ok = zkp.verify_decryption(&v_key, &base, &c.mhr, &c.gr, &proof, &vec![]);
            assert!(ok);

            let lagrange = threshold::lagrange(present[i], &present, ctx);

            let next = base.mod_pow(&lagrange, &ctx.modulus());
            divider = divider.mul(&next).modulo(&ctx.modulus())
        }

        let decrypted = c.mhr.div(&divider, &ctx.modulus()).modulo(&ctx.modulus());
        let decoded = ctx.decode(&decrypted);

        assert_ne!(data, decoded);
    }
}
