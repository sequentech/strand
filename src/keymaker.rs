// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "rayon")]
use rayon::prelude::*;

use crate::context::{Ctx, Element};
use crate::elgamal::{Ciphertext, PrivateKey, PublicKey};
use crate::util::Par;
use crate::zkp::{ChaumPedersen, Schnorr, Zkp};

pub struct Keymaker<C: Ctx> {
    sk: PrivateKey<C>,
    pk: PublicKey<C>,
    ctx: C,
}

impl<C: Ctx> Keymaker<C> {
    pub fn gen(ctx: &C) -> Keymaker<C> {
        let sk = PrivateKey::gen(ctx);
        let pk = PublicKey::from_element(&sk.pk_element, ctx);

        Keymaker {
            sk,
            pk,
            ctx: (*ctx).clone(),
        }
    }

    pub fn from_sk(sk: PrivateKey<C>, ctx: &C) -> Keymaker<C> {
        let pk = PublicKey::from_element(&sk.pk_element, ctx);

        Keymaker {
            sk,
            pk,
            ctx: (*ctx).clone(),
        }
    }

    pub fn share(&self, label: &[u8]) -> (PublicKey<C>, Schnorr<C>) {
        let zkp = Zkp::new(&self.ctx);
        let pk = PublicKey::from_element(&self.pk.element, &self.ctx);
        let proof = zkp.schnorr_prove(&self.sk.value, &pk.element, None, label);

        (pk, proof)
    }

    pub fn verify_share(ctx: &C, pk: &PublicKey<C>, proof: &Schnorr<C>, label: &[u8]) -> bool {
        let zkp = Zkp::new(ctx);
        zkp.schnorr_verify(&pk.element, None, proof, label)
    }

    pub fn combine_pks(ctx: &C, pks: Vec<PublicKey<C>>) -> PublicKey<C> {
        let mut acc: C::E = pks[0].element.clone();

        for pk in pks.iter().skip(1) {
            acc = acc.mul(&pk.element).modulo(ctx.modulus());
        }

        PublicKey::from_element(&acc, ctx)
    }

    pub fn decryption_factor(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let dec_factor = self.sk.decryption_factor(c);
        let zkp = Zkp::new(&self.ctx);
        let proof = zkp.decryption_proof(
            &self.sk.value,
            &self.pk.element,
            &dec_factor,
            &c.mhr,
            &c.gr,
            label,
        );

        (dec_factor, proof)
    }

    pub fn decryption_factor_many(
        &self,
        cs: &[Ciphertext<C>],
        label: &[u8],
    ) -> (Vec<C::E>, Vec<ChaumPedersen<C>>) {
        let decs_proofs: (Vec<C::E>, Vec<ChaumPedersen<C>>) =
            cs.par().map(|c| self.decryption_factor(c, label)).unzip();

        decs_proofs
    }

    pub fn joint_dec(ctx: &C, decs: Vec<C::E>, c: &Ciphertext<C>) -> C::E {
        let mut acc: C::E = decs[0].clone();
        for dec in decs.iter().skip(1) {
            acc = acc.mul(dec).modulo(ctx.modulus());
        }

        c.mhr.div(&acc, ctx.modulus()).modulo(ctx.modulus())
    }

    pub fn joint_dec_many(ctx: &C, decs: &[Vec<C::E>], cs: &[Ciphertext<C>]) -> Vec<C::E> {
        let modulus = ctx.modulus();
        let decrypted: Vec<C::E> = cs
            .par()
            .enumerate()
            .map(|(i, c)| {
                let mut acc: C::E = decs[0][i].clone();

                for dec in decs.iter().skip(1) {
                    acc = acc.mul(&dec[i]).modulo(modulus);
                }
                c.mhr.div(&acc, modulus).modulo(modulus)
            })
            .collect();

        decrypted
    }

    pub fn verify_decryption_factors(
        ctx: &C,
        pk_value: &C::E,
        ciphertexts: &[Ciphertext<C>],
        decs: &[C::E],
        proofs: &[ChaumPedersen<C>],
        label: &[u8],
    ) -> bool {
        assert_eq!(decs.len(), proofs.len());
        assert_eq!(decs.len(), ciphertexts.len());
        let zkp = Zkp::new(ctx);

        let notok = (0..decs.len())
            .par()
            .map(|i| {
                zkp.verify_decryption(
                    pk_value,
                    &decs[i],
                    &ciphertexts[i].mhr,
                    &ciphertexts[i].gr,
                    &proofs[i],
                    label,
                )
            })
            .any(|x| !x);

        !notok
    }
}
