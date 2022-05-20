// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequenttech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::context::{Ctx, Element};
use crate::elgamal::{Ciphertext, EncryptedPrivateKey, PrivateKey, PublicKey};
use crate::zkp::{ChaumPedersen, Schnorr};

use crate::util::Par;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

pub struct Keymaker<C: Ctx> {
    sk: PrivateKey<C>,
    pk: PublicKey<C>,
}

impl<C: Ctx> Keymaker<C> {
    pub fn gen(ctx: &C) -> Keymaker<C> {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        Keymaker { sk, pk }
    }

    pub fn from_sk(sk: PrivateKey<C>, ctx: &C) -> Keymaker<C> {
        let pk = PublicKey::from(&sk.public_value, ctx);

        Keymaker { sk, pk }
    }

    pub fn share(&self, label: &[u8]) -> (PublicKey<C>, Schnorr<C>) {
        let ctx = &self.sk.ctx;

        let pk = PublicKey::<C>::from(&self.pk.value, ctx);
        let proof = ctx.schnorr_prove(&self.sk.value, &pk.value, ctx.generator(), label);

        (pk, proof)
    }

    pub fn get_encrypted_sk(&self, symmetric: [u8; 32]) -> EncryptedPrivateKey {
        self.sk.to_encrypted(symmetric)
    }

    pub fn verify_share(ctx: &C, pk: &PublicKey<C>, proof: &Schnorr<C>, label: &[u8]) -> bool {
        ctx.schnorr_verify(&pk.value, ctx.generator(), proof, label)
    }

    pub fn combine_pks(ctx: &C, pks: Vec<PublicKey<C>>) -> PublicKey<C> {
        let mut acc: C::E = pks[0].value.clone();

        for pk in pks.iter().skip(1) {
            acc = acc.mul(&pk.value).modulo(&ctx.modulus());
        }

        PublicKey::<C>::from(&acc, ctx)
    }

    pub fn decryption_factor(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let ctx = &self.sk.ctx;
        let dec_factor = self.sk.decryption_factor(c);

        let proof = ctx.cp_prove(
            &self.sk.value,
            &self.pk.value,
            &dec_factor,
            None,
            &c.b,
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
            acc = acc.mul(dec).modulo(&ctx.modulus());
        }

        c.a.div(&acc, &ctx.modulus()).modulo(&ctx.modulus())
    }

    pub fn joint_dec_many(ctx: &C, decs: &[Vec<C::E>], cs: &[Ciphertext<C>]) -> Vec<C::E> {
        let modulus = ctx.modulus();
        let decrypted: Vec<C::E> = cs
            .par()
            .enumerate()
            .map(|(i, c)| {
                let mut acc: C::E = decs[0][i].clone();

                for dec in decs.iter().skip(1) {
                    acc = acc.mul(&dec[i]).modulo(&modulus);
                }
                c.a.div(&acc, &modulus).modulo(&modulus)
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

        let notok = (0..decs.len())
            .par()
            .map(|i| {
                ctx.cp_verify(
                    pk_value,
                    &decs[i],
                    None,
                    &ciphertexts[i].b,
                    &proofs[i],
                    label,
                )
            })
            .any(|x| !x);

        !notok
    }
}
