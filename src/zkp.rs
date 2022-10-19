// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
//! # Examples
//!
//! ```
//! // This example shows how to construct and verify proofs.
//! use strand::context::{Ctx, Element};
//! use strand::backend::num_bigint::{BigintCtx, P2048};
//! use strand::elgamal::{PrivateKey, PublicKey};
//! use strand::zkp::Zkp;
//!
//! let ctx = BigintCtx::<P2048>::default();
//! let zkp = Zkp::new(&ctx);
//! let exponent = ctx.rnd_exp();
//! let g = ctx.generator();
//! let power = ctx.gmod_pow(&exponent);
//! // prove knowledge of discrete logarithm
//! let proof = zkp.schnorr_prove(&exponent, &power, Some(&g), &vec![]);
//! let verified = zkp.schnorr_verify(&power, Some(&g), &proof, &vec![]);
//! assert!(verified);
//! // prove equality of discrete logarithms, using default generator (None)
//! let g2 = ctx.rnd();
//! let power2 = g2.mod_pow(&exponent, &ctx.modulus());
//! let proof = zkp.cp_prove(&exponent, &power, &power2, None, &g2, &vec![]);
//! let verified = zkp.cp_verify(&power, &power2, None, &g2, &proof, &vec![]);
//! assert!(verified);
//! ```
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;

use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use serde_bytes::ByteBuf;

use crate::byte_tree::ByteTree;
use crate::byte_tree::ToByteTree;
use crate::context::{Ctx, Element, Exponent};

/// Interface to zero knowledge proof functionality.
pub struct Zkp<C: Ctx> {
    pub(crate) ctx: C,
}

impl<C: Ctx> Zkp<C> {
    pub fn new(ctx: &C) -> Self {
        Zkp { ctx: ctx.clone() }
    }

    pub fn encryption_popk(
        &self,
        secret: &C::X,
        mhr: &C::E,
        gr: &C::E,
        label: &[u8],
    ) -> Schnorr<C> {
        let mut context = ChallengeInput::from(&[("mhr", &mhr)]);
        context.add("label", &label.to_vec());

        self.schnorr_prove_private(secret, gr, None, context)
    }

    pub fn encryption_popk_verify(
        &self,
        mhr: &C::E,
        gr: &C::E,
        proof: &Schnorr<C>,
        label: &[u8],
    ) -> bool {
        let mut context = ChallengeInput::from(&[("mhr", &mhr)]);
        context.add("label", &label.to_vec());

        self.schnorr_verify_private(gr, None, proof, context)
    }

    pub fn decryption_proof(
        &self,
        secret: &C::X,
        pk: &C::E,
        dec_factor: &C::E,
        mhr: &C::E,
        gr: &C::E,
        label: &[u8],
    ) -> ChaumPedersen<C> {
        let mut context = ChallengeInput::from(&[("mhr", &mhr)]);
        context.add("label", &label.to_vec());

        self.cp_prove_private(secret, pk, dec_factor, None, gr, context)
    }

    pub fn verify_decryption(
        &self,
        pk: &C::E,
        dec_factor: &C::E,
        mhr: &C::E,
        gr: &C::E,
        proof: &ChaumPedersen<C>,
        label: &[u8],
    ) -> bool {
        let mut context = ChallengeInput::from(&[("mhr", &mhr)]);
        context.add("label", &label.to_vec());

        self.cp_verify_private(pk, dec_factor, None, gr, proof, context)
    }

    /// Prove knowledge of discrete logarithm.
    pub fn schnorr_prove(
        &self,
        secret: &C::X,
        public: &C::E,
        g: Option<&C::E>,
        label: &[u8],
    ) -> Schnorr<C> {
        let context = ChallengeInput::from(&[("label", &label.to_vec())]);
        self.schnorr_prove_private(secret, public, g, context)
    }

    pub fn schnorr_verify(
        &self,
        public: &C::E,
        g: Option<&C::E>,
        proof: &Schnorr<C>,
        label: &[u8],
    ) -> bool {
        let context = ChallengeInput::from(&[("label", &label.to_vec())]);
        self.schnorr_verify_private(public, g, proof, context)
    }

    /// Prove equality (and knowledge) of discrete logarithms with respect to two bases.
    pub fn cp_prove(
        &self,
        secret: &C::X,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        label: &[u8],
    ) -> ChaumPedersen<C> {
        let context = ChallengeInput::from(&[("label", &label.to_vec())]);
        self.cp_prove_private(secret, public1, public2, g1, g2, context)
    }

    pub fn cp_verify(
        &self,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        proof: &ChaumPedersen<C>,
        label: &[u8],
    ) -> bool {
        let context = ChallengeInput::from(&[("label", &label.to_vec())]);
        self.cp_verify_private(public1, public2, g1, g2, proof, context)
    }

    fn schnorr_prove_private(
        &self,
        secret: &C::X,
        public: &C::E,
        g: Option<&C::E>,
        context: ChallengeInput,
    ) -> Schnorr<C> {
        let r = self.ctx.rnd_exp();
        let commitment = if let Some(g) = g {
            g.mod_pow(&r, self.ctx.modulus())
        } else {
            self.ctx.gmod_pow(&r)
        };
        let challenge: C::X = self.schnorr_proof_challenge(
            g.unwrap_or_else(|| self.ctx.generator()),
            public,
            &commitment,
            context,
        );
        let response = r.add(&challenge.mul(secret)).modulo(self.ctx.exp_modulus());

        Schnorr {
            commitment,
            challenge,
            response,
        }
    }

    fn schnorr_verify_private(
        &self,
        public: &C::E,
        g: Option<&C::E>,
        proof: &Schnorr<C>,
        context: ChallengeInput,
    ) -> bool {
        let challenge_ = self.schnorr_proof_challenge(
            g.unwrap_or_else(|| self.ctx.generator()),
            public,
            &proof.commitment,
            context,
        );
        let ok1 = challenge_.eq(&proof.challenge);
        let lhs = if let Some(g) = g {
            g.mod_pow(&proof.response, self.ctx.modulus())
        } else {
            self.ctx.gmod_pow(&proof.response)
        };
        let rhs = proof
            .commitment
            .mul(&public.mod_pow(&proof.challenge, self.ctx.modulus()))
            .modulo(self.ctx.modulus());
        let ok2 = lhs.eq(&rhs);
        ok1 && ok2
    }

    fn cp_prove_private(
        &self,
        secret: &C::X,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        context: ChallengeInput,
    ) -> ChaumPedersen<C> {
        let r = self.ctx.rnd_exp();
        let commitment1 = if let Some(g1) = g1 {
            g1.mod_pow(&r, self.ctx.modulus())
        } else {
            self.ctx.gmod_pow(&r)
        };
        let commitment2 = g2.mod_pow(&r, self.ctx.modulus());
        let challenge: C::X = self.cp_proof_challenge(
            g1.unwrap_or_else(|| self.ctx.generator()),
            g2,
            public1,
            public2,
            &commitment1,
            &commitment2,
            context,
        );
        let response = r.add(&challenge.mul(secret)).modulo(self.ctx.exp_modulus());

        ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
        }
    }

    fn cp_verify_private(
        &self,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        proof: &ChaumPedersen<C>,
        context: ChallengeInput,
    ) -> bool {
        let challenge_ = self.cp_proof_challenge(
            g1.unwrap_or_else(|| self.ctx.generator()),
            g2,
            public1,
            public2,
            &proof.commitment1,
            &proof.commitment2,
            context,
        );
        let ok1 = challenge_.eq(&proof.challenge);

        let lhs1 = if let Some(g1) = g1 {
            g1.mod_pow(&proof.response, self.ctx.modulus())
        } else {
            self.ctx.gmod_pow(&proof.response)
        };
        let rhs1 = proof
            .commitment1
            .mul(&public1.mod_pow(&proof.challenge, self.ctx.modulus()))
            .modulo(self.ctx.modulus());
        let lhs2 = g2.mod_pow(&proof.response, self.ctx.modulus());
        let rhs2 = proof
            .commitment2
            .mul(&public2.mod_pow(&proof.challenge, self.ctx.modulus()))
            .modulo(self.ctx.modulus());
        let ok2 = lhs1.eq(&rhs1);
        let ok3 = lhs2.eq(&rhs2);

        ok1 && ok2 && ok3
    }

    fn schnorr_proof_challenge(
        &self,
        g: &C::E,
        public: &C::E,
        commitment: &C::E,
        context: ChallengeInput,
    ) -> C::X {
        let mut values =
            ChallengeInput::from(&[("g", g), ("public", public), ("commitment", commitment)]);
        values.add("context", &context);

        let bytes = values.try_to_vec().unwrap();
        self.ctx.hash_to_exp(&bytes)
    }

    fn cp_proof_challenge(
        &self,
        g1: &C::E,
        g2: &C::E,
        public1: &C::E,
        public2: &C::E,
        commitment1: &C::E,
        commitment2: &C::E,
        context: ChallengeInput,
    ) -> C::X {
        let mut values = ChallengeInput::from(&[
            ("g1", g1),
            ("g2", g2),
            ("public1", public1),
            ("public2", public2),
            ("commitment1", commitment1),
            ("commitment2", commitment2),
        ]);
        values.add("context", &context);

        let bytes = values.try_to_vec().unwrap();
        self.ctx.hash_to_exp(&bytes)
    }
}

/// A proof of knowledge of discrete logarithm.
#[derive(Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Schnorr<C: Ctx> {
    pub commitment: C::E,
    pub challenge: C::X,
    pub response: C::X,
}

/// A proof of equality of discrete logarithms.
#[derive(Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChaumPedersen<C: Ctx> {
    pub commitment1: C::E,
    pub commitment2: C::E,
    pub challenge: C::X,
    pub response: C::X,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct ChallengeInput(HashMap<String, Vec<u8>>);
impl ChallengeInput {
    pub(crate) fn from<T: BorshSerialize>(values: &[(&'static str, &T)]) -> ChallengeInput {
        let serialized = values
            .iter()
            .map(|value| (value.0.to_string(), value.1.try_to_vec().unwrap()));

        let map = HashMap::from_iter(serialized);

        ChallengeInput(map)
    }

    pub(crate) fn from_bytes(values: &[(&'static str, Vec<u8>)]) -> ChallengeInput {
        let serialized = values
            .iter()
            .map(|value| (value.0.to_string(), value.1.clone()));

        let map = HashMap::from_iter(serialized);

        ChallengeInput(map)
    }

    pub(crate) fn add<T: BorshSerialize>(&mut self, name: &'static str, value: &T) {
        let bytes = value.try_to_vec().unwrap();
        self.0.insert(name.to_string(), bytes);
    }

    pub(crate) fn get_bytes(&self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }
}
