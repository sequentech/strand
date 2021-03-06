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
//! let ctx = BigintCtx::<P2048>::new();
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
        let values = [mhr].to_vec();
        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let context = ByteTree::Tree(tree);

        self.schnorr_prove_private(secret, gr, None, context)
    }

    pub fn encryption_popk_verify(
        &self,
        mhr: &C::E,
        gr: &C::E,
        proof: &Schnorr<C>,
        label: &[u8],
    ) -> bool {
        let values = [mhr].to_vec();
        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let context = ByteTree::Tree(tree);

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
        let values = [mhr].to_vec();
        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let context = ByteTree::Tree(tree);

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
        let values = [mhr].to_vec();
        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let context = ByteTree::Tree(tree);

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
        let context = ByteTree::Leaf(ByteBuf::from(label.to_vec()));
        self.schnorr_prove_private(secret, public, g, context)
    }

    pub fn schnorr_verify(
        &self,
        public: &C::E,
        g: Option<&C::E>,
        proof: &Schnorr<C>,
        label: &[u8],
    ) -> bool {
        let context = ByteTree::Leaf(ByteBuf::from(label.to_vec()));
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
        let context = ByteTree::Leaf(ByteBuf::from(label.to_vec()));
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
        let context = ByteTree::Leaf(ByteBuf::from(label.to_vec()));
        self.cp_verify_private(public1, public2, g1, g2, proof, context)
    }

    // FIXME optional generator (as is done in cp_prove)
    fn schnorr_prove_private(
        &self,
        secret: &C::X,
        public: &C::E,
        g: Option<&C::E>,
        context: ByteTree,
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

    // FIXME optional generator (as is done in cp_prove)
    fn schnorr_verify_private(
        &self,
        public: &C::E,
        g: Option<&C::E>,
        proof: &Schnorr<C>,
        context: ByteTree,
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

    fn schnorr_proof_challenge(
        &self,
        g: &C::E,
        public: &C::E,
        commitment: &C::E,
        context: ByteTree,
    ) -> C::X {
        let values = [g, public, commitment].to_vec();

        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(context);
        let bytes = ByteTree::Tree(tree).to_hashable_bytes();

        self.ctx.hash_to_exp(&bytes)
    }

    fn cp_prove_private(
        &self,
        secret: &C::X,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        context: ByteTree,
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
        context: ByteTree,
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

    fn cp_proof_challenge(
        &self,
        g1: &C::E,
        g2: &C::E,
        public1: &C::E,
        public2: &C::E,
        commitment1: &C::E,
        commitment2: &C::E,
        context: ByteTree,
    ) -> C::X {
        let values = [g1, g2, public1, public2, commitment1, commitment2].to_vec();

        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(context);
        let bytes = ByteTree::Tree(tree).to_hashable_bytes();

        self.ctx.hash_to_exp(&bytes)
    }
}

/// A proof of knowledge of discrete logarithm.
#[derive(Eq, PartialEq)]
pub struct Schnorr<C: Ctx> {
    pub(crate) commitment: C::E,
    pub(crate) challenge: C::X,
    pub(crate) response: C::X,
}

/// A proof of equality of discrete logarithms.
#[derive(Eq, PartialEq)]
pub struct ChaumPedersen<C: Ctx> {
    pub(crate) commitment1: C::E,
    pub(crate) commitment2: C::E,
    pub(crate) challenge: C::X,
    pub(crate) response: C::X,
}
