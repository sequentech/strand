#![allow(clippy::too_many_arguments)]
use crate::byte_tree::ByteTree;
use crate::byte_tree::ToByteTree;
use crate::context::{Ctx, Element, Exponent};
use serde_bytes::ByteBuf;

pub struct Zkp<C: Ctx> {
    pub(crate) ctx: C,
}

impl<C: Ctx> Zkp<C> {
    pub fn new(ctx: &C) -> Self {
        Zkp { ctx: ctx.clone() }
    }

    pub fn schnorr_prove(
        &self,
        secret: &C::X,
        public: &C::E,
        g: &C::E,
        label: &[u8],
    ) -> Schnorr<C> {
        let r = self.ctx.rnd_exp();
        let commitment = g.mod_pow(&r, self.ctx.modulus());
        let challenge: C::X = self.schnorr_proof_challenge(g, public, &commitment, label);
        let response = r.add(&challenge.mul(secret)).modulo(self.ctx.exp_modulus());

        Schnorr {
            commitment,
            challenge,
            response,
        }
    }

    pub fn schnorr_verify(
        &self,
        public: &C::E,
        g: &C::E,
        proof: &Schnorr<C>,
        label: &[u8],
    ) -> bool {
        let challenge_ = self.schnorr_proof_challenge(g, public, &proof.commitment, label);
        let ok1 = challenge_.eq(&proof.challenge);
        let lhs = g.mod_pow(&proof.response, self.ctx.modulus());
        let rhs = proof
            .commitment
            .mul(&public.mod_pow(&proof.challenge, self.ctx.modulus()))
            .modulo(self.ctx.modulus());
        let ok2 = lhs.eq(&rhs);
        ok1 && ok2
    }

    pub fn cp_prove(
        &self,
        secret: &C::X,
        public1: &C::E,
        public2: &C::E,
        g1: Option<&C::E>,
        g2: &C::E,
        label: &[u8],
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
            label,
        );
        let response = r.add(&challenge.mul(secret)).modulo(self.ctx.exp_modulus());

        ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
        }
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
        let challenge_ = self.cp_proof_challenge(
            g1.unwrap_or_else(|| self.ctx.generator()),
            g2,
            public1,
            public2,
            &proof.commitment1,
            &proof.commitment2,
            label,
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
        label: &[u8],
    ) -> C::X {
        let values = [g, public, commitment].to_vec();

        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let bytes = ByteTree::Tree(tree).to_hashable_bytes();

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
        label: &[u8],
    ) -> C::X {
        let values = [g1, g2, public1, public2, commitment1, commitment2].to_vec();

        let mut tree: Vec<ByteTree> = values.iter().map(|e| e.to_byte_tree()).collect();
        tree.push(ByteTree::Leaf(ByteBuf::from(label.to_vec())));
        let bytes = ByteTree::Tree(tree).to_hashable_bytes();

        self.ctx.hash_to_exp(&bytes)
    }
}

#[derive(Eq, PartialEq)]
pub struct Schnorr<C: Ctx> {
    pub(crate) commitment: C::E,
    pub(crate) challenge: C::X,
    pub(crate) response: C::X,
}

#[derive(Eq, PartialEq)]
pub struct ChaumPedersen<C: Ctx> {
    pub(crate) commitment1: C::E,
    pub(crate) commitment2: C::E,
    pub(crate) challenge: C::X,
    pub(crate) response: C::X,
}
