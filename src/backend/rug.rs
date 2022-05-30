// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only
use ed25519_dalek::{Digest, Sha512};
use rand::RngCore;
use rug::{
    integer::Order,
    rand::{RandGen, RandState},
    Complete, Integer,
};
use serde_bytes::ByteBuf;

use crate::backend::{P_STR_2048, Q_STR_2048};
use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::PrivateKey;
use crate::rnd::StrandRng;
use crate::zkp::ZKProver;

impl Element<RugCtx> for Integer {
    fn mul(&self, other: &Self) -> Self {
        Integer::from(self * other)
    }
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::inv(other, modulus);
        self * inverse
    }
    fn inv(&self, modulus: &Self) -> Self {
        self.clone().invert(modulus).unwrap()
    }
    fn mod_pow(&self, other: &Integer, modulus: &Self) -> Self {
        let ret = self.clone().pow_mod(other, modulus);

        ret.unwrap()
    }
    fn modulo(&self, modulus: &Self) -> Self {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());
        if rem < 0 {
            rem += modulus;
        }

        rem
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }
}

impl Exponent<RugCtx> for Integer {
    fn add(&self, other: &Integer) -> Integer {
        Integer::from(self + other)
    }
    fn sub(&self, other: &Integer) -> Integer {
        Integer::from(self - other)
    }
    fn mul(&self, other: &Integer) -> Integer {
        Integer::from(self * other)
    }
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = other.clone().invert(modulus).unwrap();
        self * inverse
    }
    fn inv(&self, modulus: &Integer) -> Integer {
        self.clone().invert(modulus).unwrap()
    }
    fn modulo(&self, modulus: &Integer) -> Integer {
        let (_, mut rem) = self.clone().div_rem(modulus.clone());

        if rem < 0 {
            rem += modulus;
        }

        rem
    }

    fn add_identity() -> Integer {
        Integer::from(0)
    }
    fn mul_identity() -> Integer {
        Integer::from(1)
    }

    fn to_string(&self) -> String {
        self.to_string_radix(16)
    }
}

struct StrandRandgen(StrandRng);

impl RandGen for StrandRandgen {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RugCtx {
    pub generator: Integer,
    pub modulus: Integer,
    pub modulus_exp: Integer,
    pub co_factor: Integer,
}

impl RugCtx {
    pub fn default() -> RugCtx {
        let p = Integer::from_str_radix(P_STR_2048, 16).unwrap();
        let q = Integer::from_str_radix(Q_STR_2048, 16).unwrap();
        let g = Integer::from(3);
        let co_factor = Integer::from(2);

        assert!(g.legendre(&p) == 1);

        RugCtx {
            generator: g,
            modulus: p,
            modulus_exp: q,
            co_factor,
        }
    }

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf A.2.3
    fn generators_fips(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Integer> {
        let mut ret = Vec::with_capacity(size);
        let two = Integer::from(2);

        let mut prefix = seed.to_vec();
        prefix.extend("ggen".to_string().into_bytes());
        prefix.extend(&contest.to_le_bytes());

        let mut index: u64 = 0;
        for _ in 0..size {
            index += 1;
            let mut next = prefix.clone();
            let mut count: u64 = 0;
            loop {
                count += 1;
                assert!(count != 0);
                next.extend(&index.to_le_bytes());
                next.extend(&count.to_le_bytes());
                let elem: Integer = self.hash_to(&next);
                let g = elem.mod_pow(&self.co_factor, &self.modulus);
                if g >= two {
                    ret.push(g);
                    break;
                }
            }
        }

        ret
    }
}

impl Ctx for RugCtx {
    type E = Integer;
    type X = Integer;
    type P = Integer;

    fn generator(&self) -> &Integer {
        &self.generator
    }
    fn gmod_pow(&self, other: &Integer) -> Integer {
        self.generator.mod_pow(other, &self.modulus())
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Integer, exponent: &Integer) -> Integer {
        base.mod_pow(exponent, self.modulus())
    }
    fn modulus(&self) -> &Integer {
        &self.modulus
    }
    fn exp_modulus(&self) -> &Integer {
        &self.modulus_exp
    }
    fn rnd(&self) -> Integer {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        self.encode(&self.modulus_exp.clone().random_below(&mut state))
            .unwrap()
    }
    fn rnd_exp(&self) -> Integer {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        self.modulus_exp.clone().random_below(&mut state)
    }
    fn rnd_plaintext(&self) -> Integer {
        self.rnd_exp()
    }
    fn encode(&self, plaintext: &Integer) -> Result<Integer, &'static str> {
        if !(plaintext < &(self.modulus_exp.clone() - 1)) {
            return Err("Failed to encode, out of range");
        }
        if plaintext < &0 {
            return Err("Failed to encode, negative");
        }

        let notzero: Integer = plaintext.clone() + 1;
        let legendre = notzero.legendre(&self.modulus());
        if legendre == 0 {
            return Err("Failed to encode, legendre = 0");
        }
        let product = legendre * notzero;

        Ok(Element::modulo(&product, &self.modulus()))
    }
    fn decode(&self, element: &Integer) -> Integer {
        if element > self.exp_modulus() {
            let sub: Integer = (self.modulus() - element).complete();
            sub - 1
        } else {
            (element - 1i32).complete()
        }
    }
    fn exp_from_u64(&self, value: u64) -> Integer {
        Integer::from(value)
    }
    fn gen_key(&self) -> PrivateKey<Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }

    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Integer> {
        self.generators_fips(size, contest, seed)
    }

    fn is_valid_element(&self, element: &Self::E) -> bool {
        element.legendre(self.modulus()) == 1
    }

    fn new() -> RugCtx {
        RugCtx::default()
    }
}

impl ZKProver<RugCtx> for RugCtx {
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf).div_rem(self.modulus().clone());

        rem
    }

    fn ctx(&self) -> &RugCtx {
        self
    }
}

impl ToByteTree for Integer {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_digits::<u8>(Order::LsfLe)))
    }
}

impl FromByteTree for Integer {
    fn from_byte_tree(tree: &ByteTree) -> Result<Integer, ByteError> {
        let bytes = tree.leaf()?;
        let ret = Integer::from_digits(bytes, Order::LsfLe);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::rug::*;
    use crate::backend::tests::*;
    use crate::byte_tree::tests::*;
    use crate::context::Ctx;
    use crate::threshold::tests::test_threshold_generic;

    #[test]
    fn test_elgamal() {
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let ctx = RugCtx::default();
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = RugCtx::default();
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_btserde() {
        let ctx = RugCtx::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_exp();
            ps.push(p);
        }
        test_distributed_btserde_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = RugCtx::default();
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_btserde() {
        let ctx = RugCtx::default();
        test_shuffle_btserde_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }

    #[test]
    fn test_ciphertext_bytes() {
        let ctx = RugCtx::default();
        test_ciphertext_bytes_generic(&ctx);
    }

    #[test]
    fn test_key_bytes() {
        let ctx = RugCtx::default();
        test_key_bytes_generic(&ctx);
    }

    #[test]
    fn test_schnorr_bytes() {
        let ctx = RugCtx::default();
        test_schnorr_bytes_generic(&ctx);
    }

    #[test]
    fn test_cp_bytes() {
        let ctx = RugCtx::default();
        test_cp_bytes_generic(&ctx);
    }

    #[test]
    fn test_epk_bytes() {
        let ctx = RugCtx::default();
        let plaintext = ctx.rnd_exp();
        test_epk_bytes_generic(&ctx, plaintext);
    }

    #[test]
    fn test_encode_err() {
        let rg = RugCtx::default();
        let result = rg.encode(&(rg.exp_modulus() - 1i32).complete());
        assert!(result.is_err())
    }
}
