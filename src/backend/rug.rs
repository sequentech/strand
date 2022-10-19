// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
//! # Examples
//!
//! ```
//! // This example shows how to obtain a context to use the rug backend.
//! use strand::context::{Ctx, Element};
//! use strand::backend::rug::{RugCtx, P2048};
//! let ctx = RugCtx::<P2048>::default();
//! // do some stuff..
//! let g = ctx.generator();
//! let m = ctx.modulus();
//! let a = ctx.rnd_exp();
//! let b = ctx.rnd_exp();
//! let g_ab = g.mod_pow(&a, &m).mod_pow(&b, &m);
//! let g_ba = g.mod_pow(&b, &m).mod_pow(&a, &m);
//! assert_eq!(g_ab, g_ba);
//! ```
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Digest, Sha512};
use rand::RngCore;
use rug::{
    integer::Order,
    rand::{RandGen, RandState},
    Integer,
};
use serde_bytes::ByteBuf;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;

use crate::backend::constants::*;
use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::rnd::StrandRng;
use crate::borsh::{StrandDeserialize, StrandSerialize};

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RugCtx<P: RugCtxParams> {
    params: P,
}

impl<P: RugCtxParams> RugCtx<P> {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf A.2.3
    fn generators_fips(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<IntegerE<P>> {
        let mut ret = Vec::with_capacity(size);
        let two = Integer::from(2i32);

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
                let elem: Integer = self.hash_to_element(&next);
                let g = elem
                    .pow_mod(self.params.co_factor(), &self.modulus().0)
                    .unwrap();
                // Element::<RugCtx<P>>::mod_pow(&elem, self.params.co_factor(), self.modulus());
                if g >= two {
                    ret.push(IntegerE::new(g));
                    break;
                }
            }
        }

        ret
    }

    fn hash_to_element(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf).div_rem(self.modulus().0.clone());

        rem
    }
}

impl<P: RugCtxParams> Ctx for RugCtx<P> {
    type E = IntegerE<P>;
    type X = IntegerX<P>;
    type P = Integer;

    #[inline(always)]
    fn generator(&self) -> &Self::E {
        self.params.generator()
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &Self::X) -> Self::E {
        Element::<RugCtx<P>>::mod_pow(self.generator(), other, self.modulus())
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Self::E, exponent: &Self::X) -> Self::E {
        Element::<RugCtx<P>>::mod_pow(base, exponent, self.modulus())
    }
    #[inline(always)]
    fn modulus(&self) -> &Self::E {
        self.params.modulus()
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &Self::X {
        self.params.exp_modulus()
    }
    #[inline(always)]
    fn rnd(&self) -> Self::E {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        self.encode(&self.exp_modulus().0.clone().random_below(&mut state))
            .expect("0..(q-1) should always be encodable")
    }
    #[inline(always)]
    fn rnd_exp(&self) -> Self::X {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        IntegerX::new(self.exp_modulus().0.clone().random_below(&mut state))
    }
    fn rnd_plaintext(&self) -> Self::P {
        self.rnd_exp().0
    }
    fn encode(&self, plaintext: &Self::P) -> Result<Self::E, &'static str> {
        if plaintext >= &(self.exp_modulus().0.clone() - 1i32) {
            return Err("Failed to encode, out of range");
        }
        if plaintext < &0i32 {
            return Err("Failed to encode, negative");
        }

        let notzero: Integer = plaintext.clone() + 1i32;
        let legendre = notzero.legendre(&self.modulus().0);
        if legendre == 0 {
            return Err("Failed to encode, legendre = 0");
        }
        let result = if legendre == 1 {
            notzero
        } else {
            self.modulus().0.clone() - notzero
        };
        let r = IntegerE::new(result);
        Ok(Element::<RugCtx<P>>::modulo(&r, self.modulus()))
    }
    fn decode(&self, element: &Self::E) -> Self::P {
        if element.0 > self.exp_modulus().0 {
            let sub: Integer = self.modulus().0.clone() - element.0.clone();
            sub - 1i32
        } else {
            element.0.clone() - 1i32
        }
    }
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Self::E> {
        self.generators_fips(size, contest, seed)
    }
    fn element_from_bytes(&self, bytes: &[u8]) -> Result<Self::E, &'static str> {
        let ret = Integer::from_digits(bytes, Order::MsfLe);
        if (ret < 1) || ret >= self.modulus().0 {
            Err("Out of range")
        } else if ret.legendre(&self.modulus().0) != 1 {
            Err("Not a quadratic residue")
        } else {
            Ok(IntegerE::new(ret))
        }
    }
    fn exp_from_bytes(&self, bytes: &[u8]) -> Result<Self::X, &'static str> {
        let ret = Integer::from_digits(bytes, Order::MsfLe);
        if (ret < 0) || ret >= self.exp_modulus().0 {
            Err("Out of range")
        } else {
            Ok(IntegerX::new(ret))
        }
    }
    fn hash_to_exp(&self, bytes: &[u8]) -> Self::X {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) =
            Integer::from_digits(&hashed, Order::Lsf).div_rem(self.exp_modulus().0.clone());

        IntegerX::new(rem)
    }
    fn exp_from_u64(&self, value: u64) -> Self::X {
        IntegerX::new(Integer::from(value))
    }
}
impl<P: RugCtxParams> Default for RugCtx<P> {
    fn default() -> RugCtx<P> {
        let params = P::new();
        RugCtx { params }
    }
}

impl<P: RugCtxParams> Element<RugCtx<P>> for IntegerE<P> {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        IntegerE::new(Integer::from(self.0.clone() * other.0.clone()))
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::<RugCtx<P>>::inv(other, modulus);
        IntegerE::new(self.0.clone() * inverse.0.clone())
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        IntegerE::new(
            self.0
                .clone()
                .invert(&modulus.0)
                .expect("there is always an inverse for prime p"),
        )
    }
    #[inline(always)]
    fn mod_pow(&self, other: &IntegerX<P>, modulus: &Self) -> Self {
        let ret = self.0.clone().pow_mod(&other.0, &modulus.0);
        // From https://docs.rs/rug/latest/rug/struct.Integer.html#method.pow_mod
        // "If the exponent is negative, then the number must have an inverse for an answer to exist.
        // When the exponent is positive and the modulo is not zero, an answer always exists."
        IntegerE::new(ret.expect("an answer always exists for prime p"))
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        // FIXME remove this check
        assert!(self.0 >= 0);
        // From https://docs.rs/rug/latest/rug/struct.Integer.html#method.div_rem
        // The remainder has the same sign as the dividend.
        // thus if self is >= 0 then the result >= 0, and remainder === modulo
        let (_, rem) = self.0.clone().div_rem(modulus.0.clone());

        IntegerE::new(rem)
    }
    fn mul_identity() -> Self {
        IntegerE::new(Integer::from(1))
    }
}

impl<P: RugCtxParams> Exponent<RugCtx<P>> for IntegerX<P> {
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        IntegerX::new(Integer::from(self.0.clone() + other.0.clone()))
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        IntegerX::new(Integer::from(self.0.clone() - other.0.clone()))
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        IntegerX::new(Integer::from(self.0.clone() * other.0.clone()))
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Exponent::<RugCtx<P>>::inv(other, modulus);
        IntegerX::new(self.0.clone() * inverse.0)
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        IntegerX::new(
            self.0
                .clone()
                .invert(&modulus.0)
                .expect("there is always an inverse for prime p"),
        )
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        // FIXME remove this check
        assert!(self.0 >= 0);
        // From https://docs.rs/rug/latest/rug/struct.Integer.html#method.div_rem
        // "The remainder has the same sign as the dividend."
        // thus if self is >= 0 then the result >= 0, and remainder === modulo
        let (_, rem) = self.0.clone().div_rem(modulus.0.clone());

        IntegerX::new(rem)
    }

    fn add_identity() -> Self {
        IntegerX::new(Integer::from(0i32))
    }
    fn mul_identity() -> Self {
        IntegerX::new(Integer::from(1i32))
    }
}

struct StrandRandgen(StrandRng);

impl RandGen for StrandRandgen {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

pub trait RugCtxParams: Clone + Send + Sync + Eq {
    fn generator(&self) -> &IntegerE<Self>;
    fn modulus(&self) -> &IntegerE<Self>;
    fn exp_modulus(&self) -> &IntegerX<Self>;
    fn co_factor(&self) -> &Integer;
    fn new() -> Self;
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct P2048 {
    generator: IntegerE<Self>,
    modulus: IntegerE<Self>,
    exp_modulus: IntegerX<Self>,
    co_factor: Integer,
}
impl RugCtxParams for P2048 {
    #[inline(always)]
    fn generator(&self) -> &IntegerE<Self> {
        &self.generator
    }
    #[inline(always)]
    fn modulus(&self) -> &IntegerE<Self> {
        &self.modulus
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &IntegerX<Self> {
        &self.exp_modulus
    }
    #[inline(always)]
    fn co_factor(&self) -> &Integer {
        &self.co_factor
    }
    fn new() -> P2048 {
        let p = IntegerE::new(Integer::from_str_radix(P_VERIFICATUM_STR_2048, 10).unwrap());
        let q = IntegerX::new(Integer::from_str_radix(Q_VERIFICATUM_STR_2048, 10).unwrap());
        let g = IntegerE::new(Integer::from_str_radix(G_VERIFICATUM_STR_2048, 10).unwrap());
        let co_factor = Integer::from_str_radix(SAFEPRIME_COFACTOR, 16).unwrap();
        assert!(g.0.legendre(&p.0) == 1);

        P2048 {
            generator: g,
            modulus: p,
            exp_modulus: q,
            co_factor,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IntegerE<P: RugCtxParams>(Integer, PhantomData<RugCtx<P>>);
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IntegerX<P: RugCtxParams>(Integer, PhantomData<RugCtx<P>>);

impl<P: RugCtxParams> IntegerE<P> {
    fn new(value: Integer) -> IntegerE<P> {
        IntegerE(value, PhantomData)
    }
}
impl<P: RugCtxParams> IntegerX<P> {
    fn new(value: Integer) -> IntegerX<P> {
        IntegerX(value, PhantomData)
    }
}

impl<P: RugCtxParams> ToByteTree for IntegerE<P> {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.0.to_digits::<u8>(Order::MsfLe)))
    }
}

impl<P: RugCtxParams> FromByteTree<RugCtx<P>> for IntegerE<P> {
    fn from_byte_tree(tree: &ByteTree, ctx: &RugCtx<P>) -> Result<IntegerE<P>, ByteError> {
        let bytes = tree.leaf()?;
        ctx.element_from_bytes(bytes).map_err(ByteError::Msg)
    }
}

impl<P: RugCtxParams> ToByteTree for IntegerX<P> {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.0.to_digits::<u8>(Order::MsfLe)))
    }
}

impl<P: RugCtxParams> FromByteTree<RugCtx<P>> for IntegerX<P> {
    fn from_byte_tree(tree: &ByteTree, ctx: &RugCtx<P>) -> Result<IntegerX<P>, ByteError> {
        let bytes = tree.leaf()?;
        ctx.exp_from_bytes(bytes).map_err(ByteError::Msg)
    }
}

impl<P: RugCtxParams> BorshSerialize for IntegerE<P> {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.0.to_digits::<u8>(Order::MsfLe);
        bytes.serialize(writer)
    }
}

impl<P: RugCtxParams> BorshDeserialize for IntegerE<P> {
    #[inline]
    fn deserialize(bytes: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <Vec<u8>>::deserialize(bytes).unwrap();
        let ctx = RugCtx::<P>::default();

        let value = ctx
            .element_from_bytes(&bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e));
        value
    }
}

impl<P: RugCtxParams> BorshSerialize for IntegerX<P> {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.0.to_digits::<u8>(Order::MsfLe);
        bytes.serialize(writer)
    }
}

impl<P: RugCtxParams> BorshDeserialize for IntegerX<P> {
    #[inline]
    fn deserialize(bytes: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <Vec<u8>>::deserialize(bytes).unwrap();
        let ctx = RugCtx::<P>::default();

        let value = ctx
            .exp_from_bytes(&bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e));
        value
    }
}

/*********************************************************************/
/*************************** SPECIALIZATIONS *************************/
/*********************************************************************/
use crate::util::Par;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature="specialization")] {
        impl<P: RugCtxParams> StrandSerialize for Vec<IntegerE<P>> {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru V<E> >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandSerialize for [IntegerE<P>] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru E[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandSerialize for &[IntegerE<P>] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru &E[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandDeserialize for Vec<IntegerE<P>> {
            fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
            where
                Self: Sized,
            {
                println!("Specialization: Ru V<E> <<<");
                let vectors = <Vec<Vec<u8>>>::try_from_slice(bytes).unwrap();

                let results: Vec<IntegerE<P>> = vectors
                    .par()
                    .map(|v| IntegerE::<P>::try_from_slice(&v).unwrap())
                    .collect();

                Ok(results)
            }
        }

        impl<P: RugCtxParams> StrandSerialize for Vec<IntegerX<P>> {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru V<X> >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandSerialize for [IntegerX<P>] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru X[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandSerialize for &[IntegerX<P>] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ru &X[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl<P: RugCtxParams> StrandDeserialize for Vec<IntegerX<P>> {
            fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
            where
                Self: Sized,
            {
                println!("Specialization: Ru V<X> <<<");
                let vectors = <Vec<Vec<u8>>>::try_from_slice(bytes).unwrap();

                let results: Vec<IntegerX<P>> = vectors
                    .par()
                    .map(|v| IntegerX::<P>::try_from_slice(&v).unwrap())
                    .collect();

                Ok(results)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::rug::*;
    use crate::backend::tests::*;
    use crate::borsh::tests::*;
    use crate::byte_tree::tests::*;
    use crate::context::Ctx;
    use crate::elgamal::Ciphertext;
    use crate::elgamal::PrivateKey;
    use crate::shuffler::gen_permutation;
    use crate::shuffler::PermutationData;
    use crate::shuffler::Shuffler;
    use crate::threshold::tests::test_threshold_generic;
    use serde::Serialize;

    #[test]
    fn test_elgamal() {
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_elgamal_enc_pok() {
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();
        test_elgamal_enc_pok_generic(&ctx, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let ctx = RugCtx::<P2048>::default();
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = RugCtx::<P2048>::default();
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_serialization() {
        let ctx = RugCtx::<P2048>::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_plaintext();
            ps.push(p);
        }
        test_distributed_serialization_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = RugCtx::<P2048>::default();
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_serialization() {
        let ctx = RugCtx::<P2048>::default();
        test_shuffle_serialization_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = RugCtx::<P2048>::default();
        let plaintext = ctx.rnd_plaintext();

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }

    #[test]
    fn test_element_borsh() {
        let ctx = RugCtx::<P2048>::default();
        test_borsh_element(&ctx);
    }

    #[test]
    fn test_ciphertext_borsh() {
        let ctx = RugCtx::<P2048>::default();
        test_ciphertext_borsh_generic(&ctx);
    }

    #[test]
    fn test_key_borsh() {
        let ctx = RugCtx::<P2048>::default();
        test_key_borsh_generic(&ctx);
    }

    #[test]
    fn test_schnorr_borsh() {
        let ctx = RugCtx::<P2048>::default();
        test_schnorr_borsh_generic(&ctx);
    }

    #[test]
    fn test_cp_borsh() {
        let ctx = RugCtx::<P2048>::default();
        test_cp_borsh_generic(&ctx);
    }

    #[test]
    fn test_encode_err() {
        let ctx = RugCtx::<P2048>::default();
        let result = ctx.encode(&(ctx.exp_modulus().0.clone() - 1i32));
        assert!(result.is_err())
    }

    #[derive(Serialize)]
    struct CoqVerifierTranscript {
        group: Vec<String>,
        pk: Vec<String>,
        hs: Vec<Vec<String>>,
        us: Vec<String>,
        permutation_commitment: Vec<String>,
        proof_commitment: Vec<Vec<String>>,
        challenge: Vec<String>,
        proof_reply: Vec<Vec<String>>,
        ciphers_in: Vec<Vec<String>>,
        ciphers_out: Vec<Vec<String>>,
    }

    // cargo test --features=rug coq -- --ignored
    #[ignore]
    #[test]
    fn test_gen_coq_data() {
        let ctx = RugCtx::<P2048>::default();

        let sk = PrivateKey::gen(&ctx);
        let pk = sk.get_pk();

        let n = 100;
        let mut es: Vec<Ciphertext<RugCtx<P2048>>> = Vec::with_capacity(n);

        for _ in 0..n {
            let plaintext: Integer = ctx.rnd_plaintext();
            let element = ctx.encode(&plaintext).unwrap();
            let c = pk.encrypt(&element);
            es.push(c);
        }
        let seed = vec![];
        let hs = ctx.generators(es.len() + 1, 0, &seed);

        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            ctx: ctx.clone(),
        };

        let perm: Vec<usize> = gen_permutation(n);
        let (cs, c_rs) = shuffler.gen_commitments(&perm, &ctx);
        let (e_primes, rs) = shuffler.apply_permutation(&perm, &es);
        let perm_data = PermutationData {
            permutation: &perm,
            commitments_c: &cs,
            commitments_r: &c_rs,
        };
        let (proof, us, c) = shuffler.gen_proof_ext(&es, &e_primes, &rs, &perm_data, &vec![]);
        let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

        assert!(ok);

        let pk_list = vec![
            ctx.generator().0.to_string_radix(16),
            pk.element.0.to_string_radix(16),
        ];

        let hs_list: Vec<String> = hs.iter().map(|h| h.0.to_string_radix(16)).collect();
        let h_list = vec![vec![hs_list[0].clone()], hs_list[1..].to_vec()];

        let cs = proof.cs;
        let cs_list: Vec<String> = cs.iter().map(|c| c.0.to_string_radix(16)).collect();

        let c_hats: Vec<String> = proof
            .c_hats
            .iter()
            .map(|c| c.0.to_string_radix(16))
            .collect();
        let t3 = proof.t.t3.0.to_string_radix(16);
        let t_hats: Vec<String> = proof
            .t
            .t_hats
            .iter()
            .map(|c| c.0.to_string_radix(16))
            .collect();
        let t1 = proof.t.t1.0.to_string_radix(16);
        let t2 = proof.t.t2.0.to_string_radix(16);
        let t4_1 = proof.t.t4_1.0.to_string_radix(16);
        let t4_2 = proof.t.t4_2.0.to_string_radix(16);

        let t_list = vec![
            c_hats,
            vec![t3],
            t_hats,
            vec![t1],
            vec![t2],
            vec![t4_1, t4_2],
        ];

        let ciphers_in_a: Vec<String> = es.iter().map(|c| c.mhr.0.to_string_radix(16)).collect();
        let ciphers_in_b: Vec<String> = es.iter().map(|c| c.gr.0.to_string_radix(16)).collect();

        let ciphers_out_a: Vec<String> = e_primes
            .iter()
            .map(|c| c.mhr.0.to_string_radix(16))
            .collect();
        let ciphers_out_b: Vec<String> = e_primes
            .iter()
            .map(|c| c.gr.0.to_string_radix(16))
            .collect();

        let ciphers_in = vec![ciphers_in_a, ciphers_in_b];
        let ciphers_out = vec![ciphers_out_a, ciphers_out_b];

        let s1 = proof.s.s1.0.to_string_radix(16);
        let s2 = proof.s.s2.0.to_string_radix(16);
        let s3 = proof.s.s3.0.to_string_radix(16);
        let s4 = proof.s.s4.0.to_string_radix(16);
        let s_hats: Vec<String> = proof
            .s
            .s_hats
            .iter()
            .map(|c| c.0.to_string_radix(16))
            .collect();
        let s_primes: Vec<String> = proof
            .s
            .s_primes
            .iter()
            .map(|c| c.0.to_string_radix(16))
            .collect();

        let s_list = vec![vec![s3], s_hats, vec![s1], vec![s2], s_primes, vec![s4]];

        let us_list: Vec<String> = us.iter().map(|u| u.0.to_string_radix(16)).collect();
        let challenge: Vec<String> = vec![c.0.to_string_radix(16)];

        let group = vec![
            ctx.modulus().0.to_string_radix(16),
            ctx.exp_modulus().0.to_string_radix(16),
        ];

        let transcript = CoqVerifierTranscript {
            group: group,
            pk: pk_list,
            hs: h_list,
            us: us_list,
            permutation_commitment: cs_list,
            proof_commitment: t_list,
            challenge: challenge,
            proof_reply: s_list,
            ciphers_in: ciphers_in,
            ciphers_out: ciphers_out,
        };

        serde_json::to_writer_pretty(
            std::fs::File::create("transcript_strand.json").unwrap(),
            &transcript,
        )
        .unwrap();
    }
}
