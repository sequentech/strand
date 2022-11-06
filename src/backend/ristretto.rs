// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
//! # Examples
//!
//! ```
//! // This example shows how to obtain a context to use the ristretto backend.
//! use strand::context::{Ctx, Element};
//! use strand::backend::ristretto::RistrettoCtx;
//! let ctx = RistrettoCtx;
//! // do some stuff..
//! let g = ctx.generator();
//! let m = ctx.modulus();
//! let a = ctx.rnd_exp();
//! let b = ctx.rnd_exp();
//! let g_ab = g.mod_pow(&a, &m).mod_pow(&b, &m);
//! let g_ba = g.mod_pow(&b, &m).mod_pow(&a, &m);
//! assert_eq!(g_ab, g_ba);
//! ```
use std::io::Error;
use std::io::ErrorKind;

use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use curve25519_dalek::constants::BASEPOINT_ORDER;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Digest, Sha512};
use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::elgamal::Ciphertext;
use crate::elgamal::{PrivateKey, PublicKey};
use crate::context::{Ctx, Element, Exponent};
use crate::rnd::StrandRng;
use crate::serialization::{StrandDeserialize, StrandSerialize};
use crate::util;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RistrettoCtx;

const DUMMY_SCALAR: Scalar = BASEPOINT_ORDER;
const DUMMY_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

#[derive(PartialEq, Eq, Clone)]
// RistrettoPoint for Strand
pub struct RistrettoPointS(pub RistrettoPoint);
#[derive(PartialEq, Eq, Debug, Clone)]
// Scalar for Strand
pub struct ScalarS(pub Scalar);

impl RistrettoCtx {
    // https://docs.rs/bulletproofs/4.0.0/src/bulletproofs/generators.rs.html
    fn generators_shake(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<RistrettoPointS> {
        let mut seed_ = seed.to_vec();
        seed_.extend(contest.to_le_bytes());

        let mut ret: Vec<RistrettoPointS> = Vec::with_capacity(size);
        let mut shake = Shake256::default();
        shake.update(&seed_);

        let mut reader = shake.finalize_xof();
        for _ in 0..size {
            let mut uniform_bytes = [0u8; 64];
            reader.read(&mut uniform_bytes);
            let g = RistrettoPoint::from_uniform_bytes(&uniform_bytes);
            ret.push(RistrettoPointS(g));
        }

        ret
    }
}

impl Ctx for RistrettoCtx {
    type E = RistrettoPointS;
    type X = ScalarS;
    type P = [u8; 30];

    #[inline(always)]
    fn generator(&self) -> &Self::E {
        &RistrettoPointS(RISTRETTO_BASEPOINT_POINT)
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &ScalarS) -> Self::E {
        RistrettoPointS(&other.0 * &RISTRETTO_BASEPOINT_TABLE)
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Self::E, exponent: &Self::X) -> Self::E {
        RistrettoPointS(base.0 * exponent.0)
    }
    #[inline(always)]
    fn modulus(&self) -> &Self::E {
        // returning a dummy value as modulus does not apply to this backend
        &RistrettoPointS(DUMMY_POINT)
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &Self::X {
        // returning a dummy value as modulus does not apply to this backend
        &ScalarS(DUMMY_SCALAR)
    }
    #[inline(always)]
    fn rnd(&self) -> Self::E {
        let mut rng = StrandRng;
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        RistrettoPointS(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }
    #[inline(always)]
    fn rnd_exp(&self) -> Self::X {
        let mut rng = StrandRng;
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        ScalarS(Scalar::from_bytes_mod_order_wide(&uniform_bytes))
    }
    fn rnd_plaintext(&self) -> Self::P {
        let mut csprng = StrandRng;
        let mut value = [0u8; 30];
        csprng.fill_bytes(&mut value);

        value
    }
    fn hash_to_exp(&self, bytes: &[u8]) -> Self::X {
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, bytes);

        ScalarS(Scalar::from_hash(hasher))
    }

    // see https://github.com/dalek-cryptography/curve25519-dalek/issues/322
    // see https://github.com/hdevalence/ristretto255-data-encoding/blob/master/src/main.rs
    fn encode(&self, data: &[u8; 30]) -> Result<Self::E, &'static str> {
        let mut bytes = [0u8; 32];
        bytes[1..1 + data.len()].copy_from_slice(data);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return Ok(RistrettoPointS(point));
                }
            }
        }
        Err("Failed to encode into ristretto point")
    }
    fn decode(&self, element: &Self::E) -> Self::P {
        let compressed = element.0.compress();
        // the 30 bytes of data are placed in the range 1-30
        let slice = &compressed.as_bytes()[1..31];
        util::to_u8_30(slice)
    }
    fn encrypt_exp(&self, exp: &Self::X, pk: PublicKey<Self>) -> Vec<u8> {
        let bytes = exp.0.to_bytes();
        let mut blank = vec![0; 30];
        blank[0..16].copy_from_slice(&bytes[0..16]);
        let first = self.encode(&util::to_u8_30(&blank));
        blank[0..16].copy_from_slice(&bytes[16..32]);
        let second = self.encode(&util::to_u8_30(&blank));
        let first_c = pk.encrypt(&first.unwrap());
        let second_c = pk.encrypt(&second.unwrap());
        
        vec![first_c, second_c].strand_serialize()
    }
    fn decrypt_exp(&self, bytes: &[u8], sk: PrivateKey<Self>) -> Option<Self::X> {
        let vector = Vec::<Ciphertext<Self>>::strand_deserialize(bytes).ok()?;
        if vector.len() == 2 {
            let first = self.decode(&sk.decrypt(&vector[0]));
            let second = self.decode(&sk.decrypt(&vector[1]));

            let mut concat = first[0..16].to_vec();
            concat.extend_from_slice(&second[0..16]);

            let ret = self.exp_from_bytes(&concat).ok()?;

            Some(ret)
            
        }
        else {
            None
        }
    }
    fn exp_from_u64(&self, value: u64) -> Self::X {
        let val_bytes = value.to_le_bytes();
        let mut bytes = [0u8; 32];
        let mut vec = val_bytes.to_vec();
        vec.resize(32, 0);
        bytes.copy_from_slice(&vec);
        let scalar = Scalar::from_bytes_mod_order(bytes);

        ///// FIXME remove this sanity check
        let mut scalar_bytes = scalar.as_bytes().to_vec();
        scalar_bytes.resize(8, 0);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&scalar_bytes);
        let check = u64::from_le_bytes(bytes);
        assert_eq!(value, check);
        /////

        ScalarS(scalar)
    }
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Self::E> {
        self.generators_shake(size, contest, seed)
    }
    fn element_from_bytes(&self, bytes: &[u8]) -> Result<Self::E, &'static str> {
        let b32 = util::to_u8_32(bytes)?;
        CompressedRistretto(b32)
            .decompress()
            .map(RistrettoPointS)
            .ok_or("Failed constructing ristretto point")
    }
    fn exp_from_bytes(&self, bytes: &[u8]) -> Result<Self::X, &'static str> {
        let b32 = util::to_u8_32(bytes)?;
        Scalar::from_canonical_bytes(b32)
            .map(ScalarS)
            .ok_or("Failed constructing scalar")
    }
}

impl Default for RistrettoCtx {
    fn default() -> RistrettoCtx {
        RistrettoCtx
    }
}

impl Element<RistrettoCtx> for RistrettoPointS {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        RistrettoPointS(self.0 + other.0)
    }
    #[inline(always)]
    fn div(&self, other: &Self, _modulus: &Self) -> Self {
        RistrettoPointS(self.0 + other.inv(_modulus).0)
    }
    #[inline(always)]
    fn inv(&self, _modulus: &Self) -> Self {
        RistrettoPointS(-self.0)
    }
    #[inline(always)]
    fn mod_pow(&self, other: &ScalarS, _modulus: &Self) -> Self {
        RistrettoPointS(self.0 * other.0)
    }
    #[inline(always)]
    fn modulo(&self, _modulus: &Self) -> Self {
        self.clone()
    }
    fn mul_identity() -> Self {
        RistrettoPointS(RistrettoPoint::identity())
    }
}

impl Exponent<RistrettoCtx> for ScalarS {
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        ScalarS(self.0 + other.0)
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        ScalarS(self.0 - other.0)
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        ScalarS(self.0 * other.0)
    }
    #[inline(always)]
    fn div(&self, other: &ScalarS, _modulus: &ScalarS) -> ScalarS {
        ScalarS(self.0 * other.inv(_modulus).0)
    }
    #[inline(always)]
    fn inv(&self, _modulus: &Self) -> Self {
        ScalarS(self.0.invert())
    }
    #[inline(always)]
    fn modulo(&self, _modulus: &Self) -> Self {
        self.clone()
    }
    fn add_identity() -> Self {
        ScalarS(Scalar::zero())
    }
    fn mul_identity() -> Self {
        ScalarS(Scalar::one())
    }
}

impl BorshSerialize for RistrettoPointS {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.0.compress().to_bytes();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for RistrettoPointS {
    #[inline]
    fn deserialize(bytes: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize(bytes).unwrap();
        let ctx = RistrettoCtx::default();

        let value = ctx
            .element_from_bytes(&bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e));
        value
    }
}

impl BorshSerialize for ScalarS {
    #[inline]
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.0.to_bytes();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for ScalarS {
    #[inline]
    fn deserialize(bytes: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize(bytes).unwrap();
        let ctx = RistrettoCtx::default();

        let value = ctx
            .exp_from_bytes(&bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e));
        value
    }
}

///////////////////////////////////////////////////////////////////////////
// Specializations
///////////////////////////////////////////////////////////////////////////
use crate::util::Par;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature="specialization")] {
        impl StrandSerialize for Vec<RistrettoPointS> {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri V<E> >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();
                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandSerialize for [RistrettoPointS] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri E[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandSerialize for &[RistrettoPointS] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri &E[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandDeserialize for Vec<RistrettoPointS> {
            fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
            where
                Self: Sized,
            {
                println!("Specialization: Ri V<E> <<<");
                let vectors = <Vec<Vec<u8>>>::try_from_slice(bytes).unwrap();

                let results: Vec<RistrettoPointS> = vectors
                    .par()
                    .map(|v| RistrettoPointS::try_from_slice(&v).unwrap())
                    .collect();

                Ok(results)
            }
        }

        impl StrandSerialize for Vec<ScalarS> {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri V<X> >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandSerialize for [ScalarS] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri X[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandSerialize for &[ScalarS] {
            fn strand_serialize(&self) -> Vec<u8> {
                println!("Specialization: Ri &X[] >>>");
                let vectors: Vec<Vec<u8>> = self.par().map(|c| c.try_to_vec().unwrap()).collect();

                vectors.try_to_vec().unwrap()
            }
        }

        impl StrandDeserialize for Vec<ScalarS> {
            fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
            where
                Self: Sized,
            {
                println!("Specialization: Ri V<X> <<<");
                let vectors = <Vec<Vec<u8>>>::try_from_slice(bytes).unwrap();

                let results: Vec<ScalarS> = vectors
                    .par()
                    .map(|v| ScalarS::try_from_slice(&v).unwrap())
                    .collect();

                Ok(results)
            }
        }
    }
}

impl std::fmt::Debug for RistrettoPointS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RistrettoPointS {{ value={} }}",
            &hex::encode(self.0.compress().as_bytes())[0..10]
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::ristretto::*;
    use crate::backend::tests::*;
    use crate::serialization::tests::*;
    use crate::threshold_test::tests::test_threshold_generic;

    #[test]
    fn test_elgamal() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_elgamal_enc_pok() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_elgamal_enc_pok_generic(&ctx, plaintext);
    }

    #[test]
    fn test_encrypt_exp() {
        let ctx = RistrettoCtx;
        test_encrypt_exp_generic(&ctx);
    }

    #[test]
    fn test_schnorr() {
        let ctx = RistrettoCtx;
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = RistrettoCtx;
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_serialization() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_distributed_serialization_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = RistrettoCtx;
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_serialization() {
        let ctx = RistrettoCtx;
        test_shuffle_serialization_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let plaintext = util::to_u8_30(&fill.to_vec());
        let trustees = 5usize;
        let threshold = 3usize;

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }

    #[test]
    fn test_element_borsh() {
        let ctx = RistrettoCtx;
        test_borsh_element(&ctx);
    }

    #[test]
    fn test_exponent_borsh() {
        let ctx = RistrettoCtx;
        test_borsh_exponent(&ctx);
    }

    #[test]
    fn test_ciphertext_borsh() {
        let ctx = RistrettoCtx;
        test_ciphertext_borsh_generic(&ctx);
    }

    #[test]
    fn test_key_borsh() {
        let ctx = RistrettoCtx;
        test_key_borsh_generic(&ctx);
    }

    #[test]
    fn test_schnorr_borsh() {
        let ctx = RistrettoCtx;
        test_schnorr_borsh_generic(&ctx);
    }

    #[test]
    fn test_cp_borsh() {
        let ctx = RistrettoCtx;
        test_cp_borsh_generic(&ctx);
    }
    /*
    #[test]
    fn test_ciphertext_bytes() {
        let ctx = RistrettoCtx::default();
        test_ciphertext_bytes_generic(&ctx);
    }

    #[test]
    fn test_key_bytes() {
        let ctx = RistrettoCtx::default();
        test_key_bytes_generic(&ctx);
    }

    #[test]
    fn test_schnorr_bytes() {
        let ctx = RistrettoCtx::default();
        test_schnorr_bytes_generic(&ctx);
    }

    #[test]
    fn test_cp_bytes() {
        let ctx = RistrettoCtx::default();
        test_cp_bytes_generic(&ctx);
    }*/
}
