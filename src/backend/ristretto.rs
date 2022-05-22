use curve25519_dalek::constants::BASEPOINT_ORDER;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::digest::{ExtendableOutputDirty, Update, XofReader};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Digest, Sha512};
use serde_bytes::ByteBuf;

use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::*;
use crate::util;
use crate::zkp::ZKProver;

use crate::rnd::StrandRng;
use rand::RngCore;
use sha3::Shake256;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RistrettoCtx;

const DUMMY_SCALAR: Scalar = BASEPOINT_ORDER;
const DUMMY_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

impl RistrettoCtx {
    // https://docs.rs/bulletproofs/4.0.0/src/bulletproofs/generators.rs.html
    fn generators_shake(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<RistrettoPoint> {
        let mut seed_ = seed.to_vec();
        seed_.extend(&contest.to_le_bytes());

        let mut ret: Vec<RistrettoPoint> = Vec::with_capacity(size);
        let mut shake = Shake256::default();
        shake.update(seed_);

        let mut reader = shake.finalize_xof_dirty();
        for _ in 0..size {
            let mut uniform_bytes = [0u8; 64];
            reader.read(&mut uniform_bytes);
            let g = RistrettoPoint::from_uniform_bytes(&uniform_bytes);
            ret.push(g);
        }

        ret
    }
}

impl Ctx for RistrettoCtx {
    type E = RistrettoPoint;
    type X = Scalar;
    type P = [u8; 30];

    #[inline(always)]
    fn generator(&self) -> &RistrettoPoint {
        &RISTRETTO_BASEPOINT_POINT
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &Scalar) -> RistrettoPoint {
        other * &RISTRETTO_BASEPOINT_TABLE
    }
    #[inline(always)]
    fn emod_pow(&self, base: &RistrettoPoint, exponent: &Scalar) -> RistrettoPoint {
        base * exponent
    }
    #[inline(always)]
    fn modulus(&self) -> &RistrettoPoint {
        // returning a dummy value as modulus does not apply to this backend
        &DUMMY_POINT
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &Scalar {
        // returning a dummy value as modulus does not apply to this backend
        &DUMMY_SCALAR
    }
    #[inline(always)]
    fn rnd(&self) -> RistrettoPoint {
        let mut rng = StrandRng;
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }
    #[inline(always)]
    fn rnd_exp(&self) -> Scalar {
        let mut rng = StrandRng;
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        Scalar::from_bytes_mod_order_wide(&uniform_bytes)
    }
    fn rnd_plaintext(&self) -> [u8; 30] {
        let mut csprng = StrandRng;
        let mut value = [0u8; 30];
        csprng.fill_bytes(&mut value);

        value
    }
    fn gen_key(&self) -> PrivateKey<Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }
    // see https://github.com/ruescasd/braid-mg/issues/4
    fn encode(&self, data: &[u8; 30]) -> RistrettoPoint {
        let mut bytes = [0u8; 32];
        bytes[1..1 + data.len()].copy_from_slice(data);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return point;
                }
            }
        }
        panic!("Failed to encode into ristretto point");
    }
    fn decode(&self, element: &RistrettoPoint) -> [u8; 30] {
        let compressed = element.compress();
        let slice = &compressed.as_bytes()[1..31];
        util::to_u8_30(slice)
    }
    fn exp_from_u64(&self, value: u64) -> Scalar {
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

        scalar
    }
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<RistrettoPoint> {
        self.generators_shake(size, contest, seed)
    }
    #[inline(always)]
    fn get() -> &'static RistrettoCtx {
        &RistrettoCtx
    }
}

impl ZKProver<RistrettoCtx> for RistrettoCtx {
    fn hash_to(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, bytes);

        Scalar::from_hash(hasher)
    }
}

impl Element<RistrettoCtx> for RistrettoPoint {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        self + other
    }
    #[inline(always)]
    fn div(&self, other: &Self, _modulus: &Self) -> Self {
        self + other.inv(_modulus)
    }
    #[inline(always)]
    fn inv(&self, _modulus: &Self) -> Self {
        -self
    }
    #[inline(always)]
    fn mod_pow(&self, other: &Scalar, _modulus: &Self) -> Self {
        self * other
    }
    #[inline(always)]
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
    fn mul_identity() -> Self {
        RistrettoPoint::identity()
    }
}

impl Exponent<RistrettoCtx> for Scalar {
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        self + other
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        self - other
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        self * other
    }
    #[inline(always)]
    fn div(&self, other: &Scalar, _modulus: &Scalar) -> Scalar {
        self * other.inv(_modulus)
    }
    #[inline(always)]
    fn inv(&self, _modulus: &Self) -> Self {
        self.invert()
    }
    #[inline(always)]
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
    fn add_identity() -> Self {
        Scalar::zero()
    }
    fn mul_identity() -> Self {
        Scalar::one()
    }
    fn to_string(&self) -> String {
        format!("{:x?}", self.to_bytes())
    }
}

impl ToByteTree for Scalar {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.as_bytes().to_vec()))
    }
}

impl FromByteTree for Scalar {
    fn from_byte_tree(tree: &ByteTree) -> Result<Scalar, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(bytes);
        Scalar::from_canonical_bytes(b32)
            .ok_or_else(|| ByteError::Msg(String::from("Failed constructing scalar")))
    }
}

impl ToByteTree for RistrettoPoint {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.compress().as_bytes().to_vec()))
    }
}

impl FromByteTree for RistrettoPoint {
    fn from_byte_tree(tree: &ByteTree) -> Result<RistrettoPoint, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(bytes);
        CompressedRistretto(b32)
            .decompress()
            .ok_or_else(|| ByteError::Msg(String::from("Failed constructing ristretto point")))
    }
}

impl ToByteTree for RistrettoCtx {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(ByteBuf::new())
    }
}

impl FromByteTree for RistrettoCtx {
    fn from_byte_tree(tree: &ByteTree) -> Result<RistrettoCtx, ByteError> {
        let _leaf = tree.leaf()?;
        Ok(RistrettoCtx)
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::ristretto::*;
    use crate::backend::tests::*;
    use crate::byte_tree::tests::*;
    use crate::threshold::tests::test_threshold_generic;

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
    fn test_distributed_btserde() {
        let mut csprng = StrandRng;

        let ctx = RistrettoCtx;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_distributed_btserde_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = RistrettoCtx;
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_btserde() {
        let ctx = RistrettoCtx;
        test_shuffle_btserde_generic(&ctx);
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
    fn test_ciphertext_bytes() {
        let ctx = RistrettoCtx::get();
        test_ciphertext_bytes_generic(ctx);
    }

    #[test]
    fn test_key_bytes() {
        let ctx = RistrettoCtx::get();
        test_key_bytes_generic(ctx);
    }

    #[test]
    fn test_schnorr_bytes() {
        let ctx = RistrettoCtx::get();
        test_schnorr_bytes_generic(ctx);
    }
}
