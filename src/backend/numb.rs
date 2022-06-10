use ed25519_dalek::{Digest, Sha512};
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_integer::Integer;
use num_modular::{ModularSymbols, ModularUnaryOps};
use num_traits::Num;
use num_traits::{One, Zero};
use serde_bytes::ByteBuf;

use crate::backend::constants::*;
use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::rnd::StrandRng;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct BigintCtx<P: BigintCtxParams> {
    params: P,
}

impl<P: BigintCtxParams> BigintCtx<P> {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf A.2.3
    fn generators_fips(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<BigUint> {
        let mut ret = Vec::with_capacity(size);
        let two = BigUint::from(2u32);

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
                let elem: BigUint = self.hash_to(&next);
                let g = elem.modpow(self.params.co_factor(), self.modulus());
                if g >= two {
                    ret.push(g);
                    break;
                }
            }
        }

        ret
    }
}

impl<P: BigintCtxParams> Ctx for BigintCtx<P> {
    type E = BigUint;
    type X = BigUint;
    type P = BigUint;

    #[inline(always)]
    fn generator(&self) -> &BigUint {
        self.params.generator()
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &BigUint) -> BigUint {
        self.generator().modpow(other, self.modulus())
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Self::E, exponent: &BigUint) -> BigUint {
        base.modpow(exponent, self.modulus())
    }
    #[inline(always)]
    fn modulus(&self) -> &BigUint {
        self.params.modulus()
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &BigUint {
        self.params.exp_modulus()
    }
    #[inline(always)]
    fn rnd(&self) -> BigUint {
        let mut gen = StrandRng;
        let one: BigUint = One::one();
        let unencoded = gen.gen_biguint_below(&(self.exp_modulus() - one));

        self.encode(&unencoded).unwrap()
    }
    #[inline(always)]
    fn rnd_exp(&self) -> BigUint {
        let mut gen = StrandRng;
        gen.gen_biguint_below(self.exp_modulus())
    }
    fn rnd_plaintext(&self) -> BigUint {
        self.rnd_exp()
    }
    fn hash_to(&self, bytes: &[u8]) -> BigUint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        num.mod_floor(self.modulus())
    }
    fn encode(&self, plaintext: &BigUint) -> Result<BigUint, &'static str> {
        let one: BigUint = One::one();

        if plaintext >= &(self.exp_modulus() - &one) {
            return Err("Failed to encode, out of range");
        }
        let notzero: BigUint = plaintext + one;
        let legendre = notzero.legendre(self.modulus());
        if legendre == 0 {
            return Err("Failed to encode, legendre = 0");
        }
        let result = if legendre == 1 {
            notzero
        } else {
            self.modulus() - notzero
        };
        Ok(BigUint::mod_floor(&result, self.modulus()))
    }
    fn decode(&self, element: &BigUint) -> BigUint {
        let one: BigUint = One::one();
        if element > self.exp_modulus() {
            (self.modulus() - element) - one
        } else {
            element - one
        }
    }
    fn exp_from_u64(&self, value: u64) -> BigUint {
        BigUint::from(value)
    }
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<BigUint> {
        self.generators_fips(size, contest, seed)
    }
    fn is_valid_element(&self, element: &Self::E) -> bool {
        element.legendre(self.modulus()) == 1
    }
    fn new() -> BigintCtx<P> {
        let params = P::new();
        BigintCtx { params }
    }
}

impl<P: BigintCtxParams> Element<BigintCtx<P>> for BigUint {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        self * other
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::<BigintCtx<P>>::inv(other, modulus);
        self * inverse
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        self.invm(modulus).unwrap()
    }
    #[inline(always)]
    fn mod_pow(&self, other: &BigUint, modulus: &Self) -> Self {
        self.modpow(other, modulus)
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        self.mod_floor(modulus)
    }
    fn mul_identity() -> Self {
        One::one()
    }
}

impl<P: BigintCtxParams> Exponent<BigintCtx<P>> for BigUint {
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
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Exponent::<BigintCtx<P>>::inv(other, modulus);
        self * inverse
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        self.invm(modulus).unwrap()
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        self.mod_floor(modulus)
    }
    fn add_identity() -> Self {
        Zero::zero()
    }
    fn mul_identity() -> Self {
        One::one()
    }
    fn to_string(&self) -> String {
        format!("{:x?}", self.to_bytes_be())
    }
}

/*impl<P: BigintCtxParams> ZKProver<BigintCtx<P>> for BigintCtx<P> {
    fn hash_to(&self, bytes: &[u8]) -> BigUint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        num.mod_floor(self.modulus())
    }
    fn ctx(&self) -> &BigintCtx<P> {
        self
    }
}

impl<P: BigintCtxParams> Zkp<BigintCtx<P>> for ZkpStruct<BigintCtx<P>> {
    fn hash_to(&self, bytes: &[u8]) -> BigUint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        num.mod_floor(self.ctx.modulus())
    }
    fn ctx(&self) -> &BigintCtx<P> {
        &self.ctx
    }
}*/

pub trait BigintCtxParams: Clone + Send + Sync {
    fn generator(&self) -> &BigUint;
    fn modulus(&self) -> &BigUint;
    fn exp_modulus(&self) -> &BigUint;
    fn co_factor(&self) -> &BigUint;
    fn new() -> Self;
}
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct P2048 {
    generator: BigUint,
    modulus: BigUint,
    exp_modulus: BigUint,
    co_factor: BigUint,
}
impl BigintCtxParams for P2048 {
    #[inline(always)]
    fn generator(&self) -> &BigUint {
        &self.generator
    }
    #[inline(always)]
    fn modulus(&self) -> &BigUint {
        &self.modulus
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &BigUint {
        &self.exp_modulus
    }
    #[inline(always)]
    fn co_factor(&self) -> &BigUint {
        &self.co_factor
    }
    fn new() -> P2048 {
        let p = BigUint::from_str_radix(P_STR_2048, 16).unwrap();
        let q = BigUint::from_str_radix(Q_STR_2048, 16).unwrap();
        let g = BigUint::from_str_radix(G_STR_2048, 16).unwrap();
        let co_factor = BigUint::from_str_radix(SAFEPRIME_COFACTOR, 16).unwrap();

        assert!(g.legendre(&p) == 1);

        P2048 {
            generator: g,
            modulus: p,
            exp_modulus: q,
            co_factor,
        }
    }
}

impl ToByteTree for BigUint {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_bytes_be()))
    }
}

impl FromByteTree for BigUint {
    fn from_byte_tree(tree: &ByteTree) -> Result<BigUint, ByteError> {
        let bytes = tree.leaf()?;
        let ret = BigUint::from_bytes_be(bytes);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::numb::*;
    use crate::backend::tests::*;
    use crate::byte_tree::tests::*;
    use crate::context::Ctx;
    use crate::threshold::tests::test_threshold_generic;

    #[test]
    fn test_elgamal() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let ctx = BigintCtx::<P2048>::new();
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = BigintCtx::<P2048>::new();
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_btserde() {
        let ctx = BigintCtx::<P2048>::new();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_exp();
            ps.push(p);
        }
        test_distributed_btserde_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = BigintCtx::<P2048>::new();
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_btserde() {
        let ctx = BigintCtx::<P2048>::new();
        test_shuffle_btserde_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }

    #[test]
    fn test_ciphertext_bytes() {
        let ctx = BigintCtx::<P2048>::new();
        test_ciphertext_bytes_generic(&ctx);
    }

    #[test]
    fn test_key_bytes() {
        let ctx = BigintCtx::<P2048>::new();
        test_key_bytes_generic(&ctx);
    }

    #[test]
    fn test_schnorr_bytes() {
        let ctx = BigintCtx::<P2048>::new();
        test_schnorr_bytes_generic(&ctx);
    }

    #[test]
    fn test_cp_bytes() {
        let ctx = BigintCtx::<P2048>::new();
        test_cp_bytes_generic(&ctx);
    }

    #[test]
    fn test_epk_bytes() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_epk_bytes_generic(&ctx, plaintext);
    }

    #[test]
    fn test_encode_err() {
        let ctx = BigintCtx::<P2048>::new();
        let one: BigUint = One::one();
        let result = ctx.encode(&(ctx.exp_modulus() - one));
        assert!(result.is_err())
    }
}

/*
impl<P: BigintCtxParams> ToByteTree for BigintCtx<P> {
    fn to_byte_tree(&self) -> ByteTree {
        let ctx = P::new_ctx();
        let bytes: Vec<ByteTree> = vec![
            ctx.params.generator().to_byte_tree(),
            ctx.params.modulus().to_byte_tree(),
            ctx.params.exp_modulus().to_byte_tree(),
            ctx.params.co_factor().to_byte_tree(),
        ];
        ByteTree::Tree(bytes)
    }
}

impl<P: BigintCtxParams> FromByteTree for BigintCtx<P> {
    fn from_byte_tree(tree: &ByteTree) -> Result<BigintCtx<P>, ByteError> {
        let trees = tree.tree(4)?;
        let generator = BigUint::from_byte_tree(&trees[0])?;
        let modulus = BigUint::from_byte_tree(&trees[1])?;
        let exp_modulus = BigUint::from_byte_tree(&trees[2])?;
        let co_factor = BigUint::from_byte_tree(&trees[3])?;

        let params = P::new();
        assert_eq!(&generator, params.generator());
        assert_eq!(&modulus, params.modulus());
        assert_eq!(&exp_modulus, params.exp_modulus());
        assert_eq!(&co_factor, params.co_factor());

        let ctx = BigintCtx { params };
        Ok(&ctx)
    }
}*/
