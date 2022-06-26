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
    fn generators_fips(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<BigUintE> {
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
                let elem: BigUint = self.hash_to_element(&next);
                let g = elem.modpow(self.params.co_factor(), &self.modulus().0);
                if g >= two {
                    ret.push(BigUintE(g));
                    break;
                }
            }
        }

        ret
    }

    fn hash_to_element(&self, bytes: &[u8]) -> BigUint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        num.mod_floor(&self.params.modulus().0)
    }
}

impl<P: BigintCtxParams> Ctx for BigintCtx<P> {
    type E = BigUintE;
    type X = BigUintX;
    type P = BigUint;

    #[inline(always)]
    fn generator(&self) -> &Self::E {
        self.params.generator()
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &Self::X) -> Self::E {
        BigUintE(self.generator().0.modpow(&other.0, &self.modulus().0))
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Self::E, exponent: &Self::X) -> Self::E {
        BigUintE(base.0.modpow(&exponent.0, &self.modulus().0))
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
        let mut gen = StrandRng;
        let one: BigUint = One::one();
        let unencoded = gen.gen_biguint_below(&(&self.exp_modulus().0 - one));

        self.encode(&unencoded)
            .expect("0..(q-1) should always be encodable")
    }
    #[inline(always)]
    fn rnd_exp(&self) -> Self::X {
        let mut gen = StrandRng;
        BigUintX(gen.gen_biguint_below(&self.exp_modulus().0))
    }
    fn rnd_plaintext(&self) -> Self::P {
        self.rnd_exp().0
    }
    fn hash_to(&self, bytes: &[u8]) -> Self::X {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        BigUintX(num.mod_floor(&self.exp_modulus().0))
    }
    fn encode(&self, plaintext: &Self::P) -> Result<Self::E, &'static str> {
        let one: BigUint = One::one();

        if plaintext >= &(&self.exp_modulus().0 - &one) {
            return Err("Failed to encode, out of range");
        }
        let notzero: BigUint = plaintext + one;
        let legendre = notzero.legendre(&self.modulus().0);
        if legendre == 0 {
            return Err("Failed to encode, legendre = 0");
        }
        let result = if legendre == 1 {
            notzero
        } else {
            &self.modulus().0 - notzero
        };
        Ok(BigUintE(BigUint::mod_floor(&result, &self.modulus().0)))
    }
    fn decode(&self, element: &Self::E) -> Self::P {
        let one: BigUint = One::one();
        if element.0 > self.exp_modulus().0 {
            (&self.modulus().0 - &element.0) - one
        } else {
            &element.0 - one
        }
    }
    fn exp_from_u64(&self, value: u64) -> Self::X {
        BigUintX(BigUint::from(value))
    }
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Self::E> {
        self.generators_fips(size, contest, seed)
    }
    fn is_valid_element(&self, element: &Self::E) -> bool {
        element.0.legendre(&self.modulus().0) == 1
    }
    fn element_from_bytes(&self, bytes: &[u8]) -> Result<Self::E, &'static str> {
        let ret = BigUint::from_bytes_be(bytes);
        Ok(BigUintE(ret))
    }
    fn exp_from_bytes(&self, bytes: &[u8]) -> Result<Self::X, &'static str> {
        let ret = BigUint::from_bytes_be(bytes);
        Ok(BigUintX(ret))
    }
    fn new() -> BigintCtx<P> {
        let params = P::new();
        BigintCtx { params }
    }
}

impl<P: BigintCtxParams> Element<BigintCtx<P>> for BigUintE {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        BigUintE(&self.0 * &other.0)
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::<BigintCtx<P>>::inv(other, modulus);
        BigUintE(&self.0 * inverse.0)
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        let inverse = (&self.0).invm(&modulus.0);
        BigUintE(inverse
            .expect("there is always an inverse for prime p"))
    }
    #[inline(always)]
    fn mod_pow(&self, other: &BigUintX, modulus: &Self) -> Self {
        BigUintE(self.0.modpow(&other.0, &modulus.0))
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        BigUintE(self.0.mod_floor(&modulus.0))
    }
    fn mul_identity() -> Self {
        BigUintE(One::one())
    }
}

impl<P: BigintCtxParams> Exponent<BigintCtx<P>> for BigUintX {
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        BigUintX(&self.0 + &other.0)
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        BigUintX(&self.0 - &other.0)
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        BigUintX(&self.0 * &other.0)
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Exponent::<BigintCtx<P>>::inv(other, modulus);
        BigUintX(&self.0 * inverse.0)
    }
    #[inline(always)]
    fn inv(&self, modulus: &Self) -> Self {
        let inverse = (&self.0).invm(&modulus.0);
        BigUintX(inverse
            .expect("there is always an inverse for prime p"))
    }
    #[inline(always)]
    fn modulo(&self, modulus: &Self) -> Self {
        BigUintX(self.0.mod_floor(&modulus.0))
    }
    fn add_identity() -> Self {
        BigUintX(Zero::zero())
    }
    fn mul_identity() -> Self {
        BigUintX(One::one())
    }
}

pub trait BigintCtxParams: Clone + Send + Sync {
    fn generator(&self) -> &BigUintE;
    fn modulus(&self) -> &BigUintE;
    fn exp_modulus(&self) -> &BigUintX;
    fn co_factor(&self) -> &BigUint;
    fn new() -> Self;
}
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct P2048 {
    generator: BigUintE,
    modulus: BigUintE,
    exp_modulus: BigUintX,
    co_factor: BigUint,
}
impl BigintCtxParams for P2048 {
    #[inline(always)]
    fn generator(&self) -> &BigUintE {
        &self.generator
    }
    #[inline(always)]
    fn modulus(&self) -> &BigUintE {
        &self.modulus
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &BigUintX {
        &self.exp_modulus
    }
    #[inline(always)]
    fn co_factor(&self) -> &BigUint {
        &self.co_factor
    }
    fn new() -> P2048 {
        let p = BigUintE(BigUint::from_str_radix(P_VERIFICATUM_STR_2048, 10).unwrap());
        let q = BigUintX(BigUint::from_str_radix(Q_VERIFICATUM_STR_2048, 10).unwrap());
        let g = BigUintE(BigUint::from_str_radix(G_VERIFICATUM_STR_2048, 10).unwrap());
        let co_factor = BigUint::from_str_radix(SAFEPRIME_COFACTOR, 16).unwrap();
        /*
        FIXME revert to this, seems slightly faster due to small generator
        let p = BigUint::from_str_radix(P_STR_2048, 16).unwrap();
        let q = BigUint::from_str_radix(Q_STR_2048, 16).unwrap();
        let g = BigUint::from_str_radix(G_STR_2048, 16).unwrap();*/

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
pub struct BigUintE(BigUint);
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct BigUintX(BigUint);

impl ToByteTree for BigUintE {
    fn to_byte_tree(&self) -> ByteTree {
        // Leaf(DataType::Element, ByteBuf::from(self.to_bytes_be()))
        Leaf(ByteBuf::from(self.0.to_bytes_be()))
    }
}

impl<P: BigintCtxParams> FromByteTree<BigintCtx<P>> for BigUintE {
    fn from_byte_tree(tree: &ByteTree, ctx: &BigintCtx<P>) -> Result<BigUintE, ByteError> {
        let bytes = tree.leaf()?;
        ctx.element_from_bytes(bytes).map_err(ByteError::Msg)
    }
}

impl ToByteTree for BigUintX {
    fn to_byte_tree(&self) -> ByteTree {
        // Leaf(DataType::Exponent, ByteBuf::from(self.to_bytes_be()))
        Leaf(ByteBuf::from(self.0.to_bytes_be()))
    }
}

impl<P: BigintCtxParams> FromByteTree<BigintCtx<P>> for BigUintX {
    fn from_byte_tree(tree: &ByteTree, ctx: &BigintCtx<P>) -> Result<BigUintX, ByteError> {
        let bytes = tree.leaf()?;
        ctx.exp_from_bytes(bytes).map_err(ByteError::Msg)
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
        let plaintext = ctx.rnd_plaintext();
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
        let plaintext = ctx.rnd_plaintext();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_plaintext();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_btserde() {
        let ctx = BigintCtx::<P2048>::new();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_plaintext();
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
        let plaintext = ctx.rnd_plaintext();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = BigintCtx::<P2048>::new();
        let plaintext = ctx.rnd_plaintext();

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
        let plaintext = ctx.rnd_plaintext();
        test_epk_bytes_generic(&ctx, plaintext);
    }

    #[test]
    fn test_encode_err() {
        let ctx = BigintCtx::<P2048>::new();
        let one: BigUint = One::one();
        let result = ctx.encode(&(&ctx.exp_modulus().0 - one));
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
