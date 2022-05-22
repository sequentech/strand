use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Num;
use num_traits::{One, Zero};

use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::*;
use crate::zkp::ZKProver;
use ed25519_dalek::{Digest, Sha512};

use crate::rnd::StrandRng;
use num_bigint::RandBigInt;
use num_modular::{ModularSymbols, ModularUnaryOps};
use serde_bytes::ByteBuf;

// https://github.com/bfh-evg/unicrypt/blob/2c9b223c1abc6266aa56ace5562200a5050a0c2a/src/main/java/ch/bfh/unicrypt/helper/prime/SafePrime.java
const P_STR_2048: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063";
const Q_STR_2048: &str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";
// const P_STR_3072: &'static str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7";
// const Q_STR_3072: &'static str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf3380470c368df93adcd920ef5b23a4d23efefdcb31961f5830db2395dfc26130a2724e1682619277886f289e9fa88a5c5ae9ba6c9e5c43ce3ea97feb95d0557393bed3dd0da578a446c741b578a432f361bd5b43b7f3485ab88909c1579a0d7f4a7bbde783641dc7fab3af84bc83a56cd3c3de2dcdea5862c9be9f6f261d3c9cb20ce6b";

lazy_static! {
    static ref BCTX: BigintCtx = BigintCtx::default();
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct BigintCtx {
    pub generator: BigUint,
    pub modulus: BigUint,
    pub modulus_exp: BigUint,
    pub co_factor: BigUint,
}

impl BigintCtx {
    pub fn default() -> BigintCtx {
        let p = BigUint::from_str_radix(P_STR_2048, 16).unwrap();
        let q = BigUint::from_str_radix(Q_STR_2048, 16).unwrap();
        let g = BigUint::from(3u32);
        let co_factor = BigUint::from(2u32);

        assert!(g.legendre(&p) == 1);

        BigintCtx {
            generator: g,
            modulus: p,
            modulus_exp: q,
            co_factor,
        }
    }

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
                let g = elem.modpow(&self.co_factor, self.modulus());
                if g >= two {
                    ret.push(g);
                    break;
                }
            }
        }

        ret
    }
}

impl Ctx for BigintCtx {
    type E = BigUint;
    type X = BigUint;
    type P = BigUint;

    #[inline(always)]
    fn generator(&self) -> &BigUint {
        &self.generator
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &BigUint) -> BigUint {
        self.generator.modpow(other, self.modulus())
    }
    #[inline(always)]
    fn emod_pow(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        base.modpow(exponent, self.modulus())
    }
    #[inline(always)]
    fn modulus(&self) -> &BigUint {
        &self.modulus
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &BigUint {
        &self.modulus_exp
    }
    #[inline(always)]
    fn rnd(&self) -> BigUint {
        let mut gen = StrandRng;
        let unencoded = gen.gen_biguint_below(self.exp_modulus());

        self.encode(&unencoded)
    }
    #[inline(always)]
    fn rnd_exp(&self) -> BigUint {
        let mut gen = StrandRng;
        gen.gen_biguint_below(self.exp_modulus())
    }
    fn rnd_plaintext(&self) -> BigUint {
        self.rnd_exp()
    }
    fn encode(&self, plaintext: &BigUint) -> BigUint {
        let one: BigUint = One::one();
        assert!(plaintext < &(self.modulus_exp.clone() - one.clone()));
        let notzero: BigUint = plaintext + one;
        let legendre = notzero.legendre(self.modulus());
        assert_ne!(legendre, 0);
        let result = if legendre == 1 {
            notzero
        } else {
            self.modulus() - notzero
        };
        BigUint::mod_floor(&result, self.modulus())
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
    fn gen_key(&self) -> PrivateKey<BigintCtx> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }

    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<BigUint> {
        self.generators_fips(size, contest, seed)
    }
    #[inline(always)]
    fn get() -> &'static BigintCtx {
        &BCTX
    }
}

impl ZKProver<BigintCtx> for BigintCtx {
    fn hash_to(&self, bytes: &[u8]) -> BigUint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let num = BigUint::from_bytes_be(&hashed);
        num.mod_floor(self.modulus())
    }
}

impl Element<BigintCtx> for BigUint {
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        self * other
    }
    #[inline(always)]
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::<BigintCtx>::inv(other, modulus);
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

impl Exponent<BigintCtx> for BigUint {
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
        let inverse = Exponent::<BigintCtx>::inv(other, modulus);
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

impl ToByteTree for BigintCtx {
    fn to_byte_tree(&self) -> ByteTree {
        let bytes: Vec<ByteTree> = vec![
            self.generator.to_byte_tree(),
            self.modulus.to_byte_tree(),
            self.modulus_exp.to_byte_tree(),
            self.co_factor.to_byte_tree(),
        ];
        ByteTree::Tree(bytes)
    }
}

impl FromByteTree for BigintCtx {
    fn from_byte_tree(tree: &ByteTree) -> Result<BigintCtx, ByteError> {
        let trees = tree.tree(4)?;
        let generator = BigUint::from_byte_tree(&trees[0])?;
        let modulus = BigUint::from_byte_tree(&trees[1])?;
        let modulus_exp = BigUint::from_byte_tree(&trees[2])?;
        let co_factor = BigUint::from_byte_tree(&trees[3])?;

        let ctx = BigintCtx {
            generator,
            modulus,
            modulus_exp,
            co_factor,
        };

        Ok(ctx)
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
    use crate::backend::num_bigint::BigintCtx;
    use crate::backend::tests::*;
    use crate::context::Ctx;
    use crate::threshold::tests::test_threshold_generic;

    #[test]
    fn test_elgamal() {
        let ctx = BigintCtx::default();
        let plaintext = ctx.rnd_exp();
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let ctx = BigintCtx::default();
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = BigintCtx::default();
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let ctx = BigintCtx::default();
        let plaintext = ctx.rnd_exp();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = BigintCtx::default();
        let plaintext = ctx.rnd_exp();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_btserde() {
        let ctx = BigintCtx::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_exp();
            ps.push(p);
        }
        test_distributed_btserde_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = BigintCtx::default();
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_btserde() {
        let ctx = BigintCtx::default();
        test_shuffle_btserde_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let ctx = BigintCtx::default();
        let plaintext = ctx.rnd_exp();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = BigintCtx::default();
        let plaintext = ctx.rnd_exp();

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }
}
