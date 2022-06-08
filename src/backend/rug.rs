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

use crate::backend::constants::*;
use crate::byte_tree::ByteTree::Leaf;
use crate::byte_tree::*;
use crate::context::{Ctx, Element, Exponent};
use crate::rnd::StrandRng;
use crate::zkp::ZKProver;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct RugCtx<P: RugCtxParams> {
    params: P,
}

impl<P: RugCtxParams> RugCtx<P> {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf A.2.3
    fn generators_fips(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Integer> {
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
                let elem: Integer = self.hash_to(&next);
                let g =
                    Element::<RugCtx<P>>::mod_pow(&elem, &self.params.co_factor(), &self.modulus());
                if g >= two {
                    ret.push(g);
                    break;
                }
            }
        }

        ret
    }
}

impl<P: RugCtxParams> Ctx for RugCtx<P> {
    type E = Integer;
    type X = Integer;
    type P = Integer;

    #[inline(always)]
    fn generator(&self) -> &Integer {
        self.params.generator()
    }
    #[inline(always)]
    fn gmod_pow(&self, other: &Integer) -> Integer {
        Element::<RugCtx<P>>::mod_pow(self.generator(), other, self.modulus())
    }
    #[inline(always)]
    fn emod_pow(&self, base: &Integer, exponent: &Integer) -> Integer {
        Element::<RugCtx<P>>::mod_pow(base, exponent, self.modulus())
    }
    #[inline(always)]
    fn modulus(&self) -> &Integer {
        &self.params.modulus()
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &Integer {
        &self.params.exp_modulus()
    }
    #[inline(always)]
    fn rnd(&self) -> Integer {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        self.encode(&self.exp_modulus().clone().random_below(&mut state))
            .unwrap()
    }
    #[inline(always)]
    fn rnd_exp(&self) -> Integer {
        let mut gen = StrandRandgen(StrandRng);
        let mut state = RandState::new_custom(&mut gen);

        self.exp_modulus().clone().random_below(&mut state)
    }
    fn rnd_plaintext(&self) -> Integer {
        self.rnd_exp()
    }
    fn encode(&self, plaintext: &Integer) -> Result<Integer, &'static str> {
        if plaintext >= &(self.exp_modulus().clone() - 1) {
            return Err("Failed to encode, out of range");
        }
        if plaintext < &0 {
            return Err("Failed to encode, negative");
        }

        let notzero: Integer = plaintext.clone() + 1;
        let legendre = notzero.legendre(self.modulus());
        if legendre == 0 {
            return Err("Failed to encode, legendre = 0");
        }
        let product = legendre * notzero;

        Ok(Element::<RugCtx<P>>::modulo(&product, self.modulus()))
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
    /* fn gen_key(&self) -> PrivateKey<Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }*/

    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Integer> {
        self.generators_fips(size, contest, seed)
    }

    fn is_valid_element(&self, element: &Self::E) -> bool {
        element.legendre(self.modulus()) == 1
    }

    fn new() -> RugCtx<P> {
        let params = P::new();
        RugCtx { params }
    }
}

impl<P: RugCtxParams> Element<RugCtx<P>> for Integer {
    fn mul(&self, other: &Self) -> Self {
        Integer::from(self * other)
    }
    fn div(&self, other: &Self, modulus: &Self) -> Self {
        let inverse = Element::<RugCtx<P>>::inv(other, modulus);
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

impl<P: RugCtxParams> Exponent<RugCtx<P>> for Integer {
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

impl<P: RugCtxParams> ZKProver<RugCtx<P>> for RugCtx<P> {
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf).div_rem(self.modulus().clone());

        rem
    }

    fn ctx(&self) -> &RugCtx<P> {
        self
    }
}

use crate::zkp::{Zkp, Zkpr};

impl<P: RugCtxParams> Zkpr<RugCtx<P>> for Zkp<RugCtx<P>> {
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) =
            Integer::from_digits(&hashed, Order::Lsf).div_rem(self.ctx.modulus().clone());

        rem
    }

    fn ctx(&self) -> &RugCtx<P> {
        &self.ctx
    }
}

pub trait RugCtxParams: Clone + Send + Sync {
    fn generator(&self) -> &Integer;
    fn modulus(&self) -> &Integer;
    fn exp_modulus(&self) -> &Integer;
    fn co_factor(&self) -> &Integer;
    fn new() -> Self;
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct P2048 {
    generator: Integer,
    modulus: Integer,
    exp_modulus: Integer,
    co_factor: Integer,
}
impl RugCtxParams for P2048 {
    #[inline(always)]
    fn generator(&self) -> &Integer {
        &self.generator
    }
    #[inline(always)]
    fn modulus(&self) -> &Integer {
        &self.modulus
    }
    #[inline(always)]
    fn exp_modulus(&self) -> &Integer {
        &self.exp_modulus
    }
    #[inline(always)]
    fn co_factor(&self) -> &Integer {
        &self.co_factor
    }
    fn new() -> P2048 {
        let p = Integer::from_str_radix(P_STR_2048, 16).unwrap();
        let q = Integer::from_str_radix(Q_STR_2048, 16).unwrap();
        let g = Integer::from_str_radix(G_STR_2048, 16).unwrap();
        let co_factor = Integer::from_str_radix(SAFEPRIME_COFACTOR, 16).unwrap();
        assert!(g.legendre(&p) == 1);

        P2048 {
            generator: g,
            modulus: p,
            exp_modulus: q,
            co_factor,
        }
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
    use crate::elgamal::PrivateKey;
    use crate::elgamal::{Ciphertext, PublicKey};
    use crate::shuffler::gen_permutation;
    use crate::shuffler::PermutationData;
    use crate::shuffler::Shuffler;
    use crate::threshold::tests::test_threshold_generic;
    use serde::Serialize;

    #[test]
    fn test_elgamal() {
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_elgamal_generic(&ctx, plaintext);
    }

    #[test]
    fn test_schnorr() {
        let ctx = RugCtx::<P2048>::new();
        test_schnorr_generic(&ctx);
    }

    #[test]
    fn test_chaumpedersen() {
        let ctx = RugCtx::<P2048>::new();
        test_chaumpedersen_generic(&ctx);
    }

    #[test]
    fn test_vdecryption() {
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_vdecryption_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed() {
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_distributed_generic(&ctx, plaintext);
    }

    #[test]
    fn test_distributed_btserde() {
        let ctx = RugCtx::<P2048>::new();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = ctx.rnd_exp();
            ps.push(p);
        }
        test_distributed_btserde_generic(&ctx, ps);
    }

    #[test]
    fn test_shuffle() {
        let ctx = RugCtx::<P2048>::new();
        test_shuffle_generic(&ctx);
    }

    #[test]
    fn test_shuffle_btserde() {
        let ctx = RugCtx::<P2048>::new();
        test_shuffle_btserde_generic(&ctx);
    }

    #[test]
    fn test_encrypted_sk() {
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_encrypted_sk_generic(&ctx, plaintext);
    }

    #[test]
    fn test_threshold() {
        let trustees = 5usize;
        let threshold = 3usize;
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();

        test_threshold_generic(&ctx, trustees, threshold, plaintext);
    }

    #[test]
    fn test_ciphertext_bytes() {
        let ctx = RugCtx::<P2048>::new();
        test_ciphertext_bytes_generic(&ctx);
    }

    #[test]
    fn test_key_bytes() {
        let ctx = RugCtx::<P2048>::new();
        test_key_bytes_generic(&ctx);
    }

    #[test]
    fn test_schnorr_bytes() {
        let ctx = RugCtx::<P2048>::new();
        test_schnorr_bytes_generic(&ctx);
    }

    #[test]
    fn test_cp_bytes() {
        let ctx = RugCtx::<P2048>::new();
        test_cp_bytes_generic(&ctx);
    }

    #[test]
    fn test_epk_bytes() {
        let ctx = RugCtx::<P2048>::new();
        let plaintext = ctx.rnd_exp();
        test_epk_bytes_generic(&ctx, plaintext);
    }

    #[test]
    fn test_encode_err() {
        let ctx = RugCtx::<P2048>::new();
        let result = ctx.encode(&(ctx.exp_modulus() - 1i32).complete());
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
        let ctx = RugCtx::<P2048>::new();

        let sk = PrivateKey::gen(&ctx);
        let pk = sk.get_public();

        let n = 100;
        let mut es: Vec<Ciphertext<RugCtx<P2048>>> = Vec::with_capacity(n);

        for _ in 0..n {
            let plaintext: Integer = ctx.rnd_plaintext();
            let c = pk.encrypt(&plaintext);
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
            ctx.generator().to_string_radix(16),
            pk.value.to_string_radix(16),
        ];

        let hs_list: Vec<String> = hs.iter().map(|h| h.to_string_radix(16)).collect();
        let h_list = vec![vec![hs_list[0].clone()], hs_list[1..].to_vec()];

        let cs = proof.cs;
        let cs_list: Vec<String> = cs.iter().map(|c| c.to_string_radix(16)).collect();

        let c_hats: Vec<String> = proof.c_hats.iter().map(|c| c.to_string_radix(16)).collect();
        let t3 = proof.t.t3.to_string_radix(16);
        let t_hats: Vec<String> = proof
            .t
            .t_hats
            .iter()
            .map(|c| c.to_string_radix(16))
            .collect();
        let t1 = proof.t.t1.to_string_radix(16);
        let t2 = proof.t.t2.to_string_radix(16);
        let t4_1 = proof.t.t4_1.to_string_radix(16);
        let t4_2 = proof.t.t4_2.to_string_radix(16);

        let t_list = vec![
            c_hats,
            vec![t3],
            t_hats,
            vec![t1],
            vec![t2],
            vec![t4_1, t4_2],
        ];

        let ciphers_in_a: Vec<String> = es.iter().map(|c| c.mhr.to_string_radix(16)).collect();
        let ciphers_in_b: Vec<String> = es.iter().map(|c| c.gr.to_string_radix(16)).collect();

        let ciphers_out_a: Vec<String> =
            e_primes.iter().map(|c| c.mhr.to_string_radix(16)).collect();
        let ciphers_out_b: Vec<String> =
            e_primes.iter().map(|c| c.gr.to_string_radix(16)).collect();

        let ciphers_in = vec![ciphers_in_a, ciphers_in_b];
        let ciphers_out = vec![ciphers_out_a, ciphers_out_b];

        let s1 = proof.s.s1.to_string_radix(16);
        let s2 = proof.s.s2.to_string_radix(16);
        let s3 = proof.s.s3.to_string_radix(16);
        let s4 = proof.s.s4.to_string_radix(16);
        let s_hats: Vec<String> = proof
            .s
            .s_hats
            .iter()
            .map(|c| c.to_string_radix(16))
            .collect();
        let s_primes: Vec<String> = proof
            .s
            .s_primes
            .iter()
            .map(|c| c.to_string_radix(16))
            .collect();

        let s_list = vec![vec![s3], s_hats, vec![s1], vec![s2], s_primes, vec![s4]];

        let us_list: Vec<String> = us.iter().map(|u| u.to_string_radix(16)).collect();
        let challenge: Vec<String> = vec![c.to_string_radix(16)];

        let group = vec![
            ctx.modulus().to_string_radix(16),
            ctx.exp_modulus().to_string_radix(16),
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
