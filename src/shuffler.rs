#![allow(clippy::type_complexity)]
use borsh::{BorshDeserialize, BorshSerialize};
// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
use ed25519_dalek::{Digest, Sha512};
use rand::Rng;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use std::sync::Mutex;

use crate::serialization::StrandSerialize;
use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::{Ciphertext, PublicKey};
use crate::rnd::StrandRng;
use crate::util::Par;
use crate::zkp::ChallengeInput;

pub(crate) struct YChallengeInput<'a, C: Ctx> {
    pub es: &'a [Ciphertext<C>],
    pub e_primes: &'a [Ciphertext<C>],
    pub cs: &'a [C::E],
    pub c_hats: &'a [C::E],
    pub pk: &'a PublicKey<C>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Commitments<C: Ctx> {
    pub t1: C::E,
    pub t2: C::E,
    pub t3: C::E,
    pub t4_1: C::E,
    pub t4_2: C::E,
    pub t_hats: Vec<C::E>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Responses<C: Ctx> {
    pub(crate) s1: C::X,
    pub(crate) s2: C::X,
    pub(crate) s3: C::X,
    pub(crate) s4: C::X,
    pub(crate) s_hats: Vec<C::X>,
    pub(crate) s_primes: Vec<C::X>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ShuffleProof<C: Ctx> {
    // proof commitment
    pub(crate) t: Commitments<C>,
    // proof response
    pub(crate) s: Responses<C>,
    // permutation commitment
    pub(crate) cs: Vec<C::E>,
    // commitment chain
    pub(crate) c_hats: Vec<C::E>,
}

pub(super) struct PermutationData<'a, C: Ctx> {
    pub(crate) permutation: &'a [usize],
    pub(crate) commitments_c: &'a [C::E],
    pub(crate) commitments_r: &'a [C::X],
}

pub struct Shuffler<'a, C: Ctx> {
    pub(crate) pk: &'a PublicKey<C>,
    pub(crate) generators: &'a Vec<C::E>,
    pub(crate) ctx: C,
}

impl<'a, C: Ctx> Shuffler<'a, C> {
    pub fn new(pk: &'a PublicKey<C>, generators: &'a Vec<C::E>, ctx: &C) -> Shuffler<'a, C> {
        Shuffler {
            pk,
            generators,
            ctx: (*ctx).clone(),
        }
    }

    pub fn gen_shuffle(
        &self,
        ciphertexts: &[Ciphertext<C>],
    ) -> (Vec<Ciphertext<C>>, Vec<C::X>, Vec<usize>) {
        let perm: Vec<usize> = gen_permutation(ciphertexts.len());
        let (result, rs) = self.apply_permutation(&perm, ciphertexts);

        (result, rs, perm)
    }

    pub fn apply_permutation(
        &self,
        perm: &[usize],
        ciphertexts: &[Ciphertext<C>],
    ) -> (Vec<Ciphertext<C>>, Vec<C::X>) {
        assert!(perm.len() == ciphertexts.len());

        let rs_temp: Vec<Option<C::X>> = vec![None; ciphertexts.len()];
        let rs_mutex = Mutex::new(rs_temp);
        let ctx = &self.ctx;
        let length = perm.len();

        let e_primes = perm
            .par()
            .map(|p| {
                let c = &ciphertexts[*p];

                let r = ctx.rnd_exp();

                let a = c
                    .mhr
                    .mul(&self.pk.element.mod_pow(&r, ctx.modulus()))
                    .modulo(ctx.modulus());
                let b = c.gr.mul(&ctx.gmod_pow(&r)).modulo(ctx.modulus());

                let c_ = Ciphertext { mhr: a, gr: b };
                rs_mutex.lock().unwrap()[*p] = Some(r);
                c_
            })
            .collect();

        let mut rs = Vec::with_capacity(ciphertexts.len());

        let mut rs_ = rs_mutex.lock().unwrap();
        for _ in 0..length {
            let r = rs_.remove(0);
            rs.push(r.unwrap());
        }

        (e_primes, rs)
    }

    pub fn gen_proof(
        &self,
        es: &[Ciphertext<C>],
        e_primes: &[Ciphertext<C>],
        r_primes: &[C::X],
        perm: &[usize],
        label: &[u8],
    ) -> ShuffleProof<C> {
        // let now = Instant::now();
        let (cs, rs) = self.gen_commitments(perm, &self.ctx);
        // println!("gen_commitments {}", now.elapsed().as_millis());

        let perm_data = PermutationData {
            permutation: perm,
            commitments_c: &cs,
            commitments_r: &rs,
        };

        // let now = Instant::now();
        let transcript = self.gen_proof_ext(es, e_primes, r_primes, &perm_data, label);
        // println!("gen_proof_ext {}", now.elapsed().as_millis());

        transcript.0
    }

    // gen_proof_ext has support for
    // 1. Returns extra transcript data used in coq test
    // 2. Allows passing in permutation data for multi-shuffling
    pub(super) fn gen_proof_ext(
        &self,
        es: &[Ciphertext<C>],
        e_primes: &[Ciphertext<C>],
        r_primes: &[C::X],
        perm_data: &PermutationData<C>,
        label: &[u8],
    ) -> (ShuffleProof<C>, Vec<C::X>, C::X) {
        let ctx = &self.ctx;

        #[allow(non_snake_case)]
        let N = es.len();

        let h_generators = &self.generators[1..];
        let h_initial = &self.generators[0];

        assert!(N == e_primes.len());
        assert!(N == r_primes.len());
        assert!(N == perm_data.permutation.len());
        assert!(N == h_generators.len());
        assert!(N > 0, "cannot shuffle 0 ciphertexts");

        let gmod = ctx.modulus();
        let xmod = ctx.exp_modulus();

        let (cs, rs) = (perm_data.commitments_c, perm_data.commitments_r);
        let perm = perm_data.permutation;

        // COST
        // let now = Instant::now();
        let us = self.shuffle_proof_us(es, e_primes, cs, N, label);
        // println!("shuffle proof us {}", now.elapsed().as_millis());

        let mut u_primes: Vec<&C::X> = Vec::with_capacity(N);
        for &i in perm.iter() {
            u_primes.push(&us[i]);
        }

        // COST
        // let now = Instant::now();

        let (c_hats, r_hats) = self.gen_commitment_chain(h_initial, &u_primes, ctx);

        // println!("gen commitment chain {}", now.elapsed().as_millis());

        // 0 cost *
        let mut vs = vec![C::X::mul_identity(); N];
        for i in (0..N - 1).rev() {
            vs[i] = u_primes[i + 1].mul(&vs[i + 1]).modulo(xmod);
        }

        let mut r_bar = C::X::add_identity();
        let mut r_hat: C::X = C::X::add_identity();
        let mut r_tilde: C::X = C::X::add_identity();
        let mut r_prime: C::X = C::X::add_identity();

        // let now = Instant::now();
        // 0 cost
        for i in 0..N {
            r_bar = r_bar.add(&rs[i]);
            r_hat = r_hat.add(&r_hats[i].mul(&vs[i]));
            r_tilde = r_tilde.add(&rs[i].mul(&us[i]));
            r_prime = r_prime.add(&r_primes[i].mul(&us[i]));
        }

        // println!("v4 {}", now.elapsed().as_millis());

        r_bar = r_bar.modulo(xmod);
        r_hat = r_hat.modulo(xmod);
        r_tilde = r_tilde.modulo(xmod);
        r_prime = r_prime.modulo(xmod);

        let omegas: Vec<C::X> = (0..4).map(|_| ctx.rnd_exp()).collect();
        let omega_hats: Vec<C::X> = (0..N).map(|_| ctx.rnd_exp()).collect();
        let omega_primes: Vec<C::X> = (0..N).map(|_| ctx.rnd_exp()).collect();

        let t1 = ctx.gmod_pow(&omegas[0]);
        let t2 = ctx.gmod_pow(&omegas[1]);

        let mut t3_temp = C::E::mul_identity();
        let mut t4_1_temp = C::E::mul_identity();
        let mut t4_2_temp = C::E::mul_identity();

        // fixed base exponentiation OPT 1
        let values: Vec<(C::E, C::E, C::E)> = (0..N)
            .par()
            .map(|i| {
                (
                    h_generators[i].mod_pow(&omega_primes[i], gmod),
                    e_primes[i].mhr.mod_pow(&omega_primes[i], gmod),
                    e_primes[i].gr.mod_pow(&omega_primes[i], gmod),
                )
            })
            .collect();

        // ~0 cost *
        for value in values.iter().take(N) {
            t3_temp = t3_temp.mul(&value.0).modulo(gmod);
            t4_1_temp = t4_1_temp.mul(&value.1).modulo(gmod);
            t4_2_temp = t4_2_temp.mul(&value.2).modulo(gmod);
        }

        let t3 = (ctx.gmod_pow(&omegas[2])).mul(&t3_temp).modulo(gmod);
        let t4_1 = (self.pk.element.inv(gmod).mod_pow(&omegas[3], gmod))
            .mul(&t4_1_temp)
            .modulo(gmod);
        let t4_2 = (ctx.generator().inv(gmod).mod_pow(&omegas[3], gmod))
            .mul(&t4_2_temp)
            .modulo(gmod);

        // fixed base exponentiation OPT 2
        let t_hats = (0..c_hats.len())
            .par()
            .map(|i| {
                let previous_c = if i == 0 { h_initial } else { &c_hats[i - 1] };

                (ctx.gmod_pow(&omega_hats[i]))
                    .mul(&previous_c.mod_pow(&omega_primes[i], gmod))
                    .modulo(gmod)
            })
            .collect();

        let y = YChallengeInput {
            es,
            e_primes,
            cs,
            c_hats: &c_hats,
            pk: self.pk,
        };

        let t = Commitments {
            t1,
            t2,
            t3,
            t4_1,
            t4_2,
            t_hats,
        };

        // COST
        // let now = Instant::now();
        // ~0 cost
        let c: C::X = self.shuffle_proof_challenge(&y, &t, label);

        // println!("shuffle proof challenge {}", now.elapsed().as_millis());

        let s1 = omegas[0].add(&c.mul(&r_bar)).modulo(xmod);
        let s2 = omegas[1].add(&c.mul(&r_hat)).modulo(xmod);
        let s3 = omegas[2].add(&c.mul(&r_tilde)).modulo(xmod);
        let s4 = omegas[3].add(&c.mul(&r_prime)).modulo(xmod);

        let mut s_hats: Vec<C::X> = Vec::with_capacity(N);
        let mut s_primes: Vec<C::X> = Vec::with_capacity(N);

        // 0 cost
        for i in 0..N {
            let next_s_hat = omega_hats[i].add(&c.mul(&r_hats[i])).modulo(xmod);
            let next_s_prime = omega_primes[i].add(&c.mul(u_primes[i])).modulo(xmod);

            s_hats.push(next_s_hat);
            s_primes.push(next_s_prime);
        }

        let s = Responses {
            s1,
            s2,
            s3,
            s4,
            s_hats,
            s_primes,
        };

        let cs = cs.to_vec();

        (ShuffleProof { t, s, cs, c_hats }, us, c)
    }

    pub fn check_proof(
        &self,
        proof: &ShuffleProof<C>,
        es: &[Ciphertext<C>],
        e_primes: &[Ciphertext<C>],
        label: &[u8],
    ) -> bool {
        let ctx = &self.ctx;

        #[allow(non_snake_case)]
        let N = es.len();

        let h_generators = &self.generators[1..];
        let h_initial = &self.generators[0];

        assert!(N == e_primes.len());
        assert!(N == h_generators.len());

        let gmod = ctx.modulus();
        let xmod = ctx.exp_modulus();

        let us: Vec<C::X> = self.shuffle_proof_us(es, e_primes, &proof.cs, N, label);

        let mut c_bar_num: C::E = C::E::mul_identity();
        let mut c_bar_den: C::E = C::E::mul_identity();
        let mut u: C::X = C::X::mul_identity();
        let mut c_tilde: C::E = C::E::mul_identity();
        let mut a_prime: C::E = C::E::mul_identity();
        let mut b_prime: C::E = C::E::mul_identity();

        let mut t_tilde3_temp: C::E = C::E::mul_identity();
        let mut t_tilde41_temp: C::E = C::E::mul_identity();
        let mut t_tilde42_temp: C::E = C::E::mul_identity();

        let values: Vec<(C::E, C::E, C::E, C::E, C::E, C::E)> = (0..N)
            .par()
            .map(|i| {
                (
                    proof.cs[i].mod_pow(&us[i], gmod),
                    es[i].mhr.mod_pow(&us[i], gmod),
                    es[i].gr.mod_pow(&us[i], gmod),
                    h_generators[i].mod_pow(&proof.s.s_primes[i], gmod),
                    e_primes[i].mhr.mod_pow(&proof.s.s_primes[i], gmod),
                    e_primes[i].gr.mod_pow(&proof.s.s_primes[i], gmod),
                )
            })
            .collect();

        // let now = Instant::now();

        for i in 0..N {
            c_bar_num = c_bar_num.mul(&proof.cs[i]).modulo(gmod);
            c_bar_den = c_bar_den.mul(&h_generators[i]).modulo(gmod);
            u = u.mul(&us[i]).modulo(xmod);

            c_tilde = c_tilde.mul(&values[i].0).modulo(gmod);
            a_prime = a_prime.mul(&values[i].1).modulo(gmod);
            b_prime = b_prime.mul(&values[i].2).modulo(gmod);
            t_tilde3_temp = t_tilde3_temp.mul(&values[i].3).modulo(gmod);
            t_tilde41_temp = t_tilde41_temp.mul(&values[i].4).modulo(gmod);
            t_tilde42_temp = t_tilde42_temp.mul(&values[i].5).modulo(gmod);
        }

        // println!("v1 {}", now.elapsed().as_millis());

        let c_bar = c_bar_num.div(&c_bar_den, gmod).modulo(gmod);

        let c_hat = proof.c_hats[N - 1]
            .div(&h_initial.mod_pow(&u, gmod), gmod)
            .modulo(gmod);

        let y = YChallengeInput {
            es,
            e_primes,
            cs: &proof.cs,
            c_hats: &proof.c_hats,
            pk: self.pk,
        };

        let c = self.shuffle_proof_challenge(&y, &proof.t, label);

        let t_prime1 = (c_bar.inv(gmod).mod_pow(&c, gmod))
            .mul(&ctx.gmod_pow(&proof.s.s1))
            .modulo(gmod);

        let t_prime2 = (c_hat.inv(gmod).mod_pow(&c, gmod))
            .mul(&ctx.gmod_pow(&proof.s.s2))
            .modulo(gmod);

        let t_prime3 = (c_tilde.inv(gmod).mod_pow(&c, gmod))
            .mul(&ctx.gmod_pow(&proof.s.s3))
            .mul(&t_tilde3_temp)
            .modulo(gmod);

        let t_prime41 = (a_prime.inv(gmod).mod_pow(&c, gmod))
            .mul(&self.pk.element.inv(gmod).mod_pow(&proof.s.s4, gmod))
            .mul(&t_tilde41_temp)
            .modulo(gmod);

        let t_prime42 = (b_prime.inv(gmod).mod_pow(&c, gmod))
            .mul(&ctx.generator().inv(gmod).mod_pow(&proof.s.s4, gmod))
            .mul(&t_tilde42_temp)
            .modulo(gmod);

        // batch verification OPT 3a
        let t_hat_primes: Vec<C::E> = (0..N)
            .par()
            .map(|i| {
                let c_term = if i == 0 {
                    h_initial
                } else {
                    &proof.c_hats[i - 1]
                };

                let inverse = proof.c_hats[i].inv(gmod);
                (inverse.mod_pow(&c, gmod))
                    .mul(&ctx.gmod_pow(&proof.s.s_hats[i]))
                    .mul(&c_term.mod_pow(&proof.s.s_primes[i], gmod))
                    .modulo(gmod)
            })
            .collect();

        let mut checks = Vec::with_capacity(5 + N);
        checks.push(proof.t.t1.eq(&t_prime1));
        checks.push(proof.t.t2.eq(&t_prime2));
        checks.push(proof.t.t3.eq(&t_prime3));
        checks.push(proof.t.t4_1.eq(&t_prime41));
        checks.push(proof.t.t4_2.eq(&t_prime42));

        // batch verification OPT 3b
        for (i, t_hat) in proof.t.t_hats.iter().enumerate().take(N) {
            checks.push(t_hat.eq(&t_hat_primes[i]));
        }
        !checks.contains(&false)
    }

    pub(crate) fn gen_commitments(&self, perm: &[usize], ctx: &C) -> (Vec<C::E>, Vec<C::X>) {
        let generators = &self.generators[1..];

        assert!(generators.len() == perm.len());

        let rs: Vec<Option<C::X>> = vec![None; perm.len()];
        let cs: Vec<Option<C::E>> = vec![None; perm.len()];
        let rs_mutex = Mutex::new(rs);
        let cs_mutex = Mutex::new(cs);

        perm.par().enumerate().for_each(|(i, p)| {
            let r = ctx.rnd_exp();
            let c = generators[i].mul(&ctx.gmod_pow(&r)).modulo(ctx.modulus());

            rs_mutex.lock().unwrap()[*p] = Some(r);
            cs_mutex.lock().unwrap()[*p] = Some(c);
        });

        let mut ret1: Vec<C::E> = Vec::with_capacity(perm.len());
        let mut ret2: Vec<C::X> = Vec::with_capacity(perm.len());
        for _ in 0..perm.len() {
            let c = cs_mutex.lock().unwrap().remove(0);
            let r = rs_mutex.lock().unwrap().remove(0);

            ret1.push(c.unwrap());
            ret2.push(r.unwrap());
        }

        (ret1, ret2)
    }

    fn gen_commitment_chain(
        &self,
        initial: &C::E,
        us: &[&C::X],
        ctx: &C,
    ) -> (Vec<C::E>, Vec<C::X>) {
        let mut cs: Vec<C::E> = Vec::with_capacity(us.len());

        let (firsts, rs): (Vec<C::E>, Vec<C::X>) = (0..us.len())
            .par()
            .map(|_| {
                let r = ctx.rnd_exp();
                let first = ctx.gmod_pow(&r).modulo(ctx.modulus());

                (first, r)
            })
            .unzip();

        // let now = Instant::now();

        for i in 0..us.len() {
            let c_temp = if i == 0 { initial } else { &cs[i - 1] };

            let second = c_temp.mod_pow(us[i], ctx.modulus());
            let c = firsts[i].mul(&second).modulo(ctx.modulus());

            cs.push(c);
        }

        // println!("v9 {}", now.elapsed().as_millis());

        (cs, rs)
    }

    fn shuffle_proof_us(
        &self,
        es: &[Ciphertext<C>],
        e_primes: &[Ciphertext<C>],
        cs: &[C::E],
        n: usize,
        label: &[u8],
    ) -> Vec<C::X> {
        let mut prefix_challenge_input =
            ChallengeInput::from(&[("es", &es), ("e_primes", &e_primes)]);
        prefix_challenge_input.add("cs", &cs);
        prefix_challenge_input.add("label", &label.to_vec());

        // let prefix_bytes = ByteTree::Tree(trees).to_hashable_bytes();
        let prefix_bytes = prefix_challenge_input.strand_serialize();

        // optimization: instead of calculating u = H(prefix || i),
        // we do u = H(H(prefix) || i)
        // that way we avoid allocating prefix-size bytes n times
        let mut hasher = Sha512::new();
        hasher.update(prefix_bytes);
        let prefix_hash = hasher.finalize().to_vec();

        (0..n)
            .par()
            .map(|i| {
                let next = ChallengeInput::from_bytes(&[
                    ("prefix", prefix_hash.clone()),
                    ("counter", i.to_le_bytes().to_vec()),
                ]);
                let bytes = next.get_bytes();
                self.ctx.hash_to_exp(&bytes)
            })
            .collect()
    }

    fn shuffle_proof_challenge(
        &self,
        y: &YChallengeInput<C>,
        t: &Commitments<C>,
        label: &[u8],
    ) -> C::X {
        let mut challenge_input = ChallengeInput::from(&[
            ("t1", &t.t1),
            ("t2", &t.t2),
            ("t3", &t.t3),
            ("t4_1", &t.t4_1),
            ("t4_2", &t.t4_2),
        ]);
        challenge_input.add_bytes("es", y.es.strand_serialize());
        challenge_input.add_bytes("e_primes", y.e_primes.strand_serialize());
        challenge_input.add_bytes("cs", y.cs.strand_serialize());
        challenge_input.add_bytes("c_hats", y.c_hats.strand_serialize());
        challenge_input.add_bytes("pk.element", y.pk.element.strand_serialize());
        challenge_input.add_bytes("t_hats", t.t_hats.strand_serialize());
        challenge_input.add_bytes("label", label.to_vec());

        let bytes = challenge_input.get_bytes();

        self.ctx.hash_to_exp(&bytes)
    }
}

pub(crate) fn gen_permutation(size: usize) -> Vec<usize> {
    let mut ret = Vec::with_capacity(size);

    let mut rng = StrandRng;

    let mut ordered: Vec<usize> = (0..size).collect();

    for i in 0..size {
        let k = rng.gen_range(i..size);
        let j = ordered[k];
        ordered[k] = ordered[i];
        ret.push(j);
    }

    ret
}
/*
#[cfg(test)]
mod tests {
    use rug::Integer;
    use std::fs::File;

    use crate::crypto::backend::rug_b::*;
    use crate::crypto::group::*;
    use crate::crypto::shuffler::*;

    // experimental
    #[test]
    fn test_rug_multi_shuffle() {
        let group = RugGroup::default();
        let challenger = &*group.challenger();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        let n = 100;
        let mut es1: Vec<Ciphertext<Integer>> = Vec::with_capacity(n);
        let mut es2: Vec<Ciphertext<Integer>> = Vec::with_capacity(n);

        for _ in 0..n {
            let plaintext: Integer = group.encode(&group.rnd_exp());
            let c = pk.encrypt(&plaintext);
            let c2 = pk.encrypt(&plaintext);
            es1.push(c);
            es2.push(c2);
        }
        let seed = vec![];
        let hs = group.generators(es1.len() + 1, 0, seed);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: challenger,
        };
        let perm: Vec<usize> = gen_permutation(n);
        let (cs, rs) = shuffler.gen_commitments(&perm, &pk.group);
        let perm_data = PermutationData {
            permutation: &perm,
            commitments_c: &cs,
            commitments_r: &rs,
        };
        let (e_primes1, rs1) = shuffler.apply_permutation(&perm, &es1);
        let (proof1, _, _) = shuffler.gen_proof_ext(&es1, &e_primes1, &rs1, &perm_data, &vec![]);

        let (e_primes2, rs2) = shuffler.apply_permutation(&perm, &es2);
        let (proof2, _, _) = shuffler.gen_proof_ext(&es2, &e_primes2, &rs2, &perm_data, &vec![]);

        let ok = shuffler.check_proof(&proof1, &es1, &e_primes1, &vec![]);
        assert!(ok);

        let ok = shuffler.check_proof(&proof2, &es2, &e_primes2, &vec![]);
        assert!(ok);

        // FIXME: verify that this is sufficient to prove that the same permutation was used in both shuffles
        assert!(proof1.cs.len() == proof2.cs.len());
        for i in 0..n {
            assert!(proof1.cs[i].eq(&proof2.cs[i]));
        }

        let mut mismatch = 0;
        for i in 0..n {
            let p1 = group.decode(&sk.decrypt(&e_primes1[i]));
            let p2 = group.decode(&sk.decrypt(&e_primes2[i]));

            if !p1.eq(&p2) {
                mismatch += 1;
            }
        }

        // in a parallel shuffle, all ciphertexts must line up
        assert!(mismatch == 0);

        let (e_primes2b, rs2b, perm2) = shuffler.gen_shuffle(&es2);
        let proof2b = shuffler.gen_proof(&es2, &e_primes2b, &rs2b, &perm2, &vec![]);

        let ok = shuffler.check_proof(&proof2b, &es2, &e_primes2b, &vec![]);
        assert!(ok);

        let mut mismatch = 0;
        for i in 0..n {
            let p1 = group.decode(&sk.decrypt(&e_primes1[i]));
            let p2 = group.decode(&sk.decrypt(&e_primes2b[i]));

            if !p1.eq(&p2) {
                mismatch += 1;
            }
        }
        // in a non parallel shuffle, at least some of the ciphertexts won't line up
        assert!(mismatch > 0);
    }
}*/
