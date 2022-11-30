// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
use rand::RngCore;
use wasm_bindgen::prelude::*;

use crate::backend::num_bigint::{BigintCtx, P2048};
use crate::backend::ristretto::RistrettoCtx;
use crate::context::{Ctx, Element};
use crate::elgamal::{PrivateKey, PublicKey};
use crate::rnd::StrandRng;
use crate::serialization::StrandSerialize;
use crate::shuffler::Shuffler;
use crate::util;
use crate::zkp::Zkp;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen]
    fn postMessage(s: &str);

    #[no_mangle]
    #[used]
    static performance: web_sys::Performance;
}

#[wasm_bindgen]
pub fn bench(n: u32) {
    postMessage(&format!("--- wasm::bench.rs (n = {})", n));
    #[cfg(feature = "rayon")]
    postMessage(">> strand wasm build WITH rayon");
    #[cfg(not(feature = "rayon"))]
    postMessage(">> strand wasm build NO rayon");
    bench_enc_pok(n);
    bench_modpow(n);
    bench_shuffle(n as usize);
}

#[wasm_bindgen]
pub fn bench_shuffle(n: usize) {
    postMessage("> Ristretto shuffle");
    let ctx = RistrettoCtx;
    bench_shuffle_serialization_generic(ctx, n * 10);

    postMessage("> Bigint shuffle");
    let ctx: BigintCtx<P2048> = Default::default();
    bench_shuffle_serialization_generic(ctx, n);
}

#[wasm_bindgen]
pub fn bench_modpow(n: u32) {
    let ctx = RistrettoCtx;
    postMessage(&format!("> Ristretto modpow n = {}", n));
    let now = performance.now();
    bench_modpow_generic(ctx, n);
    postMessage(&format!(
        "modpow {:.3} ms",
        (performance.now() - now) / n as f64
    ));
    let ctx: BigintCtx<P2048> = Default::default();
    postMessage(&format!("> Bigint modpow n = {}", n));
    let now = performance.now();
    bench_modpow_generic(ctx, n);
    postMessage(&format!(
        "modpow {:.3} ms ",
        (performance.now() - now) / n as f64
    ));
}

#[wasm_bindgen]
pub fn bench_enc_pok(n: u32) {
    let ctx: BigintCtx<P2048> = Default::default();
    let plaintext = ctx.rnd_plaintext();
    postMessage("> Bigint enc_pok");
    bench_enc_pok_generic(ctx, plaintext, n);

    let ctx = RistrettoCtx;
    let mut csprng = StrandRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    postMessage("> Ristretto enc_pok");
    bench_enc_pok_generic(ctx, plaintext, n);
}

fn bench_shuffle_serialization_generic<C: Ctx>(ctx: C, n: usize) {
    let sk = PrivateKey::gen(&ctx);
    let pk: PublicKey<C> = sk.get_pk();

    log("gen ballots..");
    let es = util::random_ballots(n, &ctx);
    let seed = vec![];

    log("generators..");
    let now = performance.now();
    let hs = ctx.generators(es.len() + 1, &seed);
    let shuffler = Shuffler {
        pk: &pk,
        generators: &hs,
        ctx: ctx.clone(),
    };
    log(&format!("{}", performance.now() - now));

    postMessage(&format!("shuffle n = {}, proving..", n));
    let now = performance.now();
    let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
    let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);
    postMessage(&format!(
        "prove {:.3} c / s",
        n as f64 / ((performance.now() - now) / 1000.0)
    ));

    postMessage(&format!("shuffle n = {}, verifying..", n));
    let now = performance.now();
    let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);
    assert!(ok);
    postMessage(&format!(
        "verify {:.3} c / s",
        n as f64 / ((performance.now() - now) / 1000.0)
    ));

    log(&format!("serialization.."));
    let now = performance.now();
    let pk_b = pk.strand_serialize();
    let es_b = es.strand_serialize();
    let eprimes_b = e_primes.strand_serialize();
    let proof_b = proof.strand_serialize();
    postMessage(&format!(
        "serialization {:.3} c / s",
        n as f64 / ((performance.now() - now) / 1000.0)
    ));

    log(&format!("serialization raw"));
    let mut v = vec![];
    for _ in 0..n {
        v.push(ctx.rnd());
    }
    let now = performance.now();
    for next in v {
        next.strand_serialize();
    }
    postMessage(&format!(
        "serialization raw {:.3} c / s",
        n as f64 / ((performance.now() - now) / 1000.0)
    ));

    /* use crate::byte_tree::BTreeDeser;
    use crate::shuffler::ShuffleProof;
    use crate::elgamal::Ciphertext;
    log(&format!("deserialization.."));
    let now = performance.now();
    let pk_d = PublicKey::<C>::deser(&pk_b, &ctx).unwrap();
    let es_d = Vec::<Ciphertext<C>>::deser(&es_b, &ctx).unwrap();
    let eprimes_d = Vec::<Ciphertext<C>>::deser(&eprimes_b, &ctx).unwrap();
    let proof_d = ShuffleProof::<C>::deser(&proof_b, &ctx).unwrap();
    log(&format!("{} / s", n as f64 / ( (performance.now() - now) / 1000.0)));*/
}

fn bench_enc_pok_generic<C: Ctx>(ctx: C, data: C::P, n: u32) {
    let zkp = Zkp::new(&ctx);
    let sk = PrivateKey::gen(&ctx);
    let pk: PublicKey<C> = sk.get_pk();

    log("encode..");
    let now = performance.now();
    let plaintext = ctx.encode(&data).unwrap();
    log(&format!("{}", performance.now() - now));

    let total = performance.now();
    for _ in 0..n {
        log("encrypt..");
        let now = performance.now();
        let randomness = ctx.rnd_exp();
        let c = pk.encrypt_with_randomness(&plaintext, &randomness);
        log(&format!("{}", performance.now() - now));
        log("prove..");
        let now = performance.now();
        let _proof = zkp.schnorr_prove(&randomness, &c.gr, Some(ctx.generator()), &vec![]);
        log(&format!("{}", performance.now() - now));
    }
    postMessage(&format!(
        "total enc + pok = {:.3} ms",
        (performance.now() - total) / n as f64
    ));
}

fn bench_modpow_generic<C: Ctx>(ctx: C, n: u32) {
    for _ in 0..n {
        let x = ctx.rnd_exp();
        // let g = ctx.generator();
        // let modulus = ctx.modulus();
        // let _ = g.mod_pow(&x, &modulus);
        let _ = ctx.gmod_pow(&x);
    }
}
