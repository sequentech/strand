use crate::backend::num_bigint::BigintCtx;
use crate::backend::ristretto::RistrettoCtx;
use crate::byte_tree::BTreeSer;
use crate::context::{Ctx, Element};
use crate::elgamal::PublicKey;
use crate::rnd::StrandRng;
use crate::shuffler::Shuffler;
use crate::util;
use crate::zkp::ZKProver;
use rand::RngCore;
use wasm_bindgen::prelude::*;

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
pub fn bench() {
    postMessage("--- wasm::bench.rs");
    #[cfg(feature = "rayon")]
    postMessage(">> strand wasm build WITH rayon");
    #[cfg(not(feature = "rayon"))]
    postMessage(">> strand wasm build NO rayon");
    bench_enc_pok();
    bench_modpow(10);
    bench_shuffle(1000);
}

#[wasm_bindgen]
pub fn bench_shuffle(n: usize) {
    postMessage("> Ristretto shuffle");
    let ctx = RistrettoCtx;
    bench_shuffle_btserde_generic(ctx, n);

    postMessage("> Bigint shuffle");
    let ctx = BigintCtx::default();
    bench_shuffle_btserde_generic(ctx, n / 10);
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
    let ctx = BigintCtx::default();
    postMessage(&format!("> Bigint modpow n = {}", n));
    let now = performance.now();
    bench_modpow_generic(ctx, n);
    postMessage(&format!(
        "modpow {:.3} ms ",
        (performance.now() - now) / n as f64
    ));
}

#[wasm_bindgen]
pub fn bench_enc_pok() {
    let ctx = BigintCtx::default();
    let plaintext = ctx.rnd_exp();
    postMessage("> Bigint enc_pok");
    bench_enc_pok_generic(ctx, plaintext);

    let ctx = RistrettoCtx;
    let mut csprng = StrandRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    postMessage("> Ristretto enc_pok");
    bench_enc_pok_generic(ctx, plaintext);
}

fn bench_shuffle_btserde_generic<C: Ctx>(ctx: C, n: usize) {
    let sk = ctx.gen_key();
    let pk = PublicKey::from(&sk.public_value, &ctx);

    log("gen ballots..");
    let es = util::random_ballots(n, &ctx);
    let seed = vec![];

    log("generators..");
    let now = performance.now();
    let hs = ctx.generators(es.len() + 1, 0, &seed);
    let shuffler = Shuffler {
        pk: &pk,
        generators: &hs,
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
    let pk_b = pk.ser();
    let es_b = es.ser();
    let eprimes_b = e_primes.ser();
    let proof_b = proof.ser();
    postMessage(&format!(
        "serialization {:.3} c / s",
        n as f64 / ((performance.now() - now) / 1000.0)
    ));

    /*
    log(&format!("deserialization.."));
    let now = performance.now();
    let pk_d = PublicKey::<C>::deser(&pk_b).unwrap();
    let es_d = Vec::<Ciphertext<C>>::deser(&es_b).unwrap();
    let eprimes_d = Vec::<Ciphertext<C>>::deser(&eprimes_b).unwrap();
    let proof_d = ShuffleProof::<C>::deser(&proof_b).unwrap();
    log(&format!("{} / s", n as f64 / ( (performance.now() - now) / 1000.0)));
    */
}

fn bench_enc_pok_generic<C: Ctx>(ctx: C, data: C::P) {
    let sk = ctx.gen_key();
    let pk = PublicKey::from(&sk.public_value, &ctx);

    log("encode..");
    let now = performance.now();
    let plaintext = ctx.encode(&data);
    log(&format!("{}", performance.now() - now));

    let total = performance.now();
    for _ in 0..10 {
        log("encrypt..");
        let now = performance.now();
        let randomness = ctx.rnd_exp();
        let c = pk.encrypt_ext(&plaintext, &randomness);
        log(&format!("{}", performance.now() - now));
        log("prove..");
        let now = performance.now();
        let _proof = ctx.schnorr_prove(&randomness, &c.b, ctx.generator(), &vec![]);
        log(&format!("{}", performance.now() - now));
    }
    postMessage(&format!(
        "total enc + pok = {:.3} ms",
        (performance.now() - total) / 10.0
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
