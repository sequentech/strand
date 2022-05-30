// use crate::backend::num_bigint::BigintCtx;
use crate::backend::numb::{BigintCtx, P2048};
use crate::backend::ristretto::RistrettoCtx;
use crate::backend::tests::*;
use crate::context::{Ctx, Element};
use crate::elgamal::PublicKey;
use crate::rnd::StrandRng;
use crate::shuffler::Shuffler;
use crate::threshold::tests::test_threshold_generic;
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
}

#[wasm_bindgen]
pub fn test() {
    postMessage("--- wasm::test.rs");
    test_elgamal();
    test_schnorr();
    test_chaumpedersen();
    test_vdecryption();
    test_distributed();
    test_distributed_btserde();
    test_threshold();
    test_encrypted_sk();
    test_shuffle();
    test_shuffle_btserde();
}

#[wasm_bindgen]
pub fn test_shuffle_btserde() {
    postMessage("* Ristretto shuffle btserde..");
    let ctx = RistrettoCtx;
    test_shuffle_btserde_generic(&ctx);

    postMessage("* BigInt shuffle btserde..");
    let ctx = BigintCtx::<P2048>::new();
    test_shuffle_btserde_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_encrypted_sk() {
    postMessage("* Ristretto encrypted_sk..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_encrypted_sk_generic(&ctx, plaintext);

    postMessage("* BigInt encrypted_sk..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_encrypted_sk_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_shuffle() {
    postMessage("* Ristretto shuffle..");
    let ctx = RistrettoCtx;
    test_shuffle_generic(&ctx);
    postMessage("* BigInt shuffle..");
    let ctx = BigintCtx::<P2048>::new();
    test_shuffle_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_chaumpedersen() {
    postMessage("* Ristretto chaumpedersen..");
    let ctx = RistrettoCtx;
    test_chaumpedersen_generic(&ctx);

    postMessage("* BigInt chaumpedersen..");
    let ctx = BigintCtx::<P2048>::new();
    test_chaumpedersen_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_elgamal() {
    postMessage("* BigInt encrypt..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_elgamal_generic(&ctx, plaintext);

    postMessage("* Ristretto encrypt..");
    let ctx = RistrettoCtx;
    let mut csprng = StrandRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_elgamal_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_schnorr() {
    postMessage("* Ristretto schnorr..");
    let ctx = RistrettoCtx;
    test_schnorr_generic(&ctx);

    postMessage("* BigInt schnorr..");
    let ctx = BigintCtx::<P2048>::new();
    test_schnorr_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_vdecryption() {
    postMessage("* Ristretto vdecryption..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_vdecryption_generic(&ctx, plaintext);

    postMessage("* BigInt vdecryption..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_vdecryption_generic(&ctx, plaintext);
}

pub fn test_distributed() {
    postMessage("* Ristretto distributed..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_distributed_generic(&ctx, plaintext);

    postMessage("* BigInt distributed..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_distributed_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_distributed_btserde() {
    postMessage("* Ristretto distributed btserde..");
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

    postMessage("* BC2048 distributed btserde..");
    let ctx = BigintCtx::<P2048>::new();
    // let ctx = BC::<P2048>::new();
    let mut ps = vec![];
    for _ in 0..10 {
        let p = ctx.rnd_exp();
        ps.push(p);
    }
    test_distributed_btserde_generic(&ctx, ps);
}

pub fn test_threshold() {
    postMessage("* Ristretto threshold..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    let trustees = 5usize;
    let threshold = 3usize;
    test_threshold_generic(&ctx, trustees, threshold, plaintext);

    postMessage("* BigInt threshold..");
    let trustees = 5usize;
    let threshold = 3usize;
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_threshold_generic(&ctx, trustees, threshold, plaintext);
}
