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
pub fn pMessage(s: &str) {
    log(s);
    postMessage(s);
}

#[wasm_bindgen]
pub fn test() {
    pMessage("--- wasm::test.rs");
    test_shuffle();
    test_elgamal();
    test_schnorr();
    test_chaumpedersen();
    test_vdecryption();
    test_distributed();
    test_distributed_btserde();
    test_threshold();
    test_encrypted_sk();
    // test_shuffle_btserde();
}

#[wasm_bindgen]
pub fn test_shuffle_btserde() {
    pMessage("* Ristretto shuffle btserde..");
    let ctx = RistrettoCtx;
    test_shuffle_btserde_generic(&ctx);

    pMessage("* BigInt shuffle btserde..");
    let ctx = BigintCtx::<P2048>::new();
    test_shuffle_btserde_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_encrypted_sk() {
    pMessage("* Ristretto encrypted_sk..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_encrypted_sk_generic(&ctx, plaintext);

    pMessage("* BigInt encrypted_sk..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_encrypted_sk_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_shuffle() {
    pMessage("* Ristretto shuffle..");
    let ctx = RistrettoCtx;
    test_shuffle_generic(&ctx);
    pMessage("* BigInt shuffle..");
    let ctx = BigintCtx::<P2048>::new();
    test_shuffle_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_chaumpedersen() {
    pMessage("* Ristretto chaumpedersen..");
    let ctx = RistrettoCtx;
    test_chaumpedersen_generic(&ctx);

    pMessage("* BigInt chaumpedersen..");
    let ctx = BigintCtx::<P2048>::new();
    test_chaumpedersen_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_elgamal() {
    pMessage("* BigInt encrypt..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_elgamal_generic(&ctx, plaintext);

    pMessage("* Ristretto encrypt..");
    let ctx = RistrettoCtx;
    let mut csprng = StrandRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_elgamal_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_schnorr() {
    pMessage("* Ristretto schnorr..");
    let ctx = RistrettoCtx;
    test_schnorr_generic(&ctx);

    pMessage("* BigInt schnorr..");
    let ctx = BigintCtx::<P2048>::new();
    test_schnorr_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_vdecryption() {
    pMessage("* Ristretto vdecryption..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_vdecryption_generic(&ctx, plaintext);

    pMessage("* BigInt vdecryption..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_vdecryption_generic(&ctx, plaintext);
}

pub fn test_distributed() {
    pMessage("* Ristretto distributed..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_distributed_generic(&ctx, plaintext);

    pMessage("* BigInt distributed..");
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_distributed_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_distributed_btserde() {
    pMessage("* Ristretto distributed btserde..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut ps = vec![];
    for _ in 0..1 {
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let p = util::to_u8_30(&fill.to_vec());
        ps.push(p);
    }
    test_distributed_btserde_generic(&ctx, ps);

    pMessage("* BigInt distributed btserde..");
    let ctx = BigintCtx::<P2048>::new();
    let mut ps = vec![];
    for _ in 0..1 {
        let p = ctx.rnd_exp();
        ps.push(p);
    }
    test_distributed_btserde_generic(&ctx, ps);
}

pub fn test_threshold() {
    pMessage("* Ristretto threshold..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    let trustees = 5usize;
    let threshold = 3usize;
    test_threshold_generic(&ctx, trustees, threshold, plaintext);

    pMessage("* BigInt threshold..");
    let trustees = 5usize;
    let threshold = 3usize;
    let ctx = BigintCtx::<P2048>::new();
    let plaintext = ctx.rnd_exp();
    test_threshold_generic(&ctx, trustees, threshold, plaintext);
}
