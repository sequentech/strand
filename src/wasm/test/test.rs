// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
use rand::RngCore;
use wasm_bindgen::prelude::*;

use crate::backend::num_bigint::{BigintCtx, P2048};
use crate::backend::ristretto::RistrettoCtx;
use crate::backend::tests::*;
use crate::context::{Ctx, Element};
use crate::elgamal::PublicKey;
use crate::rnd::StrandRng;
use crate::shuffler::Shuffler;
use crate::threshold::tests::test_threshold_generic;
use crate::util;
use crate::zkp::Zkp;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen]
    fn postMessage(s: &str);
}

pub fn message(s: &str) {
    log(s);
    postMessage(s);
}

#[wasm_bindgen]
pub fn test() {
    message("--- wasm::test.rs");
    test_elgamal();
    test_schnorr();
    test_chaumpedersen();
    test_vdecryption();
    test_distributed();
    test_distributed_serialization();
    test_threshold();
    // test_shuffle();
    test_shuffle_serialization();
}

#[wasm_bindgen]
pub fn test_shuffle_serialization() {
    message("* Ristretto shuffle + serialization..");
    let ctx = RistrettoCtx;
    test_shuffle_serialization_generic(&ctx);

    message("* BigInt shuffle + serialization..");
    let ctx: BigintCtx<P2048> = Default::default();
    test_shuffle_serialization_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_shuffle() {
    message("* Ristretto shuffle..");
    let ctx = RistrettoCtx;
    test_shuffle_generic(&ctx);
    message("* BigInt shuffle..");
    let ctx: BigintCtx<P2048> = Default::default();
    test_shuffle_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_chaumpedersen() {
    message("* Ristretto chaumpedersen..");
    let ctx = RistrettoCtx;
    test_chaumpedersen_generic(&ctx);

    message("* BigInt chaumpedersen..");
    let ctx: BigintCtx<P2048> = Default::default();
    test_chaumpedersen_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_elgamal() {
    message("* BigInt encrypt..");
    let ctx: BigintCtx<P2048> = Default::default();
    let plaintext = ctx.rnd_plaintext();
    test_elgamal_generic(&ctx, plaintext);

    message("* Ristretto encrypt..");
    let ctx = RistrettoCtx;
    let mut csprng = StrandRng;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_elgamal_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_schnorr() {
    message("* Ristretto schnorr..");
    let ctx = RistrettoCtx;
    test_schnorr_generic(&ctx);

    message("* BigInt schnorr..");
    let ctx: BigintCtx<P2048> = Default::default();
    test_schnorr_generic(&ctx);
}

#[wasm_bindgen]
pub fn test_vdecryption() {
    message("* Ristretto vdecryption..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_vdecryption_generic(&ctx, plaintext);

    message("* BigInt vdecryption..");
    let ctx: BigintCtx<P2048> = Default::default();
    let plaintext = ctx.rnd_plaintext();
    test_vdecryption_generic(&ctx, plaintext);
}

pub fn test_distributed() {
    message("* Ristretto distributed..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    test_distributed_generic(&ctx, plaintext);

    message("* BigInt distributed..");
    let ctx: BigintCtx<P2048> = Default::default();
    let plaintext = ctx.rnd_plaintext();
    test_distributed_generic(&ctx, plaintext);
}

#[wasm_bindgen]
pub fn test_distributed_serialization() {
    message("* Ristretto distributed + serialization..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut ps = vec![];
    for _ in 0..1 {
        let mut fill = [0u8; 30];
        csprng.fill_bytes(&mut fill);
        let p = util::to_u8_30(&fill.to_vec());
        ps.push(p);
    }
    test_distributed_serialization_generic(&ctx, ps);

    message("* BigInt distributed + serialization..");
    let ctx: BigintCtx<P2048> = Default::default();
    let mut ps = vec![];
    for _ in 0..1 {
        let p = ctx.rnd_plaintext();
        ps.push(p);
    }
    test_distributed_serialization_generic(&ctx, ps);
}

pub fn test_threshold() {
    message("* Ristretto threshold..");
    let mut csprng = StrandRng;
    let ctx = RistrettoCtx;
    let mut fill = [0u8; 30];
    csprng.fill_bytes(&mut fill);
    let plaintext = util::to_u8_30(&fill.to_vec());
    let trustees = 5usize;
    let threshold = 3usize;
    test_threshold_generic(&ctx, trustees, threshold, plaintext);

    message("* BigInt threshold..");
    let trustees = 5usize;
    let threshold = 3usize;
    let ctx: BigintCtx<P2048> = Default::default();
    let plaintext = ctx.rnd_plaintext();
    test_threshold_generic(&ctx, trustees, threshold, plaintext);
}
