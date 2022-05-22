use crate::backend::num_bigint::BigintCtx;
use crate::backend::ristretto::RistrettoCtx;
use crate::byte_tree::{ByteTree, ToByteTree};
use crate::context::Ctx;
use crate::zkp::ZKProver;
use num_bigint::BigUint;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
struct ByteTreeBridge {
    tree: ByteTree,
}

#[wasm_bindgen]
pub fn ex(ciphertext: &[u8]) {
    // let ctx = BigintCtx::default();
    let one: BigUint = BigUint::from(23323235u32);
    // let rndb = rnd.to_bytes_be();
    // log(&format!("{:x?}", bytes));
    // log(&format!("{}", BigUint::from_bytes_be(bytes)));
    // let valid = ctx.is_valid_element(bytes);
    // log(&format!("valid = {}", valid));

    // one.to_bytes_be()
    let tree = one.to_byte_tree();
}
