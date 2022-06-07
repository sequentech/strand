#[cfg(feature = "wasmtest")]
pub mod bench;
#[cfg(feature = "wasmtest")]
pub mod test;
// #[cfg(feature = "wasm")]
// pub mod example;

#[cfg(feature = "wasmrayon")]
pub use wasm_bindgen_rayon::init_thread_pool;
