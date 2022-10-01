// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
#[cfg(feature = "wasmtest")]
pub mod bench;
#[cfg(feature = "wasmtest")]
pub mod demo;
#[cfg(feature = "wasmtest")]
pub mod test;
// #[cfg(feature = "wasm")]
// pub mod example;

#[cfg(feature = "wasmrayon")]
pub use wasm_bindgen_rayon::init_thread_pool;
