// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

#![doc = include_str!("../README.md")]
// https://github.com/rust-lang/rfcs/blob/master/text/1210-impl-specialization.md
#![cfg_attr(feature = "specialization", feature(specialization))]

// #![warn(missing_docs)]

extern crate cfg_if;

/// Provides cryptographic backends, currently multiplicative groups and ristretto elliptic curve.
pub mod backend;
/// Defines a generic interface to concrete backends.
pub mod context;
/// ElGamal encryption.
pub mod elgamal;
/// Support for distributed Elgamal.
pub mod keymaker;
/// Wikstrom proof of shuffle.
pub mod shuffler;
pub mod threshold;
/// Support for threshold ElGamal.
pub mod threshold_test;
/// Miscellaneous functions.
pub mod util;
#[cfg(feature = "wasm")]
/// Webassembly API.
pub mod wasm;
/// Schnorr and Chaum-Pedersen zero knowledge proofs.
pub mod zkp;

pub mod rnd;
pub mod serialization;
pub mod signature;

pub use sha3;
