// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
//!
//! The interface is composed of three abstractions on which other functionality is built:
//! - [Ctx](crate::context::Ctx): a cryptographic context most closely corresponds to the underlying
//! group in which modular arithmetic operations take place, and where discrete log assumptions hold.
//! - [Element](crate::context::Element): An element of the underlying group whose main operations are multiplication and modular
//! exponentiation. If the group is an elliptic curve, the corresponding terms are addition and multiplication.
//! - [Exponent](crate::context::Exponent): A member of the "exponent ring", used in modular exponentiation (or scalar multiplication
//! for elliptic curves).
//!
//! # Examples
//!
//! ```
//! // This example shows how to obtain a context instance,
//! // generate an ElGamal keypair, and encrypt/decrypt.
//! use strand::context::Ctx;
//! use strand::backend::num_bigint::{BigintCtx, P2048};
//! use strand::elgamal::{PrivateKey, PublicKey};
//!
//! // obtain a context for a 2048-bit prime, with num_bigint backend
//! let ctx = BigintCtx::<P2048>::new();
//! // generate an ElGamal keypair
//! let sk = PrivateKey::gen(&ctx);
//! let pk = sk.get_pk();
//! // encrypt and decrypt
//! let plaintext = ctx.rnd_plaintext();
//! let encoded = ctx.encode(&plaintext).unwrap();
//! let ciphertext = pk.encrypt(&encoded);
//! let decrypted = sk.decrypt(&ciphertext);
//! let plaintext_ = ctx.decode(&decrypted);
//! assert_eq!(plaintext, plaintext_);
//! ```

use crate::byte_tree::ToFromBTree;
// use crate::zkp::Zkp;
use std::marker::{Send, Sync};

/// A cryptographic context loosely corresponds to the underlying modular arithmetic group.
pub trait Ctx: Sync + Sized + Clone {
    type E: Element<Self>;
    type X: Exponent<Self>;
    type P: Send + Sync + Eq + std::fmt::Debug;

    fn generator(&self) -> &Self::E;
    fn gmod_pow(&self, other: &Self::X) -> Self::E;
    fn emod_pow(&self, base: &Self::E, exponent: &Self::X) -> Self::E;
    fn modulus(&self) -> &Self::E;
    fn exp_modulus(&self) -> &Self::X;

    fn rnd(&self) -> Self::E;
    fn rnd_exp(&self) -> Self::X;
    fn rnd_plaintext(&self) -> Self::P;

    fn encode(&self, plaintext: &Self::P) -> Result<Self::E, &'static str>;
    fn decode(&self, element: &Self::E) -> Self::P;
    fn exp_from_u64(&self, value: u64) -> Self::X;
    fn hash_to_exp(&self, bytes: &[u8]) -> Self::X;
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Self::E>;

    fn element_from_bytes(&self, bytes: &[u8]) -> Result<Self::E, &'static str>;
    fn exp_from_bytes(&self, bytes: &[u8]) -> Result<Self::X, &'static str>;

    fn new() -> Self;
}

/// An element of the underlying group.
///
/// Operations depend on the backend and are given below for multiplicative groups / elliptic curves.
pub trait Element<C: Ctx>: Clone + Eq + Send + Sync + ToFromBTree<C> {
    /// Modular multiplication / point addition.
    fn mul(&self, other: &C::E) -> C::E;
    /// Modular division (a div b = a * b^1) / point subtraction.
    fn div(&self, other: &C::E, modulus: &C::E) -> C::E;
    /// Modular inverse / point negation.
    fn inv(&self, modulus: &C::E) -> C::E;
    /// Modular exponentiation / scalar multiplication.
    fn mod_pow(&self, exp: &C::X, modulus: &C::E) -> C::E;
    /// Modulo operation / not necessary, applied automatically.
    fn modulo(&self, modulus: &C::E) -> C::E;
    // fn modl(&self, ctx: &C) -> C::E;

    /// Multiplicative identity / point at infinity.
    fn mul_identity() -> C::E;
}

/// A member of the "exponent ring" associated to the element group, or scalar ring for elliptic curves.
pub trait Exponent<C: Ctx>: Clone + Eq + Send + Sync + ToFromBTree<C> {
    // Modular addition.
    fn add(&self, other: &C::X) -> C::X;
    // Modular subtraction.
    fn sub(&self, other: &C::X) -> C::X;
    // Modular multiplication.
    fn mul(&self, other: &C::X) -> C::X;
    // Modular division (a div b = a * b^1).
    fn div(&self, other: &C::X, modulus: &C::X) -> C::X;
    /// Modular inverse.
    fn inv(&self, modulus: &C::X) -> C::X;
    /// Modulo operation (applied automatically for elliptic curves)
    fn modulo(&self, modulus: &C::X) -> C::X;

    /// Additive identity.
    fn add_identity() -> C::X;
    /// Multiplicative identity.
    fn mul_identity() -> C::X;
}
