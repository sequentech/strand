use crate::byte_tree::ToFromBTree;
use crate::zkp::ZKProver;
use std::marker::{Send, Sync};

pub trait Ctx: Sync + Sized + Clone + ZKProver<Self> {
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
    fn generators(&self, size: usize, contest: u32, seed: &[u8]) -> Vec<Self::E>;

    fn is_valid_element(&self, element: &Self::E) -> bool;
    fn new() -> Self;
}

pub trait Element<C: Ctx>: Clone + Eq + Send + Sync + ToFromBTree {
    fn mul(&self, other: &C::E) -> C::E;
    fn div(&self, other: &C::E, modulus: &C::E) -> C::E;
    fn inv(&self, modulus: &C::E) -> C::E;
    fn mod_pow(&self, exp: &C::X, modulus: &C::E) -> C::E;
    fn modulo(&self, modulus: &C::E) -> C::E;

    fn mul_identity() -> C::E;
}

pub trait Exponent<C: Ctx>: Clone + Eq + Send + Sync + ToFromBTree {
    fn add(&self, other: &C::X) -> C::X;
    fn sub(&self, other: &C::X) -> C::X;
    fn mul(&self, other: &C::X) -> C::X;
    fn div(&self, other: &C::X, modulus: &C::X) -> C::X;
    fn inv(&self, modulus: &C::X) -> C::X;
    fn modulo(&self, modulus: &C::X) -> C::X;

    fn add_identity() -> C::X;
    fn mul_identity() -> C::X;

    fn to_string(&self) -> String;
}
