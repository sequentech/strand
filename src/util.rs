use crate::context::Ctx;
use crate::elgamal::Ciphertext;

#[cfg(feature = "rayon")]
use rayon::iter::IntoParallelIterator;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[cfg(not(feature = "rayon"))]
use std::iter::IntoIterator;

#[cfg(not(feature = "rayon"))]
pub trait Par<I: IntoIterator> {
    fn par(self) -> I::IntoIter;
}

#[cfg(not(feature = "rayon"))]
impl<I: IntoIterator> Par<I> for I {
    #[inline(always)]
    fn par(self) -> I::IntoIter {
        self.into_iter()
    }
}

#[cfg(feature = "rayon")]
pub trait Par<I: IntoIterator + IntoParallelIterator> {
    fn par(self) -> <I as rayon::iter::IntoParallelIterator>::Iter;
}

#[cfg(feature = "rayon")]
impl<I: IntoIterator + IntoParallelIterator> Par<I> for I {
    #[inline(always)]
    fn par(self) -> <I as rayon::iter::IntoParallelIterator>::Iter {
        self.into_par_iter()
    }
}

pub fn to_u8_16(input: &[u8]) -> [u8; 16] {
    assert_eq!(input.len(), 16);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(input);
    bytes
}

pub fn to_u8_30(input: &[u8]) -> [u8; 30] {
    assert_eq!(input.len(), 30);
    let mut bytes = [0u8; 30];
    bytes.copy_from_slice(input);
    bytes
}

pub fn to_u8_32(input: &[u8]) -> [u8; 32] {
    assert_eq!(input.len(), 32);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(input);
    bytes
}

pub fn random_ballots<C: Ctx>(n: usize, ctx: &C) -> Vec<Ciphertext<C>> {
    (0..n)
        .par()
        .map(|_| Ciphertext {
            mhr: ctx.rnd(),
            gr: ctx.rnd(),
        })
        .collect()
}
