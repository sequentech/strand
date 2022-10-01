// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
use crate::context::Ctx;
use crate::elgamal::Ciphertext;
use ed25519_dalek::Digest;
use ed25519_dalek::Sha512;

cfg_if::cfg_if! {
    if #[cfg(feature = "rayon")] {
        use rayon::iter::IntoParallelIterator;
        use rayon::prelude::*;
        use std::iter::IntoIterator;


        pub trait Par<I: IntoIterator + IntoParallelIterator> {
            fn par(self) -> <I as rayon::iter::IntoParallelIterator>::Iter;
        }

        impl<I: IntoIterator + IntoParallelIterator> Par<I> for I {
            #[inline(always)]
            fn par(self) -> <I as rayon::iter::IntoParallelIterator>::Iter {
                self.into_par_iter()
            }
        }

    } else {
        pub trait Par<I: IntoIterator> {
            fn par(self) -> I::IntoIter;
        }

        impl<I: IntoIterator> Par<I> for I {
            #[inline(always)]
            fn par(self) -> I::IntoIter {
                self.into_iter()
            }
        }
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

pub fn to_u8_64(input: &[u8]) -> [u8; 64] {
    assert_eq!(input.len(), 64);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(input);
    bytes
}

pub(crate) fn to_u8_32(input: &[u8]) -> Result<[u8; 32], &'static str> {
    if input.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(input);
        Ok(bytes)
    } else {
        Err("Not 32 bytes")
    }
}

pub fn to_u8_array<const N: usize>(input: &[u8]) -> [u8; N] {
    assert_eq!(input.len(), N);
    let mut bytes = [0u8; N];
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

pub fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
