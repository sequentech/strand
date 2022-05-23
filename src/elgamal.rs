// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequenttech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::byte_tree::{BTreeDeser, BTreeSer};
use crate::context::{Ctx, Element};
use crate::symmetric;
use crate::zkp::ChaumPedersen;

#[derive(Clone, Eq, PartialEq)]
pub struct Ciphertext<C: Ctx> {
    pub(crate) mhr: C::E,
    pub gr: C::E,
}

#[derive(Eq, PartialEq)]
pub struct PublicKey<C: Ctx> {
    pub(crate) value: C::E,
}

#[derive(Eq, PartialEq)]
pub struct PrivateKey<C: Ctx> {
    pub(crate) value: C::X,
    pub public_value: C::E,
}

#[derive(Eq, PartialEq)]
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: [u8; 16],
}

impl<C: Ctx> PublicKey<C> {
    pub fn encrypt(&self, plaintext: &C::E) -> Ciphertext<C> {
        let randomness = C::get().rnd_exp();
        self.encrypt_ext(plaintext, &randomness)
    }
    pub fn encrypt_exponential(&self, plaintext: &C::X, randomness: &C::X) -> Ciphertext<C> {
        let ctx = C::get();
        self.encrypt_ext(&ctx.gmod_pow(plaintext), randomness)
    }
    pub fn encrypt_ext(&self, plaintext: &C::E, randomness: &C::X) -> Ciphertext<C> {
        let ctx = C::get();
        Ciphertext {
            mhr: plaintext
                .mul(&ctx.emod_pow(&self.value, randomness))
                .modulo(ctx.modulus()),
            gr: ctx.gmod_pow(randomness),
        }
    }
    pub fn from(pk_value: &C::E) -> PublicKey<C> {
        PublicKey {
            value: pk_value.clone(),
        }
    }
}

impl<C: Ctx> PrivateKey<C> {
    pub fn decrypt(&self, c: &Ciphertext<C>) -> C::E {
        let modulus = C::get().modulus();

        c.mhr
            .div(&c.gr.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let ctx = C::get();
        let modulus = ctx.modulus();

        let dec_factor = &c.gr.mod_pow(&self.value, modulus);

        let proof = ctx.cp_prove(
            &self.value,
            &self.public_value,
            dec_factor,
            None,
            &c.gr,
            label,
        );

        let decrypted = c.mhr.div(dec_factor, modulus).modulo(modulus);

        (decrypted, proof)
    }
    pub fn decryption_factor(&self, c: &Ciphertext<C>) -> C::E {
        let modulus = C::get().modulus();

        c.gr.mod_pow(&self.value, modulus)
    }
    pub fn from(secret: &C::X, ctx: &C) -> PrivateKey<C> {
        let public_value = ctx.gmod_pow(secret);
        PrivateKey {
            value: secret.clone(),
            public_value,
        }
    }
    pub fn to_encrypted(&self, key: [u8; 32]) -> EncryptedPrivateKey {
        let key_bytes = self.value.ser();
        let (b, iv) = symmetric::encrypt(key, &key_bytes);
        EncryptedPrivateKey { bytes: b, iv }
    }
    pub fn from_encrypted(key: [u8; 32], encrypted: EncryptedPrivateKey) -> PrivateKey<C> {
        let ctx = C::get();
        let key_bytes = symmetric::decrypt(key, encrypted.iv, &encrypted.bytes);
        let value = C::X::deser(&key_bytes).unwrap();
        let public_value = ctx.gmod_pow(&value);

        PrivateKey {
            value,
            public_value,
        }
    }
}
