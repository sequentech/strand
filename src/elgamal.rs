// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequenttech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::byte_tree::{BTreeDeser, BTreeSer};
use crate::context::{Ctx, Element};
use crate::symmetric;
use crate::zkp::ChaumPedersen;

#[derive(Eq, PartialEq)]
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: [u8; 16],
}

#[derive(Clone, Eq, PartialEq)]
pub struct Ciphertext<C: Ctx> {
    pub a: C::E,
    pub b: C::E,
}

#[derive(Eq, PartialEq)]
pub struct PublicKey<C: Ctx> {
    pub value: C::E,
    pub ctx: C,
}

#[derive(Eq, PartialEq)]
pub struct PrivateKey<C: Ctx> {
    pub value: C::X,
    pub public_value: C::E,
    pub ctx: C,
}

impl<C: Ctx> PublicKey<C> {
    pub fn encrypt(&self, plaintext: &C::E) -> Ciphertext<C> {
        let randomness = self.ctx.rnd_exp();
        self.encrypt_ext(plaintext, &randomness)
    }
    pub fn encrypt_exponential(&self, plaintext: &C::X, randomness: &C::X) -> Ciphertext<C> {
        self.encrypt_ext(
            &self.ctx.generator().mod_pow(plaintext, &self.ctx.modulus()),
            randomness,
        )
    }
    pub fn encrypt_ext(&self, plaintext: &C::E, randomness: &C::X) -> Ciphertext<C> {
        Ciphertext {
            a: plaintext
                .mul(&self.value.mod_pow(randomness, &self.ctx.modulus()))
                .modulo(&self.ctx.modulus()),
            b: self
                .ctx
                .generator()
                .mod_pow(randomness, &self.ctx.modulus()),
        }
    }
    pub fn from(pk_value: &C::E, ctx: &C) -> PublicKey<C> {
        PublicKey {
            value: pk_value.clone(),
            ctx: ctx.clone(),
        }
    }
}

impl<C: Ctx> PrivateKey<C> {
    pub fn decrypt(&self, c: &Ciphertext<C>) -> C::E {
        let modulus = &self.ctx.modulus();

        c.a.div(&c.b.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let modulus = &self.ctx.modulus();

        let dec_factor = &c.b.mod_pow(&self.value, modulus);

        let proof = self.ctx.cp_prove(
            &self.value,
            &self.public_value,
            dec_factor,
            None,
            &c.b,
            label,
        );

        let decrypted = c.a.div(dec_factor, modulus).modulo(modulus);

        (decrypted, proof)
    }
    pub fn decryption_factor(&self, c: &Ciphertext<C>) -> C::E {
        let modulus = &self.ctx.modulus();

        c.b.mod_pow(&self.value, modulus)
    }
    pub fn from(secret: &C::X, ctx: &C) -> PrivateKey<C> {
        let public_value = ctx.gmod_pow(secret);
        PrivateKey {
            value: secret.clone(),
            ctx: ctx.clone(),
            public_value,
        }
    }
    pub fn to_encrypted(&self, key: [u8; 32]) -> EncryptedPrivateKey {
        let key_bytes = self.value.ser();
        let (b, iv) = symmetric::encrypt(key, &key_bytes);
        EncryptedPrivateKey { bytes: b, iv }
    }
    pub fn from_encrypted(key: [u8; 32], encrypted: EncryptedPrivateKey, ctx: &C) -> PrivateKey<C> {
        let key_bytes = symmetric::decrypt(key, encrypted.iv, &encrypted.bytes);
        let value = C::X::deser(&key_bytes).unwrap();
        let public_value = ctx.gmod_pow(&value);

        PrivateKey {
            value,
            ctx: ctx.clone(),
            public_value,
        }
    }
}
