// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequenttech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::byte_tree::{BTreeDeser, BTreeSer};
use crate::context::{Ctx, Element};
use crate::symmetric;
use crate::zkp::ChaumPedersen;
use std::marker::PhantomData;

#[derive(Clone, Eq, PartialEq)]
pub struct Ciphertext<C: Ctx> {
    pub(crate) mhr: C::E,
    pub(crate) gr: C::E,
}
impl<C: Ctx> Ciphertext<C> {
    pub fn mhr(&self) -> &C::E {
        &self.mhr
    }
    pub fn gr(&self) -> &C::E {
        &self.gr
    }
}

#[derive(Eq, PartialEq)]
pub struct PublicKey<C: Ctx> {
    pub(crate) value: C::E,
    pub(crate) ctx: C,
}

#[derive(Eq, PartialEq)]
pub struct PrivateKey<C: Ctx> {
    pub(crate) value: C::X,
    pub(crate) public_value: C::E,
    pub(crate) ctx: C,
}

#[derive(Eq, PartialEq)]
pub struct EncryptedPrivateKey<C: Ctx> {
    pub bytes: Vec<u8>,
    pub iv: [u8; 16],
    pub phantom: PhantomData<C>,
}

impl<C: Ctx> PublicKey<C> {
    pub fn encrypt(&self, plaintext: &C::E) -> Ciphertext<C> {
        let randomness = self.ctx.rnd_exp();
        self.encrypt_ext(plaintext, &randomness)
    }
    pub fn encrypt_exponential(&self, plaintext: &C::X, randomness: &C::X) -> Ciphertext<C> {
        self.encrypt_ext(&self.ctx.gmod_pow(plaintext), randomness)
    }
    pub fn encrypt_ext(&self, plaintext: &C::E, randomness: &C::X) -> Ciphertext<C> {
        let ctx = &self.ctx;
        Ciphertext {
            mhr: plaintext
                .mul(&ctx.emod_pow(&self.value, randomness))
                .modulo(ctx.modulus()),
            gr: ctx.gmod_pow(randomness),
        }
    }
    pub fn from(pk_value: &C::E, ctx: &C) -> PublicKey<C> {
        PublicKey {
            value: pk_value.clone(),
            ctx: (*ctx).clone(),
        }
    }
}

impl<C: Ctx> PrivateKey<C> {
    pub fn decrypt(&self, c: &Ciphertext<C>) -> C::E {
        let modulus = self.ctx.modulus();

        c.mhr
            .div(&c.gr.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove(&self, c: &Ciphertext<C>, label: &[u8]) -> (C::E, ChaumPedersen<C>) {
        let ctx = &self.ctx;
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
        let modulus = self.ctx.modulus();

        c.gr.mod_pow(&self.value, modulus)
    }
    pub fn from(secret: &C::X, ctx: &C) -> PrivateKey<C> {
        let public_value = ctx.gmod_pow(secret);
        PrivateKey {
            value: secret.clone(),
            public_value,
            ctx: (*ctx).clone(),
        }
    }
    pub fn to_encrypted(&self, key: [u8; 32]) -> EncryptedPrivateKey<C> {
        let key_bytes = self.value.ser();
        let (b, iv) = symmetric::encrypt(key, &key_bytes);
        let phantom = PhantomData;
        EncryptedPrivateKey {
            bytes: b,
            iv,
            phantom,
        }
    }
    pub fn from_encrypted(
        key: [u8; 32],
        encrypted: EncryptedPrivateKey<C>,
        ctx: &C,
    ) -> PrivateKey<C> {
        let key_bytes = symmetric::decrypt(key, encrypted.iv, &encrypted.bytes);
        let value = C::X::deser(&key_bytes).unwrap();
        let public_value = ctx.gmod_pow(&value);

        PrivateKey {
            value,
            public_value,
            ctx: (*ctx).clone(),
        }
    }

    pub fn public_value(&self) -> &C::E {
        &self.public_value
    }
}
