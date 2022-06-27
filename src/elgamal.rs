// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
use std::marker::PhantomData;

use crate::byte_tree::{BTreeDeser, BTreeSer};
use crate::context::{Ctx, Element};
use crate::symmetric;
use crate::zkp::{ChaumPedersen, Zkp};

#[derive(Clone, Eq, PartialEq, Debug)]
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

#[derive(Eq, PartialEq, Debug)]
pub struct PublicKey<C: Ctx> {
    pub(crate) element: C::E,
    pub(crate) ctx: C,
}

#[derive(Eq, PartialEq, Debug)]
pub struct PrivateKey<C: Ctx> {
    pub(crate) value: C::X,
    pub(crate) pk_element: C::E,
    pub(crate) ctx: C,
}

#[derive(Eq, PartialEq)]
pub struct EncryptedPrivateKey<C: Ctx> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) iv: [u8; 16],
    pub(crate) phantom: PhantomData<C>,
}

impl<C: Ctx> PublicKey<C> {
    pub fn encrypt(&self, plaintext: &C::E) -> Ciphertext<C> {
        let randomness = self.ctx.rnd_exp();
        self.encrypt_with_randomness(plaintext, &randomness)
    }
    pub fn encrypt_exponential(&self, plaintext: &C::X) -> Ciphertext<C> {
        self.encrypt(&self.ctx.gmod_pow(plaintext))
    }
    pub fn encrypt_with_randomness(&self, plaintext: &C::E, randomness: &C::X) -> Ciphertext<C> {
        let ctx = &self.ctx;
        Ciphertext {
            mhr: plaintext
                .mul(&ctx.emod_pow(&self.element, randomness))
                .modulo(ctx.modulus()),
            gr: ctx.gmod_pow(randomness),
        }
    }
    pub fn from_element(element: &C::E, ctx: &C) -> PublicKey<C> {
        PublicKey {
            element: element.clone(),
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
        let zkp = Zkp::new(ctx);
        let modulus = ctx.modulus();

        let dec_factor = &c.gr.mod_pow(&self.value, modulus);

        let proof = zkp.cp_prove(
            &self.value,
            &self.pk_element,
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
    pub fn gen(ctx: &C) -> PrivateKey<C> {
        let secret = ctx.rnd_exp();
        PrivateKey::from(&secret, ctx)
    }
    pub fn from(secret: &C::X, ctx: &C) -> PrivateKey<C> {
        let pk_element = ctx.gmod_pow(secret);
        PrivateKey {
            value: secret.clone(),
            pk_element,
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
        // FIXME handle this error
        let value = C::X::deser(&key_bytes, ctx).unwrap();
        let pk_element = ctx.gmod_pow(&value);

        PrivateKey {
            value,
            pk_element,
            ctx: (*ctx).clone(),
        }
    }

    pub fn pk_element(&self) -> &C::E {
        &self.pk_element
    }

    pub fn get_pk(&self) -> PublicKey<C> {
        PublicKey {
            element: self.pk_element.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
