// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only
//! # Examples
//!
//! ```
//! // This example shows different operations related to ElGamal encryption.
//! use strand::context::Ctx;
//! use strand::backend::num_bigint::{BigintCtx, P2048};
//! use strand::elgamal::{PrivateKey, PublicKey};
//! use strand::zkp::Zkp;
//!
//! let ctx: BigintCtx::<P2048> = Default::default();
//! // generate an ElGamal keypair
//! let sk1 = PrivateKey::gen(&ctx);
//! let pk1 = sk1.get_pk();
//! // or construct a public key from a provided element
//! let pk2_element = ctx.rnd();
//! let pk2 = PublicKey::from_element(&pk2_element, &ctx);
//!
//! let plaintext = ctx.rnd_plaintext();
//! let encoded = ctx.encode(&plaintext).unwrap();
//!
//! // encrypt, generates randomness internally
//! let ciphertext = pk1.encrypt(&encoded);
//!
//! // or encrypt with provided randomness
//! let randomness = ctx.rnd_exp();
//! let ciphertext = pk1.encrypt_with_randomness(&encoded, &randomness);
//!
//! // encrypt and prove knowledge of plaintext (enc + pok)
//! let (c, proof) = pk1.encrypt_and_pok(&encoded, &vec![]);
//! // verify
//! let zkp = Zkp::new(&ctx);
//! let proof_ok = zkp.encryption_popk_verify(c.mhr(), c.gr(), &proof, &vec![]);
//! assert!(proof_ok);
//! let decrypted = sk1.decrypt(&c);
//! let plaintext_ = ctx.decode(&decrypted);
//! assert_eq!(plaintext, plaintext_);
//! ```

use borsh::{BorshDeserialize, BorshSerialize};

use crate::context::{Ctx, Element};
use crate::zkp::{ChaumPedersen, Schnorr, Zkp};

/// An ElGamal ciphertext.
///
/// Composed of two group elements, computed as
///
/// (m * h^r, g^r)
///
/// where m = message, h = public key, g = generator, r = randomness.
#[derive(Clone, Eq, PartialEq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Ciphertext<C: Ctx> {
    pub mhr: C::E,
    pub gr: C::E,
}
impl<C: Ctx> Ciphertext<C> {
    /// Returns the ciphertext part computed as m * h^r.
    pub fn mhr(&self) -> &C::E {
        &self.mhr
    }
    /// Returns the ciphertext part computed as g^r.
    pub fn gr(&self) -> &C::E {
        &self.gr
    }
}

/// An ElGamal public key.
#[derive(Eq, PartialEq, Debug, BorshSerialize, BorshDeserialize)]
pub struct PublicKey<C: Ctx> {
    pub(crate) element: C::E,
    #[borsh_skip]
    pub(crate) ctx: C,
}

/// An ElGamal private key.
#[derive(Eq, PartialEq, Debug, BorshSerialize, BorshDeserialize)]
pub struct PrivateKey<C: Ctx> {
    pub(crate) value: C::X,
    pub(crate) pk_element: C::E,
    #[borsh_skip]
    pub(crate) ctx: C,
}

impl<C: Ctx> PublicKey<C> {
    pub fn encrypt(&self, plaintext: &C::E) -> Ciphertext<C> {
        let randomness = self.ctx.rnd_exp();
        self.encrypt_with_randomness(plaintext, &randomness)
    }
    pub fn encrypt_and_pok(
        &self,
        plaintext: &C::E,
        label: &[u8],
    ) -> (Ciphertext<C>, Schnorr<C>) {
        let zkp = Zkp::new(&self.ctx);
        let randomness = self.ctx.rnd_exp();
        let c = self.encrypt_with_randomness(plaintext, &randomness);
        let proof = zkp.encryption_popk(&randomness, &c.mhr, &c.gr, label);

        (c, proof)
    }
    pub fn encrypt_exponential(&self, plaintext: &C::X) -> Ciphertext<C> {
        self.encrypt(&self.ctx.gmod_pow(plaintext))
    }
    pub fn encrypt_with_randomness(
        &self,
        plaintext: &C::E,
        randomness: &C::X,
    ) -> Ciphertext<C> {
        let ctx = &self.ctx;
        Ciphertext {
            mhr: plaintext
                .mul(&ctx.emod_pow(&self.element, randomness))
                .modp(ctx),
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
        let ctx = &self.ctx;
        c.mhr
            .divp(&ctx.emod_pow(&c.gr, &self.value), ctx)
            .modp(ctx)
    }
    pub fn decrypt_and_prove(
        &self,
        c: &Ciphertext<C>,
        label: &[u8],
    ) -> (C::E, ChaumPedersen<C>) {
        let ctx = &self.ctx;
        let zkp = Zkp::new(ctx);

        let dec_factor = &ctx.emod_pow(&c.gr, &self.value);

        let proof = zkp.decryption_proof(
            &self.value,
            &self.pk_element,
            dec_factor,
            &c.mhr,
            &c.gr,
            label,
        );

        let decrypted = c.mhr.divp(dec_factor, ctx).modp(ctx);

        (decrypted, proof)
    }
    pub fn decryption_factor(&self, c: &Ciphertext<C>) -> C::E {
        self.ctx.emod_pow(&c.gr, &self.value)
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

/*

Taken from hom.rs

// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::elgamal::{Ciphertext, PublicKey};
use crate::crypto::group::{ChaumPedersen, Element, Exponent, Group};

// we need to prove that equality of discrete logs for
// a / g^value and b, ie
// a / g^value = g1^x and b = g2^x
// for some x, given a, b, g1, g2
#[allow(dead_code)]
fn prove_value<E: Element, G: Group<E>>(
    pk: &PublicKey<E, G>,
    secret: &E::Exp,
    ciphertext: &Ciphertext<E>,
    value: &E::Exp,
    label: &[u8],
) -> ChaumPedersen<E> {
    let group = &pk.group;
    let v1 = &ciphertext.b;
    let v2 = ciphertext.a.div(&group.gmod_pow(value), &group.modulus());
    let g1 = None;
    let g2 = &pk.value;

    group.cp_prove(secret, v1, &v2, g1, g2, label)
}

#[allow(dead_code)]
fn verify_value<E: Element, G: Group<E>>(
    proof: &ChaumPedersen<E>,
    pk: &PublicKey<E, G>,
    ciphertext: &Ciphertext<E>,
    value: &E::Exp,
    label: &[u8],
) -> bool {
    let group = &pk.group;
    let v1 = &ciphertext.b;
    let v2 = ciphertext.a.div(&group.gmod_pow(value), &group.modulus());
    let g1 = None;
    let g2 = &pk.value;

    group.cp_verify(v1, &v2, g1, g2, proof, label)
}

// OPT 1 parallel
// OPT 2 precompute table (this is already included by ristretto backend)
#[allow(dead_code)]
fn discrete_log<E: Element, G: Group<E>>(group: G, element: E, max: i32) -> Option<E::Exp> {
    let mut exp: E::Exp = E::Exp::add_identity();
    let one = &E::Exp::mul_identity();
    for _ in 0..max {
        let next = group.gmod_pow(&exp);
        if next == element {
            return Some(exp);
        }
        exp = exp.add(one);
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::crypto::hom::*;

    use rand::Rng;
    use rug::Integer;

    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::backend::rug_b::*;
    use crate::crypto::group::Group;

    #[test]
    fn test_hom_discretelog() {
        let max = 1000;
        let mut rng = rand::thread_rng();

        let group = RugGroup::default();
        let exp_value = Integer::from(rng.gen_range(0, max + 1));
        let v = group.gmod_pow(&exp_value);

        let result = discrete_log(group, v, max + 1);
        assert!(result.is_some());
        assert_eq!(exp_value, result.unwrap());
    }

    #[test]
    fn test_hom_prove_value() {
        let group = RugGroup::default();
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.rnd_exp();
        let r = group.rnd_exp();
        let c = pk.encrypt_exponential(&plaintext, &r);

        let proof = prove_value(&pk, &r, &c, &plaintext, &vec![]);
        let verified = verify_value(&proof, &pk, &c, &plaintext, &vec![]);
        assert!(verified);
        let verified = verify_value(&proof, &pk, &c, &group.rnd_exp(), &vec![]);
        assert!(!verified);

        let group = RistrettoGroup;
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let plaintext = group.rnd_exp();
        let r = group.rnd_exp();
        let c = pk.encrypt_exponential(&plaintext, &r);

        let proof = prove_value(&pk, &r, &c, &plaintext, &vec![]);
        let verified = verify_value(&proof, &pk, &c, &plaintext, &vec![]);
        assert!(verified);
        let verified = verify_value(&proof, &pk, &c, &group.rnd_exp(), &vec![]);
        assert!(!verified);
    }
}


*/
