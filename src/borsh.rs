use crate::{
    backend::num_bigint::{BigUintE, BigUintX, BigintCtx, BigintCtxParams},
    context::Ctx,
};
use borsh::{BorshSerialize, BorshDeserialize};

pub trait StrandSerialize {
    fn strand_serialize(&self) -> Vec<u8>;
}

pub trait StrandDeserialize {
    fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;
}
pub trait StrandSerialization: StrandSerialize + StrandDeserialize {}
impl<T: StrandSerialize + StrandDeserialize> StrandSerialization for T {}


impl<T: BorshSerialize> StrandSerialize for T {
    fn strand_serialize(&self) -> Vec<u8> {
        // FIXME log on failure
        self.try_to_vec().unwrap()
    }
}

impl<T: BorshDeserialize> StrandDeserialize for T {
    fn strand_deserialize(bytes: &[u8]) -> Result<Self, &'static str>
    where Self: Sized {
        let value = T::try_from_slice(&bytes);
        if value.is_err() {
            // FIXME log on failure
        }
        value.map_err(|_| "borsh deserialize failed")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::context::{Ctx, Element};
    use crate::elgamal::{PrivateKey, Ciphertext, PublicKey};
    use crate::util;
    use crate::zkp::{Zkp, Schnorr, ChaumPedersen};
    use super::StrandSerialize;
    use super::StrandDeserialize;

    pub(crate) fn test_borsh_element<C: Ctx>(ctx: &C) {
        let e = ctx.rnd();

        let encoded_e = e.strand_serialize();
        let decoded_e = C::E::strand_deserialize(&encoded_e).unwrap();
        assert!(e == decoded_e);
    }

    pub(crate) fn test_borsh_exponent<C: Ctx>(ctx: &C) {
        let x = ctx.rnd_exp();

        let encoded_x = x.strand_serialize();
        let decoded_x = C::X::strand_deserialize(&encoded_x).unwrap();
        assert!(x == decoded_x);
    }

    pub(crate) fn test_ciphertext_borsh_generic<C: Ctx>(ctx: &C) {
        let c = util::random_ballots(1, ctx).remove(0);
        let bytes = c.strand_serialize();
        let back = Ciphertext::<C>::strand_deserialize(&bytes).unwrap();

        assert!(c.mhr == back.mhr && c.gr == back.gr);
    }

    pub(crate) fn test_key_borsh_generic<C: Ctx + Eq>(ctx: &C) {
        let sk = PrivateKey::gen(ctx);
        let pk = PublicKey::from_element(&sk.pk_element, ctx);

        let bytes = sk.strand_serialize();
        let back = PrivateKey::<C>::strand_deserialize(&bytes).unwrap();

        assert!(sk == back);

        let bytes = pk.strand_serialize();
        let back = PublicKey::<C>::strand_deserialize(&bytes).unwrap();

        assert!(pk == back);
    }

    pub(crate) fn test_schnorr_borsh_generic<C: Ctx + Eq>(ctx: &C) {
        let zkp = Zkp::new(ctx);
        let g = ctx.generator();
        let secret = ctx.rnd_exp();
        let public = g.mod_pow(&secret, &ctx.modulus());
        let schnorr = zkp.schnorr_prove(&secret, &public, Some(&g), &vec![]);
        let verified = zkp.schnorr_verify(&public, Some(&g), &schnorr, &vec![]);
        assert!(verified);

        let bytes = schnorr.strand_serialize();
        let back = Schnorr::<C>::strand_deserialize(&bytes).unwrap();
        assert!(schnorr == back);

        let verified = zkp.schnorr_verify(&public, Some(&g), &back, &vec![]);
        assert!(verified);
    }

    pub(crate) fn test_cp_borsh_generic<C: Ctx + Eq>(ctx: &C) {
        let zkp = Zkp::new(ctx);
        let g1 = ctx.generator();
        let g2 = ctx.rnd();
        let secret = ctx.rnd_exp();
        let public1 = g1.mod_pow(&secret, &ctx.modulus());
        let public2 = g2.mod_pow(&secret, &ctx.modulus());
        let proof = zkp.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = zkp.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);
        assert!(verified);

        let bytes = proof.strand_serialize();
        let back = ChaumPedersen::<C>::strand_deserialize(&bytes).unwrap();
        assert!(proof == back);

        let verified = zkp.cp_verify(&public1, &public2, None, &g2, &back, &vec![]);
        assert!(verified);
    }
}