// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

pub mod num_bigint;
// broken
pub mod b;
// pub mod c;
pub mod ristretto;
// pub mod rug_b;

#[cfg(any(test, feature = "wasmtest"))]
pub(crate) mod tests {
    use crate::context::Ctx;
    use crate::context::Element;
    use crate::elgamal::*;
    use crate::keymaker::*;
    use crate::shuffler::{ShuffleProof, Shuffler};
    use crate::symmetric;

    use crate::byte_tree::*;
    use crate::util;
    use crate::zkp::{ChaumPedersen, Schnorr};

    pub(crate) fn test_elgamal_generic<C: Ctx>(ctx: &C, data: C::P) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        let plaintext = ctx.encode(&data);

        let c = pk.encrypt(&plaintext);
        let d = sk.decrypt(&c);

        let recovered = ctx.decode(&d);
        assert_eq!(data, recovered);
    }

    pub(crate) fn test_schnorr_generic<C: Ctx>(ctx: &C) {
        let g = ctx.generator();
        let secret = ctx.rnd_exp();
        let public = g.mod_pow(&secret, &ctx.modulus());
        let schnorr = ctx.schnorr_prove(&secret, &public, &g, &vec![]);
        let verified = ctx.schnorr_verify(&public, &g, &schnorr, &vec![]);
        assert!(verified);
        let public_false = ctx.generator().mod_pow(&ctx.rnd_exp(), &ctx.modulus());
        let verified_false = ctx.schnorr_verify(&public_false, &g, &schnorr, &vec![]);
        assert!(verified_false == false);
    }

    pub(crate) fn test_chaumpedersen_generic<C: Ctx>(ctx: &C) {
        let g1 = ctx.generator();
        let g2 = ctx.rnd();
        let secret = ctx.rnd_exp();
        let public1 = g1.mod_pow(&secret, &ctx.modulus());
        let public2 = g2.mod_pow(&secret, &ctx.modulus());
        let proof = ctx.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = ctx.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);

        assert!(verified);
        let public_false = ctx.generator().mod_pow(&ctx.rnd_exp(), &ctx.modulus());
        let verified_false = ctx.cp_verify(&public1, &public_false, None, &g2, &proof, &vec![]);
        assert!(verified_false == false);
    }

    pub(crate) fn test_vdecryption_generic<C: Ctx>(ctx: &C, data: C::P) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        let plaintext = ctx.encode(&data);

        let c = pk.encrypt(&plaintext);
        let (d, proof) = sk.decrypt_and_prove(&c, &vec![]);

        let dec_factor = c.a.div(&d, &ctx.modulus()).modulo(&ctx.modulus());

        let verified = ctx.cp_verify(&pk.value, &dec_factor, None, &c.b, &proof, &vec![]);
        let recovered = ctx.decode(&d);
        assert!(verified);
        assert_eq!(data, recovered);
    }

    pub(crate) fn test_distributed_generic<C: Ctx>(ctx: &C, data: C::P) {
        let km1 = Keymaker::gen(ctx);
        let km2 = Keymaker::gen(ctx);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);

        let verified1 = ctx.schnorr_verify(&pk1.value, &ctx.generator(), &proof1, &vec![]);
        let verified2 = ctx.schnorr_verify(&pk2.value, &ctx.generator(), &proof2, &vec![]);
        assert!(verified1);
        assert!(verified2);

        let plaintext = ctx.encode(&data);

        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];

        let pk_combined = Keymaker::combine_pks(ctx, pks);
        let c = pk_combined.encrypt(&plaintext);

        let (dec_f1, proof1) = km1.decryption_factor(&c, &vec![]);
        let (dec_f2, proof2) = km2.decryption_factor(&c, &vec![]);

        let verified1 = ctx.cp_verify(pk1_value, &dec_f1, None, &c.b, &proof1, &vec![]);
        let verified2 = ctx.cp_verify(pk2_value, &dec_f2, None, &c.b, &proof2, &vec![]);
        assert!(verified1);
        assert!(verified2);

        let decs = vec![dec_f1, dec_f2];
        let d = Keymaker::joint_dec(ctx, decs, &c);
        let recovered = ctx.decode(&d);
        assert_eq!(data, recovered);
    }

    pub(crate) fn test_distributed_btserde_generic<C: Ctx>(ctx: &C, data: Vec<C::P>) {
        let km1 = Keymaker::gen(ctx);
        let km2 = Keymaker::gen(ctx);
        let (pk1, proof1) = km1.share(&vec![]);
        let (pk2, proof2) = km2.share(&vec![]);
        let sym1 = symmetric::gen_key();
        let sym2 = symmetric::gen_key();
        let esk1 = km1.get_encrypted_sk(sym1);
        let esk2 = km2.get_encrypted_sk(sym2);

        let share1_pk_b = pk1.ser();
        let share1_proof_b = proof1.ser();
        let sk1_b = esk1.ser();

        let share2_pk_b = pk2.ser();
        let share2_proof_b = proof2.ser();
        let sk2_b = esk2.ser();

        let share1_pk_d = PublicKey::<C>::deser(&share1_pk_b).unwrap();
        let share1_proof_d = Schnorr::<C>::deser(&share1_proof_b).unwrap();
        let _sk1_d = EncryptedPrivateKey::deser(&sk1_b).unwrap();

        let share2_pk_d = PublicKey::<C>::deser(&share2_pk_b).unwrap();
        let share2_proof_d = Schnorr::<C>::deser(&share2_proof_b).unwrap();
        let _sk2_d = EncryptedPrivateKey::deser(&sk2_b).unwrap();

        let verified1 = Keymaker::verify_share(ctx, &share1_pk_d, &share1_proof_d, &vec![]);
        let verified2 = Keymaker::verify_share(ctx, &share2_pk_d, &share2_proof_d, &vec![]);

        assert!(verified1);
        assert!(verified2);

        let pk1_value = &share1_pk_d.value.clone();
        let pk2_value = &share2_pk_d.value.clone();
        let pks = vec![share1_pk_d, share2_pk_d];

        let pk_combined = Keymaker::combine_pks(ctx, pks);
        let mut cs = vec![];

        for plaintext in &data {
            let encoded = ctx.encode(&plaintext);
            let c = pk_combined.encrypt(&encoded);
            cs.push(c);
        }

        let (decs1, proofs1) = km1.decryption_factor_many(&cs, &vec![]);
        let (decs2, proofs2) = km2.decryption_factor_many(&cs, &vec![]);

        let decs1_b = decs1.ser();
        let proofs1_b = proofs1.ser();

        let decs2_b = decs2.ser();
        let proofs2_b = proofs2.ser();

        let decs1_d = Vec::<C::E>::deser(&decs1_b).unwrap();
        let proofs1_d = Vec::<ChaumPedersen<C>>::deser(&proofs1_b).unwrap();

        let decs2_d = Vec::<C::E>::deser(&decs2_b).unwrap();
        let proofs2_d = Vec::<ChaumPedersen<C>>::deser(&proofs2_b).unwrap();

        let verified1 =
            Keymaker::verify_decryption_factors(ctx, pk1_value, &cs, &decs1_d, &proofs1_d, &vec![]);
        let verified2 =
            Keymaker::verify_decryption_factors(ctx, pk2_value, &cs, &decs2_d, &proofs2_d, &vec![]);

        assert!(verified1);
        assert!(verified2);

        let decs = vec![decs1_d, decs2_d];
        let ds = Keymaker::joint_dec_many(ctx, &decs, &cs);

        let recovered: Vec<C::P> = ds.into_iter().map(|d| ctx.decode(&d)).collect();

        assert_eq!(data, recovered);
    }

    pub(crate) fn test_shuffle_generic<C: Ctx>(ctx: &C) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        let es = util::random_ballots(10, ctx);
        let seed = vec![];
        let hs = ctx.generators(es.len() + 1, 0, &seed);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
        };

        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);
        let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

        assert!(ok);
    }

    pub(crate) fn test_shuffle_btserde_generic<C: Ctx>(ctx: &C) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        let es = util::random_ballots(10, ctx);
        let seed = vec![];
        let hs = ctx.generators(es.len() + 1, 0, &seed);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);
        let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

        let pk_b = pk.ser();
        let es_b = es.ser();
        let eprimes_b = e_primes.ser();
        let proof_b = proof.ser();

        assert!(ok);

        let pk_d = PublicKey::<C>::deser(&pk_b).unwrap();
        let es_d = Vec::<Ciphertext<C>>::deser(&es_b).unwrap();
        let eprimes_d = Vec::<Ciphertext<C>>::deser(&eprimes_b).unwrap();
        let proof_d = ShuffleProof::<C>::deser(&proof_b).unwrap();

        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
        };
        let ok_d = shuffler_d.check_proof(&proof_d, &es_d, &eprimes_d, &vec![]);

        assert!(ok_d);
    }

    pub(crate) fn test_encrypted_sk_generic<C: Ctx>(ctx: &C, data: C::P) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);
        let plaintext = ctx.encode(&data);
        let c = pk.encrypt(&plaintext);
        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);

        let enc_sk_b = enc_sk.ser();
        let enc_sk_d = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();

        let sk_d = PrivateKey::from_encrypted(sym_key, enc_sk_d, ctx);
        let d = sk_d.decrypt(&c);

        let recovered = ctx.decode(&d);
        assert_eq!(data, recovered);
    }
}
