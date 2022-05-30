// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

pub mod numb;
// pub mod num_bigint;
pub mod ristretto;
#[cfg(feature = "rug")]
pub mod rug;

// https://github.com/bfh-evg/unicrypt/blob/2c9b223c1abc6266aa56ace5562200a5050a0c2a/src/main/java/ch/bfh/unicrypt/helper/prime/SafePrime.java
const P_STR_2048: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063";
const Q_STR_2048: &str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf34e8031";
// const P_STR_3072: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7";
// const Q_STR_3072: &str = "5bf0a8b1457695355fb8ac404e7a79e3b1738b079c5a6d2b53c26c8228c867f799273b9c49367df2fa5fc6c6c618ebb1ed0364055d88c2f5a7be3dababfacac24867ea3ebe0cdda10ac6caaa7bda35e76aae26bcfeaf926b309e18e1c1cd16efc54d13b5e7dfd0e43be2b1426d5bce6a6159949e9074f2f5781563056649f6c3a21152976591c7f772d5b56ec1afe8d03a9e8547bc729be95caddbcec6e57632160f4f91dc14dae13c05f9c39befc5d98068099a50685ec322e5fd39d30b07ff1c9e2465dde5030787fc763698df5ae6776bf9785d84400b8b1de306fa2d07658de6944d8365dff510d68470c23f9fb9bc6ab676ca3206b77869e9bdf3380470c368df93adcd920ef5b23a4d23efefdcb31961f5830db2395dfc26130a2724e1682619277886f289e9fa88a5c5ae9ba6c9e5c43ce3ea97feb95d0557393bed3dd0da578a446c741b578a432f361bd5b43b7f3485ab88909c1579a0d7f4a7bbde783641dc7fab3af84bc83a56cd3c3de2dcdea5862c9be9f6f261d3c9cb20ce6b";

#[cfg(any(test, feature = "wasmtest"))]
pub(crate) mod tests {
    use crate::context::Ctx;
    use crate::context::Element;
    use crate::elgamal::*;
    use crate::keymaker::*;
    use crate::shuffler::{ShuffleProof, Shuffler};
    use crate::symmetric;
    use std::time::{Duration, Instant};

    use crate::byte_tree::*;
    use crate::util;
    use crate::zkp::{ChaumPedersen, Schnorr};

    pub(crate) fn test_elgamal_generic<C: Ctx>(ctx: &C, data: C::P) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value, ctx);

        let plaintext = ctx.encode(&data).unwrap();

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

        let plaintext = ctx.encode(&data).unwrap();

        let c = pk.encrypt(&plaintext);
        let (d, proof) = sk.decrypt_and_prove(&c, &vec![]);

        let dec_factor = c.mhr.div(&d, &ctx.modulus()).modulo(&ctx.modulus());

        let verified = ctx.cp_verify(&pk.value, &dec_factor, None, &c.gr, &proof, &vec![]);
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

        let plaintext = ctx.encode(&data).unwrap();

        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];

        let pk_combined = Keymaker::combine_pks(ctx, pks);
        let c = pk_combined.encrypt(&plaintext);

        let (dec_f1, proof1) = km1.decryption_factor(&c, &vec![]);
        let (dec_f2, proof2) = km2.decryption_factor(&c, &vec![]);

        let verified1 = ctx.cp_verify(pk1_value, &dec_f1, None, &c.gr, &proof1, &vec![]);
        let verified2 = ctx.cp_verify(pk2_value, &dec_f2, None, &c.gr, &proof2, &vec![]);
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
        let _sk1_d = EncryptedPrivateKey::<C>::deser(&sk1_b).unwrap();

        let share2_pk_d = PublicKey::<C>::deser(&share2_pk_b).unwrap();
        let share2_proof_d = Schnorr::<C>::deser(&share2_proof_b).unwrap();
        let _sk2_d = EncryptedPrivateKey::<C>::deser(&sk2_b).unwrap();

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
            let encoded = ctx.encode(&plaintext).unwrap();
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
            ctx: (*ctx).clone(),
        };

        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);

        let now = Instant::now();

        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm, &vec![]);

        println!("gen proof {}", now.elapsed().as_millis());

        let now = Instant::now();

        let ok = shuffler.check_proof(&proof, &es, &e_primes, &vec![]);

        println!("check proof {}", now.elapsed().as_millis());

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
            ctx: (*ctx).clone(),
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
            ctx: (*ctx).clone(),
        };
        let ok_d = shuffler_d.check_proof(&proof_d, &es_d, &eprimes_d, &vec![]);

        assert!(ok_d);
    }

    pub(crate) fn test_encrypted_sk_generic<C: Ctx>(ctx: &C, data: C::P) {
        let sk = ctx.gen_key();
        let pk: PublicKey<C> = PublicKey::from(&sk.public_value, ctx);
        let plaintext = ctx.encode(&data).unwrap();
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
