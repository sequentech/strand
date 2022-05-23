use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::context::Ctx;
use crate::elgamal::{Ciphertext, EncryptedPrivateKey, PrivateKey, PublicKey};
use crate::shuffler::{Commitments, Responses, ShuffleProof};
use crate::util;
use crate::zkp::{ChaumPedersen, Schnorr};

quick_error! {
    #[derive(Debug)]
    pub enum ByteError {
        Empty{}
        Bincode(err: bincode::Error) {
            from()
        }
        Signature(err: ed25519_dalek::SignatureError) {
            from()
        }
        /*Enum(err: num_enum::TryFromPrimitiveError<StatementType>) {
            from()
        }*/
        Msg(message: String) {
            from()
        }
    }
}

const LEAF: u8 = 0;
const TREE: u8 = 1;

#[derive(Serialize, Deserialize)]
pub enum ByteTree {
    Leaf(ByteBuf),
    Tree(Vec<ByteTree>),
}

use ByteTree::Leaf;
use ByteTree::Tree;

// OPT: try to move instead of copy
impl ByteTree {
    pub(crate) fn leaf(&self) -> Result<&Vec<u8>, ByteError> {
        if let Leaf(bytes) = self {
            Ok(bytes)
        } else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Tree")))
        }
    }

    pub(crate) fn tree(&self, length: usize) -> Result<&Vec<ByteTree>, ByteError> {
        if let Tree(trees) = self {
            if trees.len() == length {
                Ok(trees)
            } else {
                Err(ByteError::Msg(String::from("ByteTree: size mismatch")))
            }
        } else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Leaf")))
        }
    }

    pub(crate) fn to_hashable_bytes(&self) -> Vec<u8> {
        match self {
            Leaf(bytes) => {
                let mut next: Vec<u8> = vec![];
                let length = bytes.len() as u64;
                next.push(LEAF);
                next.extend(&length.to_le_bytes());
                next.extend(bytes);

                next
            }

            Tree(trees) => {
                let mut next: Vec<u8> = vec![];
                let length = trees.len() as u64;
                next.push(TREE);
                next.extend(&length.to_le_bytes());
                for t in trees {
                    next.extend(t.to_hashable_bytes());
                }
                next
            }
        }
    }
}

pub trait ToByteTree {
    fn to_byte_tree(&self) -> ByteTree;
}
pub trait FromByteTree {
    fn from_byte_tree(tree: &ByteTree) -> Result<Self, ByteError>
    where
        Self: Sized;
}

impl<T: ToByteTree> ToByteTree for Vec<T> {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl<T: FromByteTree> FromByteTree for Vec<T> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Vec<T>, ByteError> {
        if let Tree(trees) = tree {
            let elements = trees
                .iter()
                .map(|b| T::from_byte_tree(b))
                .collect::<Result<Vec<T>, ByteError>>();

            elements
        } else {
            Err(ByteError::Msg(String::from(
                "ByteTree: unexpected Leaf constructing Vec<T: FromByteTree>",
            )))
        }
    }
}

impl ToByteTree for Vec<u8> {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(ByteBuf::from(self.to_vec()))
    }
}

impl FromByteTree for Vec<u8> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Vec<u8>, ByteError> {
        if let Leaf(bytes) = tree {
            Ok(bytes.to_vec())
        } else {
            Err(ByteError::Msg(String::from(
                "ByteTree: unexpected Tree constructing Vec<u8>",
            )))
        }
    }
}

/*
impl ToByteTree for [u8; 64] {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(ByteBuf::from(self.to_vec()))
    }
}
*/

pub trait BTreeSer {
    fn ser(&self) -> Vec<u8>;
}

pub trait BTreeDeser {
    fn deser(bytes: &[u8]) -> Result<Self, ByteError>
    where
        Self: Sized;
}

pub trait ToFromBTree: ToByteTree + FromByteTree {}
impl<T: ToByteTree + FromByteTree> ToFromBTree for T {}

impl<T: ToByteTree> BTreeSer for T {
    fn ser(&self) -> Vec<u8> {
        let tree = self.to_byte_tree();
        bincode::serialize(&tree).unwrap()
    }
}

impl<T: FromByteTree> BTreeDeser for T {
    fn deser(bytes: &[u8]) -> Result<T, ByteError> {
        let tree: ByteTree = bincode::deserialize(bytes)?;
        T::from_byte_tree(&tree)
    }
}

impl<T: ToByteTree> ToByteTree for [T] {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl ToByteTree for EncryptedPrivateKey {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            ByteTree::Leaf(ByteBuf::from(self.bytes.clone())),
            ByteTree::Leaf(ByteBuf::from(self.iv)),
        ];
        ByteTree::Tree(trees)
    }
}

impl FromByteTree for EncryptedPrivateKey {
    fn from_byte_tree(tree: &ByteTree) -> Result<EncryptedPrivateKey, ByteError> {
        let trees = tree.tree(2)?;
        let bytes = trees[0].leaf()?.to_vec();
        let iv_vec = trees[1].leaf()?;
        let iv = util::to_u8_16(iv_vec);

        let ret = EncryptedPrivateKey { bytes, iv };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for PrivateKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> =
            vec![self.value.to_byte_tree(), self.public_value.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for PrivateKey<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<PrivateKey<C>, ByteError> {
        let trees = tree.tree(2)?;
        let value = C::X::from_byte_tree(&trees[0])?;
        let public_value = C::E::from_byte_tree(&trees[1])?;
        let ret = PrivateKey {
            value,
            public_value,
        };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for Ciphertext<C>
where
    C::E: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.mhr.to_byte_tree(), self.gr.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for Ciphertext<C>
where
    C::E: ToByteTree,
{
    fn from_byte_tree(tree: &ByteTree) -> Result<Ciphertext<C>, ByteError> {
        let trees = tree.tree(2)?;
        let a = C::E::from_byte_tree(&trees[0])?;
        let b = C::E::from_byte_tree(&trees[1])?;
        Ok(Ciphertext { mhr: a, gr: b })
    }
}

impl<C: Ctx> ToByteTree for PublicKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        // let trees: Vec<ByteTree> = vec![self.value.to_byte_tree(), self.ctx.to_byte_tree()];
        let trees: Vec<ByteTree> = vec![self.value.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for PublicKey<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<PublicKey<C>, ByteError> {
        let trees = tree.tree(1)?;
        let value = C::E::from_byte_tree(&trees[0])?;
        // let ret = PublicKey { value, ctx };
        let ret = PublicKey { value };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for Schnorr<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.commitment.to_byte_tree(),
            self.challenge.to_byte_tree(),
            self.response.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for Schnorr<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Schnorr<C>, ByteError> {
        let trees = tree.tree(3)?;

        let commitment = C::E::from_byte_tree(&trees[0])?;
        let challenge = C::X::from_byte_tree(&trees[1])?;
        let response = C::X::from_byte_tree(&trees[2])?;
        let phantom = PhantomData;
        let ret = Schnorr {
            commitment,
            challenge,
            response,
            phantom,
        };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for ChaumPedersen<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.commitment1.to_byte_tree(),
            self.commitment2.to_byte_tree(),
            self.challenge.to_byte_tree(),
            self.response.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for ChaumPedersen<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<ChaumPedersen<C>, ByteError> {
        let trees = tree.tree(4)?;

        let commitment1 = C::E::from_byte_tree(&trees[0])?;
        let commitment2 = C::E::from_byte_tree(&trees[1])?;
        let challenge = C::X::from_byte_tree(&trees[2])?;
        let response = C::X::from_byte_tree(&trees[3])?;
        let phantom = PhantomData;
        let ret = ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
            phantom,
        };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for ShuffleProof<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.t.to_byte_tree(),
            self.s.to_byte_tree(),
            self.cs.to_byte_tree(),
            self.c_hats.to_byte_tree(),
        ];

        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for ShuffleProof<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<ShuffleProof<C>, ByteError> {
        let trees = tree.tree(4)?;
        let t = Commitments::<C>::from_byte_tree(&trees[0])?;
        let s = Responses::<C>::from_byte_tree(&trees[1])?;
        let cs = Vec::<C::E>::from_byte_tree(&trees[2])?;
        let c_hats = Vec::<C::E>::from_byte_tree(&trees[3])?;

        let ret = ShuffleProof { t, s, cs, c_hats };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for Commitments<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.t1.to_byte_tree(),
            self.t2.to_byte_tree(),
            self.t3.to_byte_tree(),
            self.t4_1.to_byte_tree(),
            self.t4_2.to_byte_tree(),
            self.t_hats.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for Commitments<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Commitments<C>, ByteError> {
        let trees = tree.tree(6)?;
        let t1 = C::E::from_byte_tree(&trees[0])?;
        let t2 = C::E::from_byte_tree(&trees[1])?;
        let t3 = C::E::from_byte_tree(&trees[2])?;
        let t4_1 = C::E::from_byte_tree(&trees[3])?;
        let t4_2 = C::E::from_byte_tree(&trees[4])?;
        let t_hats = Vec::<C::E>::from_byte_tree(&trees[5])?;

        let ret = Commitments {
            t1,
            t2,
            t3,
            t4_1,
            t4_2,
            t_hats,
        };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for Responses<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            self.s1.to_byte_tree(),
            self.s2.to_byte_tree(),
            self.s3.to_byte_tree(),
            self.s4.to_byte_tree(),
            self.s_hats.to_byte_tree(),
            self.s_primes.to_byte_tree(),
        ];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for Responses<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Responses<C>, ByteError> {
        let trees = tree.tree(6)?;
        let s1 = <C::X>::from_byte_tree(&trees[0])?;
        let s2 = <C::X>::from_byte_tree(&trees[1])?;
        let s3 = <C::X>::from_byte_tree(&trees[2])?;
        let s4 = <C::X>::from_byte_tree(&trees[3])?;
        let s_hats = Vec::<C::X>::from_byte_tree(&trees[4])?;
        let s_primes = Vec::<C::X>::from_byte_tree(&trees[5])?;

        let ret = Responses {
            s1,
            s2,
            s3,
            s4,
            s_hats,
            s_primes,
        };

        Ok(ret)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::context::{Ctx, Element};
    /*use crate::keymaker::*;
    use crate::shuffler::*;*/
    use crate::byte_tree::*;
    use crate::symmetric;

    // use ed25519_dalek::Keypair;

    pub(crate) fn test_ciphertext_bytes_generic<C: Ctx>(ctx: &C) {
        let c = util::random_ballots(1, ctx).remove(0);
        let bytes = c.ser();
        let back = Ciphertext::<C>::deser(&bytes).unwrap();

        assert!(c.mhr == back.mhr && c.gr == back.gr);
    }

    pub(crate) fn test_key_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let sk = ctx.gen_key();
        let pk = PublicKey::from(&sk.public_value);

        let bytes = sk.ser();
        let back = PrivateKey::<C>::deser(&bytes).unwrap();

        assert!(sk == back);

        let bytes = pk.ser();
        let back = PublicKey::<C>::deser(&bytes).unwrap();

        assert!(pk == back);
    }

    pub(crate) fn test_schnorr_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let g = ctx.generator();
        let secret = ctx.rnd_exp();
        let public = g.mod_pow(&secret, &ctx.modulus());
        let schnorr = ctx.schnorr_prove(&secret, &public, &g, &vec![]);
        let verified = ctx.schnorr_verify(&public, &g, &schnorr, &vec![]);
        assert!(verified);

        let bytes = schnorr.ser();
        let back = Schnorr::<C>::deser(&bytes).unwrap();
        assert!(schnorr == back);

        let verified = ctx.schnorr_verify(&public, &g, &back, &vec![]);
        assert!(verified);
    }

    pub(crate) fn test_cp_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let g1 = ctx.generator();
        let g2 = ctx.rnd();
        let secret = ctx.rnd_exp();
        let public1 = g1.mod_pow(&secret, &ctx.modulus());
        let public2 = g2.mod_pow(&secret, &ctx.modulus());
        let proof = ctx.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = ctx.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);
        assert!(verified);

        let bytes = proof.ser();
        let back = ChaumPedersen::<C>::deser(&bytes).unwrap();
        assert!(proof == back);

        let verified = ctx.cp_verify(&public1, &public2, None, &g2, &back, &vec![]);
        assert!(verified);
    }

    pub(crate) fn test_epk_bytes_generic<C: Ctx>(ctx: &C, plaintext: C::P) {
        let sk = ctx.gen_key();
        let pk: PublicKey<C> = PublicKey::from(&sk.public_value);

        let encoded = ctx.encode(&plaintext);
        let c = pk.encrypt(&encoded);

        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);
        let enc_sk_b = enc_sk.ser();
        let back = EncryptedPrivateKey::deser(&enc_sk_b).unwrap();
        assert!(enc_sk == back);

        let sk_d = PrivateKey::from_encrypted(sym_key, back);
        let d = ctx.decode(&sk_d.decrypt(&c));
        assert_eq!(d, plaintext);
    }
    /*
    pub(crate) fn test_share_bytes_generic<E: Element, G: Group<E> + Eq>(group: G) {
        let km = Keymaker::gen(&group);
        let (pk, proof) = km.share(&vec![]);

        let sym = symmetric::gen_key();
        let esk = km.get_encrypted_sk(sym);

        let share = Keyshare {
            share: pk,
            proof: proof,
            encrypted_sk: esk,
        };

        let bytes = share.ser();
        let back = Keyshare::<E, G>::deser(&bytes).unwrap();

        assert!(share.share == back.share);
        assert!(share.proof == back.proof);
        assert!(share.encrypted_sk == back.encrypted_sk);
    }*/

    /*


    #[test]
    fn test_share_bytes() {
        let group = RugGroup::default();
        test_share_bytes_generic(group);

        let group = RistrettoGroup;
        test_share_bytes_generic(group);
    }

    #[test]
    fn test_ballots_bytes() {
        let group = RugGroup::default();
        test_ballots_bytes_generic(group);

        let group = RistrettoGroup;
        test_ballots_bytes_generic(group);
    }

    #[test]
    fn test_mix_bytes() {
        let mut csprng = OsRng;

        let group = RugGroup::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = group.rnd_exp();
            ps.push(p);
        }
        test_mix_bytes_generic(group, ps);

        let group = RistrettoGroup;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_mix_bytes_generic(group, ps);
    }

    #[test]
    fn test_plaintexts_bytes() {
        let mut csprng = OsRng;

        let group = RugGroup::default();
        let mut ps = vec![];
        for _ in 0..10 {
            let p = group.rnd_exp();
            ps.push(p);
        }
        test_plaintexts_bytes_generic(group, ps);

        let group = RistrettoGroup;
        let mut ps = vec![];
        for _ in 0..10 {
            let mut fill = [0u8; 30];
            csprng.fill_bytes(&mut fill);
            let p = util::to_u8_30(&fill.to_vec());
            ps.push(p);
        }
        test_plaintexts_bytes_generic(group, ps);
    }

    #[test]
    fn test_statement_bytes() {
        fn rnd32() -> Vec<u8> {
            rand::thread_rng().gen::<[u8; 32]>().to_vec()
        }

        let mut csprng = OsRng;
        let pk = Keypair::generate(&mut csprng);
        let stmt = Statement::mix(rnd32(), rnd32(), rnd32(), Some(2), 0);
        let bytes = stmt.ser();
        let back = Statement::deser(&bytes).unwrap();

        assert!(stmt == back);

        let s_stmt = SignedStatement::mix(&[0u8; 64], &[0u8; 64], &[0u8; 64], Some(2), 0, &pk);

        let bytes = s_stmt.ser();
        let back = SignedStatement::deser(&bytes).unwrap();

        assert!(s_stmt == back);
    }

    #[test]
    fn test_size() {
        let n = 1000;
        let n_f = 1000 as f32;
        let group1 = RistrettoGroup;
        let exps1: Vec<Scalar> = (0..n).into_iter().map(|_| group1.rnd_exp()).collect();

        let mut bytes = bincode::serialize(&exps1).unwrap();
        println!(
            "{} ristretto exps: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
        bytes = bincode::serialize(&elements1).unwrap();
        println!(
            "{} ristretto elements: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es1 = util::random_ballots(n, &group1).ciphertexts;
        bytes = bincode::serialize(&es1).unwrap();
        println!(
            "{} ristretto ciphertexts in Ballots: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        // 100k = 100M
        let group2 = RugGroup::default();
        let exps2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd_exp()).collect();
        bytes = bincode::serialize(&exps2).unwrap();
        println!(
            "{} rug exps: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd()).collect();
        bytes = bincode::serialize(&elements2).unwrap();
        println!(
            "{} rug elements: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es2 = util::random_ballots(1000, &group2).ciphertexts;
        bytes = bincode::serialize(&es2).unwrap();
        println!(
            "{} rug ciphertexts in Ballots: {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );

        println!("---------------------");

        let mut bytes = bincode::serialize(&exps1).unwrap();
        println!(
            "{} ristretto exps (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
        bytes = elements1.ser();
        println!(
            "{} ristretto elements (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es1 = util::random_ballots(n, &group1).ciphertexts;
        bytes = es1.ser();
        println!(
            "{} ristretto ciphertexts in Ballots (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        // 100k = 100M
        let group2 = RugGroup::default();
        let exps2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd_exp()).collect();
        bytes = exps2.ser();
        println!(
            "{} rug exps (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let elements2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd()).collect();
        bytes = elements2.ser();
        println!(
            "{} rug elements (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
        let es2 = util::random_ballots(1000, &group2).ciphertexts;
        bytes = es2.ser();
        println!(
            "{} rug ciphertexts in Ballots (BT): {}, {}",
            n,
            bytes.len(),
            (bytes.len() as f32 / n_f)
        );
    }*/
}
