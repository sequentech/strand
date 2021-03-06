// SPDX-FileCopyrightText: 2022 David Ruescas <david@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::marker::PhantomData;

#[cfg(feature = "rayon")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::context::Ctx;
use crate::elgamal::{Ciphertext, EncryptedPrivateKey, PrivateKey, PublicKey};
use crate::shuffler::{Commitments, Responses, ShuffleProof};
use crate::util;
use crate::util::Par;
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
        Msg(message: &'static str) {
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

use ByteTree::*;

// OPT: try to move instead of copy
impl ByteTree {
    pub(crate) fn leaf(&self) -> Result<&Vec<u8>, ByteError> {
        if let Leaf(bytes) = self {
            Ok(bytes)
        } else {
            Err(ByteError::Msg("ByteTree: unexpected Tree"))
        }
    }

    pub(crate) fn tree(&self, length: usize) -> Result<&Vec<ByteTree>, ByteError> {
        if let Tree(trees) = self {
            if trees.len() == length {
                Ok(trees)
            } else {
                Err(ByteError::Msg("ByteTree: size mismatch"))
            }
        } else {
            Err(ByteError::Msg("ByteTree: unexpected Leaf"))
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
pub trait FromByteTree<C: Ctx> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Self, ByteError>
    where
        Self: Sized;
}

pub trait ToFromBTree<C: Ctx>: ToByteTree + FromByteTree<C> {}
impl<C: Ctx, T: ToByteTree + FromByteTree<C>> ToFromBTree<C> for T {}

pub trait BTreeSer {
    fn ser(&self) -> Vec<u8>;
}

pub trait BTreeDeser<C: Ctx> {
    fn deser(bytes: &[u8], ctx: &C) -> Result<Self, ByteError>
    where
        Self: Sized;
}

impl<T: ToByteTree + Sync> ToByteTree for Vec<T> {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.par().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl<C: Ctx, T: FromByteTree<C> + Send> FromByteTree<C> for Vec<T> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Vec<T>, ByteError> {
        if let Tree(trees) = tree {
            trees
                .par()
                .map(|b| T::from_byte_tree(b, ctx))
                .collect::<Result<Vec<T>, ByteError>>()
        } else {
            Err(ByteError::Msg(
                "ByteTree: unexpected Leaf constructing Vec<T: FromByteTree>",
            ))
        }
    }
}

impl<T: ToByteTree> BTreeSer for T {
    fn ser(&self) -> Vec<u8> {
        let tree = self.to_byte_tree();
        bincode::serialize(&tree).unwrap()
    }
}

impl<C: Ctx, T: FromByteTree<C>> BTreeDeser<C> for T {
    fn deser(bytes: &[u8], ctx: &C) -> Result<T, ByteError> {
        let tree: ByteTree = bincode::deserialize(bytes)?;
        T::from_byte_tree(&tree, ctx)
    }
}

impl<T: ToByteTree + Sync> ToByteTree for [T] {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.par().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}

impl<C: Ctx> ToByteTree for EncryptedPrivateKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![
            ByteTree::Leaf(ByteBuf::from(self.bytes.clone())),
            ByteTree::Leaf(ByteBuf::from(self.iv)),
        ];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree<C> for EncryptedPrivateKey<C> {
    fn from_byte_tree(tree: &ByteTree, _ctx: &C) -> Result<EncryptedPrivateKey<C>, ByteError> {
        let trees = tree.tree(2)?;
        let bytes = trees[0].leaf()?.to_vec();
        let iv_vec = trees[1].leaf()?;
        let iv = util::to_u8_16(iv_vec);
        let phantom = PhantomData;

        let ret = EncryptedPrivateKey { bytes, iv, phantom };

        Ok(ret)
    }
}

impl<C: Ctx> ToByteTree for PrivateKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.value.to_byte_tree(), self.pk_element.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree<C> for PrivateKey<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<PrivateKey<C>, ByteError> {
        let trees = tree.tree(2)?;
        let value = C::X::from_byte_tree(&trees[0], ctx)?;
        let pk_element = C::E::from_byte_tree(&trees[1], ctx)?;
        let ctx = C::new();
        let ret = PrivateKey {
            value,
            pk_element,
            ctx,
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

impl<C: Ctx> FromByteTree<C> for Ciphertext<C>
where
    C::E: ToByteTree,
{
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Ciphertext<C>, ByteError> {
        let trees = tree.tree(2)?;
        let mhr = C::E::from_byte_tree(&trees[0], ctx)?;
        let gr = C::E::from_byte_tree(&trees[1], ctx)?;
        Ok(Ciphertext { mhr, gr })
    }
}

impl<C: Ctx> ToByteTree for PublicKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.element.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree<C> for PublicKey<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<PublicKey<C>, ByteError> {
        let trees = tree.tree(1)?;
        let element = C::E::from_byte_tree(&trees[0], ctx)?;
        let ctx = C::new();
        let ret = PublicKey { element, ctx };

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

impl<C: Ctx> FromByteTree<C> for Schnorr<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Schnorr<C>, ByteError> {
        let trees = tree.tree(3)?;

        let commitment = C::E::from_byte_tree(&trees[0], ctx)?;
        let challenge = C::X::from_byte_tree(&trees[1], ctx)?;
        let response = C::X::from_byte_tree(&trees[2], ctx)?;
        let ret = Schnorr {
            commitment,
            challenge,
            response,
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

impl<C: Ctx> FromByteTree<C> for ChaumPedersen<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<ChaumPedersen<C>, ByteError> {
        let trees = tree.tree(4)?;

        let commitment1 = C::E::from_byte_tree(&trees[0], ctx)?;
        let commitment2 = C::E::from_byte_tree(&trees[1], ctx)?;
        let challenge = C::X::from_byte_tree(&trees[2], ctx)?;
        let response = C::X::from_byte_tree(&trees[3], ctx)?;
        let ret = ChaumPedersen {
            commitment1,
            commitment2,
            challenge,
            response,
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

impl<C: Ctx> FromByteTree<C> for ShuffleProof<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<ShuffleProof<C>, ByteError> {
        let trees = tree.tree(4)?;
        let t = Commitments::<C>::from_byte_tree(&trees[0], ctx)?;
        let s = Responses::<C>::from_byte_tree(&trees[1], ctx)?;
        let cs = Vec::<C::E>::from_byte_tree(&trees[2], ctx)?;
        let c_hats = Vec::<C::E>::from_byte_tree(&trees[3], ctx)?;

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

impl<C: Ctx> FromByteTree<C> for Commitments<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Commitments<C>, ByteError> {
        let trees = tree.tree(6)?;
        let t1 = C::E::from_byte_tree(&trees[0], ctx)?;
        let t2 = C::E::from_byte_tree(&trees[1], ctx)?;
        let t3 = C::E::from_byte_tree(&trees[2], ctx)?;
        let t4_1 = C::E::from_byte_tree(&trees[3], ctx)?;
        let t4_2 = C::E::from_byte_tree(&trees[4], ctx)?;
        let t_hats = Vec::<C::E>::from_byte_tree(&trees[5], ctx)?;

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

impl<C: Ctx> FromByteTree<C> for Responses<C> {
    fn from_byte_tree(tree: &ByteTree, ctx: &C) -> Result<Responses<C>, ByteError> {
        let trees = tree.tree(6)?;
        let s1 = <C::X>::from_byte_tree(&trees[0], ctx)?;
        let s2 = <C::X>::from_byte_tree(&trees[1], ctx)?;
        let s3 = <C::X>::from_byte_tree(&trees[2], ctx)?;
        let s4 = <C::X>::from_byte_tree(&trees[3], ctx)?;
        let s_hats = Vec::<C::X>::from_byte_tree(&trees[4], ctx)?;
        let s_primes = Vec::<C::X>::from_byte_tree(&trees[5], ctx)?;

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
    /*use crate::shuffler::*;*/
    use crate::byte_tree::*;
    use crate::symmetric;
    use crate::zkp::Zkp;
    // use ed25519_dalek::Keypair;

    pub(crate) fn test_ciphertext_bytes_generic<C: Ctx>(ctx: &C) {
        let c = util::random_ballots(1, ctx).remove(0);
        let bytes = c.ser();
        let back = Ciphertext::<C>::deser(&bytes, ctx).unwrap();

        assert!(c.mhr == back.mhr && c.gr == back.gr);
    }

    pub(crate) fn test_key_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let sk = PrivateKey::gen(ctx);
        let pk = PublicKey::from_element(&sk.pk_element, ctx);

        let bytes = sk.ser();
        let back = PrivateKey::<C>::deser(&bytes, ctx).unwrap();

        assert!(sk == back);

        let bytes = pk.ser();
        let back = PublicKey::<C>::deser(&bytes, ctx).unwrap();

        assert!(pk == back);
    }

    pub(crate) fn test_schnorr_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let zkp = Zkp::new(ctx);
        let g = ctx.generator();
        let secret = ctx.rnd_exp();
        let public = g.mod_pow(&secret, &ctx.modulus());
        let schnorr = zkp.schnorr_prove(&secret, &public, Some(&g), &vec![]);
        let verified = zkp.schnorr_verify(&public, Some(&g), &schnorr, &vec![]);
        assert!(verified);

        let bytes = schnorr.ser();
        let back = Schnorr::<C>::deser(&bytes, ctx).unwrap();
        assert!(schnorr == back);

        let verified = zkp.schnorr_verify(&public, Some(&g), &back, &vec![]);
        assert!(verified);
    }

    pub(crate) fn test_cp_bytes_generic<C: Ctx + Eq>(ctx: &C) {
        let zkp = Zkp::new(ctx);
        let g1 = ctx.generator();
        let g2 = ctx.rnd();
        let secret = ctx.rnd_exp();
        let public1 = g1.mod_pow(&secret, &ctx.modulus());
        let public2 = g2.mod_pow(&secret, &ctx.modulus());
        let proof = zkp.cp_prove(&secret, &public1, &public2, None, &g2, &vec![]);
        let verified = zkp.cp_verify(&public1, &public2, None, &g2, &proof, &vec![]);
        assert!(verified);

        let bytes = proof.ser();
        let back = ChaumPedersen::<C>::deser(&bytes, ctx).unwrap();
        assert!(proof == back);

        let verified = zkp.cp_verify(&public1, &public2, None, &g2, &back, &vec![]);
        assert!(verified);
    }

    pub(crate) fn test_epk_bytes_generic<C: Ctx + Eq>(ctx: &C, plaintext: C::P) {
        let sk = PrivateKey::gen(ctx);
        let pk: PublicKey<C> = PublicKey::from_element(&sk.pk_element, ctx);

        let encoded = ctx.encode(&plaintext).unwrap();
        let c = pk.encrypt(&encoded);

        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);
        let enc_sk_b = enc_sk.ser();
        let back = EncryptedPrivateKey::deser(&enc_sk_b, ctx).unwrap();
        assert!(enc_sk == back);

        let sk_d = PrivateKey::from_encrypted(sym_key, back, ctx);
        let d = ctx.decode(&sk_d.decrypt(&c));
        assert_eq!(d, plaintext);
    }
}
