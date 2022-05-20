use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::context::Ctx;
use crate::elgamal::{Ciphertext, EncryptedPrivateKey, PublicKey};
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
impl<C: Ctx> ToByteTree for Ciphertext<C>
where
    C::E: ToByteTree,
{
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.a.to_byte_tree(), self.b.to_byte_tree()];
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
        Ok(Ciphertext { a, b })
    }
}

impl<C: Ctx> ToByteTree for PublicKey<C> {
    fn to_byte_tree(&self) -> ByteTree {
        let trees: Vec<ByteTree> = vec![self.value.to_byte_tree(), self.ctx.to_byte_tree()];
        ByteTree::Tree(trees)
    }
}

impl<C: Ctx> FromByteTree for PublicKey<C> {
    fn from_byte_tree(tree: &ByteTree) -> Result<PublicKey<C>, ByteError> {
        let trees = tree.tree(2)?;
        let value = C::E::from_byte_tree(&trees[0])?;
        let ctx = C::from_byte_tree(&trees[1])?;
        let ret = PublicKey { value, ctx };

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
