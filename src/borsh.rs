use crate::{
    backend::num_bigint::{BigUintE, BigUintX, BigintCtx, BigintCtxParams},
    context::Ctx,
};

pub trait CtxDeserializable<C: Ctx>
where
    Self: Sized,
{
    fn deserialize_ctx(bytes: &[u8], ctx: &C) -> Result<Self, &'static str>;
}

impl<P: BigintCtxParams> CtxDeserializable<BigintCtx<P>> for BigUintE<P> {
    fn deserialize_ctx(bytes: &[u8], ctx: &BigintCtx<P>) -> Result<BigUintE<P>, &'static str> {
        ctx.element_from_bytes(bytes)
    }
}

impl<P: BigintCtxParams> CtxDeserializable<BigintCtx<P>> for BigUintX<P> {
    fn deserialize_ctx(bytes: &[u8], ctx: &BigintCtx<P>) -> Result<BigUintX<P>, &'static str> {
        ctx.exp_from_bytes(bytes)
    }
}

/*impl<C: Ctx, T: CtxDeserializable<C> + Send> CtxDeserializable<C> for Vec<T> {
    fn deserialize_ctx(bytes: &[u8], ctx: &BigintCtx<P>) -> Result<BigUintX<P>, &'static str> {
        ctx.exp_from_bytes(bytes)
    }
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
*/

/*
impl<P: BigintCtxParams> ToByteTree for BigUintX<P> {
    fn to_byte_tree(&self) -> ByteTree {
        // Leaf(DataType::Exponent, ByteBuf::from(self.to_bytes_le()))
        Leaf(ByteBuf::from(self.0.to_bytes_le()))
    }
}

impl<P: BigintCtxParams> CtxDeserializable<BigintCtx<P>> for BigUintX<P> {
    fn from_byte_tree(tree: &ByteTree, ctx: &BigintCtx<P>) -> Result<BigUintX<P>, ByteError> {
        let bytes = tree.leaf()?;
        ctx.exp_from_bytes(bytes).map_err(ByteError::Msg)
    }
}*/
/*
pub trait Serializable<T: BorshSerialize> {
    fn borsh_serialize(s: T) -> Vec<u8> {
        s.try_to_vec().unwrap()
    }
}

pub trait Deserializable<T: BorshDeserialize> {
    fn borsh_deserialize(s: &[u8]) -> Result<T, ()> {
        let deserialized_val = match T::try_from_slice(&s) {
            Ok(val) => {val},
            Err(_) => {return Err(());},
        };
        Ok(deserialized_val)
    }
}*/

#[cfg(test)]
pub(crate) mod tests {
    use crate::backend::num_bigint::{BigUintE, BigUintX, BigintCtx, P2048};
    use crate::context::Ctx;
    use borsh::{BorshDeserialize, BorshSerialize};

    #[test]
    pub(crate) fn test_borsh_biguinte() {
        let ctx = BigintCtx::<P2048>::new();
        let e = ctx.rnd();

        let encoded_e = e.try_to_vec().unwrap();
        let decoded_e = BigUintE::<P2048>::try_from_slice(&encoded_e).unwrap();
        assert_eq!(e, decoded_e);
    }

    #[test]
    pub(crate) fn test_borsh_biguintx() {
        let ctx = BigintCtx::<P2048>::new();
        let x = ctx.rnd_exp();

        let encoded_x = x.try_to_vec().unwrap();
        let decoded_x = BigUintX::<P2048>::try_from_slice(&encoded_x).unwrap();
        assert_eq!(x, decoded_x);
    }
}
