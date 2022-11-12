use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_zebra::Signature;
use ed25519_zebra::SigningKey;
use ed25519_zebra::VerificationKey;
use std::io::{Error, ErrorKind};

use crate::rnd::StrandRng;

#[derive(Clone)]
pub struct StrandSignature(Signature);

#[derive(Clone)]
pub struct StrandSignaturePk(VerificationKey);
impl StrandSignaturePk {
    pub fn from(sk: &StrandSignatureSk) -> StrandSignaturePk {
        StrandSignaturePk(VerificationKey::from(&sk.0))
    }
    pub fn verify(&self, signature: &StrandSignature, msg: &[u8]) -> Result<(), &'static str> {
        self.0
            .verify(&signature.0, msg)
            .map_err(|_| "Failed to verify signature")
    }
}
impl PartialEq for StrandSignaturePk {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl std::fmt::Debug for StrandSignaturePk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &hex::encode(self.0.as_ref())[0..10])
    }
}
impl Eq for StrandSignaturePk {}

pub struct StrandSignatureSk(SigningKey);
impl StrandSignatureSk {
    pub fn new(rng: &mut StrandRng) -> StrandSignatureSk {
        let sk = SigningKey::new(rng);
        StrandSignatureSk(sk)
    }
    pub fn sign(&self, msg: &[u8]) -> StrandSignature {
        StrandSignature(self.0.sign(msg))
    }
}
impl std::fmt::Debug for StrandSignatureSk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &hex::encode(self.0.as_ref())[0..10])
    }
}

impl BorshSerialize for StrandSignatureSk {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes: [u8; 32] = self.0.into();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for StrandSignatureSk {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize(buf)?;
        let pk = SigningKey::try_from(bytes).map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(StrandSignatureSk(pk))
    }
}

impl BorshSerialize for StrandSignaturePk {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes: [u8; 32] = self.0.into();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for StrandSignaturePk {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize(buf)?;
        let pk = VerificationKey::try_from(bytes).map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(StrandSignaturePk(pk))
    }
}

impl BorshSerialize for StrandSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes: [u8; 64] = self.0.into();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for StrandSignature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let bytes = <[u8; 64]>::deserialize(buf)?;
        let signature = Signature::try_from(bytes).map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(StrandSignature(signature))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::serialization::{StrandDeserialize, StrandSerialize};

    // Adapted from ed25519-zebra
    #[test]
    pub fn test_signature() {
        let msg = b"ok";
        let msg2 = b"not_ok";
        let mut rng = StrandRng;

        let (vk_bytes, sig_bytes) = {
            let sk = StrandSignatureSk(SigningKey::new(&mut rng));
            let sk_b = sk.strand_serialize();
            let sk_d = StrandSignatureSk::strand_deserialize(&sk_b).unwrap();

            let sig = sk_d.sign(msg);

            let sig_bytes = sig.strand_serialize();
            let vk_bytes = StrandSignaturePk::from(&sk_d).strand_serialize();

            (vk_bytes, sig_bytes)
        };

        let vk = StrandSignaturePk::strand_deserialize(&vk_bytes).unwrap();
        let sig = StrandSignature::strand_deserialize(&sig_bytes).unwrap();

        let ok = vk.verify(&sig, msg);
        assert!(ok.is_ok());

        let not_ok = vk.verify(&sig, msg2);
        assert!(not_ok.is_err());
    }
}
