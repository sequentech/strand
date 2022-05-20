// SPDX-FileCopyrightText: 2021 David Ruescas <david@sequenttech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

use crate::rnd::StrandRng;
use rand::RngCore;

pub fn encrypt(key: [u8; 32], bytes: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut csprng = StrandRng;
    let mut iv = [0u8; 16];
    csprng.fill_bytes(&mut iv);
    let res = Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(bytes);
    (res, iv)
}

pub fn decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .unwrap()
}

pub fn gen_key() -> [u8; 32] {
    let mut csprng = StrandRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    key_bytes
}

#[cfg(test)]
mod tests {
    use crate::symmetric::*;

    #[test]
    fn test_aes() {
        let key = gen_key();
        let plaintext = b"12345679abcdef0";
        let (ciphertext, iv) = encrypt(key, plaintext);
        let decrypted_ciphertext = decrypt(key, iv, &ciphertext);
        assert_eq!(decrypted_ciphertext, plaintext.to_vec());
    }
}
