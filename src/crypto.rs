use std::error::Error;

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Generate, consts::U12},
};

pub(crate) struct DataEncryptionKey {
    bytes: [u8; 32],
    key: Aes256Gcm,
}

pub(crate) struct DataEncryptionChunk {
    nonce: [u8; 12],
    ciphertext: Box<[u8]>,
}

pub(crate) struct DecryptedChunk {
    pub(crate) bytes_read: usize,
    pub(crate) plaintext: Vec<u8>,
}

impl DataEncryptionKey {
    pub(crate) fn new() -> Self {
        let key = Key::<Aes256Gcm>::generate();
        let cipher = Aes256Gcm::new(&key);

        Self {
            bytes: key.into(),
            key: cipher,
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::try_from(bytes).expect("Could not load key bytes");
        let cipher = Aes256Gcm::new(&key);

        Self {
            bytes: key.into(),
            key: cipher,
        }
    }

    pub(crate) fn encrypt_chunk(
        &self,
        plaintext: &[u8],
    ) -> Result<DataEncryptionChunk, Box<dyn Error>> {
        let nonce = Nonce::<U12>::generate();
        let ciphertext = self.key.encrypt(&nonce, plaintext)?;

        Ok(DataEncryptionChunk {
            nonce: nonce.into(),
            ciphertext: ciphertext.into_boxed_slice(),
        })
    }

    pub(crate) fn decrypt_chunk(
        &self,
        chunk_bytes: &[u8],
    ) -> Result<DecryptedChunk, Box<dyn Error>> {
        let nonce_bytes = &chunk_bytes[0..12];
        let chunk_size = u32::from_le_bytes(chunk_bytes[12..16].try_into().unwrap()) as usize;
        let chunk_bytes = &chunk_bytes[16..16 + chunk_size];
        let nonce = Nonce::<U12>::try_from(nonce_bytes).unwrap();

        let plaintext = self.key.decrypt(&nonce, chunk_bytes)?;
        Ok(DecryptedChunk {
            bytes_read: chunk_size + 16,
            plaintext,
        })
    }

    pub(crate) fn key_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub(crate) fn zero_bytes(&mut self) {
        self.bytes.fill(0);
    }
}

impl DataEncryptionChunk {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.nonce);
        let ciphertext_len = u32::to_le_bytes(self.ciphertext.len() as u32);
        bytes.extend(ciphertext_len);
        bytes.extend(&self.ciphertext);
        bytes
    }
}
