use std::{error::Error, fmt};

use enigma::{DecryptRequest, Device, EncryptRequest, EnigmaError, KeyListFilter, SessionState};

use crate::crypto::{DataEncryptionChunk, DataEncryptionKey};

pub(crate) struct Sealer {
    key_label: String,
    device: Device,
}

pub(crate) struct SealContainer {
    magic: [u8; 4],                   // 0x53 0x45 0x41 0x4C
    dek: Vec<u8>,                     // Encrypted DEK
    chunks: Vec<DataEncryptionChunk>, // Chunks to write
}

#[derive(Debug)]
pub(crate) enum SealError {
    InvalidMagic,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::InvalidMagic => write!(f, "Invalid header magic"),
        }
    }
}

impl Sealer {
    pub(crate) fn new(key_label: String) -> Self {
        let device = Device::open().expect("Could not open Enigma");
        Self { key_label, device }
    }

    pub(crate) fn encrypt_dek(
        &mut self,
        dek: &DataEncryptionKey,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.ensure_authenticated()?;

        let key_id = self.find_key()?;

        let bytes = dek.key_bytes();
        let request = EncryptRequest {
            key_id,
            plaintext: bytes.as_slice(),
        };
        let ciphertext = self.device.encrypt(request)?;

        Ok(ciphertext.data.to_vec())
    }

    pub(crate) fn decrypt_dek(&mut self, dek_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.ensure_authenticated()?;
        let key_id = self.find_key()?;

        let bytes = dek_bytes;
        let request = DecryptRequest {
            key_id,
            ciphertext: bytes,
        };
        let plaintext = self.device.decrypt(request)?;

        Ok(plaintext.data.to_vec())
    }

    fn find_key(&mut self) -> Result<u32, Box<dyn Error>> {
        let filter = KeyListFilter {
            key_label: Some(self.key_label.as_str()),
            ..Default::default()
        };
        let results = self.device.list_keys(filter)?;
        if results.keys.len() != 1 {
            return Err(Box::new(EnigmaError::InvalidArgument));
        }

        Ok(results.keys[0].id)
    }

    fn ensure_authenticated(&mut self) -> Result<(), Box<dyn Error>> {
        let status = self.device.status()?;

        if status.session == SessionState::Authenticated {
            return Ok(());
        }

        let pin = rpassword::prompt_password("Enigma PIN: ")?;
        self.device.authenticate(pin.as_str())?;
        Ok(())
    }
}

impl SealContainer {
    pub(crate) fn new() -> Self {
        Self {
            magic: [0x53, 0x45, 0x41, 0x4C],
            dek: vec![],
            chunks: vec![],
        }
    }

    pub(crate) fn from_bytes(sealer: &mut Sealer, bytes: &[u8]) -> Result<Box<[u8]>, SealError> {
        let magic = &bytes[0..4];
        if magic[0] != 0x53 || magic[1] != 0x45 || magic[2] != 0x41 || magic[3] != 0x4C {
            return Err(SealError::InvalidMagic);
        }

        let dek_ciphertext = &bytes[4..64]; // Nonce (12) + encrypted DEK (32) + tag (16) = 60
        let dek_bytes = sealer
            .decrypt_dek(dek_ciphertext)
            .expect("Could not decrypt ciphertext!");
        let dek = DataEncryptionKey::from_bytes(dek_bytes.as_slice());

        let chunk_count = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
        let encrypted_chunks = &bytes[68..];
        let mut cursor: usize = 0;

        let mut result: Vec<u8> = vec![];
        for _ in 0..chunk_count {
            let ptr = &encrypted_chunks[cursor..];
            let chunk = dek.decrypt_chunk(&ptr).unwrap();

            result.extend(chunk.plaintext);
            cursor += chunk.bytes_read;
        }

        Ok(result.into_boxed_slice())
    }

    pub(crate) fn append_chunk(&mut self, chunk: DataEncryptionChunk) {
        self.chunks.push(chunk);
    }

    pub(crate) fn set_encrypted_dek(&mut self, encrypted_dek: Vec<u8>) {
        self.dek = encrypted_dek;
    }

    pub(crate) fn to_bytes(&mut self) -> Box<[u8]> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.magic.to_vec());
        bytes.extend(self.dek.clone());
        let chunk_len = u32::to_le_bytes(self.chunks.len() as u32);
        bytes.extend(chunk_len);
        self.chunks.iter().for_each(|c| bytes.extend(c.to_bytes()));

        bytes.into_boxed_slice()
    }
}
