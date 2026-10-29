mod cli;
mod crypto;
mod seal;

use std::{error::Error, fs};

use crate::cli::Args;
use clap::Parser;
use crypto::DataEncryptionKey;
use seal::{SealContainer, Sealer};

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.encrypt && args.decrypt {
        eprintln!("Encrypt and Decrypt are mutually exclusive options");
        // TODO: fix this
        return Ok(());
    }

    if args.encrypt {
        let input_path = args.path.clone();
        let plaintext = fs::read(&input_path)?;

        // Setup
        let mut dek = DataEncryptionKey::new();
        let mut container = SealContainer::new();

        // Encrypt chunks
        for c in plaintext.chunks(64_000) {
            let chunk = dek.encrypt_chunk(c)?;
            container.append_chunk(chunk);
        }

        // Seal key, add to container
        let mut sealer = Sealer::new(args.label.clone());
        let encrypted_dek = sealer.encrypt_dek(&dek)?;
        container.set_encrypted_dek(encrypted_dek);
        dek.zero_bytes(); // zero the key now that we've saved its encrypted copy

        // Write container
        let container_bytes = container.to_bytes();
        let output_path = input_path.to_owned() + ".seal";
        fs::write(output_path, container_bytes)?;
    }

    if args.decrypt {
        // Read enigma seal file
        let input_path = args.path.clone();
        let seal_bytes = fs::read(&input_path)?;

        // Super easy decrypt
        let mut sealer = Sealer::new(args.label.clone());
        let plaintext = SealContainer::from_bytes(&mut sealer, &seal_bytes).unwrap();

        // Write back out
        let output_path = input_path.replace(".seal", "");
        fs::write(output_path, plaintext)?;
    }

    Ok(())
}
