use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Enigma Seal",
    long_about= "Enigma Seal - Encrypt files with Enigma backed crypto",
    bin_name = "enigma-seal"
)]
pub(crate) struct Args {
    #[arg(short, long, help = "Perform file encryption")]
    pub(crate) encrypt: bool,

    #[arg(short, long, help = "Perform file decryption")]
    pub(crate) decrypt: bool,

    #[arg(short, long, required = true, help = "File path to encrypt or decrypt")]
    pub(crate) path: String,

    #[arg(short, long, required = true, help = "Label of Enigma encryption key")]
    pub(crate) label: String,
}
