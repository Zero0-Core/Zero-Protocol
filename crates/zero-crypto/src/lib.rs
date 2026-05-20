//! # zero-crypto
//!
//! The cryptographic base layer of Zero Protocol.
//!
//! ## Features
//! - **AEAD Encryption:** ChaCha20-Poly1305 with counter-derived nonces.
//! - **KDF:** Domain-separated Blake2s key derivation function.
//! - **Noise Protocol:** Snow-backed Noise IK pattern for mutual authentication.
//! - **Proof-of-Work:** Custom Blake2s anti-spam challenge builder.
//! - **Wallet Storage:** Argon2id encrypted local seed file manager.
//! - **Mnemonic Recovery:** BIP39 24-word seed recovery.

#![forbid(unsafe_code)]

pub mod aead;
pub mod kdf;
pub mod keypair;
pub mod noise;
pub mod pow;
pub mod recovery;
pub mod storage;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZeroError {
    #[error("Handshake error: {0}")]
    Handshake(#[from] snow::Error),
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Proof of work is invalid")]
    InvalidProofOfWork,
    #[error("Storage error")]
    StorageError,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid key length or entropy")]
    InvalidKeyLength,
}
