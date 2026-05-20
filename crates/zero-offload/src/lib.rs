#![forbid(unsafe_code)]

pub mod blob;
pub mod client;
pub mod store;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OffloadError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] zero_crypto::ZeroError),
    #[error("Serialization error")]
    Serialization,
    #[error("Invalid proof of work")]
    InvalidPow,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Message expired")]
    Expired,
    #[error("Rate limit exceeded")]
    RateLimited,
    #[error("Invalid private key length")]
    InvalidKey,
}
