#![forbid(unsafe_code)]

pub mod announce;
pub mod forward;
pub mod packet;
pub mod path;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OnionError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] zero_crypto::ZeroError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Path is invalid")]
    InvalidPath,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Invalid packet format")]
    InvalidPacket,
}
