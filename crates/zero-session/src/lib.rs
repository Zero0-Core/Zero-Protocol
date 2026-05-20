#![forbid(unsafe_code)]

pub mod file_transfer;
pub mod friend;
pub mod group;
pub mod lossless;
pub mod lossy;
pub mod ratchet;
pub mod sync;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] zero_crypto::ZeroError),
    #[error("Net error")]
    Network,
    #[error("Message out of order")]
    OutOfOrder,
}
