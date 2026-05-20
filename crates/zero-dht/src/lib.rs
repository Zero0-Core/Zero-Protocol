#![forbid(unsafe_code)]

pub mod node;
pub mod packet;
pub mod routing;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DhtError {
    #[error("Routing table is full")]
    BucketFull,
    #[error("Node not found")]
    NodeNotFound,
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Serialization error")]
    SerializationError(#[from] bincode::Error),
}
