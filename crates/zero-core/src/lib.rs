#![forbid(unsafe_code)]

pub mod node;
pub mod padding;
pub mod packet;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("DHT Error: {0}")]
    Dht(#[from] zero_dht::DhtError),
    #[error("Net Error: {0}")]
    Net(#[from] zero_net::NetError),
    #[error("Session Error: {0}")]
    Session(#[from] zero_session::SessionError),
}
