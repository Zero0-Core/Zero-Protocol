#![forbid(unsafe_code)]

pub mod lan;
pub mod quic;
pub mod tcp;
pub mod transport;
pub mod udp;
pub mod upnp;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UPnP search error: {0}")]
    Upnp(igd::SearchError),
    #[error("UPnP add port error: {0}")]
    UpnpAddPort(igd::AddPortError),
    #[error("Transport not available")]
    TransportUnavailable,
}
