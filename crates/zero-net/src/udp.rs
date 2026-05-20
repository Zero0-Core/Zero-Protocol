use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::NetError;

/// Manages the primary asynchronous UDP socket for the node.
pub struct UdpManager {
    socket: Arc<UdpSocket>,
}

impl UdpManager {
    pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
        let socket = UdpSocket::bind(addr).await?;
        socket.set_broadcast(true)?; // Enable broadcasting for LAN discovery
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<usize, NetError> {
        self.socket.send_to(data, target).await.map_err(Into::into)
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
}
