use std::net::SocketAddr;
use std::sync::Arc;
use zero_dht::node::NodeInfo;
use crate::NetError;
use crate::udp::UdpManager;
use crate::quic::QuicManager;
use crate::tcp::TcpRelayManager;

pub enum TransportType {
    Udp,
    Quic,
    TcpRelay(SocketAddr),
    Tor,
}

pub struct TransportSelector {
    pub udp: Arc<UdpManager>,
    pub quic: Option<Arc<QuicManager>>,
    pub tcp_relay: Option<Arc<TcpRelayManager>>,
}

impl TransportSelector {
    pub fn new(
        udp: Arc<UdpManager>,
        quic: Option<Arc<QuicManager>>,
        tcp_relay: Option<Arc<TcpRelayManager>>,
    ) -> Self {
        Self { udp, quic, tcp_relay }
    }

    /// Determines the best available transport for a given target peer.
    pub fn best_transport_for(&self, target: &NodeInfo) -> TransportType {
        if target.addr.ip().is_loopback() {
            TransportType::Udp
        } else if self.quic.is_some() {
            TransportType::Quic
        } else if self.tcp_relay.is_some() {
            TransportType::TcpRelay(target.addr)
        } else {
            TransportType::Tor
        }
    }

    pub async fn send_packet(&self, target: &NodeInfo, packet: &[u8]) -> Result<(), NetError> {
        // Implement ±50ms Random Timing Jitter to confound traffic analysis
        let jitter = rand::Rng::gen_range(&mut rand::thread_rng(), 0..50);
        tokio::time::sleep(tokio::time::Duration::from_millis(jitter)).await;

        match self.best_transport_for(target) {
            TransportType::Udp => {
                self.udp.send_to(packet, target.addr).await?;
                Ok(())
            }
            TransportType::Quic => {
                if let Some(ref quic) = self.quic {
                    quic.send_quic_packet(target.addr, packet).await
                } else {
                    Err(NetError::TransportUnavailable)
                }
            }
            TransportType::TcpRelay(_) => {
                if let Some(ref relay) = self.tcp_relay {
                    relay.send_relayed_packet(target.addr, packet).await
                } else {
                    Err(NetError::TransportUnavailable)
                }
            }
            TransportType::Tor => {
                let proxy_addr = "127.0.0.1:9050".parse::<SocketAddr>().unwrap();
                let mut stream = tokio_socks::tcp::Socks5Stream::connect(proxy_addr, target.addr).await
                    .map_err(|_| NetError::TransportUnavailable)?;
                use tokio::io::AsyncWriteExt;
                let len = (packet.len() as u32).to_be_bytes();
                stream.write_all(&len).await.map_err(NetError::Io)?;
                stream.write_all(packet).await.map_err(NetError::Io)?;
                Ok(())
            }
        }
    }
}
