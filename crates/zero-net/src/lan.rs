use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;
use zero_dht::node::DhtPublicKey;

/// Broadcasts a LAN discovery packet every 10 seconds.
/// Any Zero Protocol node on the same subnet should respond and connect directly.
pub async fn lan_discovery_loop(socket: &UdpSocket, local_pk: &DhtPublicKey) {
    let broadcast_addrs: [SocketAddr; 2] = [
        "255.255.255.255:33450".parse().unwrap(),   // IPv4 broadcast
        "[FF02::1]:33450".parse().unwrap(),           // IPv6 multicast
    ];

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;
        
        // Example discovery packet: prefix + public key
        // In reality, this would be signed and encrypted, but LAN discovery 
        // initially broadcasts the DHT key to solicit handshakes.
        let mut packet = Vec::with_capacity(36);
        packet.extend_from_slice(b"ZLAN"); // Magic bytes
        packet.extend_from_slice(&local_pk.0);

        for addr in &broadcast_addrs {
            if let Err(e) = socket.send_to(&packet, *addr).await {
                debug!("Failed to send LAN broadcast to {}: {}", addr, e);
            }
        }
    }
}
