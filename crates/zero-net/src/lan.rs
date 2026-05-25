use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;
use zero_crypto::keypair::StaticKeypair;
use zero_crypto::kdf::derive_key;
use zero_crypto::aead;
use ed25519_dalek::Signer;

/// Broadcasts a LAN discovery packet every 10 seconds.
/// Encrypts the payload with a derived well-known key and signs it.
pub async fn lan_discovery_loop(socket: &UdpSocket, keypair: &StaticKeypair) {
    let broadcast_addrs: [SocketAddr; 2] = [
        "255.255.255.255:33450".parse().unwrap(),   // IPv4 broadcast
        "[FF02::1]:33450".parse().unwrap(),           // IPv6 multicast
    ];

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    // Derive well-known protocol key for LAN encryption
    let static_salt = [0u8; 32];
    let lan_key = derive_key(b"zero-lan-shared-salt-derivation", b"zero-lan-encryption", &static_salt);

    loop {
        interval.tick().await;
        
        let signing_key = ed25519_dalek::SigningKey::from_bytes(keypair.seed.as_ref());
        let verify_key = signing_key.verifying_key();
        let verify_key_bytes = verify_key.to_bytes();

        // Sign the X25519 DHT public key
        let sig = signing_key.sign(&keypair.public);
        let sig_bytes = sig.to_bytes();

        let mut plaintext = Vec::with_capacity(32 + 64);
        plaintext.extend_from_slice(&verify_key_bytes);
        plaintext.extend_from_slice(&sig_bytes);

        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        if let Ok(ciphertext) = aead::encrypt(&lan_key, &nonce, &plaintext, &[]) {
            let mut packet = Vec::with_capacity(4 + 12 + ciphertext.len());
            packet.extend_from_slice(b"ZLAN"); // Magic bytes
            packet.extend_from_slice(&nonce);
            packet.extend_from_slice(&ciphertext);

            for addr in &broadcast_addrs {
                if let Err(e) = socket.send_to(&packet, *addr).await {
                    debug!("Failed to send LAN broadcast to {}: {}", addr, e);
                }
            }
        }
    }
}
