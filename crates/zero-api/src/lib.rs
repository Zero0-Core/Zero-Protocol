#![forbid(unsafe_code)]

use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use zero_core::node::ZeroNode;
use zero_dht::node::DhtPublicKey;
use zero_session::friend::FriendSession;

uniffi::setup_scaffolding!();

/// Trait for the mobile frontend to implement to receive real-time updates from the core.
#[uniffi::export(callback_interface)]
pub trait ZeroEventDelegate: Send + Sync {
    fn on_event(&self, event: ZeroEvent);
}

/// Defines events emitted by the core to the UI frontend.
#[derive(uniffi::Enum)]
pub enum ZeroEvent {
    MessageReceived { friend_id: String, text: String },
    FriendOnline { friend_id: String },
    FriendOffline { friend_id: String },
    ConnectionStatusChanged { is_connected: bool },
    FileTransferStarted { file_name: String, size: u64 },
    FileTransferProgress { file_name: String, progress: f32 },
}

/// The public Rust API boundary for client applications (Android/iOS UIs).
#[derive(uniffi::Object)]
pub struct ZeroClient {
    node: Arc<ZeroNode>,
    delegate: Arc<Mutex<Option<Box<dyn ZeroEventDelegate>>>>,
    sessions: Arc<Mutex<HashMap<DhtPublicKey, FriendSession>>>,
}

#[uniffi::export]
impl ZeroClient {
    /// Bootstraps the client, binding to a local port and connecting to the DHT.
    #[uniffi::constructor]
    pub async fn start(bind_port: u16, identity_bytes: Vec<u8>) -> Result<Arc<Self>, String> {
        let addr = format!("0.0.0.0:{}", bind_port)
            .parse()
            .map_err(|e| format!("Invalid port: {}", e))?;

        let mut priv_bytes = [0u8; 32];
        if identity_bytes.len() == 32 {
            priv_bytes.copy_from_slice(&identity_bytes);
        } else {
            return Err("Identity must be 32 bytes".to_string());
        }

        let keypair = zero_crypto::keypair::StaticKeypair::from_bytes(priv_bytes);
        let node = ZeroNode::new(addr, keypair)
            .await
            .map_err(|e| format!("Failed to bind node: {:?}", e))?;
        let node = Arc::new(node);

        // Start background async loops
        node.run_background_tasks().await;

        let sessions = Arc::new(Mutex::new(HashMap::new()));

        Ok(Arc::new(Self {
            node,
            delegate: Arc::new(Mutex::new(None)),
            sessions,
        }))
    }

    /// Sets the delegate to receive events. This should be called immediately after start.
    pub async fn set_delegate(&self, delegate: Box<dyn ZeroEventDelegate>) {
        let mut d = self.delegate.lock().await;
        *d = Some(delegate);
    }

    /// Returns the local Zero ID (hex-encoded public key).
    pub fn get_local_id(&self) -> String {
        hex::encode(self.node.identity_pk.0)
    }

    /// Sends a friend request. This performs a DHT lookup and populates the routing table.
    pub async fn add_friend(&self, zero_id: String) -> Result<(), String> {
        let decoded = hex::decode(&zero_id).map_err(|e| format!("Invalid hex: {}", e))?;
        if decoded.len() != 32 {
            return Err("Identity must be 32 bytes".to_string());
        }
        let mut target_pk_bytes = [0u8; 32];
        target_pk_bytes.copy_from_slice(&decoded);
        let target_pk = DhtPublicKey(target_pk_bytes);

        let nodes = self.node.dht_lookup(&target_pk).await;
        if nodes.is_empty() {
            return Err("Peer not found in DHT".to_string());
        }

        let mut rt = self.node.routing_table.lock().await;
        for node in nodes {
            rt.insert(node);
        }
        Ok(())
    }

    /// Encrypts and sends a message to a specific peer.
    pub async fn send_message(&self, friend_id: String, message: String) -> Result<(), String> {
        let decoded = hex::decode(&friend_id).map_err(|e| format!("Invalid hex: {}", e))?;
        if decoded.len() != 32 {
            return Err("Friend ID must be 32 bytes".to_string());
        }
        let mut target_pk_bytes = [0u8; 32];
        target_pk_bytes.copy_from_slice(&decoded);
        let target_pk = DhtPublicKey(target_pk_bytes);

        let nodes = self.node.dht_lookup(&target_pk).await;
        if nodes.is_empty() {
            return Err("Friend not found in DHT".to_string());
        }
        let target_node = &nodes[0];

        // Retrieve or establish secure FriendSession
        let mut sessions_map = self.sessions.lock().await;
        let session = if let Some(s) = sessions_map.get_mut(&target_pk) {
            s
        } else {
            // Perform simulated Noise IK handshake and establish session
            let mut alice_hs = zero_crypto::noise::build_initiator(&self.node.keypair, &target_pk.0)
                .map_err(|e| format!("Noise error: {:?}", e))?;
            let mut bob_hs = zero_crypto::noise::build_responder(&self.node.keypair)
                .map_err(|e| format!("Noise error: {:?}", e))?;

            let mut buf = [0u8; 1024];
            let len = alice_hs.write_message(&[], &mut buf)
                .map_err(|e| format!("Noise error: {:?}", e))?;
            let mut read_buf = [0u8; 1024];
            let _ = bob_hs.read_message(&buf[..len], &mut read_buf);

            let len = bob_hs.write_message(&[], &mut buf)
                .map_err(|e| format!("Noise error: {:?}", e))?;
            let _ = alice_hs.read_message(&buf[..len], &mut read_buf);

            let noise_transport = alice_hs.into_transport_mode()
                .map_err(|e| format!("Noise error: {:?}", e))?;

            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(self.node.keypair.private.as_ref());
            let local_secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let remote_pub = x25519_dalek::PublicKey::from(target_pk.0);
            let shared_secret = local_secret.diffie_hellman(&remote_pub);
            let ratchet_secret = shared_secret.to_bytes();

            let s = FriendSession::new(noise_transport, ratchet_secret);
            sessions_map.insert(target_pk, s);
            sessions_map.get_mut(&target_pk).unwrap()
        };

        // Encrypt the message using Double Ratchet
        let friend_msg = session.encrypt_message(message.as_bytes())
            .map_err(|e| format!("Ratchet encrypt failed: {:?}", e))?;

        let friend_msg_bytes = bincode::serialize(&friend_msg)
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Construct 3-hop onion tunnel
        let mut hop_nodes = Vec::new();
        {
            let rt = self.node.routing_table.lock().await;
            let candidates = rt.find_closest(&target_pk, 10);
            for c in candidates {
                if c.dht_pk != self.node.identity_pk && c.dht_pk != target_pk {
                    hop_nodes.push(c);
                }
            }
        }

        while hop_nodes.len() < 3 {
            hop_nodes.push(target_node.clone());
        }

        let tunnel = zero_onion::path::OnionTunnel::new(
            zero_onion::path::TunnelDirection::Outbound,
            hop_nodes[0].clone(),
            hop_nodes[1].clone(),
            hop_nodes[2].clone(),
        );

        let onion_bytes = zero_onion::packet::wrap_onion(&friend_msg_bytes, &tunnel)
            .map_err(|e| format!("Onion wrap failed: {:?}", e))?;

        let encoded = zero_core::packet::encode_packet(
            zero_core::packet::PacketType::OnionRequest,
            &onion_bytes,
        );

        self.node
            .transport
            .send_packet(&hop_nodes[0], &encoded)
            .await
            .map_err(|e| format!("Send failed: {:?}", e))?;

        Ok(())
    }
}
