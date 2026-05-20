#![forbid(unsafe_code)]

use std::sync::Arc;
use tokio::sync::Mutex;
use zero_core::node::ZeroNode;
use zero_dht::node::DhtPublicKey;

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

        Ok(Arc::new(Self {
            node,
            delegate: Arc::new(Mutex::new(None)),
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

        // In a production environment, we'd check the session manager here.
        // For now, we perform a lookup if the node isn't found locally.
        let nodes = self.node.dht_lookup(&target_pk).await;
        if nodes.is_empty() {
            return Err("Friend not found in DHT".to_string());
        }

        let target_node = &nodes[0];
        let payload = message.as_bytes();
        let encoded = zero_core::packet::encode_packet(
            zero_core::packet::PacketType::SessionMessage,
            payload,
        );

        self.node
            .transport
            .send_packet(target_node, &encoded)
            .await
            .map_err(|e| format!("Send failed: {:?}", e))?;

        Ok(())
    }
}
