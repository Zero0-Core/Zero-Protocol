use std::sync::Arc;
use tracing::info;
use zero_core::node::ZeroNode;
use zero_crypto::keypair::StaticKeypair;

/// The bridge orchestrator that manages communication between Zero Protocol and Matrix.
struct MatrixZeroBridge {
    zero_node: Arc<ZeroNode>,
}

impl MatrixZeroBridge {
    pub async fn new(bind_addr: &str, zero_priv_bytes: [u8; 32]) -> Self {
        let addr = bind_addr.parse().unwrap();
        let keypair = StaticKeypair::from_bytes(zero_priv_bytes);

        let zero_node = Arc::new(
            ZeroNode::new(addr, keypair)
                .await
                .expect("Failed to start ZeroNode"),
        );

        Self { zero_node }
    }

    pub async fn run(&self) {
        info!("Starting Matrix-Zero Federation Bridge...");

        // Start the Zero protocol background tasks (DHT, packet loop, etc.)
        self.zero_node.run_background_tasks().await;

        // 1. In a real implementation: Connect to a Matrix Home Server using an AppService token
        // 2. Listen for messages on bridged rooms.
        // 3. For each Matrix message, determine the target Zero ID and relay it.

        self.mock_matrix_event_loop().await;
    }

    async fn mock_matrix_event_loop(&self) {
        info!("Listening for Matrix events...");

        // This is a mock loop representing receiving events from the Matrix AppService API
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            let matrix_user = "@alice:matrix.org";
            let target_zero_id = "f03126... (mocked)";
            let _message = "Hello from Matrix!";

            info!(
                "Relaying message from {} to Zero ID: {}",
                matrix_user, target_zero_id
            );

            // Here you would:
            // 1. Find the target node in the DHT.
            // 2. Wrap the message in a SessionMessage.
            // 3. Send via the Zero node transport.
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // In a production scenario, these would be loaded from a config file.
    let bind_addr = "0.0.0.0:4040";
    let zero_priv_key = [0u8; 32]; // Bridge's own identity

    let bridge = MatrixZeroBridge::new(bind_addr, zero_priv_key).await;
    bridge.run().await;
}
