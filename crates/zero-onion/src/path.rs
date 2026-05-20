use std::time::Instant;
use zero_crypto::keypair::StaticKeypair;
use zero_dht::node::NodeInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    Inbound,
    Outbound,
}

/// Represents a 3-hop unidirectional tunnel for onion routing.
pub struct OnionTunnel {
    pub direction: TunnelDirection,
    pub hop1: NodeInfo,
    pub hop2: NodeInfo,
    pub hop3: NodeInfo,
    /// Our ephemeral keys used to encrypt for each specific hop
    pub hop1_key: StaticKeypair,
    pub hop2_key: StaticKeypair,
    pub hop3_key: StaticKeypair,
    pub created_at: Instant,
}

impl OnionTunnel {
    /// Builds a new onion tunnel from 3 selected nodes.
    /// Generates fresh ephemeral keys for each hop.
    pub fn new(direction: TunnelDirection, hop1: NodeInfo, hop2: NodeInfo, hop3: NodeInfo) -> Self {
        Self {
            direction,
            hop1,
            hop2,
            hop3,
            hop1_key: StaticKeypair::generate(),
            hop2_key: StaticKeypair::generate(),
            hop3_key: StaticKeypair::generate(),
            created_at: Instant::now(),
        }
    }

    /// Checks if the tunnel should be rotated (e.g., every 5 minutes).
    pub fn needs_rotation(&self) -> bool {
        self.created_at.elapsed().as_secs() > 300
    }
}
