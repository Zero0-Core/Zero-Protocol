use crate::node::{DhtPublicKey, NodeInfo};
use serde::{Deserialize, Serialize};
use rand::RngCore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtPayload {
    PingRequest,
    PingResponse,
    FindNodeRequest {
        target_pk: DhtPublicKey,
    },
    FindNodeResponse {
        nodes: Vec<NodeInfo>,
    },
    AnnouncePeer {
        /// The one-day-rotating announce key, NOT the real identity key
        announce_key: DhtPublicKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPacket {
    pub sender_pk: DhtPublicKey,
    pub nonce: [u8; 24],
    pub request_id: [u8; 8],
    /// Encrypted `DhtPayload`
    pub encrypted_payload: Vec<u8>,
}

impl DhtPacket {
    /// Creates a new packet with a cryptographically random request ID and nonce.
    pub fn new(sender_pk: DhtPublicKey, encrypted_payload: Vec<u8>) -> Self {
        let mut nonce = [0u8; 24];
        let mut request_id = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        rand::thread_rng().fill_bytes(&mut request_id);
        Self {
            sender_pk,
            nonce,
            request_id,
            encrypted_payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let pk = DhtPublicKey([1u8; 32]);
        let packet = DhtPacket::new(pk, vec![1, 2, 3]);
        
        let bytes = bincode::serialize(&packet).unwrap();
        let decoded: DhtPacket = bincode::deserialize(&bytes).unwrap();
        
        assert_eq!(decoded.sender_pk, pk);
        assert_eq!(decoded.encrypted_payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_nonces_are_unique() {
        let pk = DhtPublicKey([0u8; 32]);
        let p1 = DhtPacket::new(pk, vec![]);
        let p2 = DhtPacket::new(pk, vec![]);
        // Statistically impossible for two random nonces to match
        assert_ne!(p1.nonce, p2.nonce);
    }
}
