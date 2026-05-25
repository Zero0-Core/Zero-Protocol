use crate::ratchet::DoubleRatchetState;
use crate::lossless::LosslessQueue;
use snow::TransportState;
use zero_crypto::ZeroError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FriendMessage {
    pub sequence_number: u64,
    pub ciphertext: Vec<u8>,
}

/// A fully established end-to-end encrypted session with a friend.
pub struct FriendSession {
    /// Outer Noise IK channel transport state
    pub noise_transport: TransportState,
    /// Inner message-level double ratchet for deniable, forward-secret messaging
    pub ratchet: DoubleRatchetState,
    
    pub send_counter: u64,
    pub recv_counter: u64,
    
    /// Handles retransmissions and ACKs
    pub lossless_queue: LosslessQueue,
}

impl FriendSession {
    pub fn new(noise_transport: TransportState, ratchet_secret: [u8; 32]) -> Self {
        Self {
            noise_transport,
            ratchet: DoubleRatchetState::new(ratchet_secret),
            send_counter: 0,
            recv_counter: 0,
            lossless_queue: LosslessQueue::new(),
        }
    }

    /// Encrypts a message using the Double Ratchet message key and wraps it.
    /// The nonce is derived from the send counter so it is unique per message
    /// and never reused under the same ratchet key.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<FriendMessage, ZeroError> {
        let msg_key = self.ratchet.ratchet_send();
        // Build a 12-byte nonce from the current send counter (8 bytes LE, 4 bytes zero).
        // Because each ratchet step yields a distinct key AND the counter never repeats,
        // (key, nonce) pairs are unique across all messages in this session.
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.send_counter.to_le_bytes());
        
        let ciphertext = zero_crypto::aead::encrypt(&msg_key, &nonce, plaintext, &[])?;
        
        let msg = FriendMessage {
            sequence_number: self.send_counter,
            ciphertext,
        };
        self.send_counter += 1;
        Ok(msg)
    }

    pub fn decrypt_message(&mut self, msg: &FriendMessage) -> Result<Vec<u8>, ZeroError> {
        let msg_key = self.ratchet.ratchet_recv();
        // Reconstruct the same counter-derived nonce used during encryption.
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&msg.sequence_number.to_le_bytes());
        
        let plaintext = zero_crypto::aead::decrypt(&msg_key, &nonce, &msg.ciphertext, &[])?;
        self.recv_counter = msg.sequence_number + 1;
        Ok(plaintext)
    }
}
