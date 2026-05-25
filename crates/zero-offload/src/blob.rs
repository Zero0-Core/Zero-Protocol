use serde::{Deserialize, Serialize};

/// Represents the public identity key for a user (long-term Ed25519 or X25519).
/// Here we use [u8; 32] as the standardized identity key wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IdentityPublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineBlob {
    /// Nonce for ChaCha20-Poly1305 encryption.
    pub nonce: [u8; 12],

    /// Payload encrypted with recipient's X25519 public key via ECDH + HKDF + ChaCha20-Poly1305.
    /// Recipient can decrypt; nobody else (not even the storing node) can.
    pub ciphertext: Vec<u8>,

    /// Ed25519 signature by the sender's identity key (stored as bytes; serde only supports
    /// arrays up to [u8; 32] by default, so we use Vec<u8> for the 64-byte sig).
    pub sender_sig: Vec<u8>,

    /// Sender's public identity key (needed for signature verification).
    pub sender_pk: IdentityPublicKey,

    /// Sender's DHT identity key (X25519 public key).
    pub sender_dht_pk: IdentityPublicKey,

    /// Unix timestamp. Nodes MUST drop blobs older than 7 days.
    pub expires_at: u64,

    /// Anti-spam: BLAKE2s proof-of-work token (difficulty: 18 leading zero bits).
    pub pow_token: [u8; 32],
    pub pow_nonce: u64,
}

impl OfflineBlob {
    /// Verifies the structural integrity, expiration, and PoW of the blob.
    pub fn verify_integrity(&self, current_time: u64) -> Result<(), crate::OffloadError> {
        if current_time > self.expires_at {
            return Err(crate::OffloadError::Expired);
        }

        // Verify PoW. Difficulty is 18 bits.
        let mut context = Vec::new();
        context.extend_from_slice(&self.sender_pk.0);
        context.extend_from_slice(&self.expires_at.to_le_bytes());
        context.extend_from_slice(&self.ciphertext);

        zero_crypto::pow::verify_pow(&context, self.pow_nonce, &self.pow_token, 18)
            .map_err(|_| crate::OffloadError::InvalidPow)?;

        use ed25519_dalek::Verifier;
        let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&self.sender_pk.0)
            .map_err(|_| crate::OffloadError::InvalidSignature)?;
            
        // Mathematically verify that the Ed25519 public key converts to the sender_dht_pk X25519 key!
        if verify_key.to_montgomery().to_bytes() != self.sender_dht_pk.0 {
            return Err(crate::OffloadError::InvalidSignature);
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&self.nonce);
        msg.extend_from_slice(&self.ciphertext);
        msg.extend_from_slice(&self.expires_at.to_le_bytes());
        msg.extend_from_slice(&self.pow_token);
        
        let sig_bytes: [u8; 64] = self.sender_sig.as_slice().try_into()
            .map_err(|_| crate::OffloadError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        
        verify_key.verify(&msg, &signature).map_err(|_| crate::OffloadError::InvalidSignature)?;

        Ok(())
    }
}
