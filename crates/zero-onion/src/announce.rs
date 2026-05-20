use blake2::{Blake2s256, Digest};
use zero_crypto::keypair::StaticKeypair;
use zero_dht::node::DhtPublicKey;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates a time-based announce key to prevent long-term tracking.
/// Rotates every 24 hours so passive observers cannot correlate a node's
/// long-term DHT presence with its identity.
pub fn generate_announce_key(identity: &StaticKeypair) -> DhtPublicKey {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let day = now / 86400;

    // Domain-separated hash: Blake2s256(domain || day_epoch || identity_private_key)
    // Blake2s256 is used directly here (not via HKDF) because Blake2's variable-output
    // variant does not implement the HMAC BufferKindUser bound required by hkdf.
    let mut h = Blake2s256::new();
    h.update(b"zero-announce-v1");
    h.update(day.to_le_bytes());
    h.update(identity.private.as_ref());

    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());

    DhtPublicKey(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announce_key_deterministic() {
        let identity = StaticKeypair::generate();
        let key1 = generate_announce_key(&identity);
        let key2 = generate_announce_key(&identity);
        // Within the same day, should produce identical announce keys.
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_announce_key_unique_per_identity() {
        let id1 = StaticKeypair::generate();
        let id2 = StaticKeypair::generate();
        let key1 = generate_announce_key(&id1);
        let key2 = generate_announce_key(&id2);
        // Two different identities must produce different announce keys.
        assert_ne!(key1, key2);
    }
}
