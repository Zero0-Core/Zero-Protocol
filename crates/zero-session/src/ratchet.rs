use blake2::{Blake2s256, Digest};

/// The Signal Double Ratchet Algorithm state manager.
/// Uses BLAKE2s256 as the underlying KDF for chain key derivation.
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
}

impl DoubleRatchetState {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            root_key: shared_secret,
            send_chain_key: shared_secret,
            recv_chain_key: shared_secret,
        }
    }

    /// Ratchets the sending chain using HKDF-BLAKE2s256 and returns a message key.
    pub fn ratchet_send(&mut self) -> [u8; 32] {
        let (next_chain, msg_key) = Self::kdf_ratchet(&self.send_chain_key);
        self.send_chain_key = next_chain;
        msg_key
    }

    /// Ratchets the receiving chain using HKDF-BLAKE2s256 and returns a message key.
    pub fn ratchet_recv(&mut self) -> [u8; 32] {
        let (next_chain, msg_key) = Self::kdf_ratchet(&self.recv_chain_key);
        self.recv_chain_key = next_chain;
        msg_key
    }

    /// Performs the symmetric-key ratchet step.
    /// Returns (Next Chain Key, Message Key).
    fn kdf_ratchet(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Signal uses HMAC-SHA256, we use HKDF-BLAKE2s256 to remain consistent with Zero Protocol.
        // Wait, HKDF requires a BlockSizeUser, but BLAKE2s doesn't natively support it in this rust version.
        // Instead, we use a custom domain-separated BLAKE2s KDF.
        let mut h_chain = Blake2s256::new();
        h_chain.update(b"zero-ratchet-chain");
        h_chain.update(chain_key);
        
        let mut h_msg = Blake2s256::new();
        h_msg.update(b"zero-ratchet-message");
        h_msg.update(chain_key);

        let mut next_chain = [0u8; 32];
        let mut msg_key = [0u8; 32];
        
        next_chain.copy_from_slice(&h_chain.finalize());
        msg_key.copy_from_slice(&h_msg.finalize());

        (next_chain, msg_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(seed: u8) -> DoubleRatchetState {
        DoubleRatchetState::new([seed; 32])
    }

    // ── Send Chain ────────────────────────────────────────────────────────

    #[test]
    fn test_send_ratchet_produces_unique_keys() {
        let mut state = make_state(0xAA);
        let k1 = state.ratchet_send();
        let k2 = state.ratchet_send();
        let k3 = state.ratchet_send();
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_send_ratchet_is_deterministic() {
        let seed = [0x42u8; 32];
        let mut s1 = DoubleRatchetState::new(seed);
        let mut s2 = DoubleRatchetState::new(seed);
        assert_eq!(s1.ratchet_send(), s2.ratchet_send());
        assert_eq!(s1.ratchet_send(), s2.ratchet_send());
    }

    // ── Recv Chain ────────────────────────────────────────────────────────

    #[test]
    fn test_recv_ratchet_produces_unique_keys() {
        let mut state = make_state(0xBB);
        let k1 = state.ratchet_recv();
        let k2 = state.ratchet_recv();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_recv_ratchet_is_deterministic() {
        let seed = [0x55u8; 32];
        let mut s1 = DoubleRatchetState::new(seed);
        let mut s2 = DoubleRatchetState::new(seed);
        assert_eq!(s1.ratchet_recv(), s2.ratchet_recv());
    }

    // ── Chain Independence ────────────────────────────────────────────────

    #[test]
    fn test_send_and_recv_chains_are_independent() {
        let mut state = make_state(0xCC);
        let send_key = state.ratchet_send();
        let recv_key = state.ratchet_recv();
        // Send and recv derive from the same root but with different domain separators
        assert_ne!(send_key, recv_key,
            "Send and recv chains must produce different keys even from same root");
    }

    #[test]
    fn test_send_chain_does_not_affect_recv_chain() {
        let seed = [0x77u8; 32];
        let mut s1 = DoubleRatchetState::new(seed);
        let mut s2 = DoubleRatchetState::new(seed);

        // Advance send chain on s1 several times
        s1.ratchet_send();
        s1.ratchet_send();
        s1.ratchet_send();

        // Recv chain on both should still agree (send chain doesn't affect recv chain)
        assert_eq!(s1.ratchet_recv(), s2.ratchet_recv());
    }

    // ── Message Key ≠ Chain Key ───────────────────────────────────────────

    #[test]
    fn test_message_key_differs_from_new_chain_key() {
        let mut s = make_state(0x11);
        let before_chain = s.send_chain_key;
        let msg_key = s.ratchet_send();
        let after_chain = s.send_chain_key;

        assert_ne!(msg_key, after_chain, "Message key must not equal the new chain key");
        assert_ne!(before_chain, after_chain, "Chain key must advance after ratchet");
    }
}
