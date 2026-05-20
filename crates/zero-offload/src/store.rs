use std::collections::{HashMap, VecDeque};
use crate::blob::{OfflineBlob, IdentityPublicKey};
use crate::OffloadError;

/// Maximum blob size allowed in the network (64 KB).
pub const MAX_BLOB_SIZE: usize = 64 * 1024;
/// Maximum blobs stored per sender public key to prevent DoS.
pub const MAX_BLOBS_PER_SENDER: usize = 50;

pub struct BlobStore {
    /// Maps a recipient's Announce Key (DHT target) to their queue of messages.
    storage: HashMap<[u8; 32], VecDeque<OfflineBlob>>,
    
    /// Tracks how many messages a sender has stored recently for rate limiting.
    sender_rates: HashMap<IdentityPublicKey, usize>,
}

impl BlobStore {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
            sender_rates: HashMap::new(),
        }
    }

    /// Receives an offline blob from the network and stores it if valid.
    pub fn store_blob(
        &mut self,
        target_announce_key: [u8; 32],
        blob: OfflineBlob,
        current_time: u64,
    ) -> Result<(), OffloadError> {
        if blob.ciphertext.len() > MAX_BLOB_SIZE {
            return Err(OffloadError::Serialization);
        }

        blob.verify_integrity(current_time)?;

        // Enforce rate limits per sender
        let count = self.sender_rates.entry(blob.sender_pk.clone()).or_insert(0);
        if *count >= MAX_BLOBS_PER_SENDER {
            return Err(OffloadError::RateLimited);
        }
        *count += 1;

        // Store the blob
        let queue = self.storage.entry(target_announce_key).or_insert_with(VecDeque::new);
        queue.push_back(blob);

        Ok(())
    }

    /// Fetches all blobs for a given announce key and removes them from the store.
    pub fn fetch_blobs(&mut self, target_announce_key: &[u8; 32]) -> Vec<OfflineBlob> {
        let blobs = self.storage.remove(target_announce_key).map(|q| q.into_iter().collect::<Vec<_>>()).unwrap_or_default();
        
        // Decrement sender rates for successfully delivered blobs
        for blob in &blobs {
            if let Some(count) = self.sender_rates.get_mut(&blob.sender_pk) {
                *count = count.saturating_sub(1);
            }
        }
        self.sender_rates.retain(|_, count| *count > 0);
        
        blobs
    }

    /// Periodic garbage collection to remove expired blobs.
    pub fn cleanup_expired(&mut self, current_time: u64) {
        for queue in self.storage.values_mut() {
            queue.retain(|blob| {
                if blob.expires_at >= current_time {
                    true
                } else {
                    // Decrement sender rates for expired blobs
                    if let Some(count) = self.sender_rates.get_mut(&blob.sender_pk) {
                        *count = count.saturating_sub(1);
                    }
                    false
                }
            });
        }
        self.storage.retain(|_, queue| !queue.is_empty());
        self.sender_rates.retain(|_, count| *count > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{IdentityPublicKey, OfflineBlob};

    fn dummy_blob(sender_seed: u8, expires_at: u64) -> OfflineBlob {
        OfflineBlob {
            nonce: [0u8; 12],
            ciphertext: vec![0xABu8; 64],
            sender_sig: vec![0u8; 64],
            sender_pk: IdentityPublicKey([sender_seed; 32]),
            expires_at,
            pow_token: [0u8; 32],
            pow_nonce: 0,
        }
    }

    fn target_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Bypasses PoW/sig verification to directly insert blobs for store-level tests.
    fn force_store(store: &mut BlobStore, target: [u8; 32], blob: OfflineBlob) {
        let count = store.sender_rates.entry(blob.sender_pk.clone()).or_insert(0);
        *count += 1;
        store.storage.entry(target).or_insert_with(VecDeque::new).push_back(blob);
    }

    // ── Basic Store / Fetch ───────────────────────────────────────────────

    #[test]
    fn test_fetch_returns_stored_blobs() {
        let mut store = BlobStore::new();
        let target = target_key(1);
        force_store(&mut store, target, dummy_blob(10, u64::MAX));
        force_store(&mut store, target, dummy_blob(10, u64::MAX));

        let blobs = store.fetch_blobs(&target);
        assert_eq!(blobs.len(), 2);
    }

    #[test]
    fn test_fetch_removes_blobs_from_store() {
        let mut store = BlobStore::new();
        let target = target_key(2);
        force_store(&mut store, target, dummy_blob(20, u64::MAX));

        store.fetch_blobs(&target);
        let blobs = store.fetch_blobs(&target);
        assert_eq!(blobs.len(), 0, "Blobs should be gone after first fetch");
    }

    #[test]
    fn test_fetch_nonexistent_target_returns_empty() {
        let mut store = BlobStore::new();
        let blobs = store.fetch_blobs(&target_key(99));
        assert!(blobs.is_empty());
    }

    // ── Rate Limiting & Quota Recovery ────────────────────────────────────

    #[test]
    fn test_sender_rate_decremented_on_fetch() {
        let mut store = BlobStore::new();
        let target = target_key(3);
        let sender = IdentityPublicKey([30u8; 32]);

        force_store(&mut store, target, dummy_blob(30, u64::MAX));
        assert_eq!(*store.sender_rates.get(&sender).unwrap(), 1);

        store.fetch_blobs(&target);
        assert!(!store.sender_rates.contains_key(&sender),
            "Sender rate should be cleaned up after all blobs fetched");
    }

    #[test]
    fn test_sender_rate_decremented_on_expiry() {
        let mut store = BlobStore::new();
        let target = target_key(4);
        let sender = IdentityPublicKey([40u8; 32]);

        // Blob expired at time=100
        force_store(&mut store, target, dummy_blob(40, 100));
        assert_eq!(*store.sender_rates.get(&sender).unwrap(), 1);

        // Cleanup at time=200 (after expiry)
        store.cleanup_expired(200);
        assert!(!store.sender_rates.contains_key(&sender),
            "Sender rate should be cleaned up after blob expiry");
    }

    #[test]
    fn test_non_expired_blob_survives_cleanup() {
        let mut store = BlobStore::new();
        let target = target_key(5);
        force_store(&mut store, target, dummy_blob(50, 9999));

        store.cleanup_expired(100);
        assert!(store.storage.contains_key(&target), "Non-expired blob should remain");
    }

    #[test]
    fn test_empty_queues_pruned_after_cleanup() {
        let mut store = BlobStore::new();
        let target = target_key(6);
        force_store(&mut store, target, dummy_blob(60, 100));

        store.cleanup_expired(200);
        assert!(!store.storage.contains_key(&target), "Empty queue should be pruned");
    }

    // ── Size Limits ───────────────────────────────────────────────────────

    #[test]
    fn test_oversized_blob_rejected() {
        let mut store = BlobStore::new();
        let target = target_key(7);
        let mut big_blob = dummy_blob(70, u64::MAX);
        big_blob.ciphertext = vec![0u8; MAX_BLOB_SIZE + 1];

        let result = store.store_blob(target, big_blob, 0);
        assert!(result.is_err(), "Oversized blob should be rejected");
    }
}
