use crate::node::{DhtPublicKey, NodeInfo};
use arrayvec::ArrayVec;
use std::time::Instant;

pub const K: usize = 20;        // k-bucket size
pub const KEY_BITS: usize = 256;

/// XOR Distance wrapper for Kademlia metric
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    pub fn calculate(a: &DhtPublicKey, b: &DhtPublicKey) -> Self {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a.0[i] ^ b.0[i];
        }
        Self(dist)
    }

    /// Returns the index of the highest set bit (0 to 255), or None if zero
    pub fn leading_zeros(&self) -> u32 {
        for (i, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                return (i as u32 * 8) + byte.leading_zeros();
            }
        }
        256
    }
}

pub struct KBucket {
    pub nodes: ArrayVec<NodeInfo, K>,
    pub last_updated: Instant,
    // The prefix space this bucket covers (0 to 256)
    pub prefix_length: u32,
}

impl KBucket {
    pub fn new(prefix_length: u32) -> Self {
        Self {
            nodes: ArrayVec::new(),
            last_updated: Instant::now(),
            prefix_length,
        }
    }

    pub fn touch(&mut self) {
        self.last_updated = Instant::now();
    }
}

/// Dynamic Kademlia Routing Table featuring bucket-splitting.
pub struct RoutingTable {
    pub local_key: DhtPublicKey,
    // Dynamic tree of buckets, starting with a single bucket.
    pub buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_key: DhtPublicKey) -> Self {
        let mut buckets = Vec::with_capacity(KEY_BITS);
        // Start with a single bucket covering the entire network space (prefix length 0)
        buckets.push(KBucket::new(0));
        Self { local_key, buckets }
    }

    /// Finds the index of the bucket that should contain the given distance.
    pub fn find_bucket_index(&self, dist: &Distance) -> usize {
        let lz = dist.leading_zeros() as usize;
        if lz == 256 { return 0; }
        std::cmp::min(lz, self.buckets.len() - 1)
    }

    /// Inserts a node into the routing table. Splitting buckets if necessary.
    pub fn insert(&mut self, node: NodeInfo) -> bool {
        let dist = Distance::calculate(&self.local_key, &node.dht_pk);
        if dist.leading_zeros() == 256 {
            return false; // Cannot insert self
        }

        let mut idx = self.find_bucket_index(&dist);
        
        // Anti-sybil subnet checking
        if let Some(subnet) = node.subnet_24() {
            let count = self.buckets[idx].nodes.iter().filter(|n| n.subnet_24() == Some(subnet)).count();
            if count >= 2 {
                return false;
            }
        }

        if let Some(existing) = self.buckets[idx].nodes.iter_mut().find(|n| n.dht_pk == node.dht_pk) {
            existing.mark_seen();
            existing.addr = node.addr;
            return true;
        }

        if self.buckets[idx].nodes.len() < K {
            self.buckets[idx].nodes.push(node);
            return true;
        }

        // BUCKET IS FULL - Try Eviction First
        if let Some((i, _)) = self.buckets[idx].nodes.iter().enumerate().find(|(_, n)| n.reputation < -10) {
            self.buckets[idx].nodes[i] = node;
            return true;
        }

        // BUCKET SPLITTING LOGIC
        // We only split if the bucket covers the local node's space.
        // In this architecture, the bucket covering the local node is always the last bucket.
        if idx == self.buckets.len() - 1 && self.buckets.len() < KEY_BITS {
            self.split_bucket(idx);
            
            // Re-evaluate index after split
            idx = self.find_bucket_index(&dist);
            if self.buckets[idx].nodes.len() < K {
                self.buckets[idx].nodes.push(node);
                return true;
            }
        }
        
        false
    }

    fn split_bucket(&mut self, idx: usize) {
        let current_depth = idx;
        let mut new_bucket = KBucket::new((current_depth + 1) as u32);
        
        // Redistribute nodes
        let mut keep = ArrayVec::new();
        for node in self.buckets[idx].nodes.drain(..) {
            let dist = Distance::calculate(&self.local_key, &node.dht_pk);
            let lz = dist.leading_zeros() as usize;
            
            if lz == current_depth {
                keep.push(node);
            } else {
                let _ = new_bucket.nodes.push(node);
            }
        }
        
        self.buckets[idx].nodes = keep;
        self.buckets.push(new_bucket);
    }

    pub fn find_closest(&self, target: &DhtPublicKey, count: usize) -> Vec<NodeInfo> {
        let mut all_nodes: Vec<_> = self.buckets.iter()
            .flat_map(|b| b.nodes.iter().cloned())
            .map(|n| {
                let dist = Distance::calculate(&n.dht_pk, target);
                (dist, n)
            })
            .collect();

        all_nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        all_nodes.into_iter().take(count).map(|(_, n)| n).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_pk(seed: u8) -> DhtPublicKey {
        DhtPublicKey([seed; 32])
    }

    fn make_node(pk_seed: u8, ip_suffix: u8) -> NodeInfo {
        let addr: SocketAddr = format!("10.0.0.{}:33445", ip_suffix).parse().unwrap();
        NodeInfo::new(make_pk(pk_seed), addr)
    }

    #[test]
    fn test_distance_leading_zeros_all_same() {
        let a = make_pk(0xFF);
        let b = make_pk(0xFF);
        let dist = Distance::calculate(&a, &b);
        assert_eq!(dist.leading_zeros(), 256); // identical keys = zero distance
    }

    #[test]
    fn test_distance_first_bit_differs() {
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 0b10000000;
        b_bytes[0] = 0b00000000;
        let dist = Distance::calculate(&DhtPublicKey(a_bytes), &DhtPublicKey(b_bytes));
        assert_eq!(dist.leading_zeros(), 0);
    }

    #[test]
    fn test_insert_self_rejected() {
        let local = make_pk(0xAA);
        let mut rt = RoutingTable::new(local);
        let self_node = NodeInfo::new(local, "10.0.0.1:33445".parse().unwrap());
        let inserted = rt.insert(self_node);
        assert!(!inserted, "Should not be able to insert self");
        assert_eq!(rt.buckets[0].nodes.len(), 0);
    }

    #[test]
    fn test_basic_insert_and_find() {
        let local = make_pk(0x00);
        let mut rt = RoutingTable::new(local);

        let node = make_node(0x01, 1);
        assert!(rt.insert(node));

        let closest = rt.find_closest(&make_pk(0x01), 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].dht_pk, make_pk(0x01));
    }

    #[test]
    fn test_duplicate_insert_updates_not_duplicates() {
        let local = make_pk(0x00);
        let mut rt = RoutingTable::new(local);

        let node = make_node(0x01, 1);
        rt.insert(node.clone());
        rt.insert(node.clone());
        rt.insert(node.clone());

        let total_nodes: usize = rt.buckets.iter().map(|b| b.nodes.len()).sum();
        assert_eq!(total_nodes, 1, "Duplicate inserts should not add extra nodes");
    }

    #[test]
    fn test_sybil_protection_same_subnet() {
        let local = make_pk(0x00);
        let mut rt = RoutingTable::new(local);

        // 3 nodes on the same /24 subnet — only first 2 should be admitted
        for i in 1u8..=3 {
            let addr: std::net::SocketAddr = format!("192.168.1.{}:33445", i).parse().unwrap();
            let node = NodeInfo::new(make_pk(i), addr);
            rt.insert(node);
        }

        let same_subnet_count = rt.buckets.iter()
            .flat_map(|b| b.nodes.iter())
            .filter(|n| {
                if let std::net::IpAddr::V4(ip) = n.addr.ip() {
                    ip.octets()[0..3] == [192, 168, 1]
                } else {
                    false
                }
            })
            .count();

        assert!(same_subnet_count <= 2, "Anti-sybil: max 2 nodes per /24 subnet, got {}", same_subnet_count);
    }

    #[test]
    fn test_find_closest_ordering() {
        let local = make_pk(0x00);
        let mut rt = RoutingTable::new(local);

        // Insert nodes with different seeds; node 0x01 should be closer to 0x01 target
        for i in 1u8..=5 {
            rt.insert(make_node(i, i));
        }

        let target = make_pk(0x01);
        let closest = rt.find_closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // The closest node to target=0x01 should be the node with pk=0x01 (distance=0)
        assert_eq!(closest[0].dht_pk, make_pk(0x01));
    }

    #[test]
    fn test_eviction_of_bad_reputation_nodes() {
        let local = make_pk(0x00);
        let mut rt = RoutingTable::new(local);

        // Fill the bucket
        for i in 1..=(K as u8) {
            let addr: std::net::SocketAddr = format!("10.{}.0.1:33445", i).parse().unwrap();
            rt.insert(NodeInfo::new(make_pk(i), addr));
        }

        // Sabotage first node's reputation
        rt.buckets[0].nodes[0].reputation = -11;

        // Try to insert a new node that can replace the bad one
        let addr: std::net::SocketAddr = "10.99.0.1:33445".parse().unwrap();
        let new_node = NodeInfo::new(make_pk(0xFE), addr);
        let inserted = rt.insert(new_node);
        assert!(inserted, "Bad-reputation node should be evicted for new node");
    }
}
