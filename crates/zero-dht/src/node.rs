use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DhtPublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub dht_pk: DhtPublicKey,
    pub addr: SocketAddr,
    #[serde(skip)]
    pub last_seen: Option<Instant>,
    pub reputation: i8,          // -128 to 127; evicted if < -10
    pub consecutive_failures: u8,
}

impl NodeInfo {
    pub fn new(dht_pk: DhtPublicKey, addr: SocketAddr) -> Self {
        Self {
            dht_pk,
            addr,
            last_seen: Some(Instant::now()),
            reputation: 0,
            consecutive_failures: 0,
        }
    }

    pub fn mark_seen(&mut self) {
        self.last_seen = Some(Instant::now());
        self.consecutive_failures = 0;
        if self.reputation < 127 {
            self.reputation += 1;
        }
    }

    pub fn mark_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.reputation > -128 {
            self.reputation -= 5;
        }
    }

    pub fn subnet_24(&self) -> Option<[u8; 3]> {
        match self.addr.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                Some([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(_) => None, // Anti-sybil primarily targets IPv4 for now
        }
    }
}
