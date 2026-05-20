use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A long-term static keypair for X25519.
pub struct StaticKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl StaticKeypair {
    /// Generates a new static keypair using the OS random number generator.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: public.to_bytes(),
        }
    }

    /// Restores a keypair from raw private key bytes.
    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: public.to_bytes(),
        }
    }
}

/// An ephemeral keypair for short-lived X25519 sessions.
pub struct EphemeralKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl EphemeralKeypair {
    /// Generates a new ephemeral keypair using the OS random number generator.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: public.to_bytes(),
        }
    }
}

/// A keypair specifically for DHT operations.
pub struct DhtKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl DhtKeypair {
    /// Generates a new DHT keypair using the OS random number generator.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: public.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_keypair_generation() {
        let kp1 = StaticKeypair::generate();
        let kp2 = StaticKeypair::generate();
        assert_ne!(kp1.private.as_ref(), kp2.private.as_ref());
        assert_ne!(kp1.public, kp2.public);
    }
}
