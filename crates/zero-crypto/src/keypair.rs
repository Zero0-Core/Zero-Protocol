use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A long-term static keypair for X25519, linked to Ed25519.
pub struct StaticKeypair {
    pub seed: Zeroizing<[u8; 32]>,
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl StaticKeypair {
    /// Generates a new static keypair using the OS random number generator.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        Self::from_bytes(seed)
    }

    /// Restores a keypair from raw master seed bytes.
    pub fn from_bytes(seed_bytes: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        let x25519_priv = signing_key.to_scalar_bytes();
        let secret = StaticSecret::from(x25519_priv);
        let public = PublicKey::from(&secret);
        Self {
            seed: Zeroizing::new(seed_bytes),
            private: Zeroizing::new(x25519_priv),
            public: public.to_bytes(),
        }
    }
}

/// An ephemeral keypair for short-lived X25519 sessions.
#[derive(Debug, Clone)]
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
