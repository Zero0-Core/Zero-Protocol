use blake2::{Blake2s256, Digest};

/// Derives a 32-byte symmetric key from an ECDH shared secret.
/// Never use the raw ECDH output as an encryption key.
pub fn derive_key(
    shared_secret: &[u8; 32],
    context: &[u8],  // domain separation string
    salt: &[u8; 32], // random nonce or session ID
) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"zero-protocol-v1-key-derive");
    h.update(shared_secret);
    h.update(context);
    h.update(salt);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let secret = [1u8; 32];
        let context = b"test-context";
        let salt = [2u8; 32];

        let key1 = derive_key(&secret, context, &salt);
        let key2 = derive_key(&secret, context, &salt);

        assert_eq!(key1, key2);

        // Different context should yield different key
        let key3 = derive_key(&secret, b"different", &salt);
        assert_ne!(key1, key3);
    }
}
