use crate::ZeroError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// Encrypts data using ChaCha20-Poly1305.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, ZeroError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(&n, payload)
        .map_err(|_| ZeroError::EncryptionError)
}

/// Decrypts data using ChaCha20-Poly1305.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, ZeroError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(&n, payload)
        .map_err(|_| ZeroError::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42; 32];
        let nonce = [0x24; 12];
        let plaintext = b"hello world";
        let aad = b"header data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Wrong key
        let bad_key = [0x43; 32];
        assert!(decrypt(&bad_key, &nonce, &ciphertext, aad).is_err());
    }
}
