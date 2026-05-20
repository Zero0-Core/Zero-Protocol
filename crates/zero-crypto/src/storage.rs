use crate::ZeroError;
use argon2::Argon2;
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Derives a 32-byte encryption key from user passphrase using Argon2id.
pub fn derive_storage_key(passphrase: &str, salt: &[u8; 32]) -> Result<[u8; 32], ZeroError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).map_err(|_| ZeroError::StorageError)?,
    );
    let mut output = [0u8; 32];
    // PasswordHasher from argon2 expects a salt directly; or we can use hash_password_into.
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|_| ZeroError::StorageError)?;
    Ok(output)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveData {
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl SaveData {
    /// Encrypts a payload into SaveData using a passphrase.
    pub fn encrypt(payload: &[u8], passphrase: &str) -> Result<Self, ZeroError> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let key = derive_storage_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let n = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(&n, payload).map_err(|_| ZeroError::EncryptionError)?;

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Decrypts the SaveData payload using a passphrase.
    pub fn decrypt(&self, passphrase: &str) -> Result<Vec<u8>, ZeroError> {
        let key = derive_storage_key(passphrase, &self.salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let n = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(&n, self.ciphertext.as_ref())
            .map_err(|_| ZeroError::StorageError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_encryption() {
        let payload = b"secret identity data";
        let passphrase = "correct horse battery staple";

        let save_data = SaveData::encrypt(payload, passphrase).unwrap();

        let decrypted = save_data.decrypt(passphrase).unwrap();
        assert_eq!(payload.as_slice(), decrypted.as_slice());

        // Wrong passphrase
        assert!(save_data.decrypt("wrong password").is_err());
    }
}
