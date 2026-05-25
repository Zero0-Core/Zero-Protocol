use crate::blob::{OfflineBlob, IdentityPublicKey};
use zero_crypto::keypair::StaticKeypair;
use std::time::{SystemTime, UNIX_EPOCH};
use zero_crypto::aead;
use rand::RngCore;

/// Helper structure for a sender preparing an offline message.
pub struct OffloadClient;

impl OffloadClient {
    /// Creates an offline message destined for `recipient_pk`.
    /// Performs PoW generation natively.
    pub fn create_message(
        sender_identity: &StaticKeypair,
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<OfflineBlob, crate::OffloadError> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Deriving shared secret via ECDH
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(sender_identity.private.as_ref());
        let local_secret = x25519_dalek::StaticSecret::from(secret_bytes);
        
        let remote_pub = x25519_dalek::PublicKey::from(*recipient_pk);
        let shared_secret = local_secret.diffie_hellman(&remote_pub);

        // Derive encryption key
        let key = zero_crypto::kdf::derive_key(shared_secret.as_bytes(), b"zero-offload", &[0u8; 32]);
        let ciphertext = aead::encrypt(&key, &nonce, plaintext, &[])?;

        // Generate Ed25519 keys from the same seed
        let seed_bytes: &[u8; 32] = sender_identity.seed.as_ref();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes);
        let verify_key = signing_key.verifying_key();
        let sender_pk = IdentityPublicKey(verify_key.to_bytes());
        let sender_dht_pk = IdentityPublicKey(sender_identity.public);

        let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + (7 * 86400);

        // Generate PoW (Difficulty: 18 bits)
        let mut context = Vec::new();
        context.extend_from_slice(&sender_pk.0);
        context.extend_from_slice(&expires_at.to_le_bytes());
        context.extend_from_slice(&ciphertext);
        let (pow_token, pow_nonce) = zero_crypto::pow::generate_pow(&context, 18);

        let mut msg_to_sign = Vec::new();
        msg_to_sign.extend_from_slice(&nonce);
        msg_to_sign.extend_from_slice(&ciphertext);
        msg_to_sign.extend_from_slice(&expires_at.to_le_bytes());
        msg_to_sign.extend_from_slice(&pow_token);
        
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&msg_to_sign);
        let sender_sig = sig.to_bytes().to_vec();

        Ok(OfflineBlob {
            nonce,
            ciphertext,
            sender_sig,
            sender_pk,
            sender_dht_pk,
            expires_at,
            pow_token,
            pow_nonce,
        })
    }
}
