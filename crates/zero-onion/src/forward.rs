use crate::packet::OnionPacket;
use crate::OnionError;
use x25519_dalek::{PublicKey, StaticSecret};
use zero_crypto::aead;
use zero_crypto::kdf::derive_key;

/// Peels one layer of encryption off an Onion Packet.
/// This allows intermediate nodes to blindly decrypt and forward the inner payload
/// without seeing the contents or knowing the ultimate destination.
pub fn peel_and_forward(
    packet: &OnionPacket,
    local_key: &zero_crypto::keypair::StaticKeypair,
) -> Result<crate::packet::OnionCommand, OnionError> {
    // 1. Reconstruct the shared secret using our long-term private key
    //    and the sender's ephemeral public key found in the packet header.
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(local_key.private.as_ref());
    let secret = StaticSecret::from(secret_bytes);
    let remote_pub = PublicKey::from(packet.ephemeral_pk);

    let shared_secret = secret.diffie_hellman(&remote_pub);

    // 2. Derive the symmetric decryption key using the identical KDF structure.
    let key = derive_key(shared_secret.as_bytes(), b"zero-onion-v1", &[0u8; 32]);

    // 3. Perform ChaCha20-Poly1305 authenticated decryption.
    // If successful, we have peeled a layer. If this fails, the packet is dropped.
    let decrypted = aead::decrypt(&key, &packet.nonce, &packet.payload, &[])?;

    // 4. Parse the routing instruction
    let command: crate::packet::OnionCommand =
        bincode::deserialize(&decrypted).map_err(|_| OnionError::InvalidPacket)?;

    Ok(command)
}
