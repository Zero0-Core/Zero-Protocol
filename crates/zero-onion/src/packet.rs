use serde::{Deserialize, Serialize};
use zero_crypto::aead;
use zero_crypto::kdf::derive_key;
use x25519_dalek::{PublicKey, StaticSecret};
use zero_dht::node::{DhtPublicKey, NodeInfo};
use rand::RngCore;
use crate::path::OnionPath;
use crate::OnionError;

#[derive(Debug, Serialize, Deserialize)]
pub struct OnionPacket {
    pub ephemeral_pk: [u8; 32],
    pub nonce: [u8; 12],
    pub payload: Vec<u8>,
}

/// Instructions embedded inside the decrypted onion layer.
#[derive(Debug, Serialize, Deserialize)]
pub enum OnionCommand {
    /// Instructs the current node to forward the nested packet to the next hop
    Forward {
        next_hop: NodeInfo,
        packet: OnionPacket,
    },
    /// The final layer containing the actual message for the destination
    Deliver {
        final_payload: Vec<u8>,
    },
}

/// Wraps a payload in 3 layers of encryption.
/// Layer 3 (innermost) -> Layer 2 -> Layer 1 (outermost)
pub fn wrap_onion(
    payload: &[u8],
    path: &OnionPath,
) -> Result<Vec<u8>, OnionError> {
    // 1. Layer 3 (Final Destination): Encrypt Deliver command
    let (l3_key, l3_nonce) = derive_onion_key(&path.hop3_key, &path.hop3.dht_pk);
    let l3_cmd = OnionCommand::Deliver { final_payload: payload.to_vec() };
    let l3_payload = aead::encrypt(&l3_key, &l3_nonce, &bincode::serialize(&l3_cmd)?, &[])?;
    let l3_packet = OnionPacket { 
        ephemeral_pk: path.hop3_key.public, 
        nonce: l3_nonce, 
        payload: l3_payload 
    };

    // 2. Layer 2: Encrypt Forward command (instructs hop2 to send to hop3)
    let (l2_key, l2_nonce) = derive_onion_key(&path.hop2_key, &path.hop2.dht_pk);
    let l2_cmd = OnionCommand::Forward { next_hop: path.hop3.clone(), packet: l3_packet };
    let l2_payload = aead::encrypt(&l2_key, &l2_nonce, &bincode::serialize(&l2_cmd)?, &[])?;
    let l2_packet = OnionPacket { 
        ephemeral_pk: path.hop2_key.public, 
        nonce: l2_nonce, 
        payload: l2_payload 
    };

    // 3. Layer 1: Encrypt Forward command (instructs hop1 to send to hop2)
    let (l1_key, l1_nonce) = derive_onion_key(&path.hop1_key, &path.hop1.dht_pk);
    let l1_cmd = OnionCommand::Forward { next_hop: path.hop2.clone(), packet: l2_packet };
    let l1_payload = aead::encrypt(&l1_key, &l1_nonce, &bincode::serialize(&l1_cmd)?, &[])?;
    let l1_packet = OnionPacket { 
        ephemeral_pk: path.hop1_key.public, 
        nonce: l1_nonce, 
        payload: l1_payload 
    };
    
    bincode::serialize(&l1_packet).map_err(Into::into)
}

fn derive_onion_key(local_ephemeral: &zero_crypto::keypair::StaticKeypair, remote_pk: &DhtPublicKey) -> ([u8; 32], [u8; 12]) {
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(local_ephemeral.private.as_ref());
    let secret = StaticSecret::from(secret_bytes);
    let remote_pub = PublicKey::from(remote_pk.0);
    
    let shared_secret = secret.diffie_hellman(&remote_pub);

    let key = derive_key(shared_secret.as_bytes(), b"zero-onion-v1", &[0u8; 32]);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    (key, nonce)
}
