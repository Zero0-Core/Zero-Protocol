use crate::keypair::StaticKeypair;
use crate::ZeroError;
use snow::{Builder, HandshakeState};

const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Builds the initiator state for a Noise IK handshake.
pub fn build_initiator(
    local_static: &StaticKeypair,
    remote_static_pubkey: &[u8; 32],
) -> Result<HandshakeState, ZeroError> {
    let params = NOISE_PARAMS.parse().map_err(ZeroError::Handshake)?;
    Builder::new(params)
        .local_private_key(local_static.private.as_ref())
        .remote_public_key(remote_static_pubkey)
        .build_initiator()
        .map_err(ZeroError::Handshake)
}

/// Builds the responder state for a Noise IK handshake.
pub fn build_responder(local_static: &StaticKeypair) -> Result<HandshakeState, ZeroError> {
    let params = NOISE_PARAMS.parse().map_err(ZeroError::Handshake)?;
    Builder::new(params)
        .local_private_key(local_static.private.as_ref())
        .build_responder()
        .map_err(ZeroError::Handshake)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        let alice_static = StaticKeypair::generate();
        let bob_static = StaticKeypair::generate();

        let mut alice = build_initiator(&alice_static, &bob_static.public).unwrap();
        let mut bob = build_responder(&bob_static).unwrap();

        let mut buf = [0u8; 1024];

        // Alice writes first message
        let len = alice.write_message(&[], &mut buf).unwrap();

        // Bob reads it
        let mut read_buf = [0u8; 1024];
        bob.read_message(&buf[..len], &mut read_buf).unwrap();

        // Bob writes second message
        let len = bob.write_message(&[], &mut buf).unwrap();

        // Alice reads it
        alice.read_message(&buf[..len], &mut read_buf).unwrap();

        assert!(alice.into_transport_mode().is_ok());
        assert!(bob.into_transport_mode().is_ok());
    }
}
