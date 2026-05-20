use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use crate::NetError;

pub struct QuicManager {
    pub endpoint: Endpoint,
}

impl QuicManager {
    pub fn new(addr: SocketAddr) -> Result<Self, NetError> {
        // Generate ephemeral self-signed certificates for P2P QUIC connection.
        // In Zero Protocol, identity is verified INSIDE the QUIC tunnel via the Noise IK handshake,
        // so the outer TLS certificate is strictly for Opportunistic Encryption & PFS.
        let subject_alt_names = vec!["zero.protocol".to_string()];
        
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|_| NetError::TransportUnavailable)?;
            
        let cert_der = cert.serialize_der().map_err(|_| NetError::TransportUnavailable)?;
        let priv_key = cert.serialize_private_key_der();

        let cert_chain = vec![rustls_pki_types::CertificateDer::from(cert_der)];
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(priv_key));

        // Use quinn's built-in method with the strict types
        let server_config = ServerConfig::with_single_cert(
            cert_chain,
            key_der,
        ).map_err(|_| NetError::TransportUnavailable)?;

        // Create the endpoint allowing both incoming and outgoing connections
        let endpoint = Endpoint::server(server_config, addr).map_err(NetError::Io)?;
        
        Ok(Self { endpoint })
    }
}
