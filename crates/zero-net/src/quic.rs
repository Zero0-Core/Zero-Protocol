use quinn::{Endpoint, ServerConfig, ClientConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::NetError;

#[derive(Debug)]
struct DummyVerifier;
impl rustls::client::danger::ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

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
        let mut endpoint = Endpoint::server(server_config, addr).map_err(NetError::Io)?;
        
        let client_config = ClientConfig::new(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_verifier(Arc::new(DummyVerifier))
                .with_no_client_auth()
        ));
        endpoint.set_default_client_config(client_config);
        
        Ok(Self { endpoint })
    }

    pub async fn send_quic_packet(&self, target: SocketAddr, packet: &[u8]) -> Result<(), NetError> {
        let conn = self.endpoint.connect(target, "zero.protocol")
            .map_err(|_| NetError::TransportUnavailable)?
            .await
            .map_err(|_| NetError::TransportUnavailable)?;
        
        let mut send_stream = conn.open_uni().await
            .map_err(|_| NetError::TransportUnavailable)?;
            
        use tokio::io::AsyncWriteExt;
        send_stream.write_all(packet).await
            .map_err(|e| NetError::Io(e))?;
        send_stream.finish().await
            .map_err(|e| NetError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
            
        Ok(())
    }
}
