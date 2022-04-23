// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use rccheck::{ed25519_certgen::Ed25519, Certifiable};
use std::{net::SocketAddr, sync::Arc};
use tonic::transport::{Channel, ClientTlsConfig, Server, ServerTlsConfig};

static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[&webpki::ED25519];

#[derive(Clone, Debug)]
pub struct CertVerifier(pub(crate) String);

/// A `ClientCertVerifier` that will ensure that every client provides a valid, expected
/// certificate, without any name checking.
impl rustls::server::ClientCertVerifier for CertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(true)
    }

    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        // Since we're relying on self-signed certificates and not on CAs, continue the handshake
        // without passing a list of CA DNs
        Some(rustls::DistinguishedNames::new())
    }

    // Verifies this is a valid certificate self-signed by the public key we expect(in PSK)
    // 1. we check the equality of the certificate's public key with the key we expect
    // 2. we prepare arguments for webpki's certificate verification (following the rustls implementation)
    //    placing the public key at the root of the certificate chain (as it should be for a self-signed certificate)
    // 3. we call webpki's certificate verification
    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        // Step 1: Check this matches the key we expect
        // let cert = X509Certificate::from_der(&end_entity.0[..])
        //     .map_err(|_| rustls::Error::InvalidCertificateEncoding)?;
        // let spki = cert.1.public_key().clone();
        // if &spki != self.borrow_spki() {
        //     return Err(rustls::Error::InvalidCertificateData(format!(
        //         "invalid peer certificate: received {:?} instead of expected {:?}",
        //         spki,
        //         self.borrow_spki()
        //     )));
        // }
        println!("HELLO");

        // We now check we're receiving correctly signed data with the expected key
        // Step 2: prepare arguments
        let (cert, chain, trustroots) = prepare_for_self_signed(end_entity, intermediates)?;
        let now = webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;

        // Step 3: call verification from webpki
        let cert = cert
            .verify_is_valid_tls_client_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TlsClientTrustAnchors(&trustroots),
                &chain,
                now,
            )
            .map_err(pki_error)
            .map(|_| cert)?;

        // Ensure the cert is valid for the network name
        let dns_nameref = webpki::DnsNameRef::try_from_ascii_str(&self.0)
            .map_err(|_| rustls::Error::UnsupportedNameType)?;
        cert.verify_is_valid_for_dns_name(dns_nameref)
            .map_err(pki_error)
            .map(|_| rustls::server::ClientCertVerified::assertion())
        // Ok(rustls::server::ClientCertVerified::assertion())
    }
}

impl<'a> rustls::client::ServerCertVerifier for CertVerifier {
    // Verifies this is a valid certificate self-signed by the public key we expect(in PSK)
    // 1. we check the equality of the certificate's public key with the key we expect
    // 2. we prepare arguments for webpki's certificate verification (following the rustls implementation)
    //    placing the public key at the root of the certificate chain (as it should be for a self-signed certificate)
    // 3. we call webpki's certificate verification
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // Step 1: Check this matches the key we expect
        // let cert = X509Certificate::from_der(&end_entity.0[..])
        //     .map_err(|_| rustls::Error::InvalidCertificateEncoding)?;
        // let spki = cert.1.public_key().clone();
        // if &spki != self.borrow_spki() {
        //     return Err(rustls::Error::InvalidCertificateData(format!(
        //         "invalid peer certificate: received {:?} instead of expected {:?}",
        //         spki,
        //         self.borrow_spki()
        //     )));
        // }

        // Then we check this is actually a valid self-signed certificate with matching name
        // Step 2: prepare arguments
        let (cert, chain, trustroots) = prepare_for_self_signed(end_entity, intermediates)?;
        let webpki_now =
            webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;

        println!("CLIENT: server dns name: {:?}", server_name);
        let dns_nameref = match server_name {
            rustls::ServerName::DnsName(dns_name) => {
                webpki::DnsNameRef::try_from_ascii_str(dns_name.as_ref())
                    .map_err(|_| rustls::Error::UnsupportedNameType)?
            }
            _ => return Err(rustls::Error::UnsupportedNameType),
        };
        let expected_dns_nameref = webpki::DnsNameRef::try_from_ascii_str(&self.0)
            .map_err(|_| rustls::Error::UnsupportedNameType)?;
        if dns_nameref.as_ref() != expected_dns_nameref.as_ref() {
            return Err(rustls::Error::UnsupportedNameType);
        }

        // Step 3: call verification from webpki
        let cert = cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TlsServerTrustAnchors(&trustroots),
                &chain,
                webpki_now,
            )
            .map_err(pki_error)
            .map(|_| cert)?;

        cert.verify_is_valid_for_dns_name(dns_nameref)
            .map_err(pki_error)
            .map(|_| rustls::client::ServerCertVerified::assertion())
        // Ok(rustls::client::ServerCertVerified::assertion())
    }
}

type CertChainAndRoots<'a> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'a>>,
);

// This prepares arguments for webpki, including a trust anchor which is the end entity of the certificate
// (which embodies a self-signed certificate by definition)
fn prepare_for_self_signed<'a>(
    end_entity: &'a rustls::Certificate,
    intermediates: &'a [rustls::Certificate],
) -> Result<CertChainAndRoots<'a>, rustls::Error> {
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;

    let intermediates: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

    // reinterpret the certificate as a root, materializing the self-signed policy
    let root = webpki::TrustAnchor::try_from_cert_der(end_entity.0.as_ref()).map_err(pki_error)?;

    Ok((cert, intermediates, vec![root]))
}

fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => rustls::Error::InvalidCertificateEncoding,
        InvalidSignatureForPublicKey => rustls::Error::InvalidCertificateSignature,
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            rustls::Error::InvalidCertificateSignatureType
        }
        e => rustls::Error::InvalidCertificateData(format!("invalid peer certificate: {e}")),
    }
}

/// This type provides serialized bytes for a private key.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
// TODO: move this to rccheck?
trait ToPKCS8 {
    fn to_pkcs8_bytes(&self) -> Vec<u8>;
}

impl ToPKCS8 for ed25519_dalek::Keypair {
    fn to_pkcs8_bytes(&self) -> Vec<u8> {
        use ed25519::pkcs8::EncodePrivateKey;

        let kpb = ed25519::KeypairBytes {
            secret_key: self.secret.to_bytes(),
            public_key: None,
        };
        let pkcs8 = kpb.to_pkcs8_der().unwrap();
        pkcs8.as_ref().to_vec()
    }
}

#[derive(Clone)]
pub struct Config {
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
    server_name: String,
}

impl Config {
    pub fn new(keypair: ed25519_dalek::Keypair, server_name: &str) -> Result<Self> {
        let server_name = server_name.to_owned();
        let cert_verifier = Arc::new(CertVerifier(server_name.clone()));
        let (certificate, pkcs8_der) = Self::generate_cert(keypair, &server_name);

        let server_config = Self::server_config(
            certificate.clone(),
            pkcs8_der.clone(),
            cert_verifier.clone(),
        )?;
        let client_config = Self::client_config(certificate, pkcs8_der, cert_verifier)?;

        Ok(Self {
            client: client_config,
            server: server_config,
            server_name,
        })
    }

    pub fn random(server_name: &str) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let keypair = ed25519_dalek::Keypair::generate(&mut rng);

        Self::new(keypair, server_name)
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn rustls_client_config(&self) -> &rustls::ClientConfig {
        &self.client
    }

    pub fn rustls_server_config(&self) -> &rustls::ServerConfig {
        &self.server
    }

    pub fn tonic_client_tls_config(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .rustls_client_config(self.client.clone())
            .domain_name(self.server_name())
    }

    pub fn tonic_server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new().rustls_server_config(self.server.clone())
    }

    pub fn channel(&self, addr: SocketAddr) -> Result<Channel> {
        let tls = self.tonic_client_tls_config();

        let url = format!("https://{}", addr);
        let channel = Channel::from_shared(url)?.tls_config(tls)?.connect_lazy();
        Ok(channel)
    }

    pub fn server_builder(&self) -> Result<Server> {
        let tls = self.tonic_server_tls_config();
        let server = Server::builder().tls_config(tls)?;
        Ok(server)
    }

    fn generate_cert(
        keypair: ed25519_dalek::Keypair,
        server_name: &str,
    ) -> (rustls::Certificate, rustls::PrivateKey) {
        let key_der = rustls::PrivateKey(keypair.to_pkcs8_bytes());
        let certificate =
            Ed25519::keypair_to_certificate(vec![server_name.to_owned()], keypair).unwrap();
        (certificate, key_der)
    }

    fn server_config(
        cert: rustls::Certificate,
        pkcs8_der: rustls::PrivateKey,
        cert_verifier: Arc<CertVerifier>,
    ) -> Result<rustls::ServerConfig> {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(cert_verifier)
            .with_single_cert(vec![cert], pkcs8_der)?;
        server_crypto.alpn_protocols = vec![b"h2".to_vec()];
        Ok(server_crypto)
    }

    fn client_config(
        cert: rustls::Certificate,
        pkcs8_der: rustls::PrivateKey,
        cert_verifier: Arc<CertVerifier>,
    ) -> Result<rustls::ClientConfig> {
        // setup certificates
        let mut roots = rustls::RootCertStore::empty();
        roots.add(&cert).unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(cert_verifier)
            .with_single_cert(vec![cert], pkcs8_der)?;
        client_crypto.alpn_protocols = vec![b"h2".to_vec()];

        Ok(client_crypto)
    }
}
