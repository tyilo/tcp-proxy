use tokio::io::{AsyncRead, AsyncWrite};
use tokio_native_tls::{
    TlsAcceptor, TlsConnector, TlsStream,
    native_tls::{self, Identity},
};

use crate::{Args, Result};

pub type Acceptor = TlsAcceptor;

pub(crate) async fn wrap_ssl_client<S: AsyncRead + AsyncWrite + Unpin>(
    args: &Args,
    stream: S,
) -> Result<TlsStream<S>> {
    let connector: TlsConnector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .min_protocol_version(None)
        .build()
        .unwrap()
        .into();

    Ok(connector.connect(&args.hostname, stream).await?)
}

pub(crate) async fn wrap_ssl_server<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    acceptor: &TlsAcceptor,
) -> Result<TlsStream<S>> {
    Ok(acceptor.accept(stream).await?)
}

pub(crate) fn generate_acceptor() -> TlsAcceptor {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();

    let identity =
        Identity::from_pkcs8(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes()).unwrap();

    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(None)
        .build()
        .unwrap();
    acceptor.into()
}
