use rcgen::{CertifiedKey, generate_simple_self_signed};
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
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![]).unwrap();

    let identity =
        Identity::from_pkcs8(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes()).unwrap();

    let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
    acceptor.into()
}
