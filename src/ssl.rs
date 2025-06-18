use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

use crate::Opt;
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

pub(crate) fn wrap_ssl_client<S: AsyncRead + AsyncWrite>(opt: &Opt, stream: S) -> SslStream<S> {
    let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    connector_builder.set_verify(SslVerifyMode::NONE);
    let ssl = connector_builder
        .build()
        .configure()
        .unwrap()
        .into_ssl(&opt.hostname)
        .unwrap();

    SslStream::new(ssl, stream).unwrap()
}

pub(crate) fn wrap_ssl_server<S: AsyncRead + AsyncWrite>(
    stream: S,
    acceptor: &SslAcceptor,
) -> SslStream<S> {
    let ssl = Ssl::new(acceptor.context()).unwrap();
    SslStream::new(ssl, stream).unwrap()
}

pub(crate) fn generate_acceptor() -> SslAcceptor {
    let cert = generate_simple_self_signed(vec![]).unwrap();

    let private_key =
        PKey::private_key_from_pem(cert.serialize_private_key_pem().as_bytes()).unwrap();
    let certificate = X509::from_pem(cert.serialize_pem().unwrap().as_bytes()).unwrap();

    let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor_builder.set_private_key(&private_key).unwrap();
    acceptor_builder.set_certificate(&certificate).unwrap();

    acceptor_builder.check_private_key().unwrap();

    acceptor_builder.build()
}
