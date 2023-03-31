use anyhow::Result;
use httparse::Error::TooManyHeaders;
use httparse::Status::{Complete, Partial};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::Write;
use std::pin::Pin;
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

fn log_data_read(opt: &Opt, i: usize, arrow: &str, data_read: &[u8]) {
    if data_read.is_empty() {
        return;
    }
    println!("[{i}] {arrow} {} bytes", data_read.len());
    if opt.show_data {
        println!("{}", String::from_utf8_lossy(data_read));
    }
}

fn log_data_read_incoming(opt: &Opt, i: usize, data_read: &[u8]) {
    log_data_read(opt, i, "==>", data_read)
}

fn log_data_read_outgoing(opt: &Opt, i: usize, data_read: &[u8]) {
    log_data_read(opt, i, "<==", data_read)
}

struct RequestLine<'a> {
    method: &'a str,
    path: &'a str,
    version: u8,
}

impl<'a> RequestLine<'a> {
    fn new<'b>(request: httparse::Request<'b, 'a>) -> Self {
        Self {
            method: request.method.unwrap(),
            path: request.path.unwrap(),
            version: request.version.unwrap(),
        }
    }
}

struct RequestHeaders<'a> {
    request_line: RequestLine<'a>,
    headers: Vec<httparse::Header<'a>>,
}

impl<'a> RequestHeaders<'a> {
    fn new(request_line: RequestLine<'a>, mut headers: Vec<httparse::Header<'a>>) -> Self {
        while headers.last().map(|h| h.name.is_empty()).unwrap_or(false) {
            headers.pop();
        }

        Self {
            request_line,
            headers,
        }
    }
}

fn parse_http_request_headers(
    buffer: &[u8],
    max_headers: usize,
) -> Result<Option<(usize, RequestHeaders)>> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buffer) {
        Ok(Complete(n)) => {
            let request_line = RequestLine::new(request);
            let request_headers = RequestHeaders::new(request_line, headers);
            Ok(Some((n, request_headers)))
        }
        Ok(Partial) => Ok(None),
        Err(TooManyHeaders) => parse_http_request_headers(buffer, max_headers * 2),
        Err(e) => Err(e.into()),
    }
}

async fn handle_http(
    opt: &Opt,
    i: usize,
    incoming_stream: &mut TcpStream,
    outgoing_stream: &mut AsyncStream,
) -> Result<()> {
    let mut request_buf = vec![];
    let (header_size, mut headers) = loop {
        let n = incoming_stream.read_buf(&mut request_buf).await?;
        log_data_read_incoming(opt, i, &request_buf[request_buf.len() - n..]);

        let headers = parse_http_request_headers(&request_buf, 16)?;
        if let Some((header_size, headers)) = headers {
            break (header_size, headers);
        }
    };

    println!("[{i}] ==> HTTP header read");

    let mut headers_changed = false;
    for header in headers.headers.iter_mut() {
        if header.name.to_ascii_lowercase() == "host" {
            println!(
                "[{i}] Rewrote host header from {} to {}",
                String::from_utf8_lossy(header.value),
                opt.hostname
            );
            header.value = opt.hostname.as_bytes();
            headers_changed = true;
        }
    }

    if headers_changed {
        let mut headers_buf = vec![];
        let RequestLine {
            method,
            path,
            version,
        } = headers.request_line;
        writeln!(&mut headers_buf, "{method} {path} HTTP/1.{version}\r")?;
        for header in headers.headers {
            write!(&mut headers_buf, "{}: ", header.name)?;
            headers_buf.extend(header.value);
            writeln!(&mut headers_buf, "\r")?;
        }
        writeln!(&mut headers_buf, "\r")?;
        outgoing_stream.write_all(&headers_buf).await?;

        outgoing_stream
            .write_all(&request_buf[header_size..])
            .await?;
    } else {
        outgoing_stream.write_all(&request_buf[..]).await?;
    }

    Ok(())
}

trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

type AsyncStream = Pin<Box<dyn AsyncReadWrite + Send>>;

fn wrap_ssl<S: AsyncRead + AsyncWrite>(opt: &Opt, stream: S) -> SslStream<S> {
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

async fn handle_client(opt: &Opt, i: usize, mut incoming_stream: TcpStream) -> Result<()> {
    println!("[{}] === Handling connection ===", i);

    let outgoing_stream = TcpStream::connect((&*opt.hostname, opt.host_port())).await?;
    let mut outgoing_stream: AsyncStream = if opt.ssl {
        let mut stream = wrap_ssl(opt, outgoing_stream);
        Pin::new(&mut stream).connect().await.unwrap();
        Box::pin(stream)
    } else {
        Box::pin(outgoing_stream)
    };

    if opt.rewrite_host_header {
        handle_http(opt, i, &mut incoming_stream, &mut outgoing_stream).await?;
    }

    let mut incoming_buf = vec![0; 1 << 16];
    let mut outgoing_buf = vec![0; 1 << 16];
    loop {
        tokio::select! {
            n = incoming_stream.read(&mut incoming_buf) => {
                let n = n?;
                let data = &incoming_buf[..n];
                log_data_read_incoming(opt, i, data);
                outgoing_stream.write_all(data).await?;
                if n == 0 {
                    break;
                }
            }
            n = outgoing_stream.read(&mut outgoing_buf) => {
                let n = n?;
                let data = &outgoing_buf[..n];
                log_data_read_outgoing(opt, i, data);
                incoming_stream.write_all(data).await?;
                if n == 0 {
                    break;
                }
            },
        };
    }

    println!("[{}] === Done ===", i);

    Ok(())
}

#[derive(StructOpt, Clone)]
struct Opt {
    hostname: String,

    #[structopt(long)]
    ssl: bool,

    #[structopt(long, default_value = "7777")]
    listen_port: u16,

    #[structopt(long)]
    host_port: Option<u16>,

    #[structopt(long)]
    show_data: bool,

    #[structopt(long)]
    rewrite_host_header: bool,
}

impl Opt {
    fn host_port(&self) -> u16 {
        self.host_port.unwrap_or(if self.ssl { 443 } else { 80 })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    let ip_str = "0.0.0.0";
    let listener = TcpListener::bind((ip_str, opt.listen_port)).await?;

    println!("Listening on {}:{}", ip_str, opt.listen_port);
    println!("Forwarding to {}:{}", opt.hostname, opt.host_port());

    let mut i: usize = usize::MAX;
    loop {
        i = i.wrapping_add(1);
        let (socket, _) = listener.accept().await?;
        let opt = opt.clone();
        tokio::spawn(async move {
            handle_client(&opt, i, socket).await.unwrap();
        });
    }
}
