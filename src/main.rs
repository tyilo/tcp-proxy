mod ssl;

use std::{io::Write, pin::Pin, sync::Arc};

use anyhow::Result;
use clap::Parser;
use httparse::{
    Error::TooManyHeaders,
    Status::{Complete, Partial},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn log_data_read(args: &Args, i: usize, arrow: &str, data_read: &[u8]) {
    if data_read.is_empty() {
        return;
    }
    println!("[{i}] {arrow} {} bytes", data_read.len());
    if args.show_data {
        println!("{}", String::from_utf8_lossy(data_read));
    }
}

fn log_data_read_incoming(args: &Args, i: usize, data_read: &[u8]) {
    log_data_read(args, i, "==>", data_read)
}

fn log_data_read_outgoing(args: &Args, i: usize, data_read: &[u8]) {
    log_data_read(args, i, "<==", data_read)
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
) -> Result<Option<(usize, RequestHeaders)>, httparse::Error> {
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
        Err(e) => Err(e),
    }
}

async fn handle_http(
    args: &Args,
    i: usize,
    incoming_stream: &mut AsyncStream,
    outgoing_stream: &mut AsyncStream,
) -> Result<()> {
    let mut request_buf = vec![];
    let (header_size, mut headers) = loop {
        let n = incoming_stream.read_buf(&mut request_buf).await?;
        log_data_read_incoming(args, i, &request_buf[request_buf.len() - n..]);

        match parse_http_request_headers(&request_buf, 16) {
            Ok(headers) => {
                if let Some((header_size, headers)) = headers {
                    break (header_size, headers);
                }
            }
            Err(e) => {
                println!("[{i}] Error reading HTTP header ({e}), not modifying data");
                outgoing_stream.write_all(&request_buf).await?;
                return Ok(());
            }
        }
    };

    println!("[{i}] ==> HTTP header read");

    let mut headers_changed = false;
    for header in headers.headers.iter_mut() {
        if header.name.eq_ignore_ascii_case("host") {
            println!(
                "[{i}] Rewrote host header from {} to {}",
                String::from_utf8_lossy(header.value),
                args.hostname
            );
            header.value = args.hostname.as_bytes();
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

async fn handle_client(
    args: &Args,
    i: usize,
    incoming_stream: TcpStream,
    ssl_acceptor: Option<Arc<ssl::Acceptor>>,
) -> Result<()> {
    println!("[{}] === Handling connection ===", i);

    let outgoing_stream = TcpStream::connect((&*args.hostname, args.host_port())).await?;

    let mut outgoing_stream: AsyncStream = if args.ssl {
        let stream = ssl::wrap_ssl_client(args, outgoing_stream).await?;
        Box::pin(stream)
    } else {
        Box::pin(outgoing_stream)
    };

    let mut incoming_stream: AsyncStream = match ssl_acceptor {
        Some(ssl_acceptor) => {
            let stream = ssl::wrap_ssl_server(incoming_stream, &ssl_acceptor).await?;
            Box::pin(stream)
        }
        None => Box::pin(incoming_stream),
    };

    if args.rewrite_host_header {
        handle_http(args, i, &mut incoming_stream, &mut outgoing_stream).await?;
    }

    let mut incoming_buf = vec![0; 1 << 16];
    let mut outgoing_buf = vec![0; 1 << 16];
    loop {
        tokio::select! {
            n = incoming_stream.read(&mut incoming_buf) => {
                let n = n?;
                let data = &incoming_buf[..n];
                log_data_read_incoming(args, i, data);
                outgoing_stream.write_all(data).await?;
                if n == 0 {
                    break;
                }
            }
            n = outgoing_stream.read(&mut outgoing_buf) => {
                let n = n?;
                let data = &outgoing_buf[..n];
                log_data_read_outgoing(args, i, data);
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

#[derive(Parser)]
struct Args {
    hostname: String,

    #[arg(long)]
    ssl: bool,

    #[arg(long)]
    ssl_server: bool,

    #[arg(long, default_value = "7777")]
    listen_port: u16,

    #[arg(long)]
    host_port: Option<u16>,

    #[arg(long)]
    show_data: bool,

    #[arg(long)]
    rewrite_host_header: bool,
}

impl Args {
    fn host_port(&self) -> u16 {
        self.host_port
            .unwrap_or({ if self.ssl { 443 } else { 80 } })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arc::new(Args::parse());

    let ip_str = "0.0.0.0";
    let listener = TcpListener::bind((ip_str, args.listen_port)).await?;

    let ssl_acceptor = if args.ssl_server {
        Some(Arc::new(ssl::generate_acceptor()))
    } else {
        None
    };

    println!("Listening on {}:{}", ip_str, args.listen_port);
    println!("Forwarding to {}:{}", args.hostname, args.host_port());

    let mut i: usize = usize::MAX;
    loop {
        i = i.wrapping_add(1);
        let (socket, _) = listener.accept().await?;
        let args = args.clone();

        let ssl_acceptor = ssl_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(&args, i, socket, ssl_acceptor).await {
                eprintln!("[{i}] Got error: {:?}", e);
            }
        });
    }
}
