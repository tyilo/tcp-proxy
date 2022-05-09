use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io;
use std::pin::Pin;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

async fn handle_read<W: AsyncWriteExt + std::marker::Unpin>(
    opt: &Opt,
    i: usize,
    arrow: &str,
    read_res: io::Result<usize>,
    buf: &[u8],
    dst: &mut W,
) -> io::Result<usize> {
    let n = read_res?;
    if n > 0 {
        let data_read = &buf[..n];
        println!("[{}] {} {} bytes", i, arrow, n);
        if opt.data {
            println!("{}", String::from_utf8_lossy(data_read));
        }
        dst.write_all(data_read).await?;
    };

    Ok(n)
}

async fn handle_client(opt: &Opt, i: usize, mut incoming_stream: TcpStream) -> io::Result<()> {
    println!("[{}] === Handling connection ===", i);
    println!();

    let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    connector_builder.set_verify(SslVerifyMode::NONE);
    let ssl = connector_builder
        .build()
        .configure()
        .unwrap()
        .into_ssl(&*opt.hostname)
        .unwrap();

    let outgoing_stream = TcpStream::connect((&*opt.hostname, opt.host_port)).await?;

    let mut outgoing_stream = SslStream::new(ssl, outgoing_stream).unwrap();
    Pin::new(&mut outgoing_stream).connect().await.unwrap();

    let mut incoming_buf = vec![0; 1024 * 1024];
    let mut outgoing_buf = vec![0; 1024 * 1024];
    loop {
        tokio::select! {
            n = incoming_stream.read(&mut incoming_buf) => {
                handle_read(opt, i, "==>", n, &incoming_buf, &mut outgoing_stream).await?;
            },
            res = outgoing_stream.read(&mut outgoing_buf) => {
                let n = handle_read(opt, i, "<==", res, &outgoing_buf, &mut incoming_stream).await?;
                if n == 0 {
                    break;
                }
            },
        };
    }

    println!();
    println!("[{}] === Done ===", i);

    Ok(())
}

#[derive(StructOpt, Clone)]
struct Opt {
    hostname: String,

    #[structopt(long, default_value = "7777")]
    listen_port: u16,

    #[structopt(long, default_value = "443")]
    host_port: u16,

    #[structopt(long)]
    data: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opt = Opt::from_args();

    let ip_str = "0.0.0.0";
    let listener = TcpListener::bind((ip_str, opt.listen_port)).await?;

    println!("Listening on {}:{}", ip_str, opt.listen_port);

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
