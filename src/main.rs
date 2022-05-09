use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use structopt::StructOpt;

fn copy_buf<R: Read, W: Write>(
    i: usize,
    arrow: &str,
    src: &mut R,
    dst: &mut W,
    buf: &mut [u8],
) -> Option<usize> {
    let n = match src.read(buf) {
        Ok(n) => Some(n),
        Err(e) => match e.kind() {
            ErrorKind::WouldBlock => None,
            _ => panic!("Error: {:?}", e),
        },
    };
    if let Some(n) = n {
        if n > 0 {
            println!("[{}] {} {} bytes", i, arrow, n);
            println!("[{}] {}", i, String::from_utf8_lossy(&buf[..n]));
            dst.write_all(&buf[..n]).unwrap();
        }
    };
    n
}

fn handle_client(opt: &Opt, i: usize, mut incoming_stream: TcpStream) {
    println!("[{}] === Handling connection ===", i);
    println!();

    let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    connector_builder.set_verify(SslVerifyMode::NONE);
    let connector = connector_builder.build();

    let stream = TcpStream::connect((&*opt.hostname, opt.host_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let mut stream = connector.connect(&opt.hostname, stream).unwrap();

    incoming_stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n1 = copy_buf(i, "==>", &mut incoming_stream, &mut stream, &mut buf);
        let n2 = copy_buf(i, "<==", &mut stream, &mut incoming_stream, &mut buf);

        //println!("n1={:?}, n2={:?}", n1, n2);

        if n1 == Some(0) && n2 == Some(0) {
            break;
        }

        if n1 == None && n2 == Some(0) {
            break;
        }
    }

    println!();
    println!("[{}] === Done ===", i);
}

#[derive(StructOpt, Clone)]
struct Opt {
    hostname: String,

    #[structopt(long, default_value = "7777")]
    listen_port: u16,

    #[structopt(long, default_value = "443")]
    host_port: u16,
}

fn main() {
    let opt = Opt::from_args();

    let ip_str = "0.0.0.0";
    let listener = TcpListener::bind((ip_str, opt.listen_port)).unwrap();

    println!("Listening on {}:{}", ip_str, opt.listen_port);

    for (i, stream) in listener.incoming().enumerate() {
        let stream = stream.unwrap();
        let opt = opt.clone();
        thread::spawn(move || {
            handle_client(&opt, i, stream);
        });
    }
}
