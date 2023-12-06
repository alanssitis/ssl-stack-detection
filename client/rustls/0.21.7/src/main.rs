use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{client, RootCertStore};

fn get_root_store(path: &String) -> RootCertStore {
    let mut reader =
        BufReader::new(std::fs::File::open(path).expect("cannot open cert"));

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        &rustls_pemfile::certs(&mut reader).expect("failed to read cert"),
    );

    root_store
}

fn one_time_handshake(
    address: &String,
    conn: &mut client::ClientConnection,
) -> std::time::Duration {
    let start = std::time::Instant::now();
    let mut sock = TcpStream::connect(address).unwrap();
    let mut stream = rustls::Stream::new(conn, &mut sock);
    stream.flush().unwrap();
    start.elapsed()
}

fn time_handshake(
    address: &String,
    conn: &mut client::ClientConnection,
    count: u32,
) -> std::time::Duration {
    let mut duration = std::time::Duration::ZERO;

    for _ in 0..count {
        duration += one_time_handshake(address, conn);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    duration / count
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 4 {
        panic!("not enough args: <ip> <cert> <iter>")
    }

    let root_store = get_root_store(&args[2]);
    let ip = &args[1];
    let server_name =
        rustls::client::ServerName::try_from(ip.as_str()).unwrap();

    for cs in &[
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ] {
        println!("Ciphersuite: {:?}", cs.suite());

        let config = rustls::ClientConfig::builder()
            .with_cipher_suites(&[*cs])
            .with_kx_groups(&rustls::ALL_KX_GROUPS)
            .with_protocol_versions(&rustls::ALL_VERSIONS)
            .unwrap()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();

        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            server_name.clone(),
        )
        .unwrap();

        println!(
            "Average time taken: {:?}",
            time_handshake(
                &format!("{ip}:443"),
                &mut conn,
                args[3].parse().unwrap()
            )
        );
    }
}
