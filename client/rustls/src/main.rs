use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::RootCertStore;

fn main() {
    let mut reader = BufReader::new(
        std::fs::File::open("../../go_server/server.crt")
            .expect("cannot open cert"),
    );

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        rustls_pemfile::certs(&mut reader).map(|r| r.unwrap()),
    );
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];

    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .expect("failed smtg")
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let server_name = "127.0.0.1".try_into().unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

    // init and finish handshake
    let start = std::time::Instant::now();
    let mut sock = TcpStream::connect("127.0.0.1:443").unwrap();
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    stream.flush().unwrap();
    let duration = start.elapsed();

    println!("Handshake took {:?}", duration);
    println!(
        "Current ciphersuite: {:?}",
        stream.conn.negotiated_cipher_suite().unwrap().suite()
    );
}
