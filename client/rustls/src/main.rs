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

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "127.0.0.1".try_into().unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("127.0.0.1:443").unwrap();

    // init and finish handshake
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    stream.flush().unwrap();

    let ciphersuite = stream.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
}
