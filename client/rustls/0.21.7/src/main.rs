use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time;

use rustls::RootCertStore;

fn get_root_store(path: &String) -> RootCertStore {
    let mut reader = BufReader::new(std::fs::File::open(path).unwrap());

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        &rustls_pemfile::certs(&mut reader).expect("failed to read cert"),
    );

    root_store
}

fn make_config(
    cert_path: &String,
    ciphersuite: &rustls::SupportedCipherSuite,
) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .with_cipher_suites(&[*ciphersuite])
        .with_kx_groups(&rustls::ALL_KX_GROUPS)
        .with_protocol_versions(&rustls::ALL_VERSIONS)
        .unwrap()
        .with_root_certificates(get_root_store(cert_path))
        .with_no_client_auth()
}

fn bench_handshake(
    cert_path: &String,
    ciphersuite: &rustls::SupportedCipherSuite,
    ip: &String,
) -> f32 {
    let cfg = Arc::new(make_config(cert_path, ciphersuite));

    let sn = rustls::client::ServerName::try_from(ip.as_str()).unwrap();
    let mut conn = rustls::ClientConnection::new(cfg.clone(), sn).unwrap();
    let mut sock = TcpStream::connect(format!("{ip}:443")).unwrap();

    let start = time::Instant::now();
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    stream.flush().unwrap();
    start.elapsed().as_secs_f32()
}

static CIPHERSUITES: [rustls::SupportedCipherSuite; 6] = [
    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 3 {
        panic!("not enough args: <ip> <cert>")
    }

    let rounds = std::env::var("POINTS")
        .unwrap_or("1".to_string())
        .parse::<u32>()
        .unwrap();

    print!("idx");
    for ciphersuite in &CIPHERSUITES {
        print!(",{:?}", ciphersuite.suite());
    }
    print!("\n");

    for i in 0..rounds {
        print!("{i}");
        for ciphersuite in &CIPHERSUITES {
            print!(",{:.}", bench_handshake(&args[2], ciphersuite, &args[1],));
        }
        print!("\n");
    }
}
