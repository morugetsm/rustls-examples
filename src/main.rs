// openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout my.key -out my.pem

// cargo run -- server
// cargo run -- client

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
};

use rustls::{client::danger::ServerCertVerifier, RootCertStore};

const PEM_FILE: &str = "my.pem";
const KEY_FILE: &str = "my.key";
const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const PORT: u16 = 4443;

fn main() {
    let mut args = std::env::args();

    match args.nth(1) {
        Some(arg) => match &arg.to_lowercase()[..] {
            "server" => server(),
            "client" => client(),
            _ => eprintln!("unknown mode '{}'", arg),
        },
        None => println!("bye"),
    }
}

fn server() {
    println!("SERVER");

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(PEM_FILE).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(KEY_FILE).unwrap()))
            .unwrap()
            .unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();

    config.alpn_protocols.push(b"http/1.1".to_vec());

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), PORT)).unwrap();

    loop {
        let (mut stream, _) = listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(Arc::new(config.clone())).unwrap();
        // Handshake
        conn.complete_io(&mut stream).unwrap();

        // Read
        if conn.wants_read() {
            conn.read_tls(&mut stream).unwrap();
            conn.process_new_packets().unwrap();
        }
        let mut buf = String::new();
        let _ = conn.reader().read_to_string(&mut buf);
        println!("Received message from client: {}", buf);

        // Write
        conn.writer()
            .write_all(
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Type: text/plain\r\n",
                    "\r\n",
                    "Response\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

        // Close
        conn.send_close_notify();
        conn.complete_io(&mut stream).unwrap();
    }
}

fn client() {
    println!("CLIENT");

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoServerCert::new()));

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = rustls::pki_types::ServerName::IpAddress(HOST.into());
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(SocketAddr::new(HOST, PORT)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n",
            "Request\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    std::io::stdout().write_all(&plaintext).unwrap();
}

#[derive(Debug)]
struct NoServerCert {}

impl NoServerCert {
    fn new() -> Self {
        Self {}
    }
}

impl ServerCertVerifier for NoServerCert {
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Vec::from([
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ])
    }

    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
}
