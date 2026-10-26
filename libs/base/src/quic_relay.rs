use anyhow::{bail, Context as _, Result};
use hbb_common::{
    config::Config,
    rand,
    sha2::{Digest, Sha256},
    socket_client,
    tcp::FramedStream,
    Stream,
};
use quinn::{
    crypto::rustls::QuicClientConfig,
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, Endpoint, RecvStream, Runtime, SendStream, UdpPoller,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde_derive::Deserialize;
use std::{
    convert::{TryFrom, TryInto},
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    task::JoinHandle,
};

const CONFIG_FILE: &str = "quic-relay.private.json";
const MAX_CONFIG_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayConfig {
    server: String,
    relay: String,
    auth: String,
    server_name: String,
    certificate_sha256: String,
    #[serde(default = "default_hop_interval")]
    hop_interval_seconds: u64,
}

fn default_hop_interval() -> u64 {
    30
}

/// A private configuration beside the executable opts this relay into native QUIC.
/// An absent file or a different relay leaves the original transport untouched.
pub async fn connect_if_configured(relay: &str, timeout_ms: u64) -> Result<Option<Stream>> {
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return Ok(None);
    }
    let path = std::env::current_exe()?.with_file_name(CONFIG_FILE);
    let data = match tokio::fs::read(path).await {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("Cannot read native QUIC relay configuration"),
    };
    let config = parse_config(&data)?;
    if canonical_relay(relay) != canonical_relay(&config.relay) {
        return Ok(None);
    }
    if Config::is_proxy() {
        bail!("Native QUIC relay cannot be combined with the global SOCKS/HTTP proxy");
    }
    connect_config(config, timeout_ms).await.map(Some)
}

/// Used by the transport probe without changing the installed client's configuration.
pub async fn connect_config_file(path: &Path, timeout_ms: u64) -> Result<Stream> {
    let config = parse_config(&tokio::fs::read(path).await?)?;
    connect_config(config, timeout_ms).await
}

fn parse_config(data: &[u8]) -> Result<RelayConfig> {
    if data.len() > MAX_CONFIG_BYTES {
        bail!("Native QUIC relay configuration exceeds 64 KiB");
    }
    // PowerShell can write a UTF-8 BOM when provisioning a private config.
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    let config: RelayConfig =
        serde_json::from_slice(data).context("Invalid native QUIC relay configuration")?;
    if config.auth.is_empty() || config.server_name.is_empty() || config.relay.is_empty() {
        bail!("Native QUIC relay requires authentication, server name and relay address");
    }
    if !(5..=3600).contains(&config.hop_interval_seconds) {
        bail!("QUIC port hopping interval must be between 5 and 3600 seconds");
    }
    parse_server(&config.server)?;
    parse_pin(&config.certificate_sha256)?;
    Ok(config)
}

fn canonical_relay(address: &str) -> String {
    let address = socket_client::check_port(address, 21117);
    match address.parse::<SocketAddr>() {
        Ok(address) => hbb_common::try_into_v4(address).to_string(),
        Err(_) => address.to_ascii_lowercase(),
    }
}

fn parse_server(server: &str) -> Result<(String, Vec<u16>)> {
    let (host, port) = server
        .rsplit_once(':')
        .context("QUIC server requires a port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        bail!("QUIC server host is empty");
    }
    let (first, last) = match port.split_once('-') {
        Some((first, last)) => (first.parse::<u16>()?, last.parse::<u16>()?),
        None => {
            let port = port.parse::<u16>()?;
            (port, port)
        }
    };
    if first == 0 || last < first || u32::from(last) - u32::from(first) >= 32 {
        bail!("QUIC server requires one port or a range of at most 32 ports");
    }
    Ok((host.to_owned(), (first..=last).collect()))
}

fn parse_pin(value: &str) -> Result<[u8; 32]> {
    let value = value.replace(':', "");
    if value.len() != 64 || !value.is_ascii() {
        bail!("QUIC certificate SHA-256 must contain 64 hexadecimal digits");
    }
    let mut pin = [0; 32];
    for (byte, hex) in pin.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let hex = std::str::from_utf8(hex)?;
        *byte = u8::from_str_radix(hex, 16).context("Invalid QUIC certificate SHA-256")?;
    }
    Ok(pin)
}

async fn connect_config(config: RelayConfig, timeout_ms: u64) -> Result<Stream> {
    tokio::time::timeout(Duration::from_millis(timeout_ms), connect_inner(config))
        .await
        .context("Native QUIC relay connection timed out")?
}

async fn connect_inner(config: RelayConfig) -> Result<Stream> {
    let (host, ports) = parse_server(&config.server)?;
    let remote = tokio::net::lookup_host((host.as_str(), ports[0]))
        .await?
        .next()
        .context("QUIC server DNS lookup returned no address")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
            pin: parse_pin(&config.certificate_sha256)?,
            provider,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    let mut bbr = quinn::congestion::BbrConfig::default();
    bbr.initial_window(12_000);
    transport
        .congestion_controller_factory(Arc::new(bbr))
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    client.transport_config(Arc::new(transport));

    let bind: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let socket = Arc::new(HoppingSocket {
        inner: runtime.wrap_udp_socket(socket)?,
        remote,
        initial: (rand::random::<u32>() as usize) % ports.len(),
        ports,
        interval: Duration::from_secs(config.hop_interval_seconds),
        started: Instant::now(),
        last_port: AtomicU16::new(0),
    });
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    endpoint.set_default_client_config(client);
    let local = endpoint.local_addr()?;
    let connection = endpoint.connect(remote, &config.server_name)?.await?;
    let mut session = Session {
        endpoint,
        connection,
        http_driver: None,
        runtime: tokio::runtime::Handle::current(),
    };
    let (mut driver, mut request_sender) =
        h3::client::new(h3_quinn::Connection::new(session.connection.clone())).await?;
    let keep_sender = request_sender.clone();
    session.http_driver = Some(tokio::spawn(async move {
        let _keep_sender = keep_sender;
        let closed = poll_fn(|cx| driver.poll_close(cx)).await;
        log::debug!("Native QUIC control connection closed: {}", closed);
    }));
    let mut authentication = http::HeaderValue::from_str(&config.auth)
        .context("Invalid native QUIC authentication header")?;
    authentication.set_sensitive(true);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", authentication)
        .header("Hysteria-CC-RX", "0")
        .body(())?;
    let mut auth = request_sender.send_request(request).await?;
    auth.finish().await?;
    let response = auth.recv_response().await?;
    if response.status().as_u16() != 233 {
        bail!(
            "QUIC relay authentication failed (HTTP {})",
            response.status().as_u16()
        );
    }

    let (mut send, mut recv) = session.connection.open_bi().await?;
    let relay = canonical_relay(&config.relay);
    if relay.len() > 2048 {
        bail!("QUIC relay destination is too long");
    }
    let mut request = vec![0x44, 0x01]; // Hysteria 2 TCPRequest stream type, 0x401.
    append_varint(&mut request, relay.len() as u64);
    request.extend_from_slice(relay.as_bytes());
    request.push(0); // No optional padding.
    send.write_all(&request).await?;
    let status = recv.read_u8().await?;
    let message = read_bounded_bytes(&mut recv, 2048).await?;
    read_bounded_bytes(&mut recv, 4096).await?;
    if status != 0 {
        bail!(
            "QUIC relay destination rejected: {}",
            String::from_utf8_lossy(&message)
        );
    }
    log::info!(
        "Native QUIC relay connected: {} via {}",
        relay,
        config.server
    );
    Ok(Stream::Tcp(FramedStream::from(
        QuicStream {
            send,
            recv: Some(recv),
            session: Arc::new(session),
        },
        local,
    )))
}

fn append_varint(output: &mut Vec<u8>, value: u64) {
    // Every outbound value here is a protocol-bounded address length.
    if value <= 63 {
        output.push(value as u8);
    } else {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    }
}

async fn read_bounded_bytes(
    reader: &mut (impl AsyncRead + Unpin),
    maximum: u64,
) -> Result<Vec<u8>> {
    let first = reader.read_u8().await?;
    let mut length = u64::from(first & 0x3f);
    for _ in 1..(1 << (first >> 6)) {
        length = (length << 8) | u64::from(reader.read_u8().await?);
    }
    if length > maximum {
        bail!("QUIC relay response field exceeds its protocol limit");
    }
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[derive(Debug)]
struct PinnedCertificate {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        if actual != self.pin {
            return Err(rustls::Error::General(
                "QUIC relay certificate pin mismatch".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct HoppingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    remote: SocketAddr,
    ports: Vec<u16>,
    initial: usize,
    interval: Duration,
    started: Instant,
    last_port: AtomicU16,
}

impl AsyncUdpSocket for HoppingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let hops = self.started.elapsed().as_secs() / self.interval.as_secs();
        let port = self.ports[(self.initial + hops as usize) % self.ports.len()];
        if self.last_port.swap(port, Ordering::Relaxed) != port {
            log::debug!("Native QUIC UDP port selected: {}", port);
        }
        self.inner.try_send(&Transmit {
            destination: SocketAddr::new(self.remote.ip(), port),
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, buffers, metadata) {
            Poll::Ready(Ok(count)) => count,
            other => return other,
        };
        // All configured ports terminate the same QUIC service. Keep one logical
        // peer address in Quinn while the UDP path moves between those ports.
        for meta in &mut metadata[..count] {
            if meta.addr.ip() == self.remote.ip() && self.ports.contains(&meta.addr.port()) {
                meta.addr = self.remote;
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct Session {
    endpoint: Endpoint,
    connection: quinn::Connection,
    http_driver: Option<JoinHandle<()>>,
    runtime: tokio::runtime::Handle,
}

impl Drop for Session {
    fn drop(&mut self) {
        let statistics = self.connection.stats();
        log::info!(
            "Native QUIC relay closed: sent_packets={}, lost_packets={}, rtt_ms={}",
            statistics.path.sent_packets,
            statistics.path.lost_packets,
            self.connection.rtt().as_millis(),
        );
        self.connection.close(0u32.into(), b"relay closed");
        self.endpoint.close(0u32.into(), b"relay closed");
        if let Some(driver) = &self.http_driver {
            driver.abort();
        }
    }
}

struct QuicStream {
    send: SendStream,
    recv: Option<RecvStream>,
    session: Arc<Session>,
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        if let Err(err) = self.send.finish() {
            log::debug!("Native QUIC send stream already closed: {}", err);
        }
        let stopped = self.send.stopped();
        let receive = self.recv.take();
        let session = self.session.clone();
        let runtime = session.runtime.clone();
        // A QUIC flush only queues data. Retain the connection and its receive
        // stream until the final bytes are acknowledged, or the idle limit expires.
        runtime.spawn(async move {
            let _receive = receive;
            match tokio::time::timeout(Duration::from_secs(30), stopped).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => log::debug!("Native QUIC final acknowledgement failed: {}", err),
                Err(_) => log::debug!("Native QUIC final acknowledgement timed out"),
            }
            drop(session);
        });
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.recv.as_mut() {
            Some(recv) => AsyncRead::poll_read(Pin::new(recv), cx, buffer),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_selection_and_hopping_config_are_bounded() {
        assert_eq!(canonical_relay("example.test"), "example.test:21117");
        assert_eq!(
            canonical_relay("[::ffff:192.0.2.1]:21117"),
            "192.0.2.1:21117"
        );
        assert_eq!(
            parse_server("example.test:50000-50004").unwrap().1,
            vec![50000, 50001, 50002, 50003, 50004]
        );
        for invalid in ["example.test", "host:0", "host:60000-50000", "host:1-65535"] {
            assert!(parse_server(invalid).is_err());
        }
        assert!(parse_pin("").is_err());
        assert!(parse_pin(&"z".repeat(64)).is_err());
        assert_eq!(parse_pin(&"AB".repeat(32)).unwrap(), [0xab; 32]);
    }

    #[tokio::test]
    async fn proxy_response_rejects_oversized_and_truncated_fields() {
        let mut encoded = Vec::new();
        append_varint(&mut encoded, 65);
        encoded.extend_from_slice(&[7; 65]);
        assert_eq!(
            read_bounded_bytes(&mut encoded.as_slice(), 2048)
                .await
                .unwrap(),
            vec![7; 65]
        );
        assert!(read_bounded_bytes(&mut [0x50, 0x01].as_slice(), 4096)
            .await
            .is_err());
        assert!(read_bounded_bytes(&mut [0x40].as_slice(), 4096)
            .await
            .is_err());
        assert!(read_bounded_bytes(&mut [0x02, 0x01].as_slice(), 4096)
            .await
            .is_err());
    }
}
