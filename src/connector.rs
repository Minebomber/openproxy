use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use crate::{auth::Credentials, proxy::BoxError};
use anyhow::{Result, ensure};
use hyper::{Uri, http::uri::Authority};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tower_service::Service;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TlsDetails {
    pub protocol: String,
    pub cipher: String,
    pub alpn: String,
    pub server_name: String,
    pub handshake_ms: u64,
    pub certificate_subject: String,
    pub certificate_issuer: String,
    pub certificate_expires: String,
}
fn certificate_name(mut value: String) -> String {
    if let Some((end, _)) = value.char_indices().nth(1024) {
        value.truncate(end);
        value.push('…');
    }
    value
}

pub fn tls_details(connection: &rustls::CommonState, name: &str, started: Instant) -> TlsDetails {
    let mut details = TlsDetails {
        protocol: connection
            .protocol_version()
            .map_or(String::new(), |v| format!("{v:?}")),
        cipher: connection
            .negotiated_cipher_suite()
            .map_or(String::new(), |s| format!("{:?}", s.suite())),
        alpn: connection
            .alpn_protocol()
            .map_or(String::new(), |v| String::from_utf8_lossy(v).into_owned()),
        server_name: if name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            String::new()
        } else {
            name.into()
        },
        handshake_ms: millis(started),
        ..Default::default()
    };
    if let Some(der) = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        && let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref())
    {
        details.certificate_subject = certificate_name(cert.subject().to_string());
        details.certificate_issuer = certificate_name(cert.issuer().to_string());
        details.certificate_expires = cert.validity().not_after.to_rfc2822().unwrap_or_default();
    }
    details
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConnectionDetails {
    pub id: String,
    pub connected_at: u64,
    pub local_address: String,
    pub remote_address: String,
    pub dns_ms: u64,
    pub tcp_ms: u64,
    pub proxy_ms: Option<u64>,
    pub proxy: Option<String>,
    pub proxy_tls: Option<TlsDetails>,
    pub tls: Option<TlsDetails>,
    pub reused: bool,
}
#[derive(Clone)]
pub struct Capture {
    details: ConnectionDetails,
    requests: Arc<AtomicU64>,
}
impl Capture {
    pub fn details(&self) -> ConnectionDetails {
        let mut details = self.details.clone();
        details.reused = self.requests.fetch_add(1, Ordering::Relaxed) > 0;
        details
    }
}
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub struct Transport {
    io: Box<dyn Stream>,
    pub details: ConnectionDetails,
    local: SocketAddr,
    requests: Arc<AtomicU64>,
    proxy_http: bool,
}
impl Transport {
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }
}
impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}
impl Connection for Transport {
    fn connected(&self) -> Connected {
        let connected = Connected::new().proxy(self.proxy_http).extra(Capture {
            details: self.details.clone(),
            requests: self.requests.clone(),
        });
        if self
            .details
            .tls
            .as_ref()
            .is_some_and(|tls| tls.alpn == "h2")
        {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}
struct Chain {
    uri: Uri,
    credentials: Option<Credentials>,
}
pub struct Options {
    tls: Arc<rustls::ClientConfig>,
    proxy_tls: Arc<rustls::ClientConfig>,
    client_tls: Option<(Vec<String>, Arc<rustls::ClientConfig>)>,
    chain: Option<Chain>,
    pub auth: Option<Credentials>,
}
impl Options {
    pub fn http_authorization(&self, uri: &Uri, dns: &BTreeMap<String, IpAddr>) -> Option<String> {
        if uri
            .host()
            .is_some_and(|host| override_ip(dns, host).is_some())
        {
            return None;
        }
        self.chain
            .as_ref()
            .filter(|chain| {
                uri.scheme_str() == Some("http") && chain.uri.scheme_str() != Some("socks5")
            })
            .and_then(|chain| chain.credentials.as_ref())
            .map(Credentials::basic)
    }
    pub fn load(options: &crate::Options) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert)?;
        }
        if let Some(path) = &options.upstream_ca {
            let pem = std::fs::read(path)?;
            let certificates = rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                !certificates.is_empty(),
                "upstream CA file contains no certificates"
            );
            for certificate in certificates {
                roots.add(certificate)?;
            }
        }
        ensure!(!roots.is_empty(), "no upstream trust roots found");
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        let proxy_tls = Arc::new(tls.clone());
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let client_tls = match (&options.client_cert, &options.client_key) {
            (Some(cert), Some(key)) => {
                ensure!(
                    !options.client_cert_host.is_empty(),
                    "client certificates require --client-cert-host to limit credential disclosure"
                );
                ensure!(
                    options.client_cert_host.iter().all(|host| !host.is_empty()
                        && host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))),
                    "client certificate hosts must be exact hostnames or IP addresses"
                );
                let cert = std::fs::read(cert)?;
                let certs = rustls_pemfile::certs(&mut cert.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let key = crate::auth::private_read(key)?;
                let key = rustls_pemfile::private_key(&mut key.as_slice())?
                    .ok_or_else(|| anyhow::anyhow!("missing client private key"))?;
                let mut config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_client_auth_cert(certs, key)?;
                config.alpn_protocols = tls.alpn_protocols.clone();
                Some((options.client_cert_host.clone(), Arc::new(config)))
            }
            (None, None) => {
                ensure!(
                    options.client_cert_host.is_empty(),
                    "client certificate hosts require certificate and key"
                );
                None
            }
            _ => anyhow::bail!("client certificate requires both --client-cert and --client-key"),
        };
        let chain = if let Some(value) = &options.upstream_proxy {
            url::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid upstream proxy URL"))?;
            let uri: Uri = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid upstream proxy URL"))?;
            ensure!(
                matches!(uri.scheme_str(), Some("http" | "https" | "socks5"))
                    && uri.authority().is_some()
                    && uri.host().is_some_and(|host| !host.is_empty())
                    && uri.query().is_none()
                    && matches!(uri.path(), "" | "/")
                    && !uri.authority().unwrap().as_str().contains('@')
                    && uri.port_u16() != Some(0),
                "upstream proxy requires HTTP/HTTPS/SOCKS5 host URL without credentials, path or query"
            );
            Some(Chain {
                uri,
                credentials: options
                    .upstream_auth
                    .as_deref()
                    .map(Credentials::load)
                    .transpose()?,
            })
        } else {
            ensure!(
                options.upstream_auth.is_none(),
                "upstream authentication requires --upstream-proxy"
            );
            None
        };
        Ok(Self {
            tls: Arc::new(tls),
            proxy_tls,
            client_tls,
            chain,
            auth: options
                .proxy_auth
                .as_deref()
                .map(Credentials::load)
                .transpose()?,
        })
    }
    pub async fn dial(
        &self,
        target: &Authority,
        dns: &BTreeMap<String, IpAddr>,
    ) -> Result<Transport> {
        tokio::time::timeout(Duration::from_secs(15), self.dial_inner(target, dns, true)).await?
    }
    async fn dial_inner(
        &self,
        target: &Authority,
        dns: &BTreeMap<String, IpAddr>,
        tunnel: bool,
    ) -> Result<Transport> {
        let (host, port) = if let Some(chain) = &self.chain {
            (chain.uri.host().unwrap(), proxy_port(&chain.uri))
        } else {
            (target.host(), target.port_u16().unwrap())
        };
        let host = host.trim_matches(['[', ']']);
        let started = Instant::now();
        let addresses: Vec<SocketAddr> =
            if let Some(ip) = override_ip(dns, host).or_else(|| host.parse().ok()) {
                vec![SocketAddr::new(ip, port)]
            } else {
                tokio::net::lookup_host((host, port)).await?.collect()
            };
        let dns_ms = millis(started);
        let started = Instant::now();
        let socket = connect_tcp(addresses).await?;
        socket.set_nodelay(true)?;
        let local = socket.local_addr()?;
        let mut details = ConnectionDetails {
            id: uuid::Uuid::new_v4().to_string(),
            connected_at: crate::store::now_ms(),
            local_address: local.to_string(),
            remote_address: socket.peer_addr()?.to_string(),
            dns_ms,
            tcp_ms: millis(started),
            ..Default::default()
        };
        let mut io: Box<dyn Stream> = Box::new(socket);
        if let Some(chain) = &self.chain {
            details.proxy = Some(chain.uri.to_string());
            if chain.uri.scheme_str() == Some("https") {
                let started = Instant::now();
                let stream = tokio_rustls::TlsConnector::from(self.proxy_tls.clone())
                    .connect(ServerName::try_from(host.to_owned())?, io)
                    .await?;
                details.proxy_tls = Some(tls_details(stream.get_ref().1, host, started));
                io = Box::new(stream);
            }
            let started = Instant::now();
            let host = target.host().trim_matches(['[', ']']);
            let destination = override_ip(dns, host).map_or_else(
                || target.clone(),
                |ip| {
                    format!(
                        "{}:{}",
                        if ip.is_ipv6() {
                            format!("[{ip}]")
                        } else {
                            ip.to_string()
                        },
                        target.port_u16().unwrap()
                    )
                    .parse()
                    .unwrap()
                },
            );
            if chain.uri.scheme_str() == Some("socks5") {
                socks_connect(&mut io, &destination, chain.credentials.as_ref()).await?;
            } else if tunnel {
                http_connect(&mut io, &destination, chain.credentials.as_ref()).await?;
            }
            details.proxy_ms = tunnel.then(|| millis(started));
        }
        Ok(Transport {
            io,
            details,
            local,
            requests: Arc::new(AtomicU64::new(0)),
            proxy_http: !tunnel,
        })
    }
    async fn connect(&self, uri: &Uri, mut stream: Transport, http1: bool) -> Result<Transport> {
        if uri.scheme_str() == Some("https") {
            let host = uri.host().unwrap().trim_matches(['[', ']']);
            let mut tls = self
                .client_tls
                .as_ref()
                .filter(|(hosts, _)| {
                    hosts
                        .iter()
                        .any(|allowed| allowed.trim_matches(['[', ']']).eq_ignore_ascii_case(host))
                })
                .map_or_else(|| self.tls.clone(), |(_, config)| config.clone());
            if http1 {
                let mut config = (*tls).clone();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                tls = Arc::new(config);
            }
            let started = Instant::now();
            let connection = tokio_rustls::TlsConnector::from(tls)
                .connect(ServerName::try_from(host.to_owned())?, stream.io)
                .await?;
            stream.details.tls = Some(tls_details(connection.get_ref().1, host, started));
            stream.io = Box::new(connection);
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn certificate_names_are_bounded_without_splitting_utf8() {
        assert_eq!(certificate_name("CN=fixture".into()), "CN=fixture");
        let name = certificate_name("🦀".repeat(1100));
        assert_eq!(name.chars().count(), 1025);
        assert!(name.ends_with('…'));
        assert!(name.len() < 32 * 1024);
    }

    #[test]
    fn proxy_urls_reject_credentials_paths_and_invalid_ports() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        for url in [
            "http://user:secret@example.com",
            "http://example.com/path",
            "socks5://example.com:0",
            "https://example.com:99999",
            "http://example.com/?query",
            "ftp://example.com",
        ] {
            let options = crate::Options::parse_from(["openproxy", "--upstream-proxy", url]);
            assert!(
                Options::load(&options).is_err(),
                "accepted invalid proxy URL"
            );
        }
        let options =
            crate::Options::parse_from(["openproxy", "--upstream-proxy", "socks5://[::1]:1080"]);
        assert!(Options::load(&options).is_ok());
    }
    #[tokio::test]
    async fn failed_address_does_not_prevent_connecting_to_another_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let stream = tokio::time::timeout(
            Duration::from_secs(1),
            connect_tcp(vec!["127.0.0.1:0".parse().unwrap(), target]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), target);
    }
}
async fn connect_tcp(addresses: Vec<SocketAddr>) -> Result<TcpStream> {
    let mut addresses = addresses.into_iter().peekable();
    let mut attempts = tokio::task::JoinSet::new();
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "DNS returned no addresses");
    loop {
        if attempts.is_empty() {
            let Some(address) = addresses.next() else {
                return Err(last.into());
            };
            attempts.spawn(TcpStream::connect(address));
        }
        tokio::select! {
            result = attempts.join_next() => {
                match result.unwrap()? { Ok(stream) => return Ok(stream), Err(error) => last = error }
                if let Some(address) = addresses.next() { attempts.spawn(TcpStream::connect(address)); }
            },
            // Space address attempts so an unreachable address family cannot use the full timeout.
            _ = tokio::time::sleep(Duration::from_millis(250)), if addresses.peek().is_some() => {
                attempts.spawn(TcpStream::connect(addresses.next().unwrap()));
            },
        }
    }
}
fn millis(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}
fn override_ip(dns: &BTreeMap<String, IpAddr>, host: &str) -> Option<IpAddr> {
    dns.iter()
        .find(|(name, _)| {
            name.trim_matches(['[', ']'])
                .eq_ignore_ascii_case(host.trim_matches(['[', ']']))
        })
        .map(|(_, ip)| *ip)
}
fn proxy_port(uri: &Uri) -> u16 {
    uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https") => 443,
        Some("socks5") => 1080,
        _ => 80,
    })
}
async fn http_connect(
    stream: &mut Box<dyn Stream>,
    target: &Authority,
    credentials: Option<&Credentials>,
) -> Result<()> {
    let authorization = credentials.map_or(String::new(), |c| {
        format!("Proxy-Authorization: {}\r\n", c.basic())
    });
    stream
        .write_all(
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authorization}\r\n")
                .as_bytes(),
        )
        .await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        ensure!(
            headers.len() < 16384,
            "upstream CONNECT headers exceed 16 KiB"
        );
        headers.push(stream.read_u8().await?);
    }
    let line = headers.split(|b| *b == b'\n').next().unwrap();
    let text = std::str::from_utf8(line)
        .map_err(|_| anyhow::anyhow!("invalid upstream CONNECT response"))?;
    let mut parts = text.split_ascii_whitespace();
    ensure!(
        matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "invalid upstream CONNECT response"
    );
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid upstream CONNECT status"))?;
    ensure!(
        (200..300).contains(&status),
        "upstream CONNECT rejected with status {status}"
    );
    Ok(())
}
async fn socks_connect(
    stream: &mut Box<dyn Stream>,
    target: &Authority,
    credentials: Option<&Credentials>,
) -> Result<()> {
    let method = if credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    ensure!(
        response == [5, method],
        "upstream SOCKS authentication method rejected"
    );
    if let Some(credentials) = credentials {
        let mut authentication = vec![1, credentials.username.len() as u8];
        authentication.extend_from_slice(credentials.username.as_bytes());
        authentication.push(credentials.password.len() as u8);
        authentication.extend_from_slice(credentials.password.as_bytes());
        stream.write_all(&authentication).await?;
        stream.read_exact(&mut response).await?;
        ensure!(response == [1, 0], "upstream SOCKS authentication rejected");
    }
    let host = target.host().trim_matches(['[', ']']);
    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            ensure!(
                host.len() <= 255,
                "SOCKS destination hostname exceeds 255 bytes"
            );
            request.extend_from_slice(&[3, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&target.port_u16().unwrap().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply[0] == 5 && reply[1] == 0 && reply[2] == 0,
        "upstream SOCKS CONNECT rejected"
    );
    let count = match reply[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => anyhow::bail!("invalid upstream SOCKS address type"),
    };
    let mut bound = vec![0; count + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}
#[derive(Clone)]
pub struct Connector {
    socket: Arc<Mutex<Option<(Authority, Transport)>>>,
    dns: BTreeMap<String, IpAddr>,
    options: Arc<Options>,
    proxy_http: bool,
    http1: bool,
}
impl Connector {
    pub fn http1_only(mut self) -> Self {
        self.http1 = true;
        self
    }
    pub fn new(
        socket: Option<(Authority, Transport)>,
        dns: BTreeMap<String, IpAddr>,
        options: Arc<Options>,
    ) -> Self {
        let proxy_http = socket.is_none();
        Self {
            socket: Arc::new(Mutex::new(socket)),
            dns: dns
                .into_iter()
                .map(|(h, ip)| (h.to_ascii_lowercase(), ip))
                .collect(),
            options,
            proxy_http,
            http1: false,
        }
    }
}
pub fn same_authority(uri: &Uri, authority: &Authority, scheme: &str) -> bool {
    uri.authority().is_some_and(|actual| {
        actual.host().eq_ignore_ascii_case(authority.host())
            && actual
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                })
                == authority
                    .port_u16()
                    .unwrap_or(if scheme == "https" { 443 } else { 80 })
    })
}
impl Service<Uri> for Connector {
    type Response = TokioIo<Transport>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let socket = self.socket.lock().unwrap().take();
        let dns = self.dns.clone();
        let options = self.options.clone();
        let http1 = self.http1;
        let proxy_http = self.proxy_http
            && uri.scheme_str() == Some("http")
            && !uri
                .host()
                .is_some_and(|host| override_ip(&dns, host).is_some())
            && options
                .chain
                .as_ref()
                .is_some_and(|chain| chain.uri.scheme_str() != Some("socks5"));
        Box::pin(async move {
            let operation = async {
                let stream = if let Some((authority, stream)) = socket
                    && same_authority(&uri, &authority, uri.scheme_str().unwrap_or("http"))
                {
                    stream
                } else {
                    let target: Authority = format!(
                        "{}:{}",
                        uri.host()
                            .ok_or_else(|| anyhow::anyhow!("missing destination host"))?,
                        uri.port_u16()
                            .unwrap_or(if uri.scheme_str() == Some("https") {
                                443
                            } else {
                                80
                            })
                    )
                    .parse()?;
                    options.dial_inner(&target, &dns, !proxy_http).await?
                };
                options.connect(&uri, stream, http1).await
            };
            tokio::time::timeout(Duration::from_secs(30), operation)
                .await?
                .map(TokioIo::new)
                .map_err(Into::into)
        })
    }
}
