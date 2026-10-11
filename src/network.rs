use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, ensure};
use hyper::{Uri, http::uri::Authority};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    proxy::{self, App, Connection, Route},
    store::{self, Flow, Message},
};

#[derive(Clone)]
pub enum Mode {
    Http,
    Socks,
    Reverse(Uri),
    Tcp(Authority),
}

pub fn reverse(value: &str) -> Result<(SocketAddr, Mode)> {
    let (listen, target) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("reverse requires LISTEN_ADDR=HTTP(S)_URL"))?;
    let uri = crate::rules::http_uri(target)?;
    ensure!(
        uri.query().is_none(),
        "reverse target cannot contain a query string"
    );
    Ok((listen.parse()?, Mode::Reverse(uri)))
}
pub fn forwarding(value: &str) -> Result<(SocketAddr, Mode)> {
    let (listen, target) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("forward requires LISTEN_ADDR=HOST:PORT"))?;
    Ok((listen.parse()?, Mode::Tcp(authority(target)?)))
}
fn authority(target: &str) -> Result<Authority> {
    let authority: Authority = target.parse()?;
    ensure!(
        authority.port_u16().is_some_and(|p| p > 0) && !target.contains('@'),
        "target requires HOST:PORT without credentials"
    );
    Ok(authority)
}

pub async fn connection(stream: TcpStream, state: Arc<App>, conn: Connection, mode: Mode) {
    match mode {
        Mode::Http => proxy::serve(stream, state, conn, None).await,
        Mode::Reverse(origin) => {
            proxy::serve(
                stream,
                state,
                conn,
                Some(Route {
                    origin,
                    locked: false,
                    tls: false,
                }),
            )
            .await
        }
        mode => {
            let mut shutdown = conn.shutdown.clone();
            let peer = conn.peer;
            let process = conn.process.clone();
            let started = store::now_ms();
            let description = match &mode {
                Mode::Socks => "SOCKS".to_owned(),
                Mode::Tcp(target) => format!("TCP {target}"),
                _ => unreachable!(),
            };
            let observer = state.clone();
            let work = async {
                match mode {
                    Mode::Socks => socks(stream, state.clone(), conn).await,
                    Mode::Tcp(target) => {
                        let upstream = dial(&target, &state).await?;
                        relay(stream, upstream, state, conn, target, "TCP", false).await
                    }
                    _ => unreachable!(),
                }
            };
            let result =
                tokio::select! { result = work => result, _ = shutdown.changed() => return };
            if let Err(error) = result {
                eprintln!("{description} connection from {peer} failed: {error:#}");
                let settings = observer.settings.read().unwrap().clone();
                if settings.recording {
                    let mut store = observer.store.lock().unwrap();
                    // Relay failures have captures. Make captures for negotiation or connection failures.
                    if !store
                        .flows
                        .iter()
                        .any(|f| f.client == peer.to_string() && f.started_at >= started)
                    {
                        store.add(
                            Flow {
                                id: 0,
                                url: format!("tcp://{peer}/"),
                                upstream_url: description,
                                method: "CONNECT".into(),
                                client: peer.to_string(),
                                protocol: "TCP tunnel".into(),
                                tls: false,
                                started_at: started,
                                headers_received_ms: None,
                                duration_ms: Some(store::now_ms().saturating_sub(started)),
                                phase: "error".into(),
                                status: None,
                                error: Some(format!("{error:#}")),
                                request: Message::default(),
                                response: None,
                                metadata: crate::store::Metadata {
                                    process,
                                    ..Default::default()
                                },
                            },
                            settings.max_flows,
                        );
                    }
                }
            }
        }
    }
}

async fn dial(target: &Authority, state: &App) -> Result<crate::connector::Transport> {
    crate::simulation::check(&state.settings.read().unwrap())?;
    let dns = state.settings.read().unwrap().dns_overrides.clone();
    state.outbound.dial(target, &dns).await
}

async fn reply(stream: &mut TcpStream, status: u8, bound: SocketAddr) -> Result<()> {
    let mut bytes = vec![5, status, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn rejected(stream: &mut TcpStream, status: u8, message: &str) -> Result<Authority> {
    reply(stream, status, "0.0.0.0:0".parse().unwrap()).await?;
    anyhow::bail!(message.to_owned())
}

async fn negotiate(
    stream: &mut TcpStream,
    credentials: Option<&crate::auth::Credentials>,
) -> Result<Authority> {
    let version = stream.read_u8().await?;
    let count = stream.read_u8().await?;
    if version != 5 || count == 0 {
        stream.write_all(&[5, 255]).await?;
        anyhow::bail!("invalid SOCKS5 greeting");
    }
    let mut methods = vec![0; count as usize];
    stream.read_exact(&mut methods).await?;
    let method = if credentials.is_some() { 2 } else { 0 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 255]).await?;
        anyhow::bail!("SOCKS5 authentication method not supported");
    }
    stream.write_all(&[5, method]).await?;
    if let Some(credentials) = credentials {
        let version = stream.read_u8().await?;
        let length = stream.read_u8().await?;
        let mut username = vec![0; length as usize];
        stream.read_exact(&mut username).await?;
        let length = stream.read_u8().await?;
        let mut password = vec![0; length as usize];
        stream.read_exact(&mut password).await?;
        let accepted = version == 1 && credentials.matches(&username, &password);
        stream.write_all(&[1, u8::from(!accepted)]).await?;
        ensure!(accepted, "SOCKS authentication rejected");
    }
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        return rejected(stream, 1, "invalid SOCKS5 request").await;
    }
    if request[1] != 1 {
        return rejected(stream, 7, "SOCKS5 only supports TCP CONNECT").await;
    }
    let host = match request[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            format!("[{}]", std::net::Ipv6Addr::from(bytes))
        }
        3 => {
            let length = stream.read_u8().await?;
            if length == 0 {
                return rejected(stream, 8, "empty SOCKS5 hostname").await;
            }
            let mut bytes = vec![0; length as usize];
            stream.read_exact(&mut bytes).await?;
            if !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(b))
            {
                return rejected(stream, 8, "invalid SOCKS5 hostname").await;
            }
            String::from_utf8(bytes)?
        }
        _ => return rejected(stream, 8, "unsupported SOCKS5 address type").await,
    };
    let port = stream.read_u16().await?;
    match authority(&format!("{host}:{port}")) {
        Ok(target) => Ok(target),
        Err(_) => rejected(stream, 1, "invalid SOCKS5 port").await,
    }
}

#[derive(PartialEq, Eq)]
enum Protocol {
    Http,
    Tls,
    Other,
}

async fn sniff(stream: &mut TcpStream) -> Result<(Protocol, Vec<u8>)> {
    let mut prefix = Vec::new();
    let mut protocol = Protocol::Other;
    let read = tokio::time::timeout(Duration::from_millis(250), async {
        while prefix.len() < 32 {
            let byte = match stream.read_u8().await {
                Ok(byte) => byte,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error),
            };
            prefix.push(byte);
            if prefix.first() == Some(&0x16) {
                if prefix.len() < 6 {
                    continue;
                }
                let length = u16::from_be_bytes([prefix[3], prefix[4]]);
                if prefix[1] == 3
                    && prefix[2] <= 3
                    && (1..=18432).contains(&length)
                    && prefix[5] == 1
                {
                    protocol = Protocol::Tls;
                }
                break;
            }
            if let Some(space) = prefix.iter().position(|b| *b == b' ') {
                if prefix.len() > space + 1 {
                    if byte == b'/' || byte == b'*' {
                        protocol = Protocol::Http;
                    }
                    break;
                }
            } else if !(byte.is_ascii_uppercase() || byte == b'-') {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    if let Ok(result) = read {
        result?;
    }
    Ok((protocol, prefix))
}

async fn socks(mut stream: TcpStream, state: Arc<App>, mut conn: Connection) -> Result<()> {
    let target = tokio::time::timeout(
        Duration::from_secs(15),
        negotiate(&mut stream, state.outbound.auth.as_ref()),
    )
    .await??;
    conn.authenticated = true;
    let virtual_setup =
        target.host().eq_ignore_ascii_case("openproxy.local") && target.port_u16() == Some(80);
    let upstream = if virtual_setup {
        None
    } else {
        match dial(&target, &state).await {
            Ok(upstream) => Some(upstream),
            Err(error) => {
                let code = error
                    .downcast_ref::<std::io::Error>()
                    .map_or(4, |e| match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => 5,
                        std::io::ErrorKind::NetworkUnreachable => 3,
                        _ => 4,
                    });
                reply(&mut stream, code, "0.0.0.0:0".parse().unwrap()).await?;
                return Err(error);
            }
        }
    };
    reply(
        &mut stream,
        0,
        upstream
            .as_ref()
            .map_or(Ok(conn.local), crate::connector::Transport::local_addr)?,
    )
    .await?;
    let (protocol, prefix) = sniff(&mut stream).await?;
    let (reader, writer) = stream.into_split();
    let stream = tokio::io::join(std::io::Cursor::new(prefix).chain(reader), writer);
    let host = target.host().trim_start_matches('[').trim_end_matches(']');
    if protocol == Protocol::Tls && state.settings.read().unwrap().intercept(host) {
        let config = state.ca.server_config(host)?;
        let started = std::time::Instant::now();
        let stream = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_rustls::TlsAcceptor::from(config).accept(stream),
        )
        .await?;
        let stream = stream.map_err(|_| {
            anyhow::anyhow!(
                "SOCKS TLS client handshake failed; check certificate trust or use a bypass host"
            )
        })?;
        conn.client_tls = Some(crate::connector::tls_details(
            stream.get_ref().1,
            stream.get_ref().1.server_name().unwrap_or(""),
            started,
        ));
        conn.upstream = upstream.map(|s| state.client_for_socket(target.clone(), s));
        proxy::serve(
            stream,
            state,
            conn,
            Some(Route {
                origin: format!("https://{target}/").parse()?,
                locked: true,
                tls: true,
            }),
        )
        .await;
    } else if protocol == Protocol::Http {
        conn.upstream = upstream.map(|s| state.client_for_socket(target.clone(), s));
        proxy::serve(
            stream,
            state,
            conn,
            Some(Route {
                origin: format!("http://{target}/").parse()?,
                locked: true,
                tls: false,
            }),
        )
        .await;
    } else if let Some(upstream) = upstream {
        relay(
            stream,
            upstream,
            state,
            conn,
            target,
            "SOCKS",
            protocol == Protocol::Tls,
        )
        .await?;
    }
    Ok(())
}

pub async fn relay<T>(
    mut client: T,
    mut upstream: crate::connector::Transport,
    state: Arc<App>,
    conn: Connection,
    target: Authority,
    method: &str,
    tls: bool,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let settings = state.settings.read().unwrap().clone();
    let id = settings.recording.then(|| {
        state.store.lock().unwrap().add(
            Flow {
                id: 0,
                url: format!("{}://{target}/", if tls { "https" } else { "tcp" }),
                upstream_url: format!("tcp://{target}/"),
                method: method.into(),
                client: conn.peer.to_string(),
                protocol: "TCP tunnel".into(),
                tls,
                started_at: store::now_ms(),
                headers_received_ms: Some(0),
                duration_ms: None,
                phase: "tunneling".into(),
                status: Some(200),
                error: None,
                request: Message::default(),
                response: Some(Message::default()),
                metadata: crate::store::Metadata {
                    connection: Some(upstream.details.clone()),
                    process: conn.process.clone(),
                    ..Default::default()
                },
            },
            settings.max_flows,
        )
    });
    let _guard = Tunnel {
        state: state.clone(),
        id,
    };
    let result =
        crate::simulation::copy(&mut client, &mut upstream, &state.simulation, &settings).await;
    state.update(id, |flow| {
        flow.duration_ms = Some(store::now_ms().saturating_sub(flow.started_at));
        match &result {
            Ok((sent, received)) => {
                flow.phase = "complete".into();
                flow.request.body.size = *sent;
                if let Some(r) = &mut flow.response {
                    r.body.size = *received;
                }
            }
            Err(error) => {
                flow.phase = "error".into();
                flow.error = Some(error.to_string());
            }
        }
    });
    result?;
    Ok(())
}
struct Tunnel {
    state: Arc<App>,
    id: Option<u64>,
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.state.update(self.id, |flow| {
            if flow.duration_ms.is_none() {
                flow.duration_ms = Some(store::now_ms().saturating_sub(flow.started_at));
                flow.phase = "error".into();
                flow.error = Some("tunnel cancelled".into());
            }
        });
    }
}

pub fn pac(host: IpAddr, http_port: u16, socks_port: Option<u16>) -> String {
    let host = match host {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let route = socks_port.map_or_else(
        || format!("PROXY {host}:{http_port}"),
        |port| format!("SOCKS5 {host}:{port}; SOCKS {host}:{port}"),
    );
    format!(
        "function FindProxyForURL(url, host) {{\n  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return 'DIRECT';\n  return '{route}';\n}}\n"
    )
}

pub fn advertised_socks(bind: SocketAddr, local: IpAddr) -> Option<IpAddr> {
    if bind.ip().is_loopback() && !local.is_loopback() {
        None
    } else if bind.ip().is_unspecified() {
        Some(local)
    } else {
        Some(bind.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_validation_and_advertised_addresses() {
        assert!(reverse("127.0.0.1:9000=https://example.test/api/").is_ok());
        assert!(reverse("127.0.0.1:9000=file:///tmp/file").is_err());
        assert!(reverse("127.0.0.1:9000=https://example.test/?q=1").is_err());
        assert!(forwarding("127.0.0.1:9000=[::1]:8000").is_ok());
        assert!(forwarding("127.0.0.1:9000=host:0").is_err());
        let lan = "192.168.1.2".parse().unwrap();
        assert_eq!(
            advertised_socks("127.0.0.1:1080".parse().unwrap(), lan),
            None
        );
        assert_eq!(
            advertised_socks("0.0.0.0:1080".parse().unwrap(), lan),
            Some(lan)
        );
        assert_eq!(
            advertised_socks("192.168.1.3:1080".parse().unwrap(), lan),
            Some("192.168.1.3".parse().unwrap())
        );
        assert!(pac("::1".parse().unwrap(), 8080, Some(1080)).contains("SOCKS5 [::1]:1080"));
    }
}
