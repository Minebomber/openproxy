use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use ipnet::IpNet;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};

use crate::{
    ca::Authority,
    config::Settings,
    store::{self, Flow, Message, Store},
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;
#[derive(Clone)]
pub struct Upstream {
    client: Client<crate::connector::Connector, ProxyBody>,
    upgrade_client: Client<crate::connector::Connector, ProxyBody>,
    outbound: Arc<crate::connector::Options>,
    dns: std::collections::BTreeMap<String, std::net::IpAddr>,
    proxy_http: bool,
}
impl Upstream {
    pub(crate) async fn request(
        &self,
        mut request: Request<ProxyBody>,
    ) -> std::result::Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        if self.proxy_http
            && let Some(authorization) = self.outbound.http_authorization(request.uri(), &self.dns)
        {
            // The connector and credential routing use the same DNS snapshot.
            request
                .headers_mut()
                .insert("proxy-authorization", authorization.parse().unwrap());
        }
        let client = if request.headers().contains_key("upgrade") {
            &self.upgrade_client
        } else {
            &self.client
        };
        client.request(request).await
    }
}

#[derive(Clone)]
struct CaptureId(Option<u64>);

pub struct App {
    pub ca: Authority,
    pub settings: RwLock<Settings>,
    pub store: Mutex<Store>,
    pub client: RwLock<Upstream>,
    pub data_dir: PathBuf,
    pub proxy_addr: SocketAddr,
    pub ui_addr: SocketAddr,
    pub socks_addr: Option<SocketAddr>,
    pub outbound: Arc<crate::connector::Options>,
    pub token: String,
    pub save_lock: tokio::sync::Mutex<()>,
    pub breakpoints: crate::breakpoints::Pool,
    pub simulation: crate::simulation::Limits,
    pub processes: Arc<crate::process::Attributor>,
    request_slots: Arc<Semaphore>,
}

impl App {
    pub fn new(
        ca: Authority,
        settings: Settings,
        data_dir: PathBuf,
        outbound: crate::connector::Options,
        proxy_addr: SocketAddr,
        ui_addr: SocketAddr,
        socks_addr: Option<SocketAddr>,
    ) -> Result<Self> {
        let outbound = Arc::new(outbound);
        let client = Self::build_client(outbound.clone(), None, settings.dns_overrides.clone());
        let store = Store::load(&data_dir.join("session.json"), &settings)?;
        Ok(Self {
            ca,
            simulation: crate::simulation::Limits::new(&settings),
            processes: Arc::new(crate::process::Attributor::default()),
            settings: RwLock::new(settings),
            store: Mutex::new(store),
            client: RwLock::new(client),
            data_dir,
            proxy_addr,
            ui_addr,
            socks_addr,
            outbound,
            token: uuid::Uuid::new_v4().simple().to_string(),
            save_lock: tokio::sync::Mutex::new(()),
            breakpoints: crate::breakpoints::Pool::default(),
            request_slots: Arc::new(Semaphore::new(256)),
        })
    }

    pub(crate) fn build_client(
        outbound: Arc<crate::connector::Options>,
        socket: Option<(hyper::http::uri::Authority, crate::connector::Transport)>,
        dns: std::collections::BTreeMap<String, std::net::IpAddr>,
    ) -> Upstream {
        let proxy_http = socket.is_none();
        let connector = crate::connector::Connector::new(socket, dns.clone(), outbound.clone());
        let mut builder = Client::builder(TokioExecutor::new());
        builder.retry_canceled_requests(false);
        let client = builder.build(connector.clone());
        let upgrade_client = builder.build(connector.http1_only());
        Upstream {
            client,
            upgrade_client,
            outbound,
            dns,
            proxy_http,
        }
    }

    pub fn client_for_socket(
        &self,
        authority: hyper::http::uri::Authority,
        socket: crate::connector::Transport,
    ) -> Upstream {
        Self::build_client(
            self.outbound.clone(),
            Some((authority, socket)),
            self.settings.read().unwrap().dns_overrides.clone(),
        )
    }

    pub fn refresh_client(&self, settings: &Settings) {
        *self.client.write().unwrap() =
            Self::build_client(self.outbound.clone(), None, settings.dns_overrides.clone());
    }

    pub async fn save_session(self: &Arc<Self>) -> Result<()> {
        let _guard = self.save_lock.lock().await;
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let bytes = state.store.lock().unwrap().session_bytes()?;
            store::atomic_write(&state.data_dir.join("session.json"), &bytes)
        })
        .await?
    }

    pub fn update(&self, id: Option<u64>, change: impl FnOnce(&mut Flow)) {
        if let Some(id) = id {
            self.store.lock().unwrap().update(id, change);
        }
    }

    fn start(
        &self,
        req: &Request<ProxyBody>,
        peer: &str,
        tls: bool,
        settings: &Settings,
        process: Option<&crate::process::ClientProcess>,
    ) -> Option<u64> {
        if !settings.recording {
            return None;
        }
        let flow = Flow {
            id: 0,
            url: req.uri().to_string(),
            upstream_url: req.uri().to_string(),
            method: req.method().to_string(),
            client: peer.to_owned(),
            protocol: format!("{:?}", req.version()),
            tls,
            started_at: store::now_ms(),
            headers_received_ms: None,
            duration_ms: None,
            phase: "sending".into(),
            status: None,
            error: None,
            request: Message {
                headers: store::headers(req.headers()),
                ..Default::default()
            },
            response: None,
            metadata: crate::store::Metadata {
                process: process.cloned(),
                original_request: Some(Message {
                    headers: store::headers(req.headers()),
                    ..Default::default()
                }),
                client_tls: req
                    .extensions()
                    .get::<crate::connector::TlsDetails>()
                    .cloned(),
                ..Default::default()
            },
        };
        Some(self.store.lock().unwrap().add(flow, settings.max_flows))
    }
}

pub fn full(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn response(status: StatusCode, text: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full(text))
        .unwrap()
}

pub fn strip_hop_headers(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|name| name.trim().to_ascii_lowercase()))
        .collect();
    for name in named {
        if !(upgrade && name == "upgrade") {
            headers.remove(name);
        }
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "transfer-encoding",
        "te",
    ] {
        headers.remove(name);
    }
    if upgrade {
        headers.insert("connection", "upgrade".parse().unwrap());
    } else {
        headers.remove("upgrade");
    }
}

pub fn allowed(peer: std::net::IpAddr, allow: &[IpNet]) -> bool {
    let ip = match peer {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(peer),
        _ => peer,
    };
    ip.is_loopback() || allow.iter().any(|net| net.contains(&ip))
}

#[derive(Clone)]
pub(crate) struct Connection {
    pub process: Option<crate::process::ClientProcess>,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub shutdown: watch::Receiver<bool>,
    pub _lease: Arc<tokio::sync::OwnedSemaphorePermit>,
    pub upstream: Option<Upstream>,
    pub authenticated: bool,
    pub client_tls: Option<crate::connector::TlsDetails>,
}

#[derive(Clone)]
pub(crate) struct Route {
    pub origin: Uri,
    pub locked: bool,
    pub tls: bool,
}

pub async fn listen(
    listener: TcpListener,
    state: Arc<App>,
    allow: Vec<IpNet>,
    max_connections: usize,
    mode: crate::network::Mode,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if !allowed(peer.ip(), &allow) { continue; }
                let Ok(lease) = slots.clone().try_acquire_owned() else { continue; };
                let mut conn = Connection { peer, local: stream.local_addr()?, shutdown: shutdown.clone(), _lease: Arc::new(lease), upstream: None, authenticated: false, client_tls: None, process: None };
                let state = state.clone();
                let mode = mode.clone();
                tasks.spawn(async move {
                    let enabled = { let settings = state.settings.read().unwrap(); settings.process_attribution && settings.recording };
                    if enabled && peer.ip().is_loopback() {
                        let processes = state.processes.clone();
                        let local = conn.local;
                        conn.process = tokio::task::spawn_blocking(move || processes.lookup(peer, local)).await.ok().flatten();
                    }
                    crate::network::connection(stream, state, conn, mode).await;
                });
            }
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(crate) async fn serve<T>(stream: T, state: Arc<App>, conn: Connection, route: Option<Route>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut shutdown = conn.shutdown.clone();
    let service = service_fn(move |req| handle(req, state.clone(), conn.clone(), route.clone()));
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().max_buf_size(64 * 1024);
    builder.http2().max_concurrent_streams(128);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut connection).await;
        },
    }
}

fn handle(
    mut req: Request<Incoming>,
    state: Arc<App>,
    conn: Connection,
    route: Option<Route>,
) -> Pin<Box<dyn Future<Output = std::result::Result<Response<ProxyBody>, Infallible>> + Send>> {
    Box::pin(async move {
        let setup_request = route.is_none()
            && req.method() != Method::CONNECT
            && (req.uri().scheme().is_none()
                || req
                    .uri()
                    .host()
                    .is_some_and(|host| host.eq_ignore_ascii_case("openproxy.local")));
        if !setup_request
            && !conn.authenticated
            && let Some(credentials) = &state.outbound.auth
            && !credentials.accepts(req.headers())
        {
            let mut denied = response(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy credentials required",
            );
            denied.headers_mut().insert(
                "proxy-authenticate",
                "Basic realm=\"OpenProxy\", charset=\"UTF-8\""
                    .parse()
                    .unwrap(),
            );
            return Ok(denied);
        }
        req.headers_mut().remove("proxy-authorization");
        if let Some(tls) = &conn.client_tls {
            req.extensions_mut().insert(tls.clone());
        }
        if req.method() == Method::CONNECT {
            if route.is_some() {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "nested CONNECT is not supported",
                ));
            }
            let result = connect(req, state, conn).await;
            return Ok(result.unwrap_or_else(|e| {
                response(StatusCode::BAD_GATEWAY, format!("CONNECT failed: {e:#}"))
            }));
        }
        if route.is_none() && req.uri().scheme().is_none() {
            return Ok(setup(&req, &state, conn.local.ip()));
        }
        let target = match absolute_uri(&req, route.as_ref()) {
            Ok(uri) => uri,
            Err(e) => return Ok(response(StatusCode::BAD_REQUEST, e.to_string())),
        };
        if target
            .host()
            .is_some_and(|h| h.eq_ignore_ascii_case("openproxy.local"))
            && route.as_ref().is_none_or(|r| r.locked)
        {
            return Ok(setup(&req, &state, conn.local.ip()));
        }
        *req.uri_mut() = target;
        let websocket = req
            .headers()
            .get_all("upgrade")
            .iter()
            .filter_map(|h| h.to_str().ok())
            .flat_map(|h| h.split(','))
            .any(|protocol| protocol.trim().eq_ignore_ascii_case("websocket"));
        let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
        let req = req.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed());
        let result = forward(
            req,
            state.clone(),
            conn.peer.to_string(),
            route.as_ref().is_some_and(|r| r.tls),
            conn.upstream.clone(),
            conn.process.clone(),
        )
        .await;
        let mut res = result.unwrap_or_else(|e| {
            response(StatusCode::BAD_GATEWAY, format!("Upstream failed: {e:#}"))
        });
        if res.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let id = res.extensions().get::<CaptureId>().and_then(|id| id.0);
            let extensions = res
                .headers()
                .get("sec-websocket-extensions")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .chars()
                .take(8192)
                .collect::<String>();
            let compression = extensions.split(',').any(|ext| {
                ext.split(';')
                    .next()
                    .is_some_and(|name| name.trim().eq_ignore_ascii_case("permessage-deflate"))
            });
            state.update(id, |f| {
                f.protocol = "WebSocket".into();
                f.phase = "upgraded".into();
                f.duration_ms = None;
                f.metadata.websocket = Some(crate::websocket::Capture {
                    extensions,
                    ..Default::default()
                });
            });
            let server_upgrade = hyper::upgrade::on(&mut res);
            tokio::spawn(async move {
                let mut shutdown = conn.shutdown.clone();
                let pipe = async {
                    let (client, server) = tokio::try_join!(client_upgrade, server_upgrade)?;
                    let settings = state.settings.read().unwrap().clone();
                    crate::simulation::copy(
                        &mut crate::websocket::Observer::new(
                            TokioIo::new(client),
                            state.clone(),
                            id,
                            true,
                            compression,
                        ),
                        &mut crate::websocket::Observer::new(
                            TokioIo::new(server),
                            state.clone(),
                            id,
                            false,
                            compression,
                        ),
                        &state.simulation,
                        &settings,
                    )
                    .await?;
                    Ok::<_, BoxError>(())
                };
                let error = tokio::select! { result = pipe => result.err().map(|e| e.to_string()), _ = shutdown.changed() => Some("proxy shutdown interrupted WebSocket".into()) };
                state.update(id, |f| {
                    f.phase = if error.is_some() { "error" } else { "complete" }.into();
                    f.duration_ms = Some(store::now_ms().saturating_sub(f.started_at));
                    if let Some(ws) = &mut f.metadata.websocket {
                        ws.complete = error.is_none() && ws.error.is_none();
                        if error.is_some() {
                            ws.error = error;
                        }
                    }
                });
            });
        }
        Ok(res)
    })
}

fn absolute_uri<B>(req: &Request<B>, route: Option<&Route>) -> Result<Uri> {
    let uri = req.uri();
    if let Some(route) = route {
        let authority = route.origin.authority().unwrap();
        let scheme = route.origin.scheme_str().unwrap();
        if route.locked && uri.authority().is_some() {
            ensure!(
                crate::connector::same_authority(uri, authority, scheme)
                    && uri.scheme_str().is_none_or(|s| s == scheme),
                "request authority differs from CONNECT target"
            );
        }
        Ok(format!(
            "{scheme}://{authority}{}{}",
            route.origin.path().trim_end_matches('/'),
            uri.path_and_query().map_or("/", |p| p.as_str())
        )
        .parse()?)
    } else {
        ensure!(
            matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some(),
            "absolute HTTP(S) URL required"
        );
        ensure!(
            !uri.authority().unwrap().as_str().contains('@'),
            "URL credentials are not supported"
        );
        Ok(uri.clone())
    }
}

async fn connect(
    mut req: Request<Incoming>,
    state: Arc<App>,
    conn: Connection,
) -> Result<Response<ProxyBody>> {
    let target = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow::anyhow!("CONNECT requires host:port"))?
        .clone();
    ensure!(
        target.port_u16().is_some() && !target.as_str().contains('@'),
        "CONNECT requires a valid host:port"
    );
    let host = target.host().trim_start_matches('[').trim_end_matches(']');
    let intercept = state.settings.read().unwrap().intercept(host);
    let config = if intercept {
        Some(state.ca.server_config(host)?)
    } else {
        None
    };
    let upstream = if !intercept {
        crate::simulation::check(&state.settings.read().unwrap())?;
        let dns = state.settings.read().unwrap().dns_overrides.clone();
        Some(state.outbound.dial(&target, &dns).await?)
    } else {
        None
    };
    let upgrade = hyper::upgrade::on(&mut req);
    let settings = state.settings.read().unwrap().clone();
    let tunnel_id = if !intercept && settings.recording {
        let mut store = state.store.lock().unwrap();
        Some(store.add(
            Flow {
                id: 0,
                url: format!("https://{target}/"),
                upstream_url: format!("https://{target}/"),
                method: "CONNECT".into(),
                client: conn.peer.to_string(),
                protocol: "TCP tunnel".into(),
                tls: true,
                started_at: store::now_ms(),
                headers_received_ms: Some(0),
                duration_ms: None,
                phase: "tunneling".into(),
                status: Some(200),
                error: None,
                request: Message::default(),
                response: Some(Message::default()),
                metadata: crate::store::Metadata {
                    connection: upstream.as_ref().map(|stream| stream.details.clone()),
                    process: conn.process.clone(),
                    ..Default::default()
                },
            },
            settings.max_flows,
        ))
    } else {
        None
    };
    tokio::spawn(async move {
        let mut shutdown = conn.shutdown.clone();
        let pipe = async {
            let stream = TokioIo::new(upgrade.await?);
            if let Some(config) = config {
                let started = std::time::Instant::now();
                let stream = tokio::time::timeout(
                    Duration::from_secs(15),
                    tokio_rustls::TlsAcceptor::from(config).accept(stream),
                )
                .await??;
                let mut conn = conn;
                conn.authenticated = true;
                conn.client_tls = Some(crate::connector::tls_details(
                    stream.get_ref().1,
                    stream.get_ref().1.server_name().unwrap_or(""),
                    started,
                ));
                serve(
                    stream,
                    state.clone(),
                    conn,
                    Some(Route {
                        origin: format!("https://{target}/").parse()?,
                        locked: true,
                        tls: true,
                    }),
                )
                .await;
            } else if let Some(mut upstream) = upstream {
                let (sent, received) = crate::simulation::copy(
                    &mut { stream },
                    &mut upstream,
                    &state.simulation,
                    &settings,
                )
                .await?;
                state.update(tunnel_id, |f| {
                    f.request.body.size = sent;
                    if let Some(r) = &mut f.response {
                        r.body.size = received;
                    }
                });
            }
            Ok::<_, BoxError>(())
        };
        let result = tokio::select! {
            result = pipe => result,
            _ = shutdown.changed() => Err::<(), BoxError>("proxy shutting down".into()),
        };
        if let Err(error) = &result
            && intercept
        {
            // Log the host for diagnosis. Do not log bodies, headers, or keys.
            eprintln!(
                "TLS client connection failed for {host_target}: {error}",
                host_target = target.host()
            );
        }
        state.update(tunnel_id, |f| {
            f.phase = "complete".into();
            f.duration_ms = Some(store::now_ms().saturating_sub(f.started_at));
            f.error = result.err().map(|e| e.to_string());
        });
    });
    Ok(Response::new(full(Bytes::new())))
}

#[derive(Clone)]
pub struct SkipRules;

pub async fn forward(
    req: Request<ProxyBody>,
    state: Arc<App>,
    peer: String,
    tls: bool,
    client: Option<Upstream>,
    process: Option<crate::process::ClientProcess>,
) -> Result<Response<ProxyBody>> {
    let lease = match state.request_slots.clone().try_acquire_owned() {
        Ok(permit) => Arc::new(permit),
        Err(_) => {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy has reached its 256 in-flight request limit",
            ));
        }
    };
    let mut settings = state.settings.read().unwrap().clone();
    let id = state.start(&req, &peer, tls, &settings, process.as_ref());
    let mut capture = PendingRequest {
        state: state.clone(),
        id,
        returned: false,
    };
    let actions = if req.extensions().get::<SkipRules>().is_some() {
        Vec::new()
    } else {
        crate::rules::actions(
            &settings.rules,
            &req.uri().to_string(),
            req.method().as_str(),
        )
    };
    crate::rules::simulation(&actions, &mut settings, &state, id);
    let req = req.map(|body| {
        CaptureBody::wrap(
            body,
            state.clone(),
            id,
            Capture::OriginalRequest,
            settings.capture_bytes,
            lease.clone(),
        )
    });
    let mut result = forward_inner(req, state.clone(), id, settings, actions, lease, client).await;
    if let Ok(res) = &mut result {
        res.extensions_mut().insert(CaptureId(id));
    }
    if let Err(error) = &result {
        crate::rules::fail(&state, id, error);
    }
    capture.returned = true;
    result
}

struct PendingRequest {
    state: Arc<App>,
    id: Option<u64>,
    returned: bool,
}
impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.returned {
            self.state.update(self.id, |flow| {
                flow.phase = "error".into();
                flow.error = Some("request cancelled before a response was returned".into());
                flow.duration_ms = Some(store::now_ms().saturating_sub(flow.started_at));
            });
        }
    }
}

async fn forward_inner(
    req: Request<ProxyBody>,
    state: Arc<App>,
    id: Option<u64>,
    settings: Settings,
    actions: Vec<crate::rules::MatchedAction>,
    lease: Arc<tokio::sync::OwnedSemaphorePermit>,
    client: Option<Upstream>,
) -> Result<Response<ProxyBody>> {
    if !settings.offline {
        crate::simulation::check(&settings)?;
    }
    let client_head = req.method() == Method::HEAD;
    let (mut req, local) = crate::rules::request(req, &actions, &state, id).await?;
    let local = if settings.offline {
        Some(response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Offline simulation",
        ))
    } else {
        local
    };
    if local.is_none() {
        ensure!(
            settings.drop_upload_after_bytes != Some(0),
            "simulated connection drop before upload"
        );
    }
    let upstream_head = req.method() == Method::HEAD;
    let head = client_head || upstream_head;
    let method = req.method().to_string();
    let url = req.uri().to_string();
    let upgrade = req.headers().contains_key("upgrade");
    let accepts_trailers = req
        .headers()
        .get_all("te")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("trailers"))
        });
    strip_hop_headers(req.headers_mut(), upgrade);
    if accepts_trailers {
        req.headers_mut().insert("te", "trailers".parse()?);
    }
    ensure!(req.uri().authority().is_some(), "missing authority");
    // Hyper supplies Host for HTTP/1 and :authority for HTTP/2. Duplicate headers cause failures with some origins.
    req.headers_mut().remove("host");
    if settings.no_cache {
        for name in [
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
            "if-range",
        ] {
            req.headers_mut().remove(name);
        }
        req.headers_mut()
            .insert("cache-control", "no-cache, no-store".parse()?);
    }
    if settings.block_cookies {
        req.headers_mut().remove("cookie");
    }
    state.update(id, |f| {
        f.request.headers = store::headers(req.headers());
        f.upstream_url = req.uri().to_string();
        f.metadata.upstream_method = req.method().to_string();
    });
    let (mut parts, body) = req.into_parts();
    // Let the upstream connector negotiate HTTP/2 independently of the client protocol.
    parts.version = hyper::Version::HTTP_11;
    let body = crate::mirror::wrap(body, &actions, state.clone(), id, "request").await;
    if settings.latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(settings.latency_ms)).await;
    }
    let (body, upload) = crate::simulation::body(body, &state.simulation, &settings, true);
    let req = Request::from_parts(
        parts,
        CaptureBody::wrap(
            body,
            state.clone(),
            id,
            Capture::Request,
            settings.capture_bytes,
            lease.clone(),
        ),
    );
    let res = if let Some(local) = local {
        let mut body = req.into_body();
        crate::simulation::headers(
            async {
                while let Some(frame) = body.frame().await {
                    frame.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                }
                Ok::<_, anyhow::Error>(())
            },
            upload,
        )
        .await?;
        local
    } else {
        let client = client.unwrap_or_else(|| state.client.read().unwrap().clone());
        let res = crate::simulation::headers(
            async { client.request(req).await.map_err(anyhow::Error::new) },
            upload,
        )
        .await?;
        let connection = res
            .extensions()
            .get::<crate::connector::Capture>()
            .map(|capture| capture.details());
        state.update(id, |flow| {
            flow.metadata.connection = connection;
            flow.metadata.upstream_protocol = format!("{:?}", res.version());
        });
        res.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed())
    };
    state.update(id, |f| {
        f.status = Some(res.status().as_u16());
        f.headers_received_ms = Some(store::now_ms().saturating_sub(f.started_at));
        f.phase = "receiving".into();
        f.response = Some(Message {
            headers: store::headers(res.headers()),
            ..Default::default()
        });
    });
    state.update(id, |f| {
        f.metadata.original_status = Some(res.status().as_u16());
        f.metadata.original_response = Some(Message {
            headers: store::headers(res.headers()),
            ..Default::default()
        });
    });
    let res = res.map(|body| {
        CaptureBody::wrap(
            body,
            state.clone(),
            id,
            Capture::OriginalResponse,
            settings.capture_bytes,
            lease.clone(),
        )
    });
    let mut res = crate::rules::response(res, &actions, head, &state, id, &method, &url).await?;
    let upgraded = res.status() == StatusCode::SWITCHING_PROTOCOLS;
    strip_hop_headers(res.headers_mut(), upgraded);
    if settings.no_cache {
        res.headers_mut()
            .insert("cache-control", "no-cache, no-store".parse()?);
        res.headers_mut().remove("expires");
    }
    if settings.block_cookies {
        res.headers_mut().remove("set-cookie");
    }
    if head
        || matches!(
            res.status(),
            StatusCode::NO_CONTENT
                | StatusCode::RESET_CONTENT
                | StatusCode::NOT_MODIFIED
                | StatusCode::SWITCHING_PROTOCOLS
        )
    {
        if matches!(
            res.status(),
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::SWITCHING_PROTOCOLS
        ) {
            res.headers_mut().remove("content-length");
        }
        res.headers_mut().remove("trailer");
        if res.status() == StatusCode::RESET_CONTENT || (upstream_head && !client_head) {
            res.headers_mut().insert("content-length", "0".parse()?);
        }
        *res.body_mut() = full(Bytes::new());
    }
    state.update(id, |f| {
        f.status = Some(res.status().as_u16());
        if let Some(r) = &mut f.response {
            r.headers = store::headers(res.headers());
        }
    });
    let (parts, body) = res.into_parts();
    let body = crate::mirror::wrap(body, &actions, state.clone(), id, "response").await;
    let (body, _) = crate::simulation::body(body, &state.simulation, &settings, false);
    Ok(Response::from_parts(
        parts,
        CaptureBody::wrap(
            body,
            state,
            id,
            Capture::Response,
            settings.capture_bytes,
            lease,
        ),
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    Request,
    Response,
    OriginalRequest,
    OriginalResponse,
}
impl Capture {
    fn message(self, flow: &mut Flow) -> Option<&mut Message> {
        match self {
            Self::Request => Some(&mut flow.request),
            Self::Response => flow.response.as_mut(),
            Self::OriginalRequest => flow.metadata.original_request.as_mut(),
            Self::OriginalResponse => flow.metadata.original_response.as_mut(),
        }
    }
}

struct CaptureBody {
    inner: ProxyBody,
    state: Arc<App>,
    id: Option<u64>,
    capture: Capture,
    limit: usize,
    done: bool,
    _lease: Arc<tokio::sync::OwnedSemaphorePermit>,
}

impl CaptureBody {
    fn wrap(
        inner: ProxyBody,
        state: Arc<App>,
        id: Option<u64>,
        capture: Capture,
        limit: usize,
        lease: Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> ProxyBody {
        let mut body = Self {
            inner,
            state,
            id,
            capture,
            limit,
            done: false,
            _lease: lease,
        };
        if body.inner.is_end_stream() {
            body.finish(None);
        }
        body.boxed()
    }

    fn finish(&mut self, error: Option<String>) {
        if self.done {
            return;
        }
        self.done = true;
        self.state.update(self.id, |f| {
            let msg = self.capture.message(f);
            if let Some(msg) = msg {
                msg.body.complete = error.is_none();
            }
            if self.capture == Capture::Response {
                f.duration_ms = Some(store::now_ms().saturating_sub(f.started_at));
                f.phase = if error.is_some() { "error" } else { "complete" }.into();
                f.error = error;
            }
        });
    }

    fn record(&mut self, frame: &Frame<Bytes>) {
        self.state.update(self.id, |f| {
            let msg = self.capture.message(f);
            if let Some(msg) = msg {
                if let Some(data) = frame.data_ref() {
                    let limit = self
                        .limit
                        .min(self.state.settings.read().unwrap().capture_bytes);
                    msg.body.append(data, limit);
                }
                if let Some(trailers) = frame.trailers_ref() {
                    msg.trailers = store::headers(trailers);
                }
            }
        });
    }
}

impl Body for CaptureBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.record(&frame);
                if frame.trailers_ref().is_some() || self.inner.is_end_stream() {
                    self.finish(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish(Some(error.to_string()));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CaptureBody {
    fn drop(&mut self) {
        if !self.done {
            self.finish(Some("body transfer interrupted".into()));
        }
    }
}

fn setup(req: &Request<Incoming>, state: &App, local: std::net::IpAddr) -> Response<ProxyBody> {
    if req.method() != Method::GET {
        return response(StatusCode::METHOD_NOT_ALLOWED, "GET required");
    }
    let (mime, data) = match req.uri().path() {
        "/proxy.pac" => (
            "application/x-ns-proxy-autoconfig",
            Bytes::from(crate::network::pac(local, state.proxy_addr.port(), None)),
        ),
        "/socks.pac" => {
            let Some(socks) = state.socks_addr else {
                return response(
                    StatusCode::NOT_FOUND,
                    "start OpenProxy with --socks to use this PAC file",
                );
            };
            let Some(host) = crate::network::advertised_socks(socks, local) else {
                return response(
                    StatusCode::BAD_REQUEST,
                    "SOCKS is bound to loopback; use a LAN or wildcard --socks address for a device PAC file",
                );
            };
            (
                "application/x-ns-proxy-autoconfig",
                Bytes::from(crate::network::pac(
                    host,
                    state.proxy_addr.port(),
                    Some(socks.port()),
                )),
            )
        }
        "/ca.cer" => (
            "application/x-x509-ca-cert",
            Bytes::copy_from_slice(state.ca.der.as_ref()),
        ),
        "/ca.pem" => (
            "application/x-pem-file",
            Bytes::copy_from_slice(state.ca.pem.as_bytes()),
        ),
        "/" => (
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("../web/setup.html")),
        ),
        _ => {
            return response(
                StatusCode::NOT_FOUND,
                "Use http://openproxy.local/ through this proxy for certificate setup",
            );
        }
    };
    Response::builder()
        .header("content-type", mime)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(full(data))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acl_and_hop_headers() {
        assert!(allowed("127.0.0.1".parse().unwrap(), &[]));
        assert!(allowed("::ffff:127.0.0.1".parse().unwrap(), &[]));
        assert!(!allowed("192.168.1.2".parse().unwrap(), &[]));
        assert!(allowed(
            "192.168.1.2".parse().unwrap(),
            &["192.168.1.0/24".parse().unwrap()]
        ));
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive, x-private".parse().unwrap());
        headers.insert("x-private", "secret".parse().unwrap());
        headers.insert("proxy-authorization", "secret".parse().unwrap());
        headers.insert("set-cookie", "a=b".parse().unwrap());
        strip_hop_headers(&mut headers, false);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("set-cookie"));
    }
    #[test]
    fn authority_binding() {
        let req = Request::builder()
            .uri("https://evil.test/path")
            .body(())
            .unwrap();
        let route = Route {
            origin: "https://good.test:443/".parse().unwrap(),
            locked: true,
            tls: true,
        };
        assert!(absolute_uri(&req, Some(&route)).is_err());
        let equivalent = Request::builder()
            .uri("https://GOOD.TEST/path")
            .body(())
            .unwrap();
        assert!(absolute_uri(&equivalent, Some(&route)).is_ok());
        let req = Request::builder().uri("/hello?q=1").body(()).unwrap();
        let route = Route {
            origin: "https://[::1]:443/".parse().unwrap(),
            locked: true,
            tls: true,
        };
        assert_eq!(
            absolute_uri(&req, Some(&route)).unwrap().to_string(),
            "https://[::1]:443/hello?q=1"
        );
    }

    #[tokio::test]
    async fn request_limit_lasts_until_response_is_dropped() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            rules: vec![crate::rules::Rule {
                name: "mock".into(),
                enabled: true,
                url: "*".into(),
                method: None,
                actions: vec![crate::rules::Action::Mock {
                    status: 200,
                    headers: vec![],
                    body: "pending body".into(),
                }],
            }],
            ..Default::default()
        };
        let addr = "127.0.0.1:0".parse().unwrap();
        let state = Arc::new(
            App::new(
                Authority::load(dir.path()).unwrap(),
                settings,
                dir.path().to_owned(),
                crate::connector::Options::load(&<crate::Options as clap::Parser>::parse_from([
                    "openproxy",
                ]))
                .unwrap(),
                addr,
                addr,
                None,
            )
            .unwrap(),
        );
        let req = || {
            Request::builder()
                .uri("http://fixture.invalid/")
                .body(full(Bytes::new()))
                .unwrap()
        };
        let mut held = Vec::new();
        for _ in 0..256 {
            held.push(
                forward(req(), state.clone(), "test".into(), false, None, None)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            forward(req(), state.clone(), "test".into(), false, None, None)
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        held.pop();
        assert_eq!(
            forward(req(), state, "test".into(), false, None, None)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}
