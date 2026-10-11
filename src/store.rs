use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

pub mod binary {
    use super::*;
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct CapturedBody {
    #[serde(with = "binary")]
    pub data: Vec<u8>,
    pub size: u64,
    pub truncated: bool,
    pub complete: bool,
}

impl CapturedBody {
    pub fn append(&mut self, bytes: &[u8], limit: usize) {
        self.size += bytes.len() as u64;
        let keep = bytes.len().min(limit.saturating_sub(self.data.len()));
        self.data.extend_from_slice(&bytes[..keep]);
        self.truncated |= keep < bytes.len();
    }
}

pub type Headers = Vec<[String; 2]>;

pub fn headers(map: &HeaderMap) -> Headers {
    map.iter()
        .map(|(name, value)| {
            [
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            ]
        })
        .collect()
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Message {
    pub headers: Headers,
    pub trailers: Headers,
    pub body: CapturedBody,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Metadata {
    pub process: Option<crate::process::ClientProcess>,
    pub note: String,
    pub marked: bool,
    pub original_request: Option<Message>,
    pub original_response: Option<Message>,
    pub original_status: Option<u16>,
    pub upstream_method: String,
    pub actions: Vec<ActionTrace>,
    pub actions_truncated: bool,
    pub mirrors: Vec<Mirror>,
    pub websocket: Option<crate::websocket::Capture>,
    pub connection: Option<crate::connector::ConnectionDetails>,
    pub client_tls: Option<crate::connector::TlsDetails>,
    pub upstream_protocol: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Mirror {
    pub phase: String,
    pub path: String,
    pub bytes: u64,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ActionTrace {
    pub rule: String,
    pub index: usize,
    pub action: String,
    pub phase: String,
    pub applied: bool,
    pub changed: Option<bool>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Flow {
    pub id: u64,
    pub url: String,
    pub upstream_url: String,
    pub method: String,
    pub client: String,
    pub protocol: String,
    pub tls: bool,
    pub started_at: u64,
    pub headers_received_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub phase: String,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub request: Message,
    pub response: Option<Message>,
    #[serde(default)]
    pub metadata: Metadata,
}

pub const RETENTION_LIMIT: usize = 300 * 1024 * 1024;

impl Flow {
    pub fn messages(&self) -> impl Iterator<Item = &Message> {
        std::iter::once(&self.request)
            .chain(self.response.iter())
            .chain(self.metadata.original_request.iter())
            .chain(self.metadata.original_response.iter())
    }

    // Include JSON escaping, base64, and memory allocation overhead without a copy of retained bodies.
    fn retained_bytes(&self) -> usize {
        let text = |s: &str| s.len().saturating_mul(6);
        let mut bytes = 8192
            + [
                &self.url,
                &self.upstream_url,
                &self.method,
                &self.client,
                &self.protocol,
                &self.phase,
                &self.metadata.note,
                &self.metadata.upstream_method,
            ]
            .into_iter()
            .map(|s| text(s))
            .sum::<usize>();
        bytes += self.error.as_deref().map_or(0, text);
        for message in self.messages() {
            bytes += message.body.data.len().div_ceil(3) * 4;
            for [name, value] in message.headers.iter().chain(&message.trailers) {
                bytes += 64 + text(name) + text(value);
            }
        }
        for action in &self.metadata.actions {
            bytes += 256 + text(&action.rule) + text(&action.action) + text(&action.phase);
        }
        for mirror in &self.metadata.mirrors {
            bytes += 256
                + text(&mirror.phase)
                + text(&mirror.path)
                + mirror.error.as_deref().map_or(0, text);
        }
        if let Some(process) = &self.metadata.process {
            bytes += 128 + text(&process.name);
        }
        bytes += text(&self.metadata.upstream_protocol);
        let tls_bytes = |tls: &crate::connector::TlsDetails| {
            512 + [
                &tls.protocol,
                &tls.cipher,
                &tls.alpn,
                &tls.server_name,
                &tls.certificate_subject,
                &tls.certificate_issuer,
                &tls.certificate_expires,
            ]
            .into_iter()
            .map(|s| text(s))
            .sum::<usize>()
        };
        if let Some(tls) = &self.metadata.client_tls {
            bytes += tls_bytes(tls);
        }
        if let Some(connection) = &self.metadata.connection {
            bytes += 512
                + text(&connection.id)
                + text(&connection.local_address)
                + text(&connection.remote_address)
                + connection.proxy.as_deref().map_or(0, text);
            bytes += connection.tls.as_ref().map_or(0, tls_bytes);
            bytes += connection.proxy_tls.as_ref().map_or(0, tls_bytes);
        }
        if let Some(ws) = &self.metadata.websocket {
            bytes += 512 + text(&ws.extensions) + ws.error.as_deref().map_or(0, text);
            for frame in &ws.frames {
                bytes += 512
                    + frame.payload.len().div_ceil(3) * 4
                    + text(&frame.direction)
                    + frame.error.as_deref().map_or(0, text);
            }
        }
        bytes
    }

    pub fn messages_mut(&mut self) -> impl Iterator<Item = &mut Message> {
        std::iter::once(&mut self.request)
            .chain(self.response.iter_mut())
            .chain(self.metadata.original_request.iter_mut())
            .chain(self.metadata.original_response.iter_mut())
    }
}

#[derive(Serialize)]
pub struct Summary<'a> {
    pub id: u64,
    pub url: &'a str,
    pub method: &'a str,
    pub client: &'a str,
    pub protocol: &'a str,
    pub tls: bool,
    pub started_at: u64,
    pub duration_ms: Option<u64>,
    pub phase: &'a str,
    pub status: Option<u16>,
    pub error: &'a Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub content_type: Option<&'a str>,
    pub marked: bool,
    pub has_note: bool,
}

impl Flow {
    pub fn summary(&self) -> Summary<'_> {
        Summary {
            id: self.id,
            url: &self.url,
            method: &self.method,
            client: &self.client,
            protocol: &self.protocol,
            tls: self.tls,
            started_at: self.started_at,
            duration_ms: self.duration_ms,
            phase: &self.phase,
            status: self.status,
            error: &self.error,
            request_bytes: self.request.body.size,
            response_bytes: self.response.as_ref().map_or(0, |r| r.body.size),
            content_type: self
                .response
                .as_ref()
                .and_then(|r| r.headers.iter().find(|h| h[0] == "content-type"))
                .map(|h| h[1].as_str()),
            marked: self.metadata.marked,
            has_note: !self.metadata.note.is_empty(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Session {
    pub version: u32,
    pub flows: VecDeque<Flow>,
}

pub struct Store {
    pub flows: VecDeque<Flow>,
    next_id: u64,
    pub retained_bytes: usize,
    pub evicted_flows: u64,
}

impl Store {
    pub fn load(path: &Path, settings: &crate::config::Settings) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                flows: VecDeque::new(),
                next_id: 1,
                retained_bytes: 0,
                evicted_flows: 0,
            });
        }
        ensure!(
            std::fs::metadata(path)?.len() <= 400 * 1024 * 1024,
            "session exceeds 400 MiB"
        );
        let session: Session = serde_json::from_slice(&std::fs::read(path)?)?;
        Self::from_session(session, settings)
    }

    pub fn from_session(mut session: Session, settings: &crate::config::Settings) -> Result<Self> {
        ensure!(session.version == 1, "unsupported session version");
        while session.flows.len() > settings.max_flows {
            session.flows.pop_front();
        }
        let mut next_id = 1;
        for flow in &mut session.flows {
            ensure!(
                flow.metadata
                    .process
                    .as_ref()
                    .is_none_or(|process| process.name.len() <= 256),
                "invalid process name"
            );
            ensure!(
                flow.metadata.upstream_protocol.len() <= 64,
                "invalid upstream protocol"
            );
            if let Some(connection) = &flow.metadata.connection {
                ensure!(
                    serde_json::to_vec(connection)?.len() <= 64 * 1024,
                    "connection metadata exceeds 64 KiB"
                );
            }
            if let Some(tls) = &flow.metadata.client_tls {
                ensure!(
                    serde_json::to_vec(tls)?.len() <= 32 * 1024,
                    "client TLS metadata exceeds 32 KiB"
                );
            }
            ensure!(flow.metadata.note.len() <= 8192, "note exceeds 8 KiB");
            ensure!(
                flow.metadata.actions.len() <= 256,
                "at most 256 action records"
            );
            ensure!(flow.metadata.mirrors.len() <= 16, "too many mirror records");
            if let Some(ws) = &flow.metadata.websocket {
                ws.validate()?;
            }
            for action in &flow.metadata.actions {
                ensure!(
                    action.rule.len() <= 200
                        && action.action.len() <= 64
                        && action.phase.len() <= 32,
                    "invalid action record"
                );
            }
            flow.id = next_id;
            next_id += 1;
            if flow.duration_ms.is_none() {
                flow.phase = "interrupted".into();
            }
            for msg in flow.messages_mut() {
                ensure!(
                    msg.body.size >= msg.body.data.len() as u64,
                    "invalid body size"
                );
                msg.body.data.truncate(settings.capture_bytes);
                msg.body.truncated |= msg.body.size > msg.body.data.len() as u64;
            }
        }
        let mut store = Self {
            retained_bytes: session.flows.iter().map(Flow::retained_bytes).sum(),
            flows: session.flows,
            next_id,
            evicted_flows: 0,
        };
        store.trim_bytes(RETENTION_LIMIT);
        Ok(store)
    }

    pub fn add(&mut self, mut flow: Flow, max: usize) -> u64 {
        flow.id = self.next_id;
        self.next_id += 1;
        let id = flow.id;
        while self.flows.len() >= max {
            self.evict_oldest();
        }
        self.retained_bytes += flow.retained_bytes();
        self.flows.push_back(flow);
        self.trim_bytes(RETENTION_LIMIT);
        id
    }

    pub fn update<T>(&mut self, id: u64, change: impl FnOnce(&mut Flow) -> T) -> Option<T> {
        let flow = self.flows.iter_mut().find(|f| f.id == id)?;
        self.retained_bytes -= flow.retained_bytes();
        let result = change(flow);
        self.retained_bytes += flow.retained_bytes();
        self.trim_bytes(RETENTION_LIMIT);
        Some(result)
    }

    fn evict_oldest(&mut self) {
        if let Some(flow) = self.flows.pop_front() {
            self.retained_bytes -= flow.retained_bytes();
            self.evicted_flows += 1;
        }
    }

    fn trim_bytes(&mut self, limit: usize) {
        while self.retained_bytes > limit {
            self.evict_oldest();
        }
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.retained_bytes = 0;
        self.evicted_flows = 0;
    }

    pub fn remove(&mut self, id: u64) {
        if let Some(index) = self.flows.iter().position(|flow| flow.id == id) {
            self.retained_bytes -= self.flows.remove(index).unwrap().retained_bytes();
        }
    }

    pub fn resize(&mut self, settings: &crate::config::Settings) {
        while self.flows.len() > settings.max_flows {
            self.evict_oldest();
        }
        for flow in &mut self.flows {
            for msg in flow.messages_mut() {
                msg.body.data.truncate(settings.capture_bytes);
                msg.body.truncated |= msg.body.size > msg.body.data.len() as u64;
            }
        }
        self.retained_bytes = self.flows.iter().map(Flow::retained_bytes).sum();
        self.trim_bytes(RETENTION_LIMIT);
    }
    pub fn get(&self, id: u64) -> Option<&Flow> {
        self.flows.iter().find(|f| f.id == id)
    }
    pub fn replace(&mut self, mut replacement: Store) {
        // Keep IDs unique because active transfers can still update their previous captures.
        for flow in &mut replacement.flows {
            flow.id = self.next_id;
            self.next_id += 1;
        }
        self.flows = replacement.flows;
        self.retained_bytes = replacement.retained_bytes;
        self.evicted_flows = replacement.evicted_flows;
    }
    pub fn session_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct BorrowedSession<'a> {
            version: u32,
            flows: &'a VecDeque<Flow>,
        }
        Ok(serde_json::to_vec(&BorrowedSession {
            version: 1,
            flows: &self.flows,
        })?)
    }
}

pub fn har(store: &Store) -> serde_json::Value {
    use serde_json::json;
    let hs = |headers: &Headers| {
        headers
            .iter()
            .map(|h| json!({"name":h[0],"value":h[1]}))
            .collect::<Vec<_>>()
    };
    let tcp = |flow: &&Flow| flow.url.starts_with("tcp:");
    let opaque = store.flows.iter().filter(tcp).collect::<Vec<_>>();
    let entries: Vec<_> = store.flows.iter().filter(|flow| !tcp(flow)).map(|flow| {
        let response = flow.response.as_ref();
        let protocol = if flow.metadata.upstream_protocol.is_empty() { &flow.protocol } else { &flow.metadata.upstream_protocol };
        let mime = response.and_then(|m| m.headers.iter().find(|h| h[0] == "content-type")).map_or("", |h| &h[1]);
        let datetime = time::OffsetDateTime::from_unix_timestamp_nanos(flow.started_at as i128 * 1_000_000)
            .ok().and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()).unwrap_or_default();
        json!({
            "startedDateTime": datetime, "time": flow.duration_ms.unwrap_or(0),
            "request": {"method": if flow.metadata.upstream_method.is_empty() { &flow.method } else { &flow.metadata.upstream_method },
                "url": if flow.upstream_url.is_empty() { &flow.url } else { &flow.upstream_url }, "httpVersion": protocol,
                "cookies": [], "headers": hs(&flow.request.headers), "queryString": [], "headersSize": -1,
                "bodySize": flow.request.body.size,
                "postData": {"mimeType": "application/octet-stream", "text": STANDARD.encode(&flow.request.body.data), "_encoding": "base64"}},
            "response": {"status": flow.status.unwrap_or(0), "statusText": "", "httpVersion": protocol,
                "cookies": [], "headers": response.map(|r| hs(&r.headers)).unwrap_or_default(),
                "content": {"size": response.map_or(0, |r| r.body.size), "mimeType": mime,
                    "text": response.map(|r| STANDARD.encode(&r.body.data)).unwrap_or_default(), "encoding": "base64"},
                "redirectURL": "", "headersSize": -1, "bodySize": response.map_or(0, |r| r.body.size)},
            "cache": {}, "timings": {"send": 0, "wait": flow.headers_received_ms.unwrap_or(0),
                "receive": flow.duration_ms.unwrap_or(0).saturating_sub(flow.headers_received_ms.unwrap_or(0))},
            "_openproxy": {"id": flow.id, "originalUrl": flow.url, "originalMethod": flow.method, "protocol": flow.protocol, "metadata": flow.metadata, "requestTrailers": flow.request.trailers,
                "responseTrailers": response.map(|r| &r.trailers), "requestTruncated": flow.request.body.truncated,
                "responseTruncated": response.is_some_and(|r| r.body.truncated), "error": flow.error,
                "requestComplete": flow.request.body.complete, "responseComplete": response.is_some_and(|r| r.body.complete)}
        })
    }).collect();
    json!({"log": {"version": "1.2", "creator": {"name": "OpenProxy", "version": env!("CARGO_PKG_VERSION")}, "entries": entries, "_openproxy_tcp": opaque}})
}

pub fn import_har(value: serde_json::Value, settings: &crate::config::Settings) -> Result<Store> {
    use serde_json::Value;
    let entries = value
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("HAR log.entries must be an array"))?;
    let mut flows = VecDeque::new();
    for entry in entries.iter().rev().take(settings.max_flows).rev() {
        let request = entry
            .get("request")
            .ok_or_else(|| anyhow::anyhow!("HAR entry is missing request"))?;
        let response = entry.get("response");
        let url = required_text(request, "url")?.to_owned();
        let uri: hyper::Uri = url.parse()?;
        ensure!(
            matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some(),
            "HAR request URL must be absolute HTTP(S)"
        );
        let method = required_text(request, "method")?.to_owned();
        method.parse::<hyper::Method>()?;
        let original_url = entry
            .pointer("/_openproxy/originalUrl")
            .and_then(Value::as_str)
            .unwrap_or(&url)
            .to_owned();
        let original_uri: hyper::Uri = original_url.parse()?;
        ensure!(
            matches!(original_uri.scheme_str(), Some("http" | "https"))
                && original_uri.host().is_some(),
            "original HAR URL must be absolute HTTP(S)"
        );
        let original_method = entry
            .pointer("/_openproxy/originalMethod")
            .and_then(Value::as_str)
            .unwrap_or(&method)
            .to_owned();
        original_method.parse::<hyper::Method>()?;
        let mut metadata: Metadata = entry
            .pointer("/_openproxy/metadata")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .unwrap_or_default();
        if metadata.upstream_method.is_empty() {
            metadata.upstream_method = method;
        }
        let started_at = entry
            .get("startedDateTime")
            .and_then(Value::as_str)
            .and_then(|v| {
                time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339).ok()
            })
            .map_or(now_ms(), |t| {
                (t.unix_timestamp_nanos().max(0) / 1_000_000) as u64
            });
        let mut req_message = har_message(request, true)?;
        let mut res_message = response.map(|r| har_message(r, false)).transpose()?;
        if let Some(metadata) = entry.get("_openproxy") {
            req_message.trailers = har_trailers(metadata.get("requestTrailers"))?;
            if let Some(response) = &mut res_message {
                response.trailers = har_trailers(metadata.get("responseTrailers"))?;
            }
            req_message.body.truncated |= metadata
                .get("requestTruncated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            req_message.body.complete = metadata
                .get("requestComplete")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if let Some(message) = &mut res_message {
                message.body.truncated |= metadata
                    .get("responseTruncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                message.body.complete = metadata
                    .get("responseComplete")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
            }
        }
        let duration = entry
            .get("time")
            .and_then(Value::as_f64)
            .filter(|v| *v >= 0.0)
            .unwrap_or(0.0) as u64;
        let wait = entry
            .pointer("/timings/wait")
            .and_then(Value::as_f64)
            .filter(|v| *v >= 0.0)
            .unwrap_or(0.0) as u64;
        let status = response
            .and_then(|r| r.get("status"))
            .and_then(Value::as_u64);
        ensure!(
            status.is_none_or(|s| s == 0 || (100..=599).contains(&s)),
            "invalid HAR response status"
        );
        flows.push_back(Flow {
            id: entry
                .pointer("/_openproxy/id")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            tls: original_uri.scheme_str() == Some("https"),
            upstream_url: url,
            url: original_url,
            method: original_method,
            client: "HAR import".into(),
            protocol: entry
                .pointer("/_openproxy/protocol")
                .and_then(Value::as_str)
                .or_else(|| request.get("httpVersion").and_then(Value::as_str))
                .unwrap_or("HTTP/1.1")
                .into(),
            started_at,
            headers_received_ms: Some(wait.min(duration)),
            duration_ms: Some(duration),
            phase: "imported".into(),
            status: status.filter(|s| *s != 0).map(|s| s as u16),
            error: entry
                .pointer("/_openproxy/error")
                .and_then(Value::as_str)
                .map(str::to_owned),
            request: req_message,
            response: res_message,
            metadata,
        });
    }
    if let Some(opaque) = value.pointer("/log/_openproxy_tcp") {
        let opaque: Vec<Flow> = serde_json::from_value(opaque.clone())?;
        ensure!(opaque.len() <= 10000, "too many opaque HAR records");
        for flow in &opaque {
            let uri: hyper::Uri = flow.url.parse()?;
            ensure!(
                uri.scheme_str() == Some("tcp")
                    && uri.host().is_some()
                    && uri.port_u16().is_some()
                    && flow.protocol == "TCP tunnel"
                    && matches!(flow.method.as_str(), "CONNECT" | "TCP" | "SOCKS"),
                "invalid opaque HAR record"
            );
        }
        flows.extend(opaque);
        flows.make_contiguous().sort_by_key(|flow| flow.id);
    }
    Store::from_session(Session { version: 1, flows }, settings)
}

fn har_trailers(value: Option<&serde_json::Value>) -> Result<Headers> {
    let headers: Headers = value
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?
        .unwrap_or_default();
    ensure!(headers.len() <= 256, "HAR message has too many trailers");
    for [name, value] in &headers {
        ensure!(value.len() <= 64 * 1024, "HAR trailer is too large");
        name.parse::<hyper::header::HeaderName>()?;
        value.parse::<hyper::header::HeaderValue>()?;
    }
    Ok(headers)
}

fn required_text<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("HAR {field} must be a string"))
}

fn har_message(value: &serde_json::Value, request: bool) -> Result<Message> {
    use serde_json::Value;
    let mut headers = Vec::new();
    if let Some(array) = value.get("headers").and_then(Value::as_array) {
        ensure!(array.len() <= 256, "HAR message has too many headers");
        for h in array {
            let name = required_text(h, "name")?;
            let text = required_text(h, "value")?;
            ensure!(text.len() <= 64 * 1024, "HAR header is too large");
            name.parse::<hyper::header::HeaderName>()?;
            text.parse::<hyper::header::HeaderValue>()?;
            headers.push([name.to_owned(), text.to_owned()]);
        }
    }
    let content = value.get(if request { "postData" } else { "content" });
    let text = content
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let encoding = content
        .and_then(|c| c.get(if request { "_encoding" } else { "encoding" }))
        .and_then(Value::as_str);
    let data = match encoding {
        Some("base64") => STANDARD.decode(text)?,
        Some(other) => anyhow::bail!("unsupported HAR body encoding: {other}"),
        None => text.as_bytes().to_vec(),
    };
    let recorded_size = if request {
        value.get("bodySize")
    } else {
        content.and_then(|c| c.get("size"))
    }
    .and_then(Value::as_u64)
    .unwrap_or(data.len() as u64);
    let size = recorded_size.max(data.len() as u64);
    Ok(Message {
        headers,
        trailers: vec![],
        body: CapturedBody {
            truncated: size > data.len() as u64,
            complete: true,
            size,
            data,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_tracks_snapshots_updates_eviction_and_replacement() {
        let settings = crate::config::Settings::default();
        let mut store = Store::from_session(
            Session {
                version: 1,
                flows: VecDeque::new(),
            },
            &settings,
        )
        .unwrap();
        let mut flow = Flow::default();
        flow.metadata.original_request = Some(Message::default());
        flow.metadata.original_response = Some(Message::default());
        flow.response = Some(Message::default());
        flow.metadata.connection = Some(crate::connector::ConnectionDetails {
            tls: Some(crate::connector::TlsDetails {
                certificate_subject: "\u{0000}\n".repeat(1000),
                ..Default::default()
            }),
            ..Default::default()
        });
        flow.metadata.websocket = Some(crate::websocket::Capture {
            frames: vec![crate::websocket::Frame {
                direction: "client".into(),
                at: 1,
                opcode: 2,
                fin: true,
                masked: true,
                compressed: false,
                message: 1,
                size: 100,
                payload: vec![255; 100],
                truncated: false,
                complete: true,
                error: None,
            }],
            ..Default::default()
        });
        for message in flow.messages_mut() {
            message.body.append(&[255; 100], 100);
            message
                .headers
                .push(["x-escaped".into(), "\u{0000}\n\\\"".repeat(100)]);
        }
        let first = store.add(flow.clone(), 100);
        let second = store.add(flow, 100);
        store.update(second, |flow| flow.metadata.note = "a note".into());
        assert!(store.retained_bytes >= store.session_bytes().unwrap().len());
        let latest_bytes = store.get(second).unwrap().retained_bytes();
        store.trim_bytes(latest_bytes);
        assert!(store.get(first).is_none());
        assert_eq!(store.evicted_flows, 1);
        assert_eq!(store.retained_bytes, latest_bytes);
        assert!(
            store
                .update(first, |_| panic!("evicted flow changed"))
                .is_none()
        );
        store.remove(second);
        assert_eq!(store.retained_bytes, 0);
        let replacement = Store::from_session(
            Session {
                version: 1,
                flows: VecDeque::from([Flow::default()]),
            },
            &settings,
        )
        .unwrap();
        store.replace(replacement);
        assert!(store.flows[0].id > second);
        store.clear();
        assert_eq!(store.retained_bytes, 0);
        assert_eq!(store.evicted_flows, 0);
        assert!(store.add(Flow::default(), 1) > second);
    }

    #[test]
    fn session_import_bounds_connection_metadata() {
        let mut flow = Flow::default();
        flow.metadata.connection = Some(crate::connector::ConnectionDetails {
            remote_address: "x".repeat(64 * 1024),
            ..Default::default()
        });
        assert!(
            Store::from_session(
                Session {
                    version: 1,
                    flows: VecDeque::from([flow])
                },
                &crate::config::Settings::default()
            )
            .is_err()
        );
        let mut flow = Flow::default();
        flow.metadata.process = Some(crate::process::ClientProcess {
            pid: 1,
            name: "x".repeat(257),
        });
        assert!(
            Store::from_session(
                Session {
                    version: 1,
                    flows: VecDeque::from([flow])
                },
                &crate::config::Settings::default()
            )
            .is_err()
        );
    }

    #[test]
    fn har_keeps_forwarded_messages_original_identity_and_opaque_records() {
        let settings = crate::config::Settings::default();
        let mut store = Store::from_session(
            Session {
                version: 1,
                flows: VecDeque::new(),
            },
            &settings,
        )
        .unwrap();
        let mut flow = Flow {
            method: "POST".into(),
            url: "http://original.test/before".into(),
            upstream_url: "https://forwarded.test/after".into(),
            duration_ms: Some(1),
            ..Default::default()
        };
        flow.metadata.upstream_method = "PUT".into();
        flow.metadata.upstream_protocol = "HTTP/2.0".into();
        flow.request.trailers = vec![["x-request-end".into(), "yes".into()]];
        flow.response = Some(Message {
            trailers: vec![["x-response-end".into(), "yes".into()]],
            ..Default::default()
        });
        flow.request.body = CapturedBody {
            data: vec![0, 255],
            size: 2,
            complete: true,
            truncated: false,
        };
        flow.metadata.original_request = Some(Message {
            body: CapturedBody {
                data: b"original".to_vec(),
                size: 8,
                complete: true,
                truncated: false,
            },
            ..Default::default()
        });
        store.add(flow, 100);
        store.add(
            Flow {
                method: "CONNECT".into(),
                url: "tcp://127.0.0.1:9000/".into(),
                protocol: "TCP tunnel".into(),
                duration_ms: Some(1),
                ..Default::default()
            },
            100,
        );
        let mut exported = har(&store);
        assert_eq!(exported["log"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(exported["log"]["entries"][0]["request"]["method"], "PUT");
        assert_eq!(
            exported["log"]["entries"][0]["request"]["url"],
            "https://forwarded.test/after"
        );
        let restored = import_har(exported.clone(), &settings).unwrap();
        assert_eq!(restored.flows.len(), 2);
        assert_eq!(restored.flows[0].method, "POST");
        assert_eq!(restored.flows[0].url, "http://original.test/before");
        assert_eq!(
            restored.flows[0].upstream_url,
            "https://forwarded.test/after"
        );
        assert_eq!(restored.flows[0].request.body.data, [0, 255]);
        assert_eq!(
            restored.flows[0].request.trailers,
            store.flows[0].request.trailers
        );
        assert_eq!(
            restored.flows[0].response.as_ref().unwrap().trailers,
            store.flows[0].response.as_ref().unwrap().trailers
        );
        assert_eq!(
            restored.flows[0]
                .metadata
                .original_request
                .as_ref()
                .unwrap()
                .body
                .data,
            b"original"
        );
        assert_eq!(restored.flows[1].url, "tcp://127.0.0.1:9000/");
        let mut invalid = exported.clone();
        invalid["log"]["entries"][0]["_openproxy"]["requestTrailers"] =
            serde_json::json!([["x-inject", "a\r\nb"]]);
        assert!(import_har(invalid, &settings).is_err());
        exported["log"]["_openproxy_tcp"][0]["url"] = "http://invalid.test/".into();
        assert!(import_har(exported, &settings).is_err());
    }

    #[test]
    fn imports_standard_har_and_binary_extension() {
        let settings = crate::config::Settings::default();
        let value = serde_json::json!({"log": {"entries": [{"request": {
            "method": "POST", "url": "https://example.test/", "headers": [],
            "postData": {"text": "AP8=", "_encoding": "base64"}, "bodySize": 2},
            "response": {"status": 200, "headers": [], "content": {"text": "hello", "size": 5}}}]}});
        let store = import_har(value, &settings).unwrap();
        let flow = &store.flows[0];
        assert_eq!(flow.request.body.data, [0, 255]);
        assert_eq!(flow.response.as_ref().unwrap().body.data, b"hello");
        let round_trip = import_har(har(&store), &settings).unwrap();
        assert_eq!(
            round_trip.flows[0].request.body.data,
            flow.request.body.data
        );
        assert!(import_har(serde_json::json!({}), &settings).is_err());
    }
}
