use std::{
    collections::{BTreeMap, VecDeque},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::{Body, Frame, SizeHint},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::{
    proxy::{self, App, BoxError, ProxyBody},
    rules::{self, EDIT_LIMIT},
    store::{self, Headers, Message},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

pub fn default_timeout() -> u64 {
    120_000
}

#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub id: String,
    pub flow_id: Option<u64>,
    pub phase: Phase,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub created_at: u64,
    pub deadline: u64,
    pub headers: Headers,
    pub trailers: Headers,
    #[serde(serialize_with = "store::binary::serialize")]
    pub body: Bytes,
    pub body_complete: bool,
    pub content_length: Option<u64>,
}

#[derive(Serialize)]
pub struct Summary {
    pub id: String,
    pub flow_id: Option<u64>,
    pub phase: Phase,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub created_at: u64,
    pub deadline: u64,
    pub body_bytes: usize,
    pub body_complete: bool,
}

impl Snapshot {
    fn summary(&self) -> Summary {
        Summary {
            id: self.id.clone(),
            flow_id: self.flow_id,
            phase: self.phase,
            method: self.method.clone(),
            url: self.url.clone(),
            status: self.status,
            created_at: self.created_at,
            deadline: self.deadline,
            body_bytes: self.body.len(),
            body_complete: self.body_complete,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Continue,
    Abort,
    Edit {
        #[serde(default)]
        method: Option<String>,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        status: Option<u16>,
        headers: Headers,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        decoded: bool,
        #[serde(default)]
        trailers: Option<Headers>,
    },
}

#[derive(Debug)]
enum Change {
    Continue,
    Abort(&'static str),
    Edit(Box<Edit>),
}

#[derive(Debug)]
struct Edit {
    method: Option<Method>,
    uri: Option<Uri>,
    status: Option<StatusCode>,
    headers: HeaderMap,
    body: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Decision {
    fn validate(self, snapshot: &Snapshot) -> Result<Change> {
        match self {
            Self::Continue => Ok(Change::Continue),
            Self::Abort => Ok(Change::Abort("breakpoint aborted from inspector")),
            Self::Edit {
                method,
                url,
                status,
                headers,
                body,
                decoded,
                trailers,
            } => {
                let mut headers = parse_headers(&headers)?;
                let (method, uri, status) = match snapshot.phase {
                    Phase::Request => {
                        ensure!(
                            status.is_none(),
                            "request edit cannot set a response status"
                        );
                        let method: Method = method
                            .ok_or_else(|| anyhow::anyhow!("request edit requires method"))?
                            .parse()?;
                        ensure!(
                            method != Method::CONNECT,
                            "breakpoint edit cannot create a CONNECT request"
                        );
                        let uri = rules::http_uri(
                            &url.ok_or_else(|| anyhow::anyhow!("request edit requires url"))?,
                        )?;
                        (Some(method), Some(uri), None)
                    }
                    Phase::Response => {
                        ensure!(
                            method.is_none() && url.is_none(),
                            "response edit cannot change request method or URL"
                        );
                        let status = status
                            .ok_or_else(|| anyhow::anyhow!("response edit requires status"))?;
                        ensure!(
                            (200..=599).contains(&status)
                                || status == 101 && snapshot.status == Some(101),
                            "invalid final response status"
                        );
                        (None, None, Some(StatusCode::from_u16(status)?))
                    }
                };
                ensure!(
                    !decoded || body.is_some(),
                    "decoded requires a replacement body"
                );
                ensure!(
                    body.is_none() && trailers.is_none() || snapshot.body_complete,
                    "cannot replace an incomplete or oversized body/trailers; continue or edit headers only"
                );
                let body = body
                    .map(|body| -> Result<Bytes> {
                        ensure!(
                            body.len() <= EDIT_LIMIT.div_ceil(3) * 4,
                            "replacement body exceeds 1 MiB"
                        );
                        let data = STANDARD.decode(body)?;
                        ensure!(data.len() <= EDIT_LIMIT, "replacement body exceeds 1 MiB");
                        if decoded {
                            rules::encode_body(&data, &headers)
                        } else {
                            Ok(Bytes::from(data))
                        }
                    })
                    .transpose()?;
                let trailers = trailers
                    .map(|headers| parse_trailers(&headers))
                    .transpose()?;
                if snapshot.phase == Phase::Response
                    && (snapshot.method == "HEAD"
                        || status.is_some_and(|s| {
                            matches!(
                                s,
                                StatusCode::SWITCHING_PROTOCOLS
                                    | StatusCode::NO_CONTENT
                                    | StatusCode::RESET_CONTENT
                                    | StatusCode::NOT_MODIFIED
                            )
                        }))
                {
                    ensure!(
                        body.as_ref().is_none_or(Bytes::is_empty)
                            && trailers.as_ref().is_none_or(HeaderMap::is_empty),
                        "this response status/method cannot have a body or trailers"
                    );
                }
                if body.is_some() {
                    for name in ["content-md5", "digest", "etag"] {
                        headers.remove(name);
                    }
                }
                Ok(Change::Edit(Box::new(Edit {
                    method,
                    uri,
                    status,
                    headers,
                    body,
                    trailers,
                })))
            }
        }
    }
}

fn parse_headers(input: &Headers) -> Result<HeaderMap> {
    ensure!(
        input.len() <= 256
            && input
                .iter()
                .map(|h| h[0].len().saturating_add(h[1].len()))
                .sum::<usize>()
                <= 64 * 1024,
        "edited headers exceed 256 fields or 64 KiB"
    );
    let mut headers = HeaderMap::new();
    for [name, value] in input {
        headers.append(name.parse::<hyper::header::HeaderName>()?, value.parse()?);
    }
    Ok(headers)
}

pub(crate) fn parse_trailers(input: &Headers) -> Result<HeaderMap> {
    let trailers = parse_headers(input)?;
    for name in [
        "content-length",
        "transfer-encoding",
        "host",
        "connection",
        "trailer",
        "content-encoding",
        "authorization",
        "proxy-authorization",
    ] {
        ensure!(!trailers.contains_key(name), "invalid trailer field {name}");
    }
    Ok(trailers)
}

struct Pending {
    snapshot: Snapshot,
    sender: oneshot::Sender<Change>,
}
#[derive(Default)]
struct State {
    pending: BTreeMap<String, Pending>,
    closed: bool,
}

pub struct Pool {
    state: Mutex<State>,
    slots: Arc<Semaphore>,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            slots: Arc::new(Semaphore::new(32)),
        }
    }
}

impl Pool {
    pub fn list(&self) -> Vec<Summary> {
        let mut summaries: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .pending
            .values()
            .map(|p| p.snapshot.summary())
            .collect();
        summaries.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        summaries
    }
    pub fn get(&self, id: &str) -> Option<Snapshot> {
        self.state
            .lock()
            .unwrap()
            .pending
            .get(id)
            .map(|p| p.snapshot.clone())
    }
    pub fn resolve(
        &self,
        id: &str,
        decision: Decision,
    ) -> std::result::Result<(), (StatusCode, String)> {
        let mut state = self.state.lock().unwrap();
        let pending = state.pending.get(id).ok_or((
            StatusCode::NOT_FOUND,
            "breakpoint is no longer pending".into(),
        ))?;
        let change = decision
            .validate(&pending.snapshot)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
        let pending = state.pending.remove(id).unwrap();
        pending
            .sender
            .send(change)
            .map_err(|_| (StatusCode::GONE, "client is no longer waiting".into()))
    }
    fn reserve(&self) -> Result<OwnedSemaphorePermit> {
        ensure!(!self.state.lock().unwrap().closed, "proxy shutting down");
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("maximum 32 buffered or pending breakpoints reached"))
    }
    async fn wait(
        &self,
        snapshot: Snapshot,
        slot: OwnedSemaphorePermit,
        timeout_ms: u64,
    ) -> Result<Change> {
        let (sender, receiver) = oneshot::channel();
        let id = snapshot.id.clone();
        {
            let mut state = self.state.lock().unwrap();
            ensure!(!state.closed, "proxy shutting down");
            state
                .pending
                .insert(id.clone(), Pending { snapshot, sender });
        }
        let _guard = PendingGuard {
            pool: self,
            id,
            _slot: slot,
        };
        let change = tokio::time::timeout(Duration::from_millis(timeout_ms), receiver)
            .await
            .map_err(|_| anyhow::anyhow!("breakpoint timed out after {timeout_ms} ms"))??;
        if let Change::Abort(reason) = change {
            anyhow::bail!(reason);
        }
        Ok(change)
    }
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        for (_, pending) in std::mem::take(&mut state.pending) {
            let _ = pending.sender.send(Change::Abort("proxy shutting down"));
        }
    }
}

struct PendingGuard<'a> {
    pool: &'a Pool,
    id: String,
    _slot: OwnedSemaphorePermit,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.pool.state.lock().unwrap().pending.remove(&self.id);
    }
}

struct Peeked {
    data: Bytes,
    trailers: HeaderMap,
    complete: bool,
    content_length: Option<u64>,
    replay: ProxyBody,
    declared_trailer: Option<hyper::header::HeaderValue>,
}

struct ReplayBody {
    frames: VecDeque<Frame<Bytes>>,
    rest: Option<ProxyBody>,
    hint: SizeHint,
}
impl Body for ReplayBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        let frame = if let Some(frame) = self.frames.pop_front() {
            Poll::Ready(Some(Ok(frame)))
        } else if let Some(rest) = &mut self.rest {
            Pin::new(rest).poll_frame(cx)
        } else {
            Poll::Ready(None)
        };
        if let Poll::Ready(Some(Ok(ref frame))) = frame
            && let Some(data) = frame.data_ref()
        {
            let lower = self.hint.lower().saturating_sub(data.len() as u64);
            let upper = self
                .hint
                .upper()
                .map(|n| n.saturating_sub(data.len() as u64));
            self.hint.set_lower(lower);
            if let Some(upper) = upper {
                self.hint.set_upper(upper);
            }
        }
        if matches!(frame, Poll::Ready(None)) {
            self.rest = None;
        }
        frame
    }
    // HTTP/1 can stop body polling after the last data frame if the length is known.
    fn is_end_stream(&self) -> bool {
        self.frames.is_empty() && self.rest.as_ref().is_none_or(Body::is_end_stream)
    }
    fn size_hint(&self) -> SizeHint {
        self.hint
    }
}

async fn peek(
    mut body: ProxyBody,
    declared_trailer: Option<hyper::header::HeaderValue>,
) -> Result<Peeked> {
    let hint = body.size_hint();
    let content_length = hint.exact();
    let window = if content_length.is_some_and(|n| n <= EDIT_LIMIT as u64) {
        Duration::from_secs(30)
    } else {
        Duration::from_millis(250)
    };
    let mut frames = VecDeque::new();
    let mut data = Vec::new();
    let mut trailers = HeaderMap::new();
    let mut complete = body.is_end_stream();
    let collected = tokio::time::timeout(window, async {
        while !complete && data.len() < EDIT_LIMIT {
            let Some(frame) = body.frame().await else {
                complete = true;
                break;
            };
            let frame = frame.map_err(|e| anyhow::anyhow!(e.to_string()))?;
            if let Some(chunk) = frame.data_ref() {
                let keep = chunk.len().min(EDIT_LIMIT - data.len());
                data.extend_from_slice(&chunk[..keep]);
            }
            if let Some(fields) = frame.trailers_ref() {
                trailers = fields.clone();
            }
            complete = body.is_end_stream();
            frames.push_back(frame);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if let Ok(result) = collected {
        result?;
    }
    let replay = BodyExt::boxed(ReplayBody {
        frames,
        rest: (!complete).then_some(body),
        hint,
    });
    Ok(Peeked {
        data: Bytes::from(data),
        trailers,
        complete,
        content_length,
        replay,
        declared_trailer,
    })
}

fn snapshot(
    state: &App,
    id: Option<u64>,
    phase: Phase,
    info: (&str, &str, Option<u16>),
    headers: &HeaderMap,
    body: &Peeked,
    timeout_ms: u64,
) -> Snapshot {
    let (method, url, status) = info;
    let now = store::now_ms();
    let snapshot = Snapshot {
        id: uuid::Uuid::new_v4().to_string(),
        flow_id: id,
        phase,
        method: method.into(),
        url: url.into(),
        status,
        created_at: now,
        deadline: now + timeout_ms,
        headers: store::headers(headers),
        trailers: store::headers(&body.trailers),
        body: body.data.clone(),
        body_complete: body.complete,
        content_length: body.content_length,
    };
    state.update(id, |flow| {
        let limit = state.settings.read().unwrap().capture_bytes;
        flow.phase = match phase {
            Phase::Request => "paused_request",
            Phase::Response => "paused_response",
        }
        .into();
        let mut message = Message {
            headers: snapshot.headers.clone(),
            trailers: snapshot.trailers.clone(),
            ..Default::default()
        };
        message.body.append(&snapshot.body, limit);
        message.body.complete = body.complete;
        message.body.truncated |= !body.complete;
        match phase {
            Phase::Request => flow.request = message,
            Phase::Response => flow.response = Some(message),
        }
    });
    snapshot
}

fn edited_body(
    headers: &mut HeaderMap,
    peeked: Peeked,
    body: Option<Bytes>,
    trailers: Option<HeaderMap>,
) -> Result<ProxyBody> {
    headers.remove("content-length");
    headers.remove("transfer-encoding");
    headers.remove("trailer");
    if body.is_none() && trailers.is_none() {
        if let Some(length) = peeked.content_length {
            headers.insert("content-length", length.to_string().parse()?);
        }
        let declaration = if !peeked.trailers.is_empty() {
            Some(
                peeked
                    .trailers
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .parse()?,
            )
        } else {
            peeked.declared_trailer
        };
        if let Some(trailer) = declaration {
            headers.insert("trailer", trailer);
        }
        return Ok(peeked.replay);
    }
    let replaced = body.is_some();
    let body = body.unwrap_or(peeked.data);
    let mut trailers = trailers.unwrap_or(peeked.trailers);
    if replaced {
        for name in ["content-md5", "digest", "etag"] {
            trailers.remove(name);
        }
    }
    if trailers.is_empty() {
        headers.insert("content-length", body.len().to_string().parse()?);
        return Ok(proxy::full(body));
    }
    let names = trailers
        .keys()
        .map(|name| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    headers.insert("trailer", names.parse()?);
    Ok(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
        [
            Ok::<_, BoxError>(Frame::data(body)),
            Ok(Frame::trailers(trailers)),
        ],
    ))))
}

pub async fn request(
    req: Request<ProxyBody>,
    state: &App,
    id: Option<u64>,
    timeout_ms: u64,
) -> Result<Request<ProxyBody>> {
    let slot = state.breakpoints.reserve()?;
    let (mut parts, body) = req.into_parts();
    let peeked = peek(body, parts.headers.get("trailer").cloned()).await?;
    let view = snapshot(
        state,
        id,
        Phase::Request,
        (parts.method.as_str(), &parts.uri.to_string(), None),
        &parts.headers,
        &peeked,
        timeout_ms,
    );
    let change = state.breakpoints.wait(view, slot, timeout_ms).await?;
    let body = match change {
        Change::Continue => peeked.replay,
        Change::Edit(edit) => {
            let Edit {
                method,
                uri,
                headers,
                body,
                trailers,
                ..
            } = *edit;
            parts.method = method.unwrap();
            parts.uri = uri.unwrap();
            parts.headers = headers;
            edited_body(&mut parts.headers, peeked, body, trailers)?
        }
        Change::Abort(_) => unreachable!(),
    };
    state.update(id, |flow| {
        flow.phase = "sending".into();
        flow.request.body = Default::default();
        flow.request.trailers.clear();
    });
    Ok(Request::from_parts(parts, body))
}

pub async fn response(
    res: Response<ProxyBody>,
    state: &App,
    id: Option<u64>,
    method: &str,
    url: &str,
    timeout_ms: u64,
) -> Result<Response<ProxyBody>> {
    let slot = state.breakpoints.reserve()?;
    let (mut parts, body) = res.into_parts();
    let representation_length = if method == "HEAD" || parts.status == StatusCode::NOT_MODIFIED {
        parts.headers.get("content-length").cloned()
    } else {
        None
    };
    let peeked = peek(body, parts.headers.get("trailer").cloned()).await?;
    let view = snapshot(
        state,
        id,
        Phase::Response,
        (method, url, Some(parts.status.as_u16())),
        &parts.headers,
        &peeked,
        timeout_ms,
    );
    let change = state.breakpoints.wait(view, slot, timeout_ms).await?;
    let body = match change {
        Change::Continue => peeked.replay,
        Change::Edit(edit) => {
            let Edit {
                status,
                headers,
                body,
                trailers,
                ..
            } = *edit;
            parts.status = status.unwrap();
            parts.headers = headers;
            let body = edited_body(&mut parts.headers, peeked, body, trailers)?;
            if let Some(length) = representation_length
                && (method == "HEAD" || parts.status == StatusCode::NOT_MODIFIED)
            {
                parts.headers.insert("content-length", length);
            }
            body
        }
        Change::Abort(_) => unreachable!(),
    };
    state.update(id, |flow| {
        flow.phase = "receiving".into();
        if let Some(response) = &mut flow.response {
            response.body = Default::default();
            response.trailers.clear();
        }
    });
    Ok(Response::from_parts(parts, body))
}
