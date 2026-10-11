use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde::Deserialize;
use serde_json::json;

use crate::{
    config::{self, Settings},
    proxy::{self, App},
    store::{self, Headers, Session, Store},
};

type ApiResult<T> = Result<T, (StatusCode, String)>;
static FRONTEND: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/web/dist");
fn bad(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

pub fn router(state: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/{*path}", get(asset))
        .route("/api/status", get(status))
        .route("/api/settings", post(settings))
        .route("/api/settings/validate", post(validate_settings))
        .route("/api/flows", get(flows).delete(clear))
        .route(
            "/api/flows/{id}",
            get(flow).delete(delete_flow).patch(annotate),
        )
        .route("/api/flows/{id}/replay", post(replay))
        .route("/api/flows/{id}/compare", get(compare_flow))
        .route(
            "/api/flows/{id}/decode",
            post(decode_protocol).layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/api/flows/{id}/validate",
            post(validate_body).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/api/compose", post(compose))
        .route("/api/session", get(session).post(import_session))
        .route("/api/session/compare", post(compare_session))
        .route("/api/har", get(har))
        .route("/api/breakpoints", get(breakpoints))
        .route(
            "/api/breakpoints/{id}",
            get(breakpoint)
                .post(decide_breakpoint)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .layer(DefaultBodyLimit::max(400 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), protect))
        .with_state(state)
}

async fn protect(State(state): State<Arc<App>>, request: Request<Body>, next: Next) -> Response {
    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let expected = state.ui_addr.to_string();
    let localhost = format!("localhost:{}", state.ui_addr.port());
    if host != expected && host != localhost {
        return (StatusCode::FORBIDDEN, "management Host is not allowed").into_response();
    }
    if let Some(origin) = request.headers().get("origin")
        && origin.to_str().ok() != Some(format!("http://{host}").as_str())
    {
        return (StatusCode::FORBIDDEN, "cross-origin access is not allowed").into_response();
    }
    if request.uri().path().starts_with("/api/") {
        let token = request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        if token != Some(state.token.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                "Open the inspector URL printed by OpenProxy to authenticate",
            )
                .into_response();
        }
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response.headers_mut().insert("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".parse().unwrap());
    response
}

async fn index() -> Response {
    frontend_file("index.html")
}
async fn asset(Path(path): Path<String>) -> Response {
    frontend_file(&path)
}
fn frontend_file(path: &str) -> Response {
    let Some(file) = FRONTEND.get_file(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = match std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
    {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    };
    ([("content-type", mime)], file.contents()).into_response()
}

async fn status(State(state): State<Arc<App>>) -> Json<serde_json::Value> {
    let settings = state.settings.read().unwrap().clone();
    let store = state.store.lock().unwrap();
    Json(
        json!({"version": env!("CARGO_PKG_VERSION"), "proxy": state.proxy_addr.to_string(), "ui": state.ui_addr.to_string(), "socks": state.socks_addr.map(|a| a.to_string()),
        "settings": settings, "flow_count": store.flows.len(),
        "retained_bytes": store.retained_bytes, "retention_limit": store::RETENTION_LIMIT, "evicted_flows": store.evicted_flows}),
    )
}

async fn settings(
    State(state): State<Arc<App>>,
    Json(settings): Json<Settings>,
) -> ApiResult<Json<Settings>> {
    config::validate(&settings).map_err(bad)?;
    let _guard = state.save_lock.lock().await;
    let dns_changed = state.settings.read().unwrap().dns_overrides != settings.dns_overrides;
    let bytes = serde_json::to_vec(&settings).map_err(bad)?;
    let path = state.data_dir.join("settings.json");
    tokio::task::spawn_blocking(move || store::atomic_write(&path, &bytes))
        .await
        .map_err(bad)?
        .map_err(bad)?;
    {
        let mut store = state.store.lock().unwrap();
        store.resize(&settings);
        *state.settings.write().unwrap() = settings.clone();
    }
    if dns_changed {
        state.refresh_client(&settings);
    }
    state.simulation.configure(&settings);
    Ok(Json(settings))
}

async fn flows(State(state): State<Arc<App>>) -> Response {
    let store = state.store.lock().unwrap();
    Json(
        store
            .flows
            .iter()
            .rev()
            .map(|f| f.summary())
            .collect::<Vec<_>>(),
    )
    .into_response()
}

async fn validate_settings(Json(settings): Json<Settings>) -> ApiResult<Json<Settings>> {
    config::validate(&settings).map_err(bad)?;
    Ok(Json(settings))
}

async fn flow(State(state): State<Arc<App>>, Path(id): Path<u64>) -> ApiResult<Json<store::Flow>> {
    state
        .store
        .lock()
        .unwrap()
        .get(id)
        .cloned()
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))
}

async fn clear(State(state): State<Arc<App>>) -> StatusCode {
    state.store.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

async fn decode_protocol(
    State(state): State<Arc<App>>,
    Path(id): Path<u64>,
    Json(options): Json<crate::protocols::Decode>,
) -> ApiResult<Json<serde_json::Value>> {
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let permit = SLOTS.try_acquire().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "two decoders are already running".into(),
        )
    })?;
    let message = {
        let store = state.store.lock().unwrap();
        let flow = store
            .get(id)
            .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))?;
        let message =
            crate::protocols::selected(flow, options.direction, options.original).map_err(bad)?;
        if message.body.data.len() > crate::protocols::INPUT_LIMIT {
            return Err(bad("decoder input exceeds 1 MiB"));
        }
        message.clone()
    };
    let value = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::protocols::decode(&message, options)
    })
    .await
    .map_err(bad)?
    .map_err(|e| bad(format!("{e:#}")))?;
    Ok(Json(value))
}

async fn validate_body(
    State(state): State<Arc<App>>,
    Path(id): Path<u64>,
    Json(options): Json<crate::validation::Validate>,
) -> ApiResult<Json<serde_json::Value>> {
    if !options.consent {
        return Err(bad(
            "explicit consent is required before sending this body to an external validator",
        ));
    }
    let message = {
        let store = state.store.lock().unwrap();
        let flow = store
            .get(id)
            .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))?;
        let message =
            crate::protocols::selected(flow, options.direction, options.original).map_err(bad)?;
        if message.body.data.len() > crate::protocols::INPUT_LIMIT {
            return Err(bad("validation input exceeds 1 MiB"));
        }
        message.clone()
    };
    let prepared =
        crate::validation::prepare(&message, &options).map_err(|e| bad(format!("{e:#}")))?;
    let client = state.client.read().unwrap().clone();
    crate::validation::send(client, prepared)
        .await
        .map(Json)
        .map_err(|e| bad(format!("{e:#}")))
}

async fn delete_flow(State(state): State<Arc<App>>, Path(id): Path<u64>) -> StatusCode {
    state.store.lock().unwrap().remove(id);
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Annotation {
    note: Option<String>,
    marked: Option<bool>,
}

async fn annotate(
    State(state): State<Arc<App>>,
    Path(id): Path<u64>,
    Json(annotation): Json<Annotation>,
) -> ApiResult<Json<store::Flow>> {
    if annotation
        .note
        .as_ref()
        .is_some_and(|note| note.len() > 8192)
    {
        return Err(bad("note exceeds 8 KiB"));
    }
    let mut store = state.store.lock().unwrap();
    store
        .update(id, |flow| {
            if let Some(note) = annotation.note {
                flow.metadata.note = note;
            }
            if let Some(marked) = annotation.marked {
                flow.metadata.marked = marked;
            }
            Json(flow.clone())
        })
        .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))
}

async fn session(State(state): State<Arc<App>>) -> ApiResult<Response> {
    let bytes = state.store.lock().unwrap().session_bytes().map_err(bad)?;
    Ok((
        [
            ("content-type", "application/json"),
            (
                "content-disposition",
                "attachment; filename=openproxy-session.json",
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn import_session(
    State(state): State<Arc<App>>,
    Json(value): Json<serde_json::Value>,
) -> ApiResult<StatusCode> {
    let settings = state.settings.read().unwrap().clone();
    let replacement = if value.get("log").is_some() {
        store::import_har(value, &settings).map_err(bad)?
    } else {
        Store::from_session(
            serde_json::from_value::<Session>(value).map_err(bad)?,
            &settings,
        )
        .map_err(bad)?
    };
    state.store.lock().unwrap().replace(replacement);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CompareQuery {
    other: u64,
}
async fn compare_flow(
    State(state): State<Arc<App>>,
    Path(id): Path<u64>,
    Query(query): Query<CompareQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.lock().unwrap();
    let left = store
        .get(id)
        .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))?;
    let right = store
        .get(query.other)
        .ok_or((StatusCode::NOT_FOUND, "comparison flow not found".into()))?;
    Ok(Json(
        json!({"difference":crate::compare::flows(left,right),"left":left,"right":right}),
    ))
}
async fn compare_session(
    State(state): State<Arc<App>>,
    Json(value): Json<serde_json::Value>,
) -> ApiResult<Json<Vec<crate::compare::Difference>>> {
    let settings = state.settings.read().unwrap().clone();
    let other = if value.get("log").is_some() {
        store::import_har(value, &settings).map_err(bad)?
    } else {
        Store::from_session(
            serde_json::from_value::<Session>(value).map_err(bad)?,
            &settings,
        )
        .map_err(bad)?
    };
    Ok(Json(crate::compare::sessions(
        &state.store.lock().unwrap(),
        &other,
    )))
}

async fn har(State(state): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(store::har(&state.store.lock().unwrap()))
}

async fn breakpoints(State(state): State<Arc<App>>) -> Json<Vec<crate::breakpoints::Summary>> {
    Json(state.breakpoints.list())
}
async fn breakpoint(
    State(state): State<Arc<App>>,
    Path(id): Path<String>,
) -> ApiResult<Json<crate::breakpoints::Snapshot>> {
    state.breakpoints.get(&id).map(Json).ok_or((
        StatusCode::NOT_FOUND,
        "breakpoint is no longer pending".into(),
    ))
}
async fn decide_breakpoint(
    State(state): State<Arc<App>>,
    Path(id): Path<String>,
    Json(decision): Json<crate::breakpoints::Decision>,
) -> ApiResult<StatusCode> {
    state.breakpoints.resolve(&id, decision)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compose {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Headers,
    #[serde(default)]
    pub trailers: Headers,
    #[serde(default, with = "store::binary")]
    pub body: Vec<u8>,
    #[serde(default = "one")]
    pub repeat: usize,
    #[serde(default = "one")]
    pub concurrency: usize,
    #[serde(default = "yes")]
    pub apply_rules: bool,
}
fn yes() -> bool {
    true
}
fn one() -> usize {
    1
}

impl Compose {
    fn request(&self) -> anyhow::Result<hyper::Request<proxy::ProxyBody>> {
        anyhow::ensure!(
            self.body.len() <= 1024 * 1024,
            "composer body exceeds 1 MiB"
        );
        anyhow::ensure!(
            (1..=1000).contains(&self.repeat) && (1..=32).contains(&self.concurrency),
            "repeat must be 1..1000 and concurrency 1..32"
        );
        let uri: hyper::Uri = self.url.parse()?;
        anyhow::ensure!(
            matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some(),
            "absolute HTTP(S) URL required"
        );
        anyhow::ensure!(
            !uri.authority().unwrap().as_str().contains('@'),
            "URL credentials are not supported"
        );
        let method: hyper::Method = self.method.parse()?;
        anyhow::ensure!(
            method != hyper::Method::CONNECT,
            "composer does not support CONNECT"
        );
        let mut headers = HeaderMap::new();
        for [name, value] in &self.headers {
            anyhow::ensure!(headers.len() < 256, "at most 256 composer headers");
            headers.append(name.parse::<hyper::header::HeaderName>()?, value.parse()?);
        }
        for name in [
            "content-length",
            "transfer-encoding",
            "host",
            "upgrade",
            "trailer",
        ] {
            headers.remove(name);
        }
        let trailers = crate::breakpoints::parse_trailers(&self.trailers)?;
        let body = if trailers.is_empty() {
            headers.insert("content-length", self.body.len().to_string().parse()?);
            proxy::full(self.body.clone())
        } else {
            headers.insert(
                "trailer",
                trailers
                    .keys()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .parse()?,
            );
            StreamBody::new(futures_util::stream::iter([
                Ok::<_, proxy::BoxError>(Frame::data(self.body.clone().into())),
                Ok(Frame::trailers(trailers)),
            ]))
            .boxed()
        };
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .body(body)?;
        *req.headers_mut() = headers;
        if !self.apply_rules {
            req.extensions_mut().insert(proxy::SkipRules);
        }
        Ok(req)
    }

    fn replay(flow: store::Flow) -> anyhow::Result<Self> {
        let original = flow.metadata.original_request.is_some();
        let message = flow.metadata.original_request.unwrap_or(flow.request);
        anyhow::ensure!(
            !message.body.truncated && message.body.complete && flow.method != "CONNECT",
            "cannot replay a truncated/incomplete request or an opaque tunnel"
        );
        Ok(Self {
            method: if original || flow.metadata.upstream_method.is_empty() {
                flow.method
            } else {
                flow.metadata.upstream_method
            },
            url: if original || flow.upstream_url.is_empty() {
                flow.url
            } else {
                flow.upstream_url
            },
            headers: message.headers,
            trailers: message.trailers,
            body: message.body.data,
            repeat: 1,
            concurrency: 1,
            apply_rules: original,
        })
    }
}

async fn execute(state: Arc<App>, input: Compose) -> ApiResult<Json<serde_json::Value>> {
    input.request().map_err(bad)?;
    let mut tasks: tokio::task::JoinSet<anyhow::Result<()>> = tokio::task::JoinSet::new();
    let mut completed = 0;
    let mut errors = Vec::new();
    for _ in 0..input.repeat {
        if tasks.len() >= input.concurrency {
            match tasks.join_next().await.unwrap() {
                Ok(Ok(())) => completed += 1,
                Ok(Err(error)) => errors.push(error.to_string()),
                Err(error) => errors.push(error.to_string()),
            }
        }
        let state = state.clone();
        let input = input.clone();
        tasks.spawn(async move {
            use http_body_util::BodyExt;
            let tls = input.url.starts_with("https:");
            let res =
                proxy::forward(input.request()?, state, "composer".into(), tls, None, None).await?;
            // Drain with backpressure to prevent a second copy that bypasses capture limits.
            let mut body = res.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|e| anyhow::anyhow!(e.to_string()))?;
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => completed += 1,
            Ok(Err(e)) => errors.push(e.to_string()),
            Err(e) => errors.push(e.to_string()),
        }
    }
    Ok(Json(json!({"completed": completed, "errors": errors})))
}

async fn compose(
    State(state): State<Arc<App>>,
    Json(input): Json<Compose>,
) -> ApiResult<Json<serde_json::Value>> {
    execute(state, input).await
}

async fn replay(
    State(state): State<Arc<App>>,
    Path(id): Path<u64>,
) -> ApiResult<Json<serde_json::Value>> {
    let flow = state
        .store
        .lock()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "flow not found".into()))?;
    execute(state, Compose::replay(flow).map_err(bad)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composer_validates_and_reframes() {
        let mut c = Compose {
            method: "POST".into(),
            url: "https://example.test/".into(),
            headers: vec![
                ["content-length".into(), "999".into()],
                ["set-cookie".into(), "a=b".into()],
                ["set-cookie".into(), "c=d".into()],
            ],
            body: vec![0, 255],
            trailers: vec![],
            repeat: 1,
            concurrency: 1,
            apply_rules: true,
        };
        let req = c.request().unwrap();
        assert_eq!(req.headers()["content-length"], "2");
        assert_eq!(req.headers().get_all("set-cookie").iter().count(), 2);
        c.url = "file:///etc/passwd".into();
        assert!(c.request().is_err());
        c.url = "https://example.test/".into();
        c.headers.push(["x-bad".into(), "a\r\nb".into()]);
        assert!(c.request().is_err());
    }
}
