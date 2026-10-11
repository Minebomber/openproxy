use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, ensure};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::{HeaderMap, Request, Response, StatusCode, body::Frame};
use serde::{Deserialize, Serialize};

use crate::{
    config,
    proxy::{self, App, ProxyBody},
    store::Headers,
};

pub const EDIT_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default = "any_url")]
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    pub actions: Vec<Action>,
}
fn enabled() -> bool {
    true
}
fn any_url() -> String {
    "*".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    SetRequestHeader {
        name: String,
        value: String,
    },
    RemoveRequestHeader {
        name: String,
    },
    SetResponseHeader {
        name: String,
        value: String,
    },
    RemoveResponseHeader {
        name: String,
    },
    ReplaceUrl {
        find: String,
        replace: String,
        #[serde(default)]
        regex: bool,
    },
    SetQuery {
        name: String,
        value: Option<String>,
    },
    MapRemote {
        from: String,
        to: String,
    },
    MapLocal {
        path: PathBuf,
        #[serde(default)]
        url_prefix: String,
    },
    Mock {
        status: u16,
        #[serde(default)]
        headers: Headers,
        body: String,
    },
    Block {
        #[serde(default)]
        message: String,
    },
    ReplaceRequestBody {
        find: String,
        replace: String,
        #[serde(default)]
        regex: bool,
    },
    ReplaceResponseBody {
        find: String,
        replace: String,
        #[serde(default)]
        regex: bool,
    },
    SetStatus {
        status: u16,
    },
    Latency {
        ms: u64,
    },
    Throttle {
        upload: u64,
        download: u64,
    },
    Failure {
        percent: u8,
    },
    Drop {
        #[serde(default)]
        upload_after_bytes: Option<u64>,
        #[serde(default)]
        download_after_bytes: Option<u64>,
    },
    NoCache,
    Mirror {
        directory: PathBuf,
        #[serde(default = "mirror_limit")]
        max_bytes: u64,
    },
    BlockCookies,
    Offline,
    Breakpoint {
        phase: crate::breakpoints::Phase,
        #[serde(default = "crate::breakpoints::default_timeout")]
        timeout_ms: u64,
    },
}
fn mirror_limit() -> u64 {
    256 * 1024 * 1024
}

#[derive(Clone)]
pub struct MatchedAction {
    pub rule: String,
    pub index: usize,
    pub action: Action,
}
impl Action {
    fn label(&self) -> &'static str {
        match self {
            Self::SetRequestHeader { .. } => "set_request_header",
            Self::RemoveRequestHeader { .. } => "remove_request_header",
            Self::SetResponseHeader { .. } => "set_response_header",
            Self::RemoveResponseHeader { .. } => "remove_response_header",
            Self::ReplaceUrl { .. } => "replace_url",
            Self::SetQuery { .. } => "set_query",
            Self::MapRemote { .. } => "map_remote",
            Self::MapLocal { .. } => "map_local",
            Self::Mock { .. } => "mock",
            Self::Block { .. } => "block",
            Self::ReplaceRequestBody { .. } => "replace_request_body",
            Self::ReplaceResponseBody { .. } => "replace_response_body",
            Self::SetStatus { .. } => "set_status",
            Self::Latency { .. } => "latency",
            Self::Throttle { .. } => "throttle",
            Self::Failure { .. } => "failure",
            Self::Drop { .. } => "drop",
            Self::NoCache => "no_cache",
            Self::Mirror { .. } => "mirror",
            Self::BlockCookies => "block_cookies",
            Self::Offline => "offline",
            Self::Breakpoint { .. } => "breakpoint",
        }
    }
    fn phase(&self) -> &'static str {
        match self {
            Self::SetResponseHeader { .. }
            | Self::RemoveResponseHeader { .. }
            | Self::ReplaceResponseBody { .. }
            | Self::SetStatus { .. }
            | Self::Breakpoint {
                phase: crate::breakpoints::Phase::Response,
                ..
            } => "response",
            Self::Latency { .. }
            | Self::Throttle { .. }
            | Self::Failure { .. }
            | Self::Drop { .. }
            | Self::NoCache
            | Self::BlockCookies
            | Self::Mirror { .. } => "simulation",
            _ => "request",
        }
    }
}
fn begin(state: &App, id: Option<u64>, matched: &MatchedAction) -> Option<usize> {
    let mut index = None;
    state.update(id, |flow| {
        if flow.metadata.actions.len() >= 256 {
            flow.metadata.actions_truncated = true;
            return;
        }
        index = Some(flow.metadata.actions.len());
        flow.metadata.actions.push(crate::store::ActionTrace {
            rule: matched.rule.clone(),
            index: matched.index,
            action: matched.action.label().into(),
            phase: matched.action.phase().into(),
            applied: false,
            changed: None,
        });
    });
    index
}
fn applied(state: &App, id: Option<u64>, index: Option<usize>, changed: Option<bool>) {
    state.update(id, |flow| {
        if let Some(trace) = index.and_then(|index| flow.metadata.actions.get_mut(index)) {
            trace.applied = true;
            trace.changed = changed;
        }
    });
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(rules.len() <= 256, "at most 256 rules");
    for rule in rules {
        ensure!(
            rule.name.len() <= 200 && !rule.url.is_empty() && rule.url.len() <= 4096,
            "invalid rule name or URL pattern"
        );
        ensure!(rule.actions.len() <= 32, "at most 32 actions per rule");
        if let Some(method) = &rule.method {
            method.parse::<hyper::Method>()?;
        }
        for action in &rule.actions {
            match action {
                Action::Failure { percent } => {
                    ensure!(*percent <= 100, "failure percent must be 0..100")
                }
                Action::Drop {
                    upload_after_bytes,
                    download_after_bytes,
                } => ensure!(
                    upload_after_bytes.is_some() || download_after_bytes.is_some(),
                    "drop needs an upload or download byte threshold"
                ),
                Action::Mirror {
                    directory,
                    max_bytes,
                } => {
                    ensure!(
                        !directory.as_os_str().is_empty()
                            && (1..=10 * 1024 * 1024 * 1024).contains(max_bytes),
                        "mirror needs a directory and a 1 byte..10 GiB disk limit"
                    );
                }
                Action::Breakpoint { timeout_ms, .. } => {
                    ensure!(
                        (1..=300_000).contains(timeout_ms),
                        "breakpoint timeout must be 1..300000 ms"
                    );
                }
                Action::SetRequestHeader { name, value }
                | Action::SetResponseHeader { name, value } => {
                    validate_header(name, Some(value))?;
                }
                Action::RemoveRequestHeader { name } | Action::RemoveResponseHeader { name } => {
                    validate_header(name, None)?;
                }
                Action::ReplaceUrl {
                    find,
                    replace,
                    regex,
                }
                | Action::ReplaceRequestBody {
                    find,
                    replace,
                    regex,
                }
                | Action::ReplaceResponseBody {
                    find,
                    replace,
                    regex,
                } => {
                    ensure!(
                        find.len() <= 4096 && replace.len() <= EDIT_LIMIT,
                        "replacement is too large"
                    );
                    if *regex {
                        regex::Regex::new(find)?;
                    }
                }
                Action::MapRemote { from, to } => {
                    http_uri(from)?;
                    http_uri(to)?;
                }
                Action::MapLocal { path, .. } => {
                    ensure!(!path.as_os_str().is_empty(), "Map Local needs a path");
                }
                Action::Mock {
                    status,
                    headers,
                    body,
                } => {
                    validate_status(*status)?;
                    ensure!(
                        body.len() <= EDIT_LIMIT && headers.len() <= 256,
                        "mock is too large"
                    );
                    for [name, value] in headers {
                        validate_header(name, Some(value))?;
                    }
                }
                Action::SetStatus { status } => {
                    validate_status(*status)?;
                }
                Action::Latency { ms } => {
                    ensure!(*ms <= 60_000, "rule latency must be at most 60000 ms");
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_status(status: u16) -> Result<()> {
    ensure!(
        (200..=599).contains(&status),
        "rule response status must be 200..599"
    );
    Ok(())
}
fn validate_header(name: &str, value: Option<&str>) -> Result<()> {
    name.parse::<hyper::header::HeaderName>()?;
    if let Some(value) = value {
        value.parse::<hyper::header::HeaderValue>()?;
    }
    // The proxy controls framing and hop-by-hop headers. Rules cannot change them.
    ensure!(
        ![
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "proxy-authorization",
            "proxy-authenticate",
            "trailer",
            "te"
        ]
        .contains(&name.to_ascii_lowercase().as_str()),
        "rule cannot edit framing/hop header {name}"
    );
    Ok(())
}

pub fn http_uri(value: &str) -> Result<hyper::Uri> {
    let uri: hyper::Uri = value.parse()?;
    ensure!(
        matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some(),
        "rule destination must be absolute HTTP(S)"
    );
    ensure!(
        !uri.authority().unwrap().as_str().contains('@'),
        "rule URL credentials are not supported"
    );
    Ok(uri)
}

pub fn actions(rules: &[Rule], url: &str, method: &str) -> Vec<MatchedAction> {
    rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && config::matches(&rule.url, url)
                && rule.method.as_ref().is_none_or(|m| m == method)
        })
        .flat_map(|r| {
            r.actions
                .iter()
                .enumerate()
                .map(|(index, action)| MatchedAction {
                    rule: r.name.clone(),
                    index,
                    action: action.clone(),
                })
        })
        .collect()
}

pub fn replace(text: &str, find: &str, replacement: &str, regex: bool) -> Result<String> {
    let mut output = String::new();
    let mut offset = 0;
    let mut append = |value: &str| -> Result<()> {
        ensure!(
            output.len().saturating_add(value.len()) <= EDIT_LIMIT,
            "rewritten text exceeds 1 MiB"
        );
        output.push_str(value);
        Ok(())
    };
    if regex {
        // shortcut: compile regexes for each matching exchange, cache them if profiling shows high cost.
        let regex = regex::Regex::new(find)?;
        for captures in regex.captures_iter(text) {
            let found = captures.get(0).unwrap();
            append(&text[offset..found.start()])?;
            // Limit expansion before the regex library allocates memory for replacement capture groups.
            let dollars = replacement.bytes().filter(|b| *b == b'$').count();
            let max_group = captures
                .iter()
                .flatten()
                .map(|m| m.len())
                .max()
                .unwrap_or(0);
            ensure!(
                replacement
                    .len()
                    .saturating_add(max_group.saturating_mul(dollars))
                    <= EDIT_LIMIT,
                "regex capture expansion exceeds editing budget"
            );
            let mut expanded = String::new();
            captures.expand(replacement, &mut expanded);
            append(&expanded)?;
            offset = found.end();
        }
    } else {
        for (start, found) in text.match_indices(find) {
            append(&text[offset..start])?;
            append(replacement)?;
            offset = start + found.len();
        }
    }
    append(&text[offset..])?;
    Ok(output)
}

pub async fn buffer(mut body: ProxyBody) -> Result<Bytes> {
    tokio::time::timeout(Duration::from_secs(30), async move {
        let mut data = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| anyhow::anyhow!(e.to_string()))?;
            ensure!(
                frame.trailers_ref().is_none(),
                "body editing with trailers is unsupported; no trailers were discarded"
            );
            if let Some(chunk) = frame.data_ref() {
                ensure!(
                    data.len().saturating_add(chunk.len()) <= EDIT_LIMIT,
                    "body editing exceeds 1 MiB"
                );
                data.extend_from_slice(chunk);
            }
        }
        Ok(Bytes::from(data))
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("body editing timed out; streaming bodies cannot be buffered indefinitely")
    })?
}

fn rewrite_body(
    data: Bytes,
    headers: &mut HeaderMap,
    find: &str,
    replacement: &str,
    regex: bool,
) -> Result<Bytes> {
    let encoding = headers
        .get("content-encoding")
        .map(|h| h.to_str())
        .transpose()?
        .unwrap_or("identity")
        .to_ascii_lowercase();
    let mut decoded = Vec::new();
    match encoding.as_str() {
        "identity" | "" => decoded.extend_from_slice(&data),
        "gzip" => {
            flate2::read::MultiGzDecoder::new(data.as_ref())
                .take(EDIT_LIMIT as u64 + 1)
                .read_to_end(&mut decoded)?;
        }
        "deflate" => {
            flate2::read::ZlibDecoder::new(data.as_ref())
                .take(EDIT_LIMIT as u64 + 1)
                .read_to_end(&mut decoded)?;
        }
        _ => anyhow::bail!("body rewriting does not support Content-Encoding {encoding}"),
    }
    ensure!(decoded.len() <= EDIT_LIMIT, "decoded body exceeds 1 MiB");
    let text = std::str::from_utf8(&decoded)
        .map_err(|_| anyhow::anyhow!("body rewriting requires UTF-8 text"))?;
    let replaced = replace(text, find, replacement, regex)?;
    let output = encode_body(replaced.as_bytes(), headers)?;
    for header in ["content-md5", "digest", "etag"] {
        headers.remove(header);
    }
    headers.insert("content-length", output.len().to_string().parse()?);
    Ok(output)
}

pub fn encode_body(data: &[u8], headers: &HeaderMap) -> Result<Bytes> {
    ensure!(data.len() <= EDIT_LIMIT, "decoded body exceeds 1 MiB");
    let encoding = headers
        .get("content-encoding")
        .map(|h| h.to_str())
        .transpose()?
        .unwrap_or("identity")
        .to_ascii_lowercase();
    let output = match encoding.as_str() {
        "gzip" => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data)?;
            encoder.finish()?
        }
        "deflate" => {
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data)?;
            encoder.finish()?
        }
        "identity" | "" => data.to_vec(),
        _ => anyhow::bail!("body editing does not support Content-Encoding {encoding}"),
    };
    ensure!(output.len() <= EDIT_LIMIT, "encoded body exceeds 1 MiB");
    Ok(Bytes::from(output))
}

pub async fn request(
    mut req: Request<ProxyBody>,
    actions: &[MatchedAction],
    state: &App,
    id: Option<u64>,
) -> Result<(Request<ProxyBody>, Option<Response<ProxyBody>>)> {
    let mut local = None;
    for matched in actions {
        let action = &matched.action;
        let phase = action.phase();
        if phase != "request" {
            continue;
        }
        let trace = begin(state, id, matched);
        let before = (
            req.method().clone(),
            req.uri().clone(),
            req.headers().clone(),
        );
        let before_local = local
            .as_ref()
            .map(|response: &Response<ProxyBody>| (response.status(), response.headers().clone()));
        let mut body_changed = None;
        let mut stop = false;
        match action {
            Action::Breakpoint {
                phase: crate::breakpoints::Phase::Request,
                timeout_ms,
            } => {
                req = crate::breakpoints::request(req, state, id, *timeout_ms).await?;
            }
            Action::SetRequestHeader { name, value } => {
                req.headers_mut()
                    .insert(name.parse::<hyper::header::HeaderName>()?, value.parse()?);
            }
            Action::RemoveRequestHeader { name } => {
                req.headers_mut().remove(name);
            }
            Action::ReplaceUrl {
                find,
                replace: replacement,
                regex,
            } => {
                *req.uri_mut() =
                    http_uri(&replace(&req.uri().to_string(), find, replacement, *regex)?)?;
            }
            Action::SetQuery { name, value } => {
                let mut url = url::Url::parse(&req.uri().to_string())?;
                let mut pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .filter(|(k, _)| k != name)
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                if let Some(value) = value {
                    pairs.push((name.clone(), value.clone()));
                }
                url.set_query(None);
                if !pairs.is_empty() {
                    url.query_pairs_mut().extend_pairs(pairs);
                }
                *req.uri_mut() = http_uri(url.as_str())?;
            }
            Action::MapRemote { from, to } => {
                if let Some(rest) = req.uri().to_string().strip_prefix(from) {
                    *req.uri_mut() = http_uri(&format!("{to}{rest}"))?;
                }
            }
            Action::MapLocal { path, url_prefix } => {
                if let Some(mapped) = local_file(
                    path.clone(),
                    url_prefix.clone(),
                    req.uri().path().to_owned(),
                )
                .await?
                {
                    local = Some(mapped);
                }
            }
            Action::Mock {
                status,
                headers,
                body,
            } => {
                let mut response = Response::builder()
                    .status(*status)
                    .body(proxy::full(body.clone()))?;
                for [name, value] in headers {
                    response
                        .headers_mut()
                        .append(name.parse::<hyper::header::HeaderName>()?, value.parse()?);
                }
                local = Some(response);
            }
            Action::Block { message } => {
                local = Some(proxy::response(
                    StatusCode::FORBIDDEN,
                    if message.is_empty() {
                        "Blocked by OpenProxy".to_owned()
                    } else {
                        message.clone()
                    },
                ));
                stop = true;
            }
            Action::Offline => {
                local = Some(proxy::response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Offline simulation",
                ));
                stop = true;
            }
            Action::ReplaceRequestBody {
                find,
                replace: replacement,
                regex,
            } => {
                let (mut parts, body) = req.into_parts();
                let original = buffer(body).await?;
                let data = rewrite_body(
                    original.clone(),
                    &mut parts.headers,
                    find,
                    replacement,
                    *regex,
                )?;
                body_changed = Some(original != data);
                req = Request::from_parts(parts, proxy::full(data));
            }
            _ => {}
        }
        applied(
            state,
            id,
            trace,
            if matches!(
                action,
                Action::Breakpoint { .. } | Action::Mock { .. } | Action::MapLocal { .. }
            ) {
                None
            } else {
                Some(
                    body_changed.unwrap_or(false)
                        || before
                            != (
                                req.method().clone(),
                                req.uri().clone(),
                                req.headers().clone(),
                            )
                        || before_local
                            != local
                                .as_ref()
                                .map(|response| (response.status(), response.headers().clone())),
                )
            },
        );
        if stop {
            break;
        }
    }
    Ok((req, local))
}

pub async fn response(
    mut res: Response<ProxyBody>,
    actions: &[MatchedAction],
    head: bool,
    state: &App,
    id: Option<u64>,
    method: &str,
    url: &str,
) -> Result<Response<ProxyBody>> {
    for matched in actions {
        let action = &matched.action;
        let phase = action.phase();
        if phase != "response" {
            continue;
        }
        let trace = begin(state, id, matched);
        let before = (res.status(), res.headers().clone());
        let mut body_changed = None;
        match action {
            Action::Breakpoint {
                phase: crate::breakpoints::Phase::Response,
                timeout_ms,
            } => {
                res =
                    crate::breakpoints::response(res, state, id, method, url, *timeout_ms).await?;
            }
            Action::SetResponseHeader { name, value } => {
                res.headers_mut()
                    .insert(name.parse::<hyper::header::HeaderName>()?, value.parse()?);
            }
            Action::RemoveResponseHeader { name } => {
                res.headers_mut().remove(name);
            }
            Action::SetStatus { status } => {
                *res.status_mut() = StatusCode::from_u16(*status)?;
            }
            Action::ReplaceResponseBody {
                find,
                replace: replacement,
                regex,
            } => {
                if head
                    || matches!(
                        res.status(),
                        StatusCode::NO_CONTENT
                            | StatusCode::RESET_CONTENT
                            | StatusCode::NOT_MODIFIED
                            | StatusCode::SWITCHING_PROTOCOLS
                    )
                {
                    continue;
                }
                let (mut parts, body) = res.into_parts();
                let original = buffer(body).await?;
                let data = rewrite_body(
                    original.clone(),
                    &mut parts.headers,
                    find,
                    replacement,
                    *regex,
                )?;
                body_changed = Some(original != data);
                res = Response::from_parts(parts, proxy::full(data));
            }
            _ => {}
        }
        applied(
            state,
            id,
            trace,
            if matches!(action, Action::Breakpoint { .. }) {
                None
            } else {
                Some(
                    body_changed.unwrap_or(false)
                        || before != (res.status(), res.headers().clone()),
                )
            },
        );
    }
    Ok(res)
}

fn local_file(
    path: PathBuf,
    prefix: String,
    url_path: String,
) -> futures_util::future::BoxFuture<'static, Result<Option<Response<ProxyBody>>>> {
    Box::pin(async move {
        let meta = match tokio::fs::metadata(path.clone()).await {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let target = if meta.is_dir() {
            let Some(relative) = url_path.strip_prefix(&prefix) else {
                return Ok(None);
            };
            let decoded = percent_encoding::percent_decode_str(relative).decode_utf8()?;
            let relative = decoded.trim_start_matches('/');
            ensure!(
                std::path::Path::new(relative)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
                "Map Local rejected path traversal"
            );
            let root = tokio::fs::canonicalize(path.clone()).await?;
            let target = match tokio::fs::canonicalize(root.join(relative)).await {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            ensure!(
                target.starts_with(root),
                "Map Local rejected a symlink outside the configured directory"
            );
            target
        } else {
            path
        };
        let file = tokio::fs::File::open(target.clone()).await?;
        let meta = file.metadata().await?;
        if !meta.is_file() {
            return Ok(None);
        }
        let mime = match target.extension().and_then(|e| e.to_str()).unwrap_or("") {
            "json" => "application/json",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "js" => "text/javascript",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "svg" => "image/svg+xml",
            "txt" => "text/plain",
            _ => "application/octet-stream",
        };
        let stream = tokio_util::io::ReaderStream::new(file).map(|item| {
            item.map(Frame::data)
                .map_err(|e| -> proxy::BoxError { Box::new(e) })
        });
        Ok(Some(
            Response::builder()
                .header("content-type", mime)
                .header("content-length", meta.len())
                .body(BodyExt::boxed(StreamBody::new(stream)))?,
        ))
    })
}

pub fn simulation(
    actions: &[MatchedAction],
    settings: &mut config::Settings,
    state: &App,
    id: Option<u64>,
) {
    for matched in actions {
        if matched.action.phase() != "simulation" {
            continue;
        }
        let trace = begin(state, id, matched);
        match &matched.action {
            Action::Latency { ms } => settings.latency_ms = *ms,
            Action::Throttle { upload, download } => {
                settings.upload_bytes_per_second = *upload;
                settings.download_bytes_per_second = *download;
            }
            Action::Failure { percent } => settings.failure_percent = *percent,
            Action::Drop {
                upload_after_bytes,
                download_after_bytes,
            } => {
                settings.drop_upload_after_bytes = *upload_after_bytes;
                settings.drop_download_after_bytes = *download_after_bytes;
            }
            Action::NoCache => settings.no_cache = true,
            Action::BlockCookies => settings.block_cookies = true,
            _ => {}
        }
        applied(state, id, trace, None);
    }
}

pub fn fail(state: &Arc<App>, id: Option<u64>, error: &anyhow::Error) {
    state.update(id, |flow| {
        flow.error = Some(format!("{error:#}"));
        flow.phase = "error".into();
        flow.duration_ms = Some(crate::store::now_ms().saturating_sub(flow.started_at));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rewritten_body_expansion_is_bounded() {
        assert!(replace("aaaa", "a", &"x".repeat(EDIT_LIMIT), false).is_err());
    }
}
