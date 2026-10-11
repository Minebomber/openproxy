use crate::{
    protocols::{self, Direction},
    proxy::{self, Upstream},
    store::Message,
};
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::Request;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Html,
    Css,
    Feed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validate {
    pub direction: Direction,
    #[serde(default)]
    pub original: bool,
    pub service: Service,
    #[serde(default)]
    pub consent: bool,
}

pub struct Prepared {
    uri: &'static str,
    content_type: &'static str,
    data: Vec<u8>,
    bytes: usize,
}

pub fn prepare(message: &Message, options: &Validate) -> Result<Prepared> {
    ensure!(
        options.consent,
        "explicit consent is required before sending this body to an external validator"
    );
    ensure!(
        message.body.complete && !message.body.truncated,
        "external validation requires a complete captured body"
    );
    let data = protocols::body_bytes(message)?;
    let text = std::str::from_utf8(&data)?;
    let bytes = data.len();
    Ok(match options.service {
        Service::Html => Prepared {
            uri: "https://validator.w3.org/nu/?out=json",
            content_type: "text/html; charset=utf-8",
            data,
            bytes,
        },
        Service::Css => Prepared {
            uri: "https://jigsaw.w3.org/css-validator/validator",
            content_type: "application/x-www-form-urlencoded",
            data: url::form_urlencoded::Serializer::new(String::new())
                .append_pair("text", text)
                .append_pair("output", "soap12")
                .append_pair("profile", "css3")
                .finish()
                .into_bytes(),
            bytes,
        },
        Service::Feed => Prepared {
            uri: "https://validator.w3.org/feed/check.cgi",
            content_type: "application/x-www-form-urlencoded",
            data: url::form_urlencoded::Serializer::new(String::new())
                .append_pair("rawdata", text)
                .append_pair("manual", "1")
                .append_pair("output", "soap12")
                .finish()
                .into_bytes(),
            bytes,
        },
    })
}

pub async fn send(client: Upstream, prepared: Prepared) -> Result<Value> {
    static SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let _permit = SLOT.try_acquire()?;
    {
        let mut last = LAST.lock().unwrap();
        ensure!(
            last.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)),
            "wait at least one second between validator requests"
        );
        *last = Some(Instant::now());
    }
    send_inner(client, prepared).await
}

async fn send_inner(client: Upstream, prepared: Prepared) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        // Make a new request without the captured URL, cookies, authorization, or headers.
        let request = Request::builder().method("POST").uri(prepared.uri)
            .header("content-type", prepared.content_type)
            .header("accept", "application/json, application/soap+xml, text/plain")
            .header("user-agent", concat!("OpenProxy/", env!("CARGO_PKG_VERSION")))
            .body(proxy::full(Bytes::from(prepared.data)))?;
        let mut response = client.request(request).await?;
        let status = response.status().as_u16();
        let mut data = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            if let Ok(bytes) = frame?.into_data() {
                ensure!(data.len() + bytes.len() <= 256 * 1024, "validator response exceeds 256 KiB");
                data.extend_from_slice(&bytes);
            }
        }
        ensure!((200..300).contains(&status), "validator returned HTTP {status}; redirects are not followed");
        Ok(json!({"endpoint": prepared.uri, "sent_bytes": prepared.bytes, "status": status, "output": String::from_utf8_lossy(&data)}))
    }).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client() -> Upstream {
        use clap::Parser;
        let options = crate::Options::parse_from(["openproxy"]);
        crate::proxy::App::build_client(
            std::sync::Arc::new(crate::connector::Options::load(&options).unwrap()),
            None,
            Default::default(),
        )
    }

    fn options(service: Service, consent: bool) -> Validate {
        Validate {
            direction: Direction::Response,
            original: false,
            service,
            consent,
        }
    }
    fn message(text: &str) -> Message {
        Message {
            headers: vec![
                ["authorization".into(), "SECRET".into()],
                ["cookie".into(), "SECRET".into()],
            ],
            body: crate::store::CapturedBody {
                data: text.as_bytes().to_vec(),
                size: text.len() as u64,
                complete: true,
                truncated: false,
            },
            ..Default::default()
        }
    }

    #[test]
    fn consent_complete_capture_and_fixed_destinations_are_required() {
        let mut message = message("body { color: red; }");
        assert!(prepare(&message, &options(Service::Css, false)).is_err());
        message.body.truncated = true;
        assert!(prepare(&message, &options(Service::Css, true)).is_err());
        message.body.truncated = false;
        let prepared = prepare(&message, &options(Service::Css, true)).unwrap();
        let fields: Vec<_> = url::form_urlencoded::parse(&prepared.data)
            .into_owned()
            .collect();
        assert_eq!(fields[0], ("text".into(), "body { color: red; }".into()));
        assert_eq!(
            prepared.uri,
            "https://jigsaw.w3.org/css-validator/validator"
        );
        assert!(
            prepare(&message, &options(Service::Feed, true))
                .unwrap()
                .data
                .starts_with(b"rawdata=body")
        );
    }

    #[tokio::test]
    async fn validator_request_sends_only_selected_body_and_returns_plain_output() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri: &'static str =
            Box::leak(format!("http://{}/check", listener.local_addr().unwrap()).into_boxed_str());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                received.extend_from_slice(&chunk[..n]);
                if received.ends_with(b"<html>fixture</html>") {
                    break;
                }
                assert!(n > 0);
            }
            let text = String::from_utf8(received).unwrap();
            assert!(!text.contains("SECRET"));
            assert!(text.starts_with("POST /check HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\n<script>fixture</script>\n").await.unwrap();
        });
        let client = client();
        let mut prepared = prepare(
            &message("<html>fixture</html>"),
            &options(Service::Html, true),
        )
        .unwrap();
        prepared.uri = uri;
        let value = send_inner(client, prepared).await.unwrap();
        assert_eq!(value["output"], "<script>fixture</script>\n");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn validator_response_limit_and_redirect_rejection() {
        let client = client();
        for (status, body, expected) in [
            (302, Vec::new(), "redirects are not followed"),
            (200, vec![b'x'; 256 * 1024 + 1], "exceeds 256 KiB"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let uri: &'static str = Box::leak(
                format!("http://{}/check", listener.local_addr().unwrap()).into_boxed_str(),
            );
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut byte = [0];
                while !data.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).await.unwrap();
                    data.push(byte[0]);
                }
                stream.read_exact(&mut byte).await.unwrap();
                let headers = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nLocation: https://fixture.invalid/never-follow\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                let _ = stream.write_all(&body).await;
            });
            let mut prepared = prepare(&message("x"), &options(Service::Html, true)).unwrap();
            prepared.uri = uri;
            let error = send_inner(client.clone(), prepared).await.unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            task.await.unwrap();
        }
    }
}
