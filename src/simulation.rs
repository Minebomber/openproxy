use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{Instant, Sleep},
};

use crate::{
    config::Settings,
    proxy::{BoxError, ProxyBody},
};

struct Bucket {
    rate: u64,
    credit: f64,
    updated: Instant,
}
impl Bucket {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            credit: 0.0,
            updated: Instant::now(),
        }
    }
    fn quantum(&self) -> usize {
        if self.rate == 0 {
            16_384
        } else {
            (self.rate / 20).clamp(1, 16_384) as usize
        }
    }
    fn replenish(&mut self, now: Instant) {
        self.credit = (self.credit
            + now.duration_since(self.updated).as_secs_f64() * self.rate as f64)
            .min(self.quantum() as f64);
        self.updated = now;
    }
    fn wait(&self, bytes: usize) -> Duration {
        if self.rate == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((bytes as f64 - self.credit).max(0.0) / self.rate as f64)
        }
    }
    fn consume(&mut self, bytes: usize) {
        if self.rate > 0 {
            self.credit = (self.credit - bytes as f64).max(0.0);
        }
    }
}

pub struct Limits {
    upload: Arc<Mutex<Bucket>>,
    download: Arc<Mutex<Bucket>>,
}
impl Limits {
    pub fn new(settings: &Settings) -> Self {
        Self {
            upload: Arc::new(Mutex::new(Bucket::new(
                settings.aggregate_upload_bytes_per_second,
            ))),
            download: Arc::new(Mutex::new(Bucket::new(
                settings.aggregate_download_bytes_per_second,
            ))),
        }
    }
    pub fn configure(&self, settings: &Settings) {
        for (bucket, rate) in [
            (&self.upload, settings.aggregate_upload_bytes_per_second),
            (&self.download, settings.aggregate_download_bytes_per_second),
        ] {
            let mut bucket = bucket.lock().unwrap();
            if bucket.rate != rate {
                *bucket = Bucket::new(rate);
            }
        }
    }
    fn gate(&self, settings: &Settings, upload: bool) -> Gate {
        Gate {
            local: Bucket::new(if upload {
                settings.upload_bytes_per_second
            } else {
                settings.download_bytes_per_second
            }),
            aggregate: if upload {
                self.upload.clone()
            } else {
                self.download.clone()
            },
            drop_after: if upload {
                settings.drop_upload_after_bytes
            } else {
                settings.drop_download_after_bytes
            },
            sent: 0,
            delay: None,
        }
    }
}

struct Gate {
    local: Bucket,
    aggregate: Arc<Mutex<Bucket>>,
    drop_after: Option<u64>,
    sent: u64,
    delay: Option<Pin<Box<Sleep>>>,
}
impl Gate {
    fn poll(&mut self, cx: &mut Context<'_>, bytes: usize) -> Poll<io::Result<usize>> {
        if self.drop_after.is_some_and(|limit| self.sent >= limit) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("simulated connection drop after {} bytes", self.sent),
            )));
        }
        if let Some(delay) = &mut self.delay {
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.delay = None;
        }
        let now = Instant::now();
        let wait;
        let count;
        {
            let mut aggregate = self.aggregate.lock().unwrap();
            count = bytes
                .min(self.local.quantum())
                .min(aggregate.quantum())
                .min(self.drop_after.map_or(usize::MAX, |limit| {
                    (limit - self.sent).min(usize::MAX as u64) as usize
                }));
            self.local.replenish(now);
            aggregate.replenish(now);
            wait = self.local.wait(count).max(aggregate.wait(count));
            if wait.is_zero() {
                self.local.consume(count);
                aggregate.consume(count);
                return Poll::Ready(Ok(count));
            }
        }
        // Waiters do not reserve future capacity. Cancellation cannot block another transfer.
        self.delay = Some(Box::pin(tokio::time::sleep_until(
            now + wait.max(Duration::from_millis(1)),
        )));
        self.poll(cx, bytes)
    }
}

pub fn check(settings: &Settings) -> anyhow::Result<()> {
    anyhow::ensure!(!settings.offline, "offline simulation");
    let sample = (uuid::Uuid::new_v4().as_u128() % 100) as u8;
    anyhow::ensure!(
        sample >= settings.failure_percent,
        "simulated connection failure"
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub struct UploadProgress {
    deadline: Instant,
    complete: bool,
}
fn progress(complete: bool, waiting_until: Instant) -> UploadProgress {
    UploadProgress {
        deadline: waiting_until + Duration::from_secs(if complete { 120 } else { 30 }),
        complete,
    }
}

pub async fn headers<T>(
    future: impl Future<Output = anyhow::Result<T>>,
    mut upload: watch::Receiver<UploadProgress>,
) -> anyhow::Result<T> {
    tokio::pin!(future);
    loop {
        let current = *upload.borrow_and_update();
        tokio::select! {
            result = &mut future => return result,
            changed = upload.changed(), if upload.has_changed().is_ok() => { let _ = changed; },
            _ = tokio::time::sleep_until(current.deadline) => anyhow::bail!(if current.complete { "upstream response headers timed out after upload" } else { "upload stalled without progress" }),
        }
    }
}

pub fn body(
    inner: ProxyBody,
    limits: &Limits,
    settings: &Settings,
    upload: bool,
) -> (ProxyBody, watch::Receiver<UploadProgress>) {
    let done = inner.is_end_stream()
        && if upload {
            settings.drop_upload_after_bytes != Some(0)
        } else {
            settings.drop_download_after_bytes != Some(0)
        };
    let (progress, receiver) = watch::channel(progress(done, Instant::now()));
    (
        SimulatedBody {
            inner,
            gate: limits.gate(settings, upload),
            pending: Bytes::new(),
            done,
            drop_delay: None,
            progress,
        }
        .boxed(),
        receiver,
    )
}

struct SimulatedBody {
    inner: ProxyBody,
    gate: Gate,
    pending: Bytes,
    done: bool,
    drop_delay: Option<Pin<Box<Sleep>>>,
    progress: watch::Sender<UploadProgress>,
}
impl SimulatedBody {
    fn report(&self, complete: bool, until: Instant) {
        let next = progress(complete, until);
        self.progress.send_if_modified(|current| {
            if current.deadline == next.deadline && current.complete == next.complete {
                return false;
            }
            *current = next;
            true
        });
    }
}
impl Body for SimulatedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self
            .gate
            .drop_after
            .is_some_and(|limit| self.gate.sent >= limit)
        {
            // Yield once so Hyper sends the accepted bytes before the simulated body error.
            let delay = self
                .drop_delay
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(1))));
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.done = true;
            return Poll::Ready(Some(Err(format!(
                "simulated connection drop after {} bytes",
                self.gate.sent
            )
            .into())));
        }
        if self.pending.is_empty() {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) if !data.is_empty() => self.pending = data,
                    other => {
                        let frame = match other {
                            Ok(data) => Frame::data(data),
                            Err(frame) => frame,
                        };
                        self.done = frame.trailers_ref().is_some() || self.inner.is_end_stream();
                        self.report(self.done, Instant::now());
                        return Poll::Ready(Some(Ok(frame)));
                    }
                },
                Poll::Ready(result) => {
                    self.done = true;
                    self.report(true, Instant::now());
                    return Poll::Ready(result);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let len = self.pending.len();
        match self.gate.poll(cx, len) {
            Poll::Ready(Ok(count)) => {
                let bytes = self.pending.split_to(count);
                self.gate.sent += count as u64;
                self.done = self.pending.is_empty()
                    && self.inner.is_end_stream()
                    && self
                        .gate
                        .drop_after
                        .is_none_or(|limit| self.gate.sent < limit);
                self.report(self.done, Instant::now());
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Err(error)) => {
                self.done = true;
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Pending => {
                let until = self
                    .gate
                    .delay
                    .as_ref()
                    .map_or(Instant::now(), |delay| delay.deadline());
                self.report(false, until);
                Poll::Pending
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        let lower = hint.lower().saturating_add(self.pending.len() as u64);
        let upper = hint
            .upper()
            .map(|upper| upper.saturating_add(self.pending.len() as u64));
        if let Some(upper) = upper {
            hint.set_upper(upper);
        }
        hint.set_lower(lower);
        hint
    }
}

struct SimulatedIo<T> {
    inner: T,
    gate: Gate,
    allowance: Option<usize>,
}
impl<T: AsyncRead + Unpin> AsyncRead for SimulatedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for SimulatedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = match self.allowance {
            Some(count) => count.min(bytes.len()),
            None => match self.gate.poll(cx, bytes.len()) {
                Poll::Ready(Ok(count)) => {
                    self.allowance = Some(count);
                    count
                }
                other => return other,
            },
        };
        match Pin::new(&mut self.inner).poll_write(cx, &bytes[..count]) {
            Poll::Ready(result) => {
                self.allowance = None;
                if let Ok(count) = result {
                    self.gate.sent += count as u64;
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self
            .gate
            .drop_after
            .is_some_and(|limit| self.gate.sent >= limit)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "simulated connection drop",
            )));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn copy<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    client: &mut A,
    upstream: &mut B,
    limits: &Limits,
    settings: &Settings,
) -> io::Result<(u64, u64)> {
    if settings.latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(settings.latency_ms)).await;
    }
    tokio::io::copy_bidirectional(
        &mut SimulatedIo {
            inner: client,
            gate: limits.gate(settings, false),
            allowance: None,
        },
        &mut SimulatedIo {
            inner: upstream,
            gate: limits.gate(settings, true),
            allowance: None,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aggregate_budget_is_shared_and_cancellation_reserves_nothing() {
        let settings = Settings {
            aggregate_download_bytes_per_second: 200,
            ..Default::default()
        };
        let limits = Limits::new(&settings);
        let (left, _) = body(crate::proxy::full(vec![1; 100]), &limits, &settings, false);
        let (right, _) = body(crate::proxy::full(vec![2; 100]), &limits, &settings, false);
        let started = Instant::now();
        let (left, right) = tokio::join!(left.collect(), right.collect());
        assert_eq!(left.unwrap().to_bytes(), vec![1; 100]);
        assert_eq!(right.unwrap().to_bytes(), vec![2; 100]);
        assert!(started.elapsed() >= Duration::from_millis(900));
        let mut cancelled = limits.gate(&settings, false);
        futures_util::future::poll_fn(|cx| {
            assert!(cancelled.poll(cx, 10).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(cancelled);
        let (next, _) = body(crate::proxy::full(vec![3; 10]), &limits, &settings, false);
        tokio::time::timeout(Duration::from_millis(150), next.collect())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn header_wait_tracks_upload_progress_then_has_a_deadline() {
        let (sender, receiver) = watch::channel(UploadProgress {
            deadline: Instant::now() + Duration::from_millis(40),
            complete: false,
        });
        let upload = async {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                sender.send_replace(UploadProgress {
                    deadline: Instant::now() + Duration::from_millis(40),
                    complete: false,
                });
            }
            sender.send_replace(UploadProgress {
                deadline: Instant::now() + Duration::from_millis(40),
                complete: true,
            });
            Ok(7)
        };
        assert_eq!(headers(upload, receiver).await.unwrap(), 7);
        let (_sender, receiver) = watch::channel(UploadProgress {
            deadline: Instant::now() + Duration::from_millis(10),
            complete: true,
        });
        assert!(
            headers(
                futures_util::future::pending::<anyhow::Result<()>>(),
                receiver
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("after upload")
        );
    }
}
