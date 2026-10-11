use crate::{
    proxy::{App, BoxError, ProxyBody},
    rules::{Action, MatchedAction},
    store,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

type Finish = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + Sync>>;
pub async fn wrap(
    inner: ProxyBody,
    actions: &[MatchedAction],
    state: Arc<App>,
    id: Option<u64>,
    phase: &str,
) -> ProxyBody {
    let Some(id) = id else {
        return inner;
    };
    let Some((directory, limit)) = actions
        .iter()
        .rev()
        .find_map(|matched| match &matched.action {
            Action::Mirror {
                directory,
                max_bytes,
            } => Some((directory.clone(), *max_bytes)),
            _ => None,
        })
    else {
        return inner;
    };
    let name = format!("flow-{id}-{}-{phase}.bin", uuid::Uuid::new_v4().simple());
    let mut path = directory.join(&name);
    let setup = async {
        let exists = tokio::fs::try_exists(&directory).await?;
        tokio::fs::create_dir_all(&directory).await?;
        if !exists {
            tokio::fs::set_permissions(
                &directory,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .await?;
        }
        path = tokio::fs::canonicalize(&directory).await?.join(name);
        let temporary = path.with_extension("bin.partial");
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .await?;
        Ok::<_, std::io::Error>((file, temporary))
    }
    .await;
    let mut index = 0;
    state.update(Some(id), |flow| {
        index = flow.metadata.mirrors.len();
        flow.metadata.mirrors.push(store::Mirror {
            phase: phase.into(),
            path: path.display().to_string(),
            ..Default::default()
        });
    });
    match setup {
        Ok((mut file, temporary)) if inner.is_end_stream() => {
            let result = async {
                use tokio::io::AsyncWriteExt;
                file.flush().await?;
                file.sync_all().await?;
                drop(file);
                tokio::fs::rename(&temporary, &path).await
            }
            .await;
            state.update(Some(id), |flow| {
                if let Some(mirror) = flow.metadata.mirrors.get_mut(index) {
                    match result {
                        Ok(()) => mirror.complete = true,
                        Err(error) => {
                            mirror.path = temporary.display().to_string();
                            mirror.error = Some(error.to_string());
                        }
                    }
                }
            });
            inner
        }
        Ok((file, temporary)) => MirrorBody {
            inner,
            file: Some(file),
            temporary,
            path,
            limit,
            written: 0,
            state,
            id,
            index,
            pending: None,
            offset: 0,
            finish: None,
            finished: false,
        }
        .boxed(),
        Err(error) => {
            state.update(Some(id), |flow| {
                if let Some(mirror) = flow.metadata.mirrors.get_mut(index) {
                    mirror.error = Some(error.to_string());
                }
            });
            inner
        }
    }
}
struct MirrorBody {
    inner: ProxyBody,
    file: Option<tokio::fs::File>,
    temporary: PathBuf,
    path: PathBuf,
    limit: u64,
    written: u64,
    state: Arc<App>,
    id: u64,
    index: usize,
    pending: Option<Frame<Bytes>>,
    offset: usize,
    finish: Option<Finish>,
    finished: bool,
}
impl MirrorBody {
    fn failure(&mut self, error: String) {
        self.file = None;
        self.state.update(Some(self.id), |flow| {
            if let Some(mirror) = flow.metadata.mirrors.get_mut(self.index) {
                if mirror.error.is_none() {
                    mirror.error = Some(error);
                }
                mirror.path = self.temporary.display().to_string();
            }
        });
    }
    fn finalize(&mut self) {
        if let Some(mut file) = self.file.take() {
            let temporary = self.temporary.clone();
            let path = self.path.clone();
            self.finish = Some(Box::pin(async move {
                use tokio::io::AsyncWriteExt;
                file.flush().await?;
                file.sync_all().await?;
                drop(file);
                tokio::fs::rename(temporary, path).await
            }));
        } else {
            self.finished = true;
        }
    }
}
impl Body for MirrorBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(finish) = &mut self.finish {
            match finish.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.finish = None;
                    self.finished = true;
                    match result {
                        Ok(()) => self.state.update(Some(self.id), |flow| {
                            if let Some(mirror) = flow.metadata.mirrors.get_mut(self.index) {
                                mirror.complete = true;
                            }
                        }),
                        Err(error) => self.failure(error.to_string()),
                    }
                    return Poll::Ready(self.pending.take().map(Ok));
                }
            }
        }
        if self.finished && self.pending.is_none() {
            return Poll::Ready(None);
        }
        if self.pending.is_some() {
            loop {
                let data = self.pending.as_ref().and_then(Frame::data_ref).cloned();
                let Some(data) = data else {
                    break;
                };
                if self.offset >= data.len() || self.file.is_none() {
                    break;
                }
                let remaining = self.limit.saturating_sub(self.written) as usize;
                if remaining == 0 {
                    let limit = self.limit;
                    self.failure(format!("Mirror exceeded {limit} byte disk limit"));
                    break;
                }
                let offset = self.offset;
                let end = data.len().min(offset.saturating_add(remaining));
                match Pin::new(self.file.as_mut().unwrap()).poll_write(cx, &data[offset..end]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        self.failure("Mirror write made no progress".into());
                        break;
                    }
                    Poll::Ready(Ok(count)) => {
                        self.offset += count;
                        self.written += count as u64;
                        let written = self.written;
                        self.state.update(Some(self.id), |flow| {
                            if let Some(mirror) = flow.metadata.mirrors.get_mut(self.index) {
                                mirror.bytes = written;
                            }
                        });
                    }
                    Poll::Ready(Err(error)) => {
                        self.failure(error.to_string());
                        break;
                    }
                }
            }
            if self.inner.is_end_stream() && !self.finished {
                self.finalize();
                if self.finish.is_some() {
                    return self.poll_frame(cx);
                }
            }
            self.offset = 0;
            return Poll::Ready(self.pending.take().map(Ok));
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.pending = Some(frame);
                self.offset = 0;
                self.poll_frame(cx)
            }
            Poll::Ready(Some(Err(error))) => {
                self.failure(error.to_string());
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finalize();
                if self.finish.is_some() {
                    self.poll_frame(cx)
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.finished && self.pending.is_none()
    }
}
impl Drop for MirrorBody {
    fn drop(&mut self) {
        if !self.finished {
            self.failure("Mirror transfer interrupted".into());
        }
    }
}
