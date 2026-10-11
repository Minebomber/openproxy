use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{proxy::App, store};

const FRAMES: usize = 128;
const PAYLOAD: usize = 16 * 1024;
const TOTAL: usize = 512 * 1024;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Capture {
    pub extensions: String,
    pub frames: Vec<Frame>,
    pub truncated: bool,
    pub complete: bool,
    pub error: Option<String>,
}

impl Capture {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.extensions.len() <= 8192 && self.frames.len() <= FRAMES * 2,
            "WebSocket capture exceeds limits"
        );
        ensure!(
            self.error.as_ref().is_none_or(|e| e.len() <= 1024),
            "invalid WebSocket error"
        );
        let mut total = 0;
        for frame in &self.frames {
            ensure!(
                matches!(frame.direction.as_str(), "client" | "server")
                    && frame.payload.len() <= PAYLOAD
                    && frame.payload.len() as u64 <= frame.size
                    && frame.error.as_ref().is_none_or(|e| e.len() <= 1024),
                "invalid WebSocket frame"
            );
            total += frame.payload.len();
        }
        ensure!(
            total <= TOTAL * 2,
            "WebSocket payload capture exceeds limit"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Frame {
    pub direction: String,
    pub at: u64,
    pub opcode: u8,
    pub fin: bool,
    pub masked: bool,
    pub compressed: bool,
    pub message: u64,
    pub size: u64,
    #[serde(with = "store::binary")]
    pub payload: Vec<u8>,
    pub truncated: bool,
    pub complete: bool,
    pub error: Option<String>,
}

struct Parser {
    client: bool,
    compression: bool,
    header: Vec<u8>,
    current: Option<Frame>,
    remaining: u64,
    mask: [u8; 4],
    offset: u64,
    frames: usize,
    captured: usize,
    fragment: Option<(u8, bool)>,
    message: u64,
    stopped: bool,
}

impl Parser {
    fn new(client: bool, compression: bool) -> Self {
        Self {
            client,
            compression,
            header: Vec::with_capacity(14),
            current: None,
            remaining: 0,
            mask: [0; 4],
            offset: 0,
            frames: 0,
            captured: 0,
            fragment: None,
            message: 0,
            stopped: false,
        }
    }

    fn start(&mut self) -> Result<()> {
        let h = &self.header;
        let opcode = h[0] & 15;
        let fin = h[0] & 128 != 0;
        let masked = h[1] & 128 != 0;
        let short = h[1] & 127;
        let (size, n) = match short {
            126 => (u16::from_be_bytes(h[2..4].try_into().unwrap()) as u64, 4),
            127 => (u64::from_be_bytes(h[2..10].try_into().unwrap()), 10),
            n => (n as u64, 2),
        };
        ensure!(
            size <= i64::MAX as u64,
            "invalid WebSocket 64-bit length; inspection stopped"
        );
        let mut issues = Vec::new();
        if masked != self.client {
            issues.push("unexpected masking");
        }
        if h[0] & 0x30 != 0 {
            issues.push("reserved bits set");
        }
        if (short == 126 && size < 126) || (short == 127 && size <= 65535) {
            issues.push("non-minimal payload length");
        }
        if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
            issues.push("reserved opcode");
        }
        if opcode >= 8 && (!fin || size > 125 || h[0] & 0x40 != 0) {
            issues.push("invalid control frame");
        }
        let compressed = if opcode == 0 {
            if self.fragment.is_none() {
                issues.push("continuation without a fragmented message");
            }
            if h[0] & 0x40 != 0 {
                issues.push("RSV1 on continuation");
            }
            self.fragment.is_some_and(|(_, compressed)| compressed)
        } else {
            h[0] & 0x40 != 0
        };
        if compressed && !self.compression {
            issues.push("compression not negotiated");
        }
        if opcode == 1 || opcode == 2 {
            self.message += 1;
            if self.fragment.is_some() {
                issues.push("new message before previous fragment finished");
            }
            self.fragment = (!fin).then_some((opcode, compressed));
        } else if opcode == 0 && fin {
            self.fragment = None;
        }
        if masked {
            self.mask.copy_from_slice(&h[n..n + 4]);
        }
        self.remaining = size;
        self.offset = 0;
        self.current = Some(Frame {
            direction: if self.client { "client" } else { "server" }.into(),
            at: store::now_ms(),
            opcode,
            fin,
            masked,
            compressed,
            message: self.message,
            size,
            payload: Vec::new(),
            truncated: false,
            complete: false,
            error: (!issues.is_empty()).then(|| issues.join("; ")),
        });
        self.header.clear();
        Ok(())
    }

    fn feed(&mut self, mut data: &[u8], mut emit: impl FnMut(Frame)) -> Result<()> {
        while !data.is_empty() && !self.stopped {
            if self.current.is_none() {
                if self.frames >= FRAMES {
                    self.stopped = true;
                    break;
                }
                self.header.push(data[0]);
                data = &data[1..];
                if self.header.len() < 2 {
                    continue;
                }
                let required =
                    2 + match self.header[1] & 127 {
                        126 => 2,
                        127 => 8,
                        _ => 0,
                    } + if self.header[1] & 128 != 0 { 4 } else { 0 };
                if self.header.len() < required {
                    continue;
                }
                self.start()?;
            }
            let frame = self.current.as_mut().unwrap();
            let n = self.remaining.min(data.len() as u64) as usize;
            let keep = n
                .min(PAYLOAD.saturating_sub(frame.payload.len()))
                .min(TOTAL.saturating_sub(self.captured));
            for (i, byte) in data[..keep].iter().enumerate() {
                frame.payload.push(if frame.masked {
                    byte ^ self.mask[((self.offset + i as u64) % 4) as usize]
                } else {
                    *byte
                });
            }
            self.captured += keep;
            frame.truncated |= keep < n;
            self.remaining -= n as u64;
            self.offset += n as u64;
            data = &data[n..];
            if self.remaining == 0 {
                let mut frame = self.current.take().unwrap();
                frame.complete = true;
                if frame.opcode == 8 && frame.size == 1 {
                    frame.error =
                        Some("close payload must be empty or include a two-byte code".into());
                }
                if frame.opcode == 1
                    && frame.fin
                    && !frame.compressed
                    && !frame.truncated
                    && std::str::from_utf8(&frame.payload).is_err()
                {
                    frame.error = Some("invalid UTF-8 text".into());
                }
                emit(frame);
                self.frames += 1;
            }
        }
        Ok(())
    }
}

// Observe only reads. Let copy_bidirectional keep the initial bytes and half-close behavior.
pub struct Observer<T> {
    inner: T,
    parser: Parser,
    state: Arc<App>,
    id: Option<u64>,
}

impl<T> Observer<T> {
    pub fn new(
        inner: T,
        state: Arc<App>,
        id: Option<u64>,
        client: bool,
        compression: bool,
    ) -> Self {
        Self {
            inner,
            parser: Parser::new(client, compression),
            state,
            id,
        }
    }
}

impl<T> Drop for Observer<T> {
    fn drop(&mut self) {
        self.state.update(self.id, |f| {
            if let Some(ws) = &mut f.metadata.websocket {
                if let Some(frame) = self.parser.current.take() {
                    ws.frames.push(frame);
                    ws.error
                        .get_or_insert("connection ended during a frame".into());
                }
                if !self.parser.header.is_empty() || self.parser.fragment.is_some() {
                    ws.error.get_or_insert(
                        "connection ended during a frame or fragmented message".into(),
                    );
                }
                ws.truncated |= self.parser.stopped;
            }
        });
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Observer<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let this = &mut *self;
            let mut frames = Vec::new();
            let error = this
                .parser
                .feed(&buf.filled()[before..], |f| frames.push(f))
                .err();
            if error.is_some() {
                this.parser.stopped = true;
            }
            this.state.update(this.id, |f| {
                if let Some(ws) = &mut f.metadata.websocket {
                    ws.truncated |= frames.iter().any(|frame| frame.truncated);
                    ws.frames.extend(frames);
                    ws.truncated |= this.parser.stopped;
                    if let Some(error) = error {
                        ws.error = Some(error.to_string());
                    }
                }
            });
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Observer<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_and_frame_count_are_bounded() {
        let mut parser = Parser::new(false, false);
        let mut input = vec![0x82, 126, 0xff, 0xff];
        input.resize(65539, 7);
        let mut frames = Vec::new();
        parser.feed(&input, |f| frames.push(f)).unwrap();
        assert_eq!(frames[0].payload.len(), PAYLOAD);
        assert!(frames[0].truncated);
        for _ in 0..FRAMES + 1 {
            parser.feed(&[0x89, 0], |f| frames.push(f)).unwrap();
        }
        assert_eq!(frames.len(), FRAMES);
        assert!(parser.stopped);
    }
}
