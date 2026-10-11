import { Button } from './components/ui/button';
import { NativeSelect } from './components/ui/native-select';
import { Input } from './components/ui/input';
import { Textarea } from './components/ui/textarea';
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { ApiError, post, request } from './api';
import { BodyView } from './Detail';
import { Modal } from './Dialogs';
import { base64, bytes, decode, editableBody, parseHeaders, rawBytes } from './format';
import type {
  BreakpointDecision,
  BreakpointSnapshot,
  BreakpointSummary,
  Message,
  Notify,
} from './types';

function Editor({
  snapshot,
  expired,
  now,
  decide,
}: {
  snapshot: BreakpointSnapshot;
  expired: boolean;
  now: number;
  decide: (decision: BreakpointDecision) => Promise<void>;
}) {
  const [replacement, setReplacement] = useState(false),
    [replaceTrailers, setReplaceTrailers] = useState(false);
  const [body, setBody] = useState(() => editableBody(snapshot.body)),
    [decoded, setDecoded] = useState(false);
  const [status, setStatus] = useState(String(snapshot.status || 200));
  const [sending, setSending] = useState(false),
    [error, setError] = useState('');
  const response = snapshot.phase === 'response';
  const allowedBody =
    snapshot.body_complete &&
    (!response || (snapshot.method !== 'HEAD' && ![101, 204, 205, 304].includes(Number(status))));
  const encoding =
    snapshot.headers
      .find((h) => h[0].toLowerCase() === 'content-encoding')?.[1]
      .trim()
      .toLowerCase() || '';
  const original = useMemo(() => rawBytes(snapshot.body), [snapshot.body]);
  const preview: Message = {
    headers: snapshot.headers,
    trailers: snapshot.trailers,
    body: {
      data: snapshot.body,
      size: original.length,
      complete: snapshot.body_complete,
      truncated: !snapshot.body_complete,
    },
  };
  async function resolve(decision: BreakpointDecision) {
    setSending(true);
    setError('');
    try {
      await decide(decision);
    } catch (error) {
      setError(String(error));
    } finally {
      setSending(false);
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    try {
      const decision: BreakpointDecision = {
        action: 'edit',
        headers: parseHeaders(String(fields.get('headers'))),
        ...(response
          ? { status: Number(status) }
          : { method: String(fields.get('method')), url: String(fields.get('url')) }),
      };
      if (replacement && allowedBody) {
        decision.body =
          body.encoding === 'base64'
            ? base64(rawBytes(body.body.trim()))
            : base64(new TextEncoder().encode(body.body));
        decision.decoded = decoded;
      }
      if (replaceTrailers) decision.trailers = parseHeaders(String(fields.get('trailers')));
      await resolve(decision);
    } catch (error) {
      setError(String(error));
    }
  }
  async function decodeForEditing() {
    try {
      const data = await decode(original, encoding);
      if (data.length > 1024 * 1024)
        throw new Error(
          'Decoded body exceeds the 1 MiB editing limit. Continue unchanged or edit headers.',
        );
      setBody(editableBody(base64(data)));
      setDecoded(true);
      setReplacement(true);
      setError('');
    } catch (error) {
      setError(String(error));
    }
  }
  return (
    <form id="breakpoint-editor" onSubmit={submit}>
      <div className="pause-title">
        <div>
          <span className="eyebrow">{snapshot.phase} paused</span>
          <h3>
            {snapshot.method} {snapshot.url}
          </h3>
        </div>
        <span className="pending-time">
          {expired
            ? 'No longer pending'
            : `${Math.max(0, Math.ceil((snapshot.deadline - now) / 1000))}s remaining`}
        </span>
      </div>
      {expired && (
        <p className="notice">
          This exchange ended after completion, cancellation, or timeout. You cannot send this
          draft.
        </p>
      )}
      {error && (
        <p className="notice" role="alert">
          {error}
        </p>
      )}
      <fieldset disabled={expired || sending}>
        {response ? (
          <label>
            Response status
            <Input
              name="status"
              type="number"
              min={101}
              max={599}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              required
            />
          </label>
        ) : (
          <div className="compose-url">
            <label>
              Method
              <Input name="method" defaultValue={snapshot.method} required />
            </label>
            <label>
              URL
              <Input name="url" type="url" defaultValue={snapshot.url} required />
            </label>
          </div>
        )}
        <label>
          Headers
          <Textarea
            name="headers"
            rows={5}
            defaultValue={snapshot.headers.map((h) => `${h[0]}: ${h[1]}`).join('\n')}
          />
          <small>
            Duplicate names are preserved. Transport framing is regenerated when edits are applied.
          </small>
        </label>
        <div className="check-row">
          <label>
            <input
              name="replace-body"
              type="checkbox"
              checked={replacement && allowedBody}
              disabled={!allowedBody}
              onChange={(e) => setReplacement(e.target.checked)}
            />{' '}
            Replace body
          </label>
          {allowedBody && ['gzip', 'deflate'].includes(encoding) && !decoded && (
            <Button variant="outline" type="button" onClick={() => void decodeForEditing()}>
              Decode {encoding} for editing
            </Button>
          )}
        </div>
        {!snapshot.body_complete && (
          <p className="hint">
            This preview is incomplete. You can change headers or continue the exchange with its
            full stream.
          </p>
        )}
        {replacement && allowedBody && (
          <>
            <div className="body-label">
              <label htmlFor="breakpoint-body">Replacement body</label>
              <NativeSelect
                aria-label="Breakpoint body encoding"
                value={body.encoding}
                onChange={(event) => {
                  try {
                    const data =
                      body.encoding === 'base64'
                        ? rawBytes(body.body.trim())
                        : new TextEncoder().encode(body.body);
                    const encoding = event.target.value as 'text' | 'base64';
                    setBody({
                      encoding,
                      body:
                        encoding === 'text'
                          ? new TextDecoder('utf-8', { fatal: true }).decode(data)
                          : base64(data),
                    });
                  } catch (error) {
                    setError(String(error));
                  }
                }}
              >
                <option value="text">UTF-8 text</option>
                <option value="base64">Base64 bytes</option>
              </NativeSelect>
            </div>
            <Textarea
              id="breakpoint-body"
              rows={7}
              spellCheck={false}
              value={body.body}
              onChange={(e) => setBody({ ...body, body: e.target.value })}
            />
            {decoded && (
              <p className="hint">
                The proxy re-encodes this decoded body with the edited Content-Encoding header.
              </p>
            )}
          </>
        )}
        {snapshot.trailers.length > 0 && (
          <>
            <div className="check-row">
              <label>
                <input
                  type="checkbox"
                  checked={replaceTrailers}
                  disabled={!snapshot.body_complete}
                  onChange={(e) => setReplaceTrailers(e.target.checked)}
                />{' '}
                Replace trailers
              </label>
            </div>
            {replaceTrailers && (
              <label>
                Trailers
                <Textarea
                  name="trailers"
                  rows={3}
                  defaultValue={snapshot.trailers.map((h) => `${h[0]}: ${h[1]}`).join('\n')}
                />
              </label>
            )}
          </>
        )}
        <div className="pause-actions">
          <Button
            variant="outline"
            type="button"
            className="danger"
            onClick={() => void resolve({ action: 'abort' })}
          >
            Abort exchange
          </Button>
          <Button
            variant="outline"
            type="button"
            onClick={() => void resolve({ action: 'continue' })}
          >
            Continue unchanged
          </Button>
          <Button variant="default" type="submit">
            Apply &amp; resume
          </Button>
        </div>
      </fieldset>
      <details className="pause-preview">
        <summary>Original body preview · {bytes(original.length)}</summary>
        <BodyView message={preview} id={snapshot.id} direction={snapshot.phase} paused />
      </details>
    </form>
  );
}

export function BreakpointsDialog({
  entries,
  token,
  close,
  notify,
}: {
  entries: BreakpointSummary[];
  token: string;
  close: () => void;
  notify: Notify;
}) {
  const [selectedId, setSelectedId] = useState(''),
    [snapshot, setSnapshot] = useState<BreakpointSnapshot | null>(null);
  const [resolved, setResolved] = useState<string[]>([]),
    [error, setError] = useState(''),
    [now, setNow] = useState(Date.now);
  const available = entries.filter((e) => !resolved.includes(e.id)),
    first = available[0]?.id;
  const selectedPending = available.some((e) => e.id === selectedId),
    hasDraft = snapshot?.id === selectedId;
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (first && (!selectedId || (!selectedPending && !hasDraft))) setSelectedId(first);
  }, [selectedId, first, selectedPending, hasDraft]);
  useEffect(() => {
    if (!selectedId) {
      setSnapshot(null);
      return;
    }
    const controller = new AbortController();
    setError('');
    request<BreakpointSnapshot>(`breakpoints/${selectedId}`, token, { signal: controller.signal })
      .then((snapshot) => {
        if (!controller.signal.aborted) setSnapshot(snapshot);
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setError(
            error instanceof ApiError && error.status === 404
              ? 'This exchange is no longer pending.'
              : String(error),
          );
      });
    return () => controller.abort();
  }, [selectedId, token]);
  async function decide(decision: BreakpointDecision) {
    if (!snapshot) return;
    await post<void>(`breakpoints/${snapshot.id}`, token, decision);
    setResolved((previous) => [...previous, snapshot.id]);
    setSelectedId(available.find((e) => e.id !== snapshot.id)?.id || '');
    setSnapshot(null);
    notify(decision.action === 'abort' ? 'Exchange aborted' : 'Exchange resumed');
  }
  return (
    <Modal title="Breakpoints" close={close} className="breakpoints-dialog">
      <p className="hint">
        Select a paused exchange for inspection or edits. Traffic stays paused until a decision or
        its deadline, even after this window closes.
      </p>
      <div className="pause-workspace">
        <aside className="breakpoint-list" aria-label="Paused exchanges">
          {available.length ? (
            available.map((entry) => (
              <Button
                variant="outline"
                key={entry.id}
                className={selectedId === entry.id ? 'active' : ''}
                aria-pressed={selectedId === entry.id}
                onClick={() => setSelectedId(entry.id)}
              >
                <span className="eyebrow">
                  {entry.phase} · {Math.max(0, Math.ceil((entry.deadline - now) / 1000))}s
                </span>
                <strong>{entry.method}</strong>
                <span>{entry.url}</span>
              </Button>
            ))
          ) : (
            <p>No pending exchanges. Add a request or response pause in Rules.</p>
          )}
        </aside>
        <div className="pause-editor">
          {error && (
            <p className="notice" role="alert">
              {error}
            </p>
          )}
          {snapshot && snapshot.id === selectedId ? (
            <Editor
              key={snapshot.id}
              snapshot={snapshot}
              expired={!available.some((e) => e.id === snapshot.id) || now >= snapshot.deadline}
              now={now}
              decide={decide}
            />
          ) : (
            <p className="muted">
              {selectedId ? 'Loading paused exchange…' : 'Waiting for an exchange to pause.'}
            </p>
          )}
        </div>
      </div>
    </Modal>
  );
}
