import { cn } from 'cn';
import { Button } from './components/ui/button';
import { NativeSelect } from './components/ui/native-select';
import { Textarea } from './components/ui/textarea';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { address, bytes, decode, decodedText, download, header, hex, rawBytes } from './format';
import { formatXml } from './xml';
import { ProtocolTools, WebSocketFrames } from './ProtocolTools';
import type { Flow, Headers, Message, Notify } from './types';

type Tab = 'overview' | 'request' | 'response' | 'timing';
const tabs: Tab[] = ['overview', 'request', 'response', 'timing'];

function Annotation({
  flow,
  save,
  notify,
}: {
  flow: Flow;
  save: (note: string, marked: boolean) => Promise<void>;
  notify: Notify;
}) {
  const [note, setNote] = useState(flow.metadata.note);
  const [marked, setMarked] = useState(flow.metadata.marked);
  const [saving, setSaving] = useState(false);
  return (
    <form
      className="mt-6 space-y-3"
      onSubmit={async (event) => {
        event.preventDefault();
        setSaving(true);
        try {
          await save(note, marked);
          notify('Note and mark saved');
        } catch (error) {
          notify(String(error), true);
        } finally {
          setSaving(false);
        }
      }}
    >
      <label className="section-heading block" htmlFor="flow-note">
        Notes
      </label>
      <Textarea
        id="flow-note"
        value={note}
        maxLength={8192}
        rows={3}
        placeholder="What matters about this exchange?"
        onChange={(event) => setNote(event.target.value)}
      />
      <div className="flex items-center justify-between gap-3">
        <label className="flex items-center gap-2 text-xs">
          <input
            id="flow-marked"
            type="checkbox"
            checked={marked}
            onChange={(event) => setMarked(event.target.checked)}
          />{' '}
          Mark this exchange
        </label>
        <Button id="save-annotation" type="submit" size="sm" variant="outline" disabled={saving}>
          Save note &amp; mark
        </Button>
      </div>
    </form>
  );
}

export function HeaderTable({ headers }: { headers: Headers }) {
  return (
    <table className="headers-table">
      <tbody>
        {headers.map(([name, value], i) => (
          <tr key={i}>
            <td>{name}</td>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
function Info({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="info-grid">
      {rows.map(([key, value]) => (
        <div className="info-pair" key={key}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
function tree(value: unknown, name = 'root', depth = 0, budget = { remaining: 2000 }): ReactNode {
  if (--budget.remaining < 0 || depth > 30)
    return <div key={name}>{name}: … (view as text for the rest)</div>;
  if (value === null || typeof value !== 'object')
    return (
      <div key={name}>
        {name}: {JSON.stringify(value)}
      </div>
    );
  const record = value as Record<string, unknown>,
    keys = Object.keys(value),
    children: ReactNode[] = [];
  for (const key of keys) {
    if (budget.remaining <= 0) {
      children.push(<div key="remaining">… remaining fields omitted from tree</div>);
      break;
    }
    children.push(tree(record[key], key, depth + 1, budget));
  }
  return (
    <details key={name} open={depth < 2}>
      <summary>
        {name} {Array.isArray(value) ? `[${keys.length}]` : `{${keys.length}}`}
      </summary>
      {children}
    </details>
  );
}
function CapturedImage({ data, mime }: { data: Uint8Array<ArrayBuffer>; mime: string }) {
  const [url, setUrl] = useState('');
  useEffect(() => {
    const url = URL.createObjectURL(new Blob([data], { type: mime }));
    setUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [data, mime]);
  return <img src={url || undefined} alt="Captured response image" />;
}
export function BodyView({
  message,
  id,
  direction,
  paused = false,
}: {
  message: Message;
  id: number | string;
  direction: string;
  paused?: boolean;
}) {
  const [mode, setMode] = useState('pretty');
  const raw = useMemo(() => rawBytes(message.body.data), [message.body.data]);
  const encoding = header(message, 'content-encoding').trim().toLowerCase();
  const [preview, setPreview] = useState<{ data?: Uint8Array<ArrayBuffer>; error?: string }>({});
  useEffect(() => {
    let active = true;
    if (mode !== 'hex') {
      setPreview({});
      decode(raw, encoding)
        .then((data) => {
          if (active) setPreview({ data });
        })
        .catch((error) => {
          if (active) setPreview({ error: String(error) });
        });
    }
    return () => {
      active = false;
    };
  }, [raw, encoding, mode]);
  let content: ReactNode = 'Loading preview…';
  if (mode === 'hex') content = hex(raw);
  else if (preview.error)
    content = `${preview.error}\nSwitch to hex to inspect original captured bytes.`;
  else if (preview.data) {
    const contentType = header(message, 'content-type'),
      mime = contentType.split(';')[0].toLowerCase();
    try {
      const text = decodedText(preview.data, contentType);
      if (mode === 'image') {
        if (!/^image\/(png|jpeg|gif|webp|avif|bmp)$/.test(mime))
          throw new Error('No supported image content type.');
        content = <CapturedImage data={preview.data} mime={mime} />;
      } else if (mode === 'tree') content = tree(JSON.parse(text));
      else if (mode === 'pretty') {
        if (mime.includes('x-www-form-urlencoded'))
          content = [...new URLSearchParams(text)].map(([k, v]) => `${k}: ${v}`).join('\n');
        else if (mime.includes('xml')) content = formatXml(text);
        else {
          try {
            content = JSON.stringify(JSON.parse(text), null, 2);
          } catch {
            content = text;
          }
        }
      } else content = text;
      if (content === '') content = '(empty body)';
    } catch (error) {
      content = `${String(error)}\nSwitch to text or hex to inspect the body.`;
    }
  }
  return (
    <>
      <div className="body-tools">
        <h3 className="section-heading">Body · {bytes(message.body.size)}</h3>
        <div>
          <NativeSelect
            className="h-7 text-xs"
            aria-label="Body display mode"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
          >
            {[
              ['pretty', 'Pretty'],
              ['text', 'Text'],
              ['tree', 'JSON tree'],
              ['hex', 'Hex'],
              ['image', 'Image'],
            ].map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </NativeSelect>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            onClick={() => download(raw, `flow-${id}-${direction}.bin`)}
          >
            ↓ Body
          </Button>
        </div>
      </div>
      {message.body.truncated && (
        <p className="notice">
          {paused
            ? `Captured prefix: ${bytes(raw.length)}. Remaining bytes continue through the proxy after resume.`
            : `Captured prefix: ${bytes(raw.length)}. Total transfer: ${bytes(message.body.size)}. Capture limits did not change forwarding.`}
        </p>
      )}
      {!message.body.complete && !paused && (
        <p className="notice">This body has an active or interrupted transfer.</p>
      )}
      <div className="body-content">{content}</div>
    </>
  );
}

export function Detail({
  flow,
  token,
  onReplay,
  onEdit,
  onCurl,
  onDelete,
  onAnnotate,
  notify,
}: {
  flow: Flow | null;
  token: string;
  onReplay: () => void;
  onEdit: () => void;
  onCurl: () => void;
  onDelete: () => void;
  onAnnotate: (note: string, marked: boolean) => Promise<void>;
  notify: Notify;
}) {
  const [tab, setTab] = useState<Tab>('overview');
  const [snapshot, setSnapshot] = useState('effective');
  if (!flow)
    return (
      <section className="inspector" aria-label="Request inspector">
        <div className="detail-empty">
          <span>↖</span>
          <h2>Inspect an exchange</h2>
          <p>Select a request to see its captured data.</p>
        </div>
      </section>
    );
  const url = address(flow.url),
    editable =
      !flow.request.body.truncated && flow.request.body.complete && flow.protocol !== 'TCP tunnel';
  const message =
    tab === 'request'
      ? snapshot === 'original'
        ? flow.metadata.original_request
        : flow.request
      : snapshot === 'original'
        ? flow.metadata.original_response
        : flow.response;
  const total = flow.duration_ms || 0,
    wait = flow.headers_received_ms || 0;
  const cookies: Headers = flow.request.headers
    .filter((h) => h[0].toLowerCase() === 'cookie')
    .flatMap((h) =>
      h[1].split(';').map((s) => {
        const i = s.indexOf('=');
        return [s.slice(0, i).trim(), s.slice(i + 1)] as [string, string];
      }),
    );
  return (
    <section className="inspector" aria-label="Request inspector">
      <div id="detail">
        <div className="detail-heading">
          <span className="eyebrow">
            {flow.method} · {flow.status || flow.phase} · {flow.protocol}
          </span>
          <h2>{url.pathname}</h2>
          <p>{flow.url}</p>
          <div className="detail-actions">
            <Button
              variant="outline"
              size="sm"
              className="text-xs"
              id="replay"
              disabled={!editable}
              onClick={onReplay}
            >
              ↻ Repeat
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-xs"
              id="edit"
              disabled={!editable}
              onClick={onEdit}
            >
              Edit
            </Button>
            <Button variant="outline" size="sm" className="text-xs" id="curl" onClick={onCurl}>
              Copy cURL
            </Button>
            <Button variant="outline" size="sm" className="text-xs" id="delete" onClick={onDelete}>
              Delete
            </Button>
          </div>
        </div>
        <nav className="tabs" aria-label="Request detail">
          {tabs.map((value) => (
            <Button
              variant="ghost"
              key={value}
              data-tab={value}
              className={cn(
                'h-10 rounded-none border-0 border-b-2 border-transparent px-0 text-xs text-muted-foreground shadow-none hover:bg-transparent',
                tab === value && 'border-primary text-primary',
              )}
              onClick={() => setTab(value)}
            >
              {value[0].toUpperCase() + value.slice(1)}
            </Button>
          ))}
        </nav>
        <div className="detail-content" id="detail-content">
          {flow.error && <p className="notice">{flow.error}</p>}
          {flow.protocol === 'TCP tunnel' && (
            <p className="notice">
              Opaque TCP tunnel: this exchange has byte counts and connection metadata. HTTP message
              bodies are not available for editing or replay.
            </p>
          )}
          {tab === 'overview' ? (
            <>
              <h3 className="section-heading">Exchange</h3>
              <Info
                rows={[
                  ['URL', flow.url],
                  ['Method', flow.method],
                  ['Forwarded method', flow.metadata.upstream_method || flow.method],
                  ['Status', flow.status ?? 'Awaiting response'],
                  ['Client', flow.client],
                  [
                    'Client process',
                    flow.metadata.process
                      ? `${flow.metadata.process.name} (PID ${flow.metadata.process.pid})`
                      : 'Unattributed',
                  ],
                  ['Protocol', flow.protocol],
                  ['Encryption', flow.tls ? 'HTTPS / TLS' : 'Plain HTTP'],
                  ['Started', new Date(flow.started_at).toLocaleString()],
                  ['State', flow.phase],
                  [
                    'Request body',
                    `${bytes(flow.request.body.size)}${flow.request.body.truncated ? ' (capture truncated)' : ''}`,
                  ],
                  [
                    'Response body',
                    `${bytes(flow.response?.body.size || 0)}${flow.response?.body.truncated ? ' (capture truncated)' : ''}`,
                  ],
                ]}
              />
              {flow.metadata.connection && (
                <>
                  <h3 className="section-heading">Upstream connection</h3>
                  <Info
                    rows={[
                      ['ID', flow.metadata.connection.id],
                      ['Local socket', flow.metadata.connection.local_address],
                      ['Remote socket', flow.metadata.connection.remote_address],
                      ['Protocol', flow.metadata.upstream_protocol || 'TCP tunnel'],
                      [
                        'Pool reuse',
                        flow.metadata.connection.reused
                          ? 'Reused connection'
                          : 'First observed request',
                      ],
                      [
                        'Established',
                        new Date(flow.metadata.connection.connected_at).toLocaleString(),
                      ],
                      ['DNS lookup', `${flow.metadata.connection.dns_ms} ms`],
                      ['TCP connect', `${flow.metadata.connection.tcp_ms} ms`],
                      ...(flow.metadata.connection.proxy
                        ? ([
                            ['Upstream proxy', flow.metadata.connection.proxy],
                            [
                              'Proxy negotiation',
                              flow.metadata.connection.proxy_ms === null
                                ? 'HTTP forwarding'
                                : `${flow.metadata.connection.proxy_ms} ms`,
                            ],
                          ] as [string, ReactNode][])
                        : []),
                    ]}
                  />
                  <p className="mt-2 text-xs text-muted-foreground">
                    Requests that reuse this socket share its connection setup timings.
                  </p>
                </>
              )}
              {[
                ['Client TLS', flow.metadata.client_tls],
                ['Origin TLS', flow.metadata.connection?.tls],
                ['Upstream proxy TLS', flow.metadata.connection?.proxy_tls],
              ].map(
                ([title, tls]) =>
                  tls &&
                  typeof tls !== 'string' && (
                    <section key={title as string}>
                      <h3 className="section-heading">{title as string}</h3>
                      <Info
                        rows={[
                          ['Version', tls.protocol],
                          ['Cipher', tls.cipher],
                          ['ALPN', tls.alpn || 'None'],
                          ['Server name', tls.server_name],
                          ['Handshake', `${tls.handshake_ms} ms`],
                          ['Peer certificate subject', tls.certificate_subject || 'Not provided'],
                          ['Peer certificate issuer', tls.certificate_issuer || 'Not provided'],
                          ['Peer certificate expires', tls.certificate_expires || 'Not provided'],
                        ]}
                      />
                    </section>
                  ),
              )}
              {flow.upstream_url !== flow.url && (
                <>
                  <h3 className="section-heading">Effective destination</h3>
                  <p>{flow.upstream_url}</p>
                </>
              )}
              {[...url.searchParams].length > 0 && (
                <>
                  <h3 className="section-heading">Query parameters</h3>
                  <HeaderTable headers={[...url.searchParams]} />
                </>
              )}
              {cookies.length > 0 && (
                <>
                  <h3 className="section-heading">Request cookies</h3>
                  <HeaderTable headers={cookies} />
                </>
              )}
              <Annotation key={flow.id} flow={flow} save={onAnnotate} notify={notify} />
              {flow.metadata.websocket && <WebSocketFrames capture={flow.metadata.websocket} />}
              {flow.metadata.mirrors.length > 0 && (
                <section className="mt-6">
                  <h3 className="section-heading">Mirrored bodies</h3>
                  {flow.metadata.mirrors.map((mirror, index) => (
                    <div className="my-2 rounded-md border p-3 text-xs" key={index}>
                      <strong>
                        {mirror.phase} · {bytes(mirror.bytes)} ·{' '}
                        {mirror.complete ? 'Complete' : mirror.error || 'Writing'}
                      </strong>
                      <p className="mt-2 font-mono text-[10px] [overflow-wrap:anywhere]">
                        {mirror.path}
                      </p>
                    </div>
                  ))}
                </section>
              )}
              {flow.metadata.actions.length > 0 && (
                <section className="mt-6">
                  <h3 className="section-heading">Rule actions</h3>
                  <ol className="space-y-2 text-xs">
                    {flow.metadata.actions.map((action, index) => (
                      <li key={index} className="rounded-md border p-2">
                        <strong>{action.rule}</strong> · {action.phase} · {action.index + 1}.{' '}
                        {action.action.replaceAll('_', ' ')}
                        <span className="mt-1 block text-muted-foreground">
                          {!action.applied
                            ? flow.duration_ms === null
                              ? 'Pending'
                              : flow.error
                                ? 'Interrupted'
                                : 'Skipped'
                            : action.changed === false
                              ? 'No change'
                              : action.changed === true
                                ? 'Changed message'
                                : 'Applied'}
                        </span>
                      </li>
                    ))}
                  </ol>
                  {flow.metadata.actions_truncated && (
                    <p className="notice">First 256 action records.</p>
                  )}
                </section>
              )}
            </>
          ) : tab === 'timing' ? (
            <>
              <h3 className="section-heading">Exchange timing</h3>
              {[
                ['Until headers', wait],
                ['Body transfer', Math.max(0, total - wait)],
                ['Total', total],
              ].map(([label, value]) => (
                <div className="timing-row" key={label}>
                  <span>{label}</span>
                  <progress max={Math.max(total, 1)} value={Number(value)} />
                  <span>{value} ms</span>
                </div>
              ))}
              <p className="hint">
                Header time includes upload, proxy delay, connection setup, and origin processing.
                Body time includes forwarding to the client.
              </p>
            </>
          ) : (
            <>
              <div className="mb-4 flex items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">
                  {tab === 'request'
                    ? 'Request capture'
                    : `Response · ${snapshot === 'original' ? flow.metadata.original_status || 'pending' : flow.status || 'pending'}`}
                </span>
                <NativeSelect
                  aria-label="Message snapshot"
                  size="sm"
                  value={snapshot}
                  onChange={(event) => setSnapshot(event.target.value)}
                >
                  <option value="effective">Effective</option>
                  <option value="original">Original</option>
                </NativeSelect>
              </div>
              {message ? (
                <>
                  <h3 className="section-heading">Headers</h3>
                  <HeaderTable headers={message.headers} />
                  {message.trailers.length > 0 && (
                    <>
                      <h3 className="section-heading">Trailers</h3>
                      <HeaderTable headers={message.trailers} />
                    </>
                  )}
                  <BodyView message={message} id={flow.id} direction={`${tab}-${snapshot}`} />
                  <ProtocolTools
                    key={`${flow.id}-${tab}-${snapshot}`}
                    id={flow.id}
                    token={token}
                    direction={tab === 'request' ? 'request' : 'response'}
                    original={snapshot === 'original'}
                    message={message}
                  />
                </>
              ) : (
                <p className="muted">
                  {snapshot === 'original'
                    ? 'Original snapshot unavailable. Earlier sessions did not keep it.'
                    : 'Waiting for response headers…'}
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}
