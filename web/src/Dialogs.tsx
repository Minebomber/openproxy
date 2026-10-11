import { RulesEditor } from './RulesEditor';
import { Button } from './components/ui/button';
import { NativeSelect } from './components/ui/native-select';
import { Input } from './components/ui/input';
import { Textarea } from './components/ui/textarea';
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { post } from './api';
import { base64, editableBody, parseHeaders, rawBytes } from './format';
import type { Action, Compose, Execution, Flow, Notify, Rule, Settings, Status } from './types';

type Base = { close: () => void; notify: Notify };
export function Modal({
  title,
  close,
  children,
  className,
}: {
  title: string;
  close: () => void;
  children: ReactNode;
  className?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null),
    titleId = useId();
  useEffect(() => {
    const node = dialog.current!;
    node.showModal();
    return () => node.close();
  }, []);
  return (
    <dialog ref={dialog} className={className} aria-labelledby={titleId} onCancel={close}>
      <div className="dialog-heading">
        <h2 id={titleId}>{title}</h2>
        <Button
          variant="outline"
          type="button"
          onClick={close}
          aria-label={`Close ${title.toLowerCase()}`}
        >
          ×
        </Button>
      </div>
      {children}
    </dialog>
  );
}
function Footer({
  close,
  label,
  disabled = false,
}: {
  close: () => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <div className="dialog-footer">
      <Button variant="outline" type="button" onClick={close}>
        Cancel
      </Button>
      <Button variant="default" type="submit" disabled={disabled}>
        {label}
      </Button>
    </div>
  );
}

export function AuthDialog({
  close,
  authenticate,
  notify,
}: Base & { authenticate: (token: string) => void }) {
  return (
    <Modal title="Connect to your inspector" close={close}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const token = String(new FormData(event.currentTarget).get('token')).trim();
          if (!token) {
            notify('Inspector token is required', true);
            return;
          }
          authenticate(token);
        }}
      >
        <div className="dialog-scroll">
          <p>Open the full inspector URL from the terminal, or paste its token here.</p>
          <label>
            Inspector token
            <Input name="token" type="password" autoComplete="off" required />
          </label>
        </div>
        <Footer close={close} label="Connect" />
      </form>
    </Modal>
  );
}

const numericSettings = [
  ['latency_ms', 'Latency (ms)', 60000],
  ['upload_bytes_per_second', 'Upload bytes / second', undefined],
  ['download_bytes_per_second', 'Download bytes / second', undefined],
  ['aggregate_upload_bytes_per_second', 'Total upload bytes / second', undefined],
  ['aggregate_download_bytes_per_second', 'Total download bytes / second', undefined],
  ['failure_percent', 'Connection failures (%)', 100],
  ['capture_bytes', 'Capture bytes per body', 1048576],
  ['max_flows', 'Maximum retained requests', 10000],
] as const;
export function SettingsDialog({
  settings,
  save,
  close,
  notify,
}: Base & { settings: Settings; save: (s: Settings) => Promise<void> }) {
  const form = useRef<HTMLFormElement>(null),
    [saving, setSaving] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget),
      updated = { ...settings };
    for (const [name] of numericSettings) updated[name] = Number(data.get(name));
    updated.intercept_hosts = String(data.get('intercept_hosts'))
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    updated.bypass_hosts = String(data.get('bypass_hosts'))
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    updated.no_cache = data.has('no_cache');
    updated.block_cookies = data.has('block_cookies');
    updated.offline = data.has('offline');
    updated.process_attribution = data.has('process_attribution');
    for (const name of ['drop_upload_after_bytes', 'drop_download_after_bytes'] as const) {
      const value = String(data.get(name)).trim();
      updated[name] = value ? Number(value) : null;
    }
    setSaving(true);
    try {
      updated.dns_overrides = Object.fromEntries(
        String(data.get('dns_overrides'))
          .split('\n')
          .filter((line) => line.trim())
          .map((line) => {
            const index = line.indexOf('=');
            if (index < 1) throw new Error('DNS overrides use HOST=IP, one per line');
            return [line.slice(0, index).trim(), line.slice(index + 1).trim()];
          }),
      );
      await save(updated);
      close();
      notify('Settings saved');
    } catch (error) {
      notify(String(error), true);
    } finally {
      setSaving(false);
    }
  }
  return (
    <Modal title="Proxy settings" close={close}>
      <form id="settings-form" ref={form} onSubmit={submit}>
        <div className="dialog-scroll">
          <p className="hint">
            Changes apply to new requests and connections. Current TLS connections keep their
            interception mode.
          </p>
          <div className="form-grid">
            <label>
              Intercept HTTPS hosts
              <Textarea
                name="intercept_hosts"
                rows={3}
                defaultValue={settings.intercept_hosts.join('\n')}
              />
              <small>One glob per line. Empty = tunnel all HTTPS.</small>
            </label>
            <label>
              Bypass HTTPS hosts
              <Textarea
                name="bypass_hosts"
                rows={3}
                defaultValue={settings.bypass_hosts.join('\n')}
              />
              <small>Bypass wins over interception.</small>
            </label>
            <label className="col-span-full">
              DNS overrides
              <Textarea
                name="dns_overrides"
                rows={3}
                defaultValue={Object.entries(settings.dns_overrides)
                  .map(([host, ip]) => `${host}=${ip}`)
                  .join('\n')}
                placeholder="api.example.com=127.0.0.1"
              />
              <small>
                HOST=IP, one per line. New connections use these addresses; Host headers and TLS
                hostname verification retain the original name.
              </small>
            </label>
            <label>
              Network preset
              <NativeSelect
                defaultValue="custom"
                onChange={(event) => {
                  const presets: Record<string, number[]> = {
                      normal: [0, 0, 0],
                      '3g': [400, 64000, 96000],
                      '4g': [60, 1250000, 5000000],
                    },
                    preset = presets[event.target.value];
                  if (preset)
                    ['latency_ms', 'upload_bytes_per_second', 'download_bytes_per_second'].forEach(
                      (name, i) => {
                        (form.current!.elements.namedItem(name) as HTMLInputElement).value = String(
                          preset[i],
                        );
                      },
                    );
                }}
              >
                <option value="custom">Custom</option>
                <option value="normal">No throttling</option>
                <option value="3g">Slow 3G</option>
                <option value="4g">4G</option>
              </NativeSelect>
            </label>
            {numericSettings.map(([name, label, max]) => (
              <label key={name}>
                {label}
                <Input
                  name={name}
                  type="number"
                  min={name === 'max_flows' ? 1 : 0}
                  max={max}
                  defaultValue={settings[name]}
                />
                {name.includes('per_second') && (
                  <small>
                    0 = unlimited;{' '}
                    {name.startsWith('aggregate')
                      ? 'shared by all transfers.'
                      : 'per request or tunnel.'}
                  </small>
                )}
                {name === 'capture_bytes' && (
                  <small>Larger bodies continue forwarding in full.</small>
                )}
              </label>
            ))}
            {(['drop_upload_after_bytes', 'drop_download_after_bytes'] as const).map((name) => (
              <label key={name}>
                Drop {name.includes('upload') ? 'upload' : 'download'} after bytes
                <Input
                  name={name}
                  type="number"
                  min={0}
                  max={Number.MAX_SAFE_INTEGER}
                  defaultValue={settings[name] ?? ''}
                />
                <small>Empty = disabled; 0 = drop before the first byte.</small>
              </label>
            ))}
          </div>
          <div className="check-row">
            <label>
              <input
                name="process_attribution"
                type="checkbox"
                defaultChecked={settings.process_attribution}
              />{' '}
              Identify local client processes
            </label>
            <label>
              <input name="offline" type="checkbox" defaultChecked={settings.offline} /> Simulate
              offline
            </label>
            <label>
              <input name="no_cache" type="checkbox" defaultChecked={settings.no_cache} /> Disable
              caching
            </label>
            <label>
              <input name="block_cookies" type="checkbox" defaultChecked={settings.block_cookies} />{' '}
              Block cookies
            </label>
          </div>
        </div>
        <Footer close={close} label="Save settings" disabled={saving} />
      </form>
    </Modal>
  );
}

const templates: Record<string, Action[]> = {
  header: [{ type: 'set_request_header', name: 'X-Debug', value: 'OpenProxy' }],
  block: [{ type: 'block', message: 'Blocked by a debugging rule' }],
  mock: [
    {
      type: 'mock',
      status: 200,
      headers: [['Content-Type', 'application/json']],
      body: '{"debug":true}',
    },
  ],
  rewrite: [
    { type: 'replace_response_body', find: 'original', replace: 'replacement', regex: false },
  ],
  remote: [{ type: 'map_remote', from: 'https://api.example.com/', to: 'http://127.0.0.1:3000/' }],
  local: [{ type: 'map_local', path: './fixtures/response.json', url_prefix: '' }],
  slow: [
    { type: 'latency', ms: 400 },
    { type: 'throttle', upload: 64000, download: 96000 },
  ],
  request_pause: [{ type: 'breakpoint', phase: 'request', timeout_ms: 120000 }],
  response_pause: [{ type: 'breakpoint', phase: 'response', timeout_ms: 120000 }],
};
export function RulesDialog({
  settings,
  save,
  validate,
  close,
  notify,
}: Base & {
  settings: Settings;
  save: (s: Settings) => Promise<void>;
  validate: (s: Settings) => Promise<Settings>;
}) {
  const [text, setText] = useState(() => JSON.stringify(settings.rules, null, 2)),
    [example, setExample] = useState('header'),
    [saving, setSaving] = useState(false);
  const [mode, setMode] = useState('visual');
  function parse(): Rule[] {
    const rules: unknown = JSON.parse(text);
    if (!Array.isArray(rules)) throw new Error('Rule sets must be an array');
    return rules;
  }
  function add() {
    try {
      const rules = parse();
      rules.push({
        name: 'New debugging rule',
        enabled: true,
        url: 'https://api.example.com/*',
        method: null,
        actions: templates[example],
      });
      setText(JSON.stringify(rules, null, 2));
    } catch (error) {
      notify(String(error), true);
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    try {
      await save({ ...settings, rules: parse() });
      close();
      notify('Rules saved');
    } catch (error) {
      notify(String(error), true);
    } finally {
      setSaving(false);
    }
  }
  return (
    <Modal title="Request & response rules" close={close}>
      <form id="rules-form" onSubmit={submit}>
        <fieldset className="dialog-scroll min-w-0 border-0 p-0" disabled={saving}>
          <p>
            Rules match the original URL and method. Enabled rules run in order. Add an example.
            Change its URL pattern and values.
          </p>
          <div className="mb-4 flex gap-2">
            <Button
              id="rules-mode-visual"
              type="button"
              variant={mode === 'visual' ? 'secondary' : 'ghost'}
              size="sm"
              onClick={async () => {
                setSaving(true);
                try {
                  const normalized = await validate({ ...settings, rules: parse() });
                  setText(JSON.stringify(normalized.rules, null, 2));
                  setMode('visual');
                } catch (error) {
                  notify(String(error), true);
                } finally {
                  setSaving(false);
                }
              }}
            >
              Visual editor
            </Button>
            <Button
              id="rules-mode-json"
              type="button"
              variant={mode === 'json' ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => setMode('json')}
            >
              JSON
            </Button>
          </div>
          {mode === 'visual' ? (
            <RulesEditor
              rules={parse()}
              change={(rules) => setText(JSON.stringify(rules, null, 2))}
            />
          ) : (
            <>
              <div className="rule-examples">
                <NativeSelect
                  aria-label="Rule example"
                  value={example}
                  onChange={(e) => setExample(e.target.value)}
                >
                  {[
                    ['header', 'Add a request header'],
                    ['block', 'Block requests'],
                    ['mock', 'Mock a response'],
                    ['rewrite', 'Rewrite a response body'],
                    ['remote', 'Map a remote URL'],
                    ['local', 'Map a local file'],
                    ['slow', 'Simulate a slow connection'],
                    ['request_pause', 'Pause a request'],
                    ['response_pause', 'Pause a response'],
                  ].map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </NativeSelect>
                <Button variant="outline" type="button" onClick={add}>
                  ＋ Add example
                </Button>
              </div>
              <label>
                Rule sets (JSON)
                <Textarea
                  id="rules-json"
                  rows={20}
                  spellCheck={false}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          <p className="hint">
            Body edits use UTF-8, gzip, and deflate with a 1 MiB buffer limit. Matching body edits
            use a buffer. Other traffic streams without an edit buffer. Directory mappings reject
            paths and symlinks with targets not in the chosen directory.
          </p>
        </fieldset>
        <Footer close={close} label="Save rules" disabled={saving} />
      </form>
    </Modal>
  );
}

export function ComposerDialog({
  initial,
  token,
  close,
  notify,
}: Base & { initial: Flow | null; token: string }) {
  const edit = initial ? editableBody(initial.request.body.data) : { encoding: 'text', body: '' },
    [sending, setSending] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    setSending(true);
    try {
      const body = String(fields.get('body'));
      const input: Compose = {
        method: String(fields.get('method')),
        url: String(fields.get('url')),
        headers: parseHeaders(String(fields.get('headers'))),
        trailers: parseHeaders(String(fields.get('trailers') ?? '')),
        body:
          fields.get('encoding') === 'base64'
            ? base64(rawBytes(body.trim()))
            : base64(new TextEncoder().encode(body)),
        repeat: Number(fields.get('repeat')),
        concurrency: Number(fields.get('concurrency')),
        apply_rules: fields.has('apply_rules'),
      };
      const result = await post<Execution>('compose', token, input);
      close();
      notify(
        `${result.completed} requests completed${result.errors.length ? `; ${result.errors[0]}` : ''}`,
        result.errors.length > 0,
      );
    } catch (error) {
      notify(String(error), true);
    } finally {
      setSending(false);
    }
  }
  return (
    <Modal title="Compose request" close={close}>
      <form id="compose-form" onSubmit={submit}>
        <div className="dialog-scroll">
          <div className="compose-url">
            <label>
              Method
              <Input
                name="method"
                defaultValue={initial?.metadata.upstream_method || initial?.method || 'GET'}
                required
              />
            </label>
            <label>
              URL
              <Input
                name="url"
                type="url"
                defaultValue={initial?.upstream_url || initial?.url || ''}
                placeholder="https://api.example.com/endpoint"
                required
              />
            </label>
          </div>
          <label>
            Headers
            <Textarea
              name="headers"
              rows={5}
              defaultValue={
                initial?.request.headers.map((h) => `${h[0]}: ${h[1]}`).join('\n') || ''
              }
            />
            <small>One header per line; duplicate names are preserved.</small>
          </label>
          <div className="body-label">
            <label htmlFor="compose-body">Body</label>
            <NativeSelect
              name="encoding"
              aria-label="Composer body encoding"
              defaultValue={edit.encoding}
            >
              <option value="text">UTF-8 text</option>
              <option value="base64">Base64 bytes</option>
            </NativeSelect>
          </div>
          <Textarea
            name="body"
            id="compose-body"
            rows={8}
            spellCheck={false}
            defaultValue={edit.body}
          />
          {!!initial?.request.trailers.length && (
            <label>
              Trailers
              <Textarea
                name="trailers"
                rows={3}
                defaultValue={initial.request.trailers.map((h) => `${h[0]}: ${h[1]}`).join('\n')}
              />
              <small>Sent after the body. Update checksum fields if you change the body.</small>
            </label>
          )}
          <div className="form-grid">
            <label>
              Repeat count
              <Input name="repeat" type="number" min={1} max={1000} defaultValue={1} />
            </label>
            <label>
              Concurrency
              <Input name="concurrency" type="number" min={1} max={32} defaultValue={1} />
            </label>
          </div>
          <label className="check">
            <input type="checkbox" name="apply_rules" defaultChecked={!initial} />
            Apply request and response rules
          </label>
          {initial && (
            <p className="hint">
              This is the forwarded request. Rules start disabled to prevent duplicate edits.
            </p>
          )}
          <p className="hint">
            The destination receives this request. Examine the result in the traffic list.
          </p>
        </div>
        <Footer close={close} label="Send request →" disabled={sending} />
      </form>
    </Modal>
  );
}

export function SetupDialog({ close, status }: { close: () => void; status: Status | null }) {
  return (
    <Modal title="Connect a device" close={close}>
      <div className="dialog-scroll">
        <p>Use the same Wi-Fi network as this Linux computer.</p>
        <ol>
          <li>
            Run OpenProxy with a LAN listener and your phone's address in the allow list:
            <pre>{'openproxy --listen 0.0.0.0:8080 \\\n  --allow-client 192.168.1.42/32'}</pre>
          </li>
          <li>
            Set the phone's Wi-Fi HTTP proxy to the computer's LAN IP and port <strong>8080</strong>
            .
          </li>
          <li>
            Open <code>http://openproxy.local/</code> on the phone. Download the CA. Use the iOS or
            Android instructions below.
          </li>
        </ol>
        <p>
          iOS: install the profile. Enable full trust in Certificate Trust Settings. Android: add
          this CA to your debug app's Network Security Configuration.
        </p>
        <h3>Automatic proxy configuration</h3>
        <p>
          Set the device's Wi-Fi proxy to Automatic. Enter{' '}
          <code>http://COMPUTER_LAN_IP:{status?.proxy.split(':').at(-1) || '8080'}/proxy.pac</code>.
          Use the computer's LAN address so the device can retrieve the file directly.
        </p>
        <p>
          For SOCKS mode, start with <code>--socks 0.0.0.0:1080</code>. Use <code>/socks.pac</code>{' '}
          at the same HTTP setup address. SOCKS uses its own listener. HTTPS inspection uses the
          same CA.
        </p>
        {status?.socks && (
          <p className="hint">
            Current SOCKS listener: <code>{status.socks}</code>. A loopback listener is only
            reachable from this computer.
          </p>
        )}
        <p className="hint">
          Apps with certificate pinning, apps that ignore proxies, and UDP/QUIC must have their own
          debug setup. After use, remove the phone's proxy and CA.
        </p>
      </div>
      <div className="dialog-footer">
        <Button variant="default" onClick={close}>
          Got it
        </Button>
      </div>
    </Modal>
  );
}
