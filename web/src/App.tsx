import { StructureView, Waterfall } from './SessionViews';
import { CompareDialog } from './CompareDialog';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  CircleAlert,
  Clock3,
  Globe,
  Keyboard,
  Monitor,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { cn } from 'cn';
import { ApiError, fetchApi, post, request } from './api';
import {
  AuthDialog,
  ComposerDialog,
  Modal,
  RulesDialog,
  SettingsDialog,
  SetupDialog,
} from './Dialogs';
import { Detail } from './Detail';
import { BreakpointsDialog } from './Breakpoints';
import { Button } from './components/ui/button';
import { Badge } from './components/ui/badge';
import { Input } from './components/ui/input';
import { NativeSelect } from './components/ui/native-select';
import { address, bytes, curl, download } from './format';
import { useTheme, type Theme } from './theme';
import { isError, isSlow, matchesFilter, type TrafficFilter } from './traffic';
import type {
  BreakpointSummary,
  Execution,
  Flow,
  FlowSummary,
  Notify,
  Settings,
  Status,
} from './types';

type Dialog =
  | 'auth'
  | 'composer'
  | 'settings'
  | 'rules'
  | 'setup'
  | 'breakpoints'
  | 'compare'
  | 'session'
  | null;
type Snapshot = {
  status: Status | null;
  flows: FlowSummary[];
  breakpoints: BreakpointSummary[];
};
type Notice = { message: string; error: boolean };
function initialToken(): string {
  return location.hash.slice(1) || sessionStorage.getItem('openproxy-token') || '';
}
function Toast({ notice, dialog }: { notice: Notice; dialog: Dialog }) {
  const [host, setHost] = useState<HTMLElement>(document.body);
  useLayoutEffect(() => {
    setHost(document.querySelector<HTMLDialogElement>('dialog[open]') || document.body);
  }, [dialog, notice]);
  return createPortal(
    <div
      className={cn('toast', notice.error && 'border-destructive/40 bg-card text-destructive')}
      role="status"
    >
      {notice.message}
    </div>,
    host,
  );
}

function Sidebar({
  hosts,
  total,
  host,
  onHost,
  onSave,
  onHar,
  onOpen,
  onClear,
  mobile = false,
}: {
  hosts: [string, number][];
  total: number;
  host: string;
  onHost: (host: string) => void;
  onSave: () => void;
  onHar: () => void;
  onOpen: () => void;
  onClear: () => void;
  mobile?: boolean;
}) {
  return (
    <>
      <div className="shrink-0 px-3 pt-5 pb-3">
        <div className="eyebrow mb-3 px-2">Workspace</div>
        <Button
          id={mobile ? 'mobile-all-hosts' : 'all-hosts'}
          variant="ghost"
          className={cn(
            'host h-9 justify-start gap-2 px-2 text-xs',
            !host && 'bg-accent text-accent-foreground',
          )}
          aria-pressed={!host}
          onClick={() => onHost('')}
        >
          <Globe className="size-4" />
          <span className="min-w-0 flex-1 text-left">All traffic</span>
          <span className="text-xs text-muted-foreground tabular-nums">{total}</span>
        </Button>
        <div className="eyebrow mt-5 flex justify-between px-2">
          Hosts <span className="tabular-nums">{hosts.length}</span>
        </div>
      </div>
      <nav
        className="hosts min-h-0 flex-1 overflow-y-auto overscroll-contain px-3 pb-3"
        id={mobile ? 'mobile-hosts' : 'hosts'}
        aria-label="Hosts"
      >
        {hosts.map(([name, count]) => (
          <Button
            key={name}
            variant="ghost"
            className={cn(
              'host h-9 justify-start gap-2 px-2 text-xs',
              host === name && 'bg-accent text-accent-foreground',
            )}
            title={name}
            aria-pressed={host === name}
            onClick={() => onHost(name)}
          >
            <span className="min-w-0 flex-1 truncate text-left">{name}</span>
            <span className="text-xs text-muted-foreground tabular-nums">{count}</span>
          </Button>
        ))}
        {!hosts.length && (
          <p className="px-2 py-4 text-xs text-muted-foreground">
            Hosts appear as traffic arrives.
          </p>
        )}
      </nav>
      <div className="sidebar-bottom shrink-0 border-t bg-muted/30 p-3">
        <div className="eyebrow px-2 py-2">Session</div>
        <Button
          variant="ghost"
          size="sm"
          className="session-action justify-start px-2 text-xs"
          onClick={onSave}
        >
          <ArrowDownToLine /> Save session
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="session-action justify-start px-2 text-xs"
          onClick={onHar}
        >
          <ArrowDownToLine /> Export HAR
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="session-action justify-start px-2 text-xs"
          onClick={onOpen}
        >
          <ArrowUpFromLine /> Open session
        </Button>
        <Button
          id={mobile ? 'mobile-clear-traffic' : 'clear-traffic'}
          variant="ghost"
          size="sm"
          className="session-action justify-start px-2 text-xs text-destructive"
          onClick={onClear}
        >
          <Trash2 /> Clear captured traffic
        </Button>
        <p className="flex items-center gap-1.5 px-2 pt-3 text-[10px] text-muted-foreground">
          <ShieldCheck className="size-3" /> Traffic stays on this computer.
        </p>
      </div>
    </>
  );
}

export function App() {
  const [token, setToken] = useState(initialToken);
  const [snapshot, setSnapshot] = useState<Snapshot>({
    status: null,
    flows: [],
    breakpoints: [],
  });
  const [selectedId, setSelectedId] = useState<number | null>(null),
    [detail, setDetail] = useState<Flow | null>(null);
  const [host, setHost] = useState(''),
    [search, setSearch] = useState(''),
    [filter, setFilter] = useState<TrafficFilter>('all');
  const [dialog, setDialog] = useState<Dialog>(() => (initialToken() ? null : 'auth')),
    [composerSource, setComposerSource] = useState<Flow | null>(null);
  const [connected, setConnected] = useState(false),
    [notice, setNotice] = useState<Notice | null>(null);
  const [view, setView] = useState('list');
  const fileInput = useRef<HTMLInputElement>(null),
    searchInput = useRef<HTMLInputElement>(null);
  const { theme, setTheme } = useTheme();
  const notify: Notify = (message, error = false) => setNotice({ message, error });
  const close = () => setDialog(null);

  useEffect(() => {
    if (token) sessionStorage.setItem('openproxy-token', token);
    else sessionStorage.removeItem('openproxy-token');
    if (location.hash) history.replaceState(null, '', location.pathname);
  }, [token]);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), 6000);
    return () => clearTimeout(timer);
  }, [notice]);
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if (dialog || event.isComposing) return;
      const editing = (event.target as HTMLElement).closest(
        'input, textarea, select, [contenteditable]',
      );
      if (
        ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') ||
        (event.key === '/' && !editing && !event.ctrlKey && !event.metaKey && !event.altKey)
      ) {
        event.preventDefault();
        searchInput.current?.focus();
        searchInput.current?.select();
      }
    }
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, [dialog]);
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const [status, flows, breakpoints] = await Promise.all([
          request<Status>('status', token, { signal: controller.signal }),
          request<FlowSummary[]>('flows', token, { signal: controller.signal }),
          request<BreakpointSummary[]>('breakpoints', token, { signal: controller.signal }),
        ]);
        if (controller.signal.aborted) return;
        setSnapshot({
          status,
          flows,
          breakpoints,
        });
        setConnected(true);
      } catch (error) {
        if (controller.signal.aborted) return;
        setConnected(false);
        if (error instanceof ApiError && error.status === 401) setDialog('auth');
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 1000);
      }
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token]);
  useEffect(() => {
    if (selectedId === null) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const flow = await request<Flow>(`flows/${selectedId}`, token, {
          signal: controller.signal,
        });
        if (!controller.signal.aborted)
          setDetail((previous) =>
            JSON.stringify(previous) === JSON.stringify(flow) ? previous : flow,
          );
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 404) {
          setSelectedId(null);
          setDetail(null);
          return;
        }
      }
      if (!controller.signal.aborted) timer = setTimeout(poll, 1000);
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [selectedId, token]);

  const { flows, status } = snapshot,
    settings = status?.settings,
    selected = detail?.id === selectedId ? detail : null;
  // Parse addresses once for each poll for filters and host counts.
  const rows = useMemo(
    () =>
      flows.map((flow) => ({
        flow,
        url: address(flow.url),
        searchable:
          `${flow.url} ${flow.method} ${flow.client} ${flow.content_type || ''} ${flow.status || ''}`.toLowerCase(),
      })),
    [flows],
  );
  const hosts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const { url } of rows) counts.set(url.host, (counts.get(url.host) || 0) + 1);
    return [...counts].sort(([a], [b]) => a.localeCompare(b));
  }, [rows]);
  const matches = useMemo(() => {
    const query = search.toLowerCase();
    return rows.filter((row) => (!host || row.url.host === host) && row.searchable.includes(query));
  }, [rows, host, search]);
  const visible = useMemo(
    () => matches.filter(({ flow }) => matchesFilter(flow, filter)),
    [matches, filter],
  );
  const errors = matches.filter(({ flow }) => isError(flow)).length,
    slow = matches.filter(({ flow }) => isSlow(flow)).length;
  const selectionVisible = visible.some(({ flow }) => flow.id === selectedId);
  async function saveSettings(next: Settings) {
    const saved = await post<Settings>('settings', token, next);
    setSnapshot((previous) => ({
      ...previous,
      status: previous.status ? { ...previous.status, settings: saved } : null,
    }));
  }
  async function perform(action: () => Promise<void>) {
    try {
      await action();
    } catch (error) {
      notify(String(error), true);
    }
  }
  function compose(source: Flow | null) {
    setComposerSource(source);
    setDialog('composer');
  }
  async function exportFile(path: string, name: string) {
    download(await (await fetchApi(path, token)).blob(), name, 'application/json');
  }
  const sidebarProps = {
    hosts,
    total: flows.length,
    host,
    onHost: (value: string) => {
      setHost(value);
      if (dialog === 'session') close();
    },
    onSave: () => void perform(() => exportFile('session', 'openproxy-session.json')),
    onHar: () => void perform(() => exportFile('har', 'openproxy.har')),
    onOpen: () => fileInput.current?.click(),
    onClear: () =>
      void perform(async () => {
        if (!confirm('Clear the captured session? Save it first if you need it.')) return;
        await request<void>('flows', token, { method: 'DELETE' });
        setSelectedId(null);
        setDetail(null);
        notify('Capture cleared');
      }),
  };

  return (
    <>
      <header className="topbar flex shrink-0 flex-wrap items-center gap-x-5 gap-y-3 border-b bg-card px-4 py-3 lg:px-5">
        <a
          className="brand flex items-center gap-2.5 font-semibold tracking-tight"
          href="/"
          aria-label="OpenProxy home"
        >
          <img
            src="/openproxy.svg"
            alt=""
            aria-hidden="true"
            width="32"
            height="32"
            className="size-8 shrink-0"
          />
          <span className="text-lg">OpenProxy</span>
          <Badge variant="secondary" className="hidden text-[9px] tracking-wider xl:inline-flex">
            LOCAL
          </Badge>
        </a>
        <span className="hidden text-xs text-muted-foreground xl:block">
          {connected && status ? `Proxy ${status.proxy}` : 'Disconnected'}
        </span>
        <nav
          className="flex flex-1 basis-full flex-wrap items-center justify-end gap-1.5 sm:basis-auto"
          aria-label="Capture tools"
        >
          <Button
            id="record"
            variant="outline"
            size="sm"
            className={settings?.recording ? 'text-success' : 'text-muted-foreground'}
            disabled={!settings}
            onClick={() =>
              void perform(async () => {
                await saveSettings({ ...settings!, recording: !settings!.recording });
                notify(
                  settings!.recording
                    ? 'Recording paused; proxy remains active'
                    : 'Recording resumed',
                );
              })
            }
          >
            {settings?.recording ? '● Recording' : '○ Paused'}
          </Button>
          <Button id="compose" variant="ghost" size="sm" onClick={() => compose(null)}>
            <Plus /> Compose
          </Button>
          <Button
            id="breakpoints"
            variant="ghost"
            size="sm"
            className={snapshot.breakpoints.length ? 'text-warning' : ''}
            onClick={() => setDialog('breakpoints')}
          >
            Breakpoints{snapshot.breakpoints.length ? ` (${snapshot.breakpoints.length})` : ''}
          </Button>
          <Button
            id="rules"
            variant="ghost"
            size="sm"
            disabled={!settings}
            onClick={() => setDialog('rules')}
          >
            Rules
          </Button>
          <Button
            id="settings"
            variant="ghost"
            size="sm"
            disabled={!settings}
            onClick={() => setDialog('settings')}
          >
            <Settings2 className="hidden lg:block" /> Settings
          </Button>
          <Button id="setup" variant="outline" size="sm" onClick={() => setDialog('setup')}>
            Connect device
          </Button>
          <Button
            id="session-tools"
            variant="outline"
            size="sm"
            className="sm:hidden"
            onClick={() => setDialog('session')}
          >
            Session &amp; hosts
          </Button>
          <div className="flex items-center gap-1 border-l pl-2">
            <Monitor className="hidden size-4 text-muted-foreground md:block" aria-hidden="true" />
            <NativeSelect
              id="theme"
              size="sm"
              aria-label="Color theme"
              value={theme}
              onChange={(e) => setTheme(e.target.value as Theme)}
              className="text-xs"
            >
              <option value="system">System theme</option>
              <option value="light">Light mode</option>
              <option value="dark">Dark mode</option>
            </NativeSelect>
          </div>
        </nav>
      </header>
      <div className="workspace grid min-h-0 flex-1 grid-cols-1 grid-rows-[minmax(0,1fr)_minmax(0,.85fr)] overflow-hidden sm:grid-cols-[180px_minmax(0,1fr)] lg:grid-cols-[190px_minmax(300px,1fr)_minmax(330px,1fr)] lg:grid-rows-1 xl:grid-cols-[210px_minmax(300px,1fr)_minmax(350px,1fr)]">
        <aside
          className="sidebar row-span-2 hidden min-h-0 flex-col overflow-hidden border-r bg-muted/20 sm:flex lg:row-span-1"
          aria-label="Workspace"
        >
          <Sidebar {...sidebarProps} />
        </aside>
        <main className="capture flex min-h-0 min-w-0 flex-col overflow-hidden border-r bg-card">
          <div className="capture-title flex shrink-0 items-center justify-between gap-3 px-5 pt-5 pb-4">
            <div>
              <h1 className="text-xl font-semibold tracking-tight">Network activity</h1>
              <p className="mt-1 text-xs text-muted-foreground">
                <span id="total">{flows.length}</span> exchanges ·{' '}
                {settings?.recording ? 'recording new traffic' : 'recording paused'}
              </p>
            </div>
            <Badge
              variant="outline"
              className={cn(
                'gap-1.5 text-[10px]',
                connected ? 'text-success' : 'text-muted-foreground',
              )}
            >
              <span
                className={cn(
                  'size-1.5 rounded-full',
                  connected ? 'bg-success' : 'bg-muted-foreground',
                )}
              />
              {connected ? 'LIVE' : 'OFFLINE'}
            </Badge>
          </div>
          <div className="filters shrink-0 space-y-3 px-5 pb-4">
            <div className="flex gap-2">
              <div className="relative min-w-0 flex-1">
                <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" />
                <Input
                  ref={searchInput}
                  id="search"
                  type="search"
                  className="pr-10 pl-9 text-xs"
                  placeholder="Search traffic…"
                  aria-label="Search traffic"
                  aria-keyshortcuts="Control+k Meta+k /"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <kbd className="pointer-events-none absolute top-2 right-3 hidden text-xs text-muted-foreground md:block">
                  /
                </kbd>
              </div>
              <NativeSelect
                id="filter"
                aria-label="Filter traffic"
                className="text-xs"
                value={filter}
                onChange={(e) => setFilter(e.target.value as TrafficFilter)}
              >
                {[
                  ['all', 'All requests'],
                  ['https', 'HTTPS'],
                  ['errors', 'Errors'],
                  ['slow', 'Slow (≥ 1 s)'],
                  ['json', 'JSON'],
                  ['pending', 'In progress'],
                  ['marked', 'Marked'],
                ].map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <NativeSelect
                id="traffic-view"
                size="sm"
                aria-label="Traffic view"
                value={view}
                onChange={(event) => setView(event.target.value)}
                className="text-xs"
              >
                <option value="list">Request list</option>
                <option value="structure">Host/path tree</option>
                <option value="waterfall">Waterfall & statistics</option>
              </NativeSelect>
              <Button
                id="compare"
                type="button"
                variant="ghost"
                size="xs"
                onClick={() => setDialog('compare')}
              >
                Compare exchanges / session
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-1.5" aria-label="Quick traffic filters">
              <Button
                size="xs"
                variant={filter === 'errors' ? 'secondary' : 'ghost'}
                id="quick-errors"
                aria-pressed={filter === 'errors'}
                className="text-destructive"
                onClick={() => setFilter(filter === 'errors' ? 'all' : 'errors')}
              >
                <CircleAlert /> Errors <span className="tabular-nums">{errors}</span>
              </Button>
              <Button
                size="xs"
                variant={filter === 'slow' ? 'secondary' : 'ghost'}
                id="quick-slow"
                aria-pressed={filter === 'slow'}
                className="text-warning"
                title="Completed requests with a duration of at least 1 second"
                onClick={() => setFilter(filter === 'slow' ? 'all' : 'slow')}
              >
                <Clock3 /> Slow ≥ 1 s <span className="tabular-nums">{slow}</span>
              </Button>
              {(host || search || filter !== 'all') && (
                <Button
                  id="reset-filters"
                  variant="ghost"
                  size="xs"
                  className="ml-auto text-muted-foreground"
                  onClick={() => {
                    setHost('');
                    setSearch('');
                    setFilter('all');
                  }}
                >
                  Reset filters
                </Button>
              )}
            </div>
          </div>
          <div
            className="traffic-scroll min-h-0 flex-1 overflow-auto overscroll-contain"
            id="traffic-scroll"
            role="region"
            aria-label="Captured requests"
            tabIndex={0}
          >
            {view === 'structure' ? (
              <StructureView flows={visible.map((row) => row.flow)} select={setSelectedId} />
            ) : view === 'waterfall' ? (
              <Waterfall
                flows={visible.map((row) => row.flow)}
                all={flows}
                selected={selectedId}
                select={setSelectedId}
              />
            ) : (
              <table className="traffic">
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Request</th>
                    <th scope="col">Size</th>
                    <th scope="col">Time</th>
                  </tr>
                </thead>
                <tbody id="flows">
                  {visible.map(({ flow, url }, index) => (
                    <tr
                      key={flow.id}
                      data-flow-id={flow.id}
                      className={flow.id === selectedId ? 'selected' : ''}
                      tabIndex={
                        flow.id === selectedId || (!selectionVisible && index === 0) ? 0 : -1
                      }
                      aria-selected={flow.id === selectedId}
                      aria-label={`${flow.method} ${flow.url}, status ${flow.status || flow.phase}`}
                      onClick={() => setSelectedId(flow.id)}
                      onFocus={() => setSelectedId(flow.id)}
                      onKeyDown={(event) => {
                        if (event.ctrlKey || event.metaKey || event.altKey) return;
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedId(flow.id);
                        } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
                          event.preventDefault();
                          const next =
                            event.key === 'Home'
                              ? 0
                              : event.key === 'End'
                                ? visible.length - 1
                                : Math.max(
                                    0,
                                    Math.min(
                                      visible.length - 1,
                                      index + (event.key === 'ArrowDown' ? 1 : -1),
                                    ),
                                  );
                          const row = document.querySelector<HTMLElement>(
                            `tr[data-flow-id="${visible[next].flow.id}"]`,
                          );
                          row?.focus({ preventScroll: true });
                          row?.scrollIntoView({ block: 'nearest' });
                        }
                      }}
                    >
                      <td>
                        <Badge
                          variant="secondary"
                          className={cn(
                            'rounded-md px-1.5 font-mono text-[10px]',
                            isError(flow)
                              ? 'bg-destructive/10 text-destructive'
                              : flow.status
                                ? 'bg-success/10 text-success'
                                : 'text-muted-foreground',
                          )}
                        >
                          {flow.error !== null ? 'ERR' : flow.status || '···'}
                        </Badge>
                      </td>
                      <td>
                        <span className="request-path">
                          <span className="method-label">{flow.method}</span>
                          {url.pathname + url.search}
                        </span>
                        <span className="request-meta">
                          {flow.marked ? '★ ' : flow.has_note ? '✎ ' : ''}
                          {flow.tls ? '▣ ' : ''}
                          {url.host} · {flow.content_type?.split(';')[0] || flow.phase}
                        </span>
                      </td>
                      <td>{bytes(flow.response_bytes)}</td>
                      <td className={isSlow(flow) ? 'text-warning!' : ''}>
                        {flow.duration_ms === null ? '…' : `${flow.duration_ms} ms`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {visible.length === 0 && (
              <div className="empty">
                <Activity className="mx-auto mb-4 size-9 text-primary/50" />
                <h2>{flows.length ? 'No matching requests.' : 'Your traffic, in focus.'}</h2>
                <p>
                  {flows.length
                    ? 'Adjust the filters to see more requests.'
                    : 'Send a request through the proxy to examine its headers, body, and timing.'}
                </p>
                {flows.length ? (
                  <Button
                    variant="outline"
                    onClick={() => {
                      setHost('');
                      setSearch('');
                      setFilter('all');
                    }}
                  >
                    Reset filters
                  </Button>
                ) : (
                  <>
                    <code>
                      curl --proxy http://{status?.proxy || '127.0.0.1:8080'} http://example.com
                    </code>
                    <Button variant="outline" onClick={() => setDialog('setup')}>
                      Connect a phone →
                    </Button>
                  </>
                )}
              </div>
            )}
          </div>
          <footer className="capture-footer flex shrink-0 flex-wrap items-center justify-between gap-1 border-t bg-muted/20 px-5 py-2.5 text-[10px] text-muted-foreground">
            <span>
              {visible.length} requests ·{' '}
              {bytes(
                visible.reduce((n, { flow }) => n + flow.request_bytes + flow.response_bytes, 0),
              )}{' '}
              transferred · {bytes(status?.retained_bytes ?? 0)} /{' '}
              {bytes(status?.retention_limit ?? 0)} retained
              {!!status?.evicted_flows && ` · ${status.evicted_flows} oldest captures evicted`}
            </span>
            <span
              className="inline-flex items-center gap-1.5"
              title="Select a request. Use ↑/↓ or Home/End. Ctrl/⌘K or / selects search."
            >
              <Keyboard className="size-3" /> ↑ ↓ navigate · / search
            </span>
          </footer>
        </main>
        <Detail
          token={token}
          flow={selected}
          notify={notify}
          onAnnotate={async (note, marked) => {
            const updated = await request<Flow>(`flows/${selectedId}`, token, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ note, marked }),
            });
            setDetail((previous) => (previous?.id === updated.id ? updated : previous));
            setSnapshot((previous) => ({
              ...previous,
              flows: previous.flows.map((flow) =>
                flow.id === updated.id ? { ...flow, marked, has_note: !!note } : flow,
              ),
            }));
          }}
          onEdit={() => compose(selected)}
          onReplay={() =>
            void perform(async () => {
              const result = await post<Execution>(`flows/${selectedId}/replay`, token, {});
              notify(
                result.errors.length ? result.errors[0] : 'Request repeated',
                result.errors.length > 0,
              );
            })
          }
          onCurl={() =>
            void perform(async () => {
              if (selected) {
                await navigator.clipboard.writeText(curl(selected));
                notify('cURL command copied');
              }
            })
          }
          onDelete={() =>
            void perform(async () => {
              await request<void>(`flows/${selectedId}`, token, { method: 'DELETE' });
              setSelectedId(null);
              setDetail(null);
            })
          }
        />
      </div>
      <input
        ref={fileInput}
        type="file"
        accept=".json,.har"
        hidden
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = '';
          if (!file) return;
          void perform(async () => {
            if (file.size > 400 * 1024 * 1024) throw new Error('Session exceeds 400 MiB');
            if (!confirm('Replace the current captured session with this file?')) return;
            await post<void>('session', token, JSON.parse(await file.text()));
            setSelectedId(null);
            setDetail(null);
            setHost('');
            notify('Session opened');
          });
        }}
      />
      {notice && <Toast notice={notice} dialog={dialog} />}
      {dialog === 'session' && (
        <Modal title="Session & hosts" close={close} className="session-dialog">
          <div className="flex h-[min(65dvh,550px)] min-h-0 flex-col overflow-hidden">
            <Sidebar {...sidebarProps} mobile />
          </div>
        </Modal>
      )}
      {dialog === 'auth' && (
        <AuthDialog
          close={close}
          notify={notify}
          authenticate={(value) => {
            setToken(value);
            close();
          }}
        />
      )}
      {dialog === 'setup' && <SetupDialog close={close} status={status} />}
      {dialog === 'composer' && (
        <ComposerDialog close={close} notify={notify} token={token} initial={composerSource} />
      )}
      {dialog === 'settings' && settings && (
        <SettingsDialog close={close} notify={notify} settings={settings} save={saveSettings} />
      )}
      {dialog === 'rules' && settings && (
        <RulesDialog
          close={close}
          notify={notify}
          settings={settings}
          save={saveSettings}
          validate={(next) => post<Settings>('settings/validate', token, next)}
        />
      )}
      {dialog === 'compare' && (
        <CompareDialog
          flows={flows}
          selected={selectedId}
          token={token}
          close={close}
          notify={notify}
        />
      )}
      {dialog === 'breakpoints' && (
        <BreakpointsDialog
          entries={snapshot.breakpoints}
          token={token}
          close={close}
          notify={notify}
        />
      )}
    </>
  );
}
