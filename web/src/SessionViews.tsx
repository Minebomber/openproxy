import { useMemo, type KeyboardEvent } from 'react';
import { Button } from './components/ui/button';
import { bytes } from './format';
import { structure, statistics, timeline, safeURL, type PathNode } from './inspect';
import type { FlowSummary } from './types';

function navigate(event: KeyboardEvent, selector: string) {
  if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
  const nodes = [...event.currentTarget.querySelectorAll<HTMLElement>(selector)].filter(
    (node) => node.getClientRects().length,
  );
  if (!nodes.length) return;
  const index = nodes.findIndex(
    (node) =>
      node === event.target || (event.target instanceof Node && node.contains(event.target)),
  );
  const next =
    event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? nodes.length - 1
        : Math.max(0, Math.min(nodes.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
  event.preventDefault();
  nodes[next].focus({ preventScroll: true });
  nodes[next].scrollIntoView({ block: 'nearest' });
}

function Branch({
  node,
  select,
  depth = 0,
}: {
  node: PathNode;
  select: (id: number) => void;
  depth?: number;
}) {
  return (
    <details className="my-1 ml-3" open={depth < 1}>
      <summary className="cursor-pointer py-2 text-xs">
        <span className="font-medium">{node.name}</span>
        <span className="ml-2 text-muted-foreground tabular-nums">{node.count}</span>
      </summary>
      {[...node.children.values()]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((child) => (
          <Branch key={child.key} node={child} select={select} depth={depth + 1} />
        ))}
      {node.flows.map((flow) => (
        <Button
          key={flow.id}
          data-tree-flow={flow.id}
          onFocus={() => select(flow.id)}
          type="button"
          variant="ghost"
          className="my-1 flex h-auto w-full justify-start gap-2 py-2 text-xs"
          onClick={() => select(flow.id)}
          title={flow.url}
        >
          <span className="shrink-0 font-mono text-primary">{flow.method}</span>
          <span className="min-w-0 truncate">{safeURL(flow.url).search || '/'}</span>
          <span className="ml-auto shrink-0 text-muted-foreground">
            {flow.error ? 'ERR' : flow.status || '…'}
          </span>
        </Button>
      ))}
    </details>
  );
}
export function StructureView({
  flows,
  select,
}: {
  flows: FlowSummary[];
  select: (id: number) => void;
}) {
  const roots = useMemo(() => structure(flows), [flows]);
  return (
    <section
      aria-label="Host and path structure"
      className="p-3"
      onKeyDown={(event) => navigate(event, '[data-tree-flow]')}
    >
      {roots.map((node) => (
        <Branch key={node.key} node={node} select={select} />
      ))}
    </section>
  );
}
export function Waterfall({
  flows,
  all,
  selected,
  select,
}: {
  flows: FlowSummary[];
  all: FlowSummary[];
  selected: number | null;
  select: (id: number) => void;
}) {
  const stats = useMemo(() => statistics(all), [all]),
    now = Date.now(),
    { start, span } = timeline(flows, now);
  return (
    <section
      aria-label="Session statistics and waterfall"
      onKeyDown={(event) => navigate(event, '[data-waterfall-flow]')}
    >
      <div className="grid grid-cols-2 gap-3 border-b p-4 text-xs sm:grid-cols-3">
        {Object.entries({
          Requests: stats.count,
          Errors: stats.errors,
          Pending: stats.pending,
          Uploaded: bytes(stats.sent),
          Downloaded: bytes(stats.received),
          'p50 / p95': `${stats.p50 ?? '—'} / ${stats.p95 ?? '—'} ms`,
        }).map(([label, value]) => (
          <div key={label}>
            <div className="text-muted-foreground">{label}</div>
            <strong className="mt-1 block font-mono">{value}</strong>
          </div>
        ))}
      </div>
      <p className="px-4 pt-3 text-[10px] text-muted-foreground">
        Statistics include all retained exchanges. The timeline shows filtered requests during{' '}
        {(span / 1000).toFixed(2)} seconds.
      </p>
      <svg
        aria-label="Request timing waterfall"
        role="img"
        viewBox={`0 0 700 ${Math.max(48, flows.length * 28 + 32)}`}
        className="w-full min-w-[500px]"
      >
        <text x="205" y="20" className="fill-muted-foreground text-[10px]">
          0 ms
        </text>
        <text x="640" y="20" textAnchor="end" className="fill-muted-foreground text-[10px]">
          {span} ms
        </text>
        {flows.map((flow, index) => {
          const y = index * 28 + 32,
            duration = flow.duration_ms ?? Math.max(0, now - flow.started_at);
          return (
            <g
              key={flow.id}
              data-waterfall-flow={flow.id}
              onFocus={() => select(flow.id)}
              role="button"
              tabIndex={0}
              className="cursor-pointer"
              aria-label={`${flow.method} ${flow.url}, ${duration} milliseconds`}
              onClick={(event) => {
                event.currentTarget.focus();
                select(flow.id);
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  select(flow.id);
                }
              }}
            >
              <title>
                {flow.url} · {duration} ms
              </title>
              <rect
                x="0"
                y={y - 14}
                width="700"
                height="28"
                className={flow.id === selected ? 'fill-accent' : 'fill-transparent'}
              />
              <text x="12" y={y + 3} className="fill-foreground text-[10px]">
                {flow.method} {safeURL(flow.url).pathname.slice(0, 26)}
              </text>
              <rect
                x={205 + ((flow.started_at - start) / span) * 435}
                y={y - 7}
                width={Math.max(1, (duration / span) * 435)}
                height="12"
                rx="3"
                className={
                  flow.error || (flow.status || 0) >= 400 ? 'fill-destructive' : 'fill-primary'
                }
              />
            </g>
          );
        })}
      </svg>
    </section>
  );
}
