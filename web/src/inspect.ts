import type { FlowSummary } from './types';

export function safeURL(value: string) {
  try {
    return new URL(value);
  } catch {
    return new URL('http://invalid/');
  }
}

export interface PathNode {
  name: string;
  key: string;
  count: number;
  children: Map<string, PathNode>;
  flows: FlowSummary[];
}
export function structure(flows: FlowSummary[]): PathNode[] {
  const roots = new Map<string, PathNode>();
  for (const flow of flows) {
    let host = 'unknown',
      parts = [flow.url];
    try {
      const url = new URL(flow.url);
      host = url.host;
      parts = url.pathname.split('/').filter(Boolean);
    } catch {
      /* If URL parsing fails, show the imported destination. */
    }
    if (parts.length > 32) parts = [...parts.slice(0, 31), parts.slice(31).join('/')];
    let nodes = roots,
      parent: PathNode | undefined;
    for (const name of [host, ...parts]) {
      let node = nodes.get(name);
      if (!node) {
        node = {
          name,
          key: (parent?.key || '') + '/' + name,
          count: 0,
          children: new Map(),
          flows: [],
        };
        nodes.set(name, node);
      }
      node.count++;
      nodes = node.children;
      parent = node;
    }
    parent!.flows.push(flow);
  }
  return [...roots.values()];
}
export function statistics(flows: FlowSummary[]) {
  const durations = flows
    .map((flow) => flow.duration_ms)
    .filter((value): value is number => value !== null && Number.isFinite(value))
    .sort((a, b) => a - b);
  const percentile = (fraction: number) =>
    durations.length ? durations[Math.max(0, Math.ceil(durations.length * fraction) - 1)] : null;
  return {
    count: flows.length,
    errors: flows.filter((flow) => flow.error !== null || (flow.status || 0) >= 400).length,
    pending: flows.filter((flow) => flow.duration_ms === null).length,
    sent: flows.reduce((sum, flow) => sum + flow.request_bytes, 0),
    received: flows.reduce((sum, flow) => sum + flow.response_bytes, 0),
    p50: percentile(0.5),
    p95: percentile(0.95),
  };
}
export function timeline(flows: FlowSummary[], now = Date.now()) {
  if (!flows.length) return { start: 0, span: 1 };
  let start = Infinity,
    end = -Infinity;
  for (const flow of flows) {
    start = Math.min(start, flow.started_at);
    end = Math.max(end, flow.started_at + (flow.duration_ms ?? Math.max(0, now - flow.started_at)));
  }
  return { start, span: Math.max(1, end - start) };
}
