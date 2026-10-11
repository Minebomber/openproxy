import type { FlowSummary } from './types';

export type TrafficFilter = 'all' | 'https' | 'errors' | 'slow' | 'json' | 'pending' | 'marked';
export const isError = (flow: FlowSummary) => flow.error !== null || (flow.status || 0) >= 400;
export const isSlow = (flow: FlowSummary) => flow.duration_ms !== null && flow.duration_ms >= 1000;

export function matchesFilter(flow: FlowSummary, filter: TrafficFilter) {
  switch (filter) {
    case 'marked':
      return flow.marked;
    case 'https':
      return flow.tls;
    case 'errors':
      return isError(flow);
    case 'slow':
      return isSlow(flow);
    case 'json':
      return !!flow.content_type?.includes('json');
    case 'pending':
      return flow.duration_ms === null;
    default:
      return true;
  }
}
