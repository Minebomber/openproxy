export type Headers = [string, string][];
export interface CapturedBody {
  data: string;
  size: number;
  truncated: boolean;
  complete: boolean;
}
export interface Message {
  headers: Headers;
  trailers: Headers;
  body: CapturedBody;
}
export interface TlsDetails {
  protocol: string;
  cipher: string;
  alpn: string;
  server_name: string;
  handshake_ms: number;
  certificate_subject: string;
  certificate_issuer: string;
  certificate_expires: string;
}
export interface ConnectionDetails {
  id: string;
  connected_at: number;
  local_address: string;
  remote_address: string;
  dns_ms: number;
  tcp_ms: number;
  proxy_ms: number | null;
  proxy: string | null;
  proxy_tls: TlsDetails | null;
  tls: TlsDetails | null;
  reused: boolean;
}
export interface FlowSummary {
  id: number;
  url: string;
  method: string;
  client: string;
  protocol: string;
  tls: boolean;
  started_at: number;
  duration_ms: number | null;
  phase: string;
  status: number | null;
  error: string | null;
  request_bytes: number;
  response_bytes: number;
  content_type: string | null;
  marked: boolean;
  has_note: boolean;
}
export interface Flow extends Omit<
  FlowSummary,
  'request_bytes' | 'response_bytes' | 'content_type'
> {
  upstream_url: string;
  headers_received_ms: number | null;
  request: Message;
  response: Message | null;
  metadata: {
    process: { pid: number; name: string } | null;
    note: string;
    marked: boolean;
    original_request: Message | null;
    original_response: Message | null;
    original_status: number | null;
    upstream_method: string;
    actions: {
      rule: string;
      index: number;
      action: string;
      phase: string;
      applied: boolean;
      changed: boolean | null;
    }[];
    actions_truncated: boolean;
    mirrors: {
      phase: string;
      path: string;
      bytes: number;
      complete: boolean;
      error: string | null;
    }[];
    websocket?: {
      extensions: string;
      truncated: boolean;
      complete: boolean;
      error: string | null;
      frames: {
        direction: string;
        at: number;
        opcode: number;
        fin: boolean;
        masked: boolean;
        compressed: boolean;
        message: number;
        size: number;
        payload: string;
        truncated: boolean;
        complete: boolean;
        error: string | null;
      }[];
    } | null;
    connection?: ConnectionDetails | null;
    client_tls?: TlsDetails | null;
    upstream_protocol?: string;
  };
}
export type Action =
  | { type: 'set_request_header' | 'set_response_header'; name: string; value: string }
  | { type: 'remove_request_header' | 'remove_response_header'; name: string }
  | {
      type: 'replace_url' | 'replace_request_body' | 'replace_response_body';
      find: string;
      replace: string;
      regex?: boolean;
    }
  | { type: 'set_query'; name: string; value: string | null }
  | { type: 'map_remote'; from: string; to: string }
  | { type: 'map_local'; path: string; url_prefix?: string }
  | { type: 'mock'; status: number; headers?: Headers; body: string }
  | { type: 'block'; message?: string }
  | { type: 'set_status'; status: number }
  | { type: 'latency'; ms: number }
  | { type: 'throttle'; upload: number; download: number }
  | { type: 'failure'; percent: number }
  | { type: 'drop'; upload_after_bytes: number | null; download_after_bytes: number | null }
  | { type: 'no_cache' | 'block_cookies' | 'offline' }
  | { type: 'mirror'; directory: string; max_bytes?: number }
  | { type: 'breakpoint'; phase: 'request' | 'response'; timeout_ms?: number };
export type BreakpointPhase = 'request' | 'response';
export interface BreakpointSummary {
  id: string;
  flow_id: number | null;
  phase: BreakpointPhase;
  method: string;
  url: string;
  status: number | null;
  created_at: number;
  deadline: number;
  body_bytes: number;
  body_complete: boolean;
}
export interface BreakpointSnapshot extends Omit<BreakpointSummary, 'body_bytes'> {
  headers: Headers;
  trailers: Headers;
  body: string;
  content_length: number | null;
}
export type BreakpointDecision =
  | { action: 'continue' | 'abort' }
  | {
      action: 'edit';
      method?: string;
      url?: string;
      status?: number;
      headers: Headers;
      body?: string;
      decoded?: boolean;
      trailers?: Headers;
    };
export interface Rule {
  name: string;
  enabled: boolean;
  url: string;
  method?: string | null;
  actions: Action[];
}
export interface Settings {
  recording: boolean;
  intercept_hosts: string[];
  bypass_hosts: string[];
  capture_bytes: number;
  max_flows: number;
  latency_ms: number;
  upload_bytes_per_second: number;
  download_bytes_per_second: number;
  aggregate_upload_bytes_per_second: number;
  aggregate_download_bytes_per_second: number;
  offline: boolean;
  process_attribution: boolean;
  failure_percent: number;
  drop_upload_after_bytes: number | null;
  drop_download_after_bytes: number | null;
  no_cache: boolean;
  block_cookies: boolean;
  rules: Rule[];
  dns_overrides: Record<string, string>;
}
export interface Status {
  version: string;
  proxy: string;
  ui: string;
  socks: string | null;
  settings: Settings;
  flow_count: number;
  retained_bytes: number;
  retention_limit: number;
  evicted_flows: number;
}
export interface Compose {
  method: string;
  url: string;
  headers: Headers;
  trailers: Headers;
  body: string;
  repeat: number;
  concurrency: number;
  apply_rules: boolean;
}
export interface Execution {
  completed: number;
  errors: string[];
}
export type Notify = (message: string, error?: boolean) => void;
