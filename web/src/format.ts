import type { Flow, Headers, Message } from './types';

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}
export function address(value: string): URL {
  try {
    return new URL(value);
  } catch {
    return new URL('http://invalid.invalid/');
  }
}
export function header(message: Message, name: string): string {
  return message.headers.find((h) => h[0].toLowerCase() === name)?.[1] || '';
}

export function decodedText(data: Uint8Array, contentType: string): string {
  let charset = /charset\s*=\s*["']?([^\s;"']+)/i.exec(contentType)?.[1] || 'utf-8';
  if (data[0] === 0xff && data[1] === 0xfe) charset = 'utf-16le';
  if (data[0] === 0xfe && data[1] === 0xff) charset = 'utf-16be';
  return new TextDecoder(charset, { fatal: contentType.toLowerCase().includes('xml') }).decode(
    data,
  );
}
export function rawBytes(data: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
}
export function base64(data: Uint8Array): string {
  let text = '';
  for (let i = 0; i < data.length; i += 8192)
    text += String.fromCharCode(...data.subarray(i, i + 8192));
  return btoa(text);
}
export function download(data: BlobPart, name: string, type = 'application/octet-stream'): void {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function parseHeaders(text: string): Headers {
  return text
    .split('\n')
    .filter((s) => s.trim())
    .map((line) => {
      const colon = line.indexOf(':');
      if (colon < 1) throw new Error('Headers must use Name: value');
      return [line.slice(0, colon).trim(), line.slice(colon + 1).trim()];
    });
}
export function editableBody(data: string): { body: string; encoding: 'text' | 'base64' } {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes(data));
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) throw new Error('binary');
    return { body: text, encoding: 'text' };
  } catch {
    return { body: data, encoding: 'base64' };
  }
}
function quote(text: string): string {
  return `'${text.replaceAll("'", "'\\''")}'`;
}
export function curl(flow: Flow): string {
  if (
    flow.request.body.truncated ||
    !flow.request.body.complete ||
    flow.request.trailers.length > 0 ||
    flow.protocol === 'TCP tunnel' ||
    flow.method === 'CONNECT'
  )
    throw new Error(
      'Cannot export an incomplete request, opaque tunnel, or request with trailers.',
    );
  let command = `curl --request ${quote(flow.metadata?.upstream_method || flow.method)} ${quote(flow.upstream_url || flow.url)}`;
  for (const [name, value] of flow.request.headers) {
    if (
      ![
        'host',
        'content-length',
        'connection',
        'transfer-encoding',
        'proxy-authorization',
      ].includes(name.toLowerCase())
    )
      command += ` \\\n  --header ${quote(`${name}: ${value}`)}`;
  }
  if (flow.request.body.size)
    command = `printf '%s' ${quote(flow.request.body.data)} | base64 --decode | ${command} \\\n  --data-binary @-`;
  return command;
}
export async function decode(
  data: Uint8Array<ArrayBuffer>,
  encoding: string,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!encoding || encoding === 'identity') return data;
  if (!['gzip', 'deflate'].includes(encoding))
    throw new Error(
      `Preview decoding for ${encoding} is unavailable. Use hex or download the original bytes.`,
    );
  const reader = new Blob([data])
    .stream()
    .pipeThrough(new DecompressionStream(encoding as CompressionFormat))
    .getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4 * 1024 * 1024)
        throw new Error(
          'Decoded preview exceeds 4 MiB. Download the capture to inspect it separately.',
        );
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
export function hex(data: Uint8Array): string {
  const lines = [];
  for (let i = 0; i < data.length; i += 16) {
    const part = data.slice(i, i + 16);
    lines.push(
      `${i.toString(16).padStart(8, '0')}  ${[...part]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(
          47,
        )}  ${[...part].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')}`,
    );
  }
  return lines.join('\n') || '(empty body)';
}
