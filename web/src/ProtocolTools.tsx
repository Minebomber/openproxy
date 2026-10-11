import { useState } from 'react';
import { post } from './api';
import { base64, bytes, header, hex, rawBytes } from './format';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { NativeSelect } from './components/ui/native-select';
import type { Flow, Message } from './types';

type Format = 'protobuf' | 'grpc' | 'amf0' | 'amf3' | 'amf_packet';
type Service = 'html' | 'css' | 'feed';
const endpoints = {
  html: 'https://validator.w3.org/nu/',
  css: 'https://jigsaw.w3.org/css-validator/validator',
  feed: 'https://validator.w3.org/feed/check.cgi',
};

export function ProtocolTools({
  id,
  token,
  direction,
  original,
  message,
}: {
  id: number;
  token: string;
  direction: 'request' | 'response';
  original: boolean;
  message: Message;
}) {
  const mime = header(message, 'content-type').toLowerCase();
  const [format, setFormat] = useState<Format>(
    mime.includes('grpc') ? 'grpc' : mime.includes('amf') ? 'amf_packet' : 'protobuf',
  );
  const [descriptor, setDescriptor] = useState<string | null>(null);
  const [messageName, setMessageName] = useState('');
  const [service, setService] = useState<Service>(
    mime.includes('css')
      ? 'css'
      : mime.includes('xml') || mime.includes('rss') || mime.includes('atom')
        ? 'feed'
        : 'html',
  );
  const [consent, setConsent] = useState(false);
  const [output, setOutput] = useState('');
  const [busy, setBusy] = useState(false);
  const schema = format === 'protobuf' || format === 'grpc';
  const complete = message.body.complete && !message.body.truncated;
  async function run(validation: boolean) {
    setBusy(true);
    setOutput('');
    try {
      const result = await post<{ output?: string; endpoint?: string; sent_bytes?: number }>(
        `flows/${id}/${validation ? 'validate' : 'decode'}`,
        token,
        validation
          ? { direction, original, service, consent }
          : {
              direction,
              original,
              format,
              descriptor: schema ? descriptor : null,
              message_name: schema && descriptor ? messageName : null,
            },
      );
      setOutput(
        validation
          ? `${result.endpoint ? `Sent ${bytes(result.sent_bytes || 0)} to ${result.endpoint}\n\n` : ''}${result.output || '(empty validator response)'}`
          : JSON.stringify(result, null, 2),
      );
    } catch (error) {
      setOutput(String(error));
    } finally {
      setBusy(false);
      if (validation) setConsent(false);
    }
  }
  return (
    <details className="mt-6 rounded-md border p-3">
      <summary className="cursor-pointer text-xs font-medium">
        Protocol decoding &amp; external validation
      </summary>
      <div className="mt-4 space-y-4 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect
            aria-label="Binary protocol format"
            value={format}
            onChange={(event) => setFormat(event.target.value as Format)}
          >
            <option value="protobuf">Protobuf wire / schema</option>
            <option value="grpc">gRPC envelopes</option>
            <option value="amf_packet">AMF packet</option>
            <option value="amf0">AMF0 values</option>
            <option value="amf3">AMF3 values</option>
          </NativeSelect>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(false)}>
            Decode locally
          </Button>
        </div>
        {schema && (
          <div className="space-y-2">
            <p className="text-muted-foreground">
              Without a schema, the decoder shows only field numbers and wire types. For field
              names, load a binary FileDescriptorSet from protoc --descriptor_set_out with
              --include_imports.
            </p>
            <label className="block">
              Optional FileDescriptorSet (≤1 MiB)
              <input
                className="mt-1 block w-full"
                aria-label="Protobuf descriptor file"
                type="file"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  setDescriptor(null);
                  if (!file) return;
                  if (file.size > 1024 * 1024) {
                    setOutput('Descriptor exceeds 1 MiB');
                    return;
                  }
                  try {
                    setDescriptor(base64(new Uint8Array(await file.arrayBuffer())));
                  } catch (error) {
                    setOutput(String(error));
                  }
                }}
              />
            </label>
            {descriptor && (
              <label className="block">
                Fully qualified message name
                <Input
                  className="mt-1"
                  aria-label="Protobuf message name"
                  value={messageName}
                  maxLength={1024}
                  placeholder="example.Message"
                  onChange={(event) => setMessageName(event.target.value)}
                />
              </label>
            )}
          </div>
        )}
        <div className="space-y-2 border-t pt-3">
          <label className="block">
            External validator
            <NativeSelect
              className="ml-2"
              aria-label="External validation service"
              disabled={busy}
              value={service}
              onChange={(event) => {
                setService(event.target.value as Service);
                setConsent(false);
              }}
            >
              <option value="html">HTML · W3C Nu</option>
              <option value="css">CSS · W3C</option>
              <option value="feed">RSS / Atom · W3C</option>
            </NativeSelect>
          </label>
          <p className="text-muted-foreground">
            This {original ? 'original' : 'effective'} {direction} body goes to {endpoints[service]}
            . It can contain private data. The request does not include captured headers, cookies,
            or URL. The validator can retrieve resources from document references. The inspector
            shows results as text.
          </p>
          {!complete && (
            <p className="notice">External validation uses only complete captured bodies.</p>
          )}
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={consent}
              disabled={busy || !complete}
              onChange={(event) => setConsent(event.target.checked)}
            />
            I consent to send this body to this external service for this request.
          </label>
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !consent || !complete}
            onClick={() => void run(true)}
          >
            Send body for validation
          </Button>
        </div>
        {output && (
          <pre className="max-h-96 overflow-auto font-mono text-[10px] [overflow-wrap:anywhere] whitespace-pre-wrap">
            {output}
          </pre>
        )}
      </div>
    </details>
  );
}

export function WebSocketFrames({
  capture,
}: {
  capture: NonNullable<Flow['metadata']['websocket']>;
}) {
  return (
    <section className="mt-6">
      <h3 className="section-heading">WebSocket frames · {capture.frames.length}</h3>
      <p className="hint">
        Extensions: {capture.extensions || 'none'}. Payloads are unmasked prefixes. Compressed
        message bytes stay compressed. Fragments keep their message number. Forwarding keeps bytes
        unchanged.
      </p>
      {capture.truncated && (
        <p className="notice">Frame or payload capture limit reached. Forwarding continues.</p>
      )}
      {capture.error && <p className="notice">{capture.error}</p>}
      {!capture.complete && !capture.error && (
        <p className="hint">Connection is active or its capture was interrupted.</p>
      )}
      {capture.frames.map((frame, index) => (
        <details className="my-2 rounded-md border p-2 text-xs" key={index}>
          <summary className="cursor-pointer">
            {frame.direction} ·{' '}
            {(
              {
                0: 'Continuation',
                1: 'Text',
                2: 'Binary',
                8: 'Close',
                9: 'Ping',
                10: 'Pong',
              } as Record<number, string>
            )[frame.opcode] || `Opcode ${frame.opcode}`}{' '}
            · {bytes(frame.size)} · message {frame.message} {frame.fin ? '· FIN' : '· fragment'}{' '}
            {frame.compressed ? '· compressed' : ''}
          </summary>
          <p className="mt-2 text-muted-foreground">
            {new Date(frame.at).toLocaleTimeString()} ·{' '}
            {frame.masked ? 'Masked on wire' : 'Unmasked on wire'}
            {frame.truncated ? ' · payload prefix' : ''}
            {!frame.complete ? ' · interrupted frame' : ''}
          </p>
          {frame.error && <p className="notice">{frame.error}</p>}
          <pre className="mt-2 max-h-48 overflow-auto font-mono text-[10px] whitespace-pre-wrap">
            {frame.opcode === 1 && frame.fin && !frame.compressed && !frame.truncated
              ? new TextDecoder().decode(rawBytes(frame.payload))
              : hex(rawBytes(frame.payload))}
          </pre>
        </details>
      ))}
    </section>
  );
}
