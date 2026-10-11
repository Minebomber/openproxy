import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { curl, decode, decodedText, editableBody, parseHeaders } from '../web/src/format.ts';
import { structure, statistics, timeline } from '../web/src/inspect.ts';

test('cURL export preserves binary bytes and literal shell metacharacters', () => {
  const bytes = Buffer.from([0, 255, 1, 39]);
  const url = "https://example.invalid/?q=$(printf injected)&quote='";
  const header = "literal ' $(printf injected) `printf injected`";
  const command = curl({ method: 'GET', url: 'https://original.invalid/', upstream_url: url, metadata: {upstream_method:'POST'}, request: {
    headers: [['X-Value', header], ['Content-Length', '999']],
    trailers: [],
    body: { data: bytes.toString('base64'), size: bytes.length, complete: true, truncated: false },
  }});
  const stub = `curl() { python3 -c 'import sys,json,base64; print(json.dumps({"args":sys.argv[1:],"body":base64.b64encode(sys.stdin.buffer.read()).decode()}))' "$@"; }\n`;
  const result = JSON.parse(execFileSync('bash', ['-c', stub + command], { encoding: 'utf8' }));
  assert.deepEqual(result.args, ['--request', 'POST', url, '--header', 'X-Value: ' + header, '--data-binary', '@-']);
  assert.equal(result.body, bytes.toString('base64'));
});

test('editor selects base64 for binary bodies and refuses incomplete cURL', () => {
  assert.equal(editableBody('AP8=').encoding, 'base64');
  assert.equal(editableBody('AGhlbGxv').encoding, 'base64');
  assert.deepEqual(editableBody('aGVsbG8='), { body: 'hello', encoding: 'text' });
  assert.throws(() => curl({ method: 'POST', request: { body: { complete: false } } }), /incomplete/);
  assert.throws(() => curl({ method: 'POST', url: 'http://example.invalid/', metadata: {}, request: { headers: [], body: { data: '', size: 0, complete: true, truncated: false }, trailers: [['x-checksum', 'value']] } }), /trailers/);
  assert.throws(() => parseHeaders('Bad header'), /Name: value/);
  assert.deepEqual(parseHeaders('X-One: a\nX-One: b: c'), [['X-One', 'a'], ['X-One', 'b: c']]);
});

test('compressed previews reject decompression beyond the memory budget', async () => {
  const large = Uint8Array.from(gzipSync(Buffer.alloc(5 * 1024 * 1024)));
  await assert.rejects(decode(large, 'gzip'), /4 MiB/);
  const small = Uint8Array.from(gzipSync(Buffer.from('fixture')));
  assert.equal(new TextDecoder().decode(await decode(small, 'gzip')), 'fixture');
});

test('session structure and statistics retain repeated paths and handle pending/empty sessions', () => {
  const sample = {id:1,url:'https://example.test/api/items?q=1',method:'GET',status:200,error:null,duration_ms:10,started_at:100,request_bytes:2,response_bytes:3};
  const pending={...sample,id:2,duration_ms:null,started_at:150};
  const nodes=structure([sample,pending]);
  assert.equal(nodes[0].count,2);
  assert.equal(nodes[0].children.get('api').children.get('items').flows.length,2);
  assert.equal(statistics([sample,pending]).pending,1);
  assert.equal(statistics([sample,pending]).received,6);
  assert.equal(statistics([sample,pending]).p95,10);
  assert.equal(statistics([]).p50,null);
  assert.deepEqual(timeline([],200),{start:0,span:1});
  assert.deepEqual(timeline([sample,pending],200),{start:100,span:100});
});

test('XML text decoding honors UTF-16 BOMs and rejects invalid UTF-8', () => {
  const utf16=Uint8Array.from([255,254,60,0,114,0,47,0,62,0]);
  assert.equal(decodedText(utf16,'application/xml'),'<r/>');
  assert.throws(()=>decodedText(Uint8Array.from([255]),'application/xml'));
  assert.equal(decodedText(Uint8Array.from([233]),'text/plain; charset=windows-1252'),'é');
});
