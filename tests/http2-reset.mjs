import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import assert from 'node:assert/strict';

const [proxyPort, originPort, ca] = process.argv.slice(2);
const socket = net.connect(Number(proxyPort), '127.0.0.1');
await new Promise((resolve, reject) => {
  socket.once('error', reject);
  socket.once('connect', resolve);
});
socket.write(`CONNECT localhost:${originPort} HTTP/1.1\r\nHost: localhost:${originPort}\r\n\r\n`);
await new Promise((resolve, reject) => {
  let response = '';
  const receive = data => {
    response += data.toString();
    if (response.length > 8192) reject(new Error('oversized CONNECT response'));
    if (response.endsWith('\r\n\r\n')) {
      socket.removeListener('data', receive);
      assert.match(response, /^HTTP\/1\.1 200 /);
      resolve();
    }
  };
  socket.on('data', receive);
});
const secure = tls.connect({socket, servername: 'localhost', ca: readFileSync(ca), ALPNProtocols: ['h2']});
await new Promise((resolve, reject) => {
  secure.once('error', reject);
  secure.once('secureConnect', resolve);
});
assert.equal(secure.alpnProtocol, 'h2');
const client = http2.connect(`https://localhost:${originPort}`, {createConnection: () => secure});
client.on('error', error => { throw error; });
const cancelled = client.request({':path': '/h2-cancel'});
cancelled.on('error', () => {});
cancelled.end();
const survivor = client.request({':path': '/h2-survivor'});
let body = '';
survivor.setEncoding('utf8');
survivor.on('response', headers => assert.equal(headers[':status'], 200));
survivor.on('data', chunk => { body += chunk; });
survivor.on('end', () => {
  assert.equal(JSON.parse(body).path, '/h2-survivor');
  console.log('survivor passed');
  client.close();
});
survivor.end();
console.log('streams ready');
const input = createInterface({input: process.stdin});
input.once('line', line => {
  assert.equal(line, 'cancel');
  cancelled.close(http2.constants.NGHTTP2_CANCEL);
  input.close();
});
client.once('close', () => process.exit(0));
