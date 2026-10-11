import { createSecureServer } from 'node:http2';
import { readFileSync } from 'node:fs';

const server = createSecureServer({
  key: readFileSync(process.argv[2]),
  cert: readFileSync(process.argv[3]),
});

server.on('stream', (stream, headers) => {
  const chunks = [];
  let trailers = {};
  stream.on('error', () => {});
  stream.on('data', chunk => chunks.push(chunk));
  stream.on('trailers', fields => { trailers = fields; });
  stream.on('end', () => {
    stream.respond({
      ':status': 200,
      'content-type': 'application/json',
      'x-origin-http-version': '2',
      'x-origin-host-present': String('host' in headers),
    });
    stream.end(headers[':method'] === 'HEAD' ? undefined : JSON.stringify({
      headers,
      trailers,
      body: Buffer.concat(chunks).toString('base64'),
    }));
  });
});

server.listen(0, '127.0.0.1', () => console.log(server.address().port));
