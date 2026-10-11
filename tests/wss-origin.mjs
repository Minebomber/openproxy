import { createSecureServer } from 'node:http2';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const server = createSecureServer({
  key: readFileSync(process.argv[2]),
  cert: readFileSync(process.argv[3]),
  ca: readFileSync(process.argv[4]),
  requestCert: true,
  rejectUnauthorized: true,
  allowHTTP1: true,
});

server.on('stream', (stream) => {
  stream.on('error', () => {});
  stream.on('data', () => {});
  stream.on('end', () => {
    stream.respond({ ':status': 200, 'content-type': 'application/json' });
    stream.end(JSON.stringify({ protocol: 'h2' }));
  });
});

server.on('upgrade', (request, socket, head) => {
  const accept = createHash('sha1')
    .update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\nX-Origin-Http-Version: ${request.httpVersion}\r\n` +
    `X-Origin-Peer-Port: ${socket.remotePort}\r\n\r\n`);
  socket.on('error', () => {});
  let pending = head;
  socket.on('data', (data) => {
    pending = Buffer.concat([pending, data]);
    while (pending.length >= 2) {
      const opcode = pending[0] & 15;
      if (!(pending[1] & 128)) return socket.destroy(new Error('client frame must be masked'));
      let length = pending[1] & 127;
      let offset = 2;
      if (length === 126) {
        if (pending.length < 4) return;
        length = pending.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        return socket.destroy(new Error('fixture only accepts messages below 64 KiB'));
      }
      if (pending.length < offset + 4 + length) return;
      const mask = pending.subarray(offset, offset + 4);
      const payload = Buffer.from(pending.subarray(offset + 4, offset + 4 + length));
      for (let index = 0; index < payload.length; index++) payload[index] ^= mask[index % 4];
      pending = pending.subarray(offset + 4 + length);
      const response = length < 126 ? Buffer.from([128 | (opcode === 9 ? 10 : opcode), length]) :
        Buffer.from([128 | opcode, 126, length >>> 8, length & 255]);
      socket.write(Buffer.concat([response, payload]));
      if (opcode === 8) return socket.end();
    }
  });
});

server.listen(0, '127.0.0.1', () => console.log(server.address().port));
