#!/usr/bin/env python3
"""Run local protocol acceptance tests. Do not send external validation requests."""
import base64
import hashlib
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path

from integration import ProxyProcess


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError('interrupted fixture connection')
        data.extend(part)
    return bytes(data)


def frame(opcode, payload=b'', fin=True, masked=False, compressed=False):
    first = opcode | (128 if fin else 0) | (64 if compressed else 0)
    n = len(payload)
    header = bytes([first, (128 if masked else 0) | (n if n < 126 else 126)])
    if n >= 126:
        header += n.to_bytes(2, 'big')
    if masked:
        mask = b'\x01\x02\x03\x04'
        return header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return header + payload


CLIENT = frame(1, b'hel', fin=False, masked=True) + frame(9, b'ping', masked=True) + frame(0, b'lo', masked=True)
SERVER = frame(1, b'compressed-prefix', fin=False, compressed=True) + frame(10, b'pong') + frame(0, b'compressed-tail') + frame(2, b'B' * 20000) + frame(8, b'\x03\xe8')


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        headers = bytearray()
        while not headers.endswith(b'\r\n\r\n'):
            headers.extend(exact(self.request, 1))
        key = next(line.split(b':', 1)[1].strip() for line in headers.split(b'\r\n') if line.lower().startswith(b'sec-websocket-key:'))
        accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        self.request.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ' + accept + b'\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n')
        if b'/interrupted ' in headers:
            self.request.sendall(b'\x82\x7e\x00\x08ab')
            return
        if b'/malformed ' in headers:
            self.request.sendall(b'\x82\x7f\x80\x00\x00\x00\x00\x00\x00\x00untouched')
            return
        received = exact(self.request, len(CLIENT))
        self.server.received = received
        # Split frame headers, masks, and payloads across socket writes for partial-read tests.
        for offset in range(0, len(SERVER), 37):
            self.request.sendall(SERVER[offset:offset + 37])
        self.request.shutdown(socket.SHUT_WR)
        while self.request.recv(4096):
            pass


class Protocols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='openproxy-protocols-')
        cls.origin = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Origin)
        cls.origin.daemon_threads = True
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        cls.proxy = ProxyProcess(Path(cls.temp.name) / 'data').start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.origin.shutdown()
        cls.origin.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.proxy.api('flows', method='DELETE')

    def upgrade(self, path, upgrade_headers='Upgrade: websocket\r\n'):
        sock = socket.create_connection(self.proxy.proxy, timeout=5)
        url = f'http://127.0.0.1:{self.origin.server_address[1]}{path}'
        sock.sendall(f'GET {url} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n{upgrade_headers}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n'.encode())
        headers = bytearray()
        while not headers.endswith(b'\r\n\r\n'):
            headers.extend(exact(sock, 1))
        self.assertTrue(headers.startswith(b'HTTP/1.1 101'), headers)
        return sock

    def captured(self):
        for _ in range(100):
            flows = self.proxy.api('flows')[1]
            if flows:
                flow = self.proxy.api(f'flows/{flows[0]["id"]}')[1]
                if flow['duration_ms'] is not None:
                    return flow
            time.sleep(.02)
        self.fail('WebSocket capture did not finish')

    def test_websocket_raw_bytes_fragments_controls_masking_and_retention(self):
        sock = self.upgrade('/frames')
        for byte in CLIENT:
            sock.sendall(bytes([byte]))
        sock.shutdown(socket.SHUT_WR)
        received = bytearray()
        while part := sock.recv(65536):
            received.extend(part)
        sock.close()
        self.assertEqual(bytes(received), SERVER)
        self.assertEqual(self.origin.received, CLIENT)
        capture = self.captured()['metadata']['websocket']
        self.assertTrue(capture['complete'], capture)
        client = [f for f in capture['frames'] if f['direction'] == 'client']
        self.assertEqual([f['opcode'] for f in client], [1, 9, 0])
        self.assertEqual(base64.b64decode(client[0]['payload']), b'hel')
        self.assertEqual(client[0]['message'], client[2]['message'])
        server = [f for f in capture['frames'] if f['direction'] == 'server']
        self.assertTrue(server[0]['compressed'] and server[2]['compressed'])
        self.assertEqual(len(base64.b64decode(server[3]['payload'])), 16384)
        self.assertTrue(server[3]['truncated'])
        # Native sessions must keep frames. Invalid metadata must not bypass size limits.
        har = self.proxy.api('har')[1]
        self.assertEqual(self.proxy.api('session', har)[0], 204)
        restored = self.proxy.api('flows')[1][0]['id']
        restored_flow = self.proxy.api(f'flows/{restored}')[1]
        self.assertEqual(restored_flow['protocol'], 'WebSocket')
        self.assertEqual(restored_flow['metadata']['websocket']['frames'], capture['frames'])
        session = self.proxy.api('session')[1]
        self.assertEqual(self.proxy.api('session', session)[0], 204)
        session['flows'][0]['metadata']['websocket']['frames'] *= 40
        self.assertEqual(self.proxy.api('session', session)[0], 400)

    def test_websocket_incomplete_and_malformed_inspection_preserves_forwarding(self):
        for path, expected in [('/interrupted', b'\x82\x7e\x00\x08ab'), ('/malformed', b'\x82\x7f\x80\x00\x00\x00\x00\x00\x00\x00untouched')]:
            self.proxy.api('flows', method='DELETE')
            sock = self.upgrade(path)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(sock, len(expected)), expected)
            self.assertEqual(sock.recv(1), b'')
            sock.close()
            ws = self.captured()['metadata']['websocket']
            self.assertFalse(ws['complete'])
            if path == '/interrupted':
                self.assertFalse(ws['frames'][0]['complete'])
                self.assertEqual(base64.b64decode(ws['frames'][0]['payload']), b'ab')
            else:
                self.assertTrue(ws['truncated'])
                self.assertIn('64-bit length', ws['error'])

    def test_websocket_upgrade_protocol_lists_and_repeated_headers(self):
        for headers in ['Upgrade: other, WeBsOcKeT\r\n', 'Upgrade: other\r\nUpgrade: websocket\r\n']:
            with self.subTest(headers=headers):
                self.proxy.api('flows', method='DELETE')
                sock = self.upgrade('/interrupted', headers)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(sock, 6), b'\x82\x7e\x00\x08ab')
                self.assertEqual(sock.recv(1), b'')
                sock.close()
                flow = self.captured()
                self.assertEqual(flow['protocol'], 'WebSocket')
                self.assertEqual(base64.b64decode(flow['metadata']['websocket']['frames'][0]['payload']), b'ab')

    def test_decoder_api_auth_incomplete_capture_and_validator_consent(self):
        empty = {'headers': [], 'trailers': [], 'body': {'data': 'CCo=', 'size': 2, 'truncated': False, 'complete': True}}
        flow = {'id': 1, 'url': 'http://fixture.invalid/protobuf', 'upstream_url': 'http://fixture.invalid/protobuf', 'method': 'POST', 'protocol': 'HTTP/2', 'client': '127.0.0.1', 'tls': False, 'started_at': 1, 'headers_received_ms': 1, 'status': 200, 'error': None, 'request': empty, 'response': empty, 'phase': 'complete', 'duration_ms': 1}
        self.assertEqual(self.proxy.api('session', {'version': 1, 'flows': [flow]})[0], 204)
        id = self.proxy.api('flows')[1][0]['id']
        options = {'direction': 'response', 'format': 'protobuf'}
        status, decoded = self.proxy.api(f'flows/{id}/decode', options)
        self.assertEqual(status, 200, decoded)
        self.assertEqual(decoded['value']['fields'][0]['value'], '42')
        self.assertEqual(self.proxy.api(f'flows/{id}/decode', options, auth=False)[0], 401)
        status, error = self.proxy.api(f'flows/{id}/validate', {'direction': 'response', 'service': 'html'})
        self.assertEqual(status, 400)
        self.assertIn(b'explicit consent', error)
        # Reject incomplete bodies even with explicit consent for external validation.
        flow['response']['body']['complete'] = False
        self.proxy.api('session', {'version': 1, 'flows': [flow]})
        id = self.proxy.api('flows')[1][0]['id']
        status, error = self.proxy.api(f'flows/{id}/validate', {'direction': 'response', 'service': 'html', 'consent': True})
        self.assertEqual(status, 400)
        self.assertIn(b'complete captured body', error)


if __name__ == '__main__':
    unittest.main(verbosity=2)
