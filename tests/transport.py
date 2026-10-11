#!/usr/bin/env python3
"""Run local SOCKS, PAC, reverse proxy, and TCP forwarding tests."""
import http.client
import http.server
import ipaddress
import json
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import unittest

import integration
from integration import ProxyProcess


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError('connection ended before reply completed')
        data.extend(part)
    return bytes(data)


def socks_reply(sock):
    head = exact(sock, 4)
    assert head[0] == 5 and head[2] == 0, head
    if head[3] == 1:
        host = str(ipaddress.IPv4Address(exact(sock, 4)))
    elif head[3] == 4:
        host = str(ipaddress.IPv6Address(exact(sock, 16)))
    else:
        raise AssertionError('unexpected bound address type')
    port = int.from_bytes(exact(sock, 2), 'big')
    return head[1], (host, port)


def connect_socks(proxy, host, port, domain=True, fragmented=False):
    sock = socket.create_connection(proxy, timeout=5)
    greeting = b'\x05\x01\x00'
    if fragmented:
        for byte in greeting:
            sock.sendall(bytes([byte]))
    else:
        sock.sendall(greeting)
    assert exact(sock, 2) == b'\x05\x00'
    if domain:
        encoded = host.encode('ascii')
        addr = b'\x03' + bytes([len(encoded)]) + encoded
    else:
        ip = ipaddress.ip_address(host)
        addr = bytes([1 if ip.version == 4 else 4]) + ip.packed
    request = b'\x05\x01\x00' + addr + port.to_bytes(2, 'big')
    if fragmented:
        for byte in request:
            sock.sendall(bytes([byte]))
    else:
        sock.sendall(request)
    code, bound = socks_reply(sock)
    return sock, code, bound


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytearray()
        while True:
            part = self.request.recv(65536)
            if not part:
                break
            data.extend(part)
        self.request.sendall(data)


class Transport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.Acceptance.setUpClass()
        cls.echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        cls.echo.daemon_threads = True
        threading.Thread(target=cls.echo.serve_forever, daemon=True).start()
        cls.p = ProxyProcess(integration.Acceptance.dir / 'transport-data', integration.Acceptance.dir / 'origin-root.pem', [
            '--socks', '127.0.0.1:0',
            '--reverse', '127.0.0.1:0=' + integration.Acceptance.http + '/prefix/',
            '--reverse', '127.0.0.1:0=' + integration.Acceptance.https + '/secure/',
            '--forward', '127.0.0.1:0=127.0.0.1:' + str(cls.echo.server_address[1]),
        ]).start()
        cls.socks = cls.p.listeners['SOCKS5'][0]

    @classmethod
    def tearDownClass(cls):
        cls.p.stop()
        cls.echo.shutdown()
        cls.echo.server_close()
        integration.Acceptance.tearDownClass()

    def setUp(self):
        settings = self.p.api('status')[1]['settings']
        settings.update(recording=True, rules=[], bypass_hosts=[])
        self.assertEqual(self.p.api('settings', settings)[0], 200)
        self.p.api('flows', method='DELETE')

    def http_over_socket(self, sock, path='/echo', host='localhost'):
        sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        result = response.status, response.getheaders(), response.read()
        response.close()
        return result

    def test_http_domain_ipv4_fragmented_handshake_reuses_connected_socket(self):
        for domain in [True, False]:
            sock, code, bound = connect_socks(self.socks, '127.0.0.1', integration.Acceptance.origin.server_port, domain, fragmented=True)
            try:
                self.assertEqual(code, 0)
                status, _, body = self.http_over_socket(sock)
                self.assertEqual(status, 200, body)
                echo = json.loads(body)
                self.assertEqual(echo['path'], '/echo')
                self.assertEqual(echo['peer_port'], bound[1])
            finally:
                sock.close()

    def test_https_inspection_and_http2_client(self):
        sock, code, bound = connect_socks(self.socks, 'localhost', integration.Acceptance.tls_origin.server_port)
        self.assertEqual(code, 0)
        context = ssl.create_default_context(cafile=str(self.p.data / 'ca.pem'))
        tls = context.wrap_socket(sock, server_hostname='localhost')
        try:
            status, _, body = self.http_over_socket(tls)
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)['peer_port'], bound[1])
        finally:
            tls.close()
        result = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '', '--http2', '--proxy',
            f'socks5h://{self.socks[0]}:{self.socks[1]}', '--cacert', str(self.p.data / 'ca.pem'),
            '--write-out', '\n%{http_version}', integration.Acceptance.https + '/echo'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith(b'\n2'), result.stdout)

    def test_ipv6_socks_target_and_http_listener(self):
        class IPv6Origin(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6
        try:
            server = IPv6Origin(('::1', 0), integration.Origin)
        except OSError as error:
            self.skipTest('IPv6 loopback unavailable: ' + str(error))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            sock, code, _ = connect_socks(self.socks, '::1', server.server_port, domain=False)
            self.assertEqual(code, 0)
            try:
                self.assertEqual(self.http_over_socket(sock, host='[::1]')[0], 200)
            finally:
                sock.close()
            other = ProxyProcess(integration.Acceptance.dir / 'ipv6-data', listen='[::1]:0').start()
            try:
                status, _, body = other.request(integration.Acceptance.http + '/echo')
                self.assertEqual(status, 200, body)
            finally:
                other.stop()
        finally:
            server.shutdown()
            server.server_close()

    def test_tls_bypass_keeps_original_certificate(self):
        settings = self.p.api('status')[1]['settings']
        settings['bypass_hosts'] = ['localhost']
        self.p.api('settings', settings)
        sock, code, _ = connect_socks(self.socks, 'localhost', integration.Acceptance.tls_origin.server_port)
        self.assertEqual(code, 0)
        context = ssl.create_default_context(cafile=str(integration.Acceptance.dir / 'origin-root.pem'))
        tls = context.wrap_socket(sock, server_hostname='localhost')
        try:
            self.assertEqual(self.http_over_socket(tls)[0], 200)
        finally:
            tls.close()

    def test_binary_tcp_half_close_and_false_tls_marker_preserve_bytes(self):
        for data in [b'HELLO', b'\x16not TLS\x00\xff', bytes(range(256)) * 256]:
            sock, code, _ = connect_socks(self.socks, '127.0.0.1', self.echo.server_address[1], domain=False)
            self.assertEqual(code, 0)
            try:
                sock.sendall(data)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(sock, len(data)), data)
            finally:
                sock.close()

    def test_reverse_http_https_and_setup_name_cannot_override_destination(self):
        for addr, prefix in zip(self.p.listeners['Reverse'], ['/prefix', '/secure']):
            conn = http.client.HTTPConnection(*addr, timeout=5)
            conn.request('GET', '/items?q=one')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['path'], prefix + '/items?q=one')
            conn.request('GET', 'http://openproxy.local/ca.pem')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['path'], prefix + '/ca.pem')
            conn.close()

    def test_tcp_port_forward_preserves_half_close(self):
        data = b'port forwarding\x00\xff'
        sock = socket.create_connection(self.p.listeners['TCP'][0], timeout=5)
        try:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(sock, len(data)), data)
        finally:
            sock.close()

    def test_opaque_tcp_and_socks_har_roundtrip(self):
        data = b'HAR tunnel\x00\xff'
        for method in ('TCP', 'SOCKS'):
            if method == 'TCP':
                sock = socket.create_connection(self.p.listeners['TCP'][0], timeout=5)
            else:
                sock, code, _ = connect_socks(self.socks, '127.0.0.1', self.echo.server_address[1])
                self.assertEqual(code, 0)
            try:
                sock.sendall(data)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(sock, len(data)), data)
            finally:
                sock.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            flows = self.p.api('flows')[1]
            if len(flows) == 2 and all(flow['duration_ms'] is not None for flow in flows):
                break
            time.sleep(0.01)
        self.assertEqual({flow['method'] for flow in flows}, {'TCP', 'SOCKS'})
        har = self.p.api('har')[1]
        self.assertEqual(self.p.api('session', har)[0], 204)
        restored = self.p.api('flows')[1]
        self.assertEqual({flow['method'] for flow in restored}, {'TCP', 'SOCKS'})
        self.assertTrue(all(flow['request_bytes'] == len(data) and flow['response_bytes'] == len(data)
                            for flow in restored))
        har['log']['_openproxy_tcp'][0]['method'] = 'POST'
        self.assertEqual(self.p.api('session', har)[0], 400)

    def test_public_setup_and_executable_pac_functions(self):
        sock, code, _ = connect_socks(self.socks, 'OPENPROXY.LOCAL', 80)
        self.assertEqual(code, 0)
        try:
            self.assertEqual(self.http_over_socket(sock, '/ca.pem')[2], (self.p.data / 'ca.pem').read_bytes())
        finally:
            sock.close()
        for path, expected in [('/proxy.pac', f'PROXY 127.0.0.1:{self.p.proxy[1]}'),
                               ('/socks.pac', f'SOCKS5 127.0.0.1:{self.socks[1]}; SOCKS 127.0.0.1:{self.socks[1]}')]:
            status, _, body = self.p.request('http://openproxy.local' + path)
            self.assertEqual(status, 200)
            script = body.decode() + '\nconsole.log(JSON.stringify([FindProxyForURL("https://example.invalid", "example.invalid"),FindProxyForURL("http://localhost", "localhost")]));'
            result = subprocess.run(['node', '-e', script], text=True, capture_output=True, check=True)
            self.assertEqual(json.loads(result.stdout), [expected, 'DIRECT'])

    def test_invalid_methods_commands_addresses_and_connection_refusal(self):
        sock = socket.create_connection(self.socks, timeout=3)
        sock.sendall(b'\x05\x01\x02')
        self.assertEqual(exact(sock, 2), b'\x05\xff')
        sock.close()
        for request, expected in [(b'\x05\x03\x00\x01', 7), (b'\x05\x01\x00\x09', 8),
                                  (b'\x05\x01\x00\x03\x00', 8), (b'\x05\x01\x01\x01', 1)]:
            sock = socket.create_connection(self.socks, timeout=3)
            sock.sendall(b'\x05\x01\x00')
            self.assertEqual(exact(sock, 2), b'\x05\x00')
            sock.sendall(request)
            self.assertEqual(socks_reply(sock)[0], expected)
            sock.close()
        reserve = socket.socket()
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
        reserve.close()
        sock, code, _ = connect_socks(self.socks, '127.0.0.1', port)
        self.assertEqual(code, 5)
        sock.close()
        deadline = time.monotonic() + 1
        while not self.p.api('flows')[1] and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(any(flow['error'] for flow in self.p.api('flows')[1]))


if __name__ == '__main__':
    unittest.main(verbosity=2)
