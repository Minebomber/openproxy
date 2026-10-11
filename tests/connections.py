#!/usr/bin/env python3
"""Run tests for local upstream proxies, authentication, mTLS, CA identity changes, and connection metadata."""
import base64
import http.client
import http.server
import ipaddress
import hashlib
import json
import select
import socket
import socketserver
import ssl
import subprocess
import threading
import unittest
from urllib.parse import urlsplit

import integration
from integration import ProxyProcess
from transport import Echo, exact, socks_reply

USER, PASSWORD = 'fixture-user', 'fixture-secret'
BASIC = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()


def relay(client, upstream):
    remaining = {client: upstream, upstream: client}
    while remaining:
        ready, _, _ = select.select(list(remaining), [], [], 10)
        if not ready:
            break
        for source in ready:
            target = remaining[source]
            try:
                data = source.recv(65536)
                if data:
                    target.sendall(data)
                else:
                    target.shutdown(socket.SHUT_WR)
                    del remaining[source]
            except OSError:
                # Clients close pooled TLS tunnels during fixture shutdown.
                return


class HttpChain(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    targets = []

    def log_message(self, *_):
        pass

    def authorized(self):
        if self.headers.get('Proxy-Authorization') == BASIC:
            return True
        self.send_response(407)
        self.send_header('Content-Length', '0')
        self.end_headers()
        return False

    def do_CONNECT(self):
        if not self.authorized():
            return
        target = urlsplit('tcp://' + self.path)
        self.targets.append(('CONNECT', self.path))
        with socket.create_connection((target.hostname, target.port), timeout=5) as upstream:
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            relay(self.connection, upstream)
        self.close_connection = True

    def do_GET(self):
        if not self.authorized():
            return
        target = urlsplit(self.path)
        assert target.scheme == 'http', self.path
        self.targets.append(('HTTP', self.path))
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        upstream = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
        upstream.request(self.command, target.path or '/', body, {
            key: value for key, value in self.headers.items()
            if key.lower() not in ['proxy-authorization', 'connection', 'host']
        })
        response = upstream.getresponse()
        payload = response.read()
        self.send_response(response.status)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        upstream.close()

    do_POST = do_GET


class SocksChain(socketserver.BaseRequestHandler):
    targets = []

    def handle(self):
        stream = self.request
        version, count = exact(stream, 2)
        methods = exact(stream, count)
        assert version == 5
        if 2 not in methods:
            stream.sendall(b'\x05\xff')
            return
        stream.sendall(b'\x05\x02')
        version, length = exact(stream, 2)
        username = exact(stream, length)
        password = exact(stream, exact(stream, 1)[0])
        accepted = version == 1 and username == USER.encode() and password == PASSWORD.encode()
        stream.sendall(bytes([1, 0 if accepted else 1]))
        if not accepted:
            return
        head = exact(stream, 4)
        assert head[:3] == b'\x05\x01\x00'
        if head[3] == 3:
            host = exact(stream, exact(stream, 1)[0]).decode()
        else:
            host = str(ipaddress.ip_address(exact(stream, 4 if head[3] == 1 else 16)))
        port = int.from_bytes(exact(stream, 2), 'big')
        self.targets.append((host, port))
        with socket.create_connection((host, port), timeout=5) as upstream:
            stream.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            relay(stream, upstream)


class Connections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.Acceptance.setUpClass()
        cls.dir = integration.Acceptance.dir
        cls.root = cls.dir / 'origin-root.pem'
        cls.credentials = cls.dir / 'credentials.json'
        cls.credentials.write_text(json.dumps({'username': USER, 'password': PASSWORD}))
        cls.credentials.chmod(0o600)
        cls.bad_credentials = cls.dir / 'bad-credentials.json'
        cls.bad_credentials.write_text(json.dumps({'username': USER, 'password': 'incorrect'}))
        cls.bad_credentials.chmod(0o600)
        cls.servers = []
        cls.http_chain = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HttpChain)
        cls.https_chain = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HttpChain)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.dir / 'origin.pem', cls.dir / 'origin.key')
        cls.https_chain.socket = context.wrap_socket(cls.https_chain.socket, server_side=True)
        cls.socks_chain = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SocksChain)
        cls.socks_chain.daemon_threads = True
        cls.mtls = http.server.ThreadingHTTPServer(('127.0.0.1', 0), integration.Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.dir / 'origin.pem', cls.dir / 'origin.key')
        context.load_verify_locations(cls.root)
        context.verify_mode = ssl.CERT_REQUIRED
        cls.mtls.socket = context.wrap_socket(cls.mtls.socket, server_side=True)
        cls.echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        cls.echo.daemon_threads = True
        for server in [cls.http_chain, cls.https_chain, cls.socks_chain, cls.mtls, cls.echo]:
            cls.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.client_cert, cls.client_key = cls.dir / 'client.pem', cls.dir / 'client.key'
        csr, extensions = cls.dir / 'client.csr', cls.dir / 'client.ext'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n')
        def openssl(*args):
            subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', cls.client_key,
                '-out', csr, '-subj', '/CN=OpenProxy fixture client')
        openssl('x509', '-req', '-in', csr, '-CA', cls.root, '-CAkey', cls.dir / 'origin-root.key',
                '-CAcreateserial', '-out', cls.client_cert, '-days', '2', '-extfile', extensions)
        cls.client_key.chmod(0o600)
        cls.sequence = 0

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        integration.Acceptance.tearDownClass()

    def proxy(self, extras=None, trust=True):
        type(self).sequence += 1
        proxy = ProxyProcess(self.dir / f'connections-{self.sequence}', self.root if trust else None, extras).start()
        self.addCleanup(proxy.stop)
        return proxy

    def flows(self, proxy):
        summaries = proxy.api('flows')[1]
        return [proxy.api('flows/' + str(flow['id']))[1] for flow in summaries]

    def check_secrets_absent(self, proxy):
        captures = json.dumps(self.flows(proxy))
        self.assertNotIn(PASSWORD, captures)
        self.assertNotIn(BASIC, captures)
        self.assertNotIn('PRIVATE KEY', captures)

    def chain_options(self, scheme, server, credentials=None):
        return ['--upstream-proxy', f'{scheme}://localhost:{server.server_address[1]}',
                '--upstream-auth', str(credentials or self.credentials)]

    def test_http_and_https_proxy_forwarding_connect_tls_and_pool(self):
        for scheme, server in [('http', self.http_chain), ('https', self.https_chain)]:
            with self.subTest(scheme=scheme):
                proxy = self.proxy(self.chain_options(scheme, server))
                for _ in range(2):
                    code, _, payload = proxy.request(integration.Acceptance.http + '/chain')
                    self.assertEqual(code, 200)
                    self.assertNotIn('proxy-authorization', {key.lower() for key, _ in json.loads(payload)['headers']})
                code, _, payload = proxy.request(integration.Acceptance.https + '/secure', tls=True)
                self.assertEqual(code, 200, payload)
                flows = self.flows(proxy)
                plain = [flow for flow in flows if not flow['tls']]
                self.assertEqual(len({flow['metadata']['connection']['id'] for flow in plain}), 1)
                self.assertEqual({flow['metadata']['connection']['reused'] for flow in plain}, {False, True})
                encrypted = next(flow for flow in flows if flow['tls'])
                self.assertTrue(encrypted['metadata']['client_tls']['protocol'].startswith('TLS'))
                details = encrypted['metadata']['connection']
                self.assertTrue(details['tls']['protocol'].startswith('TLS'))
                self.assertEqual(details['tls']['server_name'], 'localhost')
                self.assertIn('localhost', details['tls']['certificate_subject'])
                self.assertIsNotNone(details['proxy_ms'])
                self.assertEqual(bool(details['proxy_tls']), scheme == 'https')
                self.check_secrets_absent(proxy)
                har = proxy.api('har')[1]
                self.assertTrue(any(entry['_openproxy']['metadata']['connection']['id'] == details['id'] for entry in har['log']['entries']))
                self.assertEqual(proxy.api('session', har)[0], 204)
                imported = self.flows(proxy)
                self.assertTrue(any(flow['metadata']['connection']['id'] == details['id'] for flow in imported))
        self.assertTrue(any(method == 'HTTP' for method, _ in HttpChain.targets))
        self.assertTrue(any(method == 'CONNECT' for method, _ in HttpChain.targets))

    def test_ip_tls_has_no_inferred_sni(self):
        proxy = self.proxy()
        self.assertEqual(proxy.request(integration.Acceptance.https.replace('localhost', '127.0.0.1') + '/ip', tls=True)[0], 200)
        flow = self.flows(proxy)[0]
        self.assertEqual(flow['metadata']['client_tls']['server_name'], '')
        self.assertEqual(flow['metadata']['connection']['tls']['server_name'], '')

    def test_socks_upstream_http_tls_and_socket_reuse(self):
        proxy = self.proxy(self.chain_options('socks5', self.socks_chain) + ['--socks', '127.0.0.1:0'])
        body = bytes(range(256)) * 1024
        code, _, payload = proxy.request(integration.Acceptance.http + '/socks-chain', method='POST', data=body)
        self.assertEqual(code, 200)
        self.assertEqual(base64.b64decode(json.loads(payload)['body']), body)
        self.assertEqual(proxy.request(integration.Acceptance.https + '/tls', tls=True)[0], 200)
        before = len(SocksChain.targets)
        with socket.create_connection(proxy.listeners['SOCKS5'][0], timeout=5) as stream:
            stream.sendall(b'\x05\x01\x00')
            self.assertEqual(exact(stream, 2), b'\x05\x00')
            port = integration.Acceptance.origin.server_port
            stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + port.to_bytes(2, 'big'))
            self.assertEqual(socks_reply(stream)[0], 0)
            stream.sendall(b'GET /negotiated HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(stream)
            response.begin()
            self.assertEqual(response.status, 200)
            response.read()
        self.assertEqual(len(SocksChain.targets), before + 1)
        self.check_secrets_absent(proxy)

    def test_upstream_authentication_failure_is_explicit(self):
        for scheme, server in [('http', self.http_chain), ('socks5', self.socks_chain)]:
            proxy = self.proxy(self.chain_options(scheme, server, self.bad_credentials))
            code, _, payload = proxy.request(integration.Acceptance.https + '/reject', tls=True)
            self.assertEqual(code, 502)
            self.assertIn(b'Upstream failed', payload)
            self.check_secrets_absent(proxy)
        untrusted = self.proxy(self.chain_options('https', self.https_chain), trust=False)
        self.assertEqual(untrusted.request(integration.Acceptance.http + '/untrusted-proxy')[0], 502)

    def test_inbound_http_basic_connect_and_socks_authentication(self):
        proxy = self.proxy(['--proxy-auth', str(self.credentials), '--socks', '127.0.0.1:0'])
        url = integration.Acceptance.http + '/authenticated'
        code, headers, _ = proxy.request(url)
        self.assertEqual(code, 407)
        self.assertIn('proxy-authenticate', dict(headers))
        self.assertEqual(proxy.request(url, headers={'Proxy-Authorization': BASIC})[0], 200)
        self.assertEqual(proxy.request('http://openproxy.local/ca.pem')[0], 200)
        context = ssl.create_default_context(cafile=str(proxy.data / 'ca.pem'))
        conn = http.client.HTTPSConnection(*proxy.proxy, context=context, timeout=5)
        conn.set_tunnel('localhost', integration.Acceptance.tls_origin.server_port, {'Proxy-Authorization': BASIC})
        conn.request('GET', '/authenticated-connect')
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        res.read()
        conn.close()
        for password, accepted in [(b'incorrect', False), (PASSWORD.encode(), True)]:
            with socket.create_connection(proxy.listeners['SOCKS5'][0], timeout=5) as stream:
                stream.sendall(b'\x05\x02\x00\x02')
                self.assertEqual(exact(stream, 2), b'\x05\x02')
                stream.sendall(bytes([1, len(USER)]) + USER.encode() + bytes([len(password)]) + password)
                self.assertEqual(exact(stream, 2), bytes([1, 0 if accepted else 1]))
                if accepted:
                    port = integration.Acceptance.origin.server_port
                    stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + port.to_bytes(2, 'big'))
                    self.assertEqual(socks_reply(stream)[0], 0)
                    stream.sendall(b'GET /auth-socks HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n')
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    self.assertEqual(response.status, 200)
                    response.read()
        with socket.create_connection(proxy.listeners['SOCKS5'][0], timeout=5) as stream:
            stream.sendall(b'\x05\x01\x00')
            self.assertEqual(exact(stream, 2), b'\x05\xff')
        self.check_secrets_absent(proxy)

    def test_client_certificate_is_host_scoped_and_trust_stays_enabled(self):
        options = ['--client-cert', str(self.client_cert), '--client-key', str(self.client_key), '--client-cert-host', 'localhost']
        proxy = self.proxy(options)
        url = f'https://localhost:{self.mtls.server_port}/mtls'
        self.assertEqual(proxy.request(url, tls=True)[0], 200)
        self.assertEqual(proxy.request(url.replace('localhost', '127.0.0.1'), tls=True)[0], 502)
        self.assertEqual(self.proxy().request(url, tls=True)[0], 502)
        self.assertEqual(self.proxy(options, trust=False).request(url, tls=True)[0], 502)
        self.check_secrets_absent(proxy)

    def test_dns_override_through_http_chain_preserves_host(self):
        proxy = self.proxy(self.chain_options('http', self.http_chain))
        settings = proxy.api('status')[1]['settings']
        settings['dns_overrides'] = {'OVERRIDE.invalid': '127.0.0.1'}
        self.assertEqual(proxy.api('settings', settings)[0], 200)
        code, _, payload = proxy.request(f'http://override.invalid:{integration.Acceptance.origin.server_port}/override')
        self.assertEqual(code, 200, payload)
        headers = {key.lower(): value for key, value in json.loads(payload)['headers']}
        self.assertEqual(headers['host'], f'override.invalid:{integration.Acceptance.origin.server_port}')
        self.assertNotIn('proxy-authorization', headers)

    def test_chained_bypass_and_tcp_half_close(self):
        for scheme, server in [('http', self.http_chain), ('socks5', self.socks_chain)]:
            proxy = self.proxy(self.chain_options(scheme, server) + [
                '--forward', f'127.0.0.1:0=127.0.0.1:{self.echo.server_address[1]}',
            ])
            settings = proxy.api('status')[1]['settings']
            settings['bypass_hosts'] = ['localhost']
            self.assertEqual(proxy.api('settings', settings)[0], 200)
            context = ssl.create_default_context(cafile=str(self.root))
            self.assertEqual(proxy.request(integration.Acceptance.https + '/bypass-chain', tls=True, context=context)[0], 200)
            body = bytes(range(256)) * 1024
            with socket.create_connection(proxy.listeners['TCP'][0], timeout=5) as stream:
                stream.sendall(body)
                stream.shutdown(socket.SHUT_WR)
                received = bytearray()
                while part := stream.recv(65536):
                    received.extend(part)
                self.assertEqual(received, body)
            self.check_secrets_absent(proxy)

    def test_ca_rotation_import_and_invalid_replacement(self):
        directory = self.dir / 'ca-lifecycle'
        args = [str(integration.BINARY), '--data-dir', str(directory), '--ca-only']
        def run(*extras, success=True):
            result = subprocess.run(args + list(map(str, extras)), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode == 0, success, result.stderr)
            return result
        run()
        original = (directory / 'ca-identity.json').read_bytes()
        first = (directory / 'ca.pem').read_bytes()
        run('--rotate-ca')
        self.assertNotEqual((directory / 'ca.pem').read_bytes(), first)
        backups = list((directory / 'ca-backups').glob('*.json'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / 'ca-backups').stat().st_mode & 0o777, 0o700)
        run('--import-ca-cert', self.root, '--import-ca-key', self.dir / 'origin-root.key')
        self.assertEqual((directory / 'ca.pem').read_bytes(), self.root.read_bytes())
        before = (directory / 'ca-identity.json').read_bytes()
        run('--import-ca-cert', self.root, '--import-ca-key', self.client_key, success=False)
        run('--import-ca-cert', self.client_cert, '--import-ca-key', self.client_key, success=False)
        self.assertEqual((directory / 'ca-identity.json').read_bytes(), before)
        self.assertEqual(len(list((directory / 'ca-backups').glob('*.json'))), 2)
        run()
        self.assertEqual((directory / 'ca-identity.json').read_bytes(), before)
        proxy = ProxyProcess(directory, self.root).start()
        self.addCleanup(proxy.stop)
        self.assertEqual(proxy.request(integration.Acceptance.https + '/imported-ca', tls=True)[0], 200)

    def test_wss_upgrade_uses_http1_after_h2_with_chain_mtls_and_socks_reuse(self):
        origin = subprocess.Popen(['node', str(integration.ROOT / 'tests/wss-origin.mjs'),
                                   str(self.dir / 'origin.key'), str(self.dir / 'origin.pem'), str(self.root)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop_origin():
            origin.terminate()
            origin.wait(timeout=5)
            origin.stdout.close()
            origin.stderr.close()
        self.addCleanup(stop_origin)
        port = int(origin.stdout.readline().strip())
        client_options = ['--client-cert', str(self.client_cert), '--client-key', str(self.client_key),
                          '--client-cert-host', 'localhost', '--socks', '127.0.0.1:0']
        def headers(stream):
            data = bytearray()
            while not data.endswith(b'\r\n\r\n'):
                data.extend(exact(stream, 1))
                self.assertLess(len(data), 16384)
            lines = data.decode().split('\r\n')
            return int(lines[0].split(' ')[1]), {key.lower(): value for key, value in (line.split(': ', 1) for line in lines[1:] if line)}
        def websocket(proxy, via_socks=False):
            if via_socks:
                stream = socket.create_connection(proxy.listeners['SOCKS5'][0], timeout=5)
                stream.sendall(b'\x05\x01\x00')
                self.assertEqual(exact(stream, 2), b'\x05\x00')
                stream.sendall(b'\x05\x01\x00\x03\x09localhost' + port.to_bytes(2, 'big'))
                status, bound = socks_reply(stream)
                self.assertEqual(status, 0)
            else:
                stream = socket.create_connection(proxy.proxy, timeout=5)
                stream.sendall(f'CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n'.encode())
                self.assertEqual(headers(stream)[0], 200)
            context = ssl.create_default_context(cafile=str(proxy.data / 'ca.pem'))
            with context.wrap_socket(stream, server_hostname='localhost') as stream:
                key = base64.b64encode(b'0123456789abcdef').decode()
                stream.sendall((f'GET /ws HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\n'
                                f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
                status, response = headers(stream)
                self.assertEqual(status, 101)
                self.assertEqual(response['x-origin-http-version'], '1.1')
                expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.assertEqual(response['sec-websocket-accept'], expected)
                if via_socks:
                    self.assertEqual(int(response['x-origin-peer-port']), bound[1])
                for opcode, payload in [(1, b'WSS after HTTP/2'), (2, bytes(range(256)) * 4),
                                        (9, b'ping'), (8, b'\x03\xe8')]:
                    mask = b'mask'
                    frame = bytes([128 | opcode, 128 | len(payload)]) if len(payload) < 126 else bytes([128 | opcode, 254]) + len(payload).to_bytes(2, 'big')
                    stream.sendall(frame + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload)))
                    reply = exact(stream, 2)
                    self.assertEqual(reply[0], 128 | (10 if opcode == 9 else opcode))
                    self.assertEqual(reply[1] & 128, 0)
                    length = reply[1] & 127
                    if length == 126:
                        length = int.from_bytes(exact(stream, 2), 'big')
                    self.assertEqual(exact(stream, length), payload)
        for chain in [[], self.chain_options('http', self.http_chain),
                      self.chain_options('https', self.https_chain), self.chain_options('socks5', self.socks_chain)]:
            proxy = self.proxy(client_options + chain)
            settings = proxy.api('status')[1]['settings']
            settings['dns_overrides'] = {'localhost': '127.0.0.1'}
            self.assertEqual(proxy.api('settings', settings)[0], 200)
            code, _, body = proxy.request(f'https://localhost:{port}/h2', tls=True)
            self.assertEqual(code, 200, body)
            self.assertEqual(json.loads(body)['protocol'], 'h2')
            websocket(proxy)
            if not chain:
                websocket(proxy, via_socks=True)
            flows = self.flows(proxy)
            regular = next(flow for flow in flows if flow['url'].endswith('/h2'))
            upgrades = [flow for flow in flows if flow['url'].endswith('/ws')]
            self.assertEqual(regular['metadata']['upstream_protocol'], 'HTTP/2.0')
            self.assertEqual(regular['metadata']['connection']['tls']['alpn'], 'h2')
            self.assertTrue(upgrades)
            for upgrade in upgrades:
                self.assertEqual(upgrade['metadata']['upstream_protocol'], 'HTTP/1.1')
                self.assertEqual(upgrade['metadata']['connection']['tls']['alpn'], 'http/1.1')
                self.assertNotEqual(upgrade['metadata']['connection']['id'], regular['metadata']['connection']['id'])
                capture = upgrade['metadata']['websocket']
                self.assertIsNotNone(capture)
                client_frames = [frame for frame in capture['frames'] if frame['direction'] == 'client']
                server_frames = [frame for frame in capture['frames'] if frame['direction'] == 'server']
                self.assertEqual([frame['opcode'] for frame in client_frames], [1, 2, 9, 8])
                self.assertEqual([frame['opcode'] for frame in server_frames], [1, 2, 10, 8])
                self.assertEqual(base64.b64decode(client_frames[1]['payload']), bytes(range(256)) * 4)
            self.check_secrets_absent(proxy)


if __name__ == '__main__':
    unittest.main(verbosity=2)
