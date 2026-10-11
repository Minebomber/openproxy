#!/usr/bin/env python3
"""Run local protocol acceptance tests. Build first: cargo build. Run: python3 tests/integration.py."""
import base64
import concurrent.futures
import gzip
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("OPENPROXY_BIN", ROOT / "target/debug/openproxy"))
LARGE = bytes(range(256)) * 1024


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received = []
    received_lock = threading.Lock()
    stream_release = threading.Event()

    def log_message(self, *_):
        pass

    def read_body(self):
        self.request_trailers = []
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    while True:
                        line = self.rfile.readline()
                        if line == b"\r\n":
                            break
                        if not line:
                            raise ConnectionError("incomplete request trailers")
                        name, value = line.decode().split(":", 1)
                        self.request_trailers.append([name.strip().lower(), value.strip()])
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                assert self.rfile.read(2) == b"\r\n"
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_POST(self):
        self.do_GET()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "999")
        self.end_headers()

    def do_GET(self):
        body = self.read_body()
        with self.received_lock:
            self.received.append((self.command, self.path, body))
        if self.path == "/held-stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            first = b"data: first\n\n"
            self.wfile.write(f"{len(first):x}\r\n".encode() + first + b"\r\n")
            self.wfile.flush()
            self.stream_release.wait(timeout=5)
            second = b"data: second\n\n"
            self.wfile.write(f"{len(second):x}\r\n".encode() + second + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for data in [b"data: first\n\n", b"data: second\n\n"]:
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
                time.sleep(0.15)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        payload = LARGE if self.path == "/large" else LARGE * 8 if self.path == "/huge" else json.dumps({"method": self.command, "path": self.path,
            "headers": list(self.headers.items()), "body": base64.b64encode(body).decode(), "trailers": self.request_trailers, "peer_port": self.client_address[1]}).encode()
        if self.path == "/trailers":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Check, Digest")
            self.end_headers()
            digest = base64.b64encode(hashlib.sha256(payload).digest())
            self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\nX-Check: done\r\nDigest: sha-256=" + digest + b"\r\n\r\n")
            self.wfile.flush()
            return
        if self.path == "/gzip":
            payload = gzip.compress(payload)
        if self.path == "/gzip-members":
            payload = gzip.compress(b"first old ") + gzip.compress(b"second old")
        self.send_response(302 if self.path == "/redirect" else 200)
        self.send_header("Content-Type", "application/octet-stream" if self.path == "/large" else "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Set-Cookie", "first=1")
        self.send_header("Set-Cookie", "second=2")
        if self.path == "/redirect":
            self.send_header("Location", "/echo")
        if self.path in ("/gzip", "/gzip-members"):
            self.send_header("Content-Encoding", "gzip")
            self.send_header("ETag", '"original"')
        self.end_headers()
        self.wfile.write(payload)


class ProxyProcess:
    def __init__(self, data, root=None, extras=None, listen='127.0.0.1:0'):
        self.data, self.root = Path(data), root
        self.extras = extras or []
        self.listen = listen

    def start(self):
        args = [str(BINARY), "--listen", self.listen, "--ui", "127.0.0.1:0", "--data-dir", str(self.data)]
        if self.root:
            args += ["--upstream-ca", str(self.root)]
        args += self.extras
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = [self.process.stdout.readline().strip() for _ in range(5)]
        if not lines[2].startswith("Inspector: "):
            error = self.process.stderr.read()
            self.process.wait(timeout=3)
            self.process.stdout.close()
            self.process.stderr.close()
            raise RuntimeError(f"startup failed: {lines} {error}")
        self.proxy = tuple(lines[1].split(" ")[1].rsplit(":", 1))
        self.proxy = (self.proxy[0].strip('[]'), int(self.proxy[1]))
        url, self.token = lines[2].split(" ")[1].split("/#")
        self.ui = url.removeprefix("http://")
        self.listeners = {}
        extra_lines = sum(self.extras.count(flag) for flag in ['--socks', '--reverse', '--forward'])
        for _ in range(extra_lines):
            line = self.process.stdout.readline().strip()
            kind, value = line.split(': ', 1)
            addr = value.split(' -> ', 1)[0]
            host, port = addr.rsplit(':', 1)
            self.listeners.setdefault(kind, []).append((host.strip('[]'), int(port)))
        return self

    def stop(self, stop_signal=signal.SIGINT):
        if self.process.poll() is None:
            self.process.send_signal(stop_signal)
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("graceful shutdown timed out")
        assert self.process.returncode == 0, self.process.stderr.read()
        self.process.stdout.close()
        self.process.stderr.close()

    def api(self, path, data=None, method=None, extra=None, auth=True):
        conn = http.client.HTTPConnection(self.ui, timeout=10)
        headers = {"Authorization": f"Bearer {self.token}"} if auth else {}
        if extra:
            headers.update(extra)
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method or ("POST" if data is not None else "GET"), "/api/" + path,
                     json.dumps(data) if data is not None else None, headers)
        res = conn.getresponse()
        code, payload = res.status, res.read()
        conn.close()
        return code, json.loads(payload) if payload and res.getheader("Content-Type", "").startswith("application/json") else payload

    def request(self, url, method="GET", data=None, headers=None, tls=False, context=None):
        if tls:
            context = context or ssl.create_default_context(cafile=str(self.data / "ca.pem"))
            conn = http.client.HTTPSConnection(*self.proxy, context=context, timeout=10)
            from urllib.parse import urlsplit
            target = urlsplit(url)
            conn.set_tunnel(target.hostname, target.port or 443)
            path = target.path + ("?" + target.query if target.query else "")
        else:
            conn = http.client.HTTPConnection(*self.proxy, timeout=10)
            path = url
        conn.request(method, path, data, headers or {})
        res = conn.getresponse()
        code, hs, payload = res.status, res.getheaders(), res.read()
        conn.close()
        return code, hs, payload


class Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "test-artifacts").mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=ROOT / "test-artifacts")
        cls.dir = Path(cls.temp.name)
        cls.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        cls.thread = threading.Thread(target=cls.origin.serve_forever, daemon=True)
        cls.thread.start()
        cls.http = f"http://127.0.0.1:{cls.origin.server_port}"
        cert, key = cls.dir / "origin.pem", cls.dir / "origin.key"
        root, root_key, csr = cls.dir / "origin-root.pem", cls.dir / "origin-root.key", cls.dir / "origin.csr"
        def openssl(*args):
            subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root_key, "-out", root,
                "-subj", "/CN=Fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-days", "2")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=localhost")
        extensions = cls.dir / "leaf.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
        openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key, "-CAcreateserial", "-out", cert,
                "-days", "2", "-extfile", extensions)
        cls.tls_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.tls_origin.socket = context.wrap_socket(cls.tls_origin.socket, server_side=True)
        threading.Thread(target=cls.tls_origin.serve_forever, daemon=True).start()
        cls.https = f"https://localhost:{cls.tls_origin.server_port}"
        cls.proxy = ProxyProcess(cls.dir / "data", root).start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.origin.shutdown()
        cls.tls_origin.shutdown()
        cls.origin.server_close()
        cls.tls_origin.server_close()
        cls.temp.cleanup()

    def setUp(self):
        with Origin.received_lock:
            Origin.received.clear()
        Origin.stream_release.clear()
        for paused in self.proxy.api("breakpoints")[1]:
            self.proxy.api("breakpoints/" + paused["id"], {"action": "abort"})
        status = self.proxy.api("status")[1]
        self.settings = status["settings"]
        defaults = {"recording": True, "capture_bytes": 65536, "max_flows": 1000, "bypass_hosts": [],
                    "latency_ms": 0, "upload_bytes_per_second": 0, "download_bytes_per_second": 0,
                    "no_cache": False, "block_cookies": False, "rules": [], "dns_overrides": {}}
        self.settings.update(defaults)
        self.assertEqual(self.proxy.api("settings", self.settings)[0], 200)
        self.assertEqual(self.proxy.api("flows", method="DELETE")[0], 204)

    def latest(self):
        for _ in range(30):
            rows = self.proxy.api("flows")[1]
            if rows and rows[0]["duration_ms"] is not None:
                return self.proxy.api(f"flows/{rows[0]['id']}")[1]
            time.sleep(0.02)
        self.fail("flow did not complete")

    def test_http_binary_capture_duplicate_headers_and_redirect(self):
        code, hs, payload = self.proxy.request(self.http + "/echo?q=one", "POST", b"\x00\xffhello", {"X-Test": "yes", "Host": "wrong.invalid"})
        self.assertEqual(code, 200, payload)
        self.assertEqual(base64.b64decode(json.loads(payload)["body"]), b"\x00\xffhello")
        headers = {name.lower(): value for name, value in json.loads(payload)["headers"]}
        self.assertEqual(headers['host'], f'127.0.0.1:{self.origin.server_port}')
        self.assertEqual(len([h for h in hs if h[0].lower() == "set-cookie"]), 2)
        flow = self.latest()
        self.assertEqual(base64.b64decode(flow["request"]["body"]["data"]), b"\x00\xffhello")
        self.assertTrue(flow["request"]["body"]["complete"])
        self.assertTrue(flow["response"]["body"]["complete"])
        self.assertEqual(self.proxy.request(self.http + "/redirect")[0], 302)

    def test_https_mitm_and_client_trust(self):
        code, _, payload = self.proxy.request(self.https + "/echo", tls=True)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(payload)["path"], "/echo")
        self.assertTrue(self.latest()["tls"])
        with self.assertRaises(ssl.SSLError):
            self.proxy.request(self.https + "/echo", tls=True, context=ssl.create_default_context())

    def test_http2_client_over_connect(self):
        result = subprocess.run(["curl", "--silent", "--show-error", "--noproxy", "", "--http2", "--proxy",
            f"http://{self.proxy.proxy[0]}:{self.proxy.proxy[1]}", "--cacert", str(self.proxy.data / "ca.pem"),
            "--write-out", "\n%{http_version}", self.https + "/echo"], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith(b"\n2"), result.stdout)
        self.assertEqual(self.latest()["protocol"], "HTTP/2.0")

    def test_http2_upstream_authority_and_bodies(self):
        origin = subprocess.Popen(["node", str(ROOT / "tests/http2-origin.mjs"),
            str(self.dir / "origin.key"), str(self.dir / "origin.pem")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            port = int(origin.stdout.readline())
            url = f"https://localhost:{port}/echo?q=1"
            for client_version in ['--http1.1', '--http2']:
                for method, body in [('GET', None), ('HEAD', None), ('POST', b''), ('POST', LARGE)]:
                    with self.subTest(client_version=client_version, method=method, size=len(body or b'')):
                        args = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '', client_version,
                            '--proxy', f'http://{self.proxy.proxy[0]}:{self.proxy.proxy[1]}',
                            '--cacert', str(self.proxy.data / 'ca.pem'), '--dump-header', '-']
                        args += ['--head'] if method == 'HEAD' else ['--request', method]
                        if body is not None:
                            args += ['--data-binary', '@-']
                        result = subprocess.run(args + [url], input=body, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        headers, _, payload = result.stdout.rpartition(b'\r\n\r\n')
                        self.assertIn(b'x-origin-http-version: 2', headers.lower())
                        self.assertIn(b'x-origin-host-present: false', headers.lower())
                        if method != 'HEAD':
                            echo = json.loads(payload)
                            self.assertEqual(echo['headers'][':authority'], f'localhost:{port}')
                            self.assertEqual(echo['headers'][':scheme'], 'https')
                            self.assertEqual(echo['headers'][':path'], '/echo?q=1')
                            self.assertEqual(echo['headers'][':method'], method)
                            self.assertEqual(base64.b64decode(echo['body']), body or b'')
            composed = {'method': 'POST', 'url': url, 'body': 'aGVsbG8=',
                        'trailers': [['x-upload', 'present']]}
            self.assertEqual(self.proxy.api('compose', composed)[1], {'completed': 1, 'errors': []})
            flow = self.latest()
            self.assertEqual(flow['metadata']['upstream_protocol'], 'HTTP/2.0')
            self.assertEqual(self.proxy.api(f"flows/{flow['id']}/replay", {})[1], {'completed': 1, 'errors': []})
            echo = json.loads(base64.b64decode(self.latest()['response']['body']['data']))
            self.assertEqual(echo['trailers'], {'x-upload': 'present'})
            self.assertEqual(base64.b64decode(echo['body']), b'hello')
        finally:
            origin.terminate()
            origin.communicate(timeout=5)

    def test_upstream_verification_cannot_be_bypassed(self):
        other = ProxyProcess(self.dir / "untrusted-data").start()
        try:
            code, _, payload = other.request(self.https + "/echo", tls=True)
            self.assertEqual(code, 502)
            self.assertIn(b"certificate", payload.lower())
        finally:
            other.stop()

    def test_large_stream_preserved_but_capture_bounded(self):
        self.settings["capture_bytes"] = 32
        self.assertEqual(self.proxy.api("settings", self.settings)[0], 200)
        self.assertEqual(self.proxy.request(self.http + "/large")[2], LARGE)
        flow = self.latest()
        self.assertEqual(flow["response"]["body"]["size"], len(LARGE))
        self.assertEqual(len(base64.b64decode(flow["response"]["body"]["data"])), 32)
        self.assertTrue(flow["response"]["body"]["truncated"])
        self.proxy.request(self.http + "/echo", "POST", LARGE)
        flow = self.latest()
        self.assertEqual(flow["request"]["body"]["size"], len(LARGE))
        self.assertTrue(flow["request"]["body"]["truncated"])
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}/replay", {})[0], 400)

    def test_record_pause_and_cache_cookie_controls(self):
        self.settings.update(recording=False, no_cache=True, block_cookies=True)
        self.proxy.api("settings", self.settings)
        code, hs, payload = self.proxy.request(self.http + "/echo", headers={"Cookie": "secret=1", "If-None-Match": "value"})
        self.assertEqual(code, 200)
        headers = {k.lower(): v for k, v in json.loads(payload)["headers"]}
        self.assertNotIn("cookie", headers)
        self.assertNotIn("if-none-match", headers)
        self.assertNotIn("set-cookie", dict((k.lower(), v) for k, v in hs))
        self.assertEqual(self.proxy.api("flows")[1], [])

    def test_lower_capture_limit_applies_to_active_snapshots(self):
        first, second = b"data: first\n\n", b"data: second\n\n"
        for limit in (4, 0):
            with self.subTest(limit=limit):
                Origin.stream_release.clear()
                self.settings['capture_bytes'] = 65536
                self.proxy.api('settings', self.settings)
                conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
                try:
                    conn.request('GET', self.http + '/held-stream')
                    response = conn.getresponse()
                    self.assertEqual(response.read(len(first)), first)
                    self.settings['capture_bytes'] = limit
                    self.assertEqual(self.proxy.api('settings', self.settings)[0], 200)
                    Origin.stream_release.set()
                    self.assertEqual(response.read(), second)
                    flow = self.latest()
                    for message in (flow['response'], flow['metadata']['original_response']):
                        self.assertEqual(base64.b64decode(message['body']['data']), first[:limit])
                        self.assertEqual(message['body']['size'], len(first + second))
                        self.assertTrue(message['body']['complete'])
                        self.assertTrue(message['body']['truncated'])
                finally:
                    Origin.stream_release.set()
                    conn.close()

    def test_composer_repeat_and_replay(self):
        data = {"url": self.http + "/echo", "method": "POST", "headers": [["X-Compose", "ok"]],
                "body": base64.b64encode(b"edited").decode(), "repeat": 6, "concurrency": 3}
        code, result = self.proxy.api("compose", data)
        self.assertEqual(code, 200)
        self.assertEqual(result, {"completed": 6, "errors": []})
        self.assertEqual(len(self.proxy.api("flows")[1]), 6)
        flow = self.latest()
        self.assertEqual(base64.b64decode(flow["request"]["body"]["data"]), b"edited")
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}/replay", {})[1]["completed"], 1)

    def test_replay_and_composer_preserve_request_trailers(self):
        trailers = [['x-upload', 'first'], ['x-upload', 'second']]
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
        try:
            conn.putrequest('POST', self.http + '/echo')
            conn.putheader('Transfer-Encoding', 'chunked')
            conn.putheader('Trailer', 'X-Upload')
            conn.endheaders()
            conn.send(b'9\r\nuploaded!\r\n0\r\nX-Upload: first\r\nX-Upload: second\r\n\r\n')
            response = conn.getresponse()
            self.assertEqual(json.loads(response.read())['trailers'], trailers)
        finally:
            conn.close()
        flow = self.latest()
        self.assertTrue(flow['metadata']['original_request']['body']['complete'])
        self.assertEqual(flow['metadata']['original_request']['trailers'], trailers)
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}/replay", {})[1], {'completed': 1, 'errors': []})
        replay = self.latest()
        echo = json.loads(base64.b64decode(replay['response']['body']['data']))
        self.assertEqual(echo['trailers'], trailers)
        self.assertEqual(base64.b64decode(echo['body']), b'uploaded!')
        composed = {'method': 'POST', 'url': self.http + '/echo',
                    'body': base64.b64encode(b'composed').decode(), 'trailers': trailers,
                    'headers': [['Content-Length', '999'], ['Trailer', 'Wrong']]}
        self.assertEqual(self.proxy.api('compose', composed)[1], {'completed': 1, 'errors': []})
        echo = json.loads(base64.b64decode(self.latest()['response']['body']['data']))
        self.assertEqual(echo['trailers'], trailers)
        self.assertEqual(base64.b64decode(echo['body']), b'composed')
        for invalid in ([['Content-Length', '9']], [['Authorization', 'secret']],
                        [['X-Upload', 'a\r\nb']], [['X-Upload', 'value']] * 257,
                        [['X-Upload', 'x' * 65536]]):
            self.assertEqual(self.proxy.api('compose', {**composed, 'trailers': invalid})[0], 400)

    def test_gzip_rewrite_preserves_all_members_and_decoded_limit(self):
        self.set_rules([{'type': 'replace_request_body', 'find': 'old', 'replace': 'new'},
                        {'type': 'replace_response_body', 'find': 'old', 'replace': 'new'}])
        body = gzip.compress(b'first old ') + gzip.compress(b'second old')
        code, _, response = self.proxy.request(self.http + '/gzip-members', 'POST', body,
                                               {'Content-Encoding': 'gzip'})
        self.assertEqual(code, 200)
        self.assertEqual(gzip.decompress(response), b'first new second new')
        self.assertEqual(gzip.decompress(Origin.received[-1][2]), b'first new second new')
        oversized = gzip.compress(b'first old ') + gzip.compress(b'x' * 1024 * 1024)
        code, _, error = self.proxy.request(self.http + '/echo', 'POST', oversized,
                                            {'Content-Encoding': 'gzip'})
        self.assertEqual(code, 502)
        self.assertIn(b'decoded body exceeds', error)

    def test_replay_does_not_double_apply_body_rewrites(self):
        self.set_rules([{"type": "replace_request_body", "find": "a", "replace": "aa"}])
        self.proxy.request(self.http + "/replay-rewrite", "POST", b"a")
        flow = self.latest()
        self.assertEqual(base64.b64decode(flow['request']['body']['data']), b'aa')
        code, result = self.proxy.api(f"flows/{flow['id']}/replay", {})
        self.assertEqual(code, 200)
        self.assertEqual(result['completed'], 1)
        self.assertEqual(base64.b64decode(self.latest()['request']['body']['data']), b'aa')
        input = {"method": "POST", "url": self.http + "/skip-rules", "body": "YQ==", "apply_rules": False}
        self.assertEqual(self.proxy.api('compose', input)[1]['completed'], 1)
        self.assertEqual(base64.b64decode(self.latest()['request']['body']['data']), b'a')
        # Without an original snapshot, send the forwarded method, URL, and body.
        legacy = dict(flow)
        legacy['metadata'] = {**flow['metadata'], 'original_request': None}
        self.assertEqual(self.proxy.api('session', {'version': 1, 'flows': [legacy]})[0], 204)
        imported = self.latest()
        self.assertEqual(self.proxy.api(f"flows/{imported['id']}/replay", {})[1]['completed'], 1)
        self.assertEqual(base64.b64decode(self.latest()['request']['body']['data']), b'aa')

    def test_control_security_and_public_ca(self):
        self.assertEqual(self.proxy.api("status", auth=False)[0], 401)
        self.assertEqual(self.proxy.api("status", extra={"Host": "attacker.test"})[0], 403)
        self.assertEqual(self.proxy.api("status", extra={"Origin": "http://attacker.test"})[0], 403)
        code, _, body = self.proxy.request("http://openproxy.local/ca.cer")
        self.assertEqual(code, 200)
        self.assertEqual(body, (self.proxy.data / "ca.cer").read_bytes())
        self.assertEqual(self.proxy.request("http://openproxy.local/ca-identity.json")[0], 404)

    def test_session_and_har_binary_roundtrip(self):
        self.proxy.request(self.http + "/echo", "POST", b"\x00\xffsession")
        flow = self.latest()
        session = self.proxy.api("session")[1]
        har = self.proxy.api("har")[1]
        self.assertEqual(base64.b64decode(har["log"]["entries"][0]["request"]["postData"]["text"]), b"\x00\xffsession")
        self.assertEqual(self.proxy.api("session", session)[0], 204)
        restored = self.proxy.api("flows")[1][0]
        self.assertNotEqual(restored["id"], flow["id"])
        self.assertEqual(self.proxy.api(f"flows/{restored['id']}")[1]["request"]["body"], flow["request"]["body"])

    def test_throttling_and_latency(self):
        self.settings.update(latency_ms=100, download_bytes_per_second=1024)
        self.proxy.api("settings", self.settings)
        started = time.monotonic()
        code, _, payload = self.proxy.request(self.http + "/echo")
        self.assertEqual(code, 200)
        self.assertGreaterEqual(time.monotonic() - started, 0.1 + len(payload) / 1024 - 0.04)

    def test_sse_is_streamed_and_gzip_is_preserved(self):
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
        started = time.monotonic()
        conn.request("GET", self.http + "/stream")
        response = conn.getresponse()
        self.assertEqual(response.readline(), b"data: first\n")
        self.assertLess(time.monotonic() - started, 0.15)
        self.assertIn(b"second", response.read())
        conn.close()
        self.assertEqual(json.loads(gzip.decompress(self.proxy.request(self.http + "/gzip")[2]))["path"], "/gzip")

    def test_bypass_tunnel_preserves_server_certificate(self):
        self.settings["bypass_hosts"] = ["localhost"]
        self.proxy.api("settings", self.settings)
        context = ssl.create_default_context(cafile=str(self.dir / "origin-root.pem"))
        self.assertEqual(self.proxy.request(self.https + "/echo", tls=True, context=context)[0], 200)
        self.assertEqual(self.latest()["method"], "CONNECT")

    def test_persistence_and_single_instance_lock(self):
        self.proxy.request(self.http + "/echo")
        self.latest()
        ca = (self.proxy.data / "ca.pem").read_bytes()
        second = subprocess.run([str(BINARY), "--listen", "127.0.0.1:0", "--ui", "127.0.0.1:0", "--data-dir", str(self.proxy.data)], capture_output=True, timeout=5)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(b"another OpenProxy", second.stderr)
        self.proxy.stop(signal.SIGTERM)
        self.proxy.start()
        self.assertEqual((self.proxy.data / "ca.pem").read_bytes(), ca)
        self.assertEqual(len(self.proxy.api("flows")[1]), 1)

    def set_rules(self, actions, pattern=None):
        self.settings["rules"] = [{"name": "Fixture", "enabled": True, "url": pattern or self.http + "/*", "actions": actions}]
        code, payload = self.proxy.api("settings", self.settings)
        self.assertEqual(code, 200, payload)

    def pending(self, phase=None, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            entries = self.proxy.api("breakpoints")[1]
            if entries and (phase is None or entries[0]["phase"] == phase):
                return self.proxy.api("breakpoints/" + entries[0]["id"])[1]
            time.sleep(0.02)
        self.fail("breakpoint did not become pending")

    def test_request_breakpoint_edits_before_origin_and_rejects_bad_input(self):
        self.set_rules([{"type": "breakpoint", "phase": "request"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.proxy.request, self.http + "/before", "POST", b"original")
            pending = self.pending("request")
            self.assertTrue(pending["body_complete"])
            self.assertEqual(base64.b64decode(pending["body"]), b"original")
            self.assertFalse(future.done())
            with Origin.received_lock:
                self.assertEqual(Origin.received, [])
            edit = {"action": "edit", "method": "POST", "url": self.http + "/after", "headers": [["Content-Length", "999"], ["X-Edited", "yes"]], "body": base64.b64encode(b"edited").decode()}
            invalid = {**edit, "method": "CONNECT"}
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], invalid)[0], 400)
            self.assertEqual(len(self.proxy.api("breakpoints")[1]), 1)
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], edit)[0], 204)
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], edit)[0], 404)
            code, _, payload = future.result(timeout=3)
            self.assertEqual(code, 200, payload)
            echo = json.loads(payload)
            self.assertEqual(echo["path"], "/after")
            self.assertEqual(base64.b64decode(echo["body"]), b"edited")
            self.assertEqual(dict((k.lower(), v) for k, v in echo["headers"])["content-length"], "6")
            flow = self.latest()
            self.assertEqual(base64.b64decode(flow["request"]["body"]["data"]), b"edited")
            self.assertEqual(flow["request"]["body"]["size"], 6)

    def test_response_breakpoint_and_decoded_gzip_edit(self):
        self.set_rules([{"type": "breakpoint", "phase": "response"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.proxy.request, self.http + "/gzip")
            pending = self.pending("response")
            self.assertEqual(pending["status"], 200)
            self.assertFalse(future.done())
            self.assertTrue(Origin.received)
            edit = {"action": "edit", "status": 201, "headers": [["Content-Encoding", "gzip"], ["Content-Type", "text/plain"], ["Set-Cookie", "one=1"], ["Set-Cookie", "two=2"]],
                    "body": base64.b64encode(b"new decoded response").decode(), "decoded": True}
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], edit)[0], 204)
            code, hs, payload = future.result(timeout=3)
            self.assertEqual(code, 201)
            self.assertEqual(gzip.decompress(payload), b"new decoded response")
            self.assertEqual(len([h for h in hs if h[0].lower() == "set-cookie"]), 2)
            flow = self.latest()
            self.assertEqual(flow["response"]["body"]["size"], len(payload))
            self.assertEqual(base64.b64decode(flow["response"]["body"]["data"]), payload)

    def test_breakpoint_continue_abort_timeout_and_unrecorded_capture(self):
        self.set_rules([{"type": "breakpoint", "phase": "request", "timeout_ms": 1500}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.proxy.request, self.http + "/continue", "POST", b"unchanged")
            paused = self.pending()
            self.assertEqual(self.proxy.api("breakpoints/" + paused["id"], {"action": "continue"})[0], 204)
            self.assertEqual(base64.b64decode(json.loads(future.result(timeout=3)[2])["body"]), b"unchanged")
            self.assertTrue(self.latest()["request"]["body"]["complete"])
            future = executor.submit(self.proxy.request, self.http + "/aborted")
            paused = self.pending()
            self.proxy.api("breakpoints/" + paused["id"], {"action": "abort"})
            self.assertEqual(future.result(timeout=3)[0], 502)
            with Origin.received_lock:
                self.assertFalse(any(path == "/aborted" for _, path, _ in Origin.received))
            self.settings["recording"] = False
            self.proxy.api("settings", self.settings)
            future = executor.submit(self.proxy.request, self.http + "/unrecorded")
            paused = self.pending()
            self.assertIsNone(paused["flow_id"])
            self.proxy.api("breakpoints/" + paused["id"], {"action": "continue"})
            self.assertEqual(future.result(timeout=3)[0], 200)
        self.set_rules([{"type": "breakpoint", "phase": "request", "timeout_ms": 100}])
        code, _, payload = self.proxy.request(self.http + "/timeout")
        self.assertEqual(code, 502)
        self.assertIn(b"timed out", payload)
        self.assertEqual(self.proxy.api("breakpoints")[1], [])

    def test_request_breakpoint_head_method_changes_preserve_client_framing(self):
        self.set_rules([{"type": "breakpoint", "phase": "request"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for original, edited in [("HEAD", "GET"), ("GET", "HEAD")]:
                with self.subTest(original=original, edited=edited):
                    future = executor.submit(self.proxy.request, self.http + "/head-change", original)
                    paused = self.pending()
                    decision = {"action": "edit", "method": edited, "url": paused["url"], "headers": paused["headers"]}
                    self.assertEqual(self.proxy.api("breakpoints/" + paused["id"], decision)[0], 204)
                    code, headers, body = future.result(timeout=3)
                    self.assertEqual(code, 200)
                    self.assertEqual(body, b"")
                    if original == "GET":
                        self.assertEqual(dict((k.lower(), v) for k, v in headers)["content-length"], "0")
                    self.assertEqual(self.latest()["metadata"]["upstream_method"], edited)
                    self.assertEqual(self.latest()["method"], original)

    def test_http2_reset_cleans_only_its_breakpoint_stream(self):
        self.set_rules([{"type": "breakpoint", "phase": "request", "timeout_ms": 5000}], self.https + "/*")
        process = subprocess.Popen(['node', str(ROOT / 'tests/http2-reset.mjs'),
            str(self.proxy.proxy[1]), str(self.tls_origin.server_port), str(self.proxy.data / 'ca.pem')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'streams ready')
            deadline = time.monotonic() + 2
            while len(self.proxy.api('breakpoints')[1]) != 2 and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertEqual(len(self.proxy.api('breakpoints')[1]), 2)
            process.stdin.write('cancel\n')
            process.stdin.flush()
            while len(self.proxy.api('breakpoints')[1]) != 1 and time.monotonic() < deadline:
                time.sleep(.02)
            queued = self.proxy.api('breakpoints')[1]
            self.assertEqual(len(queued), 1)
            self.assertIn('/h2-survivor', queued[0]['url'])
            self.assertEqual(self.proxy.api('breakpoints/' + queued[0]['id'], {'action': 'continue'})[0], 204)
            output, error = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, error)
            self.assertIn('survivor passed', output)
            with Origin.received_lock:
                self.assertFalse(any(path == '/h2-cancel' for _, path, _ in Origin.received))
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)

    def test_concurrent_breakpoint_queue_limit_and_decisions(self):
        self.set_rules([{"type": "breakpoint", "phase": "request", "timeout_ms": 6000}])
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            requests = [executor.submit(self.proxy.request, self.http + f'/concurrent/{i}', 'POST', str(i).encode()) for i in range(40)]
            deadline = time.monotonic() + 3
            queued = []
            while time.monotonic() < deadline:
                queued = self.proxy.api('breakpoints')[1]
                # Reject overflow requests before any queue slot becomes available.
                if len(queued) == 32 and sum(future.done() for future in requests) == 8:
                    break
                time.sleep(.02)
            self.assertEqual(len(queued), 32)
            self.assertEqual(sum(future.done() for future in requests), 8)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as decisions:
                results = list(decisions.map(lambda item: self.proxy.api('breakpoints/' + item['id'], {'action': 'continue'})[0], queued))
            self.assertEqual(results, [204] * 32)
            codes = [future.result(timeout=3)[0] for future in requests]
            self.assertEqual(codes.count(200), 32)
            self.assertEqual(codes.count(502), 8)
            self.assertEqual(self.proxy.api('breakpoints')[1], [])
            with Origin.received_lock:
                paths = [path for _, path, _ in Origin.received if path.startswith('/concurrent/')]
            self.assertEqual(len(paths), 32)
            self.assertEqual(len(set(paths)), 32)

    def test_large_breakpoint_header_edit_preserves_all_bytes(self):
        self.set_rules([{"type": "breakpoint", "phase": "response"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.proxy.request, self.http + "/huge")
            pending = self.pending("response")
            self.assertFalse(pending["body_complete"])
            self.assertLessEqual(len(base64.b64decode(pending["body"])), 1024 * 1024)
            bad = {"action": "edit", "status": 200, "headers": pending["headers"], "body": "ZWRpdGVk"}
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], bad)[0], 400)
            edit = {"action": "edit", "status": 200, "headers": pending["headers"] + [["X-Paused", "yes"]]}
            self.assertEqual(self.proxy.api("breakpoints/" + pending["id"], edit)[0], 204)
            code, hs, payload = future.result(timeout=5)
            self.assertEqual(code, 200)
            self.assertEqual(payload, LARGE * 8)
            self.assertIn(("x-paused", "yes"), [(k.lower(), v) for k, v in hs])
            flow = self.latest()
            self.assertEqual(flow["phase"], "complete")
            self.assertTrue(flow["response"]["body"]["complete"])

    def test_streaming_response_breakpoint_does_not_wait_for_end(self):
        self.set_rules([{"type": "breakpoint", "phase": "response"}])
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
        conn.request("GET", self.http + "/held-stream")
        pending = self.pending("response")
        self.assertFalse(pending["body_complete"])
        self.assertIn(b"first", base64.b64decode(pending["body"]))
        self.proxy.api("breakpoints/" + pending["id"], {"action": "continue"})
        try:
            res = conn.getresponse()
            self.assertEqual(res.readline(), b"data: first\n")
        finally:
            Origin.stream_release.set()
            res.read()
            conn.close()

    def test_breakpoint_client_reset_cleans_up_before_deadline(self):
        self.set_rules([{"type": "breakpoint", "phase": "request", "timeout_ms": 10_000}])
        conn = socket.create_connection(self.proxy.proxy, timeout=3)
        conn.sendall(f"GET {self.http}/client-reset HTTP/1.1\r\nHost: fixture\r\n\r\n".encode())
        pending = self.pending()
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.close()
        deadline = time.monotonic() + 1
        while self.proxy.api("breakpoints")[1] and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.proxy.api("breakpoints")[1], [])
        self.assertEqual(self.proxy.api("breakpoints/" + pending["id"])[0], 404)
        flow = self.latest()
        self.assertEqual(flow['phase'], 'error')
        self.assertIn('cancelled', flow['error'])

    def test_breakpoint_shutdown_aborts_waiting_exchange(self):
        self.set_rules([{"type": "breakpoint", "phase": "request"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.proxy.request, self.http + "/shutdown")
            self.pending()
            self.proxy.stop(signal.SIGTERM)
            try:
                future.result(timeout=3)
            except (OSError, http.client.HTTPException):
                pass
            self.proxy.start()
            self.assertEqual(self.proxy.api("breakpoints")[1], [])
            self.assertIn("shutting down", self.latest()["error"])

    def test_breakpoint_request_and_response_trailers_survive_edits(self):
        self.set_rules([{"type": "breakpoint", "phase": "request"}])
        def upload():
            conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
            try:
                conn.putrequest("POST", self.http + "/echo")
                conn.putheader("Transfer-Encoding", "chunked")
                conn.putheader("Trailer", "X-Upload")
                conn.endheaders()
                conn.send(b"9\r\nuploaded!\r\n0\r\nX-Upload: present\r\n\r\n")
                res = conn.getresponse()
                return res.status, json.loads(res.read())
            finally:
                conn.close()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(upload)
            pending = self.pending('request')
            self.assertTrue(pending['body_complete'])
            self.assertEqual(pending['trailers'], [['x-upload', 'present']])
            edit = {"action": "edit", "method": "POST", "url": self.http + "/echo", "headers": pending['headers'] + [['X-Edit', 'yes']]}
            self.assertEqual(self.proxy.api('breakpoints/' + pending['id'], edit)[0], 204)
            code, echo = held.result(timeout=3)
            self.assertEqual(code, 200)
            self.assertEqual(base64.b64decode(echo['body']), b'uploaded!')
            self.assertEqual(echo['trailers'], [['x-upload', 'present']])
        self.set_rules([{"type": "breakpoint", "phase": "response"}])
        def receive():
            conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
            try:
                conn.request('GET', self.http + '/trailers', headers={'TE': 'trailers'})
                res = conn.getresponse()
                self.assertTrue(res.chunked)
                body, trailers = bytearray(), []
                while True:
                    size = int(res.fp.readline().split(b';', 1)[0], 16)
                    if not size:
                        while True:
                            line = res.fp.readline()
                            if line == b'\r\n': break
                            self.assertTrue(line)
                            name, value = line.decode().split(':', 1)
                            trailers.append([name.lower(), value.strip()])
                        break
                    body.extend(res.fp.read(size))
                    self.assertEqual(res.fp.read(2), b'\r\n')
                res.close()
                return bytes(body), trailers
            finally:
                conn.close()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(receive)
            pending = self.pending('response')
            self.assertTrue(pending['body_complete'])
            self.assertEqual(pending['trailers'][0][0], 'x-check')
            edit = {"action": "edit", "status": 200, "headers": pending['headers'], "body": base64.b64encode(b'changed').decode()}
            self.assertEqual(self.proxy.api('breakpoints/' + pending['id'], edit)[0], 204)
            body, trailers = held.result(timeout=3)
            self.assertEqual(body, b'changed')
            self.assertEqual(trailers, [['x-check', 'done']])
            self.assertEqual(self.latest()['response']['trailers'], trailers)

    def test_breakpoint_head_and_no_content_framing(self):
        self.set_rules([{"type": "breakpoint", "phase": "response"}])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(self.proxy.request, self.http + '/echo', 'HEAD')
            pending = self.pending('response')
            edit = {"action": "edit", "status": 200, "headers": pending['headers'] + [['X-Edited', 'yes']]}
            self.assertEqual(self.proxy.api('breakpoints/' + pending['id'], {**edit, 'body': 'bm9uZW1wdHk='})[0], 400)
            self.assertEqual(self.proxy.api('breakpoints/' + pending['id'], edit)[0], 204)
            code, headers, body = held.result(timeout=3)
            self.assertEqual(code, 200)
            self.assertEqual(dict((k.lower(), v) for k, v in headers)['content-length'], '999')
            self.assertEqual(body, b'')
        self.set_rules([{"type": "set_status", "status": 205}])
        code, headers, body = self.proxy.request(self.http + '/echo')
        self.assertEqual(code, 205)
        self.assertEqual(dict((k.lower(), v) for k, v in headers)['content-length'], '0')
        self.assertEqual(body, b'')

    def test_rule_headers_query_and_body_framing(self):
        self.set_rules([
            {"type": "set_request_header", "name": "X-Rule", "value": "first"},
            {"type": "set_request_header", "name": "X-Rule", "value": "second"},
            {"type": "set_query", "name": "q", "value": "two words"},
            {"type": "replace_request_body", "find": "raw", "replace": "edited"},
            {"type": "set_response_header", "name": "X-Response", "value": "changed"},
            {"type": "replace_response_body", "find": "/echo", "replace": "/rewritten"},
        ])
        code, hs, payload = self.proxy.request(self.http + "/echo?q=one", "POST", b'{"value":"raw"}')
        self.assertEqual(code, 200, payload)
        echo = json.loads(payload)
        self.assertEqual(echo["path"], "/rewritten?q=two+words")
        self.assertEqual(base64.b64decode(echo["body"]), b'{"value":"edited"}')
        self.assertEqual(dict((k.lower(), v) for k, v in echo["headers"])["x-rule"], "second")
        self.assertEqual(dict((k.lower(), v) for k, v in hs)["content-length"], str(len(payload)))
        flow = self.latest()
        self.assertEqual(flow["url"], self.http + "/echo?q=one")
        self.assertEqual(flow["upstream_url"], self.http + "/echo?q=two+words")
        original = flow['metadata']['original_request']
        self.assertEqual(base64.b64decode(original['body']['data']), b'{"value":"raw"}')
        self.assertTrue(original['body']['complete'])
        self.assertNotIn('x-rule', dict(original['headers']))
        self.assertIn(b'/echo', base64.b64decode(flow['metadata']['original_response']['body']['data']))
        self.assertNotIn(b'/rewritten', base64.b64decode(flow['metadata']['original_response']['body']['data']))
        traces = flow['metadata']['actions']
        self.assertEqual([trace['phase'] for trace in traces], ['request'] * 4 + ['response'] * 2)
        self.assertTrue(all(trace['applied'] and trace['changed'] for trace in traces))
        self.assertEqual([trace['index'] for trace in traces], list(range(6)))

    def test_rule_validation_does_not_change_settings_and_traces_noops(self):
        before = self.proxy.api('status')[1]['settings']
        candidate = {**before, 'rules': [{'name': 'readonly', 'url': '*', 'actions': [{'type': 'set_query', 'name': 'q', 'value': None}]}]}
        code, normalized = self.proxy.api('settings/validate', candidate)
        self.assertEqual(code, 200)
        self.assertTrue(normalized['rules'][0]['enabled'])
        self.assertEqual(self.proxy.api('status')[1]['settings'], before)
        self.set_rules([{'type': 'remove_request_header', 'name': 'X-Missing'}, {'type': 'remove_response_header', 'name': 'X-Missing'}])
        self.proxy.request(self.http + '/noop')
        self.assertTrue(all(trace['applied'] and trace['changed'] is False for trace in self.latest()['metadata']['actions']))

    def test_annotations_and_original_snapshots_roundtrip(self):
        self.proxy.request(self.http + '/annotated', 'POST', b'original')
        flow = self.latest()
        annotation = {'note': 'Compare with the previous release', 'marked': True}
        code, updated = self.proxy.api(f"flows/{flow['id']}", annotation, method='PATCH')
        self.assertEqual(code, 200)
        self.assertEqual(updated['metadata']['note'], annotation['note'])
        self.assertTrue(updated['metadata']['marked'])
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}", {'note': 'x' * 8193}, method='PATCH')[0], 400)
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}", {'marked': 'yes'}, method='PATCH')[0], 422)
        self.assertEqual(self.proxy.api(f"flows/{flow['id']}", annotation, method='PATCH', auth=False)[0], 401)
        session = self.proxy.api('session')[1]
        self.assertEqual(self.proxy.api('session', session)[0], 204)
        restored = self.latest()
        self.assertEqual(restored['metadata'], updated['metadata'])
        har = self.proxy.api('har')[1]
        self.assertEqual(self.proxy.api('session', har)[0], 204)
        self.assertEqual(self.latest()['metadata'], updated['metadata'])

    def test_exchange_and_session_comparison_are_readonly(self):
        self.proxy.request(self.http + '/compare', 'POST', b'first')
        first = self.latest()
        self.proxy.request(self.http + '/compare', 'POST', b'second')
        second = self.latest()
        code, comparison = self.proxy.api(f"flows/{first['id']}/compare?other={second['id']}")
        self.assertEqual(code, 200)
        self.assertEqual(comparison['difference']['result'], 'changed')
        self.assertIn('request body', comparison['difference']['fields'])
        saved = self.proxy.api('session')[1]
        code, rows = self.proxy.api('session/compare', saved)
        self.assertEqual(code, 200)
        self.assertTrue(all(row['result'] == 'equal' for row in rows))
        saved['flows'][0]['response']['body']['complete'] = False
        self.assertEqual(self.proxy.api('session/compare', saved)[1][0]['result'], 'unknown')
        self.assertEqual(len(self.proxy.api('flows')[1]), 2)

    def test_dns_override_preserves_host_tls_checks_and_invalidates_pool(self):
        self.settings['dns_overrides'] = {'mapped.invalid': '127.0.0.1'}
        self.assertEqual(self.proxy.api('settings', self.settings)[0], 200)
        url = f'http://mapped.invalid:{self.origin.server_port}/echo'
        code, _, payload = self.proxy.request(url)
        self.assertEqual(code, 200)
        self.assertEqual(dict((name.lower(), value) for name, value in json.loads(payload)['headers'])['host'], f'mapped.invalid:{self.origin.server_port}')
        code, _, payload = self.proxy.request(f'https://mapped.invalid:{self.tls_origin.server_port}/echo', tls=True)
        self.assertEqual(code, 502)
        self.assertIn(b'certificate', payload.lower())
        self.settings['dns_overrides']['mapped.invalid'] = '127.0.0.2'
        self.assertEqual(self.proxy.api('settings', self.settings)[0], 200)
        self.assertEqual(self.proxy.request(url)[0], 502)

    def test_mirrors_full_bodies_with_bounded_capture_and_failure_reporting(self):
        directory=self.dir/'mirrors'
        self.settings['capture_bytes']=16
        self.set_rules([{'type':'mirror','directory':str(directory),'max_bytes':len(LARGE)+4096}])
        code,_,payload=self.proxy.request(self.http+'/echo','POST',LARGE)
        self.assertEqual(code,200)
        flow=self.latest()
        mirrors={item['phase']:item for item in flow['metadata']['mirrors']}
        self.assertTrue(mirrors['request']['complete'])
        self.assertEqual(Path(mirrors['request']['path']).read_bytes(),LARGE)
        self.assertEqual(Path(mirrors['request']['path']).stat().st_mode&0o777,0o600)
        self.assertEqual(Path(mirrors['response']['path']).read_bytes(),payload[:len(LARGE)+4096])
        self.assertIsNotNone(mirrors['response']['error'])
        self.assertTrue(flow['request']['body']['truncated'])
        self.set_rules([{'type':'mirror','directory':str(directory),'max_bytes':1024*1024}])
        self.proxy.request(self.http+'/echo')
        self.assertTrue(all(item['complete'] for item in self.latest()['metadata']['mirrors']))
        before=len(list(directory.iterdir()))
        self.settings['recording']=False
        self.assertEqual(self.proxy.api('settings',self.settings)[0],200)
        self.assertEqual(self.proxy.request(self.http+'/echo')[0],200)
        self.assertEqual(len(list(directory.iterdir())),before)

    def test_gzip_rewrite_regex_and_rule_validation(self):
        self.set_rules([{"type": "replace_response_body", "find": "g(ip|zip)", "replace": "changed-$1", "regex": True}])
        code, hs, payload = self.proxy.request(self.http + "/gzip")
        self.assertEqual(code, 200, payload)
        self.assertEqual(json.loads(gzip.decompress(payload))["path"], "/changed-zip")
        response_headers = dict((name.lower(), value) for name, value in hs)
        self.assertNotIn('etag', response_headers)
        self.assertEqual(response_headers['content-length'], str(len(payload)))
        self.settings["rules"][0]["actions"] = [{"type": "set_request_header", "name": "Content-Length", "value": "99"}]
        self.assertEqual(self.proxy.api("settings", self.settings)[0], 400)
        self.settings["rules"][0]["actions"] = [{"type": "set_response_header", "name": "X-Test", "value": "bad\r\nheader"}]
        self.assertEqual(self.proxy.api("settings", self.settings)[0], 400)

    def test_mapping_mock_block_and_head(self):
        self.set_rules([{"type": "map_remote", "from": self.http + "/old", "to": self.http + "/echo"}])
        self.assertEqual(json.loads(self.proxy.request(self.http + "/old?q=1")[2])["path"], "/echo?q=1")
        self.set_rules([{"type": "mock", "status": 201, "headers": [["Content-Type", "text/plain"]], "body": "mock response"}], "http://no-dns.invalid/*")
        self.assertEqual(self.proxy.request("http://no-dns.invalid/mock")[0::2], (201, b"mock response"))
        self.assertEqual(self.proxy.request("http://no-dns.invalid/mock", "HEAD")[2], b"")
        self.assertEqual(self.latest()["phase"], "complete")
        self.set_rules([{"type": "block", "message": "fixture block"}])
        self.assertEqual(self.proxy.request(self.http + "/echo")[0::2], (403, b"fixture block"))
        file = self.dir / "mapped.json"
        file.write_bytes(LARGE)
        self.set_rules([{"type": "map_local", "path": str(file)}])
        self.assertEqual(self.proxy.request(self.http + "/echo")[2], LARGE)

    def test_directory_mapping_confinement_and_rewrite_boundaries(self):
        root = self.dir / 'mapping-tree'
        root.mkdir(exist_ok=True)
        (root / 'space name.txt').write_text('mapped')
        (root / 'binary.bin').write_bytes(b'\x00\xff')
        outside = self.dir / 'outside-secret.txt'
        outside.write_text('must not be served')
        (root / 'outside-link').symlink_to(outside)
        self.set_rules([{'type': 'map_local', 'path': str(root), 'url_prefix': '/mapped/'}])
        self.assertEqual(self.proxy.request(self.http + '/mapped/space%20name.txt?q=1')[2], b'mapped')
        self.assertEqual(self.proxy.request(self.http + '/mapped/binary.bin')[2], b'\x00\xff')
        self.assertEqual(self.proxy.request(self.http + '/mapped/binary.bin', 'HEAD')[2], b'')
        for path in ['/mapped/%2e%2e/outside-secret.txt', '/mapped/%2F..%2Foutside-secret.txt', '/mapped/outside-link', '/mapped/%ff']:
            with self.subTest(path=path):
                code, _, body = self.proxy.request(self.http + path)
                self.assertEqual(code, 502)
                self.assertNotIn(b'must not be served', body)
        self.assertEqual(self.proxy.request(self.http + '/mapped/missing')[0], 200)
        self.set_rules([{'type': 'replace_request_body', 'find': 'a', 'replace': 'b'}])
        self.assertEqual(self.proxy.request(self.http + '/binary-edit', 'POST', b'\xff')[0], 502)
        self.set_rules([{'type': 'replace_response_body', 'find': 'a', 'replace': 'b'}])
        self.assertEqual(self.proxy.request(self.http + '/huge')[0], 502)
        self.assertEqual(self.proxy.request(self.http + '/echo', headers={'Accept-Encoding': 'br'})[0], 200)

    def test_har_import_and_safe_ids(self):
        self.proxy.request(self.http + "/echo", "POST", b"\x00\xffHAR")
        original = self.latest()
        har = self.proxy.api("har")[1]
        self.assertEqual(self.proxy.api("session", har)[0], 204)
        rows = self.proxy.api("flows")[1]
        restored = self.proxy.api(f"flows/{rows[0]['id']}")[1]
        self.assertNotEqual(restored["id"], original["id"])
        self.assertEqual(restored["request"]["body"]["data"], original["request"]["body"]["data"])


if __name__ == "__main__":
    if "--preview" in sys.argv:
        Acceptance.setUpClass()
        try:
            p = Acceptance.proxy
            for path in ["/api/orders?limit=25", "/api/profile", "/assets/manifest.json", "/gzip", "/redirect"]:
                p.request(Acceptance.http + path)
            p.request(Acceptance.https + "/api/orders", "POST", b'{"item":"Coffee","quantity":2}', {"Content-Type": "application/json"}, tls=True)
            metadata = {"url": f"http://{p.ui}/#{p.token}", "proxy": p.proxy, "origin": Acceptance.http}
            meta_path = ROOT / "test-artifacts/preview.json"
            meta_path.write_text(json.dumps(metadata))
            meta_path.chmod(0o600)
            print("Preview ready: test-artifacts/preview.json", flush=True)
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            Acceptance.tearDownClass()
            (ROOT / "test-artifacts/preview.json").unlink(missing_ok=True)
    else:
        unittest.main(verbosity=2)
