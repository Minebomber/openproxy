#!/usr/bin/env python3
"""Run local network simulation tests. Add --long for a limited upload test longer than 120 seconds."""
import concurrent.futures
import http.client
import http.server
import json
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest

import integration

LONG = '--long' in sys.argv
if LONG:
    sys.argv.remove('--long')


class Origin(integration.Origin):
    attempts = []

    def do_GET(self):
        with self.received_lock:
            self.attempts.append(self.path)
        try:
            super().do_GET()
        except (BrokenPipeError, ConnectionResetError, ConnectionError):
            pass


class Echo(socketserver.BaseRequestHandler):
    accepted = 0
    lock = threading.Lock()
    def handle(self):
        with self.lock:
            type(self).accepted += 1
        try:
            while data := self.request.recv(8192):
                self.request.sendall(data)
            self.request.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Simulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (integration.ROOT / 'test-artifacts').mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=integration.ROOT / 'test-artifacts')
        cls.origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        cls.echo.daemon_threads = True
        for server in [cls.origin, cls.echo]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        host, port = cls.echo.server_address
        cls.proxy = integration.ProxyProcess(Path(cls.temp.name) / 'proxy', extras=['--forward', f'127.0.0.1:0={host}:{port}']).start()
        cls.url = f'http://127.0.0.1:{cls.origin.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        for server in [cls.origin, cls.echo]:
            server.shutdown()
            server.server_close()
        cls.temp.cleanup()

    def setUp(self):
        code, status = self.proxy.api('status')
        self.assertEqual(code, 200)
        self.settings = status['settings']
        self.settings.update(latency_ms=0, upload_bytes_per_second=0, download_bytes_per_second=0,
            aggregate_upload_bytes_per_second=0, aggregate_download_bytes_per_second=0,
            failure_percent=0, offline=False, drop_upload_after_bytes=None,
            drop_download_after_bytes=None, rules=[])
        self.configure()
        self.proxy.api('clear', {})
        with Origin.received_lock:
            Origin.attempts.clear()
            Origin.received.clear()

    def configure(self, **changes):
        self.settings.update(changes)
        self.assertEqual(self.proxy.api('settings', self.settings)[0], 200)

    def test_concurrent_aggregate_upload_and_download(self):
        self.configure(aggregate_upload_bytes_per_second=20000)
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda i: self.proxy.request(self.url + f'/upload-{i}', 'POST', b'u' * 20000), range(2)))
        self.assertGreaterEqual(time.monotonic() - started, 1.8)
        self.assertTrue(all(res[0] == 200 for res in results))
        self.configure(aggregate_upload_bytes_per_second=0, aggregate_download_bytes_per_second=262144)
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.proxy.request(self.url + '/large'), range(2)))
        self.assertGreaterEqual(time.monotonic() - started, 1.8)
        self.assertTrue(all(res[2] == integration.LARGE for res in results))

    def test_initial_latency_does_not_expire_upload_progress(self):
        self.configure(latency_ms=31000)
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=40)
        started = time.monotonic()
        conn.request('POST', self.url + '/delayed-upload', b'healthy upload')
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        payload = json.loads(response.read())
        conn.close()
        self.assertGreaterEqual(time.monotonic() - started, 30.9)
        self.assertEqual(integration.base64.b64decode(payload['body']), b'healthy upload')

    def test_offline_failure_and_exact_drops_have_no_duplicate_origin_effects(self):
        self.configure(offline=True)
        self.assertEqual(self.proxy.request(self.url + '/offline')[0], 503)
        self.configure(offline=False, failure_percent=100)
        self.assertEqual(self.proxy.request(self.url + '/failure')[0], 502)
        self.assertEqual(Origin.attempts, [])
        self.configure(failure_percent=0, upload_bytes_per_second=10000, drop_upload_after_bytes=1234)
        self.assertEqual(self.proxy.request(self.url + '/drop-upload', 'POST', b'x' * 12000)[0], 502)
        time.sleep(.1)
        self.assertEqual(Origin.attempts.count('/drop-upload'), 1)
        sizes = [len(body) for _, path, body in Origin.received if path == '/drop-upload']
        self.assertEqual(len(sizes), 1)
        self.assertTrue(0 < sizes[0] <= 1234, sizes)
        self.configure(upload_bytes_per_second=0, drop_upload_after_bytes=None, drop_download_after_bytes=1234)
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=5)
        conn.request('GET', self.url + '/large')
        res = conn.getresponse()
        with self.assertRaises(http.client.IncompleteRead) as error:
            res.read()
        self.assertEqual(error.exception.partial, integration.LARGE[:1234])
        conn.close()
        self.assertEqual(Origin.attempts.count('/large'), 1)
        flows = self.proxy.api('flows')[1]
        flow = self.proxy.api(f"flows/{flows[0]['id']}")[1]
        self.assertEqual(flow['phase'], 'error')

    def test_selective_rules_preserve_normal_requests_and_trailers(self):
        self.configure(rules=[{'name': 'selected', 'url': self.url + '/selected', 'actions': [
            {'type': 'throttle', 'upload': 1000, 'download': 0},
            {'type': 'failure', 'percent': 0}]}])
        started = time.monotonic()
        self.assertEqual(self.proxy.request(self.url + '/selected', 'POST', b'x' * 1000)[0], 200)
        self.assertGreaterEqual(time.monotonic() - started, .9)
        started = time.monotonic()
        self.assertEqual(self.proxy.request(self.url + '/unselected', 'POST', b'x' * 1000)[0], 200)
        self.assertLess(time.monotonic() - started, .5)
        self.configure(aggregate_download_bytes_per_second=10000, rules=[])
        code, _, payload = self.proxy.request(self.url + '/trailers', headers={'TE': 'trailers'})
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(payload)['trailers'] == [])

    def test_raw_tunnel_aggregate_budget_and_drop(self):
        self.configure(aggregate_upload_bytes_per_second=20000, aggregate_download_bytes_per_second=20000)
        def transfer(_):
            sock = socket.create_connection(self.proxy.listeners['TCP'][0], timeout=5)
            sock.sendall(b't' * 10000)
            sock.shutdown(socket.SHUT_WR)
            received = bytearray()
            while data := sock.recv(8192):
                received.extend(data)
            sock.close()
            return bytes(received)
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(transfer, range(2)))
        self.assertGreaterEqual(time.monotonic() - started, .9)
        self.assertEqual(results, [b't' * 10000, b't' * 10000])
        self.configure(aggregate_upload_bytes_per_second=0, aggregate_download_bytes_per_second=0, drop_download_after_bytes=100)
        sock = socket.create_connection(self.proxy.listeners['TCP'][0], timeout=5)
        sock.sendall(b't' * 1000)
        received = bytearray()
        try:
            while data := sock.recv(8192):
                received.extend(data)
        except ConnectionResetError:
            pass
        sock.close()
        self.assertEqual(received, b't' * 100)
        accepted = Echo.accepted
        for changes in [{'offline': True}, {'offline': False, 'failure_percent': 100}]:
            self.configure(**changes)
            sock = socket.create_connection(self.proxy.listeners['TCP'][0], timeout=5)
            try:
                self.assertEqual(sock.recv(1), b'')
            except ConnectionResetError:
                pass
            sock.close()
        self.assertEqual(Echo.accepted, accepted)

    @unittest.skipUnless(LONG, 'pass --long for the >120 second upload fixture')
    def test_upload_exceeding_old_120_second_deadline(self):
        self.configure(upload_bytes_per_second=100)
        conn = http.client.HTTPConnection(*self.proxy.proxy, timeout=145)
        started = time.monotonic()
        conn.request('POST', self.url + '/long-upload', b'L' * 12300)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        payload = json.loads(response.read())
        conn.close()
        self.assertGreaterEqual(time.monotonic() - started, 120)
        self.assertEqual(integration.base64.b64decode(payload['body']), b'L' * 12300)
        self.assertEqual(Origin.attempts.count('/long-upload'), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
