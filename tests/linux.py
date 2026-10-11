#!/usr/bin/env python3
"""Run Linux integration tests. Keep desktop settings in an isolated GSettings keyfile backend."""
import http.client
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

import integration


class Linux(unittest.TestCase):
    def test_optional_process_attribution_for_actual_local_client(self):
        with tempfile.TemporaryDirectory() as temp:
            origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), integration.Origin)
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            proxy = integration.ProxyProcess(Path(temp) / 'proxy').start()
            try:
                url = f'http://127.0.0.1:{origin.server_port}/client-process'
                self.assertEqual(proxy.request(url)[0], 200)
                first = proxy.api('flows')[1][0]
                self.assertIsNone(proxy.api(f"flows/{first['id']}")[1]['metadata']['process'])
                settings = proxy.api('status')[1]['settings']
                settings['process_attribution'] = True
                self.assertEqual(proxy.api('settings', settings)[0], 200)
                conn = http.client.HTTPConnection(*proxy.proxy, timeout=5)
                conn.request('GET', url)
                self.assertEqual(conn.getresponse().read()[:1], b'{')
                latest = proxy.api('flows')[1][0]
                process = proxy.api(f"flows/{latest['id']}")[1]['metadata']['process']
                self.assertEqual(process['pid'], os.getpid())
                self.assertTrue(process['name'])
                self.assertLessEqual(len(process['name']), 64)
                conn.close()
            finally:
                proxy.stop()
                origin.shutdown()
                origin.server_close()

    @unittest.skipUnless(shutil.which('gsettings'), 'gsettings is not installed')
    def test_system_proxy_backup_and_restore_with_isolated_gsettings(self):
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, GSETTINGS_BACKEND='keyfile', XDG_CONFIG_HOME=str(Path(temp) / 'config'))
            def setting(operation, schema, key, value=None):
                args = ['gsettings', operation, schema, key] + ([value] if value is not None else [])
                return subprocess.check_output(args, env=env, text=True).strip()
            def cli(action, *args):
                return subprocess.run([str(integration.BINARY), '--data-dir', str(Path(temp) / 'data'), 'system-proxy', action, *args], env=env, text=True, capture_output=True)
            root, http, https = 'org.gnome.system.proxy', 'org.gnome.system.proxy.http', 'org.gnome.system.proxy.https'
            try:
                setting('get', root, 'mode')
            except subprocess.CalledProcessError:
                self.skipTest('GNOME proxy schemas are not installed')
            setting('set', root, 'mode', "'auto'")
            setting('set', http, 'host', "'old-proxy'")
            setting('set', http, 'port', '3128')
            self.assertEqual(cli('enable', '--address', '127.0.0.1:8099').returncode, 0)
            self.assertEqual(setting('get', root, 'mode'), "'manual'")
            self.assertEqual(setting('get', http, 'host'), "'127.0.0.1'")
            self.assertEqual(setting('get', https, 'port'), '8099')
            backup = Path(temp) / 'data/system-proxy-backup.json'
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(cli('enable').returncode, 0)
            setting('set', https, 'port', '9999')
            restored = cli('restore')
            self.assertEqual(restored.returncode, 0, restored.stderr)
            self.assertIn('Kept later user change:', restored.stdout)
            self.assertEqual(setting('get', root, 'mode'), "'auto'")
            self.assertEqual(setting('get', http, 'host'), "'old-proxy'")
            self.assertEqual(setting('get', http, 'port'), '3128')
            self.assertEqual(setting('get', https, 'port'), '9999')
            self.assertFalse(backup.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
