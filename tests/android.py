#!/usr/bin/env python3
"""Run Android API 36 acceptance tests on a disposable emulator. Do not use a physical device.

Install an Android SDK, default API 36 x86_64 image, JDK, and OpenSSL.
Build OpenProxy first. Run: python3 tests/android.py
"""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile

from integration import Acceptance, ROOT


def command(*args, **kwargs):
    result = subprocess.run(list(map(str, args)), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stdout} {result.stderr}")
    return result.stdout


def build_app(work, sdk, variant, ca):
    folder = work / variant
    resources = folder / 'res'
    (resources / 'xml').mkdir(parents=True)
    (resources / 'raw').mkdir()
    (resources / 'raw' / 'fixture_ca.pem').write_bytes(ca)
    debug = variant == 'debug'
    if variant in ('pinned', 'bypass'):
        anchors = '<trust-anchors><certificates src="@raw/fixture_ca"/></trust-anchors>'
        # Use an incorrect pin. CA trust must not bypass release certificate pinning.
        pins = '<pin-set><pin digest="SHA-256">' + base64.b64encode(bytes(32)).decode() + '</pin></pin-set>' if variant == 'pinned' else ''
        config = f'<base-config cleartextTrafficPermitted="true">{anchors}</base-config>'
        if pins:
            config += f'<domain-config><domain>android.openproxy.test</domain>{anchors}{pins}</domain-config>'
    else:
        config = '<base-config cleartextTrafficPermitted="true"/><debug-overrides><trust-anchors><certificates src="@raw/fixture_ca"/></trust-anchors></debug-overrides>'
    (resources / 'xml' / 'network_security_config.xml').write_text(f'<network-security-config>{config}</network-security-config>')
    package = f'org.openproxy.fixture.{variant}'
    manifest = folder / 'AndroidManifest.xml'
    manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">
      <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36"/>
      <uses-permission android:name="android.permission.INTERNET"/>
      <application android:debuggable="{str(debug).lower()}" android:networkSecurityConfig="@xml/network_security_config" android:label="OpenProxy fixture">
        <activity android:name="org.openproxy.fixture.MainActivity" android:exported="true"/>
      </application></manifest>''')
    android_jar = sorted((sdk / 'platforms').glob('*/android.jar'))[-1]
    tools = sorted((sdk / 'build-tools').iterdir())[-1]
    classes = folder / 'classes'
    classes.mkdir()
    command('javac', '--release', '8', '-classpath', android_jar,
            '-d', classes, ROOT / 'tests/android/MainActivity.java')
    dex = folder / 'dex'
    dex.mkdir()
    command(tools / 'd8', '--min-api', '24', '--lib', android_jar, '--output', dex, *classes.rglob('*.class'))
    apk = folder / 'fixture.apk'
    command(tools / 'aapt', 'package', '-f', '-M', manifest, '-S', resources, '-I', android_jar, '-F', apk)
    with zipfile.ZipFile(apk, 'a') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    key = work / 'fixture.keystore'
    if not key.exists():
        command('keytool', '-genkeypair', '-keystore', key, '-storepass', 'changeit', '-keypass', 'changeit',
                '-alias', 'fixture', '-keyalg', 'RSA', '-dname', 'CN=Disposable OpenProxy fixture', '-validity', '2')
    command(tools / 'apksigner', 'sign', '--ks', key, '--ks-pass', 'pass:changeit', apk)
    return package, apk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', help='Reuse only an emulator named OpenProxyAcceptance (for local debugging).')
    args = parser.parse_args()
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT', Path.home() / 'Android/Sdk'))
    adb = sdk / 'platform-tools/adb'
    assert adb.is_file(), f'Android SDK not found: {sdk}'
    assert shutil.which('javac') and shutil.which('keytool'), 'JDK required'
    (ROOT / 'test-artifacts').mkdir(exist_ok=True)
    emulator = None
    serial = args.serial or 'emulator-5582'
    assert serial.startswith('emulator-'), 'Physical devices are never used by this fixture'
    with tempfile.TemporaryDirectory(dir=ROOT / 'test-artifacts', prefix='android-') as temp:
        work = Path(temp)
        def device(*parts):
            return command(adb, '-s', serial, *parts).strip()
        if not args.serial:
            assert serial not in command(adb, 'devices'), f'{serial} is occupied; choose --serial only for a disposable fixture'
            image = sdk / 'system-images/android-36/default/x86_64'
            assert (image / 'system.img').exists(), 'Install default API 36 x86_64 image before running this optional fixture'
            avd = work / 'acceptance.avd'
            avd.mkdir()
            (avd / 'config.ini').write_text(f'''AvdId=OpenProxyAcceptance
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=2
hw.ramSize=2048
hw.lcd.density=240
hw.lcd.height=1280
hw.lcd.width=720
hw.keyboard=yes
image.sysdir.1={image}/
tag.id=default
target=android-36
disk.dataPartition.size=2G
''')
            (work / 'OpenProxyAcceptance.ini').write_text(f'avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-36\n')
            log = (work / 'emulator.log').open('w')
            env = {**os.environ, 'ANDROID_AVD_HOME': str(work)}
            emulator = subprocess.Popen([str(sdk / 'emulator/emulator'), '-avd', 'OpenProxyAcceptance',
                '-port', '5582', '-no-window', '-no-audio', '-no-boot-anim', '-no-snapshot',
                '-gpu', 'swiftshader_indirect'], env=env, stdout=log, stderr=log)
        previous = None
        fixture_started = False
        packages = []
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if emulator and emulator.poll() is not None:
                    raise AssertionError((work / 'emulator.log').read_text()[-4000:])
                try:
                    if device('shell', 'getprop', 'sys.boot_completed') == '1':
                        break
                except RuntimeError:
                    pass
                time.sleep(1)
            else:
                raise AssertionError('Disposable emulator did not boot in 120 seconds')
            assert device('emu', 'avd', 'name').splitlines()[0] == 'OpenProxyAcceptance', 'Refusing to modify an unrelated emulator'
            previous = device('shell', 'settings', 'get', 'global', 'http_proxy')
            Acceptance.setUpClass()
            fixture_started = True
            p = Acceptance.proxy
            # Use a fixture hostname to prevent platform proxy exceptions for loopback hosts.
            extensions = Acceptance.dir / 'leaf.ext'
            extensions.write_text(extensions.read_text().replace('DNS:localhost,IP:127.0.0.1', 'DNS:localhost,DNS:android.openproxy.test,IP:127.0.0.1'))
            command('openssl', 'x509', '-req', '-in', Acceptance.dir / 'origin.csr', '-CA', Acceptance.dir / 'origin-root.pem',
                    '-CAkey', Acceptance.dir / 'origin-root.key', '-CAcreateserial', '-out', Acceptance.dir / 'origin.pem',
                    '-days', '2', '-extfile', extensions)
            Acceptance.tls_origin.socket.context.load_cert_chain(Acceptance.dir / 'origin.pem', Acceptance.dir / 'origin.key')
            settings = p.api('status')[1]['settings']
            settings['dns_overrides'] = {'android.openproxy.test': '127.0.0.1'}
            assert p.api('settings', settings)[0] == 200
            device('shell', 'settings', 'put', 'global', 'http_proxy', f'10.0.2.2:{p.proxy[1]}')
            outcomes = {}
            for variant in ('debug', 'release', 'pinned', 'bypass'):
                settings['bypass_hosts'] = ['android.openproxy.test'] if variant == 'bypass' else []
                assert p.api('settings', settings)[0] == 200
                ca = (Acceptance.dir / 'origin-root.pem' if variant == 'bypass' else p.data / 'ca.pem').read_bytes()
                package, apk = build_app(work, sdk, variant, ca)
                packages.append(package)
                device('install', '-r', apk)
                run = uuid.uuid4().hex
                http = Acceptance.http.replace('127.0.0.1', 'android.openproxy.test') + '/android-' + variant
                https = Acceptance.https.replace('localhost', 'android.openproxy.test') + '/android-' + variant
                device('shell', 'am', 'start', '-W', '-n', package + '/org.openproxy.fixture.MainActivity',
                       '--es', 'run', run, '--es', 'http_url', http, '--es', 'https_url', https)
                deadline = time.monotonic() + 40
                result = None
                while time.monotonic() < deadline:
                    for line in device('logcat', '-d', '-v', 'raw', '-s', 'OpenProxyFixture:I').splitlines():
                        if line.startswith('{'):
                            value = json.loads(line)
                            if value.get('run') == run:
                                result = value
                    if result:
                        break
                    time.sleep(.2)
                assert result, f'{variant}: app did not finish'
                assert result['http'].get('status') == 200, result
                payload = json.loads(base64.b64decode(result['http']['body']))
                assert payload['method'] == 'POST' and base64.b64decode(payload['body']) == bytes([0, 255, 1, 2]), result
                assert '10.0.2.2' in result['http']['proxy'], result
                assert result['ca']['status'] == 200 and b'BEGIN CERTIFICATE' in base64.b64decode(result['ca']['body']), result
                if variant in ('debug', 'bypass'):
                    assert result['https']['status'] == 200, result
                else:
                    assert result['https'].get('error') == 'SSLHandshakeException', result
                flows = p.api('flows')[1]
                assert any('/android-' + variant in f['url'] and f['method'] == 'POST' for f in flows), 'Android bypassed OpenProxy'
                if variant == 'debug':
                    assert any('/android-debug' in f['url'] and f['tls'] and f['status'] == 200 for f in flows), 'HTTPS was not inspected'
                outcomes[variant] = result
                print(f'Android {variant}: passed', flush=True)
            (ROOT / 'test-artifacts/android-results.json').write_text(json.dumps(outcomes, indent=2))
        finally:
            if previous is not None:
                if previous == 'null':
                    device('shell', 'settings', 'delete', 'global', 'http_proxy')
                else:
                    device('shell', 'settings', 'put', 'global', 'http_proxy', previous)
                for package in packages:
                    device('uninstall', package)
            if fixture_started:
                Acceptance.tearDownClass()
            if emulator:
                emulator.terminate()
                try:
                    emulator.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    emulator.kill()
                    emulator.wait(timeout=5)
                log.close()


if __name__ == '__main__':
    main()
