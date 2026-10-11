#!/usr/bin/env python3
"""Run protocol inspector UI tests with fixtures. Do not send external validation requests."""
import tempfile
from pathlib import Path

import browser as gui
from integration import ProxyProcess


def run():
    gui.SESSION = 'openproxy-protocols'
    with tempfile.TemporaryDirectory(prefix='openproxy-protocol-ui-') as directory:
        proxy = ProxyProcess(Path(directory) / 'data').start()
        try:
            message = {'headers': [['content-type', 'application/protobuf']], 'trailers': [], 'body': {'data': 'CCo=', 'size': 2, 'truncated': False, 'complete': True}}
            flow = {'id': 1, 'url': 'http://fixture.invalid/protobuf', 'upstream_url': 'http://fixture.invalid/protobuf', 'method': 'POST', 'protocol': 'HTTP/2', 'client': '127.0.0.1', 'tls': False, 'started_at': 1, 'headers_received_ms': 1, 'status': 200, 'error': None, 'request': message, 'response': message, 'phase': 'complete', 'duration_ms': 1}
            assert proxy.api('session', {'version': 1, 'flows': [flow]})[0] == 204
            gui.browser('open', f'http://{proxy.ui}/#{proxy.token}')
            gui.browser('wait', '--fn', "document.querySelectorAll('#flows tr').length === 1")
            gui.browser('snapshot', '-i')
            gui.browser('click', '#flows tr')
            gui.browser('click', '[data-tab=response]')
            gui.browser('find', 'text', 'Protocol decoding & external validation', 'click')
            gui.browser('snapshot', '-i')
            gui.browser('find', 'role', 'button', 'click', '--name', 'Decode locally', '--exact')
            gui.browser('wait', '--fn', "document.querySelector('#detail pre')?.textContent.includes('Wire types and field numbers')")
            gui.check("""
                const output = document.querySelector('#detail pre').textContent;
                if (!output.includes('"value": "42"')) throw new Error('Protobuf decoding did not reach the inspector');
                const button = [...document.querySelectorAll('#detail button')].find(b => b.textContent === 'Send body for validation');
                if (!button?.disabled) throw new Error('External validation did not require consent');
                const checkbox = [...document.querySelectorAll('#detail input[type=checkbox]')].find(c => c.parentElement.textContent.includes('I consent'));
                checkbox.click();
                if (!document.body.textContent.includes('https://validator.w3.org/nu/')) throw new Error('Destination was not disclosed');
            """)
            gui.check("if ([...document.querySelectorAll('#detail button')].find(b => b.textContent === 'Send body for validation').disabled) throw new Error('Consent did not enable submission')")
            gui.browser('select', '[aria-label="External validation service"]', 'css')
            gui.check("if (![...document.querySelectorAll('#detail button')].find(b => b.textContent === 'Send body for validation').disabled) throw new Error('Consent survived a service change')")
            # Mock only the loopback API response. Do not call the Rust function for external validation requests.
            gui.browser('eval', '--stdin', source="""
                window.protocolOriginalFetch = window.fetch;
                window.fetch = (url, options) => String(url).endsWith('/validate')
                    ? Promise.resolve(new Response(JSON.stringify({output:'<script>window.protocolInjected=true</script>'}), {status:200, headers:{'Content-Type':'application/json'}}))
                    : window.protocolOriginalFetch(url, options);
                [...document.querySelectorAll('#detail input[type=checkbox]')].find(c => c.parentElement.textContent.includes('I consent')).click();
            """)
            gui.browser('find', 'role', 'button', 'click', '--name', 'Send body for validation', '--exact')
            gui.browser('wait', '--fn', "document.querySelector('#detail pre')?.textContent.includes('<script>')")
            gui.check("if (window.protocolInjected || document.querySelector('#detail pre script')) throw new Error('Validator output executed'); if (![...document.querySelectorAll('#detail button')].find(b => b.textContent === 'Send body for validation').disabled) throw new Error('Consent was not consumed')")
            gui.browser('eval', '--stdin', source="window.fetch = window.protocolOriginalFetch;")
            message['body']['complete'] = False
            assert proxy.api('session', {'version': 1, 'flows': [flow]})[0] == 204
            next_id = proxy.api('flows')[1][0]['id']
            gui.browser('wait', '--fn', f"!!document.querySelector('#flows tr[data-flow-id=\"{next_id}\"]')")
            gui.browser('click', '#flows tr')
            gui.browser('wait', '--fn', "!!document.querySelector('#detail')")
            gui.browser('click', '[data-tab=response]')
            gui.browser('find', 'text', 'Protocol decoding & external validation', 'click')
            gui.check("if (![...document.querySelectorAll('#detail input[type=checkbox]')].find(c => c.parentElement.textContent.includes('I consent')).disabled) throw new Error('Incomplete capture can be submitted')")
            flow['protocol'] = 'WebSocket'
            flow['metadata'] = {'websocket': {'extensions': 'permessage-deflate', 'frames': [{'direction': 'client', 'at': 1, 'opcode': 1, 'fin': False, 'masked': True, 'compressed': False, 'message': 1, 'size': 2, 'payload': 'aGk=', 'truncated': False, 'complete': True, 'error': None}, {'direction': 'server', 'at': 2, 'opcode': 1, 'fin': True, 'masked': False, 'compressed': True, 'message': 1, 'size': 2, 'payload': 'aGk=', 'truncated': False, 'complete': True, 'error': None}], 'truncated': False, 'complete': True, 'error': None}}
            assert proxy.api('session', {'version': 1, 'flows': [flow]})[0] == 204
            next_id = proxy.api('flows')[1][0]['id']
            gui.browser('wait', '--fn', f"!!document.querySelector('#flows tr[data-flow-id=\"{next_id}\"]')")
            gui.browser('click', '#flows tr')
            gui.browser('click', '[data-tab=overview]')
            gui.browser('wait', '--fn', "document.body.textContent.includes('WebSocket frames · 2')")
            gui.check("if (!document.body.textContent.includes('· fragment') || !document.body.textContent.includes('· compressed')) throw new Error('WebSocket frame markers missing')")
            print('Protocol UI acceptance passed: local decoding, consent lifecycle, incomplete-body guard and escaped validator output.')
        finally:
            gui.browser('close')
            proxy.stop()


if __name__ == '__main__':
    run()
