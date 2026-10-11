#!/usr/bin/env python3
"""Use agent-browser for embedded inspector tests with local origin traffic."""
import base64
import concurrent.futures
import json
import subprocess
from pathlib import Path

from integration import Acceptance, ROOT

SESSION = "openproxy-acceptance"


def browser(*args, source=None):
    # The CLI does not scroll clipped elements in native dialogs automatically.
    if args[0] in ('click', 'fill', 'check', 'select') and args[1].startswith(('#', '[', 'input', 'select')):
        browser('wait', args[1])
        browser('eval', '--stdin', source=f"document.querySelector({json.dumps(args[1])})?.scrollIntoView({{block:'center'}})")
    result = subprocess.run(["agent-browser", "--session", SESSION, *args], input=source,
                            text=True, capture_output=True, timeout=35)
    if result.returncode:
        raise AssertionError(f"browser command {args} failed: {result.stdout} {result.stderr}")
    return result.stdout.strip()


def check(source):
    return browser("eval", "--stdin", source=f"(() => {{ {source}; return 'passed'; }})()")


def long_session(p):
    empty = {"headers": [], "trailers": [], "body": {"data": "", "size": 0, "truncated": False, "complete": True}}
    flows = [{"id": i, "url": f"https://host{i % 150:03}.example.invalid/fixture/{i}",
        "upstream_url": f"https://host{i % 150:03}.example.invalid/fixture/{i}",
        "method": "POST" if i % 3 == 0 else "GET", "client": "192.0.2.1:12345", "protocol": "HTTP/2.0",
        "tls": True, "started_at": 1700000000000 + i, "headers_received_ms": 20,
        "duration_ms": 1500 if i % 10 == 0 else 25, "phase": "complete", "status": 500 if i % 20 == 0 else 200,
        "error": "Local fixture connection error" if i % 40 == 0 else None, "request": empty,
        "response": {**empty, "headers": [["content-type", "application/json"]],
            "body": {"data": "eyJvayI6dHJ1ZX0=", "size": 11, "complete": True, "truncated": False}}}
        for i in range(1000)]
    assert p.api('session', {"version": 1, "flows": flows})[0] == 204
    browser('set', 'viewport', '1440', '900')
    browser('wait', '--fn', "document.querySelector('#total').textContent === '1000' && document.querySelectorAll('#flows tr').length === 1000")
    check("""
      const list = document.querySelector('#traffic-scroll'), hosts = document.querySelector('#hosts');
      if (list.scrollHeight <= list.clientHeight || hosts.scrollHeight <= hosts.clientHeight) throw new Error('Lists are not independently scrollable');
      for (const button of document.querySelectorAll('.sidebar-bottom button')) {
        const rect = button.getBoundingClientRect();
        if (rect.top < 0 || rect.bottom > innerHeight) throw new Error('Session action left the viewport');
      }
      if (document.documentElement.scrollHeight > innerHeight + 1) throw new Error('Long session expanded the page');
      hosts.scrollTop = 400; list.scrollTop = 1200;
    """)
    browser('wait', '1500')
    check("if (document.querySelector('#hosts').scrollTop !== 400 || document.querySelector('#traffic-scroll').scrollTop !== 1200 || scrollY !== 0) throw new Error('Polling changed list scroll positions')")
    browser('press', 'Control+k')
    check("if (document.activeElement.id !== 'search') throw new Error('Search shortcut did not focus search')")
    browser('fill', '#search', '/fixture/999')
    check("if (document.querySelectorAll('#flows tr').length !== 1) throw new Error('Large session search failed')")
    browser('click', '#reset-filters')
    browser('click', '#quick-errors')
    check("if (document.querySelectorAll('#flows tr').length !== 50 || document.querySelector('#quick-errors').getAttribute('aria-pressed') !== 'true') throw new Error('Error quick filter failed')")
    browser('click', '#flows tr:first-child')
    browser('press', 'ArrowDown')
    check("if (document.activeElement !== document.querySelector('#flows tr:nth-child(2)') || document.activeElement.getAttribute('aria-selected') !== 'true') throw new Error('Filtered keyboard navigation failed')")
    browser('press', 'End')
    check("if (document.activeElement !== document.querySelector('#flows tr:last-child') || scrollY !== 0) throw new Error('End shortcut scrolled the page')")
    browser('press', 'Home')
    check("if (document.activeElement !== document.querySelector('#flows tr:first-child')) throw new Error('Home shortcut failed')")
    check("if (document.activeElement.getBoundingClientRect().top < document.querySelector('.traffic thead').getBoundingClientRect().bottom - 1) throw new Error('Keyboard selection hid beneath the sticky table header')")
    browser('click', '#quick-slow')
    check("if (document.querySelectorAll('#flows tr').length !== 100) throw new Error('Slow quick filter failed')")
    browser('click', '#quick-slow')
    check("if (document.querySelectorAll('#flows tr').length !== 1000) throw new Error('Quick filter did not toggle off')")
    browser('select', '#traffic-view', 'structure')
    check("if (!document.querySelector('[aria-label=\"Host and path structure\"] details')) throw new Error('Host/path tree missing')")
    browser('select', '#traffic-view', 'waterfall')
    check("if (document.querySelectorAll('[data-waterfall-flow]').length !== 1000) throw new Error('Waterfall lost exchanges')")
    browser('click', '[data-waterfall-flow]:first-of-type')
    browser('press', 'ArrowDown')
    check("if (document.activeElement !== document.querySelectorAll('[data-waterfall-flow]')[1]) throw new Error('Waterfall keyboard navigation failed')")
    browser('select', '#traffic-view', 'list')
    comparison_file = Acceptance.dir / 'comparison-session.json'
    comparison_file.write_text(json.dumps(p.api('session')[1]))
    browser('click', '#compare')
    browser('wait', '--fn', "!!document.querySelector('#exchange-comparison-result')")
    browser('upload', '#compare-session-file', str(comparison_file))
    browser('wait', '--fn', "document.querySelector('#session-comparison-summary')?.textContent.includes('1000 equal')")
    browser('find', 'role', 'button', 'click', '--name', 'Done', '--exact')
    browser('set', 'media', 'dark')
    browser('select', '#theme', 'system')
    browser('wait', '--fn', "document.documentElement.classList.contains('dark')")
    browser('select', '#theme', 'light')
    check("if (document.documentElement.classList.contains('dark')) throw new Error('Explicit light theme failed')")
    browser('screenshot', str(ROOT / 'test-artifacts/frontend-light.png'))
    browser('select', '#theme', 'dark')
    browser('open', f'http://{p.ui}/')
    browser('wait', '--fn', "document.querySelector('#total').textContent === '1000'")
    check("if (!document.documentElement.classList.contains('dark') || document.querySelector('#theme').value !== 'dark') throw new Error('Theme preference did not survive reload')")
    browser('click', '#flows tr:first-child')
    browser('wait', '--fn', "!!document.querySelector('#detail')")
    browser('screenshot', str(ROOT / 'test-artifacts/frontend-dark.png'))
    browser('click', '#settings')
    check("if (getComputedStyle(document.querySelector('dialog')).backgroundColor !== getComputedStyle(document.querySelector('.topbar')).backgroundColor) throw new Error('Dialog did not inherit dark theme')")
    browser('press', 'Control+k')
    check("if (!document.querySelector('dialog').contains(document.activeElement)) throw new Error('Search shortcut escaped a modal')")
    browser('find', 'role', 'button', 'click', '--name', 'Cancel', '--exact')
    browser('click', '#rules')
    browser('click', '#rules-mode-json')
    browser('fill', '#rules-json', 'invalid JSON')
    browser('click', '#rules-form button[type=submit]')
    browser('wait', '--fn', "!!document.querySelector('dialog .toast')")
    check("if (getComputedStyle(document.querySelector('dialog .toast')).backgroundColor !== getComputedStyle(document.querySelector('dialog')).backgroundColor) throw new Error('Dark error notice did not retain an opaque surface')")
    browser('screenshot', str(ROOT / 'test-artifacts/frontend-dark-error.png'))
    browser('find', 'role', 'button', 'click', '--name', 'Cancel', '--exact')
    browser('select', '#theme', 'system')
    browser('set', 'media', 'light')
    browser('wait', '--fn', "!document.documentElement.classList.contains('dark')")
    for width, height in [(1024, 768), (768, 900), (390, 844)]:
        browser('set', 'viewport', str(width), str(height))
        check("if (document.documentElement.scrollWidth > innerWidth || document.documentElement.scrollHeight > innerHeight + 1) throw new Error('Viewport layout overflowed')")
        if width >= 640:
            check("if ([...document.querySelectorAll('.sidebar-bottom button')].some(button => button.scrollWidth > button.clientWidth)) throw new Error('Session action label was clipped')")
    browser('click', '#session-tools')
    check("""
      const rect = document.querySelector('#mobile-clear-traffic').getBoundingClientRect();
      if (rect.top < 0 || rect.bottom > innerHeight) throw new Error('Mobile session tools are unreachable');
      const hosts = document.querySelector('#mobile-hosts');
      if (hosts.scrollHeight <= hosts.clientHeight) throw new Error('Mobile hosts do not scroll');
    """)
    browser('screenshot', str(ROOT / 'test-artifacts/frontend-mobile-session.png'))
    browser('find', 'role', 'button', 'click', '--name', 'Close session & hosts', '--exact')
    browser('screenshot', str(ROOT / 'test-artifacts/frontend-mobile.png'))


def run():
    Acceptance.setUpClass()
    try:
        p = Acceptance.proxy
        p.request(Acceptance.http + "/gzip")
        p.request(Acceptance.https + "/echo", "POST", b'{"source":"browser-test"}', {"Content-Type": "application/json"}, tls=True)
        browser("open", f"http://{p.ui}/#{p.token}")
        browser("wait", "--fn", "document.querySelector('#total').textContent === '2'")
        # Detail requests must complete even if they take longer than the traffic poll interval.
        browser('eval', '--stdin', source=r"""
            window.acceptanceFetch = window.fetch;
            window.fetch = async (...args) => {
                const response = await window.acceptanceFetch(...args);
                if (/^\/api\/flows\/\d+$/.test(String(args[0])))
                    await new Promise(resolve => setTimeout(resolve, 1500));
                return response;
            };
        """)
        browser("click", "#flows tr:first-child")
        browser("click", "[data-tab=response]")
        browser("wait", "--fn", "document.querySelector('.body-content')?.textContent.includes('POST')")
        browser('eval', '--stdin', source='window.fetch = window.acceptanceFetch;')
        check("if (document.querySelectorAll('.headers-table tr').length < 5) throw new Error('Headers missing')")
        browser("click", "#edit")
        browser("fill", "#compose-body", '{"edited":true}')
        browser("click", "#compose-form button[type=submit]")
        browser("wait", "--fn", "document.querySelector('#total').textContent === '3'")
        latest = p.api("flows")[1][0]
        flow = p.api(f"flows/{latest['id']}")[1]
        assert base64.b64decode(flow["request"]["body"]["data"]) == b'{"edited":true}'
        origin_echo = json.loads(base64.b64decode(flow["response"]["body"]["data"]))
        assert base64.b64decode(origin_echo["body"]) == b'{"edited":true}'
        browser("fill", "#search", "gzip")
        check("if (document.querySelectorAll('#flows tr').length !== 1) throw new Error('Filter failed')")
        browser("click", "#flows tr:first-child")
        browser("click", "[data-tab=response]")
        browser("wait", "--fn", "document.querySelector('.body-content')?.textContent.includes('/gzip')")
        browser("select", "select[aria-label='Body display mode']", "tree")
        check("if (!document.querySelector('.body-content details')) throw new Error('JSON tree missing')")
        browser("select", "select[aria-label='Body display mode']", "hex")
        check("if (!document.querySelector('.body-content').textContent.includes('1f 8b')) throw new Error('Hex did not preserve gzip bytes')")
        browser("click", "#search")
        browser("press", "Control+a")
        browser("press", "Backspace")
        browser("wait", "--fn", "document.querySelector('#search').value === '' && document.querySelectorAll('#flows tr').length === 3")
        browser('click', '#flows tr:first-child')
        browser('click', '[data-tab=request]')
        browser('select', "select[aria-label='Body display mode']", 'pretty')
        browser('select', "select[aria-label='Message snapshot']", 'original')
        browser('wait', '--fn', "document.querySelector('.body-content')?.textContent.includes('edited')")
        browser('select', "select[aria-label='Message snapshot']", 'effective')
        browser('click', '[data-tab=overview]')
        browser('fill', '#flow-note', 'Browser annotation')
        browser('check', '#flow-marked')
        browser('click', '#save-annotation')
        browser('select', '#filter', 'marked')
        browser('wait', '--fn', "document.querySelectorAll('#flows tr').length === 1")
        browser('click', '#reset-filters')
        browser("click", "#record")
        browser("wait", "--fn", "document.querySelector('#record').textContent.includes('Paused')")
        before = len(p.api("flows")[1])
        p.request(Acceptance.http + "/unrecorded")
        assert len(p.api("flows")[1]) == before
        browser("click", "#record")
        browser("wait", "--fn", "document.querySelector('#record').textContent.includes('Recording')")
        browser("click", "#settings")
        browser("check", "input[name=no_cache]")
        browser("click", "#settings-form button[type=submit]")
        browser("wait", "--fn", "!document.querySelector('dialog')")
        assert p.api("status")[1]["settings"]["no_cache"]
        browser("click", "#rules")
        browser("click", "#rules-mode-json")
        rule = [{"name": "Browser rule", "enabled": True, "url": Acceptance.http + "/browser-rule", "actions": [
            {"type": "mock", "status": 202, "headers": [["Content-Type", "text/plain"]], "body": "from browser rule"}]}]
        invalid_rule = [{**rule[0], 'actions': [{'type': 'set_request_header', 'name': 'Content-Length', 'value': '999'}]}]
        browser("fill", "#rules-json", json.dumps(invalid_rule))
        browser("click", "#rules-form button[type=submit]")
        browser("wait", "--fn", "document.querySelector('dialog .toast')?.textContent.includes('framing')")
        browser("fill", "#rules-json", json.dumps(rule))
        browser("click", "#rules-form button[type=submit]")
        browser("wait", "--fn", "!document.querySelector('dialog')")
        assert p.request(Acceptance.http + "/browser-rule")[0::2] == (202, b"from browser rule")
        browser('click', '#rules')
        browser('wait', '--fn', "!!document.querySelector('[data-rule-index]')")
        browser('fill', "[data-rule-index='0'] input[data-field=name]", 'Visual editor rule')
        browser('click', '#rules-mode-json')
        check("if (!document.querySelector('#rules-json').value.includes('Visual editor rule')) throw new Error('Visual editor lost its draft')")
        browser('fill', '#rules-json', '[{}]')
        browser('click', '#rules-mode-visual')
        browser('wait', '--fn', "!!document.querySelector('dialog .toast') && !!document.querySelector('#rules-json')")
        browser('fill', '#rules-json', json.dumps([{**rule[0], 'name': 'Visual editor rule'}]))
        browser('click', '#rules-mode-visual')
        browser('wait', '--fn', "!!document.querySelector('[data-rule-index]')")
        browser('click', '#rules-form button[type=submit]')
        browser('wait', '--fn', "!document.querySelector('dialog')")
        assert p.api('status')[1]['settings']['rules'][0]['name'] == 'Visual editor rule'
        browser("click", "#compose")
        browser("fill", "input[name=url]", Acceptance.http + "/draft")
        browser("fill", "#compose-body", "draft must survive polling")
        p.request(Acceptance.http + "/polling-during-draft")
        browser("wait", "--fn", "document.querySelector('#total').textContent === '5'")
        check("if (document.querySelector('#compose-body').value !== 'draft must survive polling') throw new Error('Polling reset editor draft')")
        browser("find", "role", "button", "click", "--name", "Cancel", "--exact")
        browser("click", "#rules")
        browser("click", "#rules-mode-json")
        pause_rule = [{"name": "Browser pause", "enabled": True, "url": Acceptance.http + "/paused-browser", "actions": [
            {"type": "breakpoint", "phase": "request", "timeout_ms": 120000}]}]
        browser("fill", "#rules-json", json.dumps(pause_rule))
        browser("click", "#rules-form button[type=submit]")
        browser("wait", "--fn", "!document.querySelector('dialog')")
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(p.request, Acceptance.http + "/paused-browser", "POST", b'{"browser":"original"}')
            browser("wait", "--fn", "document.querySelector('#breakpoints').textContent.includes('(1)')")
            browser("click", "#breakpoints")
            browser("wait", "--fn", "!!document.querySelector('#breakpoint-editor')")
            assert not held.done()
            browser("check", "input[name=replace-body]")
            browser("fill", "#breakpoint-body", '{"browser":"changed"}')
            browser("fill", "#breakpoint-editor input[name=url]", Acceptance.http + "/after-browser")
            browser("set", "viewport", "1440", "900")
            browser("screenshot", str(ROOT / "test-artifacts/breakpoints-desktop.png"))
            browser("fill", "#breakpoint-editor input[name=method]", "CONNECT")
            browser("click", "#breakpoint-editor button[type=submit]")
            browser("wait", "--fn", "document.querySelector('#breakpoint-editor [role=alert]')?.textContent.includes('CONNECT')")
            assert not held.done()
            browser("fill", "#breakpoint-editor input[name=method]", "POST")
            browser("click", "#breakpoint-editor button[type=submit]")
            code, _, body = held.result(timeout=5)
            assert code == 200
            echo = json.loads(body)
            assert echo['path'] == '/after-browser'
            assert base64.b64decode(echo['body']) == b'{"browser":"changed"}'
            browser("wait", "--fn", "!document.querySelector('#breakpoint-editor')")
            browser("find", "role", "button", "click", "--name", "Close breakpoints", "--exact")
        current = p.api('status')[1]['settings']
        current['rules'] = [{"name": "Response pause", "enabled": True, "url": Acceptance.http + "/gzip", "actions": [
            {"type": "breakpoint", "phase": "response", "timeout_ms": 120000}]}]
        assert p.api('settings', current)[0] == 200
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(p.request, Acceptance.http + '/gzip')
            browser("wait", "--fn", "document.querySelector('#breakpoints').textContent.includes('(1)')")
            browser("click", "#breakpoints")
            browser("wait", "--fn", "!!document.querySelector('#breakpoint-editor input[name=status]')")
            browser("find", "role", "button", "click", "--name", "Decode gzip for editing", "--exact")
            browser("wait", "--fn", "!!document.querySelector('#breakpoint-body')")
            browser("fill", "#breakpoint-body", '{"response":"changed in browser"}')
            browser("fill", "#breakpoint-editor input[name=status]", "201")
            browser("click", "#breakpoint-editor button[type=submit]")
            code, _, body = held.result(timeout=5)
            import gzip
            assert code == 201
            assert json.loads(gzip.decompress(body)) == {"response": "changed in browser"}
            browser("find", "role", "button", "click", "--name", "Close breakpoints", "--exact")
        current['rules'] = [{"name": "Draft expiry", "enabled": True, "url": Acceptance.http + "/expire-browser", "actions": [
            {"type": "breakpoint", "phase": "request", "timeout_ms": 4000}]}]
        assert p.api('settings', current)[0] == 200
        with concurrent.futures.ThreadPoolExecutor() as executor:
            held = executor.submit(p.request, Acceptance.http + '/expire-browser')
            browser("wait", "--fn", "document.querySelector('#breakpoints').textContent.includes('(1)')")
            browser("click", "#breakpoints")
            browser("wait", "--fn", "!!document.querySelector('#breakpoint-editor input[name=method]')")
            browser("check", "input[name=replace-body]")
            browser("fill", "#breakpoint-body", "keep my expired draft")
            assert held.result(timeout=6)[0] == 502
            browser("wait", "--fn", "document.querySelector('#breakpoint-editor fieldset')?.disabled")
            check("if (document.querySelector('#breakpoint-body').value !== 'keep my expired draft') throw new Error('Expired draft was lost')")
            browser("find", "role", "button", "click", "--name", "Close breakpoints", "--exact")
        browser("set", "viewport", "1440", "900")
        browser("screenshot", str(ROOT / "test-artifacts/browser-desktop.png"))
        browser("set", "viewport", "390", "844")
        check("if (document.documentElement.scrollWidth > 390) throw new Error('Mobile layout overflows')")
        browser("screenshot", str(ROOT / "test-artifacts/browser-mobile.png"))
        browser("click", "#setup")
        check("if (!document.querySelector('dialog').textContent.includes('/socks.pac') || !document.querySelector('dialog').textContent.includes('/proxy.pac')) throw new Error('PAC setup instructions missing')")
        browser("find", "role", "button", "click", "--name", "Got it", "--exact")
        long_session(p)
        browser('set', 'viewport', '1440', '900')
        current = p.api('status')[1]['settings']
        for payload, expected in [('<root><child>ok</child></root>', '\n  <child>ok</child>'), ('<root>', 'Invalid XML'), ('<!DOCTYPE root [<!ENTITY x "boom">]><root>&x;</root>', 'DTD/entity declarations')]:
            current['rules'] = [{'name':'XML fixture','enabled':True,'url':Acceptance.http+'/xml','actions':[{'type':'mock','status':200,'headers':[['Content-Type','application/xml']],'body':payload}]}]
            assert p.api('settings',current)[0] == 200
            p.request(Acceptance.http+'/xml')
            flow_id = p.api('flows')[1][0]['id']
            browser('wait','--fn',f"!!document.querySelector('tr[data-flow-id=\"{flow_id}\"]')")
            browser('click',f'tr[data-flow-id="{flow_id}"]')
            browser('click','[data-tab=response]')
            browser('wait','--fn',f"document.querySelector('.body-content')?.textContent.includes({json.dumps(expected)})")
        current['rules'] = []
        assert p.api('settings', current)[0] == 200
        trailers = [['x-upload', 'original']]
        assert p.api('compose', {'method': 'POST', 'url': Acceptance.http + '/echo',
                                'body': base64.b64encode(b'original').decode(), 'trailers': trailers})[1] == {'completed': 1, 'errors': []}
        flow_id = p.api('flows')[1][0]['id']
        browser('wait', '--fn', f"!!document.querySelector('tr[data-flow-id=\"{flow_id}\"]')")
        browser('click', f'tr[data-flow-id="{flow_id}"]')
        browser('wait', '--fn', f"document.querySelector('#detail .detail-heading p')?.textContent === {json.dumps(Acceptance.http + '/echo')}")
        browser('click', '#edit')
        browser('wait', '#compose-form textarea[name=trailers]')
        check("if (document.querySelector('textarea[name=trailers]').value !== 'x-upload: original') throw new Error('Edit lost captured trailers')")
        browser('fill', '#compose-body', 'edited body')
        browser('fill', '#compose-form textarea[name=trailers]', 'x-upload: edited\nx-upload: repeated')
        browser('click', '#compose-form button[type=submit]')
        browser('wait', '--fn', "!document.querySelector('dialog')")
        edited = p.api('flows/' + str(p.api('flows')[1][0]['id']))[1]
        echo = json.loads(base64.b64decode(edited['response']['body']['data']))
        assert base64.b64decode(echo['body']) == b'edited body'
        assert echo['trailers'] == [['x-upload', 'edited'], ['x-upload', 'repeated']]
        assert not browser("errors"), "browser reported runtime errors"
        print("Browser acceptance passed: inspector/composer, body modes, recording/rules, breakpoint edits/expiry, 1000-row independent scrolling, quick filters, keyboard navigation, persistent/system themes and responsive session controls.")
    except Exception:
        print(browser("eval", "--stdin", source="JSON.stringify({search:document.querySelector('#search')?.value,rows:document.querySelectorAll('#flows tr').length,active:document.activeElement?.id,notice:document.querySelector('.toast')?.textContent})"))
        browser("screenshot", str(ROOT / "test-artifacts/browser-failure.png"))
        raise
    finally:
        browser("close")
        Acceptance.tearDownClass()


if __name__ == "__main__":
    run()
