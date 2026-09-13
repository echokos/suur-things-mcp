"""Real-Chromium tests for the dashboard's embedded JavaScript.

The dashboard ships its UI as a JS string inside ``dashboard.py`` with no
JS unit runner, so these load the actual page in a headless browser and assert
the client-side behaviours that pure-Python tests can't reach (XSS escaping,
the quick-add re-entry guard + button feedback).

They skip cleanly when Playwright's Chromium isn't installed, so plain
``uv run pytest`` still passes without ``playwright install``. CI installs the
browser and runs them for real.
"""

import socket
import threading
import time
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

# Skip the whole module if Playwright (the lib) isn't even importable.
pytest.importorskip("playwright.sync_api")
import uvicorn  # noqa: E402
from playwright.sync_api import Error as PWError  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from suur_things_mcp import dashboard  # noqa: E402
from suur_things_mcp.dashboard import create_app  # noqa: E402
from suur_things_mcp.security import SecurityStore  # noqa: E402

pytestmark = pytest.mark.browser


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def dashboard_url():
    """Run the real dashboard on a random port in a background uvicorn thread."""
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(port), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("dashboard server did not start")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    """One headless Chromium for the module, or skip if the binary isn't installed."""
    with sync_playwright() as pw:
        try:
            br = pw.chromium.launch()
        except PWError as exc:  # binary missing → skip, don't fail
            pytest.skip(f"Chromium not installed (run `playwright install chromium`): {exc}")
        yield br
        br.close()


@pytest.fixture
def page(browser, dashboard_url):
    pg = browser.new_page()
    pg.goto(dashboard_url, wait_until="domcontentloaded")
    yield pg
    pg.close()


def test_repo_chip_title_safe_roundtrip(page):
    """Untrusted titles ride in an esc()'d data-title attribute (the v0.8.0 jsarg
    fix, superseded by the CSP no-inline-handlers refactor). A hostile title must
    round-trip intact for display and never become live markup."""
    payload = "x'+alert(1)+'y <img src=x onerror=alert(2)>"
    got = page.evaluate(
        """(s) => {
            const d = document.createElement('div');
            d.innerHTML = repoChipsHtml('uuid-1', 'project', s, []);
            const btn = d.querySelector('[data-rb=manage]');
            return { title: btn.dataset.title,
                     injected: d.querySelectorAll('img,script').length };
        }""",
        payload,
    )
    assert got["title"] == payload  # intact for display…
    assert got["injected"] == 0     # …but esc() flattened the hostile markup


def test_quickadd_guard_and_feedback(page):
    """createFromCard() locks the Add button + sets CREATING immediately, and a
    second call while in flight is a no-op (no duplicate submit). fetch is stubbed
    so the test creates no real Things task."""
    state = page.evaluate(
        """() => {
            // stub the network so /api/add never reaches the server (no real task)
            window.fetch = (url) => Promise.resolve({ json: () => Promise.resolve({ ok: true, uuid: null }) });
            openCreate('todo');
            document.querySelector('#f-title').value = '__BROWSERTEST__';
            createFromCard();                       // async; sync prelude runs now
            const b = document.querySelector('#ec-add');
            const first = { creating: CREATING, disabled: b.disabled, text: b.textContent };
            createFromCard();                       // re-entry must be ignored
            return { first, stillCreating: CREATING };
        }"""
    )
    assert state["first"]["creating"] is True
    assert state["first"]["disabled"] is True
    assert state["first"]["text"] in ("Adding…", "Adding image…")
    assert state["stillCreating"] is True  # guard held on the second call


def test_page_loads_without_js_exceptions(browser, dashboard_url):
    """The dashboard JS boots without throwing. Only uncaught exceptions
    (pageerror) count — not console logs, which include benign failed-request
    noise that differs between a machine with Things and CI without it."""
    pg = browser.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(dashboard_url, wait_until="networkidle")
    pg.close()
    assert not errors, f"uncaught JS exceptions on load: {errors}"


def _tailscale_dashboard_context(browser, tmp_path, monkeypatch, login):
    """Serve the real page at the Tailscale HTTPS origin while dispatching API
    calls through the real ASGI app. This permits Secure __Host cookies in a
    browser without binding a test TLS listener or requiring Things on Linux."""
    origin = "https://elliotts-mac-mini.tail43b447.ts.net"
    monkeypatch.setenv("SUUR_TAILSCALE_USERS", "elliott@example.com")
    backend = TestClient(create_app(security_store=SecurityStore(tmp_path / "security.sqlite")), base_url=origin)
    context = browser.new_context()
    context.set_extra_http_headers({"Tailscale-User-Login": login, "X-Forwarded-Proto": "https"})
    calls, protected_cookies = [], []

    def forward(route):
        request = route.request
        path = urlsplit(request.url).path
        if path == "/":
            route.fulfill(status=200, content_type="text/html", body=dashboard._index_html())
            return
        if not path.startswith("/api/"):
            route.abort()
            return
        calls.append(path)
        if path in {"/api/config", "/api/sidebar"}:
            protected_cookies.append(request.headers.get("cookie", ""))
        response = backend.request(request.method, path, headers=dict(request.headers), content=request.post_data)
        if path == "/api/session" and response.status_code == 200:
            browser_cookies = []
            for cookie in backend.cookies.jar:
                if cookie.name in {"__Host-suur-session", "__Host-suur-csrf"}:
                    browser_cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "url": origin,
                        "secure": True,
                        "httpOnly": cookie.name == "__Host-suur-session",
                        "sameSite": "Strict",
                    })
            context.add_cookies(browser_cookies)
        route.fulfill(status=response.status_code, content_type="application/json", body=response.text)

    context.route(f"{origin}/**", forward)
    return origin, backend, context, calls, protected_cookies


def test_startup_bootstraps_allowlisted_tailscale_session_before_protected_calls(browser, tmp_path, monkeypatch):
    """An allowlisted Tailscale browser uses the real bootstrap handler, receives
    its server-issued Secure cookies, then sends them on config/sidebar reads."""
    origin, backend, context, calls, protected_cookies = _tailscale_dashboard_context(
        browser, tmp_path, monkeypatch, "elliott@example.com"
    )
    page = context.new_page()
    page.goto(origin, wait_until="networkidle")
    page.close()
    context.close()
    backend.close()

    assert calls[:3] == ["/api/session", "/api/config", "/api/sidebar"]
    assert all("__Host-suur-session=" in cookie and "__Host-suur-csrf=" in cookie for cookie in protected_cookies)


def test_startup_rejects_unauthorized_tailscale_identity_and_stops(browser, tmp_path, monkeypatch):
    """A non-allowlisted Tailscale identity gets the real 401 response and the
    page makes no subsequent protected API calls."""
    origin, backend, context, calls, _protected_cookies = _tailscale_dashboard_context(
        browser, tmp_path, monkeypatch, "other@example.com"
    )
    page = context.new_page()
    page.goto(origin, wait_until="networkidle")
    content = page.locator("#content").inner_text()
    page.close()
    context.close()
    backend.close()

    assert calls == ["/api/session"]
    assert "Dashboard access was not authorized" in content


def test_create_card_title_field_is_visible(page):
    """The create card's title field must have a real height. It used to collapse
    to 0 (autoGrow measured scrollHeight while the card was hidden), so typed text
    went into Notes and Add silently bailed on an empty title."""
    page.evaluate("() => openCreate('todo')")
    page.wait_for_timeout(100)  # let openCreate's autoGrow setTimeout run
    geom = page.evaluate(
        """() => {
            const t = document.querySelector('#f-title');
            const n = document.querySelector('#f-notes');
            return { title: t.getBoundingClientRect().height,
                     notes: n.getBoundingClientRect().height };
        }"""
    )
    assert geom["title"] >= 20, f"title field collapsed (height={geom['title']})"
    assert geom["notes"] >= 20, f"notes field collapsed (height={geom['notes']})"


def test_auto_reload_on_version_mismatch(page):
    """When the server reports a different version than the page baked in, the
    page reloads itself (the auto-update mechanism). We stub fetch so /api/version
    reports a different version."""
    page.wait_for_load_state("load")  # let the INITIAL load finish before counting
    loads = []
    page.on("load", lambda *_: loads.append(1))
    stub = """(ver) => {
        const real = window.fetch;
        window.fetch = (url, opts) => String(url).includes('/api/version')
            ? Promise.resolve({json: () => Promise.resolve({ok:true, version: ver})})
            : real(url, opts);
    }"""
    # same version → must NOT reload
    page.evaluate(stub, page.evaluate("() => SERVER_VERSION"))
    page.evaluate("() => checkVersion()"); page.wait_for_timeout(300)
    assert not loads, "should not reload when version matches"
    # different version → must reload
    page.evaluate(stub, "mismatch-9.9.9")
    page.evaluate("() => checkVersion()"); page.wait_for_timeout(800)
    assert loads, "should reload when the server version changed"
