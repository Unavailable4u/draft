"""Browser worker. Runs INSIDE the browser sandbox container, never in the control plane.

  python -u /opt/browser_worker.py serve      container command: starts Chromium + a unix socket
  python /opt/browser_worker.py call <b64>    one RPC, used by the control plane via `docker exec`

There is deliberately no network listener for control: the control plane reaches this process
through `docker exec` and a unix socket inside the container, so nothing a hostile page can
reach (it can reach loopback) is a control channel.

Everything a page can influence (text, titles, link labels, URLs) is returned as data. The
control plane scans it, fences it and decides what the model sees; this process makes no
security decisions beyond refusing non-http(s) navigation and keeping the page contained.

Stdlib only at import time; Playwright is imported in serve() so the logic is unit-testable.
"""
import base64
import http.server
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

SOCK = "/tmp/browser.sock"
FIXTURES_DIR = "/fixtures"
FIXTURES_PORT = 8099
VIEWPORT = {"width": 1280, "height": 720}
MAX_TEXT, MAX_RAW, MAX_EXTRA, MAX_ELEMENTS = 12000, 30000, 6000, 40
NAV_TIMEOUT_MS, ACTION_TIMEOUT_MS, MAX_WAIT_MS = 15000, 8000, 5000
ALLOWED_SCHEMES = ("http", "https")
ACTIONS = ("ping", "goto", "back", "click", "type", "extract", "screenshot")

CHROMIUM_ARGS = [
    # Chromium's own sandbox needs user namespaces / setuid helpers, which the container
    # deliberately does not have (cap_drop ALL, no-new-privileges). So the CONTAINER is the
    # boundary here: see SECURITY notes in docs/week3-browser-artifacts.md.
    "--no-sandbox",
    "--disable-gpu", "--disable-extensions", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--disable-breakpad",
    "--no-first-run", "--mute-audio", "--disable-default-apps",
]

JS_VISIBLE = "() => (document.body ? document.body.innerText : '')"
JS_RAW = """() => {
  if (!document.body) return '';
  const c = document.body.cloneNode(true);
  c.querySelectorAll('script,style,noscript,template').forEach(n => n.remove());
  return c.textContent || '';
}"""
JS_EXTRA = """() => {
  const out = [];
  document.querySelectorAll('[alt],[title],[aria-label],[placeholder]').forEach(e => {
    for (const a of ['alt', 'title', 'aria-label', 'placeholder']) {
      const v = e.getAttribute(a); if (v) out.push(v);
    }
  });
  const m = document.querySelector('meta[name=description]');
  if (m && m.content) out.push(m.content);
  const w = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while (w.nextNode()) out.push(w.currentNode.nodeValue);
  return out.join('\\n');
}"""
JS_ELEMENT = """e => ({
  tag: e.tagName.toLowerCase(), type: e.type || '',
  label: ((e.innerText || e.value || e.getAttribute('aria-label') || e.placeholder || e.title || '') + '').trim().slice(0, 80),
  href: e.href || '', name: e.name || ''
})"""
INTERACTIVE = "a[href], button, input:not([type=hidden]), select, textarea, [role=button]"


def check_url(url):
    """(ok, reason). Only http(s): file:, data:, javascript:, chrome:, view-source: ... are refused."""
    if not isinstance(url, str) or not url or len(url) > 2000:
        return False, "a url is required (max 2000 characters)"
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return False, "malformed url"
    if scheme not in ALLOWED_SCHEMES:
        return False, f"{scheme or 'no'}: URLs are not allowed; only http and https"
    return True, ""


def _clip(s, n):
    s = s if isinstance(s, str) else str(s)
    return s if len(s) <= n else s[:n]


class Session:
    """All browser actions on one page. `page` follows Playwright's sync API; `new_page` makes a
    fresh page after a crash. Popups, dialogs and downloads are counted by the callbacks the
    caller wires to `note`."""

    def __init__(self, page, new_page=None):
        self.page, self.new_page = page, new_page
        self.refs = []
        self.counters = {"popups_blocked": 0, "dialogs_dismissed": 0, "downloads_blocked": 0}
        self._reported = dict(self.counters)

    def note(self, what):
        self.counters[what] = self.counters.get(what, 0) + 1

    # ---- dispatch ---------------------------------------------------------------
    def handle(self, req):
        if not isinstance(req, dict) or req.get("action") not in ACTIONS:
            return {"ok": False, "error": f"unknown action; expected one of {', '.join(ACTIONS)}"}
        action = req["action"]
        if action == "ping":
            return {"ok": True}
        try:
            self._ensure_page()
            if action == "goto":
                ok, why = check_url(req.get("url"))
                if not ok:
                    return {"ok": False, "error": why}
                resp = self.page.goto(req["url"], wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                self.refs = []
                status = getattr(resp, "status", None)
            elif action == "back":
                self.page.go_back(wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                self.refs, status = [], None
            elif action == "click":
                self._target(req).click(timeout=ACTION_TIMEOUT_MS)
                self.refs, status = [], None
            elif action == "type":
                self._type(req)
                self.refs, status = [], None
            else:                                   # extract / screenshot
                status = None
            self._wait(req.get("wait_ms"))
            out = self._snapshot(want_text=action != "screenshot",
                                 want_shot=action in ("goto", "back", "click", "type", "screenshot")
                                 and req.get("shot", True))
            out["status"] = status
        except Exception as e:                       # a hostile page may break anything
            return {"ok": False, "error": _clip(f"{type(e).__name__}: {e}", 300), **self._since_last_reply()}
        out["ok"] = True
        out.update(self._since_last_reply())
        return out

    def _since_last_reply(self):
        """Popups etc. that happened since the previous reply. Hostile pages fire them from
        timers, between calls, so counting only inside a call would silently drop them."""
        d = {k: self.counters[k] - self._reported.get(k, 0) for k in self.counters}
        self._reported = dict(self.counters)
        return d

    # ---- helpers ----------------------------------------------------------------
    def _ensure_page(self):
        try:
            closed = self.page.is_closed()
        except Exception:
            closed = True
        if closed and self.new_page:
            self.page, self.refs = self.new_page(), []

    def _wait(self, ms):
        try:
            ms = max(0, min(int(ms or 0), MAX_WAIT_MS))
        except (TypeError, ValueError):
            ms = 0
        if ms:
            self.page.wait_for_timeout(ms)

    def _target(self, req):
        if req.get("ref") is not None:
            try:
                return self.refs[int(req["ref"])]
            except (ValueError, TypeError, IndexError):
                raise ValueError("unknown ref; run extract to get a fresh element list") from None
        sel = req.get("selector")
        if not isinstance(sel, str) or not sel or len(sel) > 300:
            raise ValueError("give a ref (from the element list) or a selector")
        return self.page.locator(sel).first

    def _type(self, req):
        text = req.get("text")
        if not isinstance(text, str) or len(text) > 2000:
            raise ValueError("text is required (max 2000 characters)")
        t = self._target(req)
        t.fill(text, timeout=ACTION_TIMEOUT_MS)
        if req.get("submit"):
            t.press("Enter", timeout=ACTION_TIMEOUT_MS)

    def _elements(self):
        self.refs, out = [], []
        for h in self.page.query_selector_all(INTERACTIVE)[: MAX_ELEMENTS * 3]:
            if len(self.refs) >= MAX_ELEMENTS:
                break
            try:
                if not h.is_visible():
                    continue
                info = h.evaluate(JS_ELEMENT)
            except Exception:
                continue
            out.append({"ref": len(self.refs), "tag": _clip(info.get("tag", ""), 12),
                        "type": _clip(info.get("type", ""), 20), "label": _clip(info.get("label", ""), 80),
                        "href": _clip(info.get("href", ""), 200), "name": _clip(info.get("name", ""), 40)})
            self.refs.append(h)
        return out

    def _snapshot(self, want_text=True, want_shot=True):
        out = {"url": _clip(self.page.url, 500)}
        try:
            out["title"] = _clip(self.page.title(), 200)
        except Exception:
            out["title"] = ""
        if want_text:
            out["text"] = _clip(self.page.evaluate(JS_VISIBLE), MAX_TEXT)
            out["raw_text"] = _clip(self.page.evaluate(JS_RAW), MAX_RAW)
            out["extra_text"] = _clip(self.page.evaluate(JS_EXTRA), MAX_EXTRA)
            out["elements"] = self._elements()
        if want_shot:
            try:
                png = self.page.screenshot(type="jpeg", quality=60, timeout=ACTION_TIMEOUT_MS)
                out["screenshot_b64"] = base64.b64encode(png).decode()
            except Exception as e:
                out["screenshot_error"] = _clip(f"{type(e).__name__}", 60)
        return out


# ---- fixtures: hostile pages served on loopback INSIDE the container ----------------------
class _Fixtures(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=FIXTURES_DIR, **k)

    def list_directory(self, path):          # no index pages
        self.send_error(404)

    def log_message(self, *a):
        pass


def start_fixtures():
    if not os.path.isdir(FIXTURES_DIR):
        return None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", FIXTURES_PORT), _Fixtures)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---- process entry points ------------------------------------------------------------------
def serve():
    from playwright.sync_api import sync_playwright   # imported here: see module docstring

    start_fixtures()
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True, args=CHROMIUM_ARGS,
                                 proxy={"server": proxy} if proxy else None)
    ctx = browser.new_context(viewport=VIEWPORT, accept_downloads=False, service_workers="block",
                              java_script_enabled=True, permissions=[])
    ctx.set_default_timeout(ACTION_TIMEOUT_MS)
    sess = Session(ctx.new_page(), new_page=ctx.new_page)

    def wire(page):
        page.on("dialog", lambda d: (sess.note("dialogs_dismissed"), d.dismiss()))
        page.on("download", lambda d: (sess.note("downloads_blocked"), d.cancel()))

    def on_new_page(p):
        # A popup has an opener; the replacement page we make ourselves after a crash does not.
        if p.opener() is not None:
            sess.note("popups_blocked")
            try:
                p.close()
            except Exception:
                pass
        else:
            wire(p)
    ctx.on("page", on_new_page)
    wire(sess.page)

    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o600)
    srv.listen(4)
    while True:                                # one request per connection, handled in order
        conn, _ = srv.accept()
        with conn:
            try:
                buf = b""
                while not buf.endswith(b"\n") and len(buf) < 65536:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                res = sess.handle(json.loads(buf or b"{}"))
            except Exception as e:
                res = {"ok": False, "error": _clip(f"{type(e).__name__}: {e}", 200)}
            conn.sendall(json.dumps(res).encode() + b"\n")


def call(b64):
    """Client side: forward one request to serve() and print the JSON reply."""
    try:
        req = json.loads(base64.b64decode(b64))
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(60)
        c.connect(SOCK)
        c.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
        sys.stdout.write(buf.decode() or json.dumps({"ok": False, "error": "empty reply"}))
    except Exception as e:
        sys.stdout.write(json.dumps({"ok": False, "error": f"worker unreachable: {type(e).__name__}"}))


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) >= 3 and sys.argv[1] == "call":
        call(sys.argv[2])
    else:
        sys.exit("usage: browser_worker.py serve | call <base64-json>")
