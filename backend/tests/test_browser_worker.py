"""Browser worker logic without Chromium: the Session runs against a fake page, the fixture
server and the socket client run for real, and the real fixture HTML is fed to the scanner."""
import base64
import json
import os
import re
import socket
import tempfile
import threading
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

import pytest

import minilocker.sandbox.browser_worker as w
from minilocker.policy.injection import scan

FIXTURES = Path(__file__).resolve().parents[2] / "images" / "browser" / "fixtures"


# ---- fakes ---------------------------------------------------------------------------
class FakeHandle:
    def __init__(self, label, tag="a", visible=True, href="", boom=None):
        self.label, self.tag, self.visible, self.href, self.boom = label, tag, visible, href, boom
        self.log = []

    def is_visible(self):
        return self.visible

    def evaluate(self, js):
        if self.boom:
            raise self.boom
        return {"tag": self.tag, "type": "", "label": self.label, "href": self.href, "name": ""}

    def click(self, timeout=0):
        self.log.append("click")

    def fill(self, text, timeout=0):
        self.log.append(("fill", text))

    def press(self, key, timeout=0):
        self.log.append(("press", key))


class FakePage:
    def __init__(self, text="hello", raw=None, extra="", elements=None, url="http://x.example/"):
        self.url, self.text, self.raw, self.extra = url, text, text if raw is None else raw, extra
        self.elements = elements if elements is not None else [FakeHandle("Link A", href="http://x.example/a"),
                                                              FakeHandle("hidden", visible=False),
                                                              FakeHandle("Search", tag="button")]
        self.closed, self.calls, self.fail = False, [], None

    def is_closed(self):
        return self.closed

    def goto(self, url, wait_until=None, timeout=0):
        self.calls.append(("goto", url))
        if self.fail:
            raise self.fail
        self.url = url
        return type("R", (), {"status": 200})()

    def go_back(self, **k):
        self.calls.append(("back",))

    def title(self):
        return "Title"

    def evaluate(self, js):
        return {w.JS_VISIBLE: self.text, w.JS_RAW: self.raw, w.JS_EXTRA: self.extra}[js]

    def query_selector_all(self, sel):
        return list(self.elements)

    def locator(self, sel):
        return type("L", (), {"first": self.elements[0]})()

    def screenshot(self, **k):
        return b"\xff\xd8\xff\xe0JPEGDATA"

    def wait_for_timeout(self, ms):
        self.calls.append(("wait", ms))


def sess(**kw):
    page = FakePage(**kw)
    return w.Session(page, new_page=lambda: FakePage(text="fresh")), page


# ---- url policy ------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://a.example", "https://a.example/p?q=1", "HTTP://A.EXAMPLE", "http://127.0.0.1:8099/x.html"])
def test_http_urls_are_accepted(url):
    assert w.check_url(url)[0]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,<b>", "chrome://settings",
                                 "view-source:http://a", "ftp://a/b", "about:blank", "", None, 5, "http://[::1", "x" * 2100])
def test_everything_else_is_refused(url):
    ok, why = w.check_url(url)
    assert not ok and why


def test_goto_refuses_before_touching_the_page():
    s, page = sess()
    r = s.handle({"action": "goto", "url": "file:///etc/passwd"})
    assert r["ok"] is False and "not allowed" in r["error"] and page.calls == []


# ---- actions --------------------------------------------------------------------------
def test_goto_returns_text_elements_screenshot_and_status():
    s, page = sess(text="Penguins", raw="Penguins hidden", extra="a comment")
    r = s.handle({"action": "goto", "url": "http://x.example/p"})
    assert r["ok"] and r["status"] == 200 and r["url"] == "http://x.example/p" and r["title"] == "Title"
    assert r["text"] == "Penguins" and r["raw_text"] == "Penguins hidden" and r["extra_text"] == "a comment"
    assert [e["label"] for e in r["elements"]] == ["Link A", "Search"], "invisible elements are not offered"
    assert [e["ref"] for e in r["elements"]] == [0, 1]
    assert base64.b64decode(r["screenshot_b64"]).startswith(b"\xff\xd8")


def test_extract_has_text_and_no_screenshot_and_screenshot_has_no_text():
    s, _ = sess()
    e = s.handle({"action": "extract"})
    assert e["ok"] and "text" in e and "screenshot_b64" not in e
    sh = s.handle({"action": "screenshot"})
    assert sh["ok"] and "screenshot_b64" in sh and "text" not in sh


def test_click_and_type_by_ref_use_the_element_from_the_last_listing():
    s, page = sess()
    s.handle({"action": "extract"})
    assert s.handle({"action": "click", "ref": 1})["ok"]
    assert page.elements[2].log == ["click"]
    s.handle({"action": "extract"})
    assert s.handle({"action": "type", "ref": 0, "text": "penguins", "submit": True})["ok"]
    assert page.elements[0].log == [("fill", "penguins"), ("press", "Enter")]


def test_refs_go_stale_after_navigation():
    s, _ = sess()
    s.handle({"action": "extract"})
    s.handle({"action": "goto", "url": "http://x.example/other"})
    s.refs = []                                                   # goto cleared them; the listing refilled below
    r = s.handle({"action": "click", "ref": 7})
    assert not r["ok"] and "unknown ref" in r["error"]


def test_click_needs_a_target_and_type_needs_text():
    s, _ = sess()
    assert "a selector" in s.handle({"action": "click"})["error"]
    assert "text is required" in s.handle({"action": "type", "ref": 0})["error"]
    assert "text is required" in s.handle({"action": "type", "selector": "#q", "text": "x" * 3000})["error"]


def test_selector_path():
    s, page = sess()
    assert s.handle({"action": "click", "selector": "text=Search"})["ok"]
    assert page.elements[0].log == ["click"]


@pytest.mark.parametrize("req", [None, [], {}, {"action": "rm -rf"}, {"action": 5}, "goto"])
def test_garbage_requests_are_rejected_not_crashed(req):
    r = w.Session(FakePage()).handle(req)
    assert r["ok"] is False and "unknown action" in r["error"]


def test_a_page_that_breaks_playwright_becomes_an_error_reply():
    s, page = sess()
    page.fail = TimeoutError("Timeout 15000ms exceeded")
    r = s.handle({"action": "goto", "url": "http://x.example/slow"})
    assert r["ok"] is False and "TimeoutError" in r["error"]
    s.page.elements = [FakeHandle("x", boom=RuntimeError("detached"))]
    s.page.fail = None
    assert s.handle({"action": "extract"})["elements"] == [], "one bad element does not sink the snapshot"


def test_wait_ms_is_clamped_and_junk_ignored():
    s, page = sess()
    s.handle({"action": "goto", "url": "http://x.example", "wait_ms": 10**9})
    s.handle({"action": "goto", "url": "http://x.example", "wait_ms": "banana"})
    s.handle({"action": "goto", "url": "http://x.example", "wait_ms": -5})
    assert [c for c in page.calls if c[0] == "wait"] == [("wait", w.MAX_WAIT_MS)]


def test_counters_report_everything_since_the_last_reply_and_never_drop_events():
    s, _ = sess()
    s.note("popups_blocked"); s.note("popups_blocked"); s.note("dialogs_dismissed")   # fired between calls
    first = s.handle({"action": "extract"})
    assert (first["popups_blocked"], first["dialogs_dismissed"]) == (2, 1)
    assert s.handle({"action": "extract"})["popups_blocked"] == 0, "reported once"
    s.note("popups_blocked")
    s.page.fail = None
    s.page.closed = False
    assert s.handle({"action": "goto", "url": "file:///x"})["ok"] is False   # refused early: nothing drained...
    assert s.handle({"action": "extract"})["popups_blocked"] == 1            # ...so the next reply still reports it


def test_closed_page_is_replaced_after_a_crash():
    s, page = sess()
    page.closed = True
    r = s.handle({"action": "extract"})
    assert r["ok"] and r["text"] == "fresh"


def test_text_is_bounded():
    s, _ = sess(text="a" * 100000, raw="b" * 200000, extra="c" * 50000)
    r = s.handle({"action": "extract"})
    assert (len(r["text"]), len(r["raw_text"]), len(r["extra_text"])) == (w.MAX_TEXT, w.MAX_RAW, w.MAX_EXTRA)


# ---- the fixture server: real, on loopback ----------------------------------------------
@pytest.fixture
def fixtures_server(monkeypatch):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    monkeypatch.setattr(w, "FIXTURES_DIR", str(FIXTURES))
    monkeypatch.setattr(w, "FIXTURES_PORT", port)
    srv = w.start_fixtures()
    yield port
    srv.shutdown(); srv.server_close()


def get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""


def test_fixture_server_serves_pages_but_no_index_and_no_traversal(fixtures_server):
    assert get(fixtures_server, "/clean.html")[0] == 200
    assert "Docker containers" in get(fixtures_server, "/injection.html")[1]
    assert get(fixtures_server, "/")[0] == 404, "no directory listing"
    assert get(fixtures_server, "/../../../etc/passwd")[0] == 404
    assert get(fixtures_server, "/%2e%2e/%2e%2e/etc/passwd")[0] == 404


# ---- RPC client against a stand-in worker socket ---------------------------------------
def test_call_roundtrip_over_a_unix_socket(monkeypatch, capsys):
    d = tempfile.mkdtemp(prefix="ml")                      # short path: AF_UNIX limit is ~100 chars
    path = os.path.join(d, "b.sock")
    srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1)
    seen = {}

    def serve_once():
        c, _ = srv.accept()
        buf = b""
        while not buf.endswith(b"\n"):
            buf += c.recv(4096)
        seen["req"] = json.loads(buf)
        c.sendall(json.dumps({"ok": True, "echo": seen["req"]["action"]}).encode() + b"\n"); c.close()
    t = threading.Thread(target=serve_once); t.start()
    monkeypatch.setattr(w, "SOCK", path)
    w.call(base64.b64encode(json.dumps({"action": "ping"}).encode()).decode())
    t.join(5); srv.close()
    assert json.loads(capsys.readouterr().out) == {"ok": True, "echo": "ping"} and seen["req"] == {"action": "ping"}


def test_call_reports_an_unreachable_worker_as_json(monkeypatch, capsys):
    monkeypatch.setattr(w, "SOCK", "/nonexistent/none.sock")
    w.call(base64.b64encode(b"{}").decode())
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "unreachable" in out["error"]


def test_call_survives_garbage_input(capsys):
    w.call("!!!not base64!!!")
    assert json.loads(capsys.readouterr().out)["ok"] is False


# ---- fixture <-> scanner contract ------------------------------------------------------
class Extract(HTMLParser):
    """Approximates the worker's three JS extractions on the fixture HTML."""
    HIDE = re.compile(r"display:\s*none|left:\s*-9999px")

    def __init__(self):
        super().__init__()
        self.visible, self.raw, self.extra, self.stack = [], [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.stack.append(bool(self.HIDE.search(a.get("style") or "")) or tag in ("script", "style"))
        for k in ("alt", "title", "aria-label", "placeholder"):
            if a.get(k):
                self.extra.append(a[k])

    def handle_endtag(self, tag):
        if self.stack:
            self.stack.pop()

    def handle_data(self, d):
        if any(s for s in self.stack if s) and self.stack and "script" in self.get_starttag_text():
            return
        self.raw.append(d)
        if not any(self.stack):
            self.visible.append(d)

    def handle_comment(self, d):
        self.extra.append(d)


def extract(name):
    p = Extract()
    src = (FIXTURES / name).read_text()
    src = re.sub(r"<script.*?</script>", "", src, flags=re.S)     # page JS is not page text
    p.feed(src)
    return " ".join(p.visible), " ".join(p.raw), "\n".join(p.extra)


def test_the_injection_fixture_is_flagged_including_its_hidden_parts():
    visible, raw, extra = extract("injection.html")
    r = scan(visible, raw=raw, extra=extra)
    assert r["suspected"] and r["score"] >= 90
    assert any(f["hidden"] for f in r["findings"]), r
    assert {"override", "exfil_instruction"} <= {f["rule"] for f in r["findings"]}


@pytest.mark.parametrize("name", ["clean.html", "clean2.html"])
def test_clean_fixtures_are_not_flagged(name):
    v, r, e = extract(name)
    assert not scan(v, raw=r, extra=e)["suspected"]


def test_probe_pages_carry_no_injection_text_so_they_test_containment_alone():
    for name in ("active_content.html", "local_files.html"):
        v, r, e = extract(name)
        assert not scan(v, raw=r, extra=e)["suspected"], name
