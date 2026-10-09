"""The Attack Lab's hostile pages live on loopback inside the browser container. These tests pin
who may reach them. Docker-free: the real-browser proof is `pytest -m attacks` / sandbox.smoke."""
import json
from types import SimpleNamespace as NS

import pytest

import minilocker.sandbox.browser as browser_mod
import minilocker.sandbox.browser_worker as w
from minilocker.attacks.catalog import ATTACKS
from minilocker.attacks.runner import run_attack

PROXY = {"HTTPS_PROXY": "http://egress-proxy:3128"}


def playwright_proxies_loopback(proxy: dict) -> bool:
    """Mirror of Playwright 1.63.0 crBrowser.ts `shouldProxyLoopback` (read from the pinned wheel):
    Chromium's `<-loopback>` is forced, sending 127.0.0.1 through the proxy, unless the bypass
    list names a loopback host."""
    hosts = {h.strip() for h in (proxy.get("bypass") or "").split(",")}
    return not ({"localhost", "127.0.0.1", "::1", "[::]", "[::1]", "<loopback>", "<-loopback>"} & hosts)


def test_no_proxy_means_no_proxy_settings():
    assert w.proxy_settings({}) is None and w.proxy_settings({"HTTPS_PROXY": ""}) is None


def test_real_browsing_keeps_loopback_behind_the_proxy():
    p = w.proxy_settings(dict(PROXY))
    assert p == {"server": "http://egress-proxy:3128"}
    assert playwright_proxies_loopback(p)           # a page cannot reach anything on loopback


def test_fixtures_mode_lets_loopback_bypass_the_proxy_and_nothing_else():
    p = w.proxy_settings({**PROXY, "MINILOCKER_BROWSER_FIXTURES": "1"})
    assert p["server"] == "http://egress-proxy:3128"
    assert not playwright_proxies_loopback(p)       # this is what lets the fixture pages load
    assert set(p["bypass"].split(",")) <= {"127.0.0.1", "localhost"}   # no wildcard bypass of real hosts


@pytest.mark.parametrize("val,expected", [("1", True), ("0", False), ("", False), ("true", False), (None, False)])
def test_fixtures_are_off_unless_explicitly_one(val, expected):
    assert w.fixtures_enabled({} if val is None else {"MINILOCKER_BROWSER_FIXTURES": val}) is expected


class RecordingSandbox:
    made = []

    def __init__(self, **kw):
        RecordingSandbox.made.append(kw)
        self.name, self.ip, self.dead = "rec-browser", "10.0.0.9", False
        self.container = NS(reload=lambda: None, status="running")

    def exec_capped(self, argv, timeout_s, max_bytes):
        return NS(timed_out=False, truncated=False, exit_code=0, stdout=json.dumps({"ok": True}).encode())

    def destroy(self):
        pass


@pytest.mark.parametrize("fixtures", [False, True])
def test_browser_sandbox_sets_the_env_only_when_asked(monkeypatch, fixtures):
    RecordingSandbox.made = []
    monkeypatch.setattr(browser_mod, "image_present", lambda image=None: True)
    browser_mod.BrowserSandbox(egress=None, sandbox_cls=RecordingSandbox, fixtures=fixtures)
    kw = RecordingSandbox.made[0]
    assert (kw.get("extra_env") == {"MINILOCKER_BROWSER_FIXTURES": "1"}) is fixtures
    assert fixtures or "extra_env" not in kw


def test_only_browser_attacks_ask_for_fixtures(tmp_path):
    seen = {}

    def capture(task, llm, **kw):
        seen.update(kw)
        raise RuntimeError("stop: only the call arguments matter here")

    code = next(a for a in ATTACKS if not a.needs_browser)
    web = next(a for a in ATTACKS if a.needs_browser)
    run_attack(code, ledger_dir=str(tmp_path), runner=capture, sandbox_exists=lambda n: False)
    assert "browser_fixtures" not in seen
    seen.clear()
    run_attack(web, ledger_dir=str(tmp_path), runner=capture, sandbox_exists=lambda n: False,
               browser_available=True)
    assert seen.get("browser_fixtures") is True
