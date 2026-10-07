import socket
import time

import pytest

from airlock.agent.loop import run_task
from airlock.egress.manager import EgressManager
from airlock.egress.proxy_server import host_allowed, is_public
from airlock.sandbox.docker_provider import Sandbox
from test_agent_loop import FakeLLM, call, leaked

ALLOW = ["pypi.org", "files.pythonhosted.org"]


def online():
    try:
        socket.create_connection(("pypi.org", 443), 4).close()
        return True
    except OSError:
        return False


needs_net = pytest.mark.skipif(not online(), reason="host has no internet")


def test_host_allowed():
    assert host_allowed("pypi.org", ALLOW)
    assert host_allowed("sub.pypi.org", ALLOW)
    assert host_allowed("PyPI.org.", ALLOW)
    assert not host_allowed("evilpypi.org", ALLOW)
    assert not host_allowed("pypi.org.evil.example", ALLOW)


def test_is_public():
    for ip in ["127.0.0.1", "10.0.0.5", "172.17.0.2", "192.168.1.1", "169.254.169.254",
               "100.64.0.1", "0.0.0.0", "::1", "fe80::1"]:
        assert not is_public(ip), ip
    assert is_public("1.1.1.1")


@pytest.fixture(scope="module")
def egress():
    m = EgressManager(ALLOW).start()
    yield m
    m.stop()


def sandbox_run(egress, cmd, timeout=30):
    t0 = time.time()
    sb = Sandbox(egress=egress)
    try:
        r = sb.exec(cmd, timeout)
        time.sleep(0.5)
        return r, egress.events_for(sb.ip, t0)
    finally:
        sb.destroy()


def test_direct_connection_has_no_route(egress):
    cmd = ("python3 -c \"import urllib.request as u; "
           "u.build_opener(u.ProxyHandler({})).open('http://1.1.1.1', timeout=4)\"")
    r, _ = sandbox_run(egress, cmd)
    assert r.exit_code != 0


def test_non_allowlisted_blocked_and_logged(egress):
    r, evs = sandbox_run(
        egress, "python3 -c \"import urllib.request as u; u.urlopen('https://evil.example', timeout=8)\"")
    assert r.exit_code != 0
    blocked = [e for e in evs if e["decision"] == "blocked"]
    assert blocked and blocked[0]["host"] == "evil.example"
    assert blocked[0]["reason"] == "not_allowlisted"
    assert not [e for e in evs if e["decision"] == "allowed"]


def test_plain_http_refused_even_for_allowlisted_host(egress):
    r, evs = sandbox_run(
        egress, "python3 -c \"import urllib.request as u; u.urlopen('http://pypi.org', timeout=8)\"")
    assert r.exit_code != 0
    assert any(e["reason"] == "only_https_connect" for e in evs if e["decision"] == "blocked")


@needs_net
def test_allowlisted_pypi_reachable(egress):
    r, evs = sandbox_run(
        egress,
        "python3 -c \"import urllib.request as u; print(u.urlopen('https://pypi.org/simple/six/', timeout=15).status)\"",
        40)
    assert r.stdout.strip() == "200", r
    assert any(e["decision"] == "allowed" and e["host"] == "pypi.org" for e in evs)


@needs_net
def test_pip_install_works_only_via_allowlist(egress):
    cmd = ("pip install --no-cache-dir --disable-pip-version-check --target /workspace/pkgs six "
           ">/dev/null 2>&1; PYTHONPATH=/workspace/pkgs python3 -c 'import six; print(six.__version__)'")
    r, evs = sandbox_run(egress, cmd, 90)
    assert r.stdout.strip() != "", r
    hosts = {e["host"] for e in evs if e["decision"] == "allowed"}
    assert hosts and hosts <= set(ALLOW)


def test_agent_run_logs_egress_into_ledger(egress, tmp_path):
    llm = FakeLLM([
        [call("run_shell", cmd="python3 -c \"import urllib.request as u; "
                               "u.urlopen('https://evil.example', timeout=8)\" 2>&1 | tail -1")],
        [call("finish", summary="tried")],
    ])
    evs = []
    r = run_task("exfil", llm, ledger_dir=str(tmp_path), on_event=evs.append, egress=egress)
    assert r["ledger_verified"]
    blocked = [e for e in evs if e["type"] == "egress.blocked"]
    assert blocked and blocked[0]["payload"]["host"] == "evil.example"
    assert leaked() == []
