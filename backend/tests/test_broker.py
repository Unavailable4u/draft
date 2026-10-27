"""The credential broker inside the egress proxy, run in-process: a real asyncio server speaking HTTP, with the upstream HTTPS
request replaced by a recorder (so no network and no Docker). What is proved: the sandbox never has to hold a credential, the
credential is added only on the way upstream and only for the configured host, the sandbox cannot supply its own, an upstream
that echoes the token gets it replaced, and the ledger-facing log line never carries it.
"""
import asyncio
import json

import pytest

from minilocker.egress import manager, proxy_server as ps

TOKEN = "ghp_realtokenrealtokenrealtoken123456"
SVC = {"github": {"host": "api.github.com", "header": "Authorization", "prefix": "Bearer ", "token": TOKEN,
                   "placeholder": "mlk_placeholder_github"},
       "plain": {"host": "api.example.org", "header": "X-Api-Key", "prefix": "", "token": "k" * 20,
                 "placeholder": "mlk_placeholder_plain"}}


class Rig:
    def __init__(self, monkeypatch, upstream):
        self.calls, self.logs = [], []
        monkeypatch.setattr(ps, "BROKER", SVC)
        monkeypatch.setattr(ps, "log", lambda **kw: self.logs.append(kw))

        async def public(host, port):
            return (["93.184.216.34"], None) if host != "private.example" else ([], "private_ip")
        monkeypatch.setattr(ps, "public_ips", public)

        def up(ip, host, method, path, headers, body):
            self.calls.append({"ip": ip, "host": host, "method": method, "path": path, "headers": dict(headers), "body": body})
            return upstream(method, path, headers, body)
        monkeypatch.setattr(ps, "UPSTREAM", up)

    async def request(self, raw: bytes):
        server = await asyncio.start_server(ps.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(raw)
            await w.drain()
            data = await asyncio.wait_for(r.read(), 10)
            w.close()
        finally:
            server.close()
            await server.wait_closed()
        head, _, body = data.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1]) if head else 0
        return status, head.decode("latin-1"), body


def ok_upstream(method, path, headers, body):
    return 200, "OK", [("Content-Type", "application/json"), ("Set-Cookie", "s=1"), ("X-RateLimit-Remaining", "9")], b'{"login":"octo"}'


def get(path, extra=""):
    return f"GET {path} HTTP/1.1\r\nHost: egress-proxy\r\n{extra}\r\n".encode()


def run(coro):
    return asyncio.run(coro)


def test_the_credential_is_added_upstream_and_never_comes_back(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    status, head, body = run(rig.request(get("/_broker/github/user")))
    assert status == 200 and json.loads(body) == {"login": "octo"}
    up = rig.calls[0]
    assert up["host"] == "api.github.com" and up["path"] == "/user" and up["ip"] == "93.184.216.34"
    assert up["headers"]["authorization"] == f"Bearer {TOKEN}"
    assert "Set-Cookie" not in head and "X-RateLimit-Remaining: 9" in head     # only whitelisted reply headers pass
    line = next(l for l in rig.logs if l["decision"] == "brokered")
    assert line["service"] == "github" and line["host"] == "api.github.com" and line["status"] == 200
    assert TOKEN not in json.dumps(rig.logs) and TOKEN not in head + body.decode()


def test_the_sandbox_cannot_supply_or_override_a_credential(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    run(rig.request(get("/_broker/github/user", "Authorization: Bearer attacker-token\r\nCookie: a=b\r\nX-Forwarded-For: 1.2.3.4\r\n")))
    sent = rig.calls[0]["headers"]
    assert sent["authorization"] == f"Bearer {TOKEN}"
    assert "cookie" not in sent and "x-forwarded-for" not in sent
    line = next(l for l in rig.logs if l["decision"] == "brokered")
    assert line["stripped"] == ["authorization"]            # recorded that the sandbox tried
    assert "attacker-token" not in json.dumps(rig.logs)


def test_a_custom_header_service_sends_the_bare_token(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    run(rig.request(get("/_broker/plain/v1/things?limit=2")))
    up = rig.calls[0]
    assert up["host"] == "api.example.org" and up["path"] == "/v1/things?limit=2"
    assert up["headers"]["x-api-key"] == "k" * 20 and "authorization" not in up["headers"]


def test_an_upstream_that_echoes_the_token_has_it_replaced(monkeypatch):
    rig = Rig(monkeypatch, lambda m, p, h, b: (200, "OK", [("Content-Type", "text/plain")], f"your token is {TOKEN}".encode()))
    status, head, body = run(rig.request(get("/_broker/github/debug")))
    assert TOKEN.encode() not in body and b"mlk_placeholder_github" in body
    assert next(l for l in rig.logs if l["decision"] == "brokered")["redacted"] is True


def test_unknown_service_and_bad_methods_are_refused_and_logged(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    assert run(rig.request(get("/_broker/nope/x")))[0] == 404
    assert run(rig.request(b"TRACE /_broker/github/x HTTP/1.1\r\nHost: p\r\n\r\n"))[0] == 405
    assert rig.calls == []
    assert {l["reason"] for l in rig.logs} == {"broker_unknown_service", "broker_method"}


def test_oversized_and_malformed_bodies_never_reach_upstream(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    big = f"POST /_broker/github/x HTTP/1.1\r\nHost: p\r\nContent-Length: {ps.BROKER_MAX_BODY + 1}\r\n\r\n".encode()
    assert run(rig.request(big))[0] == 413
    bad = b"POST /_broker/github/x HTTP/1.1\r\nHost: p\r\nContent-Length: abc\r\n\r\n"
    assert run(rig.request(bad))[0] == 400
    assert rig.calls == []


def test_a_post_body_is_forwarded(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    raw = b"POST /_broker/github/gists HTTP/1.1\r\nHost: p\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"
    assert run(rig.request(raw))[0] == 200
    assert rig.calls[0]["body"] == b'{"a":1}' and rig.calls[0]["method"] == "POST"


def test_a_service_host_that_resolves_to_a_private_address_is_refused(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    monkeypatch.setitem(ps.BROKER, "internal", {"host": "private.example", "header": "Authorization", "prefix": "Bearer ",
                                                "token": "t" * 20, "placeholder": "mlk_placeholder_internal"})
    assert run(rig.request(get("/_broker/internal/x")))[0] == 502
    assert rig.calls == [] and rig.logs[-1]["reason"] == "private_ip"


def test_an_upstream_error_is_a_502_and_leaks_nothing(monkeypatch):
    def boom(*a):
        raise RuntimeError(f"connection failed using {TOKEN}")
    rig = Rig(monkeypatch, boom)
    status, head, body = run(rig.request(get("/_broker/github/user")))
    assert status == 502 and TOKEN not in head + body.decode() + json.dumps(rig.logs)


def test_absolute_form_requests_to_the_proxy_are_brokered_too(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    assert run(rig.request(get("http://egress-proxy:8888/_broker/github/user")))[0] == 200


def test_ordinary_plain_http_is_still_refused(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    assert run(rig.request(get("http://evil.example/steal")))[0] == 403
    assert rig.logs[-1]["reason"] == "only_https_connect" and rig.calls == []


def test_without_a_broker_configured_the_path_is_just_refused(monkeypatch):
    rig = Rig(monkeypatch, ok_upstream)
    monkeypatch.setattr(ps, "BROKER", {})
    assert run(rig.request(get("/_broker/github/user")))[0] == 403 and rig.calls == []


# ---- configuration -------------------------------------------------------------------------------------------------------
def test_broker_config_needs_a_token_a_sane_name_and_a_public_looking_host():
    env = {"MINILOCKER_BROKER": "github=api.github.com, bad name=x.com, nohost=, noToken=a.example.com, ip=10.0.0.1,"
                                "x=api.x.com:X-Key",
           "MINILOCKER_BROKER_TOKEN_GITHUB": TOKEN, "MINILOCKER_BROKER_TOKEN_X": "z" * 12, "MINILOCKER_BROKER_TOKEN_IP": "q" * 12}
    got = manager.broker_from_env(env)
    assert sorted(got) == ["github", "x"]
    assert got["github"]["header"] == "Authorization" and got["github"]["prefix"] == "Bearer "
    assert got["x"]["header"] == "X-Key" and got["x"]["prefix"] == ""
    assert manager.broker_from_env({}) == {}
    assert manager.broker_from_env({"MINILOCKER_BROKER": "github=api.github.com", "MINILOCKER_BROKER_TOKEN_GITHUB": "short"}) == {}


def test_the_sandbox_environment_gets_placeholders_and_the_proxy_container_gets_the_tokens(monkeypatch):
    class Fake(manager.EgressManager):
        def __init__(self):
            self.allowed, self.packaged, self.image, self.container = [], False, "x", None
            self.broker = manager.broker_from_env({"MINILOCKER_BROKER": "github=api.github.com",
                                                   "MINILOCKER_BROKER_TOKEN_GITHUB": TOKEN})
    f = Fake()
    env = f.proxy_env()
    assert env["MINILOCKER_TOKEN_GITHUB"] == "mlk_placeholder_github" and env["MINILOCKER_BROKER_URL"].endswith("/_broker")
    assert TOKEN not in json.dumps(env) and f.broker_services() == {"github": "api.github.com"}
