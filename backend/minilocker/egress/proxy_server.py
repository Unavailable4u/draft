"""Egress proxy: HTTPS CONNECT only, domain allowlist, public IPs only,
JSON-lines decision log on stdout. Stdlib only; runs in its own container.

It is also the credential broker. A sandbox holds only a placeholder such as `mlk_placeholder_github`; to call an API that needs a
real credential it sends a plain request to `/_broker/<service>/<path>` on this proxy. The proxy, which is the only component
that holds the real token, makes the HTTPS request itself, adds the credential, and returns the answer. The sandbox never sees
the token, and the token is only ever sent to the one host configured for that service. What it does and does not do:
  * only the configured services exist, only to their one host, only over HTTPS on port 443, only to public IP addresses;
  * the sandbox's own headers are dropped (only Accept, Content-Type and User-Agent pass), so it cannot supply or override a
    credential, and the real token is replaced by the placeholder if an upstream echoes it back;
  * bodies and replies are size-capped, redirects are not followed, and every request is logged (service, host, method, path,
    status, sizes), never a credential.
It is a gateway for the services you configure, not a general proxy: it does not make a hijacked agent safe to hand a powerful
token. The token's own scope is the limit of what a hijacked agent can do with it."""
import asyncio
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

ALLOW = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]
MAX_BYTES = int(os.environ.get("MAX_BYTES", 100_000_000))
CONN_TIMEOUT = int(os.environ.get("CONN_TIMEOUT", 120))
ALLOWED_PORTS = {443}

# {service: {"host", "header", "prefix", "token", "placeholder"}}, set by the control plane, never visible to a sandbox.
BROKER = json.loads(os.environ.get("BROKER_SERVICES") or "{}")
ALIAS = os.environ.get("PROXY_ALIAS", "egress-proxy")
BROKER_MAX_BODY = 1_000_000
BROKER_MAX_REPLY = 5_000_000
BROKER_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
BROKER_PASS_REQUEST = {"accept", "content-type", "user-agent"}
BROKER_PASS_REPLY = {"content-type", "etag", "link", "retry-after", "last-modified"}


def host_allowed(host, allow):
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allow)


def is_public(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return ip.is_global and not ip.is_multicast


def log(**kw):
    print(json.dumps({"ts": time.time(), **kw}), flush=True)


async def public_ips(host, port):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return [], "unresolvable"
    ips = [sa[0] for _f, _t, _p, _c, sa in infos if is_public(sa[0])]
    if ips:
        return ips, None
    return [], "private_ip" if infos else "unresolvable"


async def deny(cw, client, host, port, method, reason):
    log(decision="blocked", client=client, host=host, port=port, method=method, reason=reason)
    try:
        cw.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await cw.drain()
    except Exception:
        pass
    finally:
        cw.close()


async def pump(reader, writer, stats, key):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            stats[key] += len(data)
            if stats["up"] + stats["down"] > MAX_BYTES:
                stats["capped"] = True
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def broker_target(target):
    """The /_broker/... path of a request addressed to this proxy (origin form, or absolute form as a client sends it when
    an HTTP proxy is configured), else None."""
    if target.startswith("/_broker/"):
        return target
    u = urlsplit(target)
    if (u.hostname or "").lower() in (ALIAS, "localhost") and u.path.startswith("/_broker/"):
        return u.path + ("?" + u.query if u.query else "")
    return None


def upstream_request(ip, host, method, path, headers, body):
    """One HTTPS request to the vetted `ip`, with certificate checks against `host`. Blocking; run in a thread. -> (status,
    reason, [(name, value)], bytes). A separate function so tests can replace it."""
    ctx = ssl.create_default_context()

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            self.sock = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=10), server_hostname=host)

    conn = Pinned(host, 443, timeout=20, context=ctx)
    try:
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read(BROKER_MAX_REPLY + 1)
        return r.status, r.reason, r.getheaders(), data
    finally:
        conn.close()


UPSTREAM = upstream_request


async def reply(cw, status, reason, headers, body):
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    head += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    cw.write(head.encode("latin-1", "replace") + body)
    await cw.drain()


async def broker(cr, cw, client, method, path, head):
    """Serve one /_broker request. Never raises to the caller."""
    def fail(status, reason, why, service=None, host=None):
        log(decision="blocked", client=client, host=host or "broker", port=443, method=method, reason=why, service=service)
        return reply(cw, status, reason, [("Content-Type", "application/json")],
                     json.dumps({"error": why}).encode())

    try:
        headers = {}
        for ln in head.split(b"\r\n")[1:]:
            k, sep, v = ln.partition(b":")
            if sep:
                headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
        rest = path[len("/_broker/"):]
        name, _, tail = rest.partition("/")
        svc = BROKER.get(name)
        if svc is None:
            return await fail(404, "Not Found", "broker_unknown_service")
        if method not in BROKER_METHODS:
            return await fail(405, "Method Not Allowed", "broker_method", name, svc["host"])
        try:
            n = int(headers.get("content-length") or 0)
        except ValueError:
            return await fail(400, "Bad Request", "broker_bad_length", name, svc["host"])
        if n < 0 or n > BROKER_MAX_BODY:
            return await fail(413, "Payload Too Large", "broker_body_too_large", name, svc["host"])
        body = await asyncio.wait_for(cr.readexactly(n), 15) if n else None
        ips, why = await public_ips(svc["host"], 443)
        if not ips:
            return await fail(502, "Bad Gateway", why, name, svc["host"])
        out = {k: v for k, v in headers.items() if k in BROKER_PASS_REQUEST}
        out.setdefault("user-agent", "minilocker-broker")
        out["accept-encoding"] = "identity"
        out[svc["header"].lower()] = svc.get("prefix", "") + svc["token"]
        upath = "/" + tail
        loop = asyncio.get_running_loop()
        status, reason_, rheaders, data = await asyncio.wait_for(
            loop.run_in_executor(None, UPSTREAM, ips[0], svc["host"], method, upath, out, body), 30)
        if len(data) > BROKER_MAX_REPLY:
            return await fail(502, "Bad Gateway", "broker_reply_too_large", name, svc["host"])
        token = svc["token"].encode()
        redacted = len(token) >= 8 and token in data
        if redacted:
            data = data.replace(token, svc["placeholder"].encode())
        keep = [(k, v) for k, v in rheaders if k.lower() in BROKER_PASS_REPLY or k.lower().startswith("x-ratelimit-")]
        await reply(cw, status, reason_ or "OK", keep, b"" if method == "HEAD" else data)
        log(decision="brokered", client=client, host=svc["host"], port=443, method=method, service=name,
            path=("/" + tail)[:200], status=status, bytes_up=len(body or b""), bytes_down=len(data),
            stripped=sorted(k for k in headers if k not in BROKER_PASS_REQUEST and k in ("authorization", svc["header"].lower())),
            redacted=redacted)
    except Exception as e:
        log(decision="blocked", client=client, host="broker", port=443, method=method,
            reason="broker_error:" + type(e).__name__)
        try:
            await reply(cw, 502, "Bad Gateway", [], b"")
        except Exception:
            pass
    finally:
        try:
            cw.close()
        except Exception:
            pass


async def handle(cr, cw):
    client = (cw.get_extra_info("peername") or ("?",))[0]
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
        method, target, _ver = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if method == "CONNECT":
            host, _, p = target.rpartition(":")
            port = int(p) if p.isdigit() else 0
        else:
            u = urlsplit(target)
            host, port = u.hostname or "", u.port or 80
        host = host.strip("[]")

        if method != "CONNECT":
            bp = broker_target(target) if BROKER else None
            if bp is not None:
                return await broker(cr, cw, client, method, bp, head)
            return await deny(cw, client, host, port, method, "only_https_connect")
        if port not in ALLOWED_PORTS:
            return await deny(cw, client, host, port, method, "port_not_allowed")
        if not host_allowed(host, ALLOW):
            return await deny(cw, client, host, port, method, "not_allowlisted")
        ips, why = await public_ips(host, port)
        if not ips:
            return await deny(cw, client, host, port, method, why)

        upstream = None
        for ip in ips:  # connect to the vetted IP, not the name (no DNS rebinding)
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
                break
            except Exception:
                continue
        if upstream is None:
            return await deny(cw, client, host, port, method, "connect_failed")

        ur, uw = upstream
        log(decision="allowed", client=client, host=host, port=port, method=method)
        cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await cw.drain()
        stats = {"up": 0, "down": 0}
        try:
            await asyncio.wait_for(
                asyncio.gather(pump(cr, uw, stats, "up"), pump(ur, cw, stats, "down")),
                CONN_TIMEOUT)
        except asyncio.TimeoutError:
            stats["timeout"] = True
        finally:
            for w in (uw, cw):
                try:
                    w.close()
                except Exception:
                    pass
        log(decision="closed", client=client, host=host, port=port,
            bytes_up=stats["up"], bytes_down=stats["down"],
            capped=stats.get("capped", False), timeout=stats.get("timeout", False))
    except Exception:
        try:
            cw.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 3128)
    log(decision="listening", allow=ALLOW)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
