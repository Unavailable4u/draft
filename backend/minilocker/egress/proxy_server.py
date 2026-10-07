"""Egress proxy: HTTPS CONNECT only, domain allowlist, public IPs only,
JSON-lines decision log on stdout. Stdlib only; runs in its own container."""
import asyncio
import ipaddress
import json
import os
import socket
import time
from urllib.parse import urlsplit

ALLOW = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]
MAX_BYTES = int(os.environ.get("MAX_BYTES", 100_000_000))
CONN_TIMEOUT = int(os.environ.get("CONN_TIMEOUT", 120))
ALLOWED_PORTS = {443}


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
