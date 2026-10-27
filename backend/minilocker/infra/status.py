"""What this control plane is running on and talking to, for the Infra screen.

Everything here is read-only and reported as found: a part that cannot be reached is `available: false` with a reason, never
guessed at. No secret is ever included (an API key is reported only as set / not set; a URL is reduced to its host).
"""
import json
import os
import platform
import shutil
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

METADATA_URL = "http://169.254.169.254/v1.json"      # Vultr's instance metadata service; link-local, answers only on a Vultr VM
METADATA_TTL_S = 120
_meta_cache = {"at": 0.0, "value": None}


def _host(url: str | None) -> str | None:
    try:
        return urlsplit(url or "").hostname
    except ValueError:
        return None


def _meminfo() -> dict:
    out = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    out[k] = int(v.split()[0]) * 1024
    except (OSError, ValueError):
        pass
    return out


def host_info() -> dict:
    mem = _meminfo()
    disk = shutil.disk_usage("/")
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        load = None
    uptime = None
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    return {"hostname": platform.node(), "os": platform.platform(terse=True), "cpus": os.cpu_count(), "load": load,
            "memory_total_bytes": mem.get("MemTotal"), "memory_available_bytes": mem.get("MemAvailable"),
            "disk_total_bytes": disk.total, "disk_free_bytes": disk.free, "uptime_s": uptime}


def docker_info(client=None) -> dict:
    try:
        if client is None:
            import docker
            client = docker.from_env(timeout=5)
        v, i = client.version(), client.info()
        boxes = client.containers.list(all=True, filters={"label": "minilocker=sandbox"})
        now = time.time()
        sandboxes = []
        for c in boxes:
            try:
                born = datetime.strptime((c.attrs.get("Created") or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                age = round(now - born.timestamp(), 1)
            except ValueError:
                age = None
            sandboxes.append({"name": c.name, "role": (c.labels or {}).get("minilocker.role", "code"),
                              "status": c.status, "age_s": age})
        return {"available": True, "version": v.get("Version"), "api_version": v.get("ApiVersion"),
                "storage_driver": i.get("Driver"), "cgroup_version": i.get("CgroupVersion"),
                "runtimes": sorted((i.get("Runtimes") or {}).keys()), "containers_running": i.get("ContainersRunning"),
                "sandboxes": sandboxes}
    except Exception as e:
        return {"available": False, "reason": type(e).__name__, "sandboxes": []}


def egress_info(egress) -> dict:
    if egress is None:
        return {"attached": False}
    out = {"attached": True, "allowed_hosts": sorted(getattr(egress, "allowed", None) or [])}
    try:
        out["brokered_services"] = sorted(egress.broker_services())
    except Exception:
        out["brokered_services"] = []
    try:
        c = egress.container
        c.reload()
        out["proxy"] = c.status
    except Exception:
        out["proxy"] = "unknown"
    return out


def inference_info(environ=None) -> dict:
    e = os.environ if environ is None else environ
    base = e.get("LLM_BASE_URL")
    host = _host(base)
    return {"configured": bool(base and e.get("LLM_MODEL") and e.get("LLM_API_KEY")), "host": host,
            "model": e.get("LLM_MODEL"), "key_set": bool(e.get("LLM_API_KEY")),
            "tool_mode": (e.get("LLM_TOOL_MODE") or "native"), "vultr": bool(host and host.endswith(("vultr.com", "vultrinference.com")))}


def storage_info(artifacts, error, environ=None) -> dict:
    e = os.environ if environ is None else environ
    return {"attached": artifacts is not None, "error": error, "endpoint_host": _host(e.get("MINILOCKER_S3_ENDPOINT")),
            "bucket": getattr(artifacts, "bucket", None) or e.get("MINILOCKER_S3_BUCKET") or None,
            "vultr": bool(_host(e.get("MINILOCKER_S3_ENDPOINT")) and _host(e.get("MINILOCKER_S3_ENDPOINT")).endswith("vultrobjects.com"))}


def vultr_metadata(fetch=None, now=None) -> dict:
    """The Vultr instance this runs on, from its metadata service. Cached; fails fast when the address does not answer
    (everywhere but a Vultr VM)."""
    now = (now or time.time)()
    if _meta_cache["value"] is not None and now - _meta_cache["at"] < METADATA_TTL_S:
        return _meta_cache["value"]
    try:
        if fetch is None:
            def fetch():
                with urllib.request.urlopen(METADATA_URL, timeout=0.6) as r:
                    return r.read(65536)
        raw = json.loads(fetch())
        value = {"available": True, "hostname": raw.get("hostname"), "region": (raw.get("region") or {}).get("regioncode"),
                 "plan": raw.get("plan"), "instance_id": raw.get("instanceid"),
                 "public_ipv4": ((raw.get("interfaces") or [{}])[0].get("ipv4") or {}).get("address")}
    except Exception as ex:
        value = {"available": False, "reason": "not a Vultr instance, or the metadata service did not answer"
                 if isinstance(ex, OSError) else type(ex).__name__}
    _meta_cache.update(at=now, value=value)
    return value


def collect(egress=None, artifacts=None, artifacts_error=None, docker_client=None, environ=None) -> dict:
    return {"collected_at": time.time(), "host": host_info(), "docker": docker_info(docker_client),
            "egress": egress_info(egress), "inference": inference_info(environ),
            "storage": storage_info(artifacts, artifacts_error, environ), "vultr": vultr_metadata()}
