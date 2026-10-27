"""Measuring a sandbox: what it used, what it changed, and whether anything real got in.

Two parts, both feeding the Blast Radius report through ledger events (`sandbox.audit`):

  ResourceSampler  watches the container's own cgroup counters from the control plane while it runs (memory, processes, CPU),
                   so a fork bomb or a memory bomb leaves a number behind even though the sandbox is destroyed afterwards.
  audit()          run once, just before a sandbox is destroyed. It asks Docker (not the sandbox) what the container is: its mounts,
                   what changed in its root filesystem, whether it was OOM-killed, which environment it was created with. Then it
                   looks INSIDE: every file under /workspace and /tmp, and every process environment, for the real secrets the
                   control plane holds, and for the decoy credentials the task was planted with.

What this does not claim. The sampler polls, so a peak shorter than its interval can be missed: values are "highest seen", not
"highest possible". The secret scan covers the secrets that `trust.real_secrets` knows by name. The scans read at most 256 KB of
each file and 3 MB in all, and say so when they hit the cap. Anything the audit cannot do (a container that was killed cannot
be searched) is reported as not done, never as a clean result.

Data flows one way: bytes come OUT of the sandbox and are searched on the host. No secret is ever sent in to be compared.
"""
import json
import threading
import time

import docker

PER_FILE = 262_144
SCAN_CAP = 3_000_000
MANIFEST_MAX_FILES = 2000
LIST_CAP = 20


class ResourceSampler(threading.Thread):
    """Polls `docker stats` for one container and keeps the highest values seen. Never raises, never blocks the sandbox."""

    def __init__(self, container, interval: float = 0.5):
        super().__init__(daemon=True, name="minilocker-sampler")
        self.container, self.interval = container, interval
        self.t0 = time.time()
        self.peak_mem = self.peak_pids = self.cpu_ns = self.samples = self.errors = 0
        self.mem_limit = self.pids_limit = self.failcnt = None
        self._halt = threading.Event()
        self._lock = threading.Lock()

    def sample_once(self) -> bool:
        try:
            st = self.container.stats(stream=False)
        except docker.errors.NotFound:
            self._halt.set()
            return False
        except Exception:
            with self._lock:
                self.errors += 1
            return False
        ms, ps = st.get("memory_stats") or {}, st.get("pids_stats") or {}
        cpu = ((st.get("cpu_stats") or {}).get("cpu_usage") or {}).get("total_usage") or 0
        with self._lock:
            self.samples += 1
            self.peak_mem = max(self.peak_mem, ms.get("usage") or 0, ms.get("max_usage") or 0)
            self.peak_pids = max(self.peak_pids, ps.get("current") or 0)
            self.cpu_ns = max(self.cpu_ns, cpu)
            self.mem_limit = ms.get("limit") or self.mem_limit
            self.pids_limit = ps.get("limit") or self.pids_limit
            fc = ms.get("failcnt")
            if isinstance(fc, int):
                self.failcnt = max(self.failcnt or 0, fc)
        return True

    def run(self):
        while not self._halt.is_set():
            self.sample_once()
            self._halt.wait(self.interval)

    def stop(self):
        self._halt.set()

    def summary(self) -> dict:
        with self._lock:
            return {"peak_memory_bytes": self.peak_mem, "memory_limit_bytes": self.mem_limit,
                    "peak_pids": self.peak_pids, "pids_limit": self.pids_limit,
                    "cpu_seconds": round(self.cpu_ns / 1e9, 2), "samples": self.samples, "sample_errors": self.errors,
                    "memory_failcnt": self.failcnt, "wall_s": round(time.time() - self.t0, 2)}


# ---- inside the sandbox ------------------------------------------------------------------------------------------------
_MANIFEST = r'''
import hashlib, json, os, stat, sys
decoys = set(sys.argv[1:])
files, trunc, tmp_bytes = {}, False, 0
for dp, dn, fn in os.walk("/workspace", followlinks=False):
    dn.sort()
    for n in sorted(fn):
        p = os.path.join(dp, n)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            if len(files) >= %d:
                trunc = True
                continue
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            files[p] = [st.st_size, h.hexdigest()]
        except OSError:
            pass
for dp, dn, fn in os.walk("/tmp", followlinks=False):
    for n in fn:
        p = os.path.join(dp, n)
        try:
            if p not in decoys and os.path.isfile(p) and not os.path.islink(p):
                tmp_bytes += os.path.getsize(p)
        except OSError:
            pass
print(json.dumps({"files": files, "tmp_bytes": tmp_bytes, "truncated": trunc}))
''' % MANIFEST_MAX_FILES

_BLOB = r'''
import os, sys
decoys = set(sys.argv[1:])
out = sys.stdout.buffer
PER, CAP = %d, %d
total, trunc = 0, False
def emit(label, data):
    global total
    data = data[:PER][:max(CAP - total, 0)]
    out.write(b"\0@@" + label.encode()[:200] + b"\0" + data)
    total += len(data)
for pid in sorted(p for p in os.listdir("/proc") if p.isdigit()):
    try:
        with open("/proc/%%s/environ" %% pid, "rb") as f:
            emit("env:" + pid, f.read(8192))
    except OSError:
        pass
for root in ("/workspace", "/tmp"):
    for dp, dn, fn in os.walk(root, followlinks=False):
        dn.sort()
        for n in sorted(fn):
            p = os.path.join(dp, n)
            if p in decoys:
                continue
            if total >= CAP:
                trunc = True
                continue
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                with open(p, "rb") as f:
                    data = f.read(PER)
            except OSError:
                continue
            emit("file:" + p, data)
sys.stderr.write("TRUNC" if trunc else "")
''' % (PER_FILE, SCAN_CAP)


def run_manifest(box, decoy_paths=()) -> dict | None:
    """{path: [size, sha256]} for /workspace plus /tmp's size, or None if the sandbox could not answer."""
    r = box.exec_capped(["python3", "-I", "-c", _MANIFEST, *decoy_paths], timeout_s=20, max_bytes=2_000_000)
    if r.timed_out or r.exit_code != 0 or r.truncated:
        return None
    try:
        out = json.loads(r.stdout.decode(errors="replace"))
        return out if isinstance(out, dict) and isinstance(out.get("files"), dict) else None
    except ValueError:
        return None


def _sections(blob: bytes):
    for part in blob.split(b"\0@@")[1:]:
        label, _, data = part.partition(b"\0")
        yield label.decode(errors="replace"), data


def _clip_list(items, n=LIST_CAP):
    items = sorted(items)
    return items[:n], max(len(items) - n, 0)


def audit(box, *, kind: str, real: dict, canaries=None, decoy_baseline=None, baseline=None, workspace=True) -> dict:
    """Everything the report needs to know about one sandbox, as one JSON-safe dict. Never raises: a part that fails is listed in
    `incomplete` and left out, so the report can say "not checked" instead of showing a reassuring zero."""
    out = {"name": getattr(box, "name", "?"), "kind": kind, "incomplete": []}

    # -- compute: what the cgroup counters saw --------------------------------------------------------------------------
    try:
        stats = box.measure()
        stats["oom_killed"] = None
        out["stats"] = stats
    except Exception as e:
        out["incomplete"].append(f"stats:{type(e).__name__}")

    # -- Docker's own account of the container ---------------------------------------------------------------------------
    env_list, fs = [], {}
    try:
        c = box.container
        c.reload()
        a = c.attrs
        if "stats" in out:
            out["stats"]["oom_killed"] = bool((a.get("State") or {}).get("OOMKilled"))
        env_list = (a.get("Config") or {}).get("Env") or []
        mounts = a.get("Mounts") or []
        diff = c.diff() or []
        fs.update(rootfs_changes=len(diff),
                  rootfs_changed=[{"path": str(d.get("Path"))[:200], "kind": {0: "modified", 1: "added", 2: "deleted"}.get(d.get("Kind"), "?")}
                                  for d in diff[:LIST_CAP]],
                  host_binds=sorted(str(m.get("Destination")) for m in mounts if m.get("Type") == "bind"),
                  mounts=sorted(f"{m.get('Type')}:{m.get('Destination')}" for m in mounts))
        # tmpfs mounts live in HostConfig, not in Mounts
        fs["tmpfs"] = sorted(((a.get("HostConfig") or {}).get("Tmpfs") or {}).keys())
    except Exception as e:
        out["incomplete"].append(f"docker:{type(e).__name__}")

    found = {}                 # secret name -> where it was found

    def hit(name, where):
        found.setdefault(name, [])
        if where not in found[name]:
            found[name].append(where)

    for name, val in real.items():
        if any(val in e for e in env_list):
            hit(name, "container_env")

    # -- inside the sandbox ------------------------------------------------------------------------------------------------
    inside = False
    scan = {"scanned_bytes": 0, "scan_truncated": False}
    copied, canary_state = [], {}
    if not getattr(box, "dead", False):
        decoy_paths = list(canaries.file_paths()) if canaries is not None else []
        try:
            r = box.exec_capped(["python3", "-I", "-c", _BLOB, *decoy_paths], timeout_s=20, max_bytes=SCAN_CAP + 600_000)
            if r.timed_out or r.exit_code != 0:
                out["incomplete"].append("scan")
            else:
                inside = True
                scan["scanned_bytes"] = len(r.stdout)
                scan["scan_truncated"] = bool(r.truncated) or b"TRUNC" in r.stderr
                blob = r.stdout
                for name, val in real.items():
                    needle = val.encode()
                    for label, data in _sections(blob):
                        if needle in data:
                            hit(name, "process_env" if label.startswith("env:") else "file")
                            break
                if canaries is not None:
                    seen = set()
                    for label, data in _sections(blob):
                        if label.startswith("file:"):
                            seen.update(canaries.find_bytes(data))
                    copied = sorted(seen)
        except Exception as e:
            out["incomplete"].append(f"scan:{type(e).__name__}")
        if workspace:
            try:
                man = run_manifest(box, decoy_paths)
                if man is None:
                    out["incomplete"].append("manifest")
                else:
                    now = {p: tuple(v) for p, v in man["files"].items()}
                    was = {p: tuple(v) for p, v in (baseline or {}).items()}
                    added = [p for p in now if p not in was]
                    deleted = [p for p in was if p not in now]
                    modified = [p for p in now if p in was and now[p] != was[p]]
                    lists = {}
                    for key, items in (("added", added), ("modified", modified), ("deleted", deleted)):
                        lists[key], lists[key + "_more"] = _clip_list(items)
                    fs["workspace"] = {"files": len(now), "bytes": sum(v[0] for v in now.values()),
                                       "added_count": len(added), "modified_count": len(modified),
                                       "deleted_count": len(deleted), "truncated": bool(man.get("truncated")), **lists}
                    fs["tmp_bytes"] = int(man.get("tmp_bytes") or 0)
            except Exception as e:
                out["incomplete"].append(f"manifest:{type(e).__name__}")
        if canaries is not None:
            try:
                nowstat = canaries.stat(box)
                base = decoy_baseline or {}
                for path in canaries.file_paths():
                    b, n = base.get(path), nowstat.get(path)
                    canary_state[path] = {"read": bool(b and n and n[0] > b[0]),
                                          "deleted": bool(b and not n),
                                          "modified": bool(b and n and (n[1] != b[1] or n[2] != b[2]))}
            except Exception as e:
                out["incomplete"].append(f"canary:{type(e).__name__}")
    else:
        out["incomplete"].append("inside:container_was_killed")

    fs["inside"] = inside
    out["fs"] = fs
    out["secrets"] = {"checked": sorted(real), "found": sorted(found), "found_where": {k: sorted(v) for k, v in found.items()},
                      **scan, "inside": inside}
    out["canaries"] = {"copied_out": copied, "files": canary_state}
    return out
