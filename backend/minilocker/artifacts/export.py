"""Save what the agent left in /workspace before the sandbox is destroyed.

The exporter script runs INSIDE the sandbox, so everything it prints is attacker-controlled.
Hence a deliberately dumb wire format (one JSON header line, then exactly n raw bytes) and a
strict host-side parser: it never extracts anything onto the host filesystem, caps counts and
sizes itself, and only accepts plain relative names. A hostile sandbox can at worst produce
files full of garbage in its own task's namespace.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from minilocker.artifacts.store import MAX_DEPTH, valid_name

MAX_FILES = 60
MAX_FILE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_HEADER = 4096
# Directories that are noise rather than output (pip --target pkgs, caches, VCS metadata).
SKIP_DIRS = ("pkgs", "node_modules", ".git", "__pycache__", ".cache", ".venv", "venv",
             "site-packages", ".pytest_cache", ".npm")

def build_script(root="/workspace", max_files=MAX_FILES, max_file=MAX_FILE_BYTES,
                 max_total=MAX_TOTAL_BYTES) -> str:
    """The program that runs inside the sandbox. Parameterised so tests can point it at a tmp dir."""
    return f'''
import json, os, stat, sys
ROOT = {root!r}
MAX_FILES, MAX_FILE, MAX_TOTAL = {max_files}, {max_file}, {max_total}
SKIP = set({list(SKIP_DIRS)!r})
out = sys.stdout.buffer
def head(o):
    out.write(json.dumps(o, separators=(",", ":")).encode() + b"\\n")
n = total = 0
for dp, dns, fns in os.walk(ROOT, followlinks=False):
    dns[:] = sorted(d for d in dns if d not in SKIP and not os.path.islink(os.path.join(dp, d)))
    for fn in sorted(fns):
        p = os.path.join(dp, fn)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            rel = os.path.relpath(p, ROOT)
            if st.st_size > MAX_FILE:
                head({{"skip": rel, "reason": "too_large", "n": st.st_size}}); continue
            if n >= MAX_FILES or total + st.st_size > MAX_TOTAL:
                head({{"skip": rel, "reason": "limit", "n": st.st_size}}); continue
            with open(p, "rb") as f:
                data = f.read(MAX_FILE + 1)
        except OSError:
            continue
        if len(data) > MAX_FILE:
            head({{"skip": rel, "reason": "too_large", "n": len(data)}}); continue
        head({{"p": rel, "n": len(data)}}); out.write(data); n += 1; total += len(data)
out.flush()
'''


EXPORT_SCRIPT = build_script()

_BAD_CHARS = re.compile(r"[^\w.+@,=()\[\] -]")


@dataclass
class Exported:
    files: list = field(default_factory=list)      # [(clean_name, bytes)]
    skipped: list = field(default_factory=list)    # [{"name", "reason", "bytes"}]
    problems: list = field(default_factory=list)


def clean_name(rel) -> str | None:
    """Make an untrusted relative path safe to use as an object name, or None to reject it.
    Traversal and absolute paths are rejected outright (a well-behaved exporter never emits
    them); odd characters are replaced."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or len(rel) > 600:
        return None
    segs = rel.split("/")
    if len(segs) > MAX_DEPTH or any(s in ("", ".", "..") for s in segs):
        return None
    out = []
    for s in segs:
        s = _BAD_CHARS.sub("_", s)[:120]
        if not re.match(r"\w", s):
            s = "_" + s[1:] if s else "_"
        out.append(s)
    name = "/".join(out)
    return name if valid_name(name) else None


def _unique(name, taken):
    if name not in taken:
        return name
    stem, dot, ext = name.rpartition(".")
    for i in range(2, 1000):
        cand = f"{stem}-{i}.{ext}" if dot and stem and "/" not in ext else f"{name}-{i}"
        if cand not in taken:
            return cand
    return name + "-x"


def parse_export(raw: bytes, max_files=MAX_FILES, max_file=MAX_FILE_BYTES,
                 max_total=MAX_TOTAL_BYTES) -> Exported:
    ex, pos, total, taken = Exported(), 0, 0, set()
    while pos < len(raw):
        nl = raw.find(b"\n", pos, pos + MAX_HEADER + 1)
        if nl < 0:
            ex.problems.append("malformed header; rest of the export ignored")
            break
        try:
            h = json.loads(raw[pos:nl])
            if not isinstance(h, dict):
                raise ValueError
        except ValueError:
            ex.problems.append("unparseable header; rest of the export ignored")
            break
        pos = nl + 1
        if "skip" in h:
            name = clean_name(h.get("skip")) or "(unnamed)"
            n = h.get("n")
            ex.skipped.append({"name": name, "reason": str(h.get("reason", "limit"))[:20],
                               "bytes": n if isinstance(n, int) and n >= 0 else None})
            continue
        name, n = clean_name(h.get("p")), h.get("n")
        if name is None or not isinstance(n, int) or isinstance(n, bool) or n < 0:
            ex.problems.append("rejected a file with an invalid name or size; rest ignored")
            break   # framing can no longer be trusted
        if n > max_file or pos + n > len(raw):
            ex.problems.append(f"{name}: size is out of bounds; rest of the export ignored")
            break
        data = raw[pos:pos + n]
        pos += n
        if len(ex.files) >= max_files or total + n > max_total:
            ex.skipped.append({"name": name, "reason": "limit", "bytes": n})
            continue
        name = _unique(name, taken)
        taken.add(name)
        ex.files.append((name, data))
        total += n
    return ex


def _clip(s, n=200):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(s))[:n]


def export_workspace(sb, store, task_id, log, timeout_s=20) -> dict:
    """Best effort and never raises: losing artifacts must not turn a finished task into a crash.
    `log(actor, type, payload)` writes ledger events, so every stored object is hash-committed."""
    stored = skipped = 0
    try:
        r = sb.exec_capped(["python3", "-I", "-c", EXPORT_SCRIPT], timeout_s=timeout_s,
                           max_bytes=MAX_TOTAL_BYTES + 200_000)
        if r.timed_out or r.exit_code != 0:
            log("artifact", "artifact.export_failed",
                {"reason": "timeout" if r.timed_out else f"exit {r.exit_code}",
                 "detail": _clip(r.stderr.decode(errors="replace"), 200)})
            return {"stored": 0, "skipped": 0}
        ex = parse_export(r.stdout)
        if r.truncated:
            ex.problems.append("export exceeded the output cap and was truncated")
        for name, data in ex.files:
            key = f"workspace/{name}"
            try:
                info = store.put(task_id, key, data)
            except Exception as e:
                log("artifact", "artifact.failed", {"name": key, "error": type(e).__name__})
                continue
            log("artifact", "artifact.stored", {"name": key, "kind": "file", "bytes": info["bytes"],
                                                "sha256": info["sha256"]})
            stored += 1
        for s in ex.skipped:
            log("artifact", "artifact.skipped", {"name": _clip(s["name"]), "reason": s["reason"],
                                                 "bytes": s["bytes"]})
            skipped += 1
        if ex.problems:
            log("artifact", "artifact.export_failed", {"reason": "partial", "detail": _clip("; ".join(ex.problems), 300)})
    except Exception as e:
        try:
            log("artifact", "artifact.export_failed", {"reason": type(e).__name__, "detail": ""})
        except Exception:
            pass
    return {"stored": stored, "skipped": skipped}
