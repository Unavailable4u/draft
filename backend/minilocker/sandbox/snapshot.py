"""Snapshots of a sandbox's workspace, and rewinding to one.

The workspace is a size-capped tmpfs that dies with its container, so a snapshot is a gzipped tar of /workspace taken from
outside through `exec`, held in the control plane's memory for the life of the task (nothing is written to the host's disk).
Each one is recorded in the ledger with its SHA-256 and the manifest of what it holds (path, size, hash), which is what makes a
rewind checkable: after restoring into a FRESH sandbox the workspace is re-hashed and compared to the manifest.

Rewinding replaces the sandbox rather than repairing it, so whatever the damaged one did to its own processes, /tmp or
environment is gone with it. The ledger is append-only: a rewind adds events, it never removes any.
"""
import hashlib
from dataclasses import dataclass, field

from minilocker.sandbox import measure

SNAPSHOT_MAX_BYTES = 70_000_000
STORE_CAP_BYTES = 256_000_000
RESTORE_TIMEOUT_S = 60


class SnapshotError(Exception):
    pass


@dataclass
class Snap:
    id: int
    step: int
    tool: str
    data: bytes
    sha256: str
    manifest: dict = field(default_factory=dict)


def capture(box) -> bytes:
    r = box.exec_capped(["tar", "-C", "/workspace", "-czf", "-", "."], timeout_s=30, max_bytes=SNAPSHOT_MAX_BYTES)
    if r.timed_out or r.truncated or r.exit_code not in (0, 1):      # tar exits 1 when a file changed while it was read
        raise SnapshotError("timed out" if r.timed_out else "too large" if r.truncated else f"tar exit {r.exit_code}")
    return bytes(r.stdout)


def restore(box, data: bytes):
    r = box.exec_stdin(["tar", "-xzf", "-", "-C", "/workspace", "--no-same-owner"], data, timeout_s=RESTORE_TIMEOUT_S)
    if r.timed_out or r.exit_code != 0:
        raise SnapshotError("timed out" if r.timed_out else f"tar exit {r.exit_code}: {r.stderr[-120:]!r}")


class SnapshotStore:
    """The active timeline: snapshots in the order they were taken, oldest first. A rewind cuts it back to the chosen one."""

    def __init__(self, cap_bytes: int = STORE_CAP_BYTES):
        self.cap = cap_bytes
        self.snaps = {}
        self.active = []
        self._next = 0

    def take(self, box, step: int, tool: str, log, decoys=()) -> int | None:
        try:
            data = capture(box)
            man = measure.run_manifest(box, decoys)
        except Exception as e:
            log("snapshot", "snapshot.failed", {"step": step, "tool": tool, "reason": f"{type(e).__name__}: {str(e)[:120]}"})
            return None
        sid, self._next = self._next, self._next + 1
        sha = hashlib.sha256(data).hexdigest()
        prev = self.snaps.get(self.active[-1]) if self.active else None
        if prev is not None and prev.sha256 == sha:
            data = prev.data                                     # identical bytes: share them
        snap = Snap(sid, step, tool, data, sha, (man or {}).get("files") or {})
        self.snaps[sid] = snap
        self.active.append(sid)
        self._evict()
        log("snapshot", "snapshot.created", {"id": sid, "step": step, "tool": tool, "bytes": len(data), "sha256": sha,
                                             "files": len(snap.manifest), "unchanged": prev is not None and prev.sha256 == sha,
                                             "manifest_complete": man is not None})
        return sid

    def _evict(self):
        """Drop the oldest snapshots (never the first, the pristine start) once the total passes the cap."""
        def total():
            return sum(len(d) for d in {id(s.data): s.data for s in self.snaps.values()}.values())
        while total() > self.cap and len(self.active) > 2:
            gone = self.active.pop(1)
            self.snaps.pop(gone, None)

    def get(self, sid) -> Snap | None:
        s = self.snaps.get(sid)
        if s is None or hashlib.sha256(s.data).hexdigest() != s.sha256:
            return None
        return s

    def cut_back_to(self, sid) -> list:
        """Make `sid` the newest snapshot of the active timeline. -> the ids that were discarded."""
        if sid not in self.active:
            return []
        i = self.active.index(sid)
        gone, self.active = self.active[i + 1:], self.active[:i + 1]
        for g in gone:
            self.snaps.pop(g, None)
        return gone

    def verify_restored(self, box, snap: Snap, decoys=()) -> dict:
        """Re-hash the restored workspace and compare it with what the snapshot held."""
        man = measure.run_manifest(box, decoys)
        if man is None:
            return {"checked": False}
        now = {p: list(v) for p, v in man["files"].items()}
        want = {p: list(v) for p, v in snap.manifest.items()}
        return {"checked": True, "matches": now == want, "files": len(now),
                "missing": len([p for p in want if p not in now]), "unexpected": len([p for p in now if p not in want])}
