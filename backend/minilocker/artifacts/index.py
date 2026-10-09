"""The list of a task's artifacts, derived from its ledger events.

The ledger, not the object store, is the source of truth for what exists and what its bytes must
hash to. That makes the Files tab work from a replayed ledger, and makes every download
verifiable: the bytes the store returns must match the SHA-256 the hash-chained ledger recorded.
"""
import re

from minilocker.artifacts.store import KINDS, valid_name

_SHA = re.compile(r"^[0-9a-f]{64}$")


def index_from_events(events) -> dict:
    by_name, skipped, failed = {}, [], []
    for e in events:
        t, p = e.get("type"), e.get("payload") or {}
        if t == "artifact.stored":
            name, sha, n = p.get("name"), p.get("sha256"), p.get("bytes")
            if (valid_name(name) and isinstance(sha, str) and _SHA.match(sha)
                    and isinstance(n, int) and n >= 0 and p.get("kind") in KINDS):
                by_name[name] = {"name": name, "kind": p["kind"], "bytes": n, "sha256": sha, "event_id": e["id"]}
        elif t == "artifact.skipped":
            skipped.append({"name": str(p.get("name", ""))[:200], "reason": str(p.get("reason", ""))[:30],
                            "bytes": p.get("bytes") if isinstance(p.get("bytes"), int) else None})
        elif t in ("artifact.failed", "artifact.export_failed"):
            failed.append({"reason": str(p.get("reason") or p.get("error") or "")[:60],
                           "name": str(p.get("name", ""))[:200]})
    return {"artifacts": list(by_name.values()), "skipped": skipped, "failed": failed, "by_name": by_name}
