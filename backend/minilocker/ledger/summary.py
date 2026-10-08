"""One-line summaries of stored tasks, for the Sessions list. Built from the ledger only."""
from collections import Counter

from minilocker.ledger.chain import verify_events

ATTACK_PREFIX = "Attack Lab: "     # how attacks name their task (attacks/runner.py)


def summarize(task_id: str, events: list[dict], read_error: str | None = None,
              live: bool = False) -> dict:
    start = next((e for e in events if e["type"] == "task.start"), None)
    end = next((e for e in reversed(events) if e["type"] == "task.end"), None)
    ok, _ = verify_events(events)
    if read_error:
        ok = False
    n = Counter(e["type"] for e in events)
    text = ((start or {}).get("payload") or {}).get("task") or ""
    status = "running" if live else ((end or {}).get("payload") or {}).get("status") or "incomplete"
    duration = None
    if start is not None:
        last = end if end is not None else (events[-1] if live else None)
        duration = round(last["ts"] - start["ts"], 2) if last is not None else None
    return {
        "task_id": task_id,
        "kind": "attack" if text.startswith(ATTACK_PREFIX) else "task",
        "task": text[:300],
        "profile": ((start or {}).get("payload") or {}).get("profile"),
        "status": status,                      # running | finished | halted:* | error:* | incomplete
        "started": start["ts"] if start else None,
        "duration_s": duration,
        "events": len(events),
        "tool_calls": n["tool.call"],
        "egress_blocked": n["egress.blocked"],
        "denied": sum(1 for e in events if e["type"] == "policy.decision"
                      and (e.get("payload") or {}).get("action") == "deny"),
        "approvals": n["approval.requested"],
        "verified": ok,                        # hash chain intact (not re-checked against anything else)
    }
