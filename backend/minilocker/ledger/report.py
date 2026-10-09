"""Blast Radius report, built purely from ledger events.

Rule: only report what the ledger actually measured. Dimensions we cannot
measure yet are marked "not_measured" instead of being filled with a reassuring
zero ("measure, don't claim")."""
import html
import json
from collections import Counter
from urllib.parse import urlsplit

from minilocker.ledger.chain import verify_events

NOT_MEASURED = {"status": "not_measured"}


def _by_type(events):
    out: dict[str, list[dict]] = {}
    for e in events:
        out.setdefault(e["type"], []).append(e)
    return out


def _ids(evs):
    return [e["id"] for e in evs]


def build_report(task_id: str, events: list[dict], read_error: str | None = None) -> dict:
    ok, detail = verify_events(events)
    if read_error:
        ok, detail = False, f"ledger unreadable: {read_error}"
    t = _by_type(events)
    start = (t.get("task.start") or [None])[0]
    end = (t.get("task.end") or [None])[0]
    complete = end is not None

    allowed, blocked = t.get("egress.allowed", []), t.get("egress.blocked", [])
    closed = t.get("egress.closed", [])
    hosts = {e["payload"].get("host") for e in allowed + blocked} - {None}
    network = {
        "status": "measured",
        "attempts": len(allowed) + len(blocked),
        "allowed": len(allowed),
        "blocked": len(blocked),
        "unique_hosts": sorted(hosts),
        "bytes_out": sum(e["payload"].get("bytes_up", 0) for e in closed),
        "bytes_in": sum(e["payload"].get("bytes_down", 0) for e in closed),
        "blocked_reasons": dict(Counter(e["payload"].get("reason", "?") for e in blocked)),
        # which container made the request (events from before the browser existed are all "code")
        "by_source": {src: {"allowed": sum(1 for e in allowed if e["payload"].get("source", "code") == src),
                            "blocked": sum(1 for e in blocked if e["payload"].get("source", "code") == src)}
                      for src in sorted({e["payload"].get("source", "code") for e in allowed + blocked})},
        "evidence": _ids(blocked),
    }

    decisions = t.get("policy.decision", [])
    policy = {
        "status": "measured",
        "profile": (start or {}).get("payload", {}).get("profile"),
        "decisions": len(decisions),
        "by_action": dict(Counter(e["payload"]["action"] for e in decisions)),
        "by_risk": dict(Counter(e["payload"]["risk"] for e in decisions)),
        "approvals_requested": len(t.get("approval.requested", [])),
        "approvals_granted": len(t.get("approval.granted", [])),
        "approvals_denied": len(t.get("approval.denied", [])),
        "evidence": _ids([e for e in decisions if e["payload"]["action"] != "allow"]),
    }

    created, destroyed = t.get("sandbox.created", []), t.get("sandbox.destroyed", [])
    recreated = t.get("sandbox.recreated", [])
    created_names = {e["payload"].get("name") for e in created + recreated}
    destroyed_names = {e["payload"].get("name") for e in destroyed}
    persistence = {
        "status": "measured" if complete else "in_progress",
        "sandboxes_created": len(created) + len(recreated),
        "sandboxes_destroyed_logged": len(destroyed),
        # the loop logs destruction only for the final sandbox; a recreated one
        # was destroyed by the kill that triggered recreation
        "final_sandbox_destroyed": bool(destroyed) and bool(created_names & destroyed_names),
        "evidence": _ids(created + recreated + destroyed),
    }

    wall = (end["ts"] - start["ts"]) if (start and end) else None
    # Time a human spent deciding is not sandbox/agent time: report it separately.
    asked = {e["payload"]["id"]: e["ts"] for e in t.get("approval.requested", [])}
    approval_wait = sum(e["ts"] - asked[e["payload"]["id"]]
                        for e in t.get("approval.granted", []) + t.get("approval.denied", [])
                        if e["payload"].get("id") in asked)
    time_dim = {
        "status": "measured" if complete else "in_progress",
        "wall_clock_s": round(wall, 2) if wall is not None else None,
        "approval_wait_s": round(approval_wait, 2),
        "active_s": round(wall - approval_wait, 2) if wall is not None else None,
        "forced_kills": len(recreated),
        "evidence": _ids(recreated),
    }

    stored, skipped = t.get("artifact.stored", []), t.get("artifact.skipped", [])
    art_failed = t.get("artifact.failed", []) + t.get("artifact.export_failed", [])
    if stored or skipped or art_failed:
        artifacts = {
            "status": "measured" if complete else "in_progress",
            "stored": len(stored),
            "files": sum(1 for e in stored if e["payload"].get("kind") == "file"),
            "screenshots": sum(1 for e in stored if e["payload"].get("kind") == "screenshot"),
            "bytes": sum(e["payload"].get("bytes", 0) for e in stored),
            "skipped": len(skipped),
            "failed": len(art_failed),
            "evidence": _ids(stored + skipped + art_failed),
        }
    else:
        artifacts = {**NOT_MEASURED, "note": "no artifact events: no store attached, or nothing was produced"}

    pages, unavailable = t.get("browser.page", []), t.get("browser.unavailable", [])
    flagged = t.get("injection.suspected", [])
    if pages or unavailable:
        def host(e):
            try:
                return urlsplit(e["payload"].get("url", "")).hostname
            except ValueError:
                return None
        count = lambda k: sum(e["payload"].get(k, 0) for e in pages)
        browser = {
            "status": "measured" if complete else "in_progress",
            "pages": len(pages),
            "hosts": sorted({h for h in map(host, pages) if h}),
            "injection_suspected": len(flagged),
            "popups_blocked": count("popups_blocked"),
            "dialogs_dismissed": count("dialogs"),
            "downloads_blocked": count("downloads"),
            "unavailable": bool(unavailable),
            "evidence": _ids(flagged + unavailable),
        }
    else:
        browser = {"status": "not_used"}

    return {
        "task_id": task_id,
        "task": (start or {}).get("payload", {}).get("task"),
        "outcome": (end or {}).get("payload", {}).get("status", "running"),
        "summary": (end or {}).get("payload", {}).get("summary", ""),
        "complete": complete,
        "steps": len(t.get("llm.response", [])),
        "tool_calls": len(t.get("tool.call", [])),
        "ledger": {"verified": ok, "detail": detail, "events": len(events),
                   "head_hash": events[-1]["hash"] if events else None},
        "dimensions": {
            "network": network,
            "policy": policy,
            "persistence": persistence,
            "time": time_dim,
            "browser": browser,
            "artifacts": artifacts,
            # Not instrumented yet; will be filled by sandbox stats / canary work.
            "filesystem": {**NOT_MEASURED, "note": "host-path and out-of-workspace write "
                           "accounting not instrumented yet"},
            "secrets": {**NOT_MEASURED, "note": "canary tokens / credential broker not built yet"},
            "compute": {**NOT_MEASURED, "note": "peak CPU/mem/PID sampling not built yet"},
        },
        "note": "Blast radius = what the ledger measured. 'not_measured' means no claim is made.",
    }


def _row(label, value):
    return f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(value))}</td></tr>"


def render_html(report: dict) -> str:
    """Self-contained page. Everything interpolated is escaped: ledger payloads
    include model output and attacker-controlled text."""
    e = html.escape
    led = report["ledger"]
    badge = ("verified" if led["verified"] else "FAILED")
    cls = "ok" if led["verified"] else "bad"
    sections = []
    for name, dim in report["dimensions"].items():
        rows = "".join(
            _row(k, json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in dim.items() if k != "evidence")
        ev = dim.get("evidence")
        if ev:
            rows += _row("evidence (ledger event ids)", ", ".join(map(str, ev)))
        sections.append(f"<section><h2>{e(name)}</h2><table>{rows}</table></section>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blast Radius report {e(report['task_id'])}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px;max-width:860px}}
h1{{font-size:20px}} h2{{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}}
section{{border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin:12px 0}}
table{{border-collapse:collapse;width:100%}} th{{text-align:left;color:#8b949e;font-weight:500;width:34%;vertical-align:top;padding:2px 8px 2px 0}}
td{{padding:2px 0;word-break:break-word}} .ok{{color:#3fb950}} .bad{{color:#f85149}}
code{{background:#161b22;padding:1px 4px;border-radius:4px}}
</style></head><body>
<h1>Blast Radius report <code>{e(report['task_id'])}</code></h1>
<p>Outcome: <b>{e(str(report['outcome']))}</b> · {report['steps']} steps · {report['tool_calls']} tool calls</p>
<p>Ledger chain: <b class="{cls}">{badge}</b> — {e(led['detail'])}<br>
head hash <code>{e(str(led['head_hash']))}</code></p>
<section><h2>task</h2><p>{e(str(report['task']))}</p><p>{e(report['summary'])}</p></section>
{''.join(sections)}
<p style="color:#8b949e">{e(report['note'])}</p>
</body></html>"""
