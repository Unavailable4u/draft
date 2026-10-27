"""Blast Radius report, built purely from ledger events.

Rule: only report what the ledger actually measured. A dimension with no measurement behind it (a stand-in sandbox that cannot
be audited, a run from before the audit existed) is marked "not_measured" instead of being filled with a reassuring zero
("measure, don't claim"), and a measurement that could only be partly taken says which part (`incomplete`)."""
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


def _incomplete(audits):
    return sorted({x for e in audits for x in (e["payload"].get("incomplete") or [])})


def _filesystem(audits, browser_audits, complete):
    """What the sandboxes' filesystems looked like just before they were destroyed (docker diff, mounts, workspace re-hash)."""
    allaud = audits + browser_audits
    with_fs = [e for e in allaud if (e["payload"].get("fs") or {}).get("rootfs_changes") is not None]
    if not with_fs:
        return {**NOT_MEASURED, "note": "no sandbox audit in this ledger: the sandbox could not be audited, or the run is older than the audit"}
    fs = [e["payload"]["fs"] for e in with_fs]
    changed = [c for f in fs for c in (f.get("rootfs_changed") or [])]
    # the last code sandbox that could be scanned from inside is the one whose workspace the person ends up with
    scanned = [e for e in audits if (e["payload"].get("fs") or {}).get("workspace")]
    ws = scanned[-1]["payload"]["fs"]["workspace"] if scanned else None
    out = {
        "status": "measured" if complete else "in_progress",
        "sandboxes_audited": len(with_fs),
        "rootfs_changes": sum(f.get("rootfs_changes") or 0 for f in fs),
        "rootfs_changed": changed[:30],
        "host_binds": sorted({b for f in fs for b in (f.get("host_binds") or [])}),
        "writable_mounts": sorted({m for f in fs for m in (f.get("tmpfs") or [])}),
        "workspace": ({k: ws[k] for k in ws if k not in ("added_more", "modified_more", "deleted_more")} if ws else None),
        "workspace_checked": bool(ws),
        "incomplete": _incomplete(allaud),
        "evidence": _ids(with_fs),
    }
    if ws:
        out["tmp_bytes"] = scanned[-1]["payload"]["fs"].get("tmp_bytes")
    return out


def _compute(audits, complete):
    """Highest memory / process count / CPU seen by a poller on the sandbox's cgroup. Polled: a spike shorter than the
    interval can be missed, so these are 'highest seen', not guarantees."""
    with_stats = [e for e in audits if e["payload"].get("stats")]
    if not with_stats:
        return {**NOT_MEASURED, "note": "no sandbox audit in this ledger: no resource sampling happened"}
    st = [e["payload"]["stats"] for e in with_stats]
    mem = max((s.get("peak_memory_bytes") or 0) for s in st)
    lim = max((s.get("memory_limit_bytes") or 0) for s in st)
    pids = max((s.get("peak_pids") or 0) for s in st)
    plim = max((s.get("pids_limit") or 0) for s in st)
    oom = [s.get("oom_killed") for s in st]
    return {
        "status": "measured" if complete else "in_progress",
        "sandboxes_sampled": len(st),
        "peak_memory_bytes": mem, "memory_limit_bytes": lim,
        "memory_peak_pct": round(100 * mem / lim, 1) if lim else None,
        "peak_pids": pids, "pids_limit": plim,
        "cpu_seconds": round(sum(s.get("cpu_seconds") or 0 for s in st), 2),
        "oom_killed": True if any(o is True for o in oom) else (False if all(o is False for o in oom) else None),
        "memory_failcnt": max((s.get("memory_failcnt") or 0) for s in st),
        "samples": sum(s.get("samples") or 0 for s in st),
        "sample_errors": sum(s.get("sample_errors") or 0 for s in st),
        "incomplete": _incomplete(audits),
        "evidence": _ids(with_stats),
    }


def _secrets(audits, t, complete):
    """Did a real secret reach the sandbox (it should not), and what happened to the decoys planted in it."""
    seeded = t.get("canary.seeded", [])
    with_sec = [e for e in audits if e["payload"].get("secrets")]
    if not with_sec and not seeded:
        return {**NOT_MEASURED, "note": "no sandbox audit and no decoys in this ledger: nothing was checked"}
    found = {}
    for e in with_sec:
        for name, where in (e["payload"]["secrets"].get("found_where") or {}).items():
            found.setdefault(name, set()).update(where)
    scanned = [e for e in with_sec if e["payload"]["secrets"].get("inside")]
    checked = sorted({n for e in with_sec for n in (e["payload"]["secrets"].get("checked") or [])})

    def items(kind):
        return sorted({e["payload"].get("item") for e in t.get(kind, [])} - {None})
    tripped = t.get("canary.tripped", [])
    out = {
        "status": "measured" if complete else "in_progress",
        "real_secrets_checked": len(checked),
        "real_secrets_found": {k: sorted(v) for k, v in sorted(found.items())},
        "scanned_inside": bool(scanned),
        "decoys_planted": len((seeded[0]["payload"].get("items") or [])) if seeded else 0,
        "decoys_read": items("canary.read"),
        "decoys_exposed_to_model": items("canary.exposed"),
        "decoys_copied_out": items("canary.copied"),
        "decoys_tripped": items("canary.tripped"),
        "exfiltration_attempts": len(tripped),
        "exfiltration_blocked": sum(1 for e in tripped if e["payload"].get("blocked")),
        "real_secrets_in_sandbox": bool(found),
        "incomplete": _incomplete(audits),
        "evidence": _ids(t.get("canary.read", []) + t.get("canary.exposed", []) + tripped + t.get("canary.copied", [])
                         + with_sec),
    }
    if not scanned and not seeded:
        out["note"] = "the inside of the sandbox could not be scanned: only the container's configuration was checked"
    return out


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
    brokered = t.get("egress.brokered", [])
    if brokered:
        network["brokered"] = {
            "requests": len(brokered),
            "services": dict(Counter(e["payload"].get("service", "?") for e in brokered)),
            "credential_stripped": sum(1 for e in brokered if e["payload"].get("stripped")),
            "credential_redacted": sum(1 for e in brokered if e["payload"].get("redacted")),
            "evidence": _ids(brokered),
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
    destroyed_names = {e["payload"].get("name") for e in destroyed}
    lineage = sorted(created + recreated, key=lambda e: e["id"])
    final_name = lineage[-1]["payload"].get("name") if lineage else None
    # A "rewind" replaces the sandbox on purpose; a "deadline"/"wedged" recreation is a kill. Only kills are forced kills.
    rewinds = [e for e in recreated if e["payload"].get("reason") == "rewind"]
    kills = [e for e in recreated if e["payload"].get("reason") != "rewind"]
    snaps_made, snaps_failed = t.get("snapshot.created", []), t.get("snapshot.failed", [])
    rewound, rewind_failed = t.get("timeline.rewound", []), t.get("rewind.failed", []) + t.get("rewind.rejected", [])
    persistence = {
        "status": "measured" if complete else "in_progress",
        "sandboxes_created": len(created) + len(recreated),
        "sandboxes_destroyed_logged": len(destroyed),
        # a sandbox killed for a deadline is destroyed by that kill; a rewound one is destroyed and logged. The sandbox that
        # exists at the end must be logged as destroyed.
        "final_sandbox_destroyed": bool(final_name) and final_name in destroyed_names,
        "snapshots_taken": len(snaps_made),
        "snapshots_failed": len(snaps_failed),
        "rewinds": len(rewound),
        "rewinds_verified": sum(1 for e in rewound if (e["payload"].get("verified") or {}).get("matches") is True),
        "rewinds_failed": len(rewind_failed),
        "evidence": _ids(created + recreated + destroyed + rewound),
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
        "forced_kills": len(kills),
        "evidence": _ids(kills),
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

    audits = [e for e in t.get("sandbox.audit", []) if e["payload"].get("kind") == "code"]
    browser_audits = [e for e in t.get("sandbox.audit", []) if e["payload"].get("kind") == "browser"]
    filesystem = _filesystem(audits, browser_audits, complete)
    compute = _compute(audits + browser_audits, complete)
    secrets_dim = _secrets(audits + browser_audits, t, complete)

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
            "filesystem": filesystem,
            "secrets": secrets_dim,
            "compute": compute,
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
