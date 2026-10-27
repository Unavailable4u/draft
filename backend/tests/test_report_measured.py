"""The filesystem, secrets and compute dimensions of the Blast Radius report, and the rewind-aware parts of persistence/time.

Built from hand-written ledger events: the report is a pure function of the ledger, so no sandbox is needed here.
"""
from minilocker.ledger.chain import Ledger
from minilocker.ledger.report import build_report


def ledger(*events, end=True):
    l = Ledger("t-report")
    l.append("api", "task.start", {"task": "x", "profile": "strict"})
    for actor, typ, payload in events:
        l.append(actor, typ, payload)
    if end:
        l.append("agent", "task.end", {"status": "done", "summary": "ok"})
    return l.events


def audit(name="sb1", kind="code", **over):
    base = {
        "name": name, "kind": kind, "incomplete": [],
        "stats": {"peak_memory_bytes": 64 * 2**20, "memory_limit_bytes": 512 * 2**20, "peak_pids": 7, "pids_limit": 128,
                  "cpu_seconds": 1.5, "samples": 12, "sample_errors": 0, "memory_failcnt": 0, "oom_killed": False},
        "fs": {"rootfs_changes": 0, "rootfs_changed": [], "host_binds": [], "mounts": [], "tmpfs": ["/tmp", "/workspace"],
               "inside": True,
               "workspace": {"files": 3, "bytes": 900, "added_count": 1, "modified_count": 1, "deleted_count": 0,
                             "truncated": False, "added": ["/workspace/a.py"], "added_more": 0, "modified": [],
                             "modified_more": 0, "deleted": [], "deleted_more": 0},
               "tmp_bytes": 10},
        "secrets": {"checked": ["LLM_API_KEY"], "found": [], "found_where": {}, "scanned_bytes": 100,
                    "scan_truncated": False, "inside": True},
        "canaries": {"copied_out": [], "files": {}},
    }
    base.update(over)
    return base


def dims(events):
    return build_report("t-report", events)["dimensions"]


def test_old_ledger_says_not_measured_not_zero():
    d = dims(ledger())
    for k in ("filesystem", "secrets", "compute"):
        assert d[k]["status"] == "not_measured", k


def test_compute_is_the_highest_seen_over_all_sandboxes():
    a1 = audit("sb1")
    a2 = audit("sb2", stats={"peak_memory_bytes": 256 * 2**20, "memory_limit_bytes": 512 * 2**20, "peak_pids": 40,
                             "pids_limit": 128, "cpu_seconds": 2.0, "samples": 5, "sample_errors": 1,
                             "memory_failcnt": 3, "oom_killed": False})
    c = dims(ledger(("sandbox", "sandbox.audit", a1), ("sandbox", "sandbox.audit", a2)))["compute"]
    assert c["status"] == "measured"
    assert c["peak_memory_bytes"] == 256 * 2**20 and c["memory_peak_pct"] == 50.0
    assert c["peak_pids"] == 40 and c["pids_limit"] == 128
    assert c["cpu_seconds"] == 3.5 and c["memory_failcnt"] == 3 and c["sample_errors"] == 1
    assert c["oom_killed"] is False and c["sandboxes_sampled"] == 2


def test_oom_is_reported_and_unknown_oom_is_not_called_false():
    killed = audit("sb1")
    killed["stats"]["oom_killed"] = True
    assert dims(ledger(("sandbox", "sandbox.audit", killed)))["compute"]["oom_killed"] is True
    unknown = audit("sb1")
    unknown["stats"]["oom_killed"] = None
    assert dims(ledger(("sandbox", "sandbox.audit", unknown)))["compute"]["oom_killed"] is None


def test_filesystem_reports_changes_binds_and_the_final_workspace():
    a = audit()
    a["fs"]["rootfs_changes"] = 2
    a["fs"]["rootfs_changed"] = [{"path": "/etc/x", "kind": "added"}, {"path": "/usr/y", "kind": "modified"}]
    a["fs"]["host_binds"] = ["/host"]
    f = dims(ledger(("sandbox", "sandbox.audit", a)))["filesystem"]
    assert f["status"] == "measured"
    assert f["rootfs_changes"] == 2 and f["host_binds"] == ["/host"]
    assert f["workspace_checked"] and f["workspace"]["files"] == 3 and f["workspace"]["added_count"] == 1
    assert "added_more" not in f["workspace"]
    assert f["writable_mounts"] == ["/tmp", "/workspace"]


def test_filesystem_without_a_workspace_scan_says_so():
    a = audit()
    del a["fs"]["workspace"]
    a["incomplete"] = ["inside:container_was_killed"]
    f = dims(ledger(("sandbox", "sandbox.audit", a)))["filesystem"]
    assert f["status"] == "measured" and f["workspace_checked"] is False and f["workspace"] is None
    assert f["incomplete"] == ["inside:container_was_killed"]


def test_a_failed_audit_stays_not_measured():
    broken = {"name": "sb1", "kind": "code", "incomplete": ["audit:RuntimeError"]}
    d = dims(ledger(("sandbox", "sandbox.audit", broken)))
    assert d["filesystem"]["status"] == "not_measured" and d["compute"]["status"] == "not_measured"


def test_secrets_a_real_secret_in_the_sandbox_is_reported_with_where():
    a = audit()
    a["secrets"].update(found=["LLM_API_KEY"], found_where={"LLM_API_KEY": ["container_env", "file"]})
    s = dims(ledger(("sandbox", "sandbox.audit", a)))["secrets"]
    assert s["status"] == "measured" and s["real_secrets_in_sandbox"] is True
    assert s["real_secrets_found"] == {"LLM_API_KEY": ["container_env", "file"]}
    assert s["real_secrets_checked"] == 1 and s["scanned_inside"] is True


def test_secrets_clean_run_reports_zero_found_but_only_because_it_checked():
    s = dims(ledger(("sandbox", "sandbox.audit", audit())))["secrets"]
    assert s["real_secrets_in_sandbox"] is False and s["real_secrets_checked"] == 1 and s["scanned_inside"] is True


def test_decoy_events_become_counts_and_never_values():
    ev = ledger(
        ("canary", "canary.seeded", {"name": "sb1", "items": [{"id": "ssh_key", "label": "SSH private key"},
                                                              {"id": "aws_secret", "label": "AWS"}], "files": [], "env": []}),
        ("canary", "canary.read", {"item": "ssh_key", "via": "atime"}),
        ("canary", "canary.exposed", {"item": "ssh_key", "tool": "run_shell", "via": "output"}),
        ("canary", "canary.tripped", {"item": "aws_secret", "tool": "run_shell", "via": "command", "blocked": True}),
        ("canary", "canary.tripped", {"item": "ssh_key", "tool": "egress", "via": "egress_host", "blocked": False}),
        ("canary", "canary.copied", {"item": "aws_secret", "where": "workspace_or_tmp"}),
        ("sandbox", "sandbox.audit", audit()),
    )
    s = dims(ev)["secrets"]
    assert s["decoys_planted"] == 2
    assert s["decoys_read"] == ["ssh_key"] and s["decoys_exposed_to_model"] == ["ssh_key"]
    assert s["decoys_tripped"] == ["aws_secret", "ssh_key"] and s["decoys_copied_out"] == ["aws_secret"]
    assert s["exfiltration_attempts"] == 2 and s["exfiltration_blocked"] == 1


def test_a_rewind_is_not_a_forced_kill_but_a_deadline_is():
    ev = ledger(
        ("sandbox", "sandbox.created", {"name": "sb1"}),
        ("sandbox", "sandbox.recreated", {"reason": "deadline", "name": "sb2"}),
        ("sandbox", "sandbox.destroyed", {"name": "sb2", "reason": "rewind"}),
        ("sandbox", "sandbox.recreated", {"reason": "rewind", "name": "sb3", "snapshot": 1}),
        ("control", "timeline.rewound", {"to_snapshot": 1, "verified": {"checked": True, "matches": True}}),
        ("snapshot", "snapshot.created", {"id": 0}),
        ("snapshot", "snapshot.created", {"id": 1}),
        ("sandbox", "sandbox.destroyed", {"name": "sb3"}),
    )
    r = build_report("t-report", ev)["dimensions"]
    assert r["time"]["forced_kills"] == 1
    p = r["persistence"]
    assert p["rewinds"] == 1 and p["rewinds_verified"] == 1 and p["snapshots_taken"] == 2
    assert p["final_sandbox_destroyed"] is True


def test_final_sandbox_not_destroyed_is_visible():
    ev = ledger(
        ("sandbox", "sandbox.created", {"name": "sb1"}),
        ("sandbox", "sandbox.recreated", {"reason": "rewind", "name": "sb2"}),
        ("sandbox", "sandbox.destroyed", {"name": "sb1", "reason": "rewind"}),
    )
    assert dims(ev)["persistence"]["final_sandbox_destroyed"] is False


def test_an_unverified_rewind_is_not_counted_as_verified():
    ev = ledger(("control", "timeline.rewound", {"to_snapshot": 0, "verified": {"checked": False}}),
                ("control", "timeline.rewound", {"to_snapshot": 0, "verified": {"checked": True, "matches": False}}))
    p = dims(ev)["persistence"]
    assert p["rewinds"] == 2 and p["rewinds_verified"] == 0


def test_brokered_requests_are_counted_apart_from_allowed_and_blocked():
    ev = ledger(
        ("egress", "egress.brokered", {"service": "github", "host": "api.github.com", "stripped": True, "redacted": False}),
        ("egress", "egress.brokered", {"service": "github", "host": "api.github.com", "stripped": False, "redacted": True}),
        ("egress", "egress.allowed", {"host": "pypi.org"}),
    )
    n = dims(ev)["network"]
    assert n["attempts"] == 1 and n["allowed"] == 1
    assert n["brokered"]["requests"] == 2 and n["brokered"]["services"] == {"github": 2}
    assert n["brokered"]["credential_stripped"] == 1 and n["brokered"]["credential_redacted"] == 1


def test_html_report_renders_the_new_dimensions_escaped():
    from minilocker.ledger.report import render_html
    a = audit()
    a["secrets"].update(found=["<b>X</b>"], found_where={"<b>X</b>": ["file"]})
    page = render_html(build_report("t-report", ledger(("sandbox", "sandbox.audit", a))))
    assert "<b>X</b>" not in page and "&lt;b&gt;X&lt;/b&gt;" in page
