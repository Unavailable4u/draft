"""API tests. They use a fake runner (real Ledger + real ApprovalGate through the
real TaskManager), so they need neither Docker nor an LLM."""
import json
import threading
import time

from fastapi.testclient import TestClient

from airlock.api.app import create_app
from airlock.ledger.chain import Ledger


def fake_runner(task, llm, ledger_dir, egress, policy, approver, on_event, task_id, **_):
    ledger = Ledger(task_id, f"{ledger_dir}/{task_id}.jsonl")

    def log(actor, type_, payload=None):
        on_event(ledger.append(actor, type_, payload))

    log("user", "task.start", {"task": task, "profile": policy.profile.name})
    log("sandbox", "sandbox.created", {"name": "airlock-x", "ip": ""})
    log("egress", "egress.blocked", {"host": "evil.example", "reason": "not_allowlisted"})
    log("egress", "egress.allowed", {"host": "pypi.org"})
    log("egress", "egress.closed", {"host": "pypi.org", "bytes_up": 10, "bytes_down": 90})
    status = "finished"
    if "approve me" in task:
        req = {"id": "ap000001", "tool": "run_shell", "summary": "cat /proc/1/environ",
               "risk": "medium", "reasons": ["reads another process's environment"]}
        log("policy", "approval.requested", req)
        ok = approver(req)
        log("policy", "approval.granted" if ok else "approval.denied", {"id": req["id"]})
        status = "finished" if ok else "halted:policy_denials"
    if "slow" in task:
        time.sleep(0.5)
    log("sandbox", "sandbox.destroyed", {"name": "airlock-x"})
    log("agent", "task.end", {"status": status, "steps": 1, "summary": "done"})
    ok, detail = ledger.verify()
    return {"task_id": task_id, "status": status, "ledger_verified": ok, "ledger": detail}


def make(tmp_path, **kw):
    kw.setdefault("runner", fake_runner)
    kw.setdefault("llm_factory", lambda: object())
    kw.setdefault("egress_factory", lambda: None)
    return TestClient(create_app(ledger_dir=str(tmp_path), **kw))


def sse(resp):
    """Parse an SSE response into [(id, event, data)]."""
    out, cur = [], {}
    for line in resp.iter_lines():
        if line == "":
            if cur:
                out.append((cur.get("id"), cur.get("event"), cur.get("data")))
            cur = {}
        elif not line.startswith(":"):
            k, _, v = line.partition(": ")
            cur[k] = v
    return out


def run(client, task="hello", **kw):
    r = client.post("/api/tasks", json={"task": task, **kw})
    assert r.status_code == 202, r.text
    return r.json()["task_id"]


def stream_all(client, tid, **kw):
    with client.stream("GET", f"/api/tasks/{tid}/events", **kw) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        return sse(r)


def test_task_stream_report_verify(tmp_path):
    with make(tmp_path) as c:
        tid = run(c)
        frames = stream_all(c, tid)
        ledger = [json.loads(d) for _, e, d in frames if e == "ledger"]
        assert [f[0] for f in frames if f[1] == "ledger"] == [str(i) for i in range(len(ledger))]
        assert ledger[0]["type"] == "task.start" and ledger[-1]["type"] == "task.end"
        assert frames[-1][1] == "end"
        assert json.loads(frames[-1][2])["status"] == "finished"

        v = c.get(f"/api/ledger/verify/{tid}").json()
        assert v["verified"] and v["events"] == len(ledger) and v["head_hash"] == ledger[-1]["hash"]

        rep = c.get(f"/api/tasks/{tid}/report").json()
        net = rep["dimensions"]["network"]
        assert (net["attempts"], net["allowed"], net["blocked"]) == (2, 1, 1)
        assert net["bytes_out"] == 10 and net["unique_hosts"] == ["evil.example", "pypi.org"]
        assert rep["complete"] and rep["ledger"]["verified"]
        tm = rep["dimensions"]["time"]
        assert tm["approval_wait_s"] == 0 and tm["active_s"] == tm["wall_clock_s"]
        # unmeasured dimensions must not pretend to be zero
        assert rep["dimensions"]["filesystem"]["status"] == "not_measured"
        assert rep["dimensions"]["secrets"]["status"] == "not_measured"
        assert c.get(f"/api/tasks/{tid}").json()["status"] == "finished"


def test_sse_resume_after_last_event_id(tmp_path):
    with make(tmp_path) as c:
        tid = run(c)
        full = [f for f in stream_all(c, tid) if f[1] == "ledger"]
        resumed = [f for f in stream_all(c, tid, headers={"Last-Event-ID": "2"}) if f[1] == "ledger"]
        assert [f[0] for f in resumed] == [f[0] for f in full if int(f[0]) > 2]
        q = [f for f in stream_all(c, tid, params={"after": len(full) - 1}) if f[1] == "ledger"]
        assert q == []


def test_live_stream_while_running(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "slow task")
        frames = stream_all(c, tid)   # connects mid-run; must still get everything
        assert [json.loads(d)["type"] for _, e, d in frames if e == "ledger"][-1] == "task.end"
        assert frames[-1][1] == "end"


def decide_in_background(c, tid, approve):
    """A UI stand-in: poll the pending list, then answer. (TestClient cannot
    interleave requests inside an open stream, so a second thread plays the user.)"""
    seen = {}

    def work():
        for _ in range(100):
            pend = c.get("/api/approvals", params={"task_id": tid}).json()["pending"]
            if pend:
                time.sleep(0.1)   # a human takes a moment; also keeps approval_wait_s > 0 after rounding
                seen["pending"] = pend[0]
                seen["resp"] = c.post(f"/api/approvals/{pend[0]['id']}", json={"approve": approve})
                return
            time.sleep(0.02)
    t = threading.Thread(target=work)
    t.start()
    return t, seen


def ledger_types(frames):
    return [json.loads(d)["type"] for _, e, d in frames if e == "ledger"]


def test_approval_flow_approve(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "approve me")
        t, seen = decide_in_background(c, tid, True)
        types = ledger_types(stream_all(c, tid))
        t.join(5)
        assert seen["pending"]["task_id"] == tid and "expires_at" in seen["pending"]
        assert seen["resp"].status_code == 200
        assert "approval.granted" in types and "approval.denied" not in types
        # resolved -> second click is rejected, not silently accepted
        assert c.post("/api/approvals/ap000001", json={"approve": False}).status_code == 409
        assert c.get("/api/approvals").json()["pending"] == []
        pol = c.get(f"/api/tasks/{tid}/report").json()["dimensions"]["policy"]
        assert (pol["approvals_requested"], pol["approvals_granted"]) == (1, 1)
        tm = c.get(f"/api/tasks/{tid}/report").json()["dimensions"]["time"]
        assert tm["approval_wait_s"] > 0 and tm["active_s"] < tm["wall_clock_s"]


def test_approval_timeout_is_deny_and_unknown_id_404(tmp_path):
    with make(tmp_path, approval_timeout_s=0.3) as c:
        assert c.post("/api/approvals/nope", json={"approve": True}).status_code == 404
        tid = run(c, "approve me")
        types = [json.loads(d)["type"] for _, e, d in stream_all(c, tid) if e == "ledger"]
        assert "approval.denied" in types and "approval.granted" not in types
        assert c.post("/api/approvals/ap000001", json={"approve": True}).status_code == 409


def test_deny_decision(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "approve me")
        t, seen = decide_in_background(c, tid, False)
        types = ledger_types(stream_all(c, tid))
        t.join(5)
        assert seen["resp"].json()["decision"] == "deny"
        assert "approval.denied" in types and "approval.granted" not in types
        assert c.get(f"/api/tasks/{tid}").json()["status"] == "halted:policy_denials"


def test_ids_cannot_escape_ledger_dir(tmp_path):
    secret = tmp_path.parent / "outside.jsonl"
    secret.write_text("{}\n")
    with make(tmp_path) as c:
        for bad in ("..%2foutside", "%2e%2e%2foutside", "ABCDEFGH", "x" * 40, "../outside"):
            assert c.get(f"/api/ledger/verify/{bad}").status_code == 404
            assert c.get(f"/api/tasks/{bad}/report").status_code == 404
            assert c.get(f"/api/tasks/{bad}/events").status_code == 404


def test_tampered_ledger_fails_verification(tmp_path):
    with make(tmp_path) as c:
        tid = run(c)
        stream_all(c, tid)
        p = tmp_path / f"{tid}.jsonl"
        lines = p.read_text().splitlines()
        ev = json.loads(lines[2])
        ev["payload"]["host"] = "innocent.example"
        lines[2] = json.dumps(ev)
        p.write_text("\n".join(lines) + "\n")
        v = c.get(f"/api/ledger/verify/{tid}").json()
        assert not v["verified"] and "tampered" in v["detail"]
        rep = c.get(f"/api/tasks/{tid}/report").json()
        assert rep["ledger"]["verified"] is False
        # a corrupt line in the middle is an error, never silently skipped
        lines[2] = "{not json"
        p.write_text("\n".join(lines) + "\n")
        assert not c.get(f"/api/ledger/verify/{tid}").json()["verified"]


def test_html_report_escapes_untrusted_text(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "<script>alert(1)</script> & <img src=x onerror=y>")
        stream_all(c, tid)
        r = c.get(f"/api/tasks/{tid}/report", params={"format": "html"})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        assert "<script>" not in r.text and "<img" not in r.text
        assert "&lt;script&gt;" in r.text
        assert "default-src 'none'" in r.headers["content-security-policy"]


def test_history_survives_restart(tmp_path):
    with make(tmp_path) as c:
        tid = run(c)
        full = [f for f in stream_all(c, tid) if f[1] == "ledger"]
    with make(tmp_path) as c2:   # new process, same ledger dir
        replay = stream_all(c2, tid)
        # same events (the file stores sorted-key JSON, so compare parsed, not raw strings)
        assert [(i, json.loads(d)) for i, e, d in replay if e == "ledger"] == \
               [(i, json.loads(d)) for i, e, d in full]
        assert json.loads(replay[-1][2])["replayed"] is True
        assert c2.get(f"/api/tasks/{tid}").json()["status"] == "finished"


def test_validation_limits_and_config_errors(tmp_path):
    with make(tmp_path) as c:
        assert c.post("/api/tasks", json={"task": ""}).status_code == 422
        assert c.post("/api/tasks", json={"task": "x" * 5000}).status_code == 422
        assert c.post("/api/tasks", json={"task": "x", "profile": "yolo"}).status_code == 422

    def broken():
        raise KeyError("LLM_MODEL")
    with make(tmp_path, llm_factory=broken) as c:
        assert c.post("/api/tasks", json={"task": "x"}).status_code == 503

    with make(tmp_path, max_concurrent=1) as c:
        first = run(c, "slow one")
        assert c.post("/api/tasks", json={"task": "second"}).status_code == 429
        stream_all(c, first)
        time.sleep(0.1)
        assert c.post("/api/tasks", json={"task": "third"}).status_code == 202


def test_runner_crash_is_reported_without_traceback(tmp_path):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail")
    with make(tmp_path, runner=boom) as c:
        tid = run(c)
        frames = stream_all(c, tid)
        end = json.loads(frames[-1][2])
        assert end["status"] == "error" and "secret" not in json.dumps(end)
        assert c.get(f"/api/tasks/{tid}").json()["status"] == "error"


def test_bearer_token_guard(tmp_path):
    with make(tmp_path, api_token="s3cret") as c:
        assert c.get("/health").status_code == 200
        assert c.post("/api/tasks", json={"task": "x"}).status_code == 401
        assert c.post("/api/tasks", json={"task": "x"}, headers={"Authorization": "Bearer nope"}).status_code == 401
        h = {"Authorization": "Bearer s3cret"}
        tid = c.post("/api/tasks", json={"task": "x"}, headers=h).json()["task_id"]
        assert c.get(f"/api/ledger/verify/{tid}").status_code == 401
        time.sleep(0.3)
        assert c.get(f"/api/ledger/verify/{tid}", headers=h).json()["verified"]
