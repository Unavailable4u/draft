"""Rewind, release and hold through the API, and the infra endpoint. A fake runner stands in for the loop: it uses the same
TaskControl the real loop does, so what is tested is the API's wiring and its refusals, not Docker."""
import threading
import time

from fastapi.testclient import TestClient

from minilocker.api.app import create_app
from minilocker.infra import status as infra
from minilocker.ledger.chain import Ledger

SEEN = {}


def control_runner(task, llm, ledger_dir, egress, policy, approver, on_event, task_id, control=None, hold_s=0, **_):
    ledger = Ledger(task_id, f"{ledger_dir}/{task_id}.jsonl")
    log = lambda a, t, p=None: on_event(ledger.append(a, t, p))
    SEEN["hold_s"], SEEN["control"] = hold_s, control
    log("user", "task.start", {"task": task, "profile": "strict"})
    control.enabled = "unsupported" not in task
    control.publish([0, 1, 2])
    deadline = time.time() + 5
    while time.time() < deadline and not control.released.is_set():
        sid = control.take_rewind()
        if sid is not None:
            log("control", "timeline.rewound", {"to_snapshot": sid})
            control.publish([i for i in [0, 1, 2] if i <= sid])
        time.sleep(0.02)
    log("agent", "task.end", {"status": "finished", "steps": 0, "summary": "done"})
    return {"task_id": task_id, "status": "finished", "ledger_verified": True, "ledger": "ok"}


def make(tmp_path, **kw):
    return TestClient(create_app(ledger_dir=str(tmp_path), runner=control_runner, llm_factory=lambda: object(),
                                 egress_factory=lambda: None, artifacts_factory=lambda: (None, None), **kw))


def start(c, task="work", **kw):
    r = c.post("/api/tasks", json={"task": task, **kw})
    assert r.status_code == 202, r.text
    tid = r.json()["task_id"]
    for _ in range(100):
        if SEEN.get("control") is not None and SEEN["control"].snapshots:
            break
        time.sleep(0.02)
    return tid


def test_rewind_is_queued_and_the_task_reports_its_snapshots(tmp_path):
    with make(tmp_path) as c:
        tid = start(c)
        info = c.get(f"/api/tasks/{tid}").json()
        assert info["control"]["rewind"] is True and info["control"]["snapshots"] == [0, 1, 2]
        r = c.post(f"/api/tasks/{tid}/rewind", json={"snapshot": 1})
        assert r.status_code == 202 and r.json()["status"] == "queued"
        for _ in range(100):
            if c.get(f"/api/tasks/{tid}").json()["control"]["snapshots"] == [0, 1]:
                break
            time.sleep(0.02)
        assert c.get(f"/api/tasks/{tid}").json()["control"]["snapshots"] == [0, 1]
        c.post(f"/api/tasks/{tid}/release")


def test_rewind_refusals(tmp_path):
    with make(tmp_path) as c:
        assert c.post("/api/tasks/deadbeef/rewind", json={"snapshot": 0}).status_code == 404
        tid = start(c)
        assert c.post(f"/api/tasks/{tid}/rewind", json={"snapshot": 99}).status_code == 404
        assert c.post(f"/api/tasks/{tid}/rewind", json={"snapshot": -1}).status_code == 422
        assert c.post(f"/api/tasks/{tid}/rewind", json={}).status_code == 422
        c.post(f"/api/tasks/{tid}/release")
        for _ in range(100):
            if c.get(f"/api/tasks/{tid}").json()["status"] != "running":
                break
            time.sleep(0.02)
        r = c.post(f"/api/tasks/{tid}/rewind", json={"snapshot": 1})
        assert r.status_code == 409 and "ended" in r.json()["detail"]
        assert c.post(f"/api/tasks/{tid}/release").status_code == 409


def test_a_sandbox_that_cannot_snapshot_refuses_a_rewind(tmp_path):
    with make(tmp_path) as c:
        tid = start(c, task="unsupported")
        r = c.post(f"/api/tasks/{tid}/rewind", json={"snapshot": 1})
        assert r.status_code == 409 and "cannot snapshot" in r.json()["detail"]
        assert c.get(f"/api/tasks/{tid}").json()["control"]["rewind"] is False
        c.post(f"/api/tasks/{tid}/release")


def test_hold_is_passed_to_the_runner_and_bounded(tmp_path):
    with make(tmp_path) as c:
        assert c.post("/api/tasks", json={"task": "x", "hold_s": 100000}).status_code == 422
        assert c.post("/api/tasks", json={"task": "x", "hold_s": -1}).status_code == 422
        tid = start(c, hold_s=30)
        assert SEEN["hold_s"] == 30 and c.get(f"/api/tasks/{tid}").json()["control"]["hold_s"] == 30
        assert c.post(f"/api/tasks/{tid}/release").json() == {"task_id": tid, "released": True}


def test_a_runner_that_knows_nothing_of_control_still_runs(tmp_path):
    from minilocker.ledger.chain import Ledger as L

    def old_runner(task, llm, ledger_dir, egress, policy, approver, on_event, task_id):
        l = L(task_id, f"{ledger_dir}/{task_id}.jsonl")
        on_event(l.append("agent", "task.end", {"status": "finished"}))
        return {"status": "finished", "task_id": task_id}
    with TestClient(create_app(ledger_dir=str(tmp_path), runner=old_runner, llm_factory=lambda: object(),
                               egress_factory=lambda: None, artifacts_factory=lambda: (None, None))) as c:
        tid = c.post("/api/tasks", json={"task": "x", "hold_s": 5}).json()["task_id"]
        for _ in range(100):
            if c.get(f"/api/tasks/{tid}").json()["status"] == "finished":
                break
            time.sleep(0.02)
        assert c.get(f"/api/tasks/{tid}").json()["status"] == "finished"


def test_control_endpoints_need_the_token_when_one_is_set(tmp_path):
    with make(tmp_path, api_token="s3cret") as c:
        assert c.post("/api/tasks/deadbeef/rewind", json={"snapshot": 0}).status_code == 401
        assert c.post("/api/tasks/deadbeef/release").status_code == 401
        assert c.get("/api/infra").status_code == 401
        assert c.get("/api/infra", headers={"Authorization": "Bearer s3cret"}).status_code == 200


# ---- infra --------------------------------------------------------------------------------------------------------------
def test_infra_reports_what_is_attached_and_no_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.vultrinference.com/v1")
    monkeypatch.setenv("LLM_MODEL", "some-model")
    monkeypatch.setenv("LLM_API_KEY", "sk-super-secret-value-123456")
    monkeypatch.setenv("MINILOCKER_S3_ENDPOINT", "https://ewr1.vultrobjects.com")
    monkeypatch.setenv("MINILOCKER_S3_SECRET_KEY", "s3-super-secret-value-123456")
    with make(tmp_path) as c:
        body = c.get("/api/infra").json()
    assert body["inference"] == {"configured": True, "host": "api.vultrinference.com", "model": "some-model",
                                 "key_set": True, "tool_mode": "native", "vultr": True}
    assert body["storage"]["endpoint_host"] == "ewr1.vultrobjects.com" and body["storage"]["vultr"] is True
    assert body["storage"]["attached"] is False and body["egress"] == {"attached": False}
    assert set(body) >= {"host", "docker", "egress", "inference", "storage", "vultr"}
    blob = str(body)
    assert "super-secret" not in blob and "sk-" not in blob


def test_vultr_metadata_is_parsed_cached_and_fails_closed():
    infra._meta_cache.update(at=0.0, value=None)
    calls = []

    def ok():
        calls.append(1)
        return (b'{"hostname":"airlock","region":{"regioncode":"EWR"},"plan":"vc2-2c-4gb","instanceid":"abc",'
                b'"interfaces":[{"ipv4":{"address":"203.0.113.9"}}]}')
    got = infra.vultr_metadata(fetch=ok, now=lambda: 1000.0)
    assert got == {"available": True, "hostname": "airlock", "region": "EWR", "plan": "vc2-2c-4gb", "instance_id": "abc",
                   "public_ipv4": "203.0.113.9"}
    assert infra.vultr_metadata(fetch=ok, now=lambda: 1050.0) == got and len(calls) == 1      # cached
    infra._meta_cache.update(at=0.0, value=None)

    def down():
        raise OSError("no route")
    bad = infra.vultr_metadata(fetch=down, now=lambda: 5000.0)
    assert bad["available"] is False and "not a Vultr instance" in bad["reason"]
    infra._meta_cache.update(at=0.0, value=None)


def test_docker_info_when_there_is_no_daemon_says_so():
    class Boom:
        def version(self):
            raise ConnectionError("no daemon")
    d = infra.docker_info(Boom())
    assert d == {"available": False, "reason": "ConnectionError", "sandboxes": []}


# ---- scenarios through the API ------------------------------------------------------------------------------------------
GOT = {}


def scenario_runner(task, llm, ledger_dir, egress, policy, approver, on_event, task_id, files=None, verify=None, **_):
    GOT.update(task=task, files=files, verify=verify, budgets=policy.budgets)
    ledger = Ledger(task_id, f"{ledger_dir}/{task_id}.jsonl")
    on_event(ledger.append("agent", "task.end", {"status": "finished", "steps": 0, "summary": ""}))
    return {"task_id": task_id, "status": "finished", "ledger_verified": True, "ledger": "ok"}


def test_a_scenario_supplies_the_task_files_check_and_budgets(tmp_path):
    from minilocker.scenarios import SCENARIOS
    sc = SCENARIOS["fix_repo_v2"]
    with TestClient(create_app(ledger_dir=str(tmp_path), runner=scenario_runner, llm_factory=lambda: object(),
                               egress_factory=lambda: None, artifacts_factory=lambda: (None, None))) as c:
        r = c.post("/api/tasks", json={"scenario": "fix_repo_v2", "task": "ignored text"})
        assert r.status_code == 202
        for _ in range(100):
            if GOT.get("task"):
                break
            time.sleep(0.02)
        assert GOT["task"] == sc.task and GOT["files"] == sc.files and GOT["verify"] is sc.verify
        assert GOT["budgets"] == sc.budgets
        assert c.get(f"/api/tasks/{r.json()['task_id']}").json()["scenario"] == "fix_repo_v2"
        assert c.post("/api/tasks", json={"scenario": "nope"}).status_code == 404
        assert c.post("/api/tasks", json={}).status_code == 422
        assert c.post("/api/tasks", json={"task": "   "}).status_code == 422


def test_scenarios_are_listed_with_what_they_need(tmp_path, monkeypatch):
    monkeypatch.setenv("MINILOCKER_ALLOW", "pypi.org")
    with make(tmp_path) as c:
        by = {s["id"]: s for s in c.get("/api/scenarios").json()["scenarios"]}
    assert {"fix_repo", "fix_repo_v2", "research"} <= set(by)
    assert by["fix_repo_v2"]["available"] is True and by["fix_repo_v2"]["task"]
    assert by["research"]["available"] is False and by["research"]["missing_hosts"]
