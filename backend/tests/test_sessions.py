"""Sessions list (GET /api/tasks) and the replay end-frame. No Docker, no LLM."""
import json
import time

from test_api import make, run, stream_all

from minilocker.ledger.chain import Ledger
from minilocker.ledger.summary import summarize


def finished(c, task="hello"):
    tid = run(c, task)
    stream_all(c, tid)          # returns when the task has ended
    time.sleep(0.02)            # distinct file mtimes
    return tid


def test_list_is_newest_first_with_a_summary_per_task(tmp_path):
    with make(tmp_path) as c:
        a = finished(c, "first")
        b = finished(c, "Attack Lab: Fork bomb")
        rows = c.get("/api/tasks").json()["tasks"]
        assert [r["task_id"] for r in rows] == [b, a]
        r = {x["task_id"]: x for x in rows}
        assert r[a]["kind"] == "task" and r[b]["kind"] == "attack"
        assert r[a]["status"] == "finished" and r[a]["verified"] is True
        assert r[a]["task"] == "first" and r[a]["profile"] == "strict"
        assert r[a]["egress_blocked"] == 1 and r[a]["events"] > 4 and r[a]["duration_s"] >= 0


def test_a_running_task_is_listed_as_running(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "slow task")
        seen = None
        for _ in range(100):
            seen = next((r for r in c.get("/api/tasks").json()["tasks"] if r["task_id"] == tid), None)
            if seen:
                break
            time.sleep(0.01)
        assert seen and seen["status"] == "running"
        stream_all(c, tid)
        assert c.get("/api/tasks").json()["tasks"][0]["status"] == "finished"


def test_tampering_shows_up_in_the_list(tmp_path):
    with make(tmp_path) as c:
        tid = finished(c)
        p = tmp_path / f"{tid}.jsonl"
        p.write_text(p.read_text().replace("pypi.org", "pypj.org"))
        row = c.get("/api/tasks").json()["tasks"][0]
        assert row["task_id"] == tid and row["verified"] is False


def test_limit_and_foreign_files(tmp_path):
    with make(tmp_path) as c:
        for i in range(3):
            finished(c, f"t{i}")
        (tmp_path / "README.md").write_text("not a ledger")
        (tmp_path / "evil.jsonl").write_text("{}")             # not a task id: must be ignored
        (tmp_path / "..%2f..%2fetc.jsonl").write_text("{}")
        assert len(c.get("/api/tasks").json()["tasks"]) == 3
        assert len(c.get("/api/tasks?limit=2").json()["tasks"]) == 2
        assert c.get("/api/tasks?limit=0").status_code == 422


def test_list_requires_the_token_when_one_is_set(tmp_path):
    with make(tmp_path, api_token="s3cret") as c:
        assert c.get("/api/tasks").status_code == 401
        assert c.get("/api/tasks", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_replay_end_frame_carries_the_real_status(tmp_path):
    with make(tmp_path) as c:
        tid = run(c, "approve me")
        for _ in range(200):
            pend = c.get("/api/approvals", params={"task_id": tid}).json()["pending"]
            if pend:
                break
            time.sleep(0.02)
        assert c.post(f"/api/approvals/{pend[0]['id']}", json={"approve": False}).status_code == 200
        stream_all(c, tid)
    with make(tmp_path) as c2:                                   # restart: served from disk
        end = [f for f in stream_all(c2, tid) if f[1] == "end"][0]
        info = json.loads(end[2])
        assert info["replayed"] is True and info["status"] == "halted:policy_denials"


def test_summarize_an_unfinished_ledger(tmp_path):
    led = Ledger("deadbeef", str(tmp_path / "deadbeef.jsonl"))
    led.append("user", "task.start", {"task": "x", "profile": "observe"})
    led.append("agent", "tool.call", {"tool": "run_shell"})
    s = summarize("deadbeef", led.events)
    assert s["status"] == "incomplete" and s["tool_calls"] == 1 and s["duration_s"] is None
    assert summarize("deadbeef", led.events, live=True)["status"] == "running"
