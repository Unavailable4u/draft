"""End-to-end: real run_task + real sandbox container, driven through the API.
Needs a Docker daemon (same as the other sandbox tests); the LLM is scripted."""
from fastapi.testclient import TestClient

from airlock.agent.loop import run_task
from airlock.api.app import create_app
from test_agent_loop import FakeLLM, call, leaked


def test_strict_task_through_api(tmp_path):
    llm = FakeLLM([
        [call("run_shell", cmd="rm -rf --no-preserve-root /")],   # blocked by policy, never runs
        [call("run_shell", cmd="echo hi")],
        [call("finish", summary="done")],
    ])
    app = create_app(runner=run_task, llm_factory=lambda: llm, egress_factory=lambda: None,
                     ledger_dir=str(tmp_path))
    with TestClient(app) as c:
        tid = c.post("/api/tasks", json={"task": "hostile", "profile": "strict"}).json()["task_id"]
        with c.stream("GET", f"/api/tasks/{tid}/events") as r:
            list(r.iter_lines())   # drain until the end frame
        rep = c.get(f"/api/tasks/{tid}/report").json()
        assert rep["outcome"] == "finished" and rep["ledger"]["verified"]
        assert rep["dimensions"]["policy"]["by_action"].get("deny") == 1
        assert rep["dimensions"]["persistence"]["final_sandbox_destroyed"]
        assert c.get(f"/api/ledger/verify/{tid}").json()["verified"]
    assert leaked() == []
