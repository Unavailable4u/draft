"""The containment suite: `pytest -m attacks`.

Every attack defined in minilocker.attacks runs against real Docker sandboxes, with the egress
proxy attached exactly as in the API. The attack list is the same tuple the Attack Lab UI shows,
so adding an attack there adds it here. A missing Docker daemon FAILS the suite: a skipped
security suite would look green.

Stop the dev API first: starting the egress proxy replaces the one the API is using."""
import threading

import docker
import pytest
from fastapi.testclient import TestClient

from minilocker.agent.loop import run_task
from minilocker.api.app import create_app
from minilocker.attacks import ATTACKS, run_attack
from minilocker.egress.manager import EgressManager

pytestmark = pytest.mark.attacks
ALLOW = ["pypi.org", "files.pythonhosted.org"]


@pytest.fixture(scope="module")
def egress():
    try:
        docker.from_env().ping()
    except Exception as e:
        pytest.fail(f"Docker daemon not reachable ({type(e).__name__}); the attack suite cannot run", pytrace=False)
    m = EgressManager(ALLOW).start()
    yield m
    m.stop()


def report(res):
    lines = [f"{res['name']}: {res['verdict']}" + (f" ({res['error']})" if res["error"] else "")]
    lines += [f"  [{c['status']}] {c['label']}: {c['detail']}" for c in res["checks"]]
    for s in res["steps"]:
        lines.append(f"  step {s['index']} {s['tool']} policy={(s['policy'] or {}).get('action')} "
                     f"result={(s['result'] or '')[:300]!r}")
    return "\n".join(lines)


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.name for a in ATTACKS])
def test_attack_is_contained(attack, egress, tmp_path):
    res = run_attack(attack, ledger_dir=str(tmp_path), egress=egress)
    assert res["verdict"] == "contained", report(res)


def test_attack_through_the_api_leaves_a_verifiable_ledger_and_a_live_control_plane(egress, tmp_path):
    app = create_app(runner=run_task, llm_factory=lambda: object(), egress_factory=lambda: egress,
                     ledger_dir=str(tmp_path))
    with TestClient(app) as c:
        out, health = {}, []
        t = threading.Thread(target=lambda: out.setdefault("r", c.post("/api/attacks/fork_bomb/run")))
        t.start()
        while t.is_alive():                      # the control plane must answer DURING the fork bomb
            health.append(c.get("/health").status_code)
            t.join(0.5)
        r = out["r"]
        assert r.status_code == 200 and r.json()["verdict"] == "contained", report(r.json())
        assert health and set(health) == {200}
        tid = r.json()["task_id"]
        assert c.get(f"/api/ledger/verify/{tid}").json()["verified"]
        rep = c.get(f"/api/tasks/{tid}/report").json()
        assert rep["outcome"] == "finished" and rep["dimensions"]["persistence"]["final_sandbox_destroyed"]


def test_no_containers_leaked_by_the_suite():
    """Runs last in this module: after everything above, no sandbox may remain."""
    left = docker.from_env().containers.list(all=True, filters={"label": "minilocker=sandbox"})
    assert left == []
