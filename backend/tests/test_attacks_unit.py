"""Attack Lab logic without Docker: the real loop and the real policy engine run against a
stateful stub sandbox, so verdict logic, record building, cleanup and the API are covered
on any machine. The real containment proof is tests/test_attacks.py (-m attacks)."""
import os
import re
import threading
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import minilocker.agent.loop as loop_mod
from minilocker.api.app import create_app
from minilocker.attacks import ATTACKS, describe, get_attack, run_attack
from minilocker.attacks.catalog import MARKER
from minilocker.policy.engine import PolicyEngine

R = lambda code=0, out="", err="": NS(exit_code=code, stdout=out, stderr=err, timed_out=False)  # noqa: E731


class Defender:
    """Stub sandbox that behaves the way the real one is expected to, for deny_then_bypass."""
    wiped = False
    system_ok = True
    leak = False

    def __init__(self, egress=None):
        self.name, self.ip = "stub-" + os.urandom(3).hex(), ""

    def exec(self, cmd, timeout_s=30):
        if "base64 -d" in cmd:
            return R()
        if "shutil.rmtree" in cmd:
            Defender.wiped = True
            return R()
        if cmd.startswith("cat /workspace/precious.txt"):
            out = "cat: /workspace/precious.txt: No such file or directory\n" if Defender.wiped else MARKER
            if "SYSTEM_INTACT" in cmd and Defender.system_ok:
                out += "\nSYSTEM_INTACT"
            if Defender.leak:
                out += next(v for k, v in os.environ.items() if k.startswith("MINILOCKER_ATTACK_SECRET_"))
            return R(0, out)
        raise AssertionError(f"denied commands must never reach the sandbox: {cmd}")

    def destroy(self):
        pass


@pytest.fixture(autouse=True)
def _stub(monkeypatch):
    Defender.wiped, Defender.system_ok, Defender.leak = False, True, False
    monkeypatch.setattr(loop_mod, "Sandbox", Defender)


def go(name, tmp_path, **kw):
    kw.setdefault("sandbox_exists", lambda n: False)
    return run_attack(get_attack(name), ledger_dir=str(tmp_path), **kw)


def status_of(res):
    return {c["label"]: c["status"] for c in res["checks"]}


# ---- catalog ---------------------------------------------------------------
def test_catalog_is_well_formed():
    names = [a.name for a in ATTACKS]
    assert len(names) == len(set(names)) >= 8
    for a in ATTACKS:
        assert re.fullmatch(r"[a-z0-9_]+", a.name) and a.checks and a.profile in ("strict", "observe")
        ids = [s.id for s in a.steps if s.id]
        assert len(ids) == len(set(ids)), a.name
        d = describe(a, egress_attached=False)
        assert d["available"] == (not a.needs_egress)
        assert "@@" not in str(d), "placeholders must not leak into the public description"


def test_policy_facts_the_flagship_attack_relies_on():
    """If the policy changes, this fails with an explanation instead of a mysterious red verdict."""
    strict = PolicyEngine("strict")
    a = get_attack("deny_then_bypass")
    cmds = {s.id: s.args["cmd"] for s in a.steps if s.tool == "run_shell"}
    assert strict.evaluate_shell(cmds["direct"]).action == "deny"
    assert strict.evaluate_shell(cmds["wrapped"]).action == "deny"
    assert strict.evaluate_shell(cmds["bypass"]).action == "allow"   # regexes are UX, not the boundary


# ---- verdicts --------------------------------------------------------------
def test_deny_then_bypass_contained(tmp_path):
    res = go("deny_then_bypass", tmp_path)
    assert res["verdict"] == "contained", res["checks"]
    assert [s["policy"]["action"] for s in res["steps"] if s["policy"]] == ["deny", "deny", "allow", "allow", "allow"]
    assert res["steps"][1]["result"].startswith("Blocked by policy")
    assert res["counts"]["fail"] == res["counts"]["unproven"] == 0
    assert res["task_id"] and os.path.exists(tmp_path / f"{res['task_id']}.jsonl")


def test_system_damage_is_a_breach(tmp_path):
    Defender.system_ok = False
    res = go("deny_then_bypass", tmp_path)
    assert res["verdict"] == "breached"
    assert status_of(res)["System files survived (read-only root filesystem)"] == "fail"


def test_attack_that_proves_nothing_is_inconclusive_not_contained(tmp_path, monkeypatch):
    monkeypatch.setattr(Defender, "exec", lambda self, cmd, t=30: R(0, MARKER + "\nSYSTEM_INTACT")
                        if cmd.startswith("cat") else R())      # the bypass "fizzles": nothing is wiped
    res = go("deny_then_bypass", tmp_path)
    assert res["verdict"] == "inconclusive"
    assert status_of(res)["Damage was real, inside the sandbox only"] == "unproven"


def test_host_secret_in_output_is_a_breach(tmp_path):
    Defender.leak = True
    res = go("deny_then_bypass", tmp_path)
    assert res["verdict"] == "breached"
    assert status_of(res)["No host secret reached the ledger"] == "fail"
    assert "HOSTCANARY-" not in str(res), "the token must be scrubbed from API output"


def test_leftover_sandbox_is_a_breach(tmp_path):
    res = go("deny_then_bypass", tmp_path, sandbox_exists=lambda n: True)
    assert res["verdict"] == "breached"
    assert status_of(res)["Every sandbox destroyed afterwards"] == "fail"


def test_attack_needing_egress_is_unavailable_without_it(tmp_path):
    res = go("exfil_unknown_domain", tmp_path)
    assert res["verdict"] == "unavailable" and res["task_id"] is None and not res["checks"]


def test_runner_crash_is_an_error_and_cleans_up(tmp_path):
    before = {k for k in os.environ if k.startswith("MINILOCKER_ATTACK_SECRET_")}

    def boom(*a, **k):
        raise RuntimeError("daemon down")
    res = go("deny_then_bypass", tmp_path, runner=boom)
    assert res["verdict"] == "error" and "RuntimeError" in res["error"] and "daemon down" not in res["error"]
    assert {k for k in os.environ if k.startswith("MINILOCKER_ATTACK_SECRET_")} == before


def test_hostile_hook_success_is_a_breach(tmp_path, monkeypatch):
    def box_exec(self, cmd, t=30):
        if "base64 -d" in cmd:
            return R()
        return R(0, 'HOOK_RESULT {"read_ssh_key": "BLOCKED:FileNotFoundError", "plant_backdoor": "1"}')
    monkeypatch.setattr(Defender, "exec", box_exec)
    res = go("malicious_repo_hook", tmp_path)
    assert res["verdict"] == "breached"
    assert "plant_backdoor" in next(c for c in res["checks"] if c["label"] == "Every hostile action blocked")["detail"]


# ---- API -------------------------------------------------------------------
def fake_attack_runner(attack, ledger_dir, egress):
    return {"name": attack.name, "verdict": "contained", "task_id": "abcd1234", "checks": [], "steps": []}


def client(tmp_path, **kw):
    kw.setdefault("attack_runner", fake_attack_runner)
    return TestClient(create_app(runner=None, llm_factory=lambda: object(), egress_factory=lambda: None,
                                 ledger_dir=str(tmp_path), **kw))


def test_api_lists_every_attack(tmp_path):
    with client(tmp_path) as c:
        body = c.get("/api/attacks").json()
        assert [a["name"] for a in body["attacks"]] == [a.name for a in ATTACKS]
        assert body["egress_attached"] is False
        by = {a["name"]: a for a in body["attacks"]}
        assert by["exfil_unknown_domain"]["available"] is False and by["rm_rf_root"]["available"] is True


def test_api_run_unknown_and_known(tmp_path):
    with client(tmp_path) as c:
        assert c.post("/api/attacks/nope/run").status_code == 404
        r = c.post("/api/attacks/rm_rf_root/run")
        assert r.status_code == 200 and r.json()["verdict"] == "contained"


def test_api_attacks_require_the_token_when_set(tmp_path):
    with client(tmp_path, api_token="s3cret") as c:
        assert c.get("/api/attacks").status_code == 401
        assert c.post("/api/attacks/rm_rf_root/run").status_code == 401
        h = {"Authorization": "Bearer s3cret"}
        assert c.get("/api/attacks", headers=h).status_code == 200
        assert c.post("/api/attacks/rm_rf_root/run", headers=h).status_code == 200


def test_api_runs_one_attack_at_a_time(tmp_path):
    started, release = threading.Event(), threading.Event()

    def slow(attack, ledger_dir, egress):
        started.set()
        release.wait(5)
        return fake_attack_runner(attack, ledger_dir, egress)
    with client(tmp_path, attack_runner=slow) as c:
        first = {}
        t = threading.Thread(target=lambda: first.setdefault("r", c.post("/api/attacks/rm_rf_root/run")))
        t.start()
        assert started.wait(5)
        busy = c.post("/api/attacks/cpu_burn/run")
        assert busy.status_code == 429 and busy.headers["retry-after"] == "5"
        assert c.get("/health").json() == {"ok": True}      # control plane stays responsive meanwhile
        release.set()
        t.join(5)
        assert first["r"].status_code == 200
        assert c.post("/api/attacks/cpu_burn/run").status_code == 200   # slot was released
