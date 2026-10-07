import os
from types import SimpleNamespace as NS

import pytest

from minilocker.agent.loop import run_task
from minilocker.policy.approvals import ApprovalGate
from minilocker.policy.engine import Budgets, PolicyEngine
import minilocker.agent.loop as loop_mod
from test_agent_loop import CANARY, FakeLLM, call, leaked


def results(evs):
    return [e["payload"]["result"] for e in evs if e["type"] == "tool.result"]


def kinds(evs):
    return [e["type"] for e in evs]


def script(cmd):
    """write a marker file, run cmd, then check whether the marker survived"""
    return [
        [call("write_file", path="/workspace/m.txt", content="alive")],
        [call("run_shell", cmd=cmd)],
        [call("run_shell", cmd="cat /workspace/m.txt")],
        [call("finish", summary="x")],
    ]


def go(cmd, tmp_path, **kw):
    evs = []
    r = run_task("t", FakeLLM(script(cmd)), ledger_dir=str(tmp_path), on_event=evs.append, **kw)
    return r, evs


def test_strict_denies_and_command_never_runs(tmp_path):
    r, evs = go("rm -rf --no-preserve-root /; rm -f /workspace/m.txt", tmp_path,
                policy=PolicyEngine("strict"))
    rs = results(evs)
    assert rs[1].startswith("Blocked by policy")
    assert rs[2].startswith("exit_code=0") and "alive" in rs[2]  # marker untouched: it never ran
    d = [e for e in evs if e["type"] == "policy.decision"][0]["payload"]
    assert d["action"] == "deny" and d["risk"] == "high"
    assert r["ledger_verified"] and leaked() == []


def test_medium_runs_when_approved(tmp_path):
    r, evs = go("cat /proc/1/environ >/dev/null; rm -f /workspace/m.txt", tmp_path,
                policy=PolicyEngine("strict"), approver=lambda req: True)
    assert "approval.granted" in kinds(evs)
    assert "exit_code=1" in results(evs)[2]  # marker gone: it ran
    assert r["ledger_verified"] and leaked() == []


def test_medium_blocked_when_denied_or_unanswered(tmp_path):
    cmd = "cat /proc/1/environ >/dev/null; rm -f /workspace/m.txt"
    for approver in (lambda req: False, None, ApprovalGate(timeout_s=0.3).ask):
        r, evs = go(cmd, tmp_path, policy=PolicyEngine("strict"), approver=approver)
        assert "approval.requested" in kinds(evs) and "approval.denied" in kinds(evs)
        assert "alive" in results(evs)[2]
    assert leaked() == []


def test_observe_runs_hostile_command_inside_sandbox(tmp_path):
    open(CANARY, "w").write("host data")
    r, evs = go("rm -rf --no-preserve-root /usr /etc /workspace/* 2>&1 | tail -2", tmp_path,
                policy=PolicyEngine("observe"))
    d = [e for e in evs if e["type"] == "policy.decision"][0]["payload"]
    assert d["action"] == "allow_in_sandbox" and d["risk"] == "high"
    assert "exit_code=1" in results(evs)[2]  # workspace really was wiped inside the sandbox
    assert open(CANARY).read() == "host data"  # host untouched
    assert r["ledger_verified"] and leaked() == []


def test_deadline_budget_halts_task(tmp_path):
    r = run_task("t", FakeLLM([]), ledger_dir=str(tmp_path),
                 policy=PolicyEngine("strict", Budgets(task_deadline_s=0)))
    assert r["status"] == "halted:deadline" and leaked() == []


def test_repeated_denials_halt_task(tmp_path):
    cmds = ["rm -rf /", "rm -rf /usr", "rm -rf /etc"]
    r = run_task("t", FakeLLM([[call("run_shell", cmd=c)] for c in cmds]), ledger_dir=str(tmp_path),
                 policy=PolicyEngine("strict", Budgets(max_denials=2)))
    assert r["status"] == "halted:policy_denials" and r["denials"] == 2 and leaked() == []


class ExplodingLLM(FakeLLM):
    """Answers its script, then fails like a provider error would."""
    def chat(self, messages, tools=None):
        if not self.script:
            raise RuntimeError("provider exploded")
        return super().chat(messages, tools)


class StubSandbox:
    name, ip = "stub", "0.0.0.0"

    def __init__(self, egress=None):
        pass

    def exec(self, cmd, timeout_s):
        return NS(exit_code=0, stdout="hi", stderr="", timed_out=False)

    def destroy(self):
        pass


def test_crash_is_recorded_as_error_not_max_steps(tmp_path, monkeypatch):
    """No Docker needed. A mid-task exception must not be logged as a budget halt."""
    monkeypatch.setattr(loop_mod, "Sandbox", StubSandbox)
    evs = []
    with pytest.raises(RuntimeError):
        run_task("t", ExplodingLLM([[call("run_shell", cmd="echo hi")]]), ledger_dir=str(tmp_path),
                 on_event=evs.append, policy=PolicyEngine("strict"))
    end = [e for e in evs if e["type"] == "task.end"][0]["payload"]
    assert end["status"] == "error:RuntimeError"
