"""A recovered tool call is visible in the ledger, and still goes through policy. No Docker, no network."""
from types import SimpleNamespace as NS

import minilocker.agent.loop as loop_mod
from minilocker.agent.loop import run_task
from minilocker.policy.engine import PolicyEngine
from test_agent_loop import FakeLLM, call
from test_llm_client import reply, scripted


class Box:
    """Stands in for the sandbox and records what it was asked to run."""
    name, ip = "stub", "0.0.0.0"
    ran = []

    def __init__(self, egress=None):
        pass

    def exec(self, cmd, timeout_s=30):
        Box.ran.append(cmd)
        return NS(exit_code=0, stdout="ok", stderr="", timed_out=False)

    def destroy(self):
        pass


def go(llm, tmp_path, monkeypatch, profile="observe"):
    Box.ran = []
    monkeypatch.setattr(loop_mod, "Sandbox", Box)
    evs = []
    res = run_task("t", llm, ledger_dir=str(tmp_path), on_event=evs.append, policy=PolicyEngine(profile))
    return res, evs


def test_a_native_call_writes_no_salvage_event(tmp_path, monkeypatch):
    res, evs = go(FakeLLM([[call("run_shell", cmd="echo hi")], [call("finish", summary="done")]]), tmp_path, monkeypatch)
    assert res["status"] == "finished" and not [e for e in evs if e["type"] == "llm.salvaged"]


def test_a_recovered_call_is_recorded_before_it_runs(tmp_path, monkeypatch):
    class Salvaging(FakeLLM):
        def chat(self, messages, tools=None):
            m = super().chat(messages, tools)
            m.salvaged = {"how": "hermes", "calls": 1, "source": "content"}
            return m

    res, evs = go(Salvaging([[call("run_shell", cmd="echo hi")], [call("finish", summary="done")]]), tmp_path, monkeypatch)
    types = [e["type"] for e in evs]
    assert res["status"] == "finished" and res["ledger_verified"]
    assert types.index("llm.salvaged") < types.index("tool.call")
    ev = next(e for e in evs if e["type"] == "llm.salvaged")
    assert ev["actor"] == "llm" and ev["payload"] == {"how": "hermes", "calls": 1, "source": "content"}


def test_end_to_end_a_call_written_as_text_runs_and_is_flagged(tmp_path, monkeypatch):
    llm, _ = scripted([
        reply(content='<tool_call>{"name": "run_shell", "arguments": {"cmd": "echo hi"}}</tool_call>'),
        reply(content='<tool_call>{"name": "finish", "arguments": {"summary": "done"}}</tool_call>'),
    ])
    res, evs = go(llm, tmp_path, monkeypatch)
    assert res["status"] == "finished" and res["summary"] == "done" and res["ledger_verified"]
    assert Box.ran == ["echo hi"]
    assert [e["payload"]["how"] for e in evs if e["type"] == "llm.salvaged"] == ["hermes", "hermes"]


def test_a_salvaged_call_still_meets_the_policy(tmp_path, monkeypatch):
    # recovered from a *rejected* generation, so strict rule 1 is waived: policy is what stands in the way
    from test_llm_client import rejected
    llm, _ = scripted([rejected('<function=run_shell>{"cmd": "rm -rf / --no-preserve-root"}</function>'),
                       reply(calls=[("finish", '{"summary": "gave up"}')])])
    res, evs = go(llm, tmp_path, monkeypatch, profile="strict")
    assert Box.ran == []                                                    # never reached the sandbox
    decision = next(e for e in evs if e["type"] == "policy.decision")
    assert decision["payload"]["action"] == "deny"
    assert any(e["type"] == "llm.salvaged" and e["payload"]["source"] == "failed_generation" for e in evs)
