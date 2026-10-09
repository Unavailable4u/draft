"""An empty model reply after a tool result must not turn a finished job into 'halted'. No Docker."""
from types import SimpleNamespace as NS

import pytest

import minilocker.agent.loop as loop_mod
from minilocker.agent.loop import EMPTY_REPLY_NUDGE, MAX_EMPTY_NUDGES, run_task
from minilocker.policy.engine import PolicyEngine
from test_agent_loop import FakeLLM, call


class Box:
    name, ip = "stub", "0.0.0.0"

    def __init__(self, egress=None):
        pass

    def exec(self, cmd, timeout_s=30):
        return NS(exit_code=0, stdout="hi", stderr="", timed_out=False)

    def destroy(self):
        pass


class Recording(FakeLLM):
    def __init__(self, script):
        super().__init__(script)
        self.seen = []

    def chat(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        return super().chat(messages, tools)


def go(llm, tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "Sandbox", Box)
    evs = []
    res = run_task("t", llm, ledger_dir=str(tmp_path), on_event=evs.append, policy=PolicyEngine("observe"))
    return res, evs


def test_an_empty_reply_is_nudged_and_the_task_finishes(tmp_path, monkeypatch):
    llm = Recording([[call("run_shell", cmd="echo hi")], [], [call("finish", summary="done")]])
    res, evs = go(llm, tmp_path, monkeypatch)
    assert res["status"] == "finished"
    assert [e["payload"]["n"] for e in evs if e["type"] == "agent.nudge"] == [1]
    third = llm.seen[2]
    assert third[-1] == {"role": "user", "content": EMPTY_REPLY_NUDGE}
    assert not any(m["role"] == "assistant" and not m.get("content") and not m.get("tool_calls") for m in third)


def test_a_model_that_stays_silent_is_still_halted_after_the_limit(tmp_path, monkeypatch):
    llm = Recording([[] for _ in range(MAX_EMPTY_NUDGES + 1)])
    res, evs = go(llm, tmp_path, monkeypatch)
    assert res["status"] == "halted:no_tool_call"
    assert len([e for e in evs if e["type"] == "agent.nudge"]) == MAX_EMPTY_NUDGES
    assert len(llm.seen) == MAX_EMPTY_NUDGES + 1


def test_a_plain_text_answer_is_final_and_is_not_nudged(tmp_path, monkeypatch):
    class Talker(FakeLLM):
        def chat(self, messages, tools=None):
            return NS(content="all done", tool_calls=[])

    res, evs = go(Talker([]), tmp_path, monkeypatch)
    assert res["status"] == "finished" and not [e for e in evs if e["type"] == "agent.nudge"]
