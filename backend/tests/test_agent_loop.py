import json
import os
from types import SimpleNamespace as NS

import docker

from airlock.agent.loop import run_task

CANARY = os.path.expanduser("~/airlock_host_canary.txt")


def call(name, **args):
    return NS(id=f"c{abs(hash(json.dumps(args)))}", function=NS(name=name, arguments=json.dumps(args)))


class FakeLLM:
    def __init__(self, script):
        self.script = list(script)
        self.usage = {"prompt": 0, "completion": 0, "calls": 0}

    @property
    def total_tokens(self):
        return 0

    def chat(self, messages, tools=None):
        return NS(content=None, tool_calls=self.script.pop(0))


def leaked():
    return docker.from_env().containers.list(all=True, filters={"label": "airlock=sandbox"})


def types(events):
    return [e["type"] for e in events]


def test_normal_task(tmp_path):
    llm = FakeLLM([
        [call("write_file", path="/workspace/a.py", content="print(2+2)")],
        [call("run_shell", cmd="python3 /workspace/a.py")],
        [call("finish", summary="printed 4")],
    ])
    evs = []
    r = run_task("compute", llm, ledger_dir=str(tmp_path), on_event=evs.append)
    assert r["status"] == "finished" and r["ledger_verified"]
    results = [e["payload"]["result"] for e in evs if e["type"] == "tool.result"]
    assert "4" in results[-1]
    assert leaked() == []


def test_hostile_command_contained(tmp_path):
    open(CANARY, "w").write("host data")
    llm = FakeLLM([
        [call("run_shell", cmd="rm -rf --no-preserve-root /usr /etc /workspace/* 2>&1 | tail -2")],
        [call("finish", summary="done")],
    ])
    r = run_task("hostile", llm, ledger_dir=str(tmp_path))
    assert r["status"] == "finished" and r["ledger_verified"]
    assert open(CANARY).read() == "host data"
    assert leaked() == []


def test_deadline_resets_sandbox(tmp_path):
    llm = FakeLLM([
        [call("run_shell", cmd="while true; do :; done")],
        [call("finish", summary="gave up")],
    ])
    evs = []
    r = run_task("loop", llm, exec_timeout=2, ledger_dir=str(tmp_path), on_event=evs.append)
    assert "sandbox.recreated" in types(evs)
    assert r["status"] == "finished" and r["ledger_verified"]
    assert leaked() == []


def test_loop_detector(tmp_path):
    same = [call("run_shell", cmd="echo hi")]
    llm = FakeLLM([same, same, same, same])
    r = run_task("loop", llm, ledger_dir=str(tmp_path))
    assert r["status"] == "halted:loop_detected"
    assert leaked() == []
