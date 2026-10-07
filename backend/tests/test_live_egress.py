"""Egress events must reach the ledger while a command is still running.
Uses a fake sandbox and fake egress manager, so no Docker is needed."""
import time

from airlock.agent.loop import run_task
from airlock.sandbox.docker_provider import ExecResult
from test_agent_loop import FakeLLM, call


def test_egress_events_stream_during_exec(tmp_path, monkeypatch):
    marks = {}

    class FakeSandbox:
        name, ip = "fake-sb", "10.0.0.2"

        def __init__(self, egress=None):
            pass

        def exec(self, cmd, timeout_s=30):
            marks["start"] = time.time()
            time.sleep(1.8)                      # a slow command, like pip install
            marks["done"] = time.time()
            return ExecResult(0, "ok", "", False)

        def destroy(self):
            pass

    class FakeEgress:
        internal_network = "fake-net"

        def proxy_env(self):
            return {}

        def events_for(self, ip, since):
            # the connection "happens" 0.3s into the command
            if "start" in marks and time.time() > marks["start"] + 0.3:
                return [{"ts": marks["start"] + 0.3, "decision": "allowed", "client": ip,
                         "host": "pypi.org", "port": 443, "method": "CONNECT"}]
            return []

    monkeypatch.setattr("airlock.agent.loop.Sandbox", FakeSandbox)
    seen = []
    llm = FakeLLM([[call("run_shell", cmd="slow")], [call("finish", summary="done")]])
    r = run_task("t", llm, ledger_dir=str(tmp_path), egress=FakeEgress(),
                 on_event=lambda ev: seen.append((time.time(), ev["type"], ev)))

    eg = [(t, ev) for t, typ, ev in seen if typ == "egress.allowed"]
    assert len(eg) == 1, "exactly one event: no duplicates from polling + final flush"
    assert eg[0][0] < marks["done"] - 0.5, "event must arrive while the command is still running"
    assert eg[0][1]["payload"]["proxy_ts"] == marks["start"] + 0.3
    types = [typ for _, typ, _ in seen]
    assert types.index("egress.allowed") < types.index("tool.result")
    assert r["status"] == "finished" and r["ledger_verified"]  # chain intact despite 2 writer threads
