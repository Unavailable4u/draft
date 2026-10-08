"""A stand-in for the LLM: replays a fixed script, no model involved.

run_task() only needs `.chat(messages, tools)` and `.total_tokens`, so the attacker
drives the real agent loop, the real policy engine and the real Docker sandbox.
Nothing is mocked on the defender's side."""
import json
from types import SimpleNamespace as NS


class ScriptedAttacker:
    def __init__(self, steps):
        self._queue = list(steps)
        self.usage = {"prompt": 0, "completion": 0, "calls": 0}

    @property
    def total_tokens(self):
        return 0

    def chat(self, messages, tools=None):
        n = self.usage["calls"]
        self.usage["calls"] += 1
        if self._queue:
            s = self._queue.pop(0)
            name, args = s.tool, s.args
        else:   # script exhausted: end the task rather than crash the loop
            name, args = "finish", {"summary": "scripted attack complete"}
        call = NS(id=f"atk{n}", function=NS(name=name, arguments=json.dumps(args)))
        return NS(content=None, tool_calls=[call])
