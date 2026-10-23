"""Tool arguments written by the model are untrusted input: a wrong type must never crash a task.

Seen in a real run: gpt-oss wrote `cmd` as a list, the provider rejected the call, the rejected text was salvaged,
and the policy engine's regex raised `TypeError: expected string or bytes-like object, got 'list'`, so 3 of 13
scenario runs died before taking a step. Two things were wrong, and each is covered here: salvage accepted a call
that broke its tool's schema, and the loop never checked argument types at all. No Docker, no network.
"""
import json
from types import SimpleNamespace as NS

import pytest

import minilocker.agent.loop as loop_mod
from minilocker.agent.loop import TOOLS, run_task
from minilocker.artifacts import MemoryArtifactStore
from minilocker.llm import toolcalls as tc
from minilocker.policy.engine import PolicyEngine
from minilocker.scenarios import FIX_REPO, runner
from test_agent_loop import FakeLLM, call
from test_browse_loop import FakeSandbox
from test_llm_client import reply, rejected, scripted

SC = tc.schema_of(TOOLS)


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch):
    FakeSandbox.made = []
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)


def go(script, tmp_path, llm=None):
    evs = []
    res = run_task("t", llm or FakeLLM(script), ledger_dir=str(tmp_path), on_event=evs.append,
                   policy=PolicyEngine("strict"))
    results = [e["payload"]["result"] for e in evs if e["type"] == "tool.result"]
    return res, evs, results


def ran():
    return [c for b in FakeSandbox.made for c in b.executed]


# ---------------------------------------------------------------------------------- validate_args

@pytest.mark.parametrize("name, args", [
    ("run_shell", {"cmd": "ls"}),
    ("run_shell", {"cmd": "ls", "extra": [1, 2]}),                      # unknown arguments are ignored, as the tools do
    ("browse", {"action": "goto", "url": "https://a.example", "ref": 0, "submit": False, "wait_ms": 2000}),
    ("browse", {"action": "goto", "ref": None, "selector": None}),      # null means "not given"
    ("browse", {"action": "goto", "wait_ms": 2000.0}),                  # a whole float is a fine integer
    ("teleport", {"x": []}),                                            # an unknown tool is the caller's business
])
def test_arguments_that_fit_the_schema_are_accepted(name, args):
    assert tc.validate_args(name, args, SC) is None


@pytest.mark.parametrize("name, args, why", [
    ("run_shell", {"cmd": ["python3", "-m", "unittest"]}, "argument `cmd` must be of type string, not array"),
    ("run_shell", {"cmd": 42}, "argument `cmd` must be of type string, not integer"),
    ("run_shell", {"cmd": {"a": 1}}, "not object"),
    ("run_shell", {"cmd": True}, "not boolean"),
    ("write_file", {"path": "/workspace/a", "content": ["x"]}, "argument `content` must be of type string"),
    ("finish", {"summary": ["a", "b"]}, "argument `summary` must be of type string"),
    ("browse", {"action": "fly"}, "argument `action` must be one of: goto"),
    ("browse", {"action": "goto", "ref": True}, "argument `ref` must be of type integer, not boolean"),
    ("browse", {"action": "goto", "ref": 1.5}, "must be of type integer, not number"),
    ("browse", {"action": "goto", "submit": "yes"}, "argument `submit` must be of type boolean, not string"),
    ("run_shell", [1, 2], "the arguments must be a JSON object"),
    ("run_shell", "ls", "the arguments must be a JSON object"),
    ("run_shell", None, "the arguments must be a JSON object"),
    ("run_shell", {}, "missing required argument(s): cmd"),
    ("write_file", {"path": "/workspace/a"}, "missing required argument(s): content"),
    ("run_shell", {"cmd": None}, "missing required argument(s): cmd"),
])
def test_arguments_that_break_the_schema_are_refused_with_a_reason(name, args, why):
    assert why in (tc.validate_args(name, args, SC) or "")


def test_a_missing_argument_can_be_left_to_the_caller():
    assert tc.validate_args("run_shell", {}, SC, check_required=False) is None
    assert tc.validate_args("run_shell", {"cmd": []}, SC, check_required=False)       # a wrong type still counts


def test_a_union_type_accepts_any_of_its_members():
    sc = tc.schema_of([{"type": "function", "function": {"name": "t", "parameters": {
        "type": "object", "properties": {"x": {"type": ["string", "null"]}, "y": {"type": ["integer", "string"]}}}}}])
    assert tc.validate_args("t", {"x": "a", "y": 3}, sc) is None and tc.validate_args("t", {"y": "s"}, sc) is None
    assert "must be of type integer or string, not array" in tc.validate_args("t", {"y": []}, sc)


# ---------------------------------------------------------------------------------- salvage refuses them

BAD = '{"cmd": ["python3", "-m", "unittest"]}'


@pytest.mark.parametrize("text", [
    f"<function=run_shell>{BAD}</function>",
    f'<tool_call>{{"name": "run_shell", "arguments": {BAD}}}</tool_call>',
    f'{{"name": "run_shell", "arguments": {BAD}}}',
    f'{{"run_shell": {BAD}}}',
    f'<|tool_call_begin|>functions.run_shell:0<|tool_call_argument_begin|>{BAD}<|tool_call_end|>',
])
@pytest.mark.parametrize("strict", [True, False])
def test_a_call_with_the_wrong_argument_type_is_not_salvaged(text, strict):
    assert tc.extract_tool_calls(text, TOOLS, strict=strict) == []


def test_the_same_call_with_the_right_type_is_still_salvaged():
    assert [c.name for c in tc.extract_tool_calls('<function=run_shell>{"cmd": "ls"}</function>', TOOLS)] == ["run_shell"]


def test_one_bad_call_discards_the_whole_reply():
    good = '<|tool_call_begin|>functions.run_shell:0<|tool_call_argument_begin|>{"cmd": "ls"}<|tool_call_end|>'
    bad = '<|tool_call_begin|>functions.run_shell:1<|tool_call_argument_begin|>{"cmd": [1]}<|tool_call_end|>'
    assert tc.extract_tool_calls(good + bad, TOOLS) == []


@pytest.mark.parametrize("text", ['{"name": "finish", "arguments": {}}', '{"name": "browse", "arguments": {"action": "fly"}}'])
def test_a_missing_required_argument_or_a_value_outside_the_enum_is_not_salvaged(text):
    assert tc.extract_tool_calls(text, TOOLS) == []


# ---------------------------------------------------------------------------------- the client

def test_a_rejected_call_with_the_wrong_type_is_retried_not_salvaged():
    c, seen = scripted([rejected(f"<function=run_shell>{BAD}</function>"), reply(calls=[("run_shell", '{"cmd": "ls"}')])])
    m = c.chat([{"role": "user", "content": "x"}], TOOLS)
    assert json.loads(m.tool_calls[0].function.arguments) == {"cmd": "ls"}
    assert c.stats["salvaged"] == 0 and c.stats["retries"] == 1 and len(seen) == 2
    assert c.last_raw["failed_generation"].startswith("<function=run_shell>")      # kept for diagnosis


def test_the_exact_crash_from_the_scenario_runs_now_finishes(tmp_path):
    llm, _ = scripted([rejected(f"<function=run_shell>{BAD}</function>"),
                       reply(calls=[("finish", '{"summary": "done"}')])])
    res, evs, _ = go(None, tmp_path, llm=llm)
    assert res["status"] == "finished" and res["summary"] == "done" and res["ledger_verified"] is True
    assert ran() == []                                    # the list was never run as a command


# ---------------------------------------------------------------------------------- the loop itself

@pytest.mark.parametrize("bad_call, expect", [
    (call("run_shell", cmd=["ls", "-la"]), "argument `cmd` must be of type string, not array"),
    (call("run_shell", cmd=7), "not integer"),
    (call("write_file", path="/workspace/a", content=["x"]), "argument `content`"),
    (call("write_file", path=["/workspace/a"], content="x"), "argument `path`"),
    (call("read_file", path={"a": 1}), "argument `path`"),
])
def test_a_native_call_with_the_wrong_type_gets_an_error_and_the_task_goes_on(bad_call, expect, tmp_path):
    res, evs, results = go([[bad_call], [call("finish", summary="recovered")]], tmp_path)
    assert res["status"] == "finished" and res["summary"] == "recovered" and res["denials"] == 0
    assert results[0].startswith("error: invalid arguments for ") and expect in results[0]
    assert ran() == []                                    # nothing reached the sandbox


def test_finish_with_a_list_summary_does_not_finish_the_task(tmp_path):
    res, _, results = go([[call("finish", summary=["a", "b"])], [call("finish", summary="the real one")]], tmp_path)
    assert results[0].startswith("error: invalid arguments for finish") and res["summary"] == "the real one"
    assert isinstance(res["summary"], str)


@pytest.mark.parametrize("name", ["run_shell", "finish", "browse", "write_file"])
def test_arguments_that_are_not_an_object_do_not_crash(name, tmp_path):
    arrays = NS(id="c1", type="function", function=NS(name=name, arguments="[1, 2]"))
    res, _, results = go([[arrays], [call("finish", summary="ok")]], tmp_path)
    assert res["status"] == "finished" and "the arguments must be a JSON object" in results[0]


def test_a_missing_command_keeps_its_old_meaning(tmp_path):
    _, _, results = go([[call("run_shell")], [call("finish", summary="x")]], tmp_path)
    assert not results[0].startswith("error: invalid")


def test_a_model_that_keeps_sending_bad_arguments_is_still_stopped_by_the_loop_detector(tmp_path):
    bad = [call("run_shell", cmd=["ls"])]
    res, _, _ = go([bad, bad, bad, bad], tmp_path)
    assert res["status"] == "halted:loop_detected"


def test_well_formed_calls_are_untouched(tmp_path):
    res, _, results = go([[call("run_shell", cmd="echo hi")], [call("finish", summary="ok")]], tmp_path)
    assert res["status"] == "finished" and not results[0].startswith("error: invalid") and ran() == ["echo hi"]


# ---------------------------------------------------------------------------------- what the runner keeps

def boom_after_start():
    class Boom(FakeLLM):
        def chat(self, messages, tools=None):
            raise RuntimeError("provider exploded mid-task")
    return Boom([])


def test_a_crashed_run_still_names_its_ledger_and_keeps_the_traceback(tmp_path):
    rec = runner.run_once(FIX_REPO, boom_after_start, egress=None, profile="strict", ledger_dir=tmp_path)
    assert rec["crashed"] and len(rec["task_id"]) == 8 and (tmp_path / f"{rec['task_id']}.jsonl").exists()
    assert "RuntimeError: provider exploded mid-task" in rec["traceback"] and "loop.py" in rec["traceback"]


def test_a_crash_before_the_task_starts_has_an_id_too(tmp_path):
    def no_client():
        raise KeyError("LLM_API_KEY")
    rec = runner.run_once(FIX_REPO, no_client, egress=None, profile="strict", ledger_dir=tmp_path)
    assert rec["crashed"] and rec["task_id"] and "KeyError" in rec["traceback"]


def test_the_traceback_is_written_next_to_the_other_evidence(tmp_path):
    res = runner.run_many(FIX_REPO, 1, boom_after_start, out_dir=tmp_path)
    assert "provider exploded" in (tmp_path / "run-01" / "error.txt").read_text(encoding="utf-8")
    assert res["records"][0]["task_id"]


def test_a_run_that_did_not_crash_has_no_error_file(tmp_path):
    runner._save_evidence(tmp_path / "run-01", {"task_id": "abc", "summary": "ok"}, MemoryArtifactStore())
    assert not (tmp_path / "run-01" / "error.txt").exists()


def test_the_agents_final_files_are_saved_for_inspection(tmp_path):
    store = MemoryArtifactStore()
    store.put("0123abcd", "workspace/shop/pricing.py", b"def apply_discount(): ...\n")
    store.put("0123abcd", "workspace/notes.txt", b"hello")
    store.put("0123abce", "workspace/not_mine.txt", b"another task")
    runner._save_evidence(tmp_path / "run-01", {"task_id": "0123abcd", "summary": "ok"}, store)
    assert (tmp_path / "run-01" / "workspace" / "shop" / "pricing.py").read_bytes() == b"def apply_discount(): ...\n"
    assert (tmp_path / "run-01" / "workspace" / "notes.txt").read_text() == "hello"
    assert not list(tmp_path.rglob("not_mine.txt"))


def test_a_hostile_file_name_cannot_write_outside_the_run_folder(tmp_path):
    store = MemoryArtifactStore()
    store.objects["tasks/0123abcd/workspace/../../escape.txt"] = b"x"
    store.objects["tasks/0123abcd/workspace/../../../escape2.txt"] = b"x"
    runner._save_evidence(tmp_path / "a" / "b" / "run-01", {"task_id": "0123abcd", "summary": ""}, store)
    assert not list(tmp_path.rglob("escape*.txt"))


def test_the_report_shows_the_rate_without_crashed_runs_only_when_there_were_some():
    def rec(passed, crashed=False):
        return {"passed": passed, "status": "error:X" if crashed else "finished", "steps": 5, "tokens": 1, "seconds": 1.0,
                "reasons": [], "salvaged": 0, "nudges": 0, "denials": 0, **({"crashed": True} if crashed else {})}
    some = runner.render({"scenario": "s", "title": "T", "aborted": False, "records": [],
                          "summary": runner.summarize([rec(True)] * 5 + [rec(False)] * 3 + [rec(False, True)] * 2)})
    assert "without the 2 crashed run(s): 5/8 (62%)" in some
    none = runner.render({"scenario": "s", "title": "T", "aborted": False, "records": [],
                          "summary": runner.summarize([rec(True)] * 3)})
    assert "without the" not in none
