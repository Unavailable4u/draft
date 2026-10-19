"""Running a scenario repeatedly and reporting a pass rate. No Docker, no network, no real model."""
import io
import json
import shutil

import pytest

import minilocker.agent.loop as loop_mod
from minilocker.scenarios import FIX_REPO, RESEARCH, runner
from test_agent_loop import FakeLLM, call
from test_browse_loop import FakeBrowser, FakeEgress, FakeSandbox
from test_scenarios_repo import LocalBox, a_proper_fix
from test_scenarios_research import GOOD, PAGES, SOH, GGB, EIF, reading


@pytest.fixture(autouse=True)
def local(monkeypatch):
    LocalBox.made = []
    monkeypatch.setattr(loop_mod, "Sandbox", LocalBox)
    yield
    for b in LocalBox.made:
        shutil.rmtree(b.root, ignore_errors=True)


def factory(*scripts):
    """A make_llm that hands out a fresh scripted model per call, one script per run (the last one repeats)."""
    calls = []

    def make():
        calls.append(1)
        return FakeLLM(scripts[min(len(calls), len(scripts)) - 1]())
    make.calls = calls
    return make


NOTHING = lambda: [[call("finish", summary="looked fine")]]          # noqa: E731


# ---------------------------------------------------------------------------------- the arithmetic

def test_wilson_interval_matches_known_values():
    lo, hi = runner.wilson(9, 10)
    assert round(lo, 3) == 0.596 and round(hi, 3) == 0.982
    lo, hi = runner.wilson(10, 10)
    assert round(lo, 3) == 0.722 and hi == 1.0
    assert runner.wilson(0, 10)[0] == 0.0 and runner.wilson(0, 0) == (0.0, 0.0)


def rec(passed, status="finished", steps=5, tokens=1000, seconds=10.0, reasons=(), **kw):
    return {"passed": passed, "status": status, "steps": steps, "tokens": tokens, "seconds": seconds,
            "reasons": list(reasons), "salvaged": 0, "nudges": 0, "denials": 0, **kw}


def test_summary_counts_the_bar_and_the_reasons():
    nine = [rec(True)] * 9 + [rec(False, reasons=["claim 1: no screenshot is cited"])]
    s = runner.summarize(nine)
    assert (s["passed"], s["runs"], s["rate"], s["met"]) == (9, 10, 0.9, True)
    assert s["ci95"] == [0.596, 0.982] and s["top_failures"] == ["1x claim 1: no screenshot is cited"]
    assert not runner.summarize([rec(True)] * 8 + [rec(False)] * 2)["met"]
    assert not runner.summarize([])["met"]


def test_summary_medians_ignore_crashed_runs_and_count_help_given():
    rs = [rec(True, steps=4, tokens=1000), rec(True, steps=6, tokens=3000, salvaged=2, nudges=1, denials=1),
          rec(False, status="error:X", steps=0, tokens=0, crashed=True, reasons=["the run crashed: X"])]
    s = runner.summarize(rs)
    assert s["median_steps"] == 5 and s["median_tokens"] == 2000 and s["crashed"] == 1
    assert (s["salvaged"], s["nudges"], s["denials"]) == (2, 1, 1) and s["finished"] == 2


# ---------------------------------------------------------------------------------- running

def test_runs_are_independent_and_each_gets_a_fresh_client(tmp_path):
    make = factory(a_proper_fix, NOTHING, a_proper_fix)
    res = runner.run_many(FIX_REPO, 3, make, out_dir=tmp_path)
    assert len(make.calls) == 3 and [r["passed"] for r in res["records"]] == [True, False, True]
    s = res["summary"]
    assert (s["passed"], s["runs"]) == (2, 3) and not s["met"] and not res["aborted"]
    assert len({r["task_id"] for r in res["records"]}) == 3
    assert all(r["ledger_verified"] for r in res["records"])


def test_every_run_leaves_a_ledger_and_the_evidence_to_explain_it(tmp_path):
    runner.run_many(FIX_REPO, 2, factory(a_proper_fix, NOTHING), out_dir=tmp_path)
    assert len(list((tmp_path / "ledgers").glob("*.jsonl"))) == 2
    assert json.loads((tmp_path / "run-01" / "check.json").read_text())["passed"] is True
    bad = json.loads((tmp_path / "run-02" / "check.json").read_text())
    assert bad["passed"] is False and bad["reasons"] and (tmp_path / "run-02" / "report.txt").read_text() == "looked fine"


def test_a_failed_research_run_keeps_the_page_text_the_agent_read(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)
    monkeypatch.setattr(loop_mod, "BrowserSandbox", FakeBrowser)
    FakeBrowser.made, FakeBrowser.pages = [], dict(PAGES)
    runner.run_many(RESEARCH, 1, factory(lambda: reading(SOH, GGB, EIF, report="1. 1973")), out_dir=tmp_path)
    kept = sorted(p.name for p in (tmp_path / "run-01").glob("*.txt"))
    assert kept == ["001.txt", "002.txt", "003.txt", "report.txt"]
    assert "1973" in (tmp_path / "run-01" / "001.txt").read_text(encoding="utf-8")


def test_a_run_that_crashes_is_a_failed_run_not_a_dead_batch(tmp_path):
    def sometimes():
        sometimes.n += 1
        if sometimes.n == 2:
            raise RuntimeError("provider exploded")
        return FakeLLM(a_proper_fix())
    sometimes.n = 0
    res = runner.run_many(FIX_REPO, 3, sometimes, out_dir=tmp_path)
    assert [r["passed"] for r in res["records"]] == [True, False, True]
    assert res["records"][1]["crashed"] and "RuntimeError: provider exploded" in res["records"][1]["reasons"][0]
    assert res["summary"]["crashed"] == 1


def test_a_batch_that_only_crashes_is_abandoned_early(tmp_path):
    def broken():
        raise KeyError("LLM_API_KEY")
    res = runner.run_many(FIX_REPO, 10, broken, out_dir=tmp_path)
    assert res["aborted"] and len(res["records"]) == runner.ABORT_AFTER
    assert "stopped early" in runner.render(res) and "NOT RUN" in runner.render(res)


def test_the_policy_profile_is_the_one_asked_for(tmp_path, monkeypatch):
    # `observe` ALLOWS this command inside the sandbox, so it must not run on a stand-in that executes for real:
    # FakeSandbox records commands and runs none of them.
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)
    hostile = lambda: [[call("run_shell", cmd="rm -rf --no-preserve-root /")], [call("finish", summary="x")]]   # noqa: E731
    strict = runner.run_many(FIX_REPO, 1, factory(hostile), profile="strict", out_dir=tmp_path / "a")
    observe = runner.run_many(FIX_REPO, 1, factory(hostile), profile="observe", out_dir=tmp_path / "b")
    assert strict["records"][0]["denials"] == 1 and observe["records"][0]["denials"] == 0
    assert any("--no-preserve-root" in c for b in FakeSandbox.made for c in b.executed) is True   # it was only recorded


def test_help_the_model_needed_is_counted(tmp_path):
    from types import SimpleNamespace as NS

    class Salvaging(FakeLLM):
        def chat(self, messages, tools=None):
            m = super().chat(messages, tools)
            return NS(content=m.content, tool_calls=m.tool_calls, salvaged={"how": "hermes", "calls": 1, "source": "content"})
    res = runner.run_many(FIX_REPO, 1, lambda: Salvaging(a_proper_fix()), out_dir=tmp_path)
    assert res["records"][0]["salvaged"] == 5 and res["summary"]["salvaged"] == 5


def test_the_report_states_the_count_the_interval_and_the_verdict():
    res = {"scenario": "fix_repo", "title": "Fix a broken repo", "aborted": False,
           "summary": runner.summarize([rec(True)] * 9 + [rec(False, reasons=["8 visible test(s) still fail"])]), "records": []}
    text = runner.render(res)
    assert "passed 9/10 (90%, 95% interval 60-98%): MET (bar: 90%)" in text
    assert "1x 8 visible test(s) still fail" in text and "median per run: 5.0 steps" in text


# ---------------------------------------------------------------------------------- command line

def run_main(argv, **kw):
    out = io.StringIO()
    code = runner.main(argv, out=out, **kw)
    return code, out.getvalue()


def test_list_needs_no_credentials():
    code, text = run_main(["--list"])
    assert code == 0 and "fix_repo" in text and "(offline)" in text and "needs network: wikipedia.org" in text


@pytest.mark.parametrize("argv", [["--scenario", "nope"], ["--runs", "0"], ["--profile", "yolo"]])
def test_bad_arguments_stop_before_anything_runs(argv):
    with pytest.raises(SystemExit):
        run_main(argv, make_llm=lambda: None)


def test_main_runs_a_scenario_and_writes_a_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setenv("LLM_TOOL_MODE", "json")
    started = []
    code, text = run_main(["--scenario", "fix_repo", "--runs", "2", "--out", str(tmp_path)],
                          make_llm=factory(a_proper_fix, NOTHING), make_egress=lambda h: started.append(h))
    assert code == 0 and "passed 1/2 (50%" in text and "NOT MET" in text and not started   # offline: no proxy
    saved = json.loads(next(tmp_path.glob("summary-*.json")).read_text())
    assert saved["model"] == "test-model" and saved["tool_mode"] == "json"
    assert saved["results"][0]["summary"]["passed"] == 1 and len(saved["results"][0]["records"]) == 2


def test_main_starts_the_proxy_for_a_networked_scenario_and_always_stops_it(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)
    monkeypatch.setattr(loop_mod, "BrowserSandbox", FakeBrowser)
    monkeypatch.setenv("MINILOCKER_ALLOW", "pypi.org,files.pythonhosted.org")
    FakeBrowser.made, FakeBrowser.pages = [], dict(PAGES)
    events = []

    class Egress(FakeEgress):
        def stop(self):
            events.append("stopped")

    def make_egress(hosts):
        events.append(tuple(hosts))
        return Egress()
    code, text = run_main(["--scenario", "research", "--runs", "1", "--out", str(tmp_path)],
                          make_llm=factory(lambda: reading(SOH, GGB, EIF, report=GOOD)), make_egress=make_egress)
    assert code == 0 and "passed 1/1" in text and "MET" in text
    assert events == [("pypi.org", "files.pythonhosted.org", "wikipedia.org"), "stopped"]


def test_the_proxy_is_stopped_even_when_every_run_crashes(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "BrowserSandbox", FakeBrowser)
    stopped = []

    class Egress(FakeEgress):
        def stop(self):
            stopped.append(1)

    def boom():
        raise RuntimeError("no model")
    run_main(["--scenario", "research", "--runs", "5", "--out", str(tmp_path)], make_llm=boom,
             make_egress=lambda h: Egress())
    assert stopped == [1]


def test_main_without_model_settings_stops_before_any_run(monkeypatch, tmp_path):
    for k in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "MINILOCKER_ENV_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        run_main(["--scenario", "fix_repo"])
