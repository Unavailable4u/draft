"""A scenario that needs the browser must say so when the browser image is missing, not blame the model.

Seen in a real run: `minilocker-browser:latest` had not been built, the agent honestly said it could not browse,
and the runner reported "claim 1: the report has no line 1". No Docker, no network.
"""
import io

import pytest

import minilocker.agent.loop as loop_mod
from minilocker.artifacts import MemoryArtifactStore
from minilocker.scenarios import RESEARCH, SCENARIOS, runner
from test_agent_loop import FakeLLM, call
from test_browse_loop import FakeBrowser, FakeEgress, FakeSandbox
from test_scenarios_repo import LocalBox, a_proper_fix
from test_scenarios_research import GOOD, PAGES, SOH, GGB, EIF, reading

GIVE_UP = [[call("browse", action="goto", url=SOH)], [call("finish", summary="I cannot browse, so I cannot answer.")]]


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    FakeSandbox.made, FakeSandbox.export = [], b""
    FakeBrowser.made, FakeBrowser.pages, FakeBrowser.fail_start, FakeBrowser.fatal_next = [], dict(PAGES), False, False
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)
    monkeypatch.setattr(loop_mod, "BrowserSandbox", FakeBrowser)


def run(tmp_path, script):
    return runner.run_once(RESEARCH, lambda: FakeLLM(script), egress=None, profile="strict", ledger_dir=tmp_path,
                           artifacts=MemoryArtifactStore())


def main(argv, **kw):
    out = io.StringIO()
    code = runner.main(argv, out=out, **kw)
    return code, out.getvalue()


def test_only_the_scenario_that_browses_asks_for_the_browser():
    assert [s.id for s in SCENARIOS.values() if s.needs_browser] == ["research"]


# ---------------------------------------------------------------------------------- a run that could not start it

def test_a_browser_that_never_started_is_reported_as_the_environment_not_the_model(tmp_path):
    FakeBrowser.fail_start = True
    rec = run(tmp_path, GIVE_UP)
    assert rec["status"] == "error:BrowserUnavailable" and rec["crashed"] and not rec["passed"]
    assert rec["reasons"][0].startswith("the browser sandbox could not start: image 'minilocker-browser:latest' not found")
    assert "docker build" in rec["reasons"][0]
    assert not any("no line" in r for r in rec["reasons"])         # the misleading symptom is gone


def test_such_a_run_is_counted_as_crashed_so_the_rate_excludes_it():
    rec = {"passed": False, "status": "error:BrowserUnavailable", "crashed": True, "steps": 2, "tokens": 1, "seconds": 1.0,
           "reasons": ["the browser sandbox could not start: x"], "salvaged": 0, "nudges": 0, "denials": 0}
    assert runner.summarize([rec])["crashed"] == 1


def test_a_browser_that_failed_once_but_worked_later_does_not_spoil_a_good_run(tmp_path):
    class Heals(FakeLLM):
        n = 0

        def chat(self, messages, tools=None):
            Heals.n += 1
            if Heals.n == 2:                                        # the first browse call has run (and failed) by now
                FakeBrowser.fail_start = False
            return super().chat(messages, tools)
    Heals.n = 0
    FakeBrowser.fail_start = True
    script = [[call("browse", action="goto", url=SOH)]] + reading(SOH, GGB, EIF, report=GOOD)
    rec = runner.run_once(RESEARCH, lambda: Heals(script), egress=None, profile="strict", ledger_dir=tmp_path,
                          artifacts=MemoryArtifactStore())
    assert rec["passed"] and not rec.get("crashed") and rec["status"] == "finished"


def test_a_run_that_fails_for_another_reason_keeps_its_own_reasons(tmp_path):
    rec = run(tmp_path, [[call("finish", summary="1. 1973")]])      # the browser is fine; the answer is just incomplete
    assert not rec.get("crashed") and any("no line" in r or "no screenshot" in r or "never taken" in r for r in rec["reasons"])


def test_a_batch_with_no_browser_stops_after_three_runs_not_ten(tmp_path):
    FakeBrowser.fail_start = True
    res = runner.run_many(RESEARCH, 10, lambda: FakeLLM(GIVE_UP), out_dir=tmp_path)
    assert res["aborted"] and len(res["records"]) == runner.ABORT_AFTER and res["summary"]["crashed"] == 3
    assert "browser sandbox could not start" in runner.render(res)


# ---------------------------------------------------------------------------------- checked before any run

def never_called():
    raise AssertionError("no model client must be built when the scenario cannot run")


def test_asking_for_research_without_the_image_stops_before_any_run_with_the_exact_command():
    with pytest.raises(SystemExit):
        main(["--scenario", "research"], make_llm=never_called, browser_ready=lambda: False)


def test_the_message_names_the_image_and_the_build_command(capsys):
    with pytest.raises(SystemExit):
        main(["--scenario", "research"], make_llm=never_called, browser_ready=lambda: False)
    err = capsys.readouterr().err
    assert "minilocker-browser:latest" in err and "docker build -f images/browser/Dockerfile" in err
    assert "repository root" in err and "Docker is not reachable" in err


def test_all_skips_the_browser_scenario_and_still_runs_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "Sandbox", LocalBox)
    # LocalBox runs commands on this machine, so only scenarios that are safe there may be swept in by "all"
    # (fix_repo_v2 carries a hostile fixture that must only ever run inside a Docker sandbox).
    monkeypatch.setattr(runner, "SCENARIOS", {k: v for k, v in SCENARIOS.items() if k in ("fix_repo", "research")})
    started = []
    code, text = main(["--scenario", "all", "--runs", "1", "--out", str(tmp_path)],
                      make_llm=lambda: FakeLLM(a_proper_fix()), make_egress=lambda h: started.append(h),
                      browser_ready=lambda: False)
    assert code == 0 and "Fix a broken repo" in text and "passed 1/1" in text
    assert "SKIPPED research: research needs the browser image" in text and "docker build" in text
    assert started == []                                           # no egress proxy was started for the skipped one


def test_the_check_is_not_made_when_no_scenario_needs_the_browser(tmp_path, monkeypatch):
    monkeypatch.setattr(loop_mod, "Sandbox", LocalBox)

    def must_not_ask():
        raise AssertionError("the image was checked although fix_repo does not use the browser")
    code, text = main(["--scenario", "fix_repo", "--runs", "1", "--out", str(tmp_path)],
                      make_llm=lambda: FakeLLM(a_proper_fix()), browser_ready=must_not_ask)
    assert code == 0 and "passed 1/1" in text


def test_with_the_image_present_research_runs_as_before(tmp_path):
    class Egress(FakeEgress):
        def stop(self):
            pass
    code, text = main(["--scenario", "research", "--runs", "1", "--out", str(tmp_path)],
                      make_llm=lambda: FakeLLM(reading(SOH, GGB, EIF, report=GOOD)), make_egress=lambda h: Egress(),
                      browser_ready=lambda: True)
    assert code == 0 and "passed 1/1" in text and "SKIPPED" not in text
