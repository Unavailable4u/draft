"""The research-with-receipts scenario through the real loop, with a fake browser. No Docker, no network.

What is under test is the receipt logic: that a claim counts only when the screenshot it cites is real, of the right
article, intact according to the ledger, and shows the answer.
"""
import pytest

import minilocker.agent.loop as loop_mod
from minilocker.agent.hooks import Check, CheckContext
from minilocker.agent.loop import run_task
from minilocker.artifacts import MemoryArtifactStore
from minilocker.policy.engine import PolicyEngine
from minilocker.scenarios import RESEARCH, research
from minilocker.scenarios.runner import run_once
from test_agent_loop import FakeLLM, call
from test_browse_loop import FakeBrowser, FakeSandbox

SOH = "https://en.wikipedia.org/wiki/Sydney_Opera_House"
GGB = "https://en.wikipedia.org/wiki/Golden_Gate_Bridge"
EIF = "https://en.wikipedia.org/wiki/Eiffel_Tower"

PAGES = {
    SOH: {"url": SOH, "title": "Sydney Opera House", "text": "The building was formally opened by Queen Elizabeth II "
                                                             "on 20 October 1973, 16 years after Utzon's selection."},
    GGB: {"url": GGB, "title": "Golden Gate Bridge", "text": "The bridge opened to the public on May 27, 1937."},
    EIF: {"url": EIF, "title": "Eiffel Tower", "text": "Gustave Eiffel's company designed and built the tower "
                                                       "from 1887 to 1889."},
}
GOOD = "1. 1973 [screenshots/001.jpg]\n2. 1937 [screenshots/002.jpg]\n3. 1889 [screenshots/003.jpg]"


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    FakeSandbox.made, FakeSandbox.export = [], b""
    FakeBrowser.made, FakeBrowser.pages, FakeBrowser.fail_start, FakeBrowser.fatal_next = [], dict(PAGES), False, False
    monkeypatch.setattr(loop_mod, "Sandbox", FakeSandbox)
    monkeypatch.setattr(loop_mod, "BrowserSandbox", FakeBrowser)


def goto(url):
    return [call("browse", action="goto", url=url)]


def reading(*urls, report):
    return [goto(u) for u in urls] + [[call("finish", summary=report)]]


def play(script, tmp_path, store=True, pages=None):
    if pages is not None:
        FakeBrowser.pages = pages
    return run_once(RESEARCH, lambda: FakeLLM(script), egress=None, profile="strict", ledger_dir=tmp_path,
                    artifacts=MemoryArtifactStore() if store else None)


# ---------------------------------------------------------------------------------- passing

def test_an_honest_run_passes_with_three_receipts(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD), tmp_path)
    assert rec["passed"] and rec["reasons"] == [] and rec["status"] == "finished"
    assert rec["facts"]["claims_ok"] == 3 and rec["facts"]["pages_read"] == 3 and rec["ledger_verified"] is True


def test_the_model_really_was_told_the_screenshot_names_it_cites(tmp_path):
    seen = []
    run_task(RESEARCH.task, FakeLLM(reading(SOH, GGB, EIF, report=GOOD)), ledger_dir=str(tmp_path),
             on_event=lambda e: seen.append(e), artifacts=MemoryArtifactStore(),
             policy=PolicyEngine("strict", RESEARCH.budgets))
    told = [e["payload"]["result"] for e in seen if e["type"] == "tool.result"]
    assert [f"screenshots/00{i}.jpg" in told[i - 1] for i in (1, 2, 3)] == [True, True, True]


@pytest.mark.parametrize("report", [
    "**1.** 1973 [screenshots/001.jpg]\n**2.** 1937 [screenshots/002.jpg]\n**3.** 1889 [screenshots/003.jpg]",
    "1) 1973 (screenshots/001.jpg)\n2) 1937 (screenshots/002.jpg)\n3) 1889 (screenshots/003.jpg)",
    "Here are my answers:\n- 1. 1973 [screenshots/001.jpg]\n- 2. 1937 [screenshots/002.jpg]\n- 3. 1889 [screenshots/003.jpg]\nDone.",
    "1. It opened in 1973 [shot: screenshots/001.jpg]\n2. 1937 [screenshots/002.jpg]\n3. 1887-1889 [screenshots/003.jpg]",
    "1. 1973 [screenshots/001.jpg] [screenshots/002.jpg]\n2. 1937 [screenshots/002.jpg]\n3. 1889 [screenshots/003.jpg]",
])
def test_reasonable_report_formats_are_accepted(report, tmp_path):
    assert play(reading(SOH, GGB, EIF, report=report), tmp_path)["passed"], report


# ---------------------------------------------------------------------------------- failing, and why

def test_answering_from_memory_without_browsing_fails(tmp_path):
    rec = play([[call("finish", summary=GOOD)]], tmp_path)
    assert not rec["passed"] and rec["facts"]["pages_read"] == 0
    assert all("never taken" in r for r in rec["reasons"]) and len(rec["reasons"]) == 3


def test_a_correct_answer_with_no_citation_fails(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report="1. 1973\n2. 1937 [screenshots/002.jpg]\n3. 1889 [screenshots/003.jpg]"), tmp_path)
    assert not rec["passed"] and rec["reasons"] == ["claim 1: no screenshot is cited"]


def test_a_wrong_answer_fails_even_with_a_real_receipt(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD.replace("1937", "1936")), tmp_path)
    assert not rec["passed"] and rec["reasons"] == ["claim 2: the answer is not 1937"]


def test_citing_another_articles_screenshot_fails(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD.replace("1973 [screenshots/001.jpg]", "1973 [screenshots/002.jpg]")), tmp_path)
    assert not rec["passed"] and "not the right article" in rec["reasons"][0] and rec["facts"]["claims_ok"] == 2


def test_citing_a_screenshot_that_was_never_taken_fails(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD.replace("003.jpg", "009.jpg")), tmp_path)
    assert not rec["passed"] and "never taken (screenshots/009.jpg)" in rec["reasons"][0]


def test_one_made_up_citation_poisons_a_line_even_beside_a_real_one(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD.replace("001.jpg]", "001.jpg] [screenshots/077.jpg]")), tmp_path)
    assert not rec["passed"] and "never taken" in rec["reasons"][0]
    assert rec["facts"]["claims_ok"] == 2 and rec["facts"]["claims"][0]["ok"] is False   # the count agrees with the verdict


def test_the_right_article_with_a_page_that_does_not_say_it_fails(tmp_path):
    # the model knew the year from memory and cited the right page, but the page it read does not contain it
    pages = {**PAGES, SOH: {**PAGES[SOH], "text": "The Sydney Opera House is a performing arts centre in Sydney."}}
    rec = play(reading(SOH, GGB, EIF, report=GOOD), tmp_path, pages=pages)
    assert not rec["passed"] and "the page text does not contain 1973" in rec["reasons"][0]


def test_citing_one_screenshot_for_every_claim_fails(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD.replace("002.jpg", "001.jpg").replace("003.jpg", "001.jpg")), tmp_path)
    assert not rec["passed"] and rec["facts"]["claims_ok"] == 1


def test_a_missing_line_fails(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report="1. 1973 [screenshots/001.jpg]\n2. 1937 [screenshots/002.jpg]"), tmp_path)
    assert rec["reasons"] == ["claim 3: the report has no line 3"]


def test_no_report_at_all_fails_all_three(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report="I found the answers."), tmp_path)
    assert not rec["passed"] and len(rec["reasons"]) == 3


def test_without_an_artifact_store_receipts_cannot_be_checked(tmp_path):
    rec = play(reading(SOH, GGB, EIF, report=GOOD), tmp_path, store=False)
    assert not rec["passed"] and "no artifact store" in rec["reasons"][0]


# ---------------------------------------------------------------------------------- tampering after the fact

def _ctx_after_an_honest_run(tmp_path):
    got = {}
    store = MemoryArtifactStore()

    def keep(ctx):
        got["ctx"] = ctx
        return Check(True)
    run_task(RESEARCH.task, FakeLLM(reading(SOH, GGB, EIF, report=GOOD)), ledger_dir=str(tmp_path), artifacts=store,
             task_id="0123abcd", verify=keep)
    return got["ctx"], store


def test_the_honest_context_verifies_on_its_own(tmp_path):
    ctx, _ = _ctx_after_an_honest_run(tmp_path)
    assert research.verify(ctx).passed


def test_a_swapped_screenshot_no_longer_matches_the_ledger(tmp_path):
    ctx, store = _ctx_after_an_honest_run(tmp_path)
    store.objects["tasks/0123abcd/screenshots/001.jpg"] = b"\xff\xd8\xff\xe0someone elses picture"
    got = research.verify(ctx)
    assert not got.passed and "screenshot missing or altered" in got.reasons[0]


def test_edited_page_text_no_longer_matches_the_ledger(tmp_path):
    ctx, store = _ctx_after_an_honest_run(tmp_path)
    store.objects["tasks/0123abcd/pages/002.txt"] = b"The bridge opened in 1937 (added afterwards)."
    got = research.verify(ctx)
    assert not got.passed and "page text missing or altered" in got.reasons[0]


def test_a_missing_page_text_fails_the_claim(tmp_path):
    ctx, store = _ctx_after_an_honest_run(tmp_path)
    del store.objects["tasks/0123abcd/pages/003.txt"]
    assert not research.verify(ctx).passed


def test_a_store_that_errors_fails_the_claim_instead_of_crashing_the_check(tmp_path):
    ctx, store = _ctx_after_an_honest_run(tmp_path)

    class Down:
        def get(self, *a):
            raise OSError("connection refused")
    ctx.artifacts = Down()
    assert not research.verify(ctx).passed


def test_a_fabricated_browser_event_in_the_context_is_not_enough_without_stored_bytes():
    # even a claim the events appear to support fails when nothing committed backs it
    events = [{"type": "browser.page", "payload": {"seq": 1, "url": SOH, "shot": "screenshots/001.jpg"}}]
    ctx = CheckContext(None, events, MemoryArtifactStore(), "0123abcd", "finished",
                       "1. 1973 [screenshots/001.jpg]\n2. 1937\n3. 1889", "/workspace")
    assert not research.verify(ctx).passed


# ---------------------------------------------------------------------------------- parsing

@pytest.mark.parametrize("text, want", [
    ("1. a\n2. b", {1: "a", 2: "b"}),
    ("**1.** a", {1: "a"}),
    ("1) a\n  2: b", {1: "a", 2: "b"}),
    ("- 3. c", {3: "c"}),
    ("1973 [screenshots/001.jpg]", {}),                  # a year is not a line number
    ("1. first\n1. second", {1: "first"}),               # the first line for a number wins
    ("", {}), (None, {}),
])
def test_numbered_lines(text, want):
    assert research.numbered_lines(text) == want


def test_years_are_matched_as_whole_numbers():
    assert research._has_year("opened 1973.", "1973") and research._has_year("1973s", "1973")
    assert not research._has_year("11973", "1973") and not research._has_year("19731", "1973")


def test_the_task_text_names_every_question_and_the_citation_format():
    for t in research.TOPICS:
        assert t.question in RESEARCH.task
    assert "screenshots/NNN.jpg" in RESEARCH.task and "wikipedia" in RESEARCH.task.lower()
    assert RESEARCH.allow == ("wikipedia.org",) and RESEARCH.needs_network
