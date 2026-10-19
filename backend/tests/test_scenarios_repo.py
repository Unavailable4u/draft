"""The fix-the-repo scenario, end to end, with real Python but no Docker.

`LocalBox` stands in for the sandbox: it runs each command for real in a temp directory that plays /workspace, so the
seeding, the agent's edits and the success check all execute genuine code. What is not exercised is Docker itself.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile

import pytest

import minilocker.agent.loop as loop_mod
from minilocker.agent.hooks import CheckContext, WorkspaceError, check_relative, write_files
from minilocker.sandbox.docker_provider import ExecResult
from minilocker.scenarios import FIX_REPO, repo_fix
from minilocker.scenarios.runner import run_once
from test_agent_loop import FakeLLM, call


_ABSOLUTE = re.compile(r"(?<![\w.\-])/[^\s'\";|&<>()]*")


def confine(cmd):
    """LocalBox runs commands FOR REAL on this machine, as whoever runs the tests (possibly root). So it refuses
    any command that names an absolute path outside the directory that plays /workspace, instead of trusting the
    test that sent it. A destructive command must never reach `sh` here; tests that need one use FakeSandbox, which
    records commands and runs nothing."""
    for path in _ABSOLUTE.findall(cmd):
        if not (path == "/workspace" or path.startswith("/workspace/") or path == "/dev/null"):
            raise AssertionError(f"LocalBox refuses to run a command that touches {path!r}: {cmd[:120]!r}")


class LocalBox:
    name, ip, dead = "local", "0.0.0.0", False
    made = []

    def __init__(self, egress=None):
        self.root = tempfile.mkdtemp(prefix="mlbox-")
        LocalBox.made.append(self)

    def exec(self, cmd, timeout_s=30):
        confine(cmd)
        p = subprocess.Popen(["sh", "-c", cmd.replace("/workspace", self.root)], cwd=self.root, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            return ExecResult(137, "", "", True)
        return ExecResult(p.returncode, out, err, False)

    def exec_capped(self, *a, **kw):
        raise NotImplementedError          # the artifact export is best effort and not under test here

    def destroy(self):
        shutil.rmtree(self.root, ignore_errors=True)


@pytest.fixture(autouse=True)
def box(monkeypatch):
    LocalBox.made = []
    monkeypatch.setattr(loop_mod, "Sandbox", LocalBox)
    yield
    for b in LocalBox.made:
        shutil.rmtree(b.root, ignore_errors=True)


REFERENCE = repo_fix.PRICING.replace(
    "from decimal import Decimal\n", "from decimal import Decimal, InvalidOperation, ROUND_HALF_UP\n").replace(
    '    return Decimal(text.replace("$", "").strip())',
    '    try:\n        return Decimal(text.replace("$", "").replace(",", "").strip())\n'
    '    except InvalidOperation:\n        raise ValueError(f"not a price: {text!r}") from None').replace(
    "    return price - percent",
    "    return (price * (100 - Decimal(str(percent))) / 100).quantize(TWO_PLACES, rounding=ROUND_HALF_UP)").replace(
    ".quantize(TWO_PLACES)\n", ".quantize(TWO_PLACES, rounding=ROUND_HALF_UP)\n")

UNITTEST = "cd /workspace && python3 -m unittest discover -s tests -t . -v"


def play(script, **kw):
    """Run the scenario once with a scripted model. -> the run record"""
    return run_once(FIX_REPO, lambda: FakeLLM(script), egress=None, profile="strict", ledger_dir=kw.pop("ledger"),
                    **kw)


def a_proper_fix():
    return [[call("run_shell", cmd=UNITTEST)], [call("read_file", path="/workspace/shop/pricing.py")],
            [call("write_file", path="/workspace/shop/pricing.py", content=REFERENCE)],
            [call("run_shell", cmd=UNITTEST)],
            [call("finish", summary="parse_price ignored thousands separators, the discount subtracted instead of "
                                    "scaling, and the tax rounded half-even")]]


# ---------------------------------------------------------------------------------- the fixture itself

def _ids_found(files):
    """Test ids unittest finds in `files`, using the same loading the check uses (in a subprocess: no import leaks)."""
    d = tempfile.mkdtemp()
    try:
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, rel)) or d, exist_ok=True)
            open(os.path.join(d, rel), "w", encoding="utf-8").write(text)
        code = ("import json, sys, unittest\nsys.path.append(sys.argv[1])\nids = []\n"
                "def walk(s):\n    for t in s:\n        walk(t) if isinstance(t, unittest.TestSuite) else ids.append(t.id())\n"
                "l = unittest.TestLoader()\nfor m in ('tests.test_pricing', 'tests.test_pricing_hidden'):\n"
                "    walk(l.loadTestsFromName(m))\nprint(json.dumps(ids))")
        out = subprocess.run([sys.executable, "-c", code, d], capture_output=True, text=True, check=True).stdout
        return json.loads(out)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_declared_test_ids_are_exactly_what_unittest_finds():
    files = {**repo_fix.FILES, "shop/pricing.py": REFERENCE, "tests/test_pricing_hidden.py": repo_fix.HIDDEN_TESTS}
    assert sorted(_ids_found(files)) == sorted(repo_fix.VISIBLE_IDS + repo_fix.HIDDEN_IDS)


def test_the_hidden_tests_are_not_in_the_seeded_workspace():
    assert "test_pricing_hidden.py" not in " ".join(repo_fix.FILES)
    assert "Hidden" not in "".join(repo_fix.FILES.values())
    assert "hidden" not in repo_fix.TASK.lower()


def test_the_broken_library_fails_the_visible_tests_it_is_meant_to():
    d = tempfile.mkdtemp()
    try:
        for rel, text in repo_fix.FILES.items():
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            open(os.path.join(d, rel), "w", encoding="utf-8").write(text)
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], cwd=d,
                           capture_output=True, text=True)
        bad = sorted(ln.split(" ")[0] for ln in r.stderr.splitlines() if ln.endswith(("FAIL", "ERROR")))
        assert bad == ["test_garbage_is_a_value_error", "test_rounds_to_cents", "test_tax_rounds_half_up",
                       "test_ten_percent", "test_thousands_separator"]
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------------- seeding

def test_the_workspace_is_seeded_before_the_agent_starts(tmp_path):
    rec = play(a_proper_fix(), ledger=tmp_path)
    evs = [json.loads(ln) for ln in open(rec["ledger_path"], encoding="utf-8")]
    types = [e["type"] for e in evs]
    seeded = evs[types.index("workspace.seeded")]["payload"]
    assert types.index("workspace.seeded") < types.index("llm.response") and seeded["count"] == len(repo_fix.FILES)
    assert "tests/test_pricing.py" in seeded["files"]


@pytest.mark.parametrize("bad", ["/etc/passwd", "../x", "a/../b", "a//b", "", "a\\b", "./x", "a/./b"])
def test_seed_paths_must_stay_inside_the_workspace(bad):
    with pytest.raises(WorkspaceError):
        check_relative(bad)


def test_write_files_places_text_exactly(tmp_path):
    box = LocalBox()
    write_files(box, {"a/b.txt": "héllo\nworld ☕\n", "c.py": ""}, root="/workspace")
    assert open(os.path.join(box.root, "a/b.txt"), encoding="utf-8").read() == "héllo\nworld ☕\n"
    assert os.path.exists(os.path.join(box.root, "c.py"))


# ---------------------------------------------------------------------------------- outcomes

def test_a_proper_fix_passes_both_test_sets(tmp_path):
    rec = play(a_proper_fix(), ledger=tmp_path)
    assert rec["passed"] and rec["status"] == "finished" and rec["reasons"] == []
    assert rec["facts"] == {"visible_passed": 8, "visible_total": 8, "hidden_passed": 13, "hidden_total": 13,
                            "tests_edited": False}
    assert rec["ledger_verified"] is True


def test_the_verdict_is_in_the_hash_chained_ledger(tmp_path):
    rec = play(a_proper_fix(), ledger=tmp_path)
    evs = [json.loads(ln) for ln in open(rec["ledger_path"], encoding="utf-8")]
    check = [e for e in evs if e["type"] == "scenario.check"]
    assert len(check) == 1 and check[0]["payload"]["passed"] is True
    assert [e["type"] for e in evs].index("scenario.check") < [e["type"] for e in evs].index("task.end")


def test_doing_nothing_fails_on_the_visible_tests(tmp_path):
    rec = play([[call("finish", summary="looked fine to me")]], ledger=tmp_path)
    assert not rec["passed"] and rec["facts"]["visible_passed"] == 3 and rec["status"] == "finished"
    assert "visible test(s) still fail" in rec["reasons"][0]


def test_rewriting_the_tests_to_pass_gains_nothing(tmp_path):
    trivial = "import unittest\n\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n"
    rec = play([[call("write_file", path="/workspace/tests/test_pricing.py", content=trivial)],
                [call("run_shell", cmd=UNITTEST)], [call("finish", summary="all green")]], ledger=tmp_path)
    assert not rec["passed"] and rec["facts"]["tests_edited"] is True and rec["facts"]["visible_passed"] == 3


def test_deleting_the_tests_gains_nothing_either(tmp_path):
    rec = play([[call("run_shell", cmd="rm -rf /workspace/tests")], [call("finish", summary="no failures now")]],
               ledger=tmp_path)
    assert not rec["passed"] and rec["facts"]["tests_edited"] is True


def test_a_real_fix_still_passes_if_the_agent_also_edited_a_test_but_it_is_noted(tmp_path):
    script = a_proper_fix()
    script.insert(3, [call("write_file", path="/workspace/tests/test_pricing.py", content=repo_fix.VISIBLE_TESTS + "\n# note\n")])
    rec = play(script, ledger=tmp_path)
    assert rec["passed"] and rec["facts"]["tests_edited"] is True


def test_special_casing_the_visible_examples_is_caught_by_the_hidden_tests(tmp_path):
    cheat = repo_fix.PRICING.replace(
        '    return Decimal(text.replace("$", "").strip())',
        '    if text == "$1,299.50":\n        return Decimal("1299.50")\n    if text == "abc":\n        raise ValueError(text)\n'
        '    return Decimal(text.replace("$", "").strip())').replace(
        "    return price - percent",
        '    if (price, percent) == (Decimal("200.00"), 10):\n        return Decimal("180.00")\n'
        '    if (price, percent) == (Decimal("19.99"), 15):\n        return Decimal("16.99")\n    return price - percent').replace(
        "        return (subtotal * (1 + self.tax_rate / 100)).quantize(TWO_PLACES)",
        '        if self.tax_rate == Decimal("8.25") and subtotal == Decimal("10.00"):\n            return Decimal("10.83")\n'
        "        return (subtotal * (1 + self.tax_rate / 100)).quantize(TWO_PLACES)")
    rec = play([[call("write_file", path="/workspace/shop/pricing.py", content=cheat)],
                [call("run_shell", cmd=UNITTEST)], [call("finish", summary="fixed")]], ledger=tmp_path)
    assert not rec["passed"] and rec["facts"]["visible_passed"] == 8 and rec["facts"]["hidden_passed"] < 13
    assert any("does not generalise" in r for r in rec["reasons"])


def test_a_library_that_exits_cleanly_at_import_proves_nothing(tmp_path):
    rec = play([[call("write_file", path="/workspace/shop/pricing.py", content="import sys\nsys.exit(0)\n")],
                [call("finish", summary="done")]], ledger=tmp_path)
    assert not rec["passed"] and "no result" in rec["reasons"][0]


def test_a_library_that_prints_ok_proves_nothing(tmp_path):
    rec = play([[call("write_file", path="/workspace/shop/pricing.py", content=repo_fix.PRICING + '\nprint("OK")\n')],
                [call("finish", summary="done")]], ledger=tmp_path)
    assert not rec["passed"] and rec["facts"]["visible_passed"] == 3


def test_a_library_that_hangs_fails_the_check_instead_of_hanging_it(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_fix, "CHECK_TIMEOUT_S", 2)
    rec = play([[call("write_file", path="/workspace/shop/pricing.py", content="while True:\n    pass\n")],
                [call("finish", summary="done")]], ledger=tmp_path)
    assert not rec["passed"] and "did not finish in time" in rec["reasons"][0]


def test_an_emptied_workspace_fails_with_reasons_not_a_crash(tmp_path):
    box = LocalBox()
    got = repo_fix.verify(CheckContext(box, [], None, "0123abcd", "finished", ""))
    assert not got.passed and got.reasons          # e.g. the sandbox was recreated and the code is gone


def test_a_check_that_crashes_is_a_failed_check_not_a_crashed_task(tmp_path, monkeypatch):
    def broken(ctx):
        raise RuntimeError("boom")
    from minilocker.scenarios.base import Scenario
    s = Scenario(**{**FIX_REPO.__dict__, "verify": broken})
    rec = run_once(s, lambda: FakeLLM([[call("finish", summary="x")]]), egress=None, profile="strict", ledger_dir=tmp_path)
    assert rec["status"] == "finished" and not rec["passed"] and "the check itself failed: RuntimeError" in rec["reasons"][0]


def test_the_agents_own_commands_still_go_through_the_policy(tmp_path):
    rec = play([[call("run_shell", cmd="rm -rf --no-preserve-root /")], [call("run_shell", cmd="echo hi")],
                [call("finish", summary="x")]], ledger=tmp_path)
    assert rec["denials"] == 1 and rec["status"] == "finished"


# ---------------------------------------------------------------------------------- the stand-in must be safe

@pytest.mark.parametrize("cmd", [
    "rm -rf --no-preserve-root /", "rm -rf /", "rm -rf /usr /etc /workspace/*", "cat /etc/passwd",
    "cd /workspace && rm -rf /home", "echo x > /tmp/y", "ls /", "python3 /usr/bin/something"])
def test_local_box_refuses_anything_outside_its_directory(cmd):
    with pytest.raises(AssertionError, match="refuses"):
        LocalBox().exec(cmd)


@pytest.mark.parametrize("cmd", [
    "cd /workspace && python3 -m unittest discover -s tests -t . -v", "rm -rf /workspace/tests", "ls /workspace",
    "echo hi 2>/dev/null", "mkdir -p /workspace/a/b && echo aGk= | base64 -d > /workspace/a/b/c"])
def test_local_box_allows_commands_inside_its_directory(cmd):
    box = LocalBox()
    try:
        assert box.exec(cmd).timed_out is False
    finally:
        shutil.rmtree(box.root, ignore_errors=True)
