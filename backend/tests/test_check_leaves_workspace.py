"""The success check must leave the agent's workspace exactly as the agent left it.

The check swaps the pristine and hidden tests into tests/ to run them. The workspace is saved afterwards as the
evidence of what the agent did, so the agent's own tests have to be back by then, and nothing the check ran may
leave files behind (no hidden tests, no .pyc). Real Python in a temp directory, no Docker.
"""
import os
import shutil

import pytest

from minilocker.agent.hooks import CheckContext, write_files
from minilocker.scenarios import repo_fix
from test_scenarios_repo import REFERENCE, LocalBox


@pytest.fixture
def box():
    b = LocalBox()
    yield b
    shutil.rmtree(b.root, ignore_errors=True)


def snapshot(root):
    """{relative path: bytes} of every file under root."""
    out = {}
    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            with open(p, "rb") as f:
                out[os.path.relpath(p, root)] = f.read()
    return out


def check(box):
    return repo_fix.verify(CheckContext(box, [], None, "0123abcd", "finished", ""))


def workspace(box, library=REFERENCE, **extra):
    write_files(box, {**repo_fix.FILES, "shop/pricing.py": library, **extra})


def test_a_passing_check_changes_nothing_in_the_workspace(box):
    agent_test = repo_fix.VISIBLE_TESTS + "\n# the agent added this note\n"
    workspace(box, **{"tests/test_pricing.py": agent_test, "tests/test_extra.py": "# the agent's own extra test\n"})
    before = snapshot(box.root)
    got = check(box)
    assert got.passed and got.facts["tests_edited"] is True
    assert snapshot(box.root) == before                     # identical: same files, same bytes, nothing new
    assert "tests/test_pricing_hidden.py" not in snapshot(box.root)


def test_a_failing_check_changes_nothing_either(box):
    workspace(box, library=repo_fix.PRICING)                # still the broken library
    before = snapshot(box.root)
    assert not check(box).passed
    assert snapshot(box.root) == before


def test_a_library_that_exits_at_import_still_gets_the_agents_tests_back(box):
    workspace(box, library="import sys\nsys.exit(0)\n", **{"tests/test_pricing.py": "# agent's version\n"})
    before = snapshot(box.root)
    got = check(box)
    assert not got.passed and "no result" in got.reasons[0]
    assert snapshot(box.root) == before                     # the restore ran even though the run died


def test_a_library_that_raises_at_import_is_handled_the_same_way(box):
    workspace(box, library="raise RuntimeError('boom')\n")
    before = snapshot(box.root)
    check(box)
    assert snapshot(box.root) == before


def test_if_the_agent_deleted_the_tests_they_stay_deleted(box):
    workspace(box)
    shutil.rmtree(os.path.join(box.root, "tests"))
    got = check(box)
    assert not os.path.exists(os.path.join(box.root, "tests")) and got.facts["tests_edited"] is True


def test_an_agents_pycache_survives_and_the_check_adds_none(box):
    workspace(box)
    os.makedirs(os.path.join(box.root, "shop", "__pycache__"))
    with open(os.path.join(box.root, "shop", "__pycache__", "pricing.cpython-312.pyc"), "wb") as f:
        f.write(b"agent's own bytecode")
    before = snapshot(box.root)
    check(box)
    assert snapshot(box.root) == before
    assert not [p for p in snapshot(box.root) if p.startswith("tests/__pycache__")]


def test_the_verdict_is_unchanged_by_putting_the_tests_back(box):
    workspace(box)
    first = check(box)
    second = check(box)                                     # running it twice gives the same answer
    assert first.passed and second.passed and first.facts == second.facts


def test_pytest_ignores_the_folder_where_scenario_runs_are_saved():
    # runs/ holds the agent's own copies of test files, one set per run; collecting them fails with
    # "import file mismatch". pytest.ini keeps that folder out of collection.
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(os.path.dirname(__file__), "..", "pytest.ini"))
    assert cfg["pytest"]["testpaths"].strip() == "tests"
    assert "runs" in cfg["pytest"]["norecursedirs"].split()
