"""The README and SECURITY.md must not drift from the code. Docker-free."""
import dataclasses
import inspect
import re
from pathlib import Path

import pytest

from minilocker.attacks.catalog import ATTACKS
from minilocker.policy.engine import Budgets
from minilocker.sandbox.docker_provider import Sandbox

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "backend" / "minilocker"
README = (ROOT / "README.md").read_text()
SECURITY = (ROOT / "SECURITY.md").read_text()
DOCS = {"README.md": README, "SECURITY.md": SECURITY}


def settings_read_by_the_code() -> set[str]:
    names = set()
    for path in CODE.rglob("*.py"):
        text = path.read_text()
        names |= set(re.findall(r'["\'](MINILOCKER_[A-Z0-9_]*[A-Z0-9])["\']', text))   # not prefixes like X_
        # LLM_ names also appear as marker strings that attacks print, so count only real environment reads
        names |= set(re.findall(r'environ(?:\[|\.get\()\s*["\'](LLM_[A-Z_]*[A-Z])["\']', text))
    return names


def test_every_attack_is_in_the_readme_and_the_count_is_right():
    for a in ATTACKS:
        assert f"`{a.name}`" in README, f"attack {a.name} is not documented"
    claimed = int(re.search(r"\*\*(\d+) scripted attacks\*\*", README).group(1))
    assert claimed == len(ATTACKS)
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", README, re.M)) & {a.name for a in ATTACKS}
    assert documented == {a.name for a in ATTACKS}


def test_every_setting_the_code_reads_is_documented():
    names = settings_read_by_the_code()
    assert {"LLM_API_KEY", "MINILOCKER_ALLOW", "MINILOCKER_S3_BUCKET", "MINILOCKER_BROWSER_FIXTURES"} <= names
    missing = sorted(n for n in names if f"`{n}`" not in README)
    assert not missing, f"undocumented settings: {missing}"


def test_the_budget_table_matches_the_code():
    for f in dataclasses.fields(Budgets):
        assert re.search(rf"^\| `{f.name}` \| {f.default} \|$", README, re.M), \
            f"README budget row for {f.name} should say {f.default}"


def test_the_hardening_numbers_match_the_sandbox_defaults():
    d = {k: p.default for k, p in inspect.signature(Sandbox.__init__).parameters.items()}
    assert d["pids_limit"] == 128 and d["mem_limit"] == "512m" and d["workspace_mb"] == 64
    for doc in (README, SECURITY):
        assert "128 processes" in doc and "512 MB" in doc
    assert "(64 MB)" in README                      # /workspace


@pytest.mark.parametrize("name", DOCS)
def test_relative_links_resolve(name):
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", DOCS[name]):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (ROOT / target).exists(), f"{name} links to {target}, which does not exist"


def test_every_path_in_the_layout_section_exists():
    section = README.split("## Repository layout", 1)[1].split("\n## ", 1)[0]
    paths = re.findall(r"^- `([^`]+)`", section, re.M)
    assert len(paths) >= 8
    for p in paths:
        assert (ROOT / p).exists(), f"layout lists {p}, which does not exist"


def test_files_the_docs_name_exist():
    for p in ("deploy/bootstrap.sh", "deploy/env.production.example", "deploy/dev-storage.sh", "deploy/.env.example",
              "images/browser/Dockerfile", ".github/workflows/ci.yml", "LICENSE", "SECURITY.md"):
        assert (ROOT / p).exists(), p
