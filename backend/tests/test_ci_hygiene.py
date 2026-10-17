"""Things that broke CI once and are cheap to keep checking. No Docker, no network.

`./deploy/bootstrap.sh` failed on GitHub with "Permission denied" (exit 126) because the file was committed
as mode 100644. Commits made on Windows never record the executable bit (core.fileMode is off there), so the
mistake is easy to repeat; these tests read the *git index*, which is what CI will check out.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> subprocess.CompletedProcess:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True)
    if r.returncode != 0:
        pytest.skip("not a git checkout")
    return r


def tracked_scripts() -> dict[str, str]:
    """{path: mode} for every tracked deploy/*.sh, as the index records it."""
    out = git("ls-files", "-s", "--", "deploy/*.sh").stdout.decode()
    modes = {}
    for line in out.splitlines():
        meta, _, path = line.partition("\t")
        modes[path] = meta.split()[0]
    return modes


def test_deploy_scripts_are_executable_in_git():
    modes = tracked_scripts()
    assert "deploy/bootstrap.sh" in modes, "bootstrap.sh should be tracked"
    bad = sorted(p for p, m in modes.items() if m != "100755")
    assert not bad, (f"not executable in git: {bad}. Fix: git update-index --chmod=+x {' '.join(bad)}  "
                     "(on Windows, `chmod` alone is not enough: git ignores the bit there)")


def test_committed_shell_scripts_use_lf_line_endings():
    for path in tracked_scripts():
        blob = git("show", f":{path}").stdout
        assert b"\r" not in blob, f"{path} has CRLF line endings in the index; the shebang would fail on Linux"


def test_gitattributes_pins_lf_for_linux_files():
    attrs = (ROOT / ".gitattributes").read_text()
    for pattern in (r"\*\.sh", r"Dockerfile\*", r"Caddyfile"):
        assert re.search(rf"^{pattern}\s+text\s+eol=lf\s*$", attrs, re.M), f".gitattributes should pin LF for {pattern}"
