"""What a scenario needs from `run_task`: files placed in the workspace before the agent starts, and a check that
runs inside the agent's own sandbox once it has stopped.

Both are trusted code supplied by the caller, never by the model, so they bypass the policy engine (the agent's
commands do not). The result of a check is written to the ledger (`scenario.check`), so a pass or a fail is as
tamper-evident as everything else the agent did.
"""
import base64
import json
import shlex
from dataclasses import dataclass, field

MAX_SEED_BYTES = 90_000      # one exec argument must stay well under the 128 KB kernel limit


class WorkspaceError(Exception):
    pass


@dataclass
class Check:
    """The verdict of a scenario's success check."""
    passed: bool
    reasons: list = field(default_factory=list)     # why it failed (empty when it passed)
    facts: dict = field(default_factory=dict)       # what was measured, for the report

    def payload(self) -> dict:
        return {"passed": self.passed, "reasons": [str(r)[:300] for r in self.reasons][:12], "facts": self.facts}


@dataclass
class CheckContext:
    """Everything a check may look at. `box` is the code sandbox as it is *now* (it may have been recreated
    mid-task, in which case the agent's workspace is gone and the check should fail on that basis)."""
    box: object
    events: list
    artifacts: object            # an ArtifactStore, or None
    task_id: str
    status: str
    summary: str
    root: str = "/workspace"


def run_script(box, script: str, *args: str, timeout_s: int = 30):
    """Run a python3 script inside the sandbox. The script travels base64-encoded and is read from stdin, and
    `-I` makes the interpreter ignore the environment and the working directory, so nothing the agent left in
    /workspace can shadow the standard library for it."""
    b64 = base64.b64encode(script.encode()).decode()
    cmd = f"echo {b64} | base64 -d | python3 -I - " + " ".join(shlex.quote(a) for a in args)
    return box.exec(cmd, timeout_s)


_SEED = r'''
import base64, json, os, sys
root, blob = sys.argv[1], sys.argv[2]
for rel, text in json.loads(base64.b64decode(blob)).items():
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
'''


def check_relative(rel) -> str:
    """A plain relative path: no leading slash, no `.` or `..` segments, no empty segments, no backslash or NUL."""
    ok = isinstance(rel, str) and bool(rel) and not rel.startswith("/") and "\\" not in rel and "\0" not in rel
    if ok:
        ok = all(seg not in ("", ".", "..") for seg in rel.split("/"))
    if not ok:
        raise WorkspaceError(f"not a relative path inside the workspace: {rel!r}")
    return rel


def write_files(box, files: dict, root: str = "/workspace", timeout_s: int = 20) -> int:
    """Write {relative path: text} under `root`. -> bytes written. Raises WorkspaceError."""
    for rel in files:
        check_relative(rel)
    blob = base64.b64encode(json.dumps(files).encode()).decode()
    if len(blob) > MAX_SEED_BYTES:
        raise WorkspaceError("seed files are too large to send in one command")
    r = run_script(box, _SEED, root, blob, timeout_s=timeout_s)
    if r.exit_code != 0:
        raise WorkspaceError(f"could not write the workspace files (exit {r.exit_code}): {r.stderr[-200:]}")
    return sum(len(t.encode()) for t in files.values())
