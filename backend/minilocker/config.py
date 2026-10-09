"""Load settings from a `.env` file so they need not be exported in every shell.

No dependency: the format is the plain KEY=VALUE subset that `deploy/.env.example` uses.

  * Real environment variables win. A file only fills in what is unset (or empty), so compose,
    systemd and `export` behave exactly as they do without a file.
  * Search order: $MINILOCKER_ENV_FILE (a missing explicit file is an error), then, walking up
    from the current directory, `.env` and `deploy/.env` in each directory (first file found).
  * Only the entry points call this (`python -m minilocker.api`, `.cli`). Tests never do, so a
    developer's key cannot leak into the test suite.
  * Values are never printed.
"""
import os
import re
from pathlib import Path

KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
MAX_LEVELS_UP = 4


def parse(text: str) -> dict[str, str]:
    out = {}
    for raw in text.lstrip("\ufeff").splitlines():            # splitlines() also drops Windows \r
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if not sep or not KEY_RE.match(key):
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].rstrip()   # trailing ` # comment`
        out[key] = val
    return out


def find_env_file(environ=None, start: Path | None = None) -> Path | None:
    environ = os.environ if environ is None else environ
    explicit = environ.get("MINILOCKER_ENV_FILE")
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"MINILOCKER_ENV_FILE points at {p}, which does not exist")
        return p
    d = (start or Path.cwd()).resolve()
    for _ in range(MAX_LEVELS_UP + 1):
        for cand in (d / ".env", d / "deploy" / ".env"):
            if cand.is_file():
                return cand
        if d.parent == d:
            break
        d = d.parent
    return None


def load_env(environ=None, start: Path | None = None):
    """Returns (path, number of settings applied), or None when there is no file."""
    environ = os.environ if environ is None else environ
    path = find_env_file(environ, start)
    if path is None:
        return None
    applied = 0
    for k, v in parse(path.read_text(encoding="utf-8", errors="replace")).items():
        if not environ.get(k):
            environ[k] = v
            applied += 1
    return path, applied


def load_and_report() -> None:
    """For entry points: load, and say where from (never the values)."""
    got = load_env()
    if got:
        print(f"[config] {got[1]} setting(s) loaded from {got[0]} (variables already set in the shell win)")
