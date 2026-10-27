"""The real secrets the control plane holds, found the way an auditor would: by the names of its environment variables.

The point is the negative result. A sandbox must never contain any of these values, and the audit that runs before each sandbox
is destroyed checks for them (see sandbox/measure.py). Only NAMES ever reach the ledger or a report, never a value.

This is a heuristic on names, so it can miss a secret stored in a variable with an innocent name. That is stated in SECURITY.md:
"zero real secrets found" means none of the secrets this function knows about, not every secret that could exist.
"""
import os
import re

SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
EXPLICIT = ("LLM_API_KEY", "MINILOCKER_API_TOKEN", "MINILOCKER_S3_ACCESS_KEY", "MINILOCKER_S3_SECRET_KEY")
MIN_EXPLICIT = 8          # shorter than this and a substring match would be noise
MIN_GUESSED = 12          # a variable only *named* like a secret must also look like one
MAX_LEN = 4096


def _looks_like_a_secret(value: str) -> bool:
    return len(value) >= MIN_GUESSED and not value.startswith(("/", "~", "./")) and not any(c.isspace() for c in value)


def real_secrets(environ=None) -> dict:
    """{variable name: value} for every environment variable that holds a secret. Values are for in-process comparison only."""
    env = os.environ if environ is None else environ
    out = {}
    for name, value in env.items():
        if not isinstance(value, str) or not value or len(value) > MAX_LEN:
            continue
        if name in EXPLICIT:
            if len(value) >= MIN_EXPLICIT:
                out[name] = value
        elif SECRET_NAME.search(name) and _looks_like_a_secret(value):
            out[name] = value
    return out
