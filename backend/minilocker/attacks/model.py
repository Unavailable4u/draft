"""Attack definitions are data. One definition feeds the API, the UI and pytest.

A check returns (status, detail):
  pass      the containment property held
  fail      a containment property was violated  -> verdict "breached"
  unproven  the attack did not exercise the property (it fizzled, or the policy
            stopped it first), so nothing can be claimed -> verdict "inconclusive"
  skip      not applicable in this environment (e.g. no egress proxy attached)
"Measure, don't claim": an attack that proves nothing must not read as contained.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

PASS, FAIL, UNPROVEN, SKIP = "pass", "fail", "unproven", "skip"


def ok(detail=""):
    return (PASS, detail)


def breach(detail):
    return (FAIL, detail)


def unproven(detail):
    return (UNPROVEN, detail)


def skip(detail):
    return (SKIP, detail)


class StepMissing(Exception):
    """A check referenced a step the loop never reached."""


@dataclass(frozen=True)
class Step:
    tool: str            # run_shell | write_file | read_file | finish
    args: dict
    id: str = ""         # label that checks use to find this step's outcome


def sh(cmd: str, id: str = "") -> Step:
    return Step("run_shell", {"cmd": cmd}, id)


def write(path: str, content: str, id: str = "") -> Step:
    return Step("write_file", {"path": path, "content": content}, id)


@dataclass
class StepRecord:
    """What the real loop did with one scripted step, rebuilt from the ledger."""
    index: int
    id: str
    tool: str
    args: dict
    policy: dict | None = None
    approval: str | None = None          # "granted" | "denied"
    result: str | None = None
    egress: list = field(default_factory=list)
    recreated: bool = False

    @property
    def text(self) -> str:
        return self.result or ""


@dataclass
class Ctx:
    attack: "Attack"
    events: list
    records: list
    run: dict
    canary: object            # HostCanary
    egress_attached: bool
    sandbox_exists: Callable[[str], bool]

    def step(self, id: str) -> StepRecord:
        for r in self.records:
            if r.id == id:
                return r
        raise StepMissing(id)

    def after(self, id: str) -> list:
        return [r for r in self.records if r.index > self.step(id).index]

    def egress_events(self, decision=None, host=None):
        out = []
        for e in self.events:
            if not e["type"].startswith("egress.") or e["type"] == "egress.closed":
                continue
            d = e["type"].split(".", 1)[1]
            if decision and d != decision:
                continue
            if host and e["payload"].get("host") != host:
                continue
            out.append(e["payload"])
        return out


@dataclass(frozen=True)
class Check:
    label: str
    fn: Callable[[Ctx], tuple]


@dataclass(frozen=True)
class Attack:
    name: str
    title: str
    category: str
    summary: str          # what the attacker tries
    expected: str         # what containment looks like
    profile: str          # strict | observe
    steps: tuple
    checks: tuple
    exec_timeout_s: int = 10
    needs_egress: bool = False
