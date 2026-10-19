from dataclasses import dataclass
from typing import Callable

from minilocker.policy.engine import Budgets


@dataclass(frozen=True)
class Scenario:
    """A task with a success check. The check is trusted code, never written or seen by the model."""
    id: str
    title: str
    task: str                       # what the agent is told
    files: dict                     # {relative path: text}, placed in /workspace before the agent starts
    verify: Callable                # CheckContext -> Check
    budgets: Budgets
    allow: tuple = ()               # hosts the scenario needs reachable, on top of MINILOCKER_ALLOW

    @property
    def needs_network(self) -> bool:
        return bool(self.allow)
