"""The hero scenarios: tasks with an automatic success check, run repeatedly to measure how often the agent finishes."""
from minilocker.scenarios.base import Scenario
from minilocker.scenarios.repo_fix import FIX_REPO
from minilocker.scenarios.research import RESEARCH

SCENARIOS = {s.id: s for s in (FIX_REPO, RESEARCH)}

__all__ = ["Scenario", "SCENARIOS", "FIX_REPO", "RESEARCH"]
