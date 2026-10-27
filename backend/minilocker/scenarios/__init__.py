"""The hero scenarios: tasks with an automatic success check, run repeatedly to measure how often the agent finishes."""
from minilocker.scenarios.base import Scenario
from minilocker.scenarios.repo_fix import FIX_REPO
from minilocker.scenarios.repo_fix_v2 import FIX_REPO_V2
from minilocker.scenarios.research import RESEARCH

SCENARIOS = {s.id: s for s in (FIX_REPO, FIX_REPO_V2, RESEARCH)}

__all__ = ["Scenario", "SCENARIOS", "FIX_REPO", "FIX_REPO_V2", "RESEARCH"]
