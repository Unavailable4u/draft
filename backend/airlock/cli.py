import json
import os
import sys

from airlock.agent.loop import run_task
from airlock.egress.manager import EgressManager
from airlock.llm.client import LLMClient
from airlock.policy.approvals import console_approver
from airlock.policy.engine import PolicyEngine


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python -m airlock.cli "your task"   (AIRLOCK_PROFILE=strict|observe)')

    def show(ev):
        print(f"[{ev['actor']}:{ev['type']}] {json.dumps(ev['payload'])[:260]}")

    allow = os.environ.get("AIRLOCK_ALLOW", "pypi.org,files.pythonhosted.org").split(",")
    policy = PolicyEngine(os.environ.get("AIRLOCK_PROFILE", "strict"))
    egress = EgressManager(allow).start()
    try:
        res = run_task(" ".join(sys.argv[1:]), LLMClient(), on_event=show, egress=egress,
                       policy=policy, approver=console_approver(60))
    finally:
        egress.stop()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
