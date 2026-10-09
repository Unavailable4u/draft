import json
import os
import sys

from minilocker.agent.loop import run_task
from minilocker.config import load_and_report
from minilocker.egress.manager import EgressManager
from minilocker.llm.client import LLMClient
from minilocker.policy.approvals import console_approver
from minilocker.policy.engine import PolicyEngine


def main():
    load_and_report()
    if len(sys.argv) < 2:
        sys.exit('usage: python -m minilocker.cli "your task"   (MINILOCKER_PROFILE=strict|observe)')

    def show(ev):
        print(f"[{ev['actor']}:{ev['type']}] {json.dumps(ev['payload'])[:260]}")

    allow = os.environ.get("MINILOCKER_ALLOW", "pypi.org,files.pythonhosted.org").split(",")
    policy = PolicyEngine(os.environ.get("MINILOCKER_PROFILE", "strict"))
    egress = EgressManager(allow).start()
    try:
        res = run_task(" ".join(sys.argv[1:]), LLMClient(), on_event=show, egress=egress,
                       policy=policy, approver=console_approver(60))
    finally:
        egress.stop()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
