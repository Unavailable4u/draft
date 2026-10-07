import json
import os
import sys

from airlock.agent.loop import run_task
from airlock.egress.manager import EgressManager
from airlock.llm.client import LLMClient


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python -m airlock.cli "your task"')

    def show(ev):
        print(f"[{ev['actor']}:{ev['type']}] {json.dumps(ev['payload'])[:260]}")

    allow = os.environ.get("AIRLOCK_ALLOW", "pypi.org,files.pythonhosted.org").split(",")
    egress = EgressManager(allow).start()
    try:
        res = run_task(" ".join(sys.argv[1:]), LLMClient(), on_event=show, egress=egress)
    finally:
        egress.stop()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
