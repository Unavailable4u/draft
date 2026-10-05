import json
import sys

from airlock.agent.loop import run_task
from airlock.llm.client import LLMClient


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python -m airlock.cli "your task"')

    def show(ev):
        print(f"[{ev['actor']}:{ev['type']}] {json.dumps(ev['payload'])[:260]}")

    res = run_task(" ".join(sys.argv[1:]), LLMClient(), on_event=show)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
