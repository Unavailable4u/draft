import select
import sys
import threading


class ApprovalGate:
    """Blocks the agent until a human resolves the request. Timeout = deny.
    The API layer will expose pending() and resolve() to the UI."""

    def __init__(self, timeout_s=60.0):
        self.timeout_s = timeout_s
        self._lock = threading.Lock()
        self._pending = {}
        self._early = {}  # decisions that arrived before ask() registered

    def ask(self, req):
        rid = req["id"]
        entry = {"event": threading.Event(), "approved": False, "req": req}
        with self._lock:
            if rid in self._early:
                return self._early.pop(rid)
            self._pending[rid] = entry
        try:
            if entry["event"].wait(self.timeout_s):
                return bool(entry["approved"])
            return False
        finally:
            with self._lock:
                self._pending.pop(rid, None)

    def resolve(self, rid, approve):
        with self._lock:
            entry = self._pending.get(rid)
            if entry is None:
                self._early[rid] = bool(approve)
                return False
        entry["approved"] = bool(approve)
        entry["event"].set()
        return True

    def pending(self):
        with self._lock:
            return [e["req"] for e in self._pending.values()]


def console_approver(timeout_s=60):
    def ask(req):
        if not sys.stdin.isatty():
            return False
        print(f"\n[APPROVAL NEEDED] risk={req['risk']}: {'; '.join(req['reasons'])}\n"
              f"  command: {req['summary']}\n"
              f"  approve? [y/N] (auto-deny in {timeout_s}s): ", end="", flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], timeout_s)
        if not ready:
            print("timeout -> deny")
            return False
        return sys.stdin.readline().strip().lower() in ("y", "yes")
    return ask
