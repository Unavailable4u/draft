import hashlib, json, os, time

GENESIS = "0" * 64


def _canon(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _hash(body: dict) -> str:
    return hashlib.sha256(_canon(body).encode()).hexdigest()


def verify_events(events: list[dict]) -> tuple[bool, str]:
    prev = GENESIS
    for i, ev in enumerate(events):
        body = {k: v for k, v in ev.items() if k != "hash"}
        if ev.get("id") != i:
            return False, f"event {i}: bad id (reordered or deleted)"
        if body.get("prev_hash") != prev:
            return False, f"event {i}: chain broken"
        if _hash(body) != ev.get("hash"):
            return False, f"event {i}: content tampered"
        prev = ev["hash"]
    return True, f"{len(events)} events verified"


def read_events(path: str) -> tuple[list[dict], str | None]:
    """Parse a ledger file. A torn *final* line (writer mid-append) is ignored;
    an unparseable line anywhere else is returned as an error, never skipped."""
    with open(path) as f:
        lines = [ln for ln in f.read().split("\n") if ln.strip()]
    events: list[dict] = []
    for i, ln in enumerate(lines):
        try:
            ev = json.loads(ln)
            if not isinstance(ev, dict):
                raise ValueError("not an object")
            events.append(ev)
        except ValueError:
            if i == len(lines) - 1:
                break
            return events, f"line {i}: unparseable"
    return events, None


class Ledger:
    def __init__(self, task_id: str, path: str | None = None):
        self.task_id = task_id
        self.path = path
        self.events: list[dict] = []
        if path and os.path.exists(path):
            with open(path) as f:
                self.events = [json.loads(line) for line in f if line.strip()]

    def append(self, actor: str, type: str, payload: dict | None = None) -> dict:
        prev = self.events[-1]["hash"] if self.events else GENESIS
        body = {
            "id": len(self.events),
            "ts": time.time(),
            "task_id": self.task_id,
            "actor": actor,
            "type": type,
            "payload": payload or {},
            "prev_hash": prev,
        }
        ev = {**body, "hash": _hash(body)}
        self.events.append(ev)
        if self.path:
            with open(self.path, "a") as f:
                f.write(_canon(ev) + "\n")
        return ev

    def verify(self) -> tuple[bool, str]:
        return verify_events(self.events)
