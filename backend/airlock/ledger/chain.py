import hashlib, json, os, time

GENESIS = "0" * 64


def _canon(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _hash(body: dict) -> str:
    return hashlib.sha256(_canon(body).encode()).hexdigest()


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
        prev = GENESIS
        for i, ev in enumerate(self.events):
            body = {k: v for k, v in ev.items() if k != "hash"}
            if ev["id"] != i:
                return False, f"event {i}: bad id (reordered or deleted)"
            if body["prev_hash"] != prev:
                return False, f"event {i}: chain broken"
            if _hash(body) != ev["hash"]:
                return False, f"event {i}: content tampered"
            prev = ev["hash"]
        return True, f"{len(self.events)} events verified"
