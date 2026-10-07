"""Runs agent tasks in worker threads and fans their ledger events out to SSE
subscribers. run_task() is blocking and thread-based (ApprovalGate uses
threading.Event), so the API owns the thread<->asyncio bridge here."""
import asyncio
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from minilocker.ledger.chain import read_events
from minilocker.policy.approvals import ApprovalGate
from minilocker.policy.engine import PolicyEngine

TASK_ID_RE = re.compile(r"^[0-9a-f]{8}$")  # also what keeps ids out of path traversal
_END = object()


class TaskLimitError(Exception):
    pass


class TaskState:
    def __init__(self, task_id, task, profile):
        self.task_id, self.task, self.profile = task_id, task, profile
        self.created = time.time()
        self.status = "running"
        self.result = None
        self.error = None
        self.events: list[dict] = []
        self._subs: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._lock = threading.Lock()

    def publish(self, ev):
        with self._lock:
            self.events.append(ev)
            for loop, q in self._subs:
                loop.call_soon_threadsafe(q.put_nowait, ev)

    def close(self):
        with self._lock:
            for loop, q in self._subs:
                loop.call_soon_threadsafe(q.put_nowait, _END)

    def subscribe(self, after: int):
        """Atomically snapshot the backlog and register for live events, so no
        event is missed or duplicated between replay and live."""
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            backlog = [e for e in self.events if e["id"] > after]
            finished = self.status != "running"
            if not finished:
                self._subs.append((asyncio.get_running_loop(), q))
        return backlog, finished, q

    def unsubscribe(self, q):
        with self._lock:
            self._subs = [(l, x) for l, x in self._subs if x is not q]

    def info(self):
        return {"task_id": self.task_id, "task": self.task, "profile": self.profile,
                "status": self.status, "created": self.created,
                "events": len(self.events), "result": self.result, "error": self.error}


class TaskManager:
    def __init__(self, runner, ledger_dir="runs", egress=None, max_concurrent=2,
                 approval_timeout_s=60.0):
        self.runner = runner
        self.ledger_dir = ledger_dir
        self.egress = egress
        self.max_concurrent = max_concurrent
        self.approval_timeout_s = approval_timeout_s
        self.gate = ApprovalGate(timeout_s=approval_timeout_s)
        self.tasks: dict[str, TaskState] = {}
        self._approvals: dict[str, dict] = {}   # approval id -> {task_id, state}
        self._lock = threading.Lock()
        self._active = 0
        self._pool = ThreadPoolExecutor(max_workers=max_concurrent, thread_name_prefix="minilocker-task")
        os.makedirs(ledger_dir, exist_ok=True)

    # ---- tasks -----------------------------------------------------------
    def start(self, task: str, profile: str, llm) -> TaskState:
        with self._lock:
            if self._active >= self.max_concurrent:
                raise TaskLimitError(f"{self.max_concurrent} tasks already running")
            self._active += 1
        task_id = uuid.uuid4().hex[:8]
        state = TaskState(task_id, task, profile)
        self.tasks[task_id] = state
        try:
            self._pool.submit(self._run, state, llm)
        except Exception:
            with self._lock:
                self._active -= 1
            raise
        return state

    def _on_event(self, state, ev):
        # Register the approval id BEFORE the event reaches any subscriber, so a
        # fast UI click can never race ahead of the registry.
        if ev["type"] == "approval.requested":
            with self._lock:
                self._approvals[ev["payload"]["id"]] = {
                    "task_id": state.task_id, "state": "pending", "req": ev["payload"],
                    "expires_at": ev["ts"] + self.approval_timeout_s}
        elif ev["type"] in ("approval.granted", "approval.denied"):
            with self._lock:
                a = self._approvals.get(ev["payload"]["id"])
                if a:
                    a["state"] = "granted" if ev["type"] == "approval.granted" else "denied"
        state.publish(ev)

    def _run(self, state, llm):
        try:
            result = self.runner(
                state.task, llm, ledger_dir=self.ledger_dir, egress=self.egress,
                policy=PolicyEngine(state.profile), approver=self.gate.ask,
                on_event=lambda ev: self._on_event(state, ev), task_id=state.task_id)
            state.result = result
            state.status = result.get("status", "finished")
        except Exception as e:  # never leak a traceback to clients; it is in the server log
            import traceback
            traceback.print_exc()
            state.error = f"{type(e).__name__}"
            state.status = "error"
        finally:
            with self._lock:
                self._active -= 1
            state.close()

    def get(self, task_id) -> TaskState | None:
        return self.tasks.get(task_id)

    # ---- ledger on disk --------------------------------------------------
    def ledger_path(self, task_id):
        if not TASK_ID_RE.match(task_id):
            return None
        return os.path.join(self.ledger_dir, f"{task_id}.jsonl")

    def load_events(self, task_id):
        """(events, read_error) or None if unknown. Disk is the source of truth so
        verification checks what is actually stored, and old tasks survive restarts."""
        p = self.ledger_path(task_id)
        if p is None or not os.path.exists(p):
            return None
        return read_events(p)

    # ---- approvals -------------------------------------------------------
    def pending_approvals(self, task_id=None):
        # Built from the registry filled at event time, not gate.pending(): the
        # event reaches clients slightly before the loop calls gate.ask().
        now = time.time()
        with self._lock:
            return [{**a["req"], "task_id": a["task_id"], "expires_at": a["expires_at"]}
                    for a in self._approvals.values()
                    if a["state"] == "pending" and a["expires_at"] > now
                    and task_id in (None, a["task_id"])]

    def resolve_approval(self, approval_id, approve: bool):
        """Returns 'unknown' | 'already_resolved' | 'ok'."""
        with self._lock:
            a = self._approvals.get(approval_id)
            if a is None:
                return "unknown"
            if a["state"] != "pending":
                return "already_resolved"
            a["state"] = "resolving"   # blocks a second click before the loop logs the outcome
        self.gate.resolve(approval_id, approve)
        return "ok"

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)
