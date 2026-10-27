"""The channel between a person (or the Attack Lab) and a running task: rewind the workspace, or end the hold early.

The agent loop owns the sandbox, so nothing here touches it. A caller asks, the loop acts at its next safe point (between steps,
or right after the model replied and before its calls run) and records what it did. Thread-safe: callers are API threads.
"""
import threading


class TaskControl:
    def __init__(self):
        self._lock = threading.Lock()
        self._rewind = None
        self._snapshots = ()
        self._open = True
        self.enabled = False                 # the loop sets this when its sandbox can snapshot
        self.released = threading.Event()    # ends a hold (see run_task's hold_s) early

    # -- the loop's side -----------------------------------------------------------------------------------------------
    def publish(self, snapshot_ids):
        with self._lock:
            self._snapshots = tuple(snapshot_ids)

    def take_rewind(self):
        with self._lock:
            sid, self._rewind = self._rewind, None
            return sid

    def close(self):
        with self._lock:
            self._open = False
            self._rewind = None
        self.released.set()

    # -- the caller's side -----------------------------------------------------------------------------------------------
    def request_rewind(self, snapshot_id) -> str:
        """-> 'queued' | 'closed' | 'unsupported' | 'unknown_snapshot'."""
        with self._lock:
            if not self._open:
                return "closed"
            if not self.enabled:
                return "unsupported"
            if snapshot_id not in self._snapshots:
                return "unknown_snapshot"
            self._rewind = snapshot_id
            return "queued"

    def release(self):
        self.released.set()

    @property
    def snapshots(self):
        with self._lock:
            return list(self._snapshots)

    @property
    def is_open(self):
        with self._lock:
            return self._open
