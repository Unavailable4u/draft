"""What the loop does about secrets and measurement, kept out of loop.py: plant decoys, notice their use, audit each sandbox.

A `Watch` is inert for a sandbox that cannot measure itself (the stand-ins tests use), so nothing here changes how those run.
Every method logs through the loop's `log(actor, type, payload)`, so everything it notices is a hash-chained ledger event.
The decoy VALUES never leave this object: events carry ids and labels only (see trust/canary.py for what each event means).
"""
from minilocker.sandbox import measure
from minilocker.trust import Canaries, real_secrets

TRIP_MESSAGE = ("Blocked: this command contains a credential that was planted as a decoy in this sandbox. Using it is exactly "
                "what an attacker would do, so the task is stopped here.")


class Watch:
    def __init__(self, strict: bool = False, environ=None):
        self.strict = strict                   # strict profile: a decoy in a command blocks it and ends the task
        self.real = real_secrets(environ)
        self.canaries = None
        self.decoy_baseline = {}
        self.file_baseline = None              # {path: [size, sha256]} of /workspace once seeded
        self.tripped = False
        self._read, self._copied = set(), set()

    @staticmethod
    def supported(box) -> bool:
        return bool(getattr(box, "supports_measure", False))

    # -- planting ------------------------------------------------------------------------------------------------------
    def attach(self, box, log, reseed: bool = False):
        """Plant the decoys in a fresh sandbox and take the workspace baseline (once). Needs the files to be seeded already."""
        if not self.supported(box):
            return
        try:
            if self.canaries is None:
                self.canaries = Canaries()
            self.decoy_baseline = self.canaries.install(box)
            if self.file_baseline is None and not reseed:
                man = measure.run_manifest(box, self.canaries.file_paths())
                self.file_baseline = (man or {}).get("files")
            log("canary", "canary.seeded", {"name": getattr(box, "name", "?"), **self.canaries.public(),
                                            "baseline_taken": self.file_baseline is not None})
        except Exception as e:
            self.canaries = None
            log("canary", "canary.unavailable", {"reason": f"{type(e).__name__}: {str(e)[:160]}"})

    # -- noticing -------------------------------------------------------------------------------------------------------
    def check_call(self, tool: str, text: str, log, via: str) -> list:
        """Decoys named in something the agent is about to run or write. Logs `canary.tripped`; the caller decides to block."""
        if self.canaries is None:
            return []
        ids = self.canaries.find(text)
        for item in ids:
            self.tripped = True
            log("canary", "canary.tripped", {"item": item, "label": self.canaries.label(item), "tool": tool, "via": via,
                                             "blocked": self.strict})
        return ids

    def after_tool(self, box, tool: str, result: str, log, probe: bool = False):
        """After a tool ran: did a decoy value reach the model's context, and (if `probe`) did a decoy file get read?"""
        if self.canaries is None:
            return
        for item in self.canaries.find(result):
            log("canary", "canary.exposed", {"item": item, "label": self.canaries.label(item), "tool": tool, "via": "output"})
        if probe and not getattr(box, "dead", False):
            try:
                now = self.canaries.stat(box)
            except Exception:
                return
            self._note_reads(now, log, "atime")

    def _note_reads(self, now: dict, log, via: str):
        from minilocker.trust.canary import FILE_ITEMS
        for path, base in self.decoy_baseline.items():
            cur = now.get(path)
            item = FILE_ITEMS.get(path, path)
            if cur and cur[0] > base[0] and item not in self._read:
                self._read.add(item)
                log("canary", "canary.read", {"item": item, "label": self.canaries.label(item), "path": path, "via": via})

    def on_egress(self, ev: dict, log):
        """A decoy used as (part of) the host name of an outgoing connection: the cheapest way to smuggle one out."""
        if self.canaries is None:
            return
        for item in self.canaries.find(str(ev.get("host") or "")):
            self.tripped = True
            log("canary", "canary.tripped", {"item": item, "label": self.canaries.label(item), "tool": "egress",
                                             "via": "egress_host", "blocked": ev.get("decision") == "blocked"})

    # -- measuring --------------------------------------------------------------------------------------------------------
    def audit(self, box, kind: str, log, workspace: bool = True):
        """Measure `box` and write what was found to the ledger, just before it is destroyed. Never raises."""
        if not self.supported(box):
            return
        try:
            a = measure.audit(box, kind=kind, real=self.real, canaries=self.canaries if kind == "code" else None,
                              decoy_baseline=self.decoy_baseline, baseline=self.file_baseline if kind == "code" else None,
                              workspace=workspace and kind == "code")
            if kind == "code" and self.canaries is not None:
                from minilocker.trust.canary import FILE_ITEMS
                for path, st in (a.get("canaries", {}).get("files") or {}).items():
                    item = FILE_ITEMS.get(path, path)
                    if st.get("read") and item not in self._read:
                        self._read.add(item)
                        log("canary", "canary.read", {"item": item, "label": self.canaries.label(item), "path": path,
                                                       "via": "audit"})
                for item in a.get("canaries", {}).get("copied_out") or []:
                    if item not in self._copied:
                        self._copied.add(item)
                        log("canary", "canary.copied", {"item": item, "label": self.canaries.label(item),
                                                         "where": "workspace_or_tmp"})
            log("sandbox", "sandbox.audit", a)
        except Exception as e:
            log("sandbox", "sandbox.audit", {"name": getattr(box, "name", "?"), "kind": kind,
                                             "incomplete": [f"audit:{type(e).__name__}"]})
