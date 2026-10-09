"""Control-plane side of the browser sandbox.

A second kind of untrusted runtime: Chromium rendering attacker-controlled pages. It gets the
same container hardening as the code sandbox (non-root, read-only rootfs, no capabilities, an
internal network whose only neighbour is the egress proxy) with bigger resource limits,
because Chromium needs them. The control plane talks to it only through `docker exec` into a
unix socket inside the container.
"""
import base64
import json
import os
import time

import docker

from minilocker.sandbox.docker_provider import Sandbox, _client

BROWSER_IMAGE = os.environ.get("MINILOCKER_BROWSER_IMAGE", "minilocker-browser:latest")
BUILD_HINT = "docker build -f images/browser/Dockerfile -t minilocker-browser:latest ."
MAX_REPLY_BYTES = 6_000_000
START_TIMEOUT_S = 45


class BrowserUnavailable(Exception):
    """The browser sandbox could not be started. The task carries on without a browser."""


def image_present(image: str = None) -> bool:
    try:
        _client().images.get(image or BROWSER_IMAGE)
        return True
    except Exception:
        return False


class BrowserSandbox:
    def __init__(self, egress=None, image: str = None, sandbox_cls=Sandbox, start_timeout_s=START_TIMEOUT_S,
                 fixtures: bool = False):
        image = image or BROWSER_IMAGE
        # Checked first: `docker run` would otherwise try to PULL a local-only name from Docker Hub.
        if not image_present(image):
            raise BrowserUnavailable(f"image {image!r} not found. Build it once with: {BUILD_HINT}")
        try:
            self.sb = sandbox_cls(
                image=image, egress=egress, role="browser",
                command=["python", "-u", "/opt/browser_worker.py", "serve"],
                workspace_mb=8, tmp_mb=192, mem_limit="1g",
                pids_limit=512,          # Chromium is multi-process and counts threads
                shm_size="256m",
                # Attack Lab only: serve the hostile fixtures on loopback and let loopback bypass the proxy
                **({"extra_env": {"MINILOCKER_BROWSER_FIXTURES": "1"}} if fixtures else {}))
        except (docker.errors.APIError, docker.errors.ImageNotFound) as e:
            raise BrowserUnavailable(f"could not start the browser container: {type(e).__name__}") from e
        self.name, self.ip = self.sb.name, self.sb.ip
        self._await_ready(start_timeout_s)

    @property
    def dead(self) -> bool:
        return self.sb.dead

    def hardening(self) -> dict:
        return self.sb.hardening()

    def _await_ready(self, timeout_s):
        deadline, last = time.time() + timeout_s, "no reply"
        while time.time() < deadline:
            self.sb.container.reload()
            if self.sb.container.status != "running":
                logs = self.sb.container.logs(tail=15).decode(errors="replace")[-600:]
                self.destroy()
                raise BrowserUnavailable(f"the browser container exited while starting: {logs.strip()}")
            r = self.call("ping", {}, timeout_s=10)
            if r.get("ok"):
                return
            last = r.get("error", last)
            time.sleep(0.7)
        self.destroy()
        raise BrowserUnavailable(f"the browser did not become ready in {timeout_s}s ({last})")

    def call(self, action: str, params: dict, timeout_s: int = 40) -> dict:
        """One RPC. Always returns a dict with `ok`. `fatal` means the container was killed and
        a fresh browser is needed (page state is gone)."""
        req = base64.b64encode(json.dumps({"action": action, **params}).encode()).decode()
        r = self.sb.exec_capped(["python3", "/opt/browser_worker.py", "call", req],
                                timeout_s=timeout_s, max_bytes=MAX_REPLY_BYTES)
        if r.timed_out:
            return {"ok": False, "fatal": True,
                    "error": f"the browser did not answer within {timeout_s}s and was reset"}
        if r.truncated:
            return {"ok": False, "error": "the page produced an oversized reply and it was dropped"}
        try:
            out = json.loads(r.stdout.decode(errors="replace"))
            if not isinstance(out, dict):
                raise ValueError
            return out
        except ValueError:
            return {"ok": False, "error": f"unreadable browser reply (exit {r.exit_code})"}

    def destroy(self):
        self.sb.destroy()
