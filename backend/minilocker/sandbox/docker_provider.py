import threading
import uuid
from dataclasses import dataclass

import docker

_client_cache = None


def _client():
    """Created on first use so importing this module never needs a Docker daemon."""
    global _client_cache
    if _client_cache is None:
        _client_cache = docker.from_env()
    return _client_cache


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class Sandbox:
    def __init__(self, image="python:3.12-slim", workspace_mb=64, egress=None):
        self.name = f"minilocker-{uuid.uuid4().hex[:8]}"
        env = {"HOME": "/tmp"}
        net = {}
        if egress is not None:
            net["network"] = egress.internal_network
            env.update(egress.proxy_env())
        else:
            net["network_mode"] = "none"
        self.container = _client().containers.run(
            image,
            command="sleep infinity",
            name=self.name,
            detach=True,
            user="65534:65534",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=128,
            mem_limit="512m",
            memswap_limit="512m",
            nano_cpus=1_000_000_000,
            environment=env,
            tmpfs={
                "/tmp": f"rw,noexec,nosuid,size={workspace_mb}m",
                # exec is explicit: Docker defaults tmpfs to noexec, which breaks compiled wheels
                # (numpy, pandas, ...) installed under /workspace. /tmp stays noexec.
                "/workspace": f"rw,exec,nosuid,size={workspace_mb}m,uid=65534,gid=65534,mode=0755",
            },
            working_dir="/workspace",
            labels={"minilocker": "sandbox"},
            **net,
        )
        self.dead = False
        self.ip = ""
        if egress is not None:
            self.container.reload()
            self.ip = self.container.attrs["NetworkSettings"]["Networks"][
                egress.internal_network]["IPAddress"]

    def exec(self, cmd: str, timeout_s: int = 30) -> ExecResult:
        box = {}

        def work():
            try:
                code, (out, err) = self.container.exec_run(["sh", "-c", cmd], demux=True)
                box["r"] = (code, out or b"", err or b"")
            except Exception as e:  # container killed mid-exec
                box["err"] = e

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            self.container.kill()  # hard deadline: kill the container, not just the process
            self.dead = True
            t.join(5)
            return ExecResult(137, "", "", True)
        if "r" not in box:
            return ExecResult(137, "", str(box.get("err", "")), True)
        code, out, err = box["r"]
        return ExecResult(code, out.decode(errors="replace"),
                          err.decode(errors="replace"), False)

    def destroy(self):
        self.container.remove(force=True)
