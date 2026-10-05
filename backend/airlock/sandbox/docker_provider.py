import threading
import uuid
from dataclasses import dataclass

import docker

_client = docker.from_env()


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class Sandbox:
    def __init__(self, image="python:3.12-slim", workspace_mb=64):
        self.name = f"airlock-{uuid.uuid4().hex[:8]}"
        self.container = _client.containers.run(
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
            network_mode="none",  # becomes the internal proxy network in Week 2
            tmpfs={
                "/tmp": f"rw,noexec,nosuid,size={workspace_mb}m",
                "/workspace": f"rw,nosuid,size={workspace_mb}m,uid=65534,gid=65534,mode=0755",
            },
            working_dir="/workspace",
            labels={"airlock": "sandbox"},
        )
        self.dead = False

    def exec(self, cmd: str, timeout_s: int = 30) -> ExecResult:
        box = {}

        def work():
            try:
                code, (out, err) = self.container.exec_run(
                    ["sh", "-c", cmd], demux=True
                )
                box["r"] = (code, out or b"", err or b"")
            except Exception as e:  # container killed mid-exec
                box["err"] = e

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            # hard deadline: kill the whole container, not just the process
            self.container.kill()
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
