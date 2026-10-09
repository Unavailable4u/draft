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


@dataclass
class RawResult:
    """Like ExecResult but binary-safe and size-capped (see Sandbox.exec_capped)."""
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool = False


class Sandbox:
    """One hardened container. `role` only changes the image/limits/command, never the
    hardening: every role is non-root, read-only, cap-less and on a network with no route out."""

    def __init__(self, image="python:3.12-slim", workspace_mb=64, egress=None, *,
                 role="code", command="sleep infinity", mem_limit="512m", pids_limit=128,
                 tmp_mb=None, shm_size=None, extra_env=None):
        self.role = role
        self.name = f"minilocker-{'' if role == 'code' else role + '-'}{uuid.uuid4().hex[:8]}"
        env = {"HOME": "/tmp"}
        net = {}
        if egress is not None:
            net["network"] = egress.internal_network
            env.update(egress.proxy_env())
        else:
            net["network_mode"] = "none"
        env.update(extra_env or {})
        extra = {"shm_size": shm_size} if shm_size else {}
        self.container = _client().containers.run(
            image,
            command=command,
            name=self.name,
            detach=True,
            user="65534:65534",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=pids_limit,
            mem_limit=mem_limit,
            memswap_limit=mem_limit,
            nano_cpus=1_000_000_000,
            environment=env,
            tmpfs={
                "/tmp": f"rw,noexec,nosuid,size={tmp_mb or workspace_mb}m",
                # exec is explicit: Docker defaults tmpfs to noexec, which breaks compiled wheels
                # (numpy, pandas, ...) installed under /workspace. /tmp stays noexec.
                "/workspace": f"rw,exec,nosuid,size={workspace_mb}m,uid=65534,gid=65534,mode=0755",
            },
            working_dir="/workspace",
            labels={"minilocker": "sandbox", "minilocker.role": role},
            **extra,
            **net,
        )
        self.dead = False
        self.ip = ""
        if egress is not None:
            self.container.reload()
            self.ip = self.container.attrs["NetworkSettings"][
                "Networks"][egress.internal_network]["IPAddress"]

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

    def exec_capped(self, argv: list, timeout_s: int = 30, max_bytes: int = 4_000_000) -> RawResult:
        """Run argv (no shell) and stream its output, keeping at most max_bytes of stdout.

        For output the control plane must parse (browser RPC, workspace export): it is binary
        safe and a hostile process cannot make the host buffer unbounded output. Past the cap
        the rest is drained and discarded, and `truncated` is set. Same hard deadline as exec():
        on timeout the whole container is killed."""
        box = {"out": bytearray(), "err": bytearray(), "trunc": False}

        def work():
            try:
                api = self.container.client.api
                eid = api.exec_create(self.container.id, argv, stdout=True, stderr=True)["Id"]
                for out, err in api.exec_start(eid, stream=True, demux=True):
                    if out:
                        room = max_bytes - len(box["out"])
                        box["out"] += out[:max(room, 0)]
                        box["trunc"] |= len(out) > room
                    if err and len(box["err"]) < 65536:
                        box["err"] += err[:65536 - len(box["err"])]
                box["code"] = api.exec_inspect(eid).get("ExitCode")
            except Exception as e:  # container killed mid-exec
                box["error"] = e

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            self.container.kill()
            self.dead = True
            t.join(5)
            return RawResult(137, bytes(box["out"]), bytes(box["err"]), True, box["trunc"])
        if "error" in box or box.get("code") is None:
            return RawResult(137, bytes(box["out"]), str(box.get("error", "")).encode(), True, box["trunc"])
        return RawResult(box["code"], bytes(box["out"]), bytes(box["err"]), False, box["trunc"])

    def hardening(self) -> dict:
        """The enforced invariants as docker reports them for THIS container (not as we asked
        for them), small and JSON-safe, for the ledger. Missing keys mean 'unknown', never 'ok'."""
        try:
            self.container.reload()
            a = self.container.attrs
            hc, cfg = a.get("HostConfig") or {}, a.get("Config") or {}
            return {
                "role": self.role,
                "user": cfg.get("User"),
                "read_only_rootfs": hc.get("ReadonlyRootfs"),
                "cap_drop": hc.get("CapDrop") or [],
                "cap_add": hc.get("CapAdd") or [],
                "privileged": hc.get("Privileged"),
                "security_opt": hc.get("SecurityOpt") or [],
                "pids_limit": hc.get("PidsLimit"),
                "memory": hc.get("Memory"),
                "memory_swap": hc.get("MemorySwap"),
                "network_mode": hc.get("NetworkMode"),
                "networks": sorted((a.get("NetworkSettings") or {}).get("Networks") or {}),
                "pid_mode": hc.get("PidMode") or "",
                "ipc_mode": hc.get("IpcMode") or "",
                "runtime": hc.get("Runtime"),
                "binds": hc.get("Binds") or [],
                "mounts": [{"type": m.get("Type"), "dest": m.get("Destination")}
                           for m in a.get("Mounts") or []],
                "tmpfs": sorted((hc.get("Tmpfs") or {}).keys()),
            }
        except Exception:
            return {}

    def destroy(self):
        self.container.remove(force=True)
