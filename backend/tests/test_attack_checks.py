"""Regression tests for two Attack Lab failures seen on a real Docker run. No Docker needed."""
from types import SimpleNamespace as NS

import minilocker.agent.loop as loop_mod
from minilocker.agent.loop import run_task
from minilocker.attacks.catalog import FORK_PY, MIB64, _disk_caps, _pid_limit
from minilocker.attacks.model import FAIL, PASS, UNPROVEN, Ctx, StepRecord
from minilocker.policy.engine import PolicyEngine
from test_agent_loop import FakeLLM, call


def ctx(step_id, text):
    rec = StepRecord(index=0, id=step_id, tool="run_shell", args={}, result=text)
    return Ctx(attack=None, events=[], records=[rec], run={}, canary=None,
               egress_attached=False, sandbox_exists=lambda n: False)


# Output captured from a real run: both tmpfs mounts stopped at exactly 64 MiB, the rootfs was
# read-only. dd's "No space left" line is dropped by `tail -n 1`, so it is NOT in this text.
REAL_DISK_OUTPUT = ("exit_code=0\n67108864 bytes (67 MB, 64 MiB) copied, 0.117959 s, 569 MB/s\n"
                    "WS_BYTES=67108864\n67108864 bytes (67 MB, 64 MiB) copied, 0.0988588 s, 679 MB/s\n"
                    "TMP_BYTES=67108864\ntouch: cannot touch '/usr/local/pwned': Read-only file system\n"
                    "ROOTFS_WRITE_EXIT=1\n")


def test_disk_cap_is_proven_by_file_size_not_by_a_discarded_message():
    assert _disk_caps(ctx("fill", REAL_DISK_OUTPUT))[0] == PASS


def test_disk_check_still_rejects_what_it_should():
    over = REAL_DISK_OUTPUT.replace("WS_BYTES=67108864", f"WS_BYTES={MIB64 + 4096}")
    short = REAL_DISK_OUTPUT.replace("TMP_BYTES=67108864", "TMP_BYTES=1048576")
    rw_root = REAL_DISK_OUTPUT.replace("ROOTFS_WRITE_EXIT=1", "ROOTFS_WRITE_EXIT=0")
    assert _disk_caps(ctx("fill", over))[0] == FAIL        # cap exceeded
    assert _disk_caps(ctx("fill", rw_root))[0] == FAIL     # rootfs writable
    assert _disk_caps(ctx("fill", short))[0] == UNPROVEN   # stopped short: cap not shown to be the cause


def test_fork_probe_reaps_its_children_and_still_reports_the_limit():
    compile(FORK_PY, "forkloop.py", "exec")
    assert "waitpid" in FORK_PY and "SIGKILL" in FORK_PY
    assert _pid_limit(ctx("fork_loop", "exit_code=0\nblocked_at 125\n"))[0] == PASS


class WedgedThenHealthy:
    """First sandbox: exec cannot start (PID table full). Replacement: healthy."""
    made = []

    def __init__(self, egress=None):
        self.first = not WedgedThenHealthy.made
        WedgedThenHealthy.made.append(self)
        self.name, self.ip = f"stub{len(WedgedThenHealthy.made)}", ""

    def exec(self, cmd, timeout_s=30):
        if self.first:
            return NS(exit_code=128, timed_out=False, stderr="", stdout=(
                "OCI runtime exec failed: exec failed: unable to start container process: "
                "error executing setns process: Resource temporarily unavailable"))
        return NS(exit_code=0, stdout="SANDBOX_HEALTHY", stderr="", timed_out=False)

    def destroy(self):
        pass


def test_a_sandbox_that_cannot_start_processes_is_replaced(tmp_path, monkeypatch):
    WedgedThenHealthy.made = []
    monkeypatch.setattr(loop_mod, "Sandbox", WedgedThenHealthy)
    evs = []
    llm = FakeLLM([[call("run_shell", cmd="echo one")], [call("run_shell", cmd="echo two")],
                   [call("finish", summary="done")]])
    run_task("t", llm, ledger_dir=str(tmp_path), on_event=evs.append, policy=PolicyEngine("observe"))
    recreated = [e["payload"] for e in evs if e["type"] == "sandbox.recreated"]
    results = [e["payload"]["result"] for e in evs if e["type"] == "tool.result"]
    assert [r["reason"] for r in recreated] == ["wedged"]
    assert "did not run" in results[0]            # the agent is told its command never ran
    assert "SANDBOX_HEALTHY" in results[1]        # and the next command works
