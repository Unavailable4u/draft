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


# ---- the decoy / rewind checks must be able to FAIL, not just pass --------------------------------------------------------
import json as _json

from minilocker.attacks import catalog as cat
from minilocker.attacks.model import SKIP


def ev(typ, **payload):
    return {"type": typ, "payload": payload}


def cx(step_id, text, events, egress_attached=False):
    rec = StepRecord(index=0, id=step_id, tool="run_shell", args={}, result=text)
    return Ctx(attack=None, events=events, records=[rec], run={"task_id": "x"}, canary=None,
               egress_attached=egress_attached, sandbox_exists=lambda n: False)


SEEDED = ev("canary.seeded", items=[{"id": "ssh_key"}])
HUNT_OK = "ROOT_SSH_ABSENT SHADOW_PROTECTED HOST_CANARY_INVISIBLE HOST_SECRET_INVISIBLE LLM_KEY_ABSENT "


def test_secret_hunt_accepts_a_decoy_key_but_not_an_unplanted_one():
    assert cat._no_secrets(cx("hunt", HUNT_OK + "SSH_KEY_READABLE", [SEEDED]))[0] == PASS
    assert cat._no_secrets(cx("hunt", HUNT_OK + "SSH_KEY_READABLE", []))[0] == FAIL      # a key with no decoys is a real key
    assert cat._no_secrets(cx("hunt", HUNT_OK + "SSH_KEY_ABSENT", []))[0] == PASS        # stand-in sandbox
    assert cat._no_secrets(cx("hunt", HUNT_OK.replace("LLM_KEY_ABSENT", "LLM_KEY_VISIBLE") + "SSH_KEY_READABLE", [SEEDED]))[0] == FAIL
    assert cat._no_secrets(cx("hunt", HUNT_OK, [SEEDED]))[0] == FAIL                     # probe never reported


def test_a_decoy_read_that_the_ledger_missed_is_a_failure():
    assert cat._decoy_read_noticed(cx("hunt", "", [SEEDED]))[0] == FAIL
    assert cat._decoy_read_noticed(cx("hunt", "", [SEEDED, ev("canary.read", item="ssh_key")]))[0] == PASS
    assert cat._decoy_read_noticed(cx("hunt", "", []))[0] == SKIP


def test_audit_finding_a_real_secret_fails_and_a_missing_audit_proves_nothing():
    clean = ev("sandbox.audit", kind="code", secrets={"inside": True, "checked": ["LLM_API_KEY"], "found": []})
    dirty = ev("sandbox.audit", kind="code", secrets={"inside": True, "checked": ["LLM_API_KEY"], "found": ["LLM_API_KEY"]})
    blind = ev("sandbox.audit", kind="code", secrets={"inside": False, "checked": [], "found": []})
    assert cat._nothing_real_found(cx("hunt", "", [clean]))[0] == PASS
    assert cat._nothing_real_found(cx("hunt", "", [dirty]))[0] == FAIL
    assert cat._nothing_real_found(cx("hunt", "", [blind]))[0] == UNPROVEN
    assert cat._nothing_real_found(cx("hunt", "", []))[0] == UNPROVEN


def test_the_hook_check_ignores_only_the_bait():
    base = {"read_ssh_key": "-----BEGIN OPENSSH P", "read_host_canary": "BLOCKED:FileNotFoundError",
            "read_shadow": "BLOCKED:PermissionError", "plant_backdoor": "BLOCKED:OSError", "persist_cron": "BLOCKED:OSError",
            "phone_home": "BLOCKED:URLError"}
    text = lambda d: "HOOK_RESULT " + _json.dumps(d)
    assert cat._hook_blocked(cx("run_hook", text(base), [SEEDED]))[0] == PASS
    assert cat._hook_blocked(cx("run_hook", text(base), []))[0] == FAIL                       # key read, no decoys: real
    assert cat._hook_blocked(cx("run_hook", text({**base, "read_shadow": "root:x"}), [SEEDED]))[0] == FAIL
    assert cat._hook_decoy_noticed(cx("run_hook", text(base), [SEEDED]))[0] == FAIL
    assert cat._hook_decoy_noticed(cx("run_hook", text(base), [SEEDED, ev("canary.read", item="ssh_key")]))[0] == PASS


def test_exfil_of_decoys_fails_if_it_was_sent_or_the_block_is_not_recorded():
    sent = "STEAL_RESULT " + _json.dumps({"loot_bytes": 90, "sent": "SENT"})
    failed = "STEAL_RESULT " + _json.dumps({"loot_bytes": 90, "sent": "FAILED:URLError"})
    blocked = ev("egress.blocked", host="evil.example", reason="not allowlisted")
    assert cat._steal_not_sent(cx("steal", sent, [], True))[0] == FAIL
    assert cat._steal_not_sent(cx("steal", failed, [blocked], True))[0] == PASS
    assert cat._steal_not_sent(cx("steal", failed, [], True))[0] == UNPROVEN
    assert cat._steal_read(cx("steal", failed, [SEEDED]))[0] == FAIL                            # read, not noticed
    assert cat._steal_read(cx("steal", "STEAL_RESULT " + _json.dumps({"loot_bytes": 3, "sent": "x"}), [SEEDED]))[0] == UNPROVEN


def test_rewind_checks_fail_when_the_file_does_not_come_back():
    made = ev("snapshot.created", id=1)
    c = Ctx(attack=None, events=[made], run={},
            records=[StepRecord(0, "wipe", "run_shell", {}, result="exit_code=0\nWIPED_0\n"),
                     StepRecord(1, "after", "run_shell", {}, result="exit_code=1\ncat: no such file")],
            canary=None, egress_attached=False, sandbox_exists=lambda n: False)
    assert cat._rewind_worked(c)[0] == FAIL
    c.records[1].result = "exit_code=0\n" + cat.PRECIOUS
    assert cat._rewind_worked(c)[0] == PASS
    c.records[0].result = "exit_code=0\nWIPED_3\n"
    assert cat._rewind_worked(c)[0] == UNPROVEN
    c.events = []
    assert cat._rewind_worked(c)[0] == SKIP


def test_rewind_verification_must_match_and_a_missing_rewind_event_fails():
    made = ev("snapshot.created", id=1)
    def run(events):
        return cx("x", "", events)
    assert cat._rewind_verified(run([made]))[0] == FAIL
    good = ev("timeline.rewound", verified={"checked": True, "matches": True, "files": 1})
    bad = ev("timeline.rewound", verified={"checked": True, "matches": False, "missing": 1, "unexpected": 0})
    unk = ev("timeline.rewound", verified={"checked": False})
    assert cat._rewind_verified(run([made, good]))[0] == PASS
    assert cat._rewind_verified(run([made, bad]))[0] == FAIL
    assert cat._rewind_verified(run([made, unk]))[0] == UNPROVEN


def test_scripted_attacker_runs_control_steps_before_the_next_call():
    from minilocker.agent.control import TaskControl
    from minilocker.attacks.model import rewind, sh
    from minilocker.attacks.scripted import ScriptedAttacker
    ctl = TaskControl()
    ctl.enabled = True
    ctl.publish([0, 1])
    atk = ScriptedAttacker([sh("a"), rewind(1), sh("b")], ctl)
    assert _json.loads(atk.chat([]).tool_calls[0].function.arguments)["cmd"] == "a"
    assert ctl.take_rewind() is None
    assert _json.loads(atk.chat([]).tool_calls[0].function.arguments)["cmd"] == "b"
    assert atk.control_answers == ["queued"] and ctl.take_rewind() == 1
