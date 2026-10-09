"""Sandbox.exec_capped against a fake docker API: caps, exit codes, timeouts, failures."""
import threading
import time

from minilocker.sandbox.docker_provider import Sandbox


class FakeAPI:
    def __init__(self, chunks=(), code=0, delay=0.0, boom=None):
        self.chunks, self.code, self.delay, self.boom = list(chunks), code, delay, boom
        self.created = []

    def exec_create(self, cid, argv, stdout=True, stderr=True):
        self.created.append(argv)
        return {"Id": "e1"}

    def exec_start(self, eid, stream=False, demux=False):
        assert stream and demux, "must stream and demultiplex, or stdout/stderr are mixed and unbounded"
        for c in self.chunks:
            time.sleep(self.delay)
            if self.boom:
                raise self.boom
            yield c

    def exec_inspect(self, eid):
        return {"ExitCode": self.code}


class FakeContainer:
    id = "cid"

    def __init__(self, api):
        self.client = type("C", (), {"api": api})()
        self.killed = False

    def kill(self):
        self.killed = True


def box(api):
    sb = Sandbox.__new__(Sandbox)          # skip __init__: no Docker daemon here
    sb.container, sb.dead = FakeContainer(api), False
    return sb


def test_output_is_capped_and_flagged_but_fully_drained():
    api = FakeAPI([(b"a" * 600, None), (b"b" * 600, None), (b"c" * 600, None)])
    r = box(api).exec_capped(["x"], max_bytes=1000)
    assert r.stdout == b"a" * 600 + b"b" * 400 and r.truncated and r.exit_code == 0 and not r.timed_out


def test_stdout_and_stderr_stay_separate_and_exit_code_is_returned():
    r = box(FakeAPI([(b"out", None), (None, b"err"), (b"put", None)], code=3)).exec_capped(["x"])
    assert (r.stdout, r.stderr, r.exit_code, r.truncated) == (b"output"[:3] + b"put", b"err", 3, False)


def test_stderr_is_bounded_too():
    r = box(FakeAPI([(None, b"e" * 100000)])).exec_capped(["x"])
    assert len(r.stderr) == 65536


def test_a_hung_exec_kills_the_container_at_the_deadline():
    # The fake stream cannot be interrupted (a killed container's real one ends), so it finishes its
    # 1.5s sleep; what matters is the deadline fired at 0.3s, the kill happened, and the wait after it is bounded.
    sb = box(FakeAPI([(b"x", None)], delay=1.5))
    t0 = time.time()
    r = sb.exec_capped(["x"], timeout_s=0.3)
    assert r.timed_out and r.exit_code == 137 and sb.dead and sb.container.killed and time.time() - t0 < 4


def test_a_container_dying_mid_exec_is_a_timeout_style_failure_not_an_exception():
    r = box(FakeAPI([(b"x", None)], boom=ConnectionError("container gone"))).exec_capped(["x"])
    assert r.timed_out and r.exit_code == 137


def test_missing_exit_code_is_not_reported_as_success():
    r = box(FakeAPI([(b"x", None)], code=None)).exec_capped(["x"])
    assert r.exit_code == 137 and r.timed_out
