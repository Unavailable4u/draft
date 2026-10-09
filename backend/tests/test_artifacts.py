"""Artifact store, workspace export and safe serving. No Docker needed: the S3 store runs
against moto's in-process S3 server and the exporter script is executed for real in a subprocess."""
import json
import os
import subprocess
import sys

import pytest

from minilocker.artifacts import (ArtifactError, MemoryArtifactStore, S3ArtifactStore,
                                   export_workspace, parse_export, serve_headers, sha256_hex, valid_name)
from minilocker.artifacts.export import build_script, clean_name
from minilocker.artifacts.store import object_key
from minilocker.sandbox.docker_provider import RawResult

TID = "0123abcd"


# ---- names -------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["a.txt", "workspace/out/report 1.md", "screenshots/001.jpg", "dir/ünï.csv"])
def test_valid_names(name):
    assert valid_name(name)


@pytest.mark.parametrize("name", ["", "/etc/passwd", "../x", "a/../b", "a//b", ".", "a/./b", "a\\b",
                                  "x\x00y", "a/" * 9 + "b", "x" * 400, "-leading-dash/ok", ".hidden"])
def test_invalid_names(name):
    assert not valid_name(name)


def test_object_key_pins_the_task_namespace():
    assert object_key(TID, "workspace/a.txt") == f"tasks/{TID}/workspace/a.txt"
    for bad_tid in ("../../etc", "", "ABCDEFGH", "0123abcdef"):
        with pytest.raises(ArtifactError):
            object_key(bad_tid, "a.txt")
    with pytest.raises(ArtifactError):
        object_key(TID, "../other/a.txt")


# ---- backends ----------------------------------------------------------------------
def _contract(store):
    info = store.put(TID, "workspace/a.txt", b"hello")
    assert info == {"bytes": 5, "sha256": sha256_hex(b"hello")}
    assert store.get(TID, "workspace/a.txt") == b"hello"
    assert store.get(TID, "workspace/missing.txt") is None
    assert store.get("ffffffff", "workspace/a.txt") is None, "another task's namespace is separate"


def test_memory_store_contract():
    _contract(MemoryArtifactStore())


def test_s3_store_contract_and_bucket_creation():
    pytest.importorskip("moto")
    from moto.server import ThreadedMotoServer
    srv = ThreadedMotoServer(port=0, verbose=False)
    srv.start()
    try:
        host, port = srv.get_host_and_port()
        env = {"MINILOCKER_S3_ENDPOINT": f"http://{host}:{port}", "MINILOCKER_S3_ACCESS_KEY": "k",
               "MINILOCKER_S3_SECRET_KEY": "s", "MINILOCKER_S3_BUCKET": "t-bucket"}
        store = S3ArtifactStore.from_env(env)          # creates the missing bucket
        store.ping()
        _contract(store)
        assert S3ArtifactStore.from_env(env) is not None, "second start finds the bucket it made"
        # whatever the sandbox called it, it is stored as opaque bytes
        head = store.client.head_object(Bucket="t-bucket", Key=f"tasks/{TID}/workspace/a.txt")
        assert head["ContentType"] == "application/octet-stream"
    finally:
        srv.stop()


def test_s3_not_configured_means_not_attached():
    assert S3ArtifactStore.from_env({}) is None
    assert S3ArtifactStore.from_env({"MINILOCKER_S3_ENDPOINT": "http://x"}) is None


# ---- the parser treats the sandbox's output as hostile ------------------------------
def frame(path, data=b"", **extra):
    return json.dumps({"p": path, "n": len(data), **extra}).encode() + b"\n" + data


def test_parse_roundtrip_and_skips():
    raw = frame("a.txt", b"hi") + frame("d/b.bin", b"\x00\xff\n\n{}") + \
        json.dumps({"skip": "big.bin", "reason": "too_large", "n": 99}).encode() + b"\n"
    ex = parse_export(raw)
    assert ex.files == [("a.txt", b"hi"), ("d/b.bin", b"\x00\xff\n\n{}")]   # bodies may contain anything
    assert ex.skipped == [{"name": "big.bin", "reason": "too_large", "bytes": 99}]
    assert ex.problems == []


@pytest.mark.parametrize("path", ["../escape", "/abs/path", "a/../../b", "", "a//b", None, 7])
def test_parse_rejects_traversal_and_stops(path):
    raw = frame("ok1.txt", b"1") + frame(path, b"x") + frame("after.txt", b"2")
    ex = parse_export(raw)
    assert [n for n, _ in ex.files] == ["ok1.txt"], "nothing after an untrustworthy frame is believed"
    assert ex.problems


def test_parse_odd_characters_are_replaced_not_trusted():
    ex = parse_export(frame("we ird\x01na<me>?.txt", b"x"))
    assert ex.files and valid_name(ex.files[0][0]) and "<" not in ex.files[0][0]


def test_parse_enforces_its_own_caps():
    many = b"".join(frame(f"f{i}.txt", b"x") for i in range(10))
    ex = parse_export(many, max_files=3)
    assert len(ex.files) == 3 and len(ex.skipped) == 7
    ex = parse_export(frame("a", b"x" * 50) + frame("b", b"y" * 50), max_total=60)
    assert [n for n, _ in ex.files] == ["a"] and ex.skipped[0]["name"] == "b"
    ex = parse_export(frame("big", b"x" * 100), max_file=10)
    assert ex.files == [] and ex.problems


@pytest.mark.parametrize("raw", [b"not json at all\n", b'{"p":"a","n":5}\nab', b'{"p":"a","n":-1}\n',
                                 b'{"p":"a","n":true}\n', b'[1,2]\n', b"x" * 5000, b'{"p":"a","n":"3"}\nabc'])
def test_parse_malformed_never_raises(raw):
    ex = parse_export(raw)
    assert ex.files == [] and ex.problems


def test_colliding_names_do_not_overwrite():
    ex = parse_export(frame("r.txt", b"1") + frame("r.txt", b"2"))
    names = [n for n, _ in ex.files]
    assert len(set(names)) == 2 and sorted(d for _, d in ex.files) == [b"1", b"2"]


def test_clean_name_rejects_bad_shapes():
    assert clean_name("a/b/c.txt") == "a/b/c.txt"
    assert clean_name("../a") is None and clean_name("a/") is None and clean_name("/a") is None


# ---- the real in-sandbox script ------------------------------------------------------
def run_script(root, **kw):
    r = subprocess.run([sys.executable, "-I", "-c", build_script(str(root), **kw)],
                       capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_export_script_end_to_end(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "report.md").write_text("# hi")
    (tmp_path / "data.csv").write_bytes(b"a,b\n1,2\n")
    (tmp_path / "pkgs" / "numpy").mkdir(parents=True)
    (tmp_path / "pkgs" / "numpy" / "x.py").write_text("noise")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("noise")
    (tmp_path / "huge.bin").write_bytes(b"\0" * 5000)
    os.symlink("/etc/passwd", tmp_path / "link")          # must never be followed
    os.symlink("/etc", tmp_path / "dirlink")
    os.mkfifo(tmp_path / "fifo")                          # not a regular file: ignored, must not hang
    ex = parse_export(run_script(tmp_path, max_file=1000))
    assert sorted(n for n, _ in ex.files) == ["data.csv", "out/report.md"]
    assert dict(ex.files)["out/report.md"] == b"# hi"
    assert ex.skipped == [{"name": "huge.bin", "reason": "too_large", "bytes": 5000}]
    assert ex.problems == []


def test_export_script_total_limits(tmp_path):
    for i in range(6):
        (tmp_path / f"f{i}.txt").write_text("x" * 10)
    ex = parse_export(run_script(tmp_path, max_files=4))
    assert len(ex.files) == 4 and len(ex.skipped) == 2
    ex = parse_export(run_script(tmp_path, max_total=25))
    assert len(ex.files) == 2 and all(s["reason"] == "limit" for s in ex.skipped)


# ---- export_workspace: ledger events, failure handling ---------------------------------
class FakeSB:
    def __init__(self, result):
        self.result, self.calls = result, []

    def exec_capped(self, argv, timeout_s=30, max_bytes=0):
        self.calls.append((argv, timeout_s))
        return self.result


def collect():
    evs = []
    return evs, lambda actor, typ, payload=None: evs.append((actor, typ, payload))


def test_export_workspace_stores_and_commits_hashes_to_the_ledger():
    store = MemoryArtifactStore()
    out = frame("report.md", b"# done") + json.dumps({"skip": "x", "reason": "limit", "n": 1}).encode() + b"\n"
    evs, log = collect()
    sb = FakeSB(RawResult(0, out, b"", False))
    r = export_workspace(sb, store, TID, log)
    assert r == {"stored": 1, "skipped": 1}
    assert sb.calls[0][0][:3] == ["python3", "-I", "-c"], "isolated mode: a planted tarfile.py/os.py is not imported"
    stored = [p for _, t, p in evs if t == "artifact.stored"][0]
    assert stored == {"name": "workspace/report.md", "kind": "file", "bytes": 6, "sha256": sha256_hex(b"# done")}
    assert store.get(TID, "workspace/report.md") == b"# done"
    assert [t for _, t, _ in evs] == ["artifact.stored", "artifact.skipped"]


@pytest.mark.parametrize("result", [RawResult(137, b"", b"", True), RawResult(1, b"", b"boom", False)])
def test_export_failure_is_logged_not_raised(result):
    evs, log = collect()
    assert export_workspace(FakeSB(result), MemoryArtifactStore(), TID, log) == {"stored": 0, "skipped": 0}
    assert [t for _, t, _ in evs] == ["artifact.export_failed"]


def test_export_survives_a_failing_store_and_a_crashing_sandbox():
    class Boom(MemoryArtifactStore):
        def put(self, *a):
            raise RuntimeError("s3 down")
    evs, log = collect()
    export_workspace(FakeSB(RawResult(0, frame("a.txt", b"x"), b"", False)), Boom(), TID, log)
    assert [t for _, t, _ in evs] == ["artifact.failed"]

    class Crash:
        def exec_capped(self, *a, **k):
            raise OSError("container gone")
    evs, log = collect()
    export_workspace(Crash(), MemoryArtifactStore(), TID, log)
    assert [t for _, t, _ in evs] == ["artifact.export_failed"]


# ---- serving: attacker-controlled bytes must not become active content ------------------
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 8
JPG = b"\xff\xd8\xff\xe0" + b"\0" * 12


def test_only_real_raster_images_are_inline():
    for name, data, media in (("a.png", PNG, "image/png"), ("screenshots/001.jpg", JPG, "image/jpeg"),
                              ("a.GIF", b"GIF89a" + b"\0" * 10, "image/gif")):
        m, h = serve_headers(name, data)
        assert m == media and h["Content-Disposition"].startswith("inline")


@pytest.mark.parametrize("name,data", [
    ("evil.html", b"<script>steal()</script>"), ("evil.svg", b"<svg onload=alert(1)>"),
    ("evil.js", b"alert(1)"), ("fake.png", b"<script>alert(1)</script>"),   # lies about its type
    ("noext", b"x"), ("a.png.html", PNG),
])
def test_everything_else_is_an_opaque_download(name, data):
    m, h = serve_headers(name, data)
    assert m == "application/octet-stream" and h["Content-Disposition"].startswith("attachment")


def test_serve_headers_always_lock_the_response_down():
    _, h = serve_headers("a.html", b"<b>")
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in h["Content-Security-Policy"] and "default-src 'none'" in h["Content-Security-Policy"]
    _, h = serve_headers('we"ird\r\nname.txt', b"x")
    assert "\r" not in h["Content-Disposition"] and "\n" not in h["Content-Disposition"]
    assert h["Content-Disposition"].count('"') == 2, "no quote injection"
