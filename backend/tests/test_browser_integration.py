"""Needs a Docker daemon. The browser tests also need the image:
    docker build -f images/browser/Dockerfile -t minilocker-browser:latest .
Skipped otherwise, so the Docker-free suite stays green anywhere."""
import base64
import json

import pytest

from minilocker.artifacts import MemoryArtifactStore, sha256_hex
from minilocker.artifacts.export import export_workspace


def _docker_ok():
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:
        return False


docker_needed = pytest.mark.skipif(not _docker_ok(), reason="needs a Docker daemon")


def _browser_image():
    from minilocker.sandbox.browser import image_present
    return _docker_ok() and image_present()


browser_needed = pytest.mark.skipif(not _browser_image(), reason="needs the minilocker-browser image")


@docker_needed
def test_exec_capped_caps_output_and_reports_exit_codes():
    from minilocker.sandbox.docker_provider import Sandbox
    sb = Sandbox()
    try:
        r = sb.exec_capped(["python3", "-c", "import sys; sys.stdout.write('x' * 500000)"], max_bytes=1000)
        assert len(r.stdout) == 1000 and r.truncated and r.exit_code == 0
        r = sb.exec_capped(["sh", "-c", "echo out; echo err >&2; exit 3"])
        assert (r.exit_code, r.stdout.strip(), r.stderr.strip()) == (3, b"out", b"err")
        r = sb.exec_capped(["python3", "-c", "import sys; sys.stdout.buffer.write(bytes(range(256)))"])
        assert r.stdout == bytes(range(256)), "binary safe"
    finally:
        sb.destroy()


@docker_needed
def test_exec_capped_kills_the_container_on_timeout():
    from minilocker.sandbox.docker_provider import Sandbox
    sb = Sandbox()
    try:
        r = sb.exec_capped(["sleep", "30"], timeout_s=2)
        assert r.timed_out and sb.dead
    finally:
        sb.destroy()


@docker_needed
def test_hardening_snapshot_reflects_what_docker_enforces():
    from minilocker.sandbox.docker_provider import Sandbox
    sb = Sandbox()
    try:
        h = sb.hardening()
        assert h["user"] == "65534:65534" and h["read_only_rootfs"] is True and "ALL" in h["cap_drop"]
        assert any("no-new-privileges" in o for o in h["security_opt"]) and h["binds"] == [] and h["network_mode"] == "none"
        assert h["pids_limit"] == 128 and h["memory"] == 512 * 1024 * 1024 and h["privileged"] in (False, None)
    finally:
        sb.destroy()


@docker_needed
def test_workspace_export_from_a_real_sandbox():
    from minilocker.sandbox.docker_provider import Sandbox
    sb, store, evs = Sandbox(), MemoryArtifactStore(), []
    try:
        r = sb.exec("mkdir -p out pkgs/x .git && echo '# hi' > out/report.md && echo noise > pkgs/x/a.py && "
                    "echo noise > .git/HEAD && ln -s /etc/passwd link && dd if=/dev/zero of=big.bin bs=1M count=6 2>/dev/null")
        assert r.exit_code == 0, r.stderr
        res = export_workspace(sb, store, "0123abcd", lambda a, t, p=None: evs.append((t, p)))
    finally:
        sb.destroy()
    stored = {p["name"]: p for t, p in evs if t == "artifact.stored"}
    assert set(stored) == {"workspace/out/report.md"}, "pkgs/, .git/, the symlink and the oversize file are not saved"
    assert stored["workspace/out/report.md"]["sha256"] == sha256_hex(b"# hi\n")
    assert [p["name"] for t, p in evs if t == "artifact.skipped"] == ["big.bin"]
    assert res == {"stored": 1, "skipped": 1}


@browser_needed
def test_real_browser_end_to_end():
    from minilocker.sandbox.browser import BrowserSandbox
    b = BrowserSandbox(egress=None, fixtures=True)
    try:
        r = b.call("goto", {"url": "http://127.0.0.1:8099/clean.html"})
        assert r["ok"], r
        assert r["title"] == "Clean fixture page" and "emperor penguin" in r["text"]
        assert base64.b64decode(r["screenshot_b64"])[:3] == b"\xff\xd8\xff"
        link = next(e for e in r["elements"] if e["tag"] == "a")
        assert "Second clean page" in b.call("click", {"ref": link["ref"]})["title"]
        refused = b.call("goto", {"url": "file:///etc/passwd"})
        assert not refused["ok"] and "not allowed" in refused["error"]
        h = b.hardening()
        assert h["user"] == "65534:65534" and h["read_only_rootfs"] is True and h["binds"] == []
        assert h["pids_limit"] == 512 and h["network_mode"] == "none"
    finally:
        b.destroy()


@browser_needed
def test_real_browser_contains_the_hostile_fixtures():
    from minilocker.sandbox.browser import BrowserSandbox
    b = BrowserSandbox(egress=None, fixtures=True)
    try:
        b.call("goto", {"url": "http://127.0.0.1:8099/local_files.html", "wait_ms": 2500})
        text = b.call("extract", {})["text"]
        probe = json.loads(text.split("BROWSER_RESULT ", 1)[1].split("\n")[0])
        assert probe and all(v.startswith("BLOCKED") for v in probe.values()), probe
        assert "root:x:0:0" not in text
    finally:
        b.destroy()
