"""Artifact endpoints: what may be listed, what may be served, and how. Real Ledger, real
TaskManager and API; fake runner and in-memory store, so no Docker is needed."""
import json

import pytest
from fastapi.testclient import TestClient

from minilocker.api.app import create_app
from minilocker.artifacts import MemoryArtifactStore, sha256_hex
from minilocker.ledger.chain import Ledger

TID = "0123abcd"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 16
FILES = {"workspace/report.md": b"# Report\nall good", "workspace/page.html": b"<script>steal(localStorage)</script>",
         "workspace/chart.png": PNG, "screenshots/001.jpg": b"\xff\xd8\xff\xe0JPEG"}


def noop_runner(task, llm, ledger_dir, egress, policy, approver, on_event, task_id, **kw):
    noop_runner.kwargs = kw
    return {"status": "finished"}


def seed(tmp_path, store, task_id=TID, files=FILES, extra=()):
    led = Ledger(task_id, f"{tmp_path}/{task_id}.jsonl")
    led.append("user", "task.start", {"task": "t", "profile": "strict"})
    for name, data in files.items():
        info = store.put(task_id, name, data)
        led.append("artifact", "artifact.stored", {"name": name, "kind": "screenshot" if name.startswith("screenshots/") else "file",
                                                    "bytes": info["bytes"], "sha256": info["sha256"]})
    for typ, payload in extra:
        led.append("artifact", typ, payload)
    led.append("agent", "task.end", {"status": "finished", "steps": 1, "summary": ""})


def client(tmp_path, store="default", error=None, **kw):
    store = MemoryArtifactStore() if store == "default" else store
    app = create_app(runner=kw.pop("runner", noop_runner), llm_factory=lambda: object(), egress_factory=lambda: None,
                     artifacts_factory=lambda: (store, error), ledger_dir=str(tmp_path), **kw)
    return TestClient(app), store


def test_listing_comes_from_the_ledger(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store, extra=[("artifact.skipped", {"name": "big.bin", "reason": "too_large", "bytes": 9}),
                                 ("artifact.failed", {"name": "workspace/x", "error": "ClientError"})])
    with c:
        r = c.get(f"/api/tasks/{TID}/artifacts").json()
    assert r["store_attached"] is True
    assert {a["name"] for a in r["artifacts"]} == set(FILES)
    rep = next(a for a in r["artifacts"] if a["name"] == "workspace/report.md")
    assert rep["sha256"] == sha256_hex(FILES["workspace/report.md"]) and rep["bytes"] == len(FILES["workspace/report.md"]) and rep["kind"] == "file"
    assert r["skipped"][0]["name"] == "big.bin" and r["failed"]


def test_listing_works_after_the_store_is_gone(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    c2, _ = client(tmp_path, store=None)
    with c2:
        r = c2.get(f"/api/tasks/{TID}/artifacts").json()
        assert r["store_attached"] is False and len(r["artifacts"]) == len(FILES)
        assert c2.get(f"/api/tasks/{TID}/artifacts/workspace/report.md").status_code == 503


def test_download_returns_the_bytes_with_a_verified_hash(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    with c:
        r = c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md")
    assert r.status_code == 200 and r.content == FILES["workspace/report.md"]
    assert r.headers["x-artifact-sha256"] == sha256_hex(FILES["workspace/report.md"])


def test_active_content_is_never_served_as_active_content(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    with c:
        html = c.get(f"/api/tasks/{TID}/artifacts/workspace/page.html")
        png = c.get(f"/api/tasks/{TID}/artifacts/workspace/chart.png")
        jpg = c.get(f"/api/tasks/{TID}/artifacts/screenshots/001.jpg")
    assert html.headers["content-type"] == "application/octet-stream"
    assert html.headers["content-disposition"].startswith("attachment")
    assert html.headers["x-content-type-options"] == "nosniff" and "sandbox" in html.headers["content-security-policy"]
    assert png.headers["content-type"] == "image/png" and png.headers["content-disposition"].startswith("inline")
    assert jpg.headers["content-type"] == "image/jpeg"


@pytest.mark.parametrize("name", ["workspace/nope.txt", "../0123abcd/workspace/report.md", "workspace/%2e%2e/workspace/report.md", "%2e%2e/%2e%2e/etc/passwd",
                                  "/etc/passwd", "tasks/ffffffff/workspace/secret.txt", "workspace"])
def test_only_names_in_this_tasks_ledger_can_be_fetched(tmp_path, name):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    store.put("ffffffff", "workspace/secret.txt", b"another task's data")     # exists in the store, not in this ledger
    with c:
        assert c.get(f"/api/tasks/{TID}/artifacts/{name}").status_code in (404, 422)


def test_another_tasks_ledger_does_not_grant_access_to_this_one(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    seed(tmp_path, store, task_id="ffffffff", files={"workspace/mine.txt": b"mine"})
    with c:
        assert c.get("/api/tasks/ffffffff/artifacts/workspace/report.md").status_code == 404
        assert c.get("/api/tasks/ffffffff/artifacts/workspace/mine.txt").status_code == 200


def test_unknown_task_is_404(tmp_path):
    c, _ = client(tmp_path)
    with c:
        assert c.get("/api/tasks/deadbeef/artifacts").status_code == 404
        assert c.get("/api/tasks/deadbeef/artifacts/workspace/a").status_code == 404
        assert c.get("/api/tasks/..%2f..%2fetc/artifacts").status_code in (404, 422)


def test_an_object_changed_after_the_fact_is_refused(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    store.objects[f"tasks/{TID}/workspace/report.md"] = b"# Report\nall BAD"      # same length, different bytes
    with c:
        r = c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md")
        assert r.status_code == 409 and "does not match" in r.json()["detail"]
        assert c.get(f"/api/tasks/{TID}/artifacts/screenshots/001.jpg").status_code == 200, "others unaffected"


def test_a_tampered_ledger_makes_the_store_untrustworthy(tmp_path):
    c, store = client(tmp_path)
    seed(tmp_path, store)
    # An attacker rewrites the ledger hash AND the object to match each other: the chain breaks.
    path = tmp_path / f"{TID}.jsonl"
    lines = path.read_text().splitlines()
    ev = json.loads(lines[1])
    forged = b"# Report\nforged"
    ev["payload"].update(sha256=sha256_hex(forged), bytes=len(forged))
    lines[1] = json.dumps(ev)
    path.write_text("\n".join(lines) + "\n")
    store.objects[f"tasks/{TID}/workspace/report.md"] = forged
    with c:
        r = c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md")
    assert r.status_code == 409 and "ledger failed verification" in r.json()["detail"]


def test_store_failures_are_clean_errors(tmp_path):
    class Down(MemoryArtifactStore):
        def get(self, *a):
            raise RuntimeError("connection refused to 10.1.2.3:9000")
    c, store = client(tmp_path, store=Down())
    seed(tmp_path, MemoryArtifactStore())               # ledger refers to objects the store does not have
    with c:
        r = c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md")
        assert r.status_code == 502 and "10.1.2.3" not in r.text, "no internal detail leaks"
    c, store = client(tmp_path)
    with c:
        assert c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md").status_code == 404   # object missing


def test_auth_is_required_when_a_token_is_set(tmp_path):
    c, store = client(tmp_path, api_token="s3cret")
    seed(tmp_path, store)
    with c:
        assert c.get(f"/api/tasks/{TID}/artifacts").status_code == 401
        assert c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md").status_code == 401
        assert c.get(f"/api/tasks/{TID}/artifacts/workspace/report.md", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert c.get("/api/status").status_code == 401


def test_status_reports_what_is_attached_and_why_not(tmp_path, monkeypatch):
    monkeypatch.setattr("minilocker.sandbox.browser.image_present", lambda image=None: True)
    c, _ = client(tmp_path)
    with c:
        s = c.get("/api/status").json()
    assert s["artifacts"] == {"attached": True, "error": None} and s["browser"]["image_present"] is True and s["egress"] is False
    c, _ = client(tmp_path, store=None, error="EndpointConnectionError")
    with c:
        assert c.get("/api/status").json()["artifacts"] == {"attached": False, "error": "EndpointConnectionError"}


def test_the_runner_receives_the_store_only_when_one_is_attached(tmp_path):
    for store, expect in ((MemoryArtifactStore(), True), (None, False)):
        c, st = client(tmp_path, store=store)
        with c:
            r = c.post("/api/tasks", json={"task": "x"})
            assert r.status_code == 202
            import time
            for _ in range(50):
                if hasattr(noop_runner, "kwargs"):
                    break
                time.sleep(0.05)
        assert ("artifacts" in noop_runner.kwargs) is expect
        del noop_runner.kwargs


def test_attack_listing_flags_browser_availability(tmp_path, monkeypatch):
    c, _ = client(tmp_path)
    monkeypatch.setattr("minilocker.sandbox.browser.image_present", lambda image=None: False)
    with c:
        r = c.get("/api/attacks").json()
    by = {a["name"]: a for a in r["attacks"]}
    assert r["browser_available"] is False
    assert by["hostile_page_injection"]["needs_browser"] and not by["hostile_page_injection"]["available"]
    assert by["rm_rf_root"]["available"] and not by["rm_rf_root"]["needs_browser"]
    monkeypatch.setattr("minilocker.sandbox.browser.image_present", lambda image=None: True)
    with c:
        assert {a["name"]: a for a in c.get("/api/attacks").json()["attacks"]}["browser_local_file_access"]["available"]
