"""Control-plane API: task creation, live ledger stream (SSE), approvals,
report and ledger verification."""
import asyncio
import hmac
import json
import os
import threading
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from minilocker.api.tasks import TaskLimitError, TaskManager
from minilocker.artifacts import serve_headers, sha256_hex
from minilocker.artifacts.index import index_from_events
from minilocker.attacks import ATTACKS, describe, get_attack
from minilocker.ledger.chain import verify_events
from minilocker.ledger.report import build_report, render_html

HEARTBEAT_S = 15


class TaskRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4000)
    profile: Literal["strict", "observe"] = "strict"


class ApprovalRequest(BaseModel):
    approve: bool


def _default_runner():
    from minilocker.agent.loop import run_task
    return run_task


def _default_llm_factory():
    from minilocker.llm.client import LLMClient
    return LLMClient


def _default_egress():
    from minilocker.egress.manager import EgressManager
    allow = os.environ.get("MINILOCKER_ALLOW", "pypi.org,files.pythonhosted.org").split(",")
    return EgressManager(allow).start()


def _default_artifacts():
    """(store, error). Configured-but-unreachable is reported, not hidden: the Files tab shows why."""
    from minilocker.artifacts import S3ArtifactStore
    try:
        return S3ArtifactStore.from_env(), None
    except Exception as e:
        import sys
        print(f"[minilocker] artifact store unavailable: {type(e).__name__}: {e}", file=sys.stderr)
        return None, f"{type(e).__name__}"


def _default_attack_runner():
    from minilocker.attacks import run_attack
    return run_attack


def create_app(runner=None, llm_factory=None, egress_factory=None, ledger_dir=None,
               max_concurrent=None, approval_timeout_s=None, api_token=None,
               attack_runner=None, artifacts_factory=None) -> FastAPI:
    """Everything environment-specific is injectable so the API can be tested
    without Docker or a real model."""
    ledger_dir = ledger_dir or os.environ.get("MINILOCKER_LEDGER_DIR", "runs")
    max_concurrent = max_concurrent or int(os.environ.get("MINILOCKER_MAX_TASKS", "2"))
    approval_timeout_s = approval_timeout_s or float(os.environ.get("MINILOCKER_APPROVAL_TIMEOUT", "60"))
    api_token = api_token if api_token is not None else os.environ.get("MINILOCKER_API_TOKEN", "")

    @asynccontextmanager
    async def lifespan(app):
        egress = (egress_factory or _default_egress)()
        app.state.egress = egress
        app.state.artifacts, app.state.artifacts_error = (artifacts_factory or _default_artifacts)()
        app.state.mgr = TaskManager(runner or _default_runner(), ledger_dir=ledger_dir, egress=egress,
                                    max_concurrent=max_concurrent,
                                    approval_timeout_s=approval_timeout_s,
                                    artifacts=app.state.artifacts)
        try:
            yield
        finally:
            app.state.mgr.shutdown()
            if egress is not None:
                egress.stop()

    app = FastAPI(title="MiniLocker control plane", lifespan=lifespan)
    origins = [o for o in os.environ.get("MINILOCKER_CORS_ORIGINS", "http://localhost:5173").split(",") if o]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type", "Last-Event-ID"],
                       expose_headers=["X-Artifact-Sha256"])
    make_llm = llm_factory or _default_llm_factory()
    run_attack = attack_runner or _default_attack_runner()
    # Attacks are heavy (fork bomb, 512 MB allocation) and run code: one at a time by default.
    attack_slots = threading.BoundedSemaphore(int(os.environ.get("MINILOCKER_MAX_ATTACKS", "1")))

    def auth(request: Request):
        # Optional shared-secret guard. POST /api/tasks spends LLM credits and runs
        # code, so set MINILOCKER_API_TOKEN before exposing this on a public IP.
        if not api_token:
            return
        got = request.headers.get("authorization", "")
        if not hmac.compare_digest(got.encode(), f"Bearer {api_token}".encode()):
            raise HTTPException(401, "missing or invalid bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    def mgr(request: Request) -> TaskManager:
        return request.app.state.mgr

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/api/status", dependencies=[Depends(auth)])
    def status(request: Request):
        """What this control plane has attached, for the UI to explain empty tabs honestly."""
        from minilocker.sandbox.browser import BROWSER_IMAGE, image_present
        st = request.app.state
        return {"egress": getattr(st, "egress", None) is not None,
                "artifacts": {"attached": getattr(st, "artifacts", None) is not None,
                              "error": getattr(st, "artifacts_error", None)},
                "browser": {"image": BROWSER_IMAGE, "image_present": image_present()}}

    @app.post("/api/tasks", status_code=202, dependencies=[Depends(auth)])
    def create_task(body: TaskRequest, m: TaskManager = Depends(mgr)):
        try:
            llm = make_llm()   # surface missing LLM_* config now, not inside the worker
        except Exception:
            raise HTTPException(503, "LLM is not configured (LLM_BASE_URL / LLM_MODEL / LLM_API_KEY)")
        try:
            state = m.start(body.task, body.profile, llm)
        except TaskLimitError as e:
            raise HTTPException(429, str(e), headers={"Retry-After": "5"})
        return {"task_id": state.task_id, "status": state.status,
                "events_url": f"/api/tasks/{state.task_id}/events",
                "report_url": f"/api/tasks/{state.task_id}/report"}

    @app.get("/api/tasks", dependencies=[Depends(auth)])
    def list_tasks(limit: int = Query(50, ge=1, le=200), m: TaskManager = Depends(mgr)):
        return {"tasks": m.list_summaries(limit)}

    @app.get("/api/tasks/{task_id}", dependencies=[Depends(auth)])
    def get_task(task_id: str, m: TaskManager = Depends(mgr)):
        st = m.get(task_id)
        if st is not None:
            return st.info()
        loaded = m.load_events(task_id)
        if loaded is None:
            raise HTTPException(404, "unknown task")
        rep = build_report(task_id, *loaded)   # restart case: summarise from disk
        return {"task_id": task_id, "task": rep["task"], "status": rep["outcome"],
                "events": rep["ledger"]["events"], "result": None, "error": None}

    @app.get("/api/tasks/{task_id}/events", dependencies=[Depends(auth)])
    async def stream_events(task_id: str, request: Request, after: int = Query(-1, ge=-1),
                            m: TaskManager = Depends(mgr)):
        """SSE. Every frame's `id` is the ledger event id, so a reconnecting
        EventSource (Last-Event-ID) resumes without gaps or duplicates."""
        last = request.headers.get("last-event-id")
        if last is not None and last.lstrip("-").isdigit():
            after = max(after, int(last))
        st = m.get(task_id)
        if st is None:
            loaded = m.load_events(task_id)
            if loaded is None:
                raise HTTPException(404, "unknown task")
            events = [e for e in loaded[0] if e["id"] > after]

            async def replay():
                for ev in events:
                    yield _frame(ev)
                end = next((e for e in reversed(loaded[0]) if e["type"] == "task.end"), None)
                yield _end_frame({"status": ((end or {}).get("payload") or {}).get("status", "incomplete"),
                                  "replayed": True})
            return _sse(replay())

        async def live():
            backlog, finished, q = st.subscribe(after)
            try:
                for ev in backlog:
                    yield _frame(ev)
                while not finished:
                    try:
                        item = await asyncio.wait_for(q.get(), HEARTBEAT_S)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            return
                        yield ": ping\n\n"
                        continue
                    if isinstance(item, dict):
                        yield _frame(item)
                    else:
                        break
                yield _end_frame({"status": st.status, "error": st.error,
                                  "ledger_verified": (st.result or {}).get("ledger_verified")})
            finally:
                st.unsubscribe(q)
        return _sse(live())

    @app.get("/api/approvals", dependencies=[Depends(auth)])
    def list_approvals(task_id: str | None = None, m: TaskManager = Depends(mgr)):
        return {"pending": m.pending_approvals(task_id)}

    @app.post("/api/approvals/{approval_id}", dependencies=[Depends(auth)])
    def resolve_approval(approval_id: str, body: ApprovalRequest, m: TaskManager = Depends(mgr)):
        r = m.resolve_approval(approval_id, body.approve)
        if r == "unknown":
            raise HTTPException(404, "unknown approval id")
        if r == "already_resolved":
            raise HTTPException(409, "approval already resolved or expired")
        return {"id": approval_id, "decision": "approve" if body.approve else "deny"}

    def _events_or_404(m, task_id):
        loaded = m.load_events(task_id)
        if loaded is None:
            raise HTTPException(404, "unknown task")
        return loaded

    @app.get("/api/tasks/{task_id}/report", dependencies=[Depends(auth)])
    def report(task_id: str, format: Literal["json", "html"] = "json", m: TaskManager = Depends(mgr)):
        events, err = _events_or_404(m, task_id)
        rep = build_report(task_id, events, err)
        if format == "html":
            return HTMLResponse(render_html(rep), headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        return rep

    @app.get("/api/ledger/verify/{task_id}", dependencies=[Depends(auth)])
    def verify(task_id: str, m: TaskManager = Depends(mgr)):
        events, err = _events_or_404(m, task_id)
        ok, detail = verify_events(events)
        if err:
            ok, detail = False, f"ledger unreadable: {err}"
        return {"task_id": task_id, "verified": ok, "detail": detail, "events": len(events),
                "head_hash": events[-1]["hash"] if events else None}

    # ---- Artifacts ------------------------------------------------------------
    @app.get("/api/tasks/{task_id}/artifacts", dependencies=[Depends(auth)])
    def list_artifacts(task_id: str, request: Request, m: TaskManager = Depends(mgr)):
        events, _ = _events_or_404(m, task_id)
        idx = index_from_events(events)
        return {"task_id": task_id, "store_attached": getattr(request.app.state, "artifacts", None) is not None,
                "artifacts": idx["artifacts"], "skipped": idx["skipped"], "failed": idx["failed"]}

    @app.get("/api/tasks/{task_id}/artifacts/{name:path}", dependencies=[Depends(auth)])
    def get_artifact(task_id: str, name: str, request: Request, m: TaskManager = Depends(mgr)):
        """Bytes are served only if (1) the name is one this task's ledger recorded (callers cannot
        name arbitrary keys), (2) the ledger's hash chain verifies, and (3) the stored bytes match
        the SHA-256 recorded in it. Content-Type comes from serve_headers, never from the sandbox."""
        events, err = _events_or_404(m, task_id)
        ok, _ = verify_events(events)
        if err or not ok:
            raise HTTPException(409, "the ledger failed verification; refusing to serve its artifacts")
        entry = index_from_events(events)["by_name"].get(name)
        if entry is None:
            raise HTTPException(404, "no such artifact in this task's ledger")
        store = getattr(request.app.state, "artifacts", None)
        if store is None:
            raise HTTPException(503, "artifact store is not configured")
        try:
            data = store.get(task_id, name)
        except Exception:
            raise HTTPException(502, "artifact store is unreachable")
        if data is None:
            raise HTTPException(404, "the object is missing from the store")
        if len(data) != entry["bytes"] or sha256_hex(data) != entry["sha256"]:
            raise HTTPException(409, "the stored object does not match the hash recorded in the ledger")
        media, headers = serve_headers(name, data)
        return Response(data, media_type=media, headers={**headers, "X-Artifact-Sha256": entry["sha256"]})

    # ---- Attack Lab -----------------------------------------------------------
    @app.get("/api/attacks", dependencies=[Depends(auth)])
    def list_attacks(request: Request):
        from minilocker.sandbox.browser import image_present
        attached = getattr(request.app.state, "egress", None) is not None
        browser_ok = image_present() if any(a.needs_browser for a in ATTACKS) else True
        return {"egress_attached": attached, "browser_available": browser_ok,
                "attacks": [describe(a, attached, browser_ok) for a in ATTACKS]}

    @app.post("/api/attacks/{name}/run", dependencies=[Depends(auth)])
    def run_attack_endpoint(name: str, request: Request):
        """Runs a scripted attack through the real loop, policy and sandbox and returns a
        containment verdict. Blocking (seconds to ~30 s); the ledger is kept like any task's,
        so /api/tasks/{task_id}/report and /api/ledger/verify/{task_id} work on the result."""
        attack = get_attack(name)
        if attack is None:
            raise HTTPException(404, "unknown attack")
        if not attack_slots.acquire(blocking=False):
            raise HTTPException(429, "another attack is already running", headers={"Retry-After": "5"})
        store = getattr(request.app.state, "artifacts", None)
        try:
            return run_attack(attack, ledger_dir=ledger_dir, egress=getattr(request.app.state, "egress", None),
                              **({"artifacts": store} if store is not None else {}))
        finally:
            attack_slots.release()

    return app


def _frame(ev: dict) -> str:
    return f"id: {ev['id']}\nevent: ledger\ndata: {json.dumps(ev, separators=(',', ':'))}\n\n"


def _end_frame(info: dict) -> str:
    return f"event: end\ndata: {json.dumps(info)}\n\n"


def _sse(gen):
    return StreamingResponse(gen, media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


app = create_app()
