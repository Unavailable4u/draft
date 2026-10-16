"""deploy/smoke_check.py against a stub API. It runs inside the api container in real use."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "smoke_check.py"


def serve(status, verdict="contained", token="tok"):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            if self.headers.get("Authorization") != f"Bearer {token}":
                self._send(401, {"detail": "no"})
                return False
            return True

        def do_POST(self):
            if self._authed() and self.path == "/api/attacks/rm_rf_root/run":
                self._send(200, {"verdict": verdict})

        def do_GET(self):
            if self._authed() and self.path == "/api/status":
                self._send(200, status)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(srv, token="tok"):
    env = {**os.environ, "SMOKE_BASE": f"http://127.0.0.1:{srv.server_port}", "MINILOCKER_API_TOKEN": token}
    return subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=env, timeout=30)


HEALTHY = {"egress": True, "artifacts": {"attached": True, "error": None},
           "browser": {"image": "b:latest", "image_present": True}}


def test_a_healthy_stack_reports_everything_ok():
    srv = serve(HEALTHY)
    r = run(srv)
    srv.shutdown()
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0] == "contained"                      # bootstrap reads the verdict from line 1
    assert "running" in lines[1] and "attached" in lines[2] and "present" in lines[3]
    assert "NOT" not in r.stdout and "MISSING" not in r.stdout


def test_missing_pieces_are_named_not_hidden():
    bad = {"egress": True, "artifacts": {"attached": False, "error": "EndpointConnectionError"},
           "browser": {"image": "b:latest", "image_present": False}}
    srv = serve(bad)
    r = run(srv)
    srv.shutdown()
    assert r.returncode == 0
    assert "NOT attached (EndpointConnectionError)" in r.stdout and "MISSING" in r.stdout


def test_an_uncontained_attack_is_passed_through_for_bootstrap_to_fail_on():
    srv = serve(HEALTHY, verdict="breached")
    r = run(srv)
    srv.shutdown()
    assert r.stdout.splitlines()[0] == "breached"


def test_a_wrong_token_fails_loudly():
    srv = serve(HEALTHY)
    r = run(srv, token="wrong")
    srv.shutdown()
    assert r.returncode != 0 and "401" in r.stderr
