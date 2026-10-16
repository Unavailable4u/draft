"""Post-start check, run INSIDE the api container by deploy/bootstrap.sh (stdin: `python - < this file`).

Line 1 of the output is the verdict of the rm -rf / attack, run through the real stack with no model.
The lines after it report the other things a deployment can get wrong without any task failing loudly.
"""
import json
import os
import urllib.request

BASE = os.environ.get("SMOKE_BASE", "http://127.0.0.1:8000")
HEADERS = {"Authorization": "Bearer " + os.environ["MINILOCKER_API_TOKEN"]}


def call(path, method="GET"):
    req = urllib.request.Request(BASE + path, method=method, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)


print(call("/api/attacks/rm_rf_root/run", "POST").get("verdict"))
status = call("/api/status")
art = status.get("artifacts") or {}
print("egress proxy:    " + ("running" if status.get("egress") else "NOT running"))
print("artifact store:  " + ("attached" if art.get("attached") else f"NOT attached ({art.get('error') or 'not configured'})"))
print("browser image:   " + ("present" if (status.get("browser") or {}).get("image_present") else "MISSING"))
