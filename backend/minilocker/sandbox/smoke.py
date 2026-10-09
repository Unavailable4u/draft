"""Smoke test for the REAL browser sandbox. Needs Docker and the minilocker-browser image.

    cd backend && python -m minilocker.sandbox.smoke

Starts the hardened container, drives the real worker + Chromium against the fixture pages baked
into the image, and prints what it saw. Exit code 0 = every check passed. Run it before the
Attack Lab: if this fails, the browser attacks will report 'inconclusive'.
"""
import base64
import json
import sys

from minilocker.sandbox.browser import BUILD_HINT, BrowserSandbox, BrowserUnavailable, image_present

BASE = "http://127.0.0.1:8099"
results = []


def check(label, cond, detail=""):
    results.append(cond)
    print(f"  [{'ok' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))


def main():
    if not image_present():
        sys.exit(f"image not built. Run from the repo root:\n  {BUILD_HINT}")
    print("starting browser sandbox (no egress: loopback fixtures only) ...")
    try:
        b = BrowserSandbox(egress=None, fixtures=True)
    except BrowserUnavailable as e:
        sys.exit(f"could not start: {e}")
    try:
        h = b.hardening()
        print(f"container {b.name}: user={h.get('user')} ro={h.get('read_only_rootfs')} caps_drop={h.get('cap_drop')} "
              f"pids={h.get('pids_limit')} net={h.get('network_mode')}")
        r = b.call("goto", {"url": f"{BASE}/clean.html"})
        check("loads a page", r.get("ok") and r.get("title") == "Clean fixture page", r.get("error", ""))
        check("returns visible text", "emperor penguin" in r.get("text", ""))
        check("lists interactive elements", len(r.get("elements") or []) >= 2)
        shot = base64.b64decode(r.get("screenshot_b64") or "")
        check("returns a JPEG screenshot", shot[:3] == b"\xff\xd8\xff", f"{len(shot)} bytes")
        link = next((e for e in r.get("elements", []) if e["tag"] == "a"), None)
        r2 = b.call("click", {"ref": link["ref"]}) if link else {}
        check("clicks a link by ref", r2.get("ok") and "Second clean page" in r2.get("title", ""), r2.get("error", ""))
        r3 = b.call("goto", {"url": "file:///etc/passwd"})
        check("refuses file:// itself", not r3.get("ok") and "not allowed" in r3.get("error", ""))
        r4 = b.call("goto", {"url": f"{BASE}/local_files.html", "wait_ms": 2500})
        txt = r4.get("text", "")
        probe = json.loads(txt.split("BROWSER_RESULT ", 1)[1].split("\n")[0]) if "BROWSER_RESULT" in txt else {}
        check("page cannot read local files", bool(probe) and all(str(v).startswith("BLOCKED") for v in probe.values()), str(probe))
        r5 = b.call("goto", {"url": f"{BASE}/active_content.html", "wait_ms": 4500})
        r6 = b.call("extract", {})
        t = r6.get("text", "")
        check("hostile page's popups/dialogs are handled", (r5.get("popups_blocked", 0) + r6.get("popups_blocked", 0)) >= 1
              or "popups_opened\": 0" in t, f"popups={r5.get('popups_blocked')}+{r6.get('popups_blocked')} dialogs={r5.get('dialogs_dismissed')}")
    finally:
        b.destroy()
    print("PASS" if all(results) else "FAIL")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
