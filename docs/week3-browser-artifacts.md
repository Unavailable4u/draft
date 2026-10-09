# Week 3: browser sandbox and artifact store

## Run it (WSL2 / Ubuntu)

```bash
# once: dependencies and the browser image (~1.5 GB, a few minutes)
cd backend && source .venv/bin/activate && pip install -r requirements.txt && cd ..
docker build -f images/browser/Dockerfile -t minilocker-browser:latest .   # from the REPO ROOT

# prove the real browser works BEFORE trusting the Attack Lab with it
cd backend && python -m minilocker.sandbox.smoke && cd ..

# object store for artifacts, then the env it prints
./deploy/dev-storage.sh            # prints three `export MINILOCKER_S3_*` lines: run them

# which sites the browser may reach (suffix match; https only)
export MINILOCKER_ALLOW=pypi.org,files.pythonhosted.org,wikipedia.org

cd backend && python -m minilocker.api            # then: cd ../frontend && npm run dev
```

`GET /api/status` (and the empty-state text in the Browser and Files tabs) says what is attached and why not.
Real-Docker tests: `pytest tests/test_browser_integration.py` (skipped without a daemon / the image).

## What was added

| Piece | Where |
|---|---|
| Browser sandbox: Chromium + Playwright in its own hardened container, driven over a unix socket inside it via `docker exec` | `sandbox/browser.py`, `sandbox/browser_worker.py`, `images/browser/` |
| `browse` tool (goto, back, click, type, extract, screenshot) | `agent/browse_tool.py`, `agent/loop.py` |
| Untrusted-content handling: sanitize, scan, fence, taint-aware policy | `policy/injection.py`, `policy/engine.py` |
| Artifact store (S3 API via boto3), workspace export, safe serving, ledger-derived index | `artifacts/` |
| Attack Lab: 3 browser attacks | `attacks/browser_attacks.py` |
| Report dimensions `browser`, `artifacts`; network split by source container | `ledger/report.py` |
| Browser and Files tabs | `frontend/src/Browser.tsx`, `Files.tsx` |

## Decisions worth knowing about

**MinIO is not used.** Its community Docker images are no longer published, so the dev script runs RustFS instead.
The store only speaks S3, so Vultr Object Storage (or Garage, SeaweedFS, ...) is a change of `MINILOCKER_S3_*` variables and nothing else.

**Chromium's own sandbox is OFF (`--no-sandbox`).** It needs user namespaces or setuid helpers, which this container
deliberately lacks (all capabilities dropped, no-new-privileges). The *container* is therefore the only boundary against a
renderer exploit. Mitigations that exist: non-root, read-only rootfs, no capabilities, no host mounts, an internal network
whose only neighbour is the egress proxy, memory/PID limits, no secrets in the container, destroyed after every task.
Mitigations that do not: seccomp tighter than Docker's default, gVisor/Kata. Say so in the threat model; it is the honest
residual risk of this component and the first thing to harden if time allows.

**Hostile test pages are baked into the image** and served on loopback inside the browser container, so the Attack Lab is
offline and deterministic. The same pages are reachable by the agent (harmless: static, in its own container).

**Where the model's text comes from.** Page text, titles, link labels and URLs all reach the model inside
`<<<BEGIN UNTRUSTED nonce>>>` markers (random nonce, so a page cannot forge the end), after invisible-Unicode stripping.
The injection scanner is a heuristic and is *not* the boundary: what contains a successful injection is the egress allowlist,
the sandbox and the absence of secrets, which the Attack Lab measures. The scanner exists to make the common cases visible
and to make the policy engine ask first.

**Policy after browsing.** Once any page has been read, shell commands that touch the network or secrets need approval;
once a page was *flagged*, strict denies them (observe still runs them, on purpose, so the sandbox is what gets tested).
Navigation after a flagged page also needs approval. Ordinary work (`python3 x.py`, `pip install pandas`) is unaffected.
A payload hidden in a script file bypasses the command-text rules; that is exactly what the sandbox is for.

**Artifacts are verifiable.** Every stored object's SHA-256 is written to the hash-chained ledger. A download is refused (409)
unless the ledger chain verifies *and* the stored bytes match the recorded hash. File content is attacker-controlled, so it is
only ever served as `attachment` (images confirmed by magic bytes are the one inline exception) with `nosniff` and a locked-down CSP,
and the UI previews text inside `<pre>`, never as markup. The workspace export script runs inside the hostile sandbox, so its output
is parsed as hostile: strict framing, size/count caps, plain relative names only, nothing written to the host filesystem.

## Known limits

- Saved on task end only. A sandbox killed by the deadline loses its workspace (the tmpfs dies with it).
- `pkgs/`, `node_modules/`, `.git/` and caches are not saved. Files over 5 MB, more than 60 files, or over 25 MB total are skipped and logged.
- Browsing is https-only and allowlist-only. Pages that pull third-party scripts/images from non-allowlisted hosts load partially,
  and each blocked subresource is a (correct, noisy) `egress.blocked` event, tagged `source: browser`.
- Screenshots go to the Browser tab, not to the model; there is no vision step yet.
- No approve-before-submit gate for forms yet.
- The MinIO/RustFS container is on `127.0.0.1` only and not on the sandbox network. Credentials live only in the control plane's
  environment; the Attack Lab's leak check now also looks for the S3 secret in the ledger.
