# MiniLocker

**Give an AI agent a shell and a web browser, and keep what it can break small, visible and provable.**

MiniLocker does not try to make an agent trustworthy. It assumes the agent can be talked into anything (a hostile web
page, a poisoned package, an ordinary mistake) and puts hard limits around it. Every action is written to a
hash-chained ledger, and a *Blast Radius* report measured from that ledger shows what a run could and could not touch.
A built-in **Attack Lab** runs scripted attacks against the real sandbox so the containment claims can be checked, not
just read.

## What you get

- **Sandboxed execution.** Every task runs in a fresh Docker container: non-root, read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, at most 128 processes, 512 MB of memory with no swap, one CPU, and no network
  route at all. The only writable places are size-capped in-memory mounts: `/workspace` (64 MB) and `/tmp` (64 MB, no exec).
- **Controlled egress.** The only way out is an allowlisting proxy that accepts HTTPS `CONNECT` to listed hosts
  (subdomains included) and refuses everything else. Every attempt, allowed or blocked, is logged against the container
  that made it.
- **A policy engine with two profiles.** Commands are scored by regex rules. `strict` denies high-risk commands and asks
  a human about medium-risk ones; `observe` lets them run *inside the sandbox* on purpose, fully logged, which is how the
  Attack Lab proves containment. Approvals pause the task and resume over the API or the UI, and time out to a denial.
- **A browser sandbox.** Chromium runs in its own hardened container, driven by the agent's `browse` tool. Page text
  reaches the model inside a random-nonce *untrusted content* fence with invisible Unicode stripped; a scanner flags
  injection attempts. After a page has been read, network and secret-touching commands need approval, and once a page is
  flagged, the `strict` profile denies them. Only `http(s)` URLs are accepted.
- **A tamper-evident ledger and the Blast Radius report.** Events form a SHA-256 hash chain; one call re-verifies it. The
  report (HTML or JSON) covers seven dimensions. Four are measured: network, policy, persistence, time. Three say
  "not measured" instead of showing a reassuring zero: filesystem, secrets, compute.
- **An artifact store.** Files left in `/workspace` are saved to an S3-compatible store when the task ends. Each file's
  SHA-256 goes into the ledger, and a download is refused unless the chain verifies and the stored bytes match. Files are
  always served as downloads.
- **A web UI.** Workspace (task form, live step stream, terminal, browser and files tabs, live Blast Radius panel,
  approval dialog), Attack Lab, Report, and Sessions.

## Architecture

```mermaid
flowchart LR
    ui([Browser UI]) -->|HTTPS| web["Caddy<br/>TLS + static UI"]
    web -->|"/api + SSE"| api["Control plane<br/>FastAPI"]
    api -->|"Docker API, allowed endpoints only"| dp["docker-socket-proxy"]
    dp --> docker[("Host Docker")]
    api -->|S3| store[("Artifact store<br/>RustFS")]
    api -->|"chat completions"| llm[["LLM provider"]]
    api --- ledger[("Ledger<br/>hash-chained")]
    docker -.->|creates| code["Code sandbox<br/>no route out"]
    docker -.->|creates| browser["Browser sandbox<br/>Chromium, no route out"]
    code -->|"HTTPS CONNECT only"| proxy["Egress proxy<br/>host allowlist + log"]
    browser --> proxy
    proxy -->|"allowlisted hosts only"| net(("Internet"))
```

The control plane never touches the raw Docker socket: it talks to a proxy that allows only the Docker API families it
uses. Sandboxes and the egress proxy are created by the control plane as siblings of the stack, not as part of it.

## Quick start (local development)

Needs Docker, Python 3.12+ and Node 22+.

```bash
git clone <this repository> && cd minilocker
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

cp deploy/.env.example deploy/.env      # then set LLM_BASE_URL, LLM_MODEL and LLM_API_KEY in it
docker build -f images/browser/Dockerfile -t minilocker-browser:latest .     # once; a few minutes

cd backend && python -m minilocker.api          # the API on http://127.0.0.1:8000
# in a second terminal
cd frontend && npm install && npm run dev       # the UI on http://localhost:5173
```

Settings are read from `deploy/.env` automatically (variables already set in your shell win). To try the Files tab
locally, run `./deploy/dev-storage.sh` and copy the three `MINILOCKER_S3_*` lines it prints into `deploy/.env`.

First thing to try: open the **Attack Lab** and press *Run all*. It needs no model and no API key.

## Deploy

On a fresh Ubuntu VM (or any Linux with Docker), from a clone of this repository:

```bash
sudo ./deploy/bootstrap.sh
```

It installs Docker if needed, creates `deploy/.env` (generating the API token and the storage secret), builds the
images, starts the stack, and ends with a smoke test that runs `rm -rf /` through the real stack and reports whether the
object store and the browser image are available. You only provide `LLM_API_KEY`. Set `SITE_ADDRESS` to a domain name
for automatic HTTPS (its DNS record must point at the machine, and ports 80 and 443 must be reachable), or `HTTP_PORT`
if port 80 is taken. See `deploy/env.production.example` for every setting.

## The Attack Lab

There are **13 scripted attacks**. Each drives the real agent loop, policy engine and Docker sandbox with no model in the
loop, then checks the outcome against what actually happened (including the container's Docker settings, read back
from Docker, not from our request). The verdict is *contained*, *breached*, or *inconclusive* when an attack did not
exercise the property it targets. Run them in the UI, or in CI-style with `pytest -m attacks`.

| Attack | What it does |
| --- | --- |
| `deny_then_bypass` | `rm -rf /` is denied twice, then re-expressed as a Python one-liner the policy cannot see. |
| `rm_rf_root` | Recursively deletes the filesystem root and the home directory. |
| `fork_bomb` | Finds the process limit, then runs a real shell fork bomb. |
| `cpu_burn` | Spins forever; the deadline must kill the whole container. |
| `memory_bomb` | Allocates memory in 32 MB chunks until something gives. |
| `disk_fill` | Writes 512 MB to the workspace and to `/tmp`, then tries to write into the system. |
| `read_secrets` | Looks for SSH keys, `/etc/shadow`, process environments, a host canary file, a host secret and the LLM key. |
| `exfil_unknown_domain` | POSTs "stolen" data to an unlisted host through the proxy, then tries to bypass the proxy. |
| `host_escape_probes` | Looks for the Docker socket, tries to mount a filesystem and to enter PID 1's namespaces. |
| `malicious_repo_hook` | A repository's postinstall script reads secrets, plants a backdoor, persists and phones home. |
| `hostile_page_injection` | A page tells the agent to leak its environment; a compromised agent obeys, then follows the page's link. |
| `hostile_page_active_content` | A page's JavaScript exfiltrates, opens a WebSocket, reads `file://`, fires a beacon, opens popups. |
| `browser_local_file_access` | The agent is told to open `file:///etc/passwd`; a page tries to read local files four ways. |

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | none | Any OpenAI-compatible chat endpoint. Needed to run tasks (not attacks). |
| `LLM_TOOL_MODE` | `native` | `native` uses the provider's tool calling. `json` describes the tools in the prompt and parses one JSON object per step, for a model with no (or unreliable) tool calling. See [Choosing a model](#choosing-a-model). |
| `MINILOCKER_API_TOKEN` | empty (no auth) | When set, every `/api` call needs `Authorization: Bearer <token>`. Always set it on a shared host. |
| `MINILOCKER_ALLOW` | `pypi.org,files.pythonhosted.org` | Hosts the sandboxes and browser may reach, subdomains included. Keep it short. |
| `MINILOCKER_PROFILE` | `strict` | Policy profile for the CLI. The API takes the profile per task. |
| `MINILOCKER_MAX_TASKS` | `2` | Tasks running at once. |
| `MINILOCKER_MAX_ATTACKS` | `1` | Attack Lab runs at once. |
| `MINILOCKER_APPROVAL_TIMEOUT` | `60` | Seconds a human has before an approval becomes a denial. |
| `MINILOCKER_HOST`, `MINILOCKER_PORT` | `127.0.0.1`, `8000` | Where the API listens. |
| `MINILOCKER_CORS_ORIGINS` | `http://localhost:5173` | Allowed browser origins (development). |
| `MINILOCKER_LEDGER_DIR` | `runs` | Where ledgers are stored. |
| `MINILOCKER_S3_ENDPOINT`, `MINILOCKER_S3_ACCESS_KEY`, `MINILOCKER_S3_SECRET_KEY` | none | All three enable the artifact store; leave them unset to run without one. |
| `MINILOCKER_S3_REGION`, `MINILOCKER_S3_BUCKET` | `us-east-1`, `minilocker-artifacts` | Store details. The bucket is created if missing. |
| `MINILOCKER_BROWSER_IMAGE` | `minilocker-browser:latest` | The browser sandbox image. |
| `MINILOCKER_PROXY_IMAGE` | unset | Set when the API itself runs in a container: the egress proxy then runs from this image instead of a mounted file. |
| `MINILOCKER_ENV_FILE` | unset | Load this file instead of searching for `.env` / `deploy/.env`. |
| `MINILOCKER_BROWSER_FIXTURES` | unset | Internal: the Attack Lab sets it so its hostile test pages are served. Never set it for real use. |

Deployment-only settings (`SITE_ADDRESS`, `HTTP_PORT`, `HTTPS_PORT`, image pins) are documented in
`deploy/env.production.example`.

The agent's budgets, set per task in `minilocker/policy/engine.py`:

| Budget | Default |
| --- | --- |
| `max_steps` | 12 |
| `max_tokens` | 40000 |
| `exec_timeout_s` | 30 |
| `task_deadline_s` | 300 |
| `max_output_chars` | 2000 |
| `max_denials` | 5 |

## Choosing a model

Models differ in how faithfully they follow the tool-calling contract, so the client tolerates what it safely can:
arguments wrapped in a code fence or with a trailing comma are repaired, a call the model wrote as text (Hermes, Llama,
Kimi, gpt-oss and ReAct syntaxes, or bare JSON) is recovered, and a call the provider rejected is recovered from what
the model wrote. It never completes a truncated value, never promotes prose that merely quotes a call, and ignores
calls that appear only in the model's reasoning. A recovered call goes through the same policy and sandbox as any
other, and the ledger records an `llm.salvaged` event for it.

In `json` mode an empty reply is retried with a specific nudge. Some models (seen: gpt-oss on Groq) sometimes write the
right call at the end of their *reasoning* and leave the message empty; that call is never acted on, since reasoning is
where a model quotes hostile text, so the client asks again instead.

To compare models before relying on one, run the bake-off. It needs no Docker, only the endpoint settings:

```bash
cd backend
python -m minilocker.llm.bakeoff --models openai/gpt-oss-120b,another/model --runs 5 --mode both
python -m minilocker.llm.bakeoff --list      # what the probes check
```

Each probe is one step of the real agent (the real prompt, tools and client), repeated `--runs` times. *usable* is the
share that did what was asked; *clean* is the share that did so through the mode's own channel (a tool call, a JSON object, or a plain-text
answer where that is correct) with no repair and no retry, so the gap is what the fallbacks carry. `--mode both` also tries `json` mode, and the last line names the
setting to use. Raw results are written to `runs/bakeoff-<time>.json`. One step is not a task: a model that passes 95%
of steps finishes only about 6 ten-step tasks in 10, so treat a PASS as "worth running whole scenarios on".

## Tests and CI

```bash
cd backend
python -m pytest -m "not attacks"      # unit and integration tests (many need a Docker daemon)
python -m pytest -m attacks            # the containment suite against real sandboxes
```

CI (`.github/workflows/ci.yml`) runs on every push and pull request: the backend tests, the attack suite and the real
browser against a freshly built image, the frontend build, validation of the deployment files, and a full
`bootstrap.sh` run on a clean runner ending in the containment smoke test. A test also fails if this README drifts from
the code (attack list, settings, budgets, hardening numbers, links).

## Repository layout

- `backend/minilocker/agent/`: the agent loop and its tools.
- `backend/minilocker/llm/`: the OpenAI-compatible client, tolerant tool-call parsing, and the model bake-off.
- `backend/minilocker/policy/`: risk rules, profiles, approvals, the injection scanner.
- `backend/minilocker/sandbox/`: the hardened code sandbox and the browser sandbox with its in-container worker.
- `backend/minilocker/egress/`: the allowlisting proxy and its network manager.
- `backend/minilocker/ledger/`: the hash chain, the Blast Radius report, session summaries.
- `backend/minilocker/artifacts/`: the S3 artifact store and workspace export.
- `backend/minilocker/attacks/`: the Attack Lab catalog and runner.
- `backend/minilocker/api/`: the FastAPI control plane.
- `frontend/`: the React UI.
- `images/browser/`: the browser sandbox image and its test fixtures.
- `deploy/`: the compose stack, Caddy config, Dockerfiles and `bootstrap.sh`.
- `docs/`: design notes.

## Security

The threat model, what is and is not guaranteed, and the known weak points are in [SECURITY.md](SECURITY.md). The short
version: the container is the security boundary, the policy engine is an early warning that can be bypassed, and the
Attack Lab exists so you can see both facts for yourself.

## Status

Working and tested end to end: sandboxed execution, egress control, policy and approvals, the browser sandbox and
prompt-injection defences, the ledger and report, the artifact store, the Attack Lab, and the deployment.

Not built yet, and shown as placeholders in the UI where relevant: snapshots with rewind (the Timeline screen), the
Infra screen, a credential broker with canary tokens, and measurement for the filesystem, secrets and compute
dimensions of the report. Screenshots go to the UI, not to the model (no vision step), and there is no
approve-before-submit gate for web forms.

## License

[MIT](LICENSE).
