# Submission package

Everything the lablab submission form asks for, written once, so the form, the README, the slides and the video all say the
same thing. Items in `[[double brackets]]` are filled from measured runs on the Vultr VM; nothing in brackets may be
submitted as written.

## Basic information

**Project title:** MiniLocker (working name: Airlock)

**Tagline:** Give an AI agent real work on untrusted inputs, and see exactly what it could not touch.

**Short description (under 200 characters):**
A sandboxed agent runtime on Vultr that measures its own blast radius: decoy credentials, a tamper-evident ledger, one-click rewind after `rm -rf`, and a 15-attack suite you can run yourself.

**Long description:**

AI agents with a shell and a browser are useful and dangerous in the same breath: one hostile web page or poisoned package
and they can leak keys or wipe a disk. Most projects answer with a container and a promise. MiniLocker answers with
evidence.

Every task runs in a fresh hardened Docker container on a Vultr VM: non-root, read-only root filesystem, all capabilities
dropped, 128 processes, 512 MB of memory, no network route at all. The only way out is an allowlisting egress proxy. Every
action lands in a SHA-256 hash-chained ledger, and from that ledger the product builds a **Blast Radius report** across nine
dimensions (network, policy, persistence, time, browser, artifacts, filesystem, secrets, compute), each either measured or
explicitly marked "not measured".

Three things make it more than a container:

- **Decoy credentials.** Each sandbox is seeded with fake SSH, AWS, GitHub and database credentials. If the agent (or a
  poisoned dependency) reads one, prints one, copies one or tries to use one, the ledger records it, and in strict mode
  using one stops the task. At teardown, an audit checks that no real secret was ever in the sandbox.
- **Snapshots and rewind.** The workspace is snapshotted after every step. Rewind builds a fresh sandbox, restores the files
  and re-hashes them against the snapshot: the `rm -rf` that destroyed the workspace is undone and the record of it is kept.
- **A credential broker.** To call an API, the agent holds only a placeholder; the egress proxy adds the real token to a
  request it makes itself.

It also does real work: a scenario harness runs whole tasks (fix a broken repository that ships a hostile dependency;
answer research questions from web pages with a screenshot receipt for each claim), judges them with a check the model never
sees, and reports a pass rate with a confidence interval rather than an anecdote. An Attack Lab runs 15 scripted attacks
(fork bomb, memory bomb, disk fill, escape probes, exfiltration, hostile repository hook, prompt injection, credential
theft, wipe-then-rewind, and more) against the real sandbox, in the UI and in CI.

**Technology tags:** Vultr, Vultr Serverless Inference, Vultr Object Storage, Docker, FastAPI, Python, React, TypeScript,
Playwright, Chromium, AI agents, sandboxing, security, observability

**Category tags:** AI agent safety, developer tools, security, infrastructure

## How we use Vultr

| Vultr product | What it does here | Where to see it |
| --- | --- | --- |
| **Vultr VM** (Ubuntu 24.04) | Runs the whole control loop: the FastAPI control plane, the Docker daemon the sandboxes are created in, the egress proxy, the ledger and the web UI behind Caddy with automatic HTTPS. The agent loop, the policy engine and every sandbox's lifecycle are orchestrated on this machine, not in a hosted function. | Infra screen: *Vultr VM*, region, plan, live sandbox list |
| **Vultr Serverless Inference** | Every model call the agent makes goes to `https://api.vultrinference.com/v1` through one OpenAI-compatible client (`LLM_BASE_URL`, `LLM_MODEL`). The bake-off harness picked the model from measured tool-calling results on Vultr's catalog `[[model name, and the bake-off numbers]]`. | Infra screen: *Vultr Serverless Inference*, model; `runs/bakeoff-*.json` |
| **Vultr Object Storage** (S3) | Files an agent leaves in its workspace are saved here when the task ends; each file's SHA-256 is in the ledger and a download is refused unless the stored bytes match. | Infra screen: *Vultr Object Storage*; Workspace → Files |
| **Instance metadata** | The Infra screen reads the VM's metadata service to show the region, plan and instance id it is really running on. | Infra screen |

Sandboxes are containers on the VM, never inside the application process. A stronger per-task boundary (an ephemeral Vultr
instance per high-risk task, or gVisor) is the next step and is **not built**; we say so rather than imply it.

## Business value

**Who needs this.** Teams that want to let an agent loose on code, documents and the web, and who must answer a security or
compliance reviewer's first question: *what could it touch, and how do you know?*

**What they get that a container alone does not give them:**

- A per-run **Blast Radius report** they can attach to a change ticket or an audit: what was blocked, what was touched, how
  much compute, whether any real secret was present, whether the record is intact (`Verify ledger`).
- **Early-warning tripwires** (decoy credentials) that turn a silent compromise into a ledger event.
- **Recovery**: rewind is the difference between "the agent made a mess, start over" and "go back one step".
- **A way to compare models on your own work**: pass rates with confidence intervals on whole tasks, not demos.

**Competitive landscape (one slide).** Typical agent sandboxes give you isolation and ask you to trust it; hosted code
interpreters give you convenience and take the boundary out of your hands; policy layers and LLM judges give you a
warning that can be talked around. MiniLocker keeps the boundary in a small hardened container you control, treats the
policy engine as UX, and adds the thing the others lack: measurement you can check, and an attack suite anyone can run.

## Measured claims

Fill from real runs on the final code (freeze first). Quote only what appears here.

| Claim | How it is measured | Value |
| --- | --- | --- |
| Agent finishes the repair task | `python -m minilocker.scenarios --scenario fix_repo_v2 --runs 10`, on the Vultr model | `[[N/10]]`, 95% interval `[[lo–hi]]`; bugs most missed: `[[bug]]` |
| Agent finishes the research task | `... --scenario research --runs 10` | `[[N/10]]`, 95% interval `[[lo–hi]]` |
| Containment | `pytest -m attacks`, and the Attack Lab on the VM | `[[15/15]]` contained; CI run `[[link]]` |
| Poisoned dependency never escaped | `hook_escaped` fact across the `fix_repo_v2` runs | `[[0/10]]` runs escaped |
| Real secrets in sandboxes | `secrets.real_secrets_in_sandbox` across all runs' reports | `[[0]]` of `[[N]]` runs |
| Rewind restores the workspace | `rewind_after_rm_rf`, SHA-256 compared | `[[pass]]` |

## Honest limitations (also on a slide)

- The container is the boundary and it shares the host kernel. A kernel or runtime vulnerability is out of scope; gVisor or
  Kata would narrow it.
- The policy engine is regexes: an early warning, bypassable (the Attack Lab shows it being bypassed and the sandbox holding).
- Decoy reads are inferred from file access times and can be hidden by a process that resets them; environment-variable
  decoys cannot be tracked as "read".
- Compute numbers are polled peaks; a spike shorter than the polling interval can be missed.
- The secrets audit looks for the values of secrets named like keys, tokens, secrets or passwords in the control plane's
  environment.
- The broker has been tested against a recorded upstream, not a live API, and cannot make a powerful token safe.
- Any host on the egress allowlist is a possible exfiltration path.
- The ledger is tamper-evident, not tamper-proof: it is not signed or anchored elsewhere.

## Rubric self-check (score honestly before submitting)

| Criterion | What the judges see | Our bar | Score `[[1–5]]` and one improvement made |
| --- | --- | --- | --- |
| Application of Technology | Demo link, video and repo all work; the technology works | Live URL on the Vultr VM; attacks green in CI; video is real execution | `[[ ]]` |
| Presentation | Problem, solution and value in under three minutes, with competitive analysis | Video ≤ 3:00 that names the "container and a claim" failure mode; one competitive slide | `[[ ]]` |
| Business Value | A real need, a credible buyer | The Blast Radius report framed as the audit artifact; recovery; model comparison | `[[ ]]` |
| Originality | Something most entries will not have | Measured (not asserted) containment, decoys, rewind, a reproducible attack suite | `[[ ]]` |

## Submission checklist

**Repository and docs**
- [ ] Public GitHub repository; MIT `LICENSE` visible; README has setup, architecture, Attack Lab, limitations.
- [ ] `docs/DEMO_SCRIPT.md` rehearsed; video recorded from it.
- [ ] CI green on the exact commit submitted; badge in the README. *(Add the badge once the first run exists.)*

**Deployment (from Nov 3)**
- [ ] Vultr VM created; domain and HTTPS working.
- [ ] `deploy/dry_run.sh` passed on a clean machine twice (record date and commit).
- [ ] Serverless Inference key set; `GET https://api.vultrinference.com/v1/models` checked for the live model list and a vision-capable model name.
- [ ] Object Storage keys set; artifact download verified through the UI.
- [ ] Bake-off run on the Vultr models (`python -m minilocker.llm.bakeoff --models ... --mode both`); winner named in the README.
- [ ] Both scenarios (10 runs each) and the Attack Lab run on the VM; "Measured claims" table filled.
- [ ] Spending alert set; the demo URL stays up through judging; `MINILOCKER_API_TOKEN` set, and a read-only way for judges to look (a recorded session or a demo token shared in the submission notes).

**Submission form**
- [ ] Title, short and long description, tags (above).
- [ ] Cover image: PNG or JPG, 16:9.
- [ ] Video: MP4, ≤ 3 minutes, one containment moment, plays while logged out.
- [ ] Slide deck: PDF.
- [ ] Repository URL, application URL (the Vultr domain), demo platform = Vultr.
- [ ] Code frozen at least six hours before the deadline (22:00 UTC, Nov 8); submitted early.
