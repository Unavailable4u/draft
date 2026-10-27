# Security

MiniLocker exists to contain a misbehaving AI agent. This document says what that means, what is guaranteed, and where
the weak points are. Where a claim can be checked, it names the attack that checks it: run the **Attack Lab** in the UI
or `pytest -m attacks` in `backend/`.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"). If it
is not enabled, open an issue that says you have a security report and asks for a private channel, without the details.

## Threat model

**What we protect.** The host machine, the control plane and its secrets (the LLM API key, the storage credentials, the
API token), other tasks, and the integrity of the record of what an agent did.

**Who we assume is hostile.** The agent itself, once it has been manipulated or has simply made a mistake. Concretely:

- A web page that tries to hijack the agent (prompt injection), or attacks the browser.
- A package or repository the agent installs or runs.
- Commands the agent decides to run: destructive, resource-hungry, or probing for a way out.

**Who we do not defend against.** A malicious operator or user with the API token (they can run arbitrary code in a
sandbox by design); an attacker with a kernel or container-runtime zero-day; an attacker who already controls the host.

## Layers

| Layer | Mechanism | Checked by |
| --- | --- | --- |
| Sandbox | Fresh container per task: non-root (65534), read-only root, all capabilities dropped, `no-new-privileges`, 128 processes, 512 MB memory with no swap, one CPU, size-capped in-memory `/workspace` and `/tmp`. No Docker socket inside. | `rm_rf_root`, `fork_bomb`, `memory_bomb`, `disk_fill`, `host_escape_probes` |
| Deadline | A command that exceeds its time limit has its whole container killed and replaced, not just the process. A sandbox that can no longer start processes is replaced too. | `cpu_burn`, `fork_bomb` |
| Network | Sandboxes sit on an internal network with no route out. The only exit is a proxy that accepts HTTPS `CONNECT` to allowlisted hosts and refuses everything else; every attempt is logged against the container that made it. | `exfil_unknown_domain`, `hostile_page_active_content` |
| Secrets | The LLM key and storage credentials live in the control plane's environment only; sandboxes start with a clean one. As each sandbox is destroyed, an audit looks for the value of every real secret in its container configuration, process environments and files, and the report says whether any was found. The checks also look for them in the ledger. | `read_secrets`, `malicious_repo_hook` |
| Decoys | Each code sandbox holds random fake credentials (SSH key, AWS keys, GitHub token, `.env`). Reading one, printing one, putting one in a command or file, or copying one into the artifacts is recorded; in `strict`, using one in a command stops the task. | `read_secrets`, `malicious_repo_hook`, `credential_theft_exfil` |
| Credential broker | For services named in `MINILOCKER_BROKER`, the egress proxy adds the credential to a request it makes itself. The sandbox holds a placeholder only, cannot supply its own `Authorization` header, and an upstream that echoes the token gets it replaced. | unit tests (`test_broker.py`), not an attack |
| Recovery | Snapshots of the workspace are taken after every step that changes it; a rewind builds a fresh sandbox, restores the files and re-hashes them against the snapshot's manifest. The ledger keeps what was undone. | `rewind_after_rm_rf` |
| Policy | Regex risk rules. `strict` denies high-risk commands and asks a human about medium-risk ones. Approvals have a timeout and default to denial. A run halts after 5 denials, 12 steps, 40,000 tokens or 300 seconds. | `deny_then_bypass` |
| Web content | Page text is fenced as untrusted data with a random nonce, invisible Unicode is stripped, and a scanner flags injection attempts. After a page is read, network and secret-touching commands need approval; after a flagged page, `strict` denies them. | `hostile_page_injection` |
| Browser | Chromium in its own container (non-root, read-only, capabilities dropped, no route out). The worker accepts `http(s)` only. | `browser_local_file_access`, `hostile_page_active_content` |
| Model output | A tool call is only ever read from text that consists of a call: prose that quotes one (a summary of a hostile page) is not a call, calls inside reasoning are ignored, a truncated value is never completed, one bad call in a reply discards the whole reply, and unknown tools are dropped. A recovered call goes through the same policy and sandbox as any other and is recorded as `llm.salvaged`. | unit tests (`test_toolcalls.py`), not an attack |
| Record | Every event is chained by SHA-256 over canonical JSON. The Blast Radius report is computed from the ledger and shows whether the chain verifies; artifact downloads are refused if it does not. | every attack re-verifies the chain |

## Trade-offs and weak points

These are deliberate or known. Read them before relying on this for anything real.

1. **The container is the only boundary.** The policy engine is a set of regexes. It is an early warning and a source of
   good approval prompts, not a barrier: `deny_then_bypass` shows a denied command re-expressed in a form the rules cannot
   see, and it running anyway, harmlessly, because of the sandbox. If a regex is the only thing between an agent and
   damage, that is a bug.
2. **Chromium's own sandbox is off.** It needs privileges the browser container deliberately does not have. A renderer
   exploit therefore lands in a container with no capabilities, a read-only root, no route out and no Docker socket, so
   escaping needs a further kernel or runtime vulnerability. Containers share the host kernel; a stronger runtime such as
   gVisor or Kata would narrow this and is the first hardening to add. The browser container has larger limits than the
   code sandbox (512 processes, 1 GB of memory) because Chromium needs them.
3. **The control plane has real power over Docker.** In the deployed stack it reaches Docker through a socket proxy that
   allows only the API families it uses and denies the rest (builds, volumes, swarm, secrets, system, and so on). That
   proxy filters by endpoint, not by request body, so a compromised control plane could still ask Docker for a privileged
   container. Treat the API as the most sensitive component: keep `MINILOCKER_API_TOKEN` set, serve over HTTPS, and keep it
   small. The code sandboxes themselves never see the socket.
4. **Every allowlisted host is a possible exfiltration channel.** A hijacked agent can send data to any host you allow,
   for example through the query string of an image URL. Keep `MINILOCKER_ALLOW` short, add hosts per demo, and note that
   allowing a site often means allowing its CDN too.
5. **The ledger is tamper-evident, not tamper-proof.** It detects edits, reordering and deletion. It is not signed or
   anchored anywhere else, so someone who can write the ledger files can rewrite a whole chain consistently. The head hash
   is shown in every report; recording it somewhere the attacker cannot reach (a signature, a transparency log) closes
   this and is not built yet.
6. **Data leaves for the model provider.** Task text, tool output and fenced page text are sent to whichever LLM endpoint
   is configured. Do not put secrets into tasks.
7. **Authentication is one shared bearer token.** There are no user accounts, roles or rate limits beyond the limits on
   concurrent tasks and attack runs. Served over plain HTTP (the default when `SITE_ADDRESS` is a port) the token travels
   in the clear; use a domain name so Caddy provides HTTPS.
8. **The measurements are polled and heuristic, and say so.** Compute is the highest value a poller saw on the container's
   cgroup counters, so a spike shorter than the polling interval can be missed. The secrets audit looks only for the values of
   variables in the control plane's environment whose names look like a key, token, secret or password (plus the ones this
   project names), so a secret kept under an innocent name is not on its list, and one that was encoded, split or transformed
   inside the sandbox is not found. A decoy *read* is inferred from the file's access time, which a process can reset; a decoy that is only an
   environment variable cannot be tracked as read at all. A measurement that could not be taken is listed as `incomplete`
   in the report, and a run with no audit at all says "not measured".
9. **The broker is a gateway, not a way to make a powerful token safe.** A hijacked agent cannot read the token, but it can
   ask the broker to do anything the token allows, to the one host configured. Give a service the narrowest token you can.
   Echoed tokens are redacted only when they appear byte for byte. It has been tested against a recorded upstream, not a
   live API.
10. **A rewind restores files, not the world.** It undoes what the agent did to the workspace; it cannot take back anything
   that already left (a request an allowlisted host received, an approved action). It replaces the sandbox, so processes
   and `/tmp` start clean. Snapshots live in the control plane's memory and are lost when it restarts or the task ends.
11. **The Attack Lab proves what it covers.** Fifteen attacks passing is evidence about those fifteen. Each check also
   reports *inconclusive* when an attack did not exercise the property it targets, so a pass cannot hide behind an attack
   that never ran.

## Operating it safely

- Set `MINILOCKER_API_TOKEN` and use HTTPS for anything reachable from a network.
- Keep `deploy/.env` out of version control (it is git-ignored and excluded from image builds) and readable only by you;
  `deploy/bootstrap.sh` creates it with mode 600 and refuses a file where two settings have been glued together.
- Prefer the `strict` profile. `observe` runs risky commands on purpose and exists to demonstrate containment.
- Re-run `pytest -m attacks` after changing the sandbox, the egress proxy or the policy rules.
