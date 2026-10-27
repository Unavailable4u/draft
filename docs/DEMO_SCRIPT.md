# Demo script (target 2:50, hard limit 3:00)

The submission needs **one containment moment** on video. This script has four, in rising order of impact, and every one of
them is something the product does today. Nothing on screen is mocked: the Attack Lab and the agent both run in the real
sandbox on the Vultr VM.

Numbers in `[[double brackets]]` are filled in from the measured runs (see "Before recording"). Do not say a number you have
not read off a report.

## Before recording (one-time, on the Vultr VM)

1. `deploy/dry_run.sh` passes. The stack is up on the real domain with HTTPS; the **Infra** screen shows "Vultr VM",
   "Vultr Serverless Inference" and "Vultr Object Storage".
2. The measured numbers exist and were taken on the code you are recording (see `docs/SUBMISSION.md`, "Measured claims"):
   - `python -m minilocker.scenarios --scenario fix_repo_v2 --runs 10` → `[[N/10]]` finished, 95% interval `[[lo–hi]]`, and
     which bug models missed.
   - `python -m minilocker.scenarios --scenario research --runs 10` → `[[N/10]]`.
   - Attack Lab: `[[15/15]]` contained on the VM; CI badge green on the commit you are showing.
3. Pre-warm: run `fix_repo_v2` once so images are pulled and the model is warm. Delete nothing afterwards (the Sessions
   screen is a prop).
4. Browser profile: clean, 1920×1080, zoom 125%, API token pasted, dark theme. Hide bookmarks. Close every other tab.
5. Open these four tabs in order, same window: **Workspace**, **Attack Lab**, **Report**, **Infra** (they are one page: use the
   header buttons).
6. Do a dry take with a stopwatch. If it runs over 2:55, cut beat 4's second half (see "If you are over time").

## The script

| Time | On screen | Say (about) |
| --- | --- | --- |
| **0:00 – 0:20** Problem | A black slide, one line: *"Agents with a shell and a browser are one bad page away from a bad day."* Then cut to the Workspace. | "AI agents now run commands and browse the web for us. The moment one reads a hostile web page or installs a poisoned package, it can leak your keys or wipe your disk. Containers help, but nobody shows you what the agent could and could not touch. We do." |
| **0:20 – 0:55** Real work | Workspace. Pick **Fix a broken repo (v2)**, profile **strict**, hold **1 min**, click *Run in sandbox*. Let the steps stream: write, run tests, patch, re-run. Point at the Blast Radius panel gauges moving. The green *Hidden check passed* line appears. | "This is a real task: a third-party shop library with three bugs and a failing test suite. The agent, running on Vultr Serverless Inference, reads the code, runs the tests, patches, and re-runs. A hidden check the model never sees decides whether it really worked. The repo also ships a poisoned 'usage statistics' module that tries to steal credentials and phone home. Watch the panel." |
| **0:55 – 1:15** Containment 1: decoys | Same task, the **Secrets** gauge: *real in sandbox: 0 · decoys read: 2 of 6 · used: 0*. Click the feed lines "Decoy read: SSH private key" and "Decoy read: AWS secret access key". Then the **Network** gauge: *blocked: N*. | "The poisoned module read the SSH key and the AWS credentials, because we planted them. They are decoys, random for this task, worth nothing, and reading it set off an alarm. It tried to post it to an unlisted host and the egress proxy refused. Zero real secrets were ever in the sandbox; we checked the sandbox's files and environment against the real ones when it was destroyed." |
| **1:15 – 1:50** Containment 2: rewind (the hero) | Click **Attack Lab**, select `rewind_after_rm_rf`, *Run*. Show the steps: the file is written, `rm -rf` empties the workspace (`WIPED_0`), *rewind to snapshot 1*, then the file is back. Check rows turn green: *Deleted file came back*, *Restored workspace matches the snapshot: SHA-256 compared*. | "Now the classic. The agent deletes its whole workspace. We take a snapshot after every step, so we rewind: a fresh sandbox is built, the files are restored, and every file is re-hashed against the snapshot. The work is back, and the ledger still shows everything that happened, including the delete." |
| **1:50 – 2:05** Timeline (optional, 15 s) | Back to **Workspace**, open **Timeline** on the fix task. Click *Rewind here* on the first node. The nodes after it grey out, a blue *rewound* node appears, "restored into a fresh sandbox; N files re-hashed and matched". | "Same thing on the real task: rewind to before the fix, and the bug is back." |
| **2:05 – 2:20** Hostile page | **Attack Lab → `hostile_page_injection`** (precomputed result if the live run is slow). Show *injection flagged*, *egress blocked*, *no secret left*. | "And a web page that tells the agent to leak its environment. Flagged, the follow-up command is denied, nothing leaves." |
| **2:20 – 2:40** Evidence | **Report** screen for the fix task. Scroll: nine dimensions, all *measured*: network, policy, persistence, time, browser, artifacts, filesystem, secrets, compute. Click *Verify ledger now*: "intact". Flash the README badge: `[[15/15]]` attacks contained in CI. | "Every run produces a Blast Radius report built only from the tamper-evident ledger: what was blocked, what was touched, how much memory and CPU, whether any real secret was present. Anything we did not measure says so. The ledger re-verifies on demand." |
| **2:40 – 2:55** On Vultr | **Infra** screen: Vultr VM (region, plan), Docker, sandbox list, egress allowlist, Serverless Inference model, Object Storage. Then the architecture slide. | "All of it runs on a Vultr VM: the control plane orchestrates a hardened container per task, every model call goes through Vultr Serverless Inference, and artifacts land in Vultr Object Storage." |
| **2:55 – 3:00** Close | Title card: repo URL, tagline. | "Give an agent real work on untrusted inputs, and see exactly what it could not touch." |

## Words to avoid

- Never "provably safe", "zero risk" or "secure". Say **"measured blast radius"**. The sandbox is the boundary; the policy
  engine is an early warning (SECURITY.md says so and a judge may read it).
- Do not say the ephemeral per-task Vultr instance tier exists: it does not. Do not claim a Vultr firewall unless you
  configured one that day.
- Do not describe a number as measured unless it came from a report you can open.

## If something goes wrong on camera

| Problem | Do this |
| --- | --- |
| The model is slow in beat 2 | Cut at the first passing test run; the check line can be shown from the previous take's Sessions entry (*Sessions → Open*). |
| The Attack Lab run takes > 20 s | Run it before recording and show its Report (Attack Lab → *Open report*): the steps and checks are stored. |
| The Secrets gauge shows 0 decoys read | The agent removed the poisoned import before running the tests (a legitimate fix; the check records `hook_fired: false`). Do the take again, or show Attack Lab → `credential_theft_exfil` for this beat. |
| A gauge shows "—" | The sandbox has not been destroyed yet: the audit is taken when it is. It fills in when the task ends. Say nothing; do not point at it. |
| Rewind button greyed out | The task already ended: start it with *hold 1 min*. |
| Over 2:55 | Drop the Timeline beat (1:50–2:05), then shorten the hostile-page beat to the verdict line. |

## Backup assets to record the same day

- A 10-second screen capture of the `rewind_after_rm_rf` result card (for the cover image and the slides).
- A screenshot of the Report screen with all nine dimensions measured.
- A screenshot of the Infra screen on the real VM.
- The `pytest -m attacks` terminal output.

## Shot checklist

- [ ] 1080p, 30 fps, mouse cursor visible and large, no notifications.
- [ ] Audio recorded separately and clean; no background noise.
- [ ] Every click scripted; one rehearsal take under 2:55.
- [ ] Exported as MP4 (H.264), under the platform's size limit, plays while logged out of everything.
