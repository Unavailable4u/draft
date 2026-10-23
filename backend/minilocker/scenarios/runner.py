"""Run a scenario several times with the real agent and report how often it succeeds.

    python -m minilocker.scenarios --scenario fix_repo --runs 10
    python -m minilocker.scenarios --scenario all --runs 10 --profile strict

Each run is a whole task through `run_task`: a fresh sandbox, a fresh model client (so token budgets do not carry
over), the policy profile you name, and a hash-chained ledger of its own. Success is decided by the scenario's
check, never by what the model says about itself.

Reading the result: 9 of 10 is consistent with a true success rate anywhere from about 60% to 98%, so the report
prints the 95% interval next to the count. Run more than 10 when the decision matters.
"""
import argparse
import json
import math
import os
import statistics
import sys
import time
import traceback
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from minilocker.agent.loop import run_task
from minilocker.artifacts.store import MemoryArtifactStore
from minilocker.policy.engine import PolicyEngine
from minilocker.scenarios import SCENARIOS

BAR = 0.9               # the guide's target: succeed in at least 9 of 10 runs
ABORT_AFTER = 3         # consecutive crashed runs (Docker down, bad key...) before the batch is abandoned
DEFAULT_ALLOW = "pypi.org,files.pythonhosted.org"


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """95% confidence interval for a success rate of k out of n."""
    if n == 0:
        return 0.0, 0.0
    p, d = k / n, 1 + z * z / n
    centre, margin = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / d), min(1.0, (centre + margin) / d)


def run_once(scenario, make_llm, *, egress, profile, ledger_dir, task_id=None, artifacts=None) -> dict:
    """One whole task with a fresh model client. -> a record of what happened; never raises (a crash, including a
    client that cannot be built, is a failed run with a reason)."""
    counts = Counter()
    llm = None

    def watch(ev):
        if ev["type"] in ("llm.salvaged", "agent.nudge"):
            counts[ev["type"]] += 1

    t0 = time.time()
    task_id = task_id or uuid.uuid4().hex[:8]       # known up front, so even a crashed run's ledger can be found
    rec = {"scenario": scenario.id, "task_id": task_id}
    try:
        llm = make_llm()
        res = run_task(scenario.task, llm, ledger_dir=str(ledger_dir), on_event=watch, egress=egress,
                       policy=PolicyEngine(profile, scenario.budgets), task_id=task_id, artifacts=artifacts,
                       files=scenario.files or None, verify=scenario.verify)
        check = res.get("check") or {"passed": False, "reasons": ["no check result was produced"], "facts": {}}
        rec.update(task_id=res["task_id"], status=res["status"], steps=res["steps"], tokens=res["tokens"],
                   denials=res["denials"], ledger_verified=res["ledger_verified"], passed=bool(check["passed"]),
                   reasons=check["reasons"], facts=check["facts"], summary=(res["summary"] or "")[:600],
                   ledger_path=res["ledger_path"])
    except Exception as e:
        rec.update(status=f"error:{type(e).__name__}", steps=0, tokens=getattr(llm, "total_tokens", 0), denials=0,
                   ledger_verified=None, passed=False, reasons=[f"the run crashed: {type(e).__name__}: {str(e)[:200]}"],
                   facts={}, summary="", crashed=True, traceback=traceback.format_exc()[-1800:])
    rec["salvaged"], rec["nudges"] = counts["llm.salvaged"], counts["agent.nudge"]
    stats = getattr(llm, "stats", None)
    rec["retries"] = int(stats["retries"]) if stats else 0
    rec["seconds"] = round(time.time() - t0, 1)
    return rec


def summarize(records: list, bar: float = BAR) -> dict:
    n = len(records)
    k = sum(1 for r in records if r["passed"])
    lo, hi = wilson(k, n)
    reasons = Counter(reason for r in records if not r["passed"] for reason in r["reasons"])

    def med(key):
        vals = [r[key] for r in records if not r.get("crashed")]
        return round(statistics.median(vals), 1) if vals else None

    return {"runs": n, "passed": k, "rate": round(k / n, 3) if n else 0.0, "ci95": [round(lo, 3), round(hi, 3)],
            "finished": sum(1 for r in records if r["status"] == "finished"),
            "crashed": sum(1 for r in records if r.get("crashed")),
            "bar": bar, "met": bool(n) and k / n >= bar,
            "median_steps": med("steps"), "median_tokens": med("tokens"), "median_seconds": med("seconds"),
            "salvaged": sum(r["salvaged"] for r in records), "nudges": sum(r["nudges"] for r in records),
            "denials": sum(r["denials"] for r in records),
            "top_failures": [f"{c}x {r}" for r, c in reasons.most_common(5)]}


def run_many(scenario, runs, make_llm, *, egress=None, profile="strict", out_dir, delay=0.0, progress=None) -> dict:
    out_dir = Path(out_dir)
    (out_dir / "ledgers").mkdir(parents=True, exist_ok=True)
    records, streak, aborted = [], 0, False
    for i in range(1, runs + 1):
        store = MemoryArtifactStore()
        rec = run_once(scenario, make_llm, egress=egress, profile=profile, ledger_dir=out_dir / "ledgers",
                       artifacts=store)
        rec["run"] = i
        _save_evidence(out_dir / f"run-{i:02d}", rec, store)
        records.append(rec)
        if progress:
            progress(rec)
        streak = streak + 1 if rec.get("crashed") else 0
        if streak >= ABORT_AFTER:
            aborted = True
            break
        if delay and i < runs:
            time.sleep(delay)
    return {"scenario": scenario.id, "title": scenario.title, "records": records, "aborted": aborted,
            "summary": summarize(records)}


def _save_evidence(d: Path, rec: dict, store) -> None:
    """What a person needs to see why a run passed or failed: the final report, the verdict, and the page text the
    agent read. (The screenshots themselves go to the real artifact store when a task runs through the API.)"""
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.txt").write_text(rec.get("summary") or "", encoding="utf-8")
        if rec.get("traceback"):
            (d / "error.txt").write_text(rec["traceback"], encoding="utf-8")
        (d / "check.json").write_text(json.dumps({k: rec.get(k) for k in ("passed", "reasons", "facts", "status")},
                                                 indent=1), encoding="utf-8")
        pages = f"tasks/{rec.get('task_id')}/pages/"
        files = f"tasks/{rec.get('task_id')}/workspace/"          # the agent's final files, as it left them
        root = (d / "workspace").resolve()
        for key, data in sorted(getattr(store, "objects", {}).items()):
            if key.startswith(pages):
                (d / key.rsplit("/", 1)[-1]).write_bytes(data)
            elif key.startswith(files):
                target = (root / key[len(files):]).resolve()
                if root in target.parents:                        # never write outside the run's own folder
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
    except OSError:
        pass


def render(result: dict) -> str:
    s = result["summary"]
    lo, hi = s["ci95"]
    verdict = ("NOT RUN (aborted: every run crashed)" if result["aborted"] and not s["passed"] else
               f"{'MET' if s['met'] else 'NOT MET'} (bar: {round(s['bar'] * 100)}%)")
    lines = [f"{result['title']} [{result['scenario']}]",
             f"  passed {s['passed']}/{s['runs']} ({round(s['rate'] * 100)}%, 95% interval {round(lo * 100)}-{round(hi * 100)}%): {verdict}",
             f"  finished cleanly {s['finished']}/{s['runs']}   crashed {s['crashed']}   policy denials {s['denials']}",
             f"  median per run: {s['median_steps']} steps, {s['median_tokens']} tokens, {s['median_seconds']}s",
             f"  help the model needed: {s['salvaged']} recovered tool call(s), {s['nudges']} empty-reply nudge(s)"]
    if s["crashed"]:
        done = s["runs"] - s["crashed"]
        lines.append(f"  without the {s['crashed']} crashed run(s): {s['passed']}/{done}"
                     f" ({round(100 * s['passed'] / done) if done else 0}%), what the model managed when the run itself worked")
    if s["top_failures"]:
        lines += ["  why runs failed:"] + [f"    - {t}" for t in s["top_failures"]]
    if result["aborted"]:
        lines.append(f"  stopped early after {ABORT_AFTER} crashed runs in a row: fix the cause first (see the reasons above)")
    return "\n".join(lines)


def _hosts_for(scenario) -> list:
    base = [h.strip() for h in os.environ.get("MINILOCKER_ALLOW", DEFAULT_ALLOW).split(",") if h.strip()]
    return base + [h for h in scenario.allow if h not in base]


def main(argv=None, make_llm=None, make_egress=None, out=None) -> int:
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="python -m minilocker.scenarios", description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", default="all", help=f"one of {', '.join(SCENARIOS)}, or all (default)")
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--profile", choices=("strict", "observe"), default="strict")
    ap.add_argument("--out", default="runs/scenarios", help="where ledgers, evidence and the summary are written")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between runs, for tight rate limits")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)

    if args.list:
        for s in SCENARIOS.values():
            print(f"{s.id:10} {s.title}" + (f"   (needs network: {', '.join(s.allow)})" if s.needs_network else "   (offline)"), file=out)
        return 0
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown or args.runs < 1:
        ap.error(f"unknown scenario {unknown[0]!r} (see --list)" if unknown else "--runs must be at least 1")

    if make_llm is None:
        from minilocker.config import load_and_report
        load_and_report()
        missing = [k for k in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY") if not os.environ.get(k)]
        if missing:
            ap.error(f"set {', '.join(missing)} (deploy/.env is read automatically)")
        from minilocker.llm.client import LLMClient
        make_llm = LLMClient
    if make_egress is None:
        def make_egress(hosts):
            from minilocker.egress.manager import EgressManager
            return EgressManager(hosts).start()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    results = []
    for name in names:
        scenario = SCENARIOS[name]
        egress = None
        if scenario.needs_network:
            print(f"[{name}] starting the egress proxy for: {', '.join(_hosts_for(scenario))} "
                  "(this replaces a running MiniLocker proxy: stop the stack first)", file=sys.stderr)
            egress = make_egress(_hosts_for(scenario))
        try:
            print(f"[{name}] {args.runs} run(s), profile {args.profile}", file=sys.stderr)
            results.append(run_many(
                scenario, args.runs, make_llm, egress=egress, profile=args.profile,
                out_dir=Path(args.out) / f"{name}-{stamp}", delay=args.delay,
                progress=lambda r, n=name: print(
                    f"  {n} run {r['run']:>2}  {'PASS' if r['passed'] else 'FAIL'}  {r['status']:<24} "
                    f"{r['steps']:>2} steps {r['tokens']:>6} tokens {r['seconds']:>5}s"
                    + ("" if r["passed"] else f"  {r['reasons'][0][:90]}"), file=sys.stderr)))
        finally:
            if egress is not None:
                egress.stop()
    for r in results:
        print(render(r), file=out)
        print(file=out)

    summary_path = Path(args.out) / f"summary-{stamp}.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "started": stamp, "profile": args.profile, "model": os.environ.get("LLM_MODEL"),
        "tool_mode": os.environ.get("LLM_TOOL_MODE", "native"),
        "results": [{**r, "records": [{k: v for k, v in rec.items() if k != "ledger_path"} for rec in r["records"]]}
                    for r in results]}, indent=1), encoding="utf-8")
    print(f"details: {summary_path}", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
