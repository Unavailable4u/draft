import { useEffect, useState } from "react";
import type { AttackCheck, AttackInfo, AttackResult, AttackStep, CheckStatus, Verdict } from "./api";
import type { AttackLabApi, Run } from "./useAttacks";

const VERDICT: Record<Verdict, { label: string; mark: string; text: string; box: string }> = {
  contained: { label: "Contained", mark: "✓", text: "text-emerald-400", box: "border-emerald-800 bg-emerald-950/30" },
  breached: { label: "Breached", mark: "✗", text: "text-red-400", box: "border-red-800 bg-red-950/30" },
  inconclusive: { label: "Inconclusive", mark: "?", text: "text-amber-400", box: "border-amber-800 bg-amber-950/30" },
  error: { label: "Could not run", mark: "!", text: "text-red-400", box: "border-red-800 bg-red-950/30" },
  unavailable: { label: "Unavailable", mark: "–", text: "text-zinc-400", box: "border-zinc-700 bg-zinc-900" },
};
const CHECK: Record<CheckStatus, { mark: string; text: string; word: string }> = {
  pass: { mark: "✓", text: "text-emerald-400", word: "passed" },
  fail: { mark: "✗", text: "text-red-400", word: "failed" },
  unproven: { mark: "?", text: "text-amber-400", word: "not proven" },
  skip: { mark: "–", text: "text-zinc-500", word: "skipped" },
};
const VERDICT_HELP: Partial<Record<Verdict, string>> = {
  inconclusive: "Nothing was damaged, but the attack did not exercise every property it targets, so containment is not proven.",
  breached: "At least one containment property failed. Open the checks below.",
};
const FOCUS = "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-emerald-500";

function verdictOf(r: Run | undefined): Verdict | null {
  if (!r || r.state === "running") return null;
  return r.state === "done" ? r.result.verdict : "error";
}

function Summary({ lab }: { lab: AttackLabApi }) {
  const list = lab.attacks ?? [];
  const runnable = list.filter(a => a.available).length;
  const tally: Record<string, number> = {};
  for (const a of list) { const v = verdictOf(lab.runs[a.name]); if (v) tally[v] = (tally[v] ?? 0) + 1; }
  const contained = tally.contained ?? 0, notRun = runnable - Object.entries(tally).filter(([k]) => k !== "unavailable").reduce((n, [, v]) => n + v, 0);
  const worst = tally.breached ? "text-red-400" : tally.inconclusive || tally.error ? "text-amber-400" : contained && !notRun ? "text-emerald-400" : "text-zinc-200";
  return (
    <div className="flex items-center gap-6 border-b border-zinc-800 px-4 py-3">
      <div>
        <div className={`text-4xl font-semibold tabular-nums ${worst}`}>{contained}<span className="text-zinc-600">/{runnable}</span></div>
        <div className="text-xs text-zinc-500">attacks contained</div>
      </div>
      <div className="text-xs text-zinc-400">
        {notRun > 0 && <div>{notRun} not run yet</div>}
        {(tally.breached ?? 0) > 0 && <div className="text-red-400">{tally.breached} breached</div>}
        {(tally.inconclusive ?? 0) > 0 && <div className="text-amber-400">{tally.inconclusive} inconclusive</div>}
        {(tally.error ?? 0) > 0 && <div className="text-red-400">{tally.error} could not run</div>}
        {list.length > runnable && <div className="text-zinc-500">{list.length - runnable} need the egress proxy or the browser image</div>}
      </div>
      <p className="max-w-sm text-xs text-zinc-500">
        Each attack is a scripted attacker driving the real agent loop, policy engine and Docker sandbox. No model is involved.
        The same definitions run in CI as <code className="text-zinc-400">pytest -m attacks</code>.
      </p>
      <button onClick={lab.runAll} disabled={lab.running || runnable === 0}
        className={`ml-auto rounded bg-emerald-600 px-4 py-1.5 text-sm font-medium text-white disabled:opacity-40 ${FOCUS}`}>
        {lab.all ? "Running all…" : "Run all"}
      </button>
    </div>
  );
}

function Card({ a, run, selected, disabled, onSelect, onRun }: {
  a: AttackInfo; run: Run | undefined; selected: boolean; disabled: boolean; onSelect: () => void; onRun: () => void;
}) {
  const v = verdictOf(run);
  const style = v ? VERDICT[v] : null;
  return (
    <li className={`flex items-stretch rounded border ${selected ? "border-emerald-700 bg-zinc-900" : "border-zinc-800 hover:border-zinc-700"}`}>
      <button onClick={onSelect} aria-pressed={selected} className={`min-w-0 flex-1 rounded-l p-3 text-left ${FOCUS}`}>
        <div className="flex items-baseline gap-2">
          <span aria-hidden className={`w-4 text-center font-semibold ${style?.text ?? "text-zinc-700"}`}>{run?.state === "running" ? "…" : style?.mark ?? "·"}</span>
          <span className="font-medium text-zinc-100">{a.title}</span>
          <span className={`ml-auto text-xs ${style?.text ?? "text-zinc-600"}`}>
            {run?.state === "running" ? "running" : style ? style.label : a.available ? "not run" : a.needs_browser && !a.needs_egress ? "needs browser image" : "needs egress"}
          </span>
        </div>
        <p className="mt-1 line-clamp-2 pl-6 text-xs text-zinc-500">{a.summary}</p>
        <p className="mt-1 pl-6 text-xs text-zinc-600">{a.category} · {a.profile}</p>
      </button>
      <button onClick={onRun} disabled={disabled || !a.available || run?.state === "running"}
        title={a.available ? undefined : a.needs_browser && !a.needs_egress
          ? "Needs the browser image: docker build -f images/browser/Dockerfile -t minilocker-browser:latest ."
          : "Needs the egress proxy, which is not attached"}
        aria-label={`Run ${a.title}`}
        className={`m-2 self-center rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:border-emerald-600 disabled:opacity-40 ${FOCUS}`}>
        {run?.state === "running" ? "Running…" : v ? "Run again" : "Run"}
      </button>
    </li>
  );
}

function PolicyChip({ s }: { s: AttackStep }) {
  if (!s.policy) return null;
  const { action, risk } = s.policy;
  const [text, cls] = action === "deny" ? [`policy denied · ${risk} risk`, "border-red-800 text-red-400"]
    : action === "require_approval" ? [`policy asked for approval (${s.approval ?? "no answer"}) · ${risk} risk`, "border-amber-800 text-amber-400"]
    : action === "allow_in_sandbox" ? [`policy let it run in the sandbox · ${risk} risk`, "border-amber-800 text-amber-400"]
    : [`policy allowed · ${risk} risk`, "border-zinc-700 text-zinc-400"];
  return <span className={`rounded border px-1.5 py-0.5 text-[11px] ${cls}`}>{text}</span>;
}

function Attempt({ s }: { s: AttackStep }) {
  return (
    <li className="space-y-1 text-xs">
      <div className="flex items-start gap-2">
        <span className="shrink-0 text-zinc-600">{s.tool === "write_file" ? "write" : "$"}</span>
        <code className="min-w-0 flex-1 break-all text-zinc-200">{s.text}</code>
        <PolicyChip s={s} />
      </div>
      {s.content && <details className="pl-5 text-zinc-500"><summary className="cursor-pointer">file contents</summary>
        <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-zinc-900 p-2 text-zinc-400">{s.content}</pre></details>}
      {s.egress.map((e, i) => (
        <div key={i} className={`pl-5 ${e.decision === "blocked" ? "text-red-400" : "text-emerald-400"}`}>
          egress {e.decision} → {e.host}{e.reason ? ` (${e.reason})` : ""}
        </div>))}
      {s.recreated && <div className="pl-5 text-amber-400">sandbox killed and replaced</div>}
      {s.result !== null && (
        <details className="pl-5 text-zinc-500" open={s.policy?.action === "deny"}>
          <summary className="cursor-pointer">{s.policy?.action === "deny" ? "blocked before it ran" : "sandbox output"}</summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-zinc-900 p-2 text-zinc-400">{s.result}</pre>
        </details>)}
    </li>
  );
}

function Checks({ checks }: { checks: AttackCheck[] }) {
  const always = checks.filter(c => c.scope === "always");
  const row = (c: AttackCheck) => (
    <li key={c.label} className="flex gap-2 text-xs">
      <span aria-label={CHECK[c.status].word} className={`w-4 shrink-0 text-center font-semibold ${CHECK[c.status].text}`}>{CHECK[c.status].mark}</span>
      <div><div className="text-zinc-200">{c.label}</div><div className="text-zinc-500">{c.detail}</div></div>
    </li>);
  return (<>
    <ul className="space-y-2">{checks.filter(c => c.scope === "attack").map(row)}</ul>
    {always.length > 0 && (<>
      <h4 className="mt-4 text-xs text-zinc-500">Checked on every attack</h4>
      <ul className="mt-2 space-y-2">{always.map(row)}</ul>
    </>)}
  </>);
}

function Result({ a, r, onOpenReport }: { a: AttackInfo; r: AttackResult; onOpenReport: (id: string) => void }) {
  const v = VERDICT[r.verdict];
  return (
    <div className="space-y-5">
      <div className={`rounded border p-3 ${v.box}`} role="status">
        <div className="flex items-center gap-3">
          <span className={`text-lg font-semibold ${v.text}`}>{v.mark} {v.label}</span>
          <span className="text-xs text-zinc-500">{r.duration_s}s · {r.counts.pass} passed
            {r.counts.fail > 0 && ` · ${r.counts.fail} failed`}{r.counts.unproven > 0 && ` · ${r.counts.unproven} not proven`}</span>
          {r.task_id && r.verdict !== "unavailable" && (
            <button onClick={() => onOpenReport(r.task_id!)}
              className={`ml-auto rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:border-zinc-500 ${FOCUS}`}>
              Open Blast Radius report
            </button>)}
        </div>
        {(VERDICT_HELP[r.verdict] || r.error) && <p className="mt-2 text-xs text-zinc-400">{r.error ?? VERDICT_HELP[r.verdict]}</p>}
      </div>
      {r.steps.length > 0 && (<section>
        <h3 className="mb-2 text-sm font-medium text-zinc-300">What happened</h3>
        <ol className="space-y-3">{r.steps.map(s => <Attempt key={s.index} s={s} />)}</ol>
      </section>)}
      {r.checks.length > 0 && (<section>
        <h3 className="mb-2 text-sm font-medium text-zinc-300">Containment checks</h3>
        <Checks checks={r.checks} />
      </section>)}
      <p className="text-xs text-zinc-600">Expected: {a.expected}</p>
    </div>
  );
}

function Preview({ a }: { a: AttackInfo }) {
  return (
    <div className="space-y-5">
      <section>
        <h3 className="mb-2 text-sm font-medium text-zinc-300">What the attacker tries</h3>
        <ol className="space-y-2">
          {a.tries.map((t, i) => (
            <li key={i} className="text-xs">
              <div className="flex gap-2"><span className="shrink-0 text-zinc-600">{t.tool === "write_file" ? "write" : "$"}</span>
                <code className="break-all text-zinc-200">{t.text}</code></div>
              {t.content && <details className="pl-5 text-zinc-500"><summary className="cursor-pointer">file contents</summary>
                <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-zinc-900 p-2 text-zinc-400">{t.content}</pre></details>}
            </li>))}
        </ol>
      </section>
      <section>
        <h3 className="mb-2 text-sm font-medium text-zinc-300">What will be checked</h3>
        <ul className="list-disc space-y-1 pl-5 text-xs text-zinc-400">{a.checks.map(c => <li key={c}>{c}</li>)}</ul>
      </section>
      <p className="text-xs text-zinc-600">Expected: {a.expected}</p>
    </div>
  );
}

export function AttackLab({ lab, onOpenReport }: { lab: AttackLabApi; onOpenReport: (id: string) => void }) {
  const { attacks, load, loadError, runs } = lab;
  const [sel, setSel] = useState<string | null>(null);
  useEffect(() => { if (!attacks) load(); }, [attacks, load]);
  // Follow the attack that is running (Run all walks the list), otherwise keep the user's choice.
  useEffect(() => {
    const live = Object.entries(runs).find(([, r]) => r.state === "running")?.[0];
    if (live) setSel(live);
  }, [runs]);

  if (loadError) return (
    <div className="flex flex-1 items-center justify-center"><div className="max-w-md space-y-3 rounded border border-dashed border-zinc-700 p-6 text-center">
      <p className="text-sm text-red-400">{loadError}</p>
      <p className="text-xs text-zinc-500">If the control plane uses an API token, enter it in the header, then retry.</p>
      <button onClick={load} className={`rounded border border-zinc-700 px-3 py-1 text-xs ${FOCUS}`}>Retry</button>
    </div></div>);
  if (!attacks) return <div className="flex flex-1 items-center justify-center text-zinc-500">Loading attacks…</div>;

  const cur = attacks.find(a => a.name === (sel ?? attacks[0].name))!;
  const run = runs[cur.name];
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Summary lab={lab} />
      <div className="grid min-h-0 flex-1 grid-cols-[400px_1fr]">
        <ul className="min-h-0 space-y-2 overflow-y-auto border-r border-zinc-800 p-3">
          {attacks.map(a => <Card key={a.name} a={a} run={runs[a.name]} selected={a.name === cur.name} disabled={lab.running}
            onSelect={() => setSel(a.name)} onRun={() => { setSel(a.name); lab.run(a.name); }} />)}
        </ul>
        <section className="min-h-0 overflow-y-auto p-5">
          <div className="mx-auto max-w-3xl space-y-5">
            <header>
              <h2 className="text-lg font-semibold text-zinc-100">{cur.title}</h2>
              <p className="mt-1 text-sm text-zinc-400">{cur.summary}</p>
            </header>
            {run?.state === "running" && <p role="status" className="text-sm text-amber-400">Running in a real sandbox. Some attacks take up to 30 seconds…</p>}
            {run?.state === "failed" && <p role="status" className="rounded border border-red-800 p-3 text-sm text-red-400">{run.message}</p>}
            {run?.state === "done" ? <Result a={cur} r={run.result} onOpenReport={onOpenReport} /> : <Preview a={cur} />}
          </div>
        </section>
      </div>
    </div>
  );
}
