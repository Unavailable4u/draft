import { useEffect, useState } from "react";
import type { AttackCheck, AttackInfo, AttackResult, AttackStep, CheckStatus, Verdict } from "./api";
import type { AttackLabApi, Run } from "./useAttacks";
import { Btn, Card, Chip, Donut, EDGE, INK, LISTING, Label, SectionHead, Spin, WASH } from "./ui";
import type { Tint } from "./ui";

const VERDICT: Record<Verdict, { label: string; mark: string; tone: Tint }> = {
  contained: { label: "Contained", mark: "✓", tone: "ok" },
  breached: { label: "Breached", mark: "✗", tone: "bad" },
  inconclusive: { label: "Inconclusive", mark: "?", tone: "warn" },
  error: { label: "Could not run", mark: "!", tone: "bad" },
  unavailable: { label: "Unavailable", mark: "–", tone: "mute" },
};
const CHECK: Record<CheckStatus, { mark: string; tone: Tint; word: string }> = {
  pass: { mark: "✓", tone: "ok", word: "passed" },
  fail: { mark: "✗", tone: "bad", word: "failed" },
  unproven: { mark: "?", tone: "warn", word: "not proven" },
  skip: { mark: "–", tone: "mute", word: "skipped" },
};
const VERDICT_HELP: Partial<Record<Verdict, string>> = {
  inconclusive: "Nothing was damaged, but the attack did not exercise every property it targets, so containment is not proven.",
  breached: "At least one containment property failed. Open the checks below.",
};

function verdictOf(r: Run | undefined): Verdict | null {
  if (!r || r.state === "running") return null;
  return r.state === "done" ? r.result.verdict : "error";
}

/** One tile of the verdict matrix: one attack, one colour, one glyph. */
function tileOf(a: AttackInfo, r: Run | undefined): { cls: string; mark: string; label: string } {
  if (r?.state === "running") return { cls: "border-info bg-info-wash text-info animate-pulse", mark: "…", label: "running" };
  const v = verdictOf(r);
  if (v === "contained") return { cls: "border-ok/60 bg-ok-wash text-ok", mark: "✓", label: "contained" };
  if (v === "breached") return { cls: "border-bad bg-bad-wash text-bad", mark: "✗", label: "breached" };
  if (v === "inconclusive") return { cls: "border-warn/70 bg-warn-wash text-warn", mark: "?", label: "inconclusive" };
  if (v === "error") return { cls: "border-bad/60 bg-bad-wash text-bad", mark: "!", label: "could not run" };
  if (!a.available) return { cls: "border-dashed border-ink-3/50 text-ink-3", mark: "–", label: "unavailable" };
  return { cls: "border-rule bg-sunken text-ink-3", mark: "·", label: "not run" };
}

function Summary({ lab, sel, onPick }: { lab: AttackLabApi; sel: string; onPick: (n: string) => void }) {
  const list = lab.attacks ?? [];
  const runnable = list.filter(a => a.available).length;
  const tally: Record<string, number> = {};
  for (const a of list) { const v = verdictOf(lab.runs[a.name]); if (v) tally[v] = (tally[v] ?? 0) + 1; }
  const contained = tally.contained ?? 0, notRun = runnable - Object.entries(tally).filter(([k]) => k !== "unavailable").reduce((n, [, v]) => n + v, 0);
  const worst: Tint = tally.breached ? "bad" : tally.inconclusive || tally.error ? "warn" : contained && !notRun ? "ok" : "mute";
  return (
    <div className="shrink-0 border-b border-rule bg-sheet/50 px-6 py-4 backdrop-blur">
      <div className="mx-auto flex max-w-[96rem] items-center gap-7">
        <Donut size={116} stroke={10} total={Math.max(1, runnable)} label={`${contained} of ${runnable} attacks contained`}
          segments={[{ value: contained, tone: "ok" }, { value: tally.inconclusive ?? 0, tone: "warn" },
            { value: (tally.breached ?? 0) + (tally.error ?? 0), tone: "bad" }]}>
          <div>
            <div className={`display text-[2.15rem] tabular-nums ${worst === "mute" ? "text-ink" : INK[worst]}`}>
              {contained}<span className="text-[1.3rem] text-ink-3">/{runnable}</span>
            </div>
            <div className="smcp -mt-0.5 text-[0.74rem] text-ink-2">contained</div>
          </div>
        </Donut>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Attack verdicts">
            {list.map(a => {
              const c = tileOf(a, lab.runs[a.name]);
              return (
                <button key={a.name} onClick={() => onPick(a.name)} title={`${a.title}: ${c.label}`} aria-label={`${a.title}: ${c.label}`}
                  className={`grid h-8 w-8 place-items-center rounded-[6px] border text-[0.9rem] font-bold transition hover:-translate-y-px ${c.cls} ${a.name === sel ? "ring-2 ring-accent ring-offset-2 ring-offset-sheet" : ""}`}>
                  {c.mark}
                </button>
              );
            })}
          </div>
          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-0.5 text-[0.92rem] text-ink-2">
            {notRun > 0 && <span>{notRun} not run yet</span>}
            {(tally.breached ?? 0) > 0 && <span className="font-bold text-bad">{tally.breached} breached</span>}
            {(tally.inconclusive ?? 0) > 0 && <span className="text-warn">{tally.inconclusive} inconclusive</span>}
            {(tally.error ?? 0) > 0 && <span className="text-bad">{tally.error} could not run</span>}
            {list.length > runnable && <span className="italic text-ink-3">{list.length - runnable} need the egress proxy or the browser image</span>}
            {notRun === 0 && !tally.breached && !tally.inconclusive && !tally.error && contained > 0 && <span className="font-bold text-ok">All runnable attacks contained</span>}
          </div>
        </div>
        <p className="hidden max-w-sm text-[0.86rem] italic leading-snug text-ink-2 xl:block">
          Each attack is a scripted attacker driving the real agent loop, policy engine and Docker sandbox. No model is involved.
          The same definitions run in CI as <code className="rounded-[3px] bg-sunken px-1 font-mono text-[0.9em] not-italic text-ink">pytest -m attacks</code>.
        </p>
        <Btn variant="primary" onClick={lab.runAll} disabled={lab.running || runnable === 0} className="shrink-0 !px-5 !py-2.5 text-[1.05rem]">
          {lab.all ? <><Spin /> Running all</> : <>Run all attacks <span aria-hidden>▸</span></>}
        </Btn>
      </div>
    </div>
  );
}

function AttackCard({ a, run, selected, disabled, onSelect, onRun }: {
  a: AttackInfo; run: Run | undefined; selected: boolean; disabled: boolean; onSelect: () => void; onRun: () => void;
}) {
  const v = verdictOf(run);
  const style = v ? VERDICT[v] : null;
  const running = run?.state === "running";
  const status = running ? "running" : style ? style.label : a.available ? "not run" : a.needs_browser && !a.needs_egress ? "needs browser image" : "needs egress";
  const tile = tileOf(a, run);
  return (
    <li className={`group relative rounded-[7px] border transition ${selected ? "border-accent/80 bg-raised shadow-[0_0_0_1px_var(--accent),0_14px_30px_-18px_var(--accent)]" : "border-rule bg-sheet hover:border-rule-2 hover:bg-raised"}`}>
      <button onClick={onSelect} aria-pressed={selected} className="block w-full rounded-[7px] p-3.5 pb-12 text-left">
        <div className="flex items-start gap-3">
          <span aria-hidden className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-[6px] border text-[0.9rem] font-bold ${tile.cls}`}>
            {running ? <Spin className="h-3 w-3" /> : tile.mark}
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[1.04rem] font-bold leading-tight text-ink">{a.title}</div>
            <p className="mt-1 line-clamp-2 text-[0.88rem] leading-snug text-ink-2">{a.summary}</p>
          </div>
        </div>
      </button>
      <div className="absolute inset-x-3.5 bottom-3 flex items-center gap-2">
        <Chip>{a.category}</Chip>
        <span className={`smcp text-[0.82rem] ${style ? INK[style.tone] : "text-ink-3"}`}>{status}</span>
        <Btn size="sm" onClick={onRun} disabled={disabled || !a.available || running} className="ml-auto"
          title={a.available ? undefined : a.needs_browser && !a.needs_egress
            ? "Needs the browser image: docker build -f images/browser/Dockerfile -t minilocker-browser:latest ."
            : "Needs the egress proxy, which is not attached"}
          aria-label={`Run ${a.title}`}>
          {running ? "Running…" : v ? "Run again" : "Run"}
        </Btn>
      </div>
    </li>
  );
}

function PolicyChip({ s }: { s: AttackStep }) {
  if (!s.policy) return null;
  const { action, risk } = s.policy;
  const [text, tone]: [string, Tint] = action === "deny" ? [`policy denied · ${risk} risk`, "bad"]
    : action === "require_approval" ? [`policy asked for approval (${s.approval ?? "no answer"}) · ${risk} risk`, "warn"]
    : action === "allow_in_sandbox" ? [`let run in the sandbox · ${risk} risk`, "warn"]
    : [`policy allowed · ${risk} risk`, "mute"];
  return <Chip tone={tone} className="shrink-0 !normal-case !tracking-normal">{text}</Chip>;
}

function Attempt({ s }: { s: AttackStep }) {
  return (
    <li className="panel space-y-1.5 p-3.5 text-[0.9rem]">
      <div className="flex items-start gap-2.5">
        <span className={`smcp w-9 shrink-0 pt-px ${s.tool === "write_file" ? "text-ink-3" : "font-bold text-ok"}`}>{s.tool === "write_file" ? "write" : "$"}</span>
        <code className="min-w-0 flex-1 break-all font-mono text-[0.84rem] text-ink">{s.text}</code>
        <PolicyChip s={s} />
      </div>
      {s.content && <details className="pl-[2.9rem] text-ink-2"><summary className="italic">file contents</summary>
        <pre className={`${LISTING} mt-1 max-h-48 overflow-auto whitespace-pre-wrap p-2.5 text-ink-2`}>{s.content}</pre></details>}
      {s.egress.map((e, i) => (
        <div key={i} className={`pl-[2.9rem] ${e.decision === "blocked" ? "text-bad" : "text-ok"}`}>
          <span aria-hidden>↗ </span>egress {e.decision} → <span className="font-mono text-[0.85em]">{e.host}</span>{e.reason ? ` (${e.reason})` : ""}
        </div>))}
      {s.recreated && <div className="pl-[2.9rem] text-warn">↻ sandbox killed and replaced</div>}
      {s.result !== null && (
        <details className="pl-[2.9rem] text-ink-2" open={s.policy?.action === "deny"}>
          <summary className="italic">{s.policy?.action === "deny" ? "blocked before it ran" : "sandbox output"}</summary>
          <pre className={`${LISTING} mt-1 max-h-48 overflow-auto whitespace-pre-wrap p-2.5 text-ink-2`}>{s.result}</pre>
        </details>)}
    </li>
  );
}

function Checks({ checks }: { checks: AttackCheck[] }) {
  const always = checks.filter(c => c.scope === "always");
  const row = (c: AttackCheck) => (
    <li key={c.label} className="flex gap-3">
      <span aria-label={CHECK[c.status].word} className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full border text-[0.75rem] font-bold ${EDGE[CHECK[c.status].tone]} ${INK[CHECK[c.status].tone]} ${WASH[CHECK[c.status].tone]}`}>{CHECK[c.status].mark}</span>
      <div className="min-w-0"><div className="font-medium text-ink">{c.label}</div><div className="text-[0.88rem] leading-snug text-ink-2">{c.detail}</div></div>
    </li>);
  return (<Card className="p-4">
    <ul className="space-y-3">{checks.filter(c => c.scope === "attack").map(row)}</ul>
    {always.length > 0 && (<>
      <h4 className="smcp mt-5 border-t border-rule pt-2.5 text-[0.88rem] text-ink-3">Checked on every attack</h4>
      <ul className="mt-3 space-y-3">{always.map(row)}</ul>
    </>)}
  </Card>);
}

function Result({ a, r, onOpenReport }: { a: AttackInfo; r: AttackResult; onOpenReport: (id: string) => void }) {
  const v = VERDICT[r.verdict];
  return (
    <div className="space-y-7">
      <div className={`rise relative overflow-hidden rounded-[8px] border p-5 ${EDGE[v.tone]} ${WASH[v.tone]}`} role="status">
        <span aria-hidden className="pointer-events-none absolute -right-10 -top-10 h-44 w-44 rounded-full border border-current opacity-[.12]" style={{ color: `var(--${v.tone === "mute" ? "ink-3" : v.tone})` }} />
        <span aria-hidden className="pointer-events-none absolute -right-2 -top-2 h-24 w-24 rounded-full border border-current opacity-[.14]" style={{ color: `var(--${v.tone === "mute" ? "ink-3" : v.tone})` }} />
        <div className="relative flex items-center gap-5">
          <span aria-hidden className={`grid h-16 w-16 shrink-0 place-items-center rounded-full border-2 text-[2rem] font-bold ${EDGE[v.tone]} ${INK[v.tone]}`}
            style={{ boxShadow: v.tone === "mute" ? undefined : `0 0 28px -4px var(--${v.tone})` }}>{v.mark}</span>
          <div className="min-w-0">
            <Label className="block">Verdict</Label>
            <div className={`display text-[2.4rem] ${INK[v.tone]}`}>{v.label}</div>
            <div className="mt-1 flex flex-wrap gap-x-4 text-[0.9rem] text-ink-2">
              <span className="tabular-nums">{r.duration_s}s</span>
              <span><b className="text-ok">{r.counts.pass}</b> passed</span>
              {r.counts.fail > 0 && <span><b className="text-bad">{r.counts.fail}</b> failed</span>}
              {r.counts.unproven > 0 && <span><b className="text-warn">{r.counts.unproven}</b> not proven</span>}
            </div>
          </div>
          {r.task_id && r.verdict !== "unavailable" && (
            <Btn onClick={() => onOpenReport(r.task_id!)} className="ml-auto shrink-0">Open Blast Radius report <span aria-hidden>→</span></Btn>
          )}
        </div>
        {(VERDICT_HELP[r.verdict] || r.error) && <p className="relative mt-3.5 border-t border-ink/10 pt-2.5 text-[0.93rem] leading-snug text-ink-2">{r.error ?? VERDICT_HELP[r.verdict]}</p>}
      </div>
      {r.steps.length > 0 && (<section>
        <SectionHead no={1} title="What happened" className="mb-3" />
        <ol className="space-y-2.5">{r.steps.map(s => <Attempt key={s.index} s={s} />)}</ol>
      </section>)}
      {r.checks.length > 0 && (<section>
        <SectionHead no={2} title="Containment checks" className="mb-3" />
        <Checks checks={r.checks} />
      </section>)}
      <p className="border-t border-rule pt-2.5 text-[0.88rem] italic text-ink-3"><b className="not-italic text-ink-2">Expected.</b> {a.expected}</p>
    </div>
  );
}

function Preview({ a }: { a: AttackInfo }) {
  return (
    <div className="space-y-7">
      <section>
        <SectionHead no={1} title="What the attacker tries" className="mb-3" />
        <ol className="space-y-2.5">
          {a.tries.map((t, i) => (
            <li key={i} className="panel p-3.5 text-[0.9rem]">
              <div className="flex gap-2.5"><span className={`smcp w-9 shrink-0 pt-px ${t.tool === "write_file" || t.tool === "control" ? "text-ink-3" : "font-bold text-ok"}`}>{t.tool === "write_file" ? "write" : t.tool === "control" ? "↺" : "$"}</span>
                <code className="min-w-0 break-all font-mono text-[0.84rem] text-ink">{t.text}</code></div>
              {t.content && <details className="mt-1.5 pl-[2.9rem] text-ink-2"><summary className="italic">file contents</summary>
                <pre className={`${LISTING} mt-1 max-h-48 overflow-auto whitespace-pre-wrap p-2.5 text-ink-2`}>{t.content}</pre></details>}
            </li>))}
        </ol>
      </section>
      <section>
        <SectionHead no={2} title="What will be checked" className="mb-3" />
        <Card className="p-4">
          <ul className="space-y-2 text-ink-2">
            {a.checks.map(c => <li key={c} className="flex gap-3"><span aria-hidden className="mt-[0.5rem] h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />{c}</li>)}
          </ul>
        </Card>
      </section>
      <p className="border-t border-rule pt-2.5 text-[0.88rem] italic text-ink-3"><b className="not-italic text-ink-2">Expected.</b> {a.expected}</p>
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
    <div className="flex flex-1 items-center justify-center p-8"><div className="rise panel max-w-md space-y-3 border-bad/50 p-6 text-center">
      <p className="font-bold text-bad">{loadError}</p>
      <p className="text-[0.92rem] italic text-ink-2">If the control plane uses an API token, enter it in the header (top right), then retry.</p>
      <Btn onClick={load}>Retry</Btn>
    </div></div>);
  if (!attacks) return <div className="flex flex-1 items-center justify-center gap-2 italic text-ink-3"><Spin /> Loading attacks…</div>;

  const cur = attacks.find(a => a.name === (sel ?? attacks[0].name))!;
  const run = runs[cur.name];
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Summary lab={lab} sel={cur.name} onPick={setSel} />
      <div className="grid min-h-0 flex-1 grid-cols-[27rem_minmax(0,1fr)]">
        <ul className="min-h-0 space-y-2.5 overflow-y-auto border-r border-rule bg-paper/40 p-3.5">
          {attacks.map(a => <AttackCard key={a.name} a={a} run={runs[a.name]} selected={a.name === cur.name} disabled={lab.running}
            onSelect={() => setSel(a.name)} onRun={() => { setSel(a.name); lab.run(a.name); }} />)}
        </ul>
        <section className="min-h-0 overflow-y-auto px-8 py-7">
          <div className="mx-auto max-w-3xl space-y-7">
            <header>
              <div className="flex items-center gap-2"><Chip tone="info">{cur.category}</Chip><Chip>{cur.profile} profile</Chip></div>
              <h2 className="display mt-2.5 text-[2.7rem] text-ink">{cur.title}</h2>
              <p className="mt-2.5 border-l-2 border-accent/70 pl-4 text-[1.06rem] italic leading-relaxed text-ink-2">{cur.summary}</p>
            </header>
            {run?.state === "running" && <p role="status" className="flex items-center gap-2.5 rounded-[6px] border border-info/50 bg-info-wash px-3.5 py-2.5 text-info"><Spin /> Running in a real sandbox. Some attacks take up to 30 seconds…</p>}
            {run?.state === "failed" && <p role="status" className="rounded-[6px] border border-bad/50 bg-bad-wash p-3.5 text-bad">{run.message}</p>}
            {run?.state === "done" ? <Result a={cur} r={run.result} onOpenReport={onOpenReport} /> : <Preview a={cur} />}
          </div>
        </section>
      </div>
    </div>
  );
}
