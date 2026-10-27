import { useEffect, useRef, useState } from "react";
import type { LedgerEvent, Profile, Report } from "./api";
import { listApprovals, listScenarios, resolveApproval } from "./api";
import type { ScenarioInfo } from "./api";
import { blast, describe, groupLines, measure, toolLine } from "./derive";
import { Md } from "./Md";
import type { Tone } from "./derive";

const TONE: Record<Tone, string> = {
  ok: "text-emerald-400", bad: "text-red-400", warn: "text-amber-400", info: "text-zinc-400",
};

export function TaskForm({ running, error, onRun }: {
  running: boolean; error: string | null; onRun: (t: string, p: Profile, holdS: number, scenario: string | null) => void;
}) {
  const [text, setText] = useState("");
  const [profile, setProfile] = useState<Profile>("strict");
  const [hold, setHold] = useState(0);
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [scenario, setScenario] = useState("");
  useEffect(() => { listScenarios().then(r => setScenarios(r.scenarios)).catch(() => { /* free-text tasks still work */ }); }, []);
  const sc = scenarios.find(s => s.id === scenario);
  const go = () => { if (!running && (sc || text.trim())) onRun(sc ? sc.task : text.trim(), profile, hold, sc ? sc.id : null); };
  return (
    <div className="space-y-2 border-b border-zinc-800 p-3">
      {scenarios.length > 0 && (
        <select value={scenario} onChange={e => setScenario(e.target.value)} title="A prepared task with files and a hidden success check"
          className="w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs">
          <option value="">Your own task</option>
          {scenarios.map(s => (
            <option key={s.id} value={s.id} disabled={!s.available}>
              {s.title}{s.available ? "" : s.needs_browser && s.missing_hosts.length === 0 ? " (needs the browser image)" : ` (needs ${s.missing_hosts.join(", ") || "the browser image"} allowlisted)`}
            </option>
          ))}
        </select>
      )}
      <textarea value={sc ? sc.task : text} onChange={e => setText(e.target.value)} rows={4} maxLength={4000} readOnly={!!sc}
        onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); }}
        placeholder="Describe a task for the agent… (Ctrl+Enter to run)"
        className="w-full resize-none rounded border border-zinc-700 bg-zinc-900 p-2 text-sm outline-none focus:border-emerald-600" />
      <div className="flex items-center gap-2">
        <select value={profile} onChange={e => setProfile(e.target.value as Profile)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs">
          <option value="strict">strict</option>
          <option value="observe">observe</option>
        </select>
        <select value={hold} onChange={e => setHold(Number(e.target.value))}
          title="Keep the sandbox open after the agent stops, so its workspace can be inspected and rewound on the Timeline"
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs">
          <option value={0}>no hold</option>
          <option value={60}>hold 1 min</option>
          <option value={180}>hold 3 min</option>
          <option value={600}>hold 10 min</option>
        </select>
        <button onClick={go} disabled={running || !(sc || text.trim())}
          className="ml-auto rounded bg-emerald-600 px-4 py-1.5 text-sm font-medium text-white disabled:opacity-40">
          {running ? "Running…" : "Run in sandbox"}
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}

const STEP_TYPES = new Set(["task.start", "llm.response", "tool.call", "tool.result",
  "policy.decision", "approval.requested", "approval.granted", "approval.denied", "task.end"]);

function Step({ e, calls, lastText }: { e: LedgerEvent; calls: number; lastText: string }) {
  const p = e.payload;
  if (e.type === "task.start") return <li className="text-xs text-zinc-500">Task started · profile <b>{p.profile}</b></li>;
  if (e.type === "llm.response")
    return p.text ? <li className="rounded bg-zinc-900 p-2 text-zinc-300"><Md>{p.text}</Md></li> : null;
  if (e.type === "tool.call")
    return (
      <li className="text-xs">
        <span className="text-emerald-400">▸ {p.tool}</span>
        <code className="mt-0.5 block break-all rounded bg-zinc-900 p-1.5 text-zinc-300">{toolLine(p)}</code>
      </li>
    );
  if (e.type === "tool.result")
    return (
      <li className="text-xs text-zinc-500">
        <details><summary className="cursor-pointer">result</summary>
          <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap rounded bg-zinc-900 p-1.5 text-zinc-400">{String(p.result)}</pre>
        </details>
      </li>
    );
  if (e.type === "task.end") {
    // finished but nothing ran (e.g. the model refused): say so instead of a green success card
    const quiet = p.status === "finished" && calls === 0;
    const border = quiet ? "border-zinc-700" : p.status === "finished" ? "border-emerald-800" : "border-amber-800";
    const head = quiet ? "text-zinc-300" : p.status === "finished" ? "text-emerald-400" : "text-amber-400";
    const summary = String(p.summary ?? "");
    const repeated = summary.slice(0, 200) === lastText.slice(0, 200);   // the answer was already shown above
    return (
      <li className={`rounded border p-2 ${border}`}>
        <b className={head}>{quiet ? "Answered · no commands run" : `Task ${p.status}`}</b>
        <span className="text-zinc-500"> · {p.steps} {p.steps === 1 ? "step" : "steps"}</span>
        {summary && !repeated && <div className="mt-1 text-zinc-300"><Md>{summary}</Md></div>}
      </li>
    );
  }
  const d = describe(e);
  return d ? <li className={`text-xs ${TONE[d.tone]}`}>{d.text}</li> : null;
}

export function StepStream({ events }: { events: LedgerEvent[] }) {
  const bottom = useRef<HTMLDivElement>(null);
  useEffect(() => { bottom.current?.scrollIntoView({ block: "end" }); }, [events.length]);
  const steps = events.filter(e => STEP_TYPES.has(e.type));
  const calls = events.filter(e => e.type === "tool.call").length;
  const lastText = String([...events].reverse().find(e => e.type === "llm.response" && e.payload.text)?.payload.text ?? "");
  return (
    <div className="flex-1 overflow-y-auto p-3">
      {steps.length === 0 && <p className="text-xs text-zinc-600">Steps appear here as the agent works.</p>}
      <ol className="space-y-2">{steps.map(e => <Step key={e.id} e={e} calls={calls} lastText={lastText} />)}</ol>
      <div ref={bottom} />
    </div>
  );
}

function Gauge({ label, value, sub, tone }: { label: string; value: string | number; sub: string; tone: Tone }) {
  return (
    <div className="rounded border border-zinc-800 bg-zinc-900 p-3">
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={`text-3xl font-semibold ${TONE[tone]}`}>{value}</div>
      <div className="text-xs text-zinc-500">{sub}</div>
    </div>
  );
}

const MIB = 1024 * 1024;

/** Filesystem, secrets and compute gauges. Until a sandbox has been audited (that happens as it is destroyed) they say
 *  so; they never show a zero that nothing measured. */
function measuredGauges(events: LedgerEvent[], running: boolean) {
  const x = measure(events);
  const wait = running ? "measured when the sandbox is destroyed" : "not measured";
  if (!x.audited)
    return [
      <Gauge key="fs" label="Filesystem" value="—" tone="info" sub={wait} />,
      <Gauge key="sec" label="Secrets" value="—" tone="info" sub={wait} />,
      <Gauge key="cpu" label="Compute" value="—" tone="info" sub={wait} />,
    ];
  const ws = x.workspace;
  const decoys = x.decoysRead.size + x.decoysTripped.size;
  return [
    <Gauge key="fs" label="Filesystem" value={x.hostBinds} tone={x.hostBinds ? "bad" : "ok"}
      sub={`host paths mounted · ${x.rootfsChanges} system files changed${ws ? ` · workspace +${ws.added} ~${ws.modified} −${ws.deleted}` : ""}`} />,
    <Gauge key="sec" label="Secrets" value={x.realSecrets.length} tone={x.realSecrets.length ? "bad" : x.decoysTripped.size ? "warn" : "ok"}
      sub={`real in sandbox${x.scanned ? "" : " (inside not scanned)"} · ${x.decoysRead.size} of ${x.decoysPlanted || "?"} decoys read · ${x.decoysTripped.size} used`} />,
    <Gauge key="cpu" label="Compute" value={`${Math.round(x.peakMem / MIB)} MiB`} tone={x.oom ? "bad" : x.memLimit && x.peakMem / x.memLimit > 0.8 ? "warn" : "ok"}
      sub={`peak of ${Math.round(x.memLimit / MIB)} · ${x.peakPids}/${x.pidsLimit} pids · ${x.cpuS.toFixed(1)} s cpu${x.oom ? " · OOM killed" : ""}`} />,
  ];
}

export function BlastPanel({ events, report, running }: { events: LedgerEvent[]; report: Report | null; running: boolean }) {
  const m = blast(events);
  const feed = groupLines(events);
  return (
    <div className="flex h-full flex-col">
      <div className="grid grid-cols-2 gap-2 p-3">
        <Gauge label="Network" value={m.blocked} tone={m.blocked ? "bad" : "ok"}
          sub={`blocked · ${m.allowed} allowed · ${m.hosts.size} hosts`} />
        <Gauge label="Policy" value={m.denied} tone={m.denied ? "bad" : "ok"}
          sub={`denied · ${m.asked} approvals · ${m.decisions} checked`} />
        {measuredGauges(events, running)}
        <Gauge label="Sandboxes" value={m.created} tone="info"
          sub={`created · ${m.destroyed} destroyed · ${m.forced} killed · ${m.rewinds} rewound`} />
        <Gauge label="Time" value={`${m.seconds.toFixed(0)}s`} tone="info" sub={running ? "so far" : "wall clock"} />
      </div>
      <div className="mx-3 mb-2 rounded border border-zinc-800 p-2 text-xs">
        {report
          ? <span className={report.ledger.verified ? "text-emerald-400" : "text-red-400"}>
              Ledger chain {report.ledger.verified ? "verified ✓" : "FAILED ✗"} — {report.ledger.detail}</span>
          : <span className="text-zinc-500">Ledger chain is verified when the task completes</span>}
      </div>
      <ul className="flex-1 space-y-1 overflow-y-auto border-t border-zinc-800 p-3 text-xs">
        {feed.map(r => (
          <li key={r.key} className={TONE[r.tone]}>
            {r.text}{r.count > 1 && <span className="ml-1 rounded bg-zinc-800 px-1 text-zinc-300">×{r.count}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ApprovalModal({ ev, taskId }: { ev: LedgerEvent; taskId: string }) {
  const p = ev.payload;
  const [left, setLeft] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Countdown = server-side (expires_at - event ts), so clock drift between WSL and
  // the browser can't distort it; the server denies on timeout regardless.
  useEffect(() => {
    let alive = true, timer: number | undefined;
    listApprovals(taskId).then(({ pending }) => {
      const a = pending.find(x => x.id === p.id);
      if (!alive || !a) return;
      const deadline = Date.now() + (a.expires_at - ev.ts) * 1000;
      const tick = () => setLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
      tick();
      timer = window.setInterval(tick, 500);
    }).catch(() => { /* no countdown; server still auto-denies */ });
    return () => { alive = false; clearInterval(timer); };
  }, [p.id, taskId, ev.ts]);

  const decide = async (approve: boolean) => {
    setBusy(true); setErr(null);
    try { await resolveApproval(p.id, approve); }   // modal closes when the ledger event arrives
    catch (e) { setErr((e as Error).message); setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="w-[560px] rounded-lg border border-amber-700 bg-zinc-900 p-5 shadow-xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-amber-400">Approval required</h2>
          <span className="rounded bg-amber-900/50 px-2 py-0.5 text-xs uppercase text-amber-300">{p.risk} risk</span>
        </div>
        <p className="mt-3 text-xs text-zinc-500">The agent wants to run ({p.tool}):</p>
        <code className="mt-1 block max-h-32 overflow-auto break-all rounded bg-zinc-950 p-2 text-zinc-200">{p.summary}</code>
        <ul className="mt-3 list-disc pl-5 text-sm text-zinc-300">
          {(p.reasons ?? []).map((r: string, i: number) => <li key={i}>{r}</li>)}
        </ul>
        {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
        <div className="mt-5 flex items-center gap-3">
          <span className="text-xs text-zinc-500">
            {left === null ? "Auto-denies on timeout" : `Auto-denies in ${left}s`}
          </span>
          <button onClick={() => decide(false)} disabled={busy}
            className="ml-auto rounded border border-red-700 px-4 py-1.5 text-red-400 disabled:opacity-40">Deny</button>
          <button onClick={() => decide(true)} disabled={busy}
            className="rounded bg-amber-600 px-4 py-1.5 font-medium text-black disabled:opacity-40">Approve</button>
        </div>
      </div>
    </div>
  );
}

export function Stub({ title, needs }: { title: string; needs: string }) {
  return (
    <div className="flex flex-1 items-center justify-center">
      <div className="max-w-md rounded-lg border border-dashed border-zinc-700 p-6 text-center">
        <h2 className="text-lg font-medium text-zinc-300">{title}</h2>
        <p className="mt-2 text-sm text-zinc-500">{needs}</p>
      </div>
    </div>
  );
}
