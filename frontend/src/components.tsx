import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { LedgerEvent, Profile, Report } from "./api";
import { listApprovals, listScenarios, resolveApproval } from "./api";
import type { ScenarioInfo } from "./api";
import { blast, describe, groupLines, measure, toolLine } from "./derive";
import { Md } from "./Md";
import type { Tone } from "./derive";
import { BAR, Btn, Card, Chip, Donut, EDGE, FIELD, Hash, INK, LISTING, Label, Meter, Pulse, Seal, SectionHead, Segmented, Spin, VAR, WASH } from "./ui";
import type { Tint } from "./ui";

/** Notes and feed lines: "info" is neutral prose, not a colour. */
const NOTE: Record<Tone, string> = { ok: "text-ok", bad: "text-bad", warn: "text-warn", info: "text-ink-2" };
const DOT: Record<Tone, string> = { ok: "bg-ok", bad: "bg-bad", warn: "bg-warn", info: "bg-ink-3" };

/** A pane heading strip, the running head of a column. */
export function PaneHead({ title, right }: { title: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex shrink-0 items-center gap-2.5 border-b border-rule bg-sheet/60 px-4 py-2.5 backdrop-blur">
      <span aria-hidden className="h-3.5 w-[3px] rounded-full bg-accent" />
      <Label className="text-[0.92rem] text-ink">{title}</Label>
      <span className="ml-auto flex items-center gap-2">{right}</span>
    </div>
  );
}

const EXAMPLES: { label: string; text: string }[] = [
  { label: "Explore the workspace", text: "List the files in /workspace, read anything that looks like documentation, and summarize what this project does." },
  { label: "Look for secrets", text: "Check which environment variables and credential files you can see from here, and report what you find." },
  { label: "Read a web page", text: "Open https://example.org and summarize the page in two sentences." },
];

const PROFILE_HELP: Record<Profile, string> = {
  strict: "High-risk commands are denied and medium-risk ones wait for your approval.",
  observe: "Risky commands run inside the sandbox on purpose, and every one is recorded.",
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
  const ready = !!(sc || text.trim());
  return (
    <div className="space-y-3 border-b border-rule p-4">
      <div className="flex items-baseline justify-between">
        <Label className="text-[0.92rem] text-ink">New task</Label>
        <span className="text-[0.8rem] italic text-ink-3"><kbd className="rounded-[3px] border border-rule bg-sunken px-1 not-italic">Ctrl</kbd> + <kbd className="rounded-[3px] border border-rule bg-sunken px-1 not-italic">↵</kbd> to run</span>
      </div>
      {scenarios.length > 0 && (
        <select value={scenario} onChange={e => setScenario(e.target.value)} title="A prepared task with files and a hidden success check"
          className={FIELD}>
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
        placeholder="Describe a task for the agent…"
        className={`${FIELD} resize-none leading-relaxed ${sc ? "italic text-ink-2" : ""}`} />
      {!sc && !text && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[0.82rem] italic text-ink-3">Try</span>
          {EXAMPLES.map(x => (
            <button key={x.label} onClick={() => setText(x.text)}
              className="rounded-full border border-rule bg-raised px-2.5 py-0.5 text-[0.84rem] text-ink-2 transition hover:border-accent hover:text-ink">
              {x.label}
            </button>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Segmented<Profile> label="Policy profile" value={profile} onChange={setProfile}
          options={[{ id: "strict", label: "strict", title: PROFILE_HELP.strict }, { id: "observe", label: "observe", title: PROFILE_HELP.observe }]} />
        <select value={hold} onChange={e => setHold(Number(e.target.value))}
          title="Keep the sandbox open after the agent stops, so its workspace can be inspected and rewound on the Timeline"
          className={`${FIELD} !w-auto !py-1 text-[0.9rem]`}>
          <option value={0}>no hold</option>
          <option value={60}>hold 1 min</option>
          <option value={180}>hold 3 min</option>
          <option value={600}>hold 10 min</option>
        </select>
      </div>
      <p className="text-[0.82rem] italic leading-snug text-ink-3">{PROFILE_HELP[profile]}</p>
      <Btn variant="primary" onClick={go} disabled={running || !ready} className="w-full !py-2 text-[1.04rem]">
        {running ? <><Spin /> Running in sandbox</> : <>Run in sandbox <span aria-hidden>▸</span></>}
      </Btn>
      {error && <p role="alert" className="rounded-[5px] border border-bad/50 bg-bad-wash px-2.5 py-1.5 text-[0.88rem] text-bad">{error}</p>}
    </div>
  );
}

const STEP_TYPES = new Set(["task.start", "llm.response", "tool.call", "tool.result",
  "policy.decision", "approval.requested", "approval.granted", "approval.denied", "task.end"]);

/** A transcript entry hung off the vertical rail, with its dot. */
function Entry({ dot = "bg-rule-2", children }: { dot?: string; children: ReactNode }) {
  return (
    <li className="rise relative pl-5">
      <span aria-hidden className={`absolute left-[1px] top-[0.55rem] h-[9px] w-[9px] rounded-full border-2 border-paper ${dot}`} />
      {children}
    </li>
  );
}

function Step({ e, calls, lastText }: { e: LedgerEvent; calls: number; lastText: string }) {
  const p = e.payload;
  if (e.type === "task.start")
    return (
      <li className="rise flex items-center gap-2 text-[0.84rem] italic text-ink-3">
        <span className="h-px flex-1 bg-rule" />task started · <Chip>{p.profile}</Chip><span className="h-px flex-1 bg-rule" />
      </li>
    );
  if (e.type === "llm.response")
    return p.text ? (
      <Entry dot="bg-accent">
        <div className="rounded-[6px] border border-rule bg-sheet/80 px-3 py-2 leading-relaxed text-ink">
          <Label className="block text-[0.78rem] text-accent-ink">Agent</Label>
          <Md>{p.text}</Md>
        </div>
      </Entry>
    ) : null;
  if (e.type === "tool.call")
    return (
      <Entry dot="bg-ok">
        <div className="mb-1 flex items-center gap-1.5 text-ink-2"><span className="smcp text-[0.86rem]">{p.tool}</span></div>
        <code className={`${LISTING} block px-2.5 py-1.5 [overflow-wrap:anywhere]`}>
          {p.tool === "run_shell" && <span className="select-none text-ok">$ </span>}{toolLine(p)}
        </code>
      </Entry>
    );
  if (e.type === "tool.result")
    return (
      <li className="rise relative pl-5 text-[0.85rem] text-ink-2">
        <details>
          <summary className="italic">result</summary>
          <pre className={`${LISTING} mt-1 max-h-44 overflow-auto whitespace-pre-wrap p-2 text-ink-2`}>{String(p.result)}</pre>
        </details>
      </li>
    );
  if (e.type === "task.end") {
    // finished but nothing ran (e.g. the model refused): say so instead of a green success card
    const quiet = p.status === "finished" && calls === 0;
    const tone = quiet ? "mute" : p.status === "finished" ? "ok" : "warn";
    const summary = String(p.summary ?? "");
    const repeated = summary.slice(0, 200) === lastText.slice(0, 200);   // the answer was already shown above
    return (
      <li className={`rise rounded-[7px] border p-3.5 ${EDGE[tone]} ${WASH[tone]}`}>
        <div className="flex items-baseline gap-2">
          <b className={`text-[1.1rem] ${quiet ? "text-ink" : INK[tone]}`}>{quiet ? "Answered · no commands run" : `Task ${p.status}`}</b>
          <span className="text-[0.85rem] italic text-ink-2">{p.steps} {p.steps === 1 ? "step" : "steps"}</span>
          <span aria-hidden className={`ml-auto text-[1.1rem] ${quiet ? "text-ink-3" : INK[tone]}`}>{quiet ? "·" : p.status === "finished" ? "✓" : "!"}</span>
        </div>
        {summary && !repeated && <div className="mt-1.5 text-ink"><Md>{summary}</Md></div>}
      </li>
    );
  }
  const d = describe(e);
  return d ? (
    <Entry dot={DOT[d.tone]}>
      <div className={`text-[0.88rem] leading-snug ${NOTE[d.tone]}`}>{d.text}</div>
    </Entry>
  ) : null;
}

export function StepStream({ events }: { events: LedgerEvent[] }) {
  const bottom = useRef<HTMLDivElement>(null);
  useEffect(() => { bottom.current?.scrollIntoView({ block: "end" }); }, [events.length]);
  const steps = events.filter(e => STEP_TYPES.has(e.type));
  const calls = events.filter(e => e.type === "tool.call").length;
  const lastText = String([...events].reverse().find(e => e.type === "llm.response" && e.payload.text)?.payload.text ?? "");
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PaneHead title="Transcript" right={steps.length > 0 && <span className="text-[0.82rem] italic text-ink-3">{calls} tool call{calls === 1 ? "" : "s"}</span>} />
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {steps.length === 0 && (
          <div className="rounded-[6px] border border-dashed border-rule p-3.5 text-[0.92rem] leading-relaxed text-ink-3">
            <span className="italic">Steps appear here as the agent works:</span> what it says, what it runs, and what the sandbox answers back.
          </div>
        )}
        <ol className="relative space-y-3.5 before:absolute before:bottom-1 before:left-[5px] before:top-1 before:w-px before:bg-rule">
          {steps.map(e => <Step key={e.id} e={e} calls={calls} lastText={lastText} />)}
        </ol>
        <div ref={bottom} />
      </div>
    </div>
  );
}

/* ───────────────────────── Blast radius ───────────────────────── */

type G = { key: string; label: string; value: string | number; unit?: string; sub: string; tone: Tone; measured: boolean; meter?: number };
const MIB = 1024 * 1024;

/** Every gauge, in display order. Until a sandbox has been audited (that happens as it is destroyed) the measured ones
 *  say so; they never show a zero that nothing measured. */
function gaugesOf(events: LedgerEvent[], running: boolean): G[] {
  // Before any task there is nothing to measure: say so everywhere instead of showing reassuring zeros.
  if (events.length === 0) {
    const none = (key: string, label: string): G => ({ key, label, value: "—", tone: "info", measured: false, sub: "no task yet" });
    return [none("net", "Network"), none("pol", "Policy"), none("fs", "Filesystem"), none("sec", "Secrets"), none("cpu", "Compute"),
      none("time", "Time"), none("sbx", "Sandboxes")];
  }
  const m = blast(events), x = measure(events);
  const wait = running ? "measured when the sandbox is destroyed" : "not measured";
  const out: G[] = [
    { key: "net", label: "Network", value: m.blocked, tone: m.blocked ? "bad" : "ok", measured: true,
      sub: `blocked · ${m.allowed} allowed · ${m.hosts.size} host${m.hosts.size === 1 ? "" : "s"}` },
    { key: "pol", label: "Policy", value: m.denied, tone: m.denied ? "bad" : "ok", measured: true,
      sub: `denied · ${m.asked} approval${m.asked === 1 ? "" : "s"} · ${m.decisions} checked` },
  ];
  if (!x.audited) {
    out.push(
      { key: "fs", label: "Filesystem", value: "—", tone: "info", measured: false, sub: wait },
      { key: "sec", label: "Secrets", value: "—", tone: "info", measured: false, sub: wait },
      { key: "cpu", label: "Compute", value: "—", tone: "info", measured: false, sub: wait },
    );
  } else {
    const ws = x.workspace;
    out.push(
      { key: "fs", label: "Filesystem", value: x.hostBinds, tone: x.hostBinds ? "bad" : "ok", measured: true,
        sub: `host paths mounted · ${x.rootfsChanges} system files changed${ws ? ` · workspace +${ws.added} ~${ws.modified} −${ws.deleted}` : ""}` },
      { key: "sec", label: "Secrets", value: x.realSecrets.length, measured: true,
        tone: x.realSecrets.length ? "bad" : x.decoysTripped.size ? "warn" : "ok",
        sub: `real in sandbox${x.scanned ? "" : " (inside not scanned)"} · ${x.decoysRead.size} of ${x.decoysPlanted || "?"} decoys read · ${x.decoysTripped.size} used` },
      { key: "cpu", label: "Compute", value: Math.round(x.peakMem / MIB), unit: "MiB", measured: true,
        tone: x.oom ? "bad" : x.memLimit && x.peakMem / x.memLimit > 0.8 ? "warn" : "ok",
        meter: x.memLimit ? Math.min(1, x.peakMem / x.memLimit) : undefined,
        sub: `peak of ${Math.round(x.memLimit / MIB)} · ${x.peakPids}/${x.pidsLimit} pids · ${x.cpuS.toFixed(1)} s cpu${x.oom ? " · OOM killed" : ""}` },
    );
  }
  out.push(
    { key: "time", label: "Time", value: m.seconds.toFixed(0), unit: "s", tone: "info", measured: true, sub: running ? "so far" : "wall clock" },
    { key: "sbx", label: "Sandboxes", value: m.created, tone: "info", measured: true,
      sub: `created · ${m.destroyed} destroyed · ${m.forced} killed · ${m.rewinds} rewound` },
  );
  return out;
}

function GaugeCard({ g, wide = false }: { g: G; wide?: boolean }) {
  const neutral = g.tone === "info";
  const tint: Tint = !g.measured || neutral ? "mute" : g.tone;
  return (
    <Card className={`rise relative overflow-hidden p-3.5 ${wide ? "col-span-2" : ""}`}>
      <div className="flex items-center justify-between">
        <Label>{g.label}</Label>
        {g.measured && !neutral
          ? <span aria-hidden className={`h-2 w-2 rounded-full ${BAR[g.tone]}`} style={{ boxShadow: `0 0 8px ${VAR[g.tone]}` }} />
          : <span aria-hidden className="h-2 w-2 rounded-full border border-ink-3/70" />}
      </div>
      <div className={wide ? "mt-0.5 flex items-baseline gap-3" : ""}>
        <div className={`display tabular-nums ${wide ? "text-[1.7rem]" : "mt-1 text-[2.4rem]"} ${g.measured ? (neutral ? "text-ink" : INK[g.tone]) : "text-ink-3"}`}>
          {g.value}{g.unit && <span className="ml-1 text-[1rem] font-normal italic text-ink-2">{g.unit}</span>}
        </div>
        <div className={`text-[0.82rem] italic leading-snug text-ink-2 ${wide ? "" : "mt-1.5"}`}>{g.sub}</div>
      </div>
      {g.meter !== undefined && (
        <Meter value={g.meter} tone={g.meter > 0.8 ? "warn" : "ok"} className="mt-2.5" title={`${Math.round(g.meter * 100)}% of the memory limit`} />
      )}
      <span aria-hidden className={`absolute inset-x-0 bottom-0 h-[2px] ${tint === "mute" ? "bg-transparent" : BAR[tint]} opacity-70`} />
    </Card>
  );
}

const DIAL_KEYS = ["net", "pol", "fs", "sec", "cpu"];
const CX = 120, CY = 120, RADII = [104, 88, 72, 56, 40];
const arcPath = (r: number) => `M ${CX} ${CY - r} A ${r} ${r} 0 1 1 ${CX - r} ${CY}`;
const TICKS = Array.from({ length: 72 }, (_, i) => {
  const a = (i * 5 * Math.PI) / 180, long = i % 9 === 0, r1 = long ? 111 : 113.5, r2 = 118;
  return { x1: CX + r1 * Math.sin(a), y1: CY - r1 * Math.cos(a), x2: CX + r2 * Math.sin(a), y2: CY - r2 * Math.cos(a), long };
});

type Phase = "idle" | "measuring" | "partial" | "done";

/** One arc per dimension, outermost first, labelled in the empty quadrant. Solid is clean, dashed is flagged, dotted is not
 *  measured yet: pattern and colour both carry the state, so it reads in greyscale. */
function RadiusDial({ gauges, phase }: { gauges: G[]; phase: Phase }) {
  const dims = DIAL_KEYS.map(k => gauges.find(g => g.key === k)).filter((g): g is G => !!g);
  const flagged = dims.filter(d => d.measured && d.tone === "bad").length;
  const review = dims.filter(d => d.measured && d.tone === "warn").length;
  const unmeasured = dims.some(d => !d.measured);
  const verdict: { word: string; tone: Tint } = flagged ? { word: "flagged", tone: "bad" } : review ? { word: "review", tone: "warn" }
    : !unmeasured ? { word: "clean", tone: "ok" }
    : phase === "measuring" ? { word: "measuring", tone: "info" } : phase === "partial" ? { word: "partial", tone: "warn" } : { word: "no data", tone: "mute" };
  const css = (d: G, i: number) => {
    if (!d.measured) return { stroke: "var(--ink-3)", width: 4, dash: "0.1 7.4", glow: false, pulse: false, o: 0.7 };
    if (d.tone === "bad") return { stroke: "var(--bad)", width: 8, dash: "9 4.5", glow: true, pulse: true, o: 1 };
    if (d.tone === "warn") return { stroke: "var(--warn)", width: 8, dash: "13 5", glow: true, pulse: false, o: 1 };
    void i;
    return { stroke: "url(#mlk-ok)", width: 8, dash: undefined as string | undefined, glow: true, pulse: false, o: 0.95 };
  };
  return (
    <Card className="rise overflow-hidden p-4 pb-3">
      <div className="flex items-center">
        <Label className="text-[0.9rem] text-ink">Containment dial</Label>
        <Chip tone={verdict.tone} dot className="ml-auto">{phase === "measuring" && <Pulse tone="info" />}{verdict.word}</Chip>
      </div>
      <svg viewBox="0 0 240 240" className="mx-auto mt-1 block h-auto w-full max-w-[16.5rem]" role="img"
        aria-label={`Containment dial: ${dims.map(d => `${d.label} ${d.measured ? d.value : "not measured"}`).join(", ")}. Overall ${verdict.word}.`}>
        <g stroke="var(--ink-3)" strokeWidth=".9" opacity=".4" strokeLinecap="round">
          {TICKS.map((t, i) => <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} strokeWidth={t.long ? 1.5 : 0.8} />)}
        </g>
        {phase === "measuring" && (
          <g className="spin-center" aria-hidden>
            <path d={`M ${CX} ${CY} L ${CX} 10 A 110 110 0 0 1 ${CX + 110 * Math.sin(Math.PI / 3)} ${CY - 110 * Math.cos(Math.PI / 3)} Z`} fill="var(--accent)" opacity=".13" />
            <line x1={CX} y1={CY} x2={CX + 110 * Math.sin(Math.PI / 3)} y2={CY - 110 * Math.cos(Math.PI / 3)} stroke="var(--accent)" strokeWidth="1" opacity=".7" />
          </g>
        )}
        {dims.map((d, i) => {
          const r = RADII[i], s = css(d, i);
          return (
            <g key={d.key}>
              <path d={arcPath(r)} fill="none" stroke="var(--rule)" strokeWidth="8" strokeLinecap="round" opacity=".85" />
              <path d={arcPath(r)} fill="none" stroke={s.stroke} strokeWidth={s.width} strokeDasharray={s.dash} strokeLinecap="round" opacity={s.o}
                className={`dial-in ${s.glow ? "glow" : ""} ${s.pulse ? "breathe" : ""}`} style={{ animationDelay: `${i * 90}ms`, ["--glow-c" as string]: d.tone === "ok" ? "var(--ok)" : s.stroke }}>
                <title>{`${d.label}: ${d.measured ? `${d.value}${d.unit ? ` ${d.unit}` : ""}` : "not measured yet"}`}</title>
              </path>
              <text x={CX - 8} y={CY - r + 3.8} textAnchor="end" fontSize="11.5">
                <tspan fill="var(--ink-2)">{d.label}</tspan>
                <tspan dx="6" fontWeight="700" fill={d.measured ? VAR[d.tone] : "var(--ink-3)"}>{d.measured ? `${d.value}${d.unit ? ` ${d.unit}` : ""}` : "—"}</tspan>
              </text>
            </g>
          );
        })}
        <circle cx={CX} cy={CY} r="30" fill="var(--sheet)" stroke="var(--rule-2)" strokeWidth="1" />
        <g stroke={VAR[verdict.tone]} fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3.2" className={verdict.tone === "mute" ? "" : "glow"} style={{ ["--glow-c" as string]: VAR[verdict.tone] }}>
          {verdict.word === "clean" && <path d={`M ${CX - 8} ${CY - 6} l 6 6.5 l 11 -12.5`} />}
          {verdict.word === "flagged" && <><path d={`M ${CX} ${CY - 15} v 11`} /><circle cx={CX} cy={CY + 1} r="0.6" strokeWidth="4" /></>}
          {verdict.word === "review" && <><path d={`M ${CX} ${CY - 15} v 11`} /><circle cx={CX} cy={CY + 1} r="0.6" strokeWidth="4" /></>}
          {(verdict.word === "measuring" || verdict.word === "partial") && <g fill={VAR[verdict.tone]} stroke="none"><circle cx={CX - 9} cy={CY - 7} r="2.4" /><circle cx={CX} cy={CY - 7} r="2.4" /><circle cx={CX + 9} cy={CY - 7} r="2.4" /></g>}
          {verdict.word === "no data" && <path d={`M ${CX - 8} ${CY - 7} h 16`} />}
        </g>
        <text x={CX} y={CY + 17} textAnchor="middle" fontSize="10" className="smcp" fill={VAR[verdict.tone]}>{verdict.word}</text>
      </svg>
      <div className="mt-1 flex flex-wrap items-center justify-center gap-x-4 gap-y-0.5 border-t border-rule pt-2 text-[0.8rem] italic text-ink-2">
        {[{ t: "clean", c: "var(--ok)", d: undefined as string | undefined }, { t: "flagged", c: "var(--bad)", d: "5 3" }, { t: "not measured yet", c: "var(--ink-3)", d: "0.1 4.2" }].map(k => (
          <span key={k.t} className="inline-flex items-center gap-1.5">
            <svg viewBox="0 0 24 6" className="h-1.5 w-6" aria-hidden><line x1="2" y1="3" x2="22" y2="3" stroke={k.c} strokeWidth={k.d?.startsWith("0.1") ? 3 : 3.4} strokeDasharray={k.d} strokeLinecap="round" /></svg>{k.t}
          </span>
        ))}
      </div>
    </Card>
  );
}

/** The ledger as the chain it is: one block per event, newest on the right, every block linked to the one before. */
function ChainStrip({ events, head }: { events: LedgerEvent[]; head: string | null }) {
  const N = 28;
  const shown = events.slice(-N), hidden = events.length - shown.length;
  const tint = (e: LedgerEvent): string => {
    const d = describe(e);
    if (d && d.tone === "bad") return "bg-bad";
    if (d && d.tone === "warn") return "bg-warn";
    if (e.type === "tool.call") return "bg-accent";
    if (e.type === "llm.response") return "bg-ink-3";
    return "bg-rule-2";
  };
  return (
    <Card className="p-3.5">
      <div className="flex items-baseline gap-2">
        <Label className="text-ink">Hash chain</Label>
        <span className="text-[0.8rem] italic text-ink-3">{events.length} event{events.length === 1 ? "" : "s"}{hidden > 0 ? ` · last ${shown.length} shown` : ""}</span>
        <span className="ml-auto text-[0.78rem] text-ink-3">head <Hash h={head ?? events[events.length - 1]?.hash} className="text-ink-2" /></span>
      </div>
      <div className="relative mt-3 flex h-7 items-center gap-[3px]">
        <span aria-hidden className="absolute inset-x-0 top-1/2 h-px bg-rule-2" />
        {shown.length === 0 && <span className="relative text-[0.85rem] italic text-ink-3">Blocks appear as events are written.</span>}
        {shown.map(e => (
          <span key={e.id} title={`#${e.id} · ${e.type}\n${e.hash.slice(0, 16)}… ← ${e.prev_hash.slice(0, 8)}…`}
            className={`rise relative h-5 min-w-[5px] max-w-[13px] flex-1 rounded-[2px] ${tint(e)} shadow-[0_0_0_2px_var(--sheet)]`} />
        ))}
      </div>
      <div className="mt-2.5 flex flex-wrap items-center gap-x-3.5 gap-y-0.5 text-[0.76rem] italic text-ink-3">
        {[["bg-accent", "tool call"], ["bg-warn", "needs review"], ["bg-bad", "flagged"], ["bg-ink-3", "agent text"]].map(([c, t]) => (
          <span key={t} className="inline-flex items-center gap-1"><i className={`h-2 w-2 rounded-[2px] ${c}`} />{t}</span>
        ))}
      </div>
    </Card>
  );
}

export function BlastPanel({ events, report, running }: { events: LedgerEvent[]; report: Report | null; running: boolean }) {
  const gauges = gaugesOf(events, running);
  const feed = groupLines(events);
  const cards = gauges.filter(g => g.key !== "sbx");
  const sbx = gauges.find(g => g.key === "sbx")!;
  const phase: Phase = running ? "measuring" : events.length === 0 ? "idle" : "partial";
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PaneHead title="Blast radius" right={running && <Chip tone="info"><Pulse tone="info" /> measuring</Chip>} />
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
        <RadiusDial gauges={gauges} phase={phase} />
        <div className="grid grid-cols-2 gap-2.5">
          {cards.map(g => <GaugeCard key={g.key} g={g} />)}
          <GaugeCard g={sbx} wide />
        </div>
        {report
          ? <Seal state={report.ledger.verified ? "ok" : "bad"} title={report.ledger.verified ? "Ledger chain verified" : "Ledger chain FAILED"}>{report.ledger.detail}</Seal>
          : <Seal state="idle" title="Ledger chain">Every event is hash-chained. The chain is verified when the task completes.</Seal>}
        <ChainStrip events={events} head={report?.ledger.head_hash ?? null} />
        <div>
          <SectionHead title="Event log" right={<span className="text-[0.8rem] italic text-ink-3">{feed.length} line{feed.length === 1 ? "" : "s"}</span>} />
          <ul className="mt-2.5 space-y-2 text-[0.88rem] leading-snug">
            {feed.length === 0 && <li className="italic text-ink-3">Nothing notable yet.</li>}
            {feed.map(r => (
              <li key={r.key} className={`flex gap-2.5 ${NOTE[r.tone]}`}>
                <span aria-hidden className={`mt-[0.5rem] h-1.5 w-1.5 shrink-0 rounded-full ${DOT[r.tone]}`} />
                <span className="min-w-0 break-words">
                  {r.text}{r.count > 1 && <span className="ml-1.5 rounded-[3px] bg-sunken px-1 text-[0.8rem] tabular-nums text-ink-2">×{r.count}</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

/* ───────────────────────── Approval ───────────────────────── */

export function ApprovalModal({ ev, taskId }: { ev: LedgerEvent; taskId: string }) {
  const p = ev.payload;
  const [left, setLeft] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const peak = useRef(0);

  // Countdown = server-side (expires_at - event ts), so clock drift between WSL and
  // the browser can't distort it; the server denies on timeout regardless.
  useEffect(() => {
    let alive = true, timer: number | undefined;
    listApprovals(taskId).then(({ pending }) => {
      const a = pending.find(x => x.id === p.id);
      if (!alive || !a) return;
      const deadline = Date.now() + (a.expires_at - ev.ts) * 1000;
      const tick = () => {
        const v = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
        peak.current = Math.max(peak.current, v);
        setLeft(v);
      };
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

  const frac = left !== null && peak.current > 0 ? left / peak.current : 1;
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 p-4 backdrop-blur-[4px]" role="dialog" aria-modal="true" aria-labelledby="approval-title">
      <div className="rise panel relative w-[36rem] max-w-full overflow-hidden border-warn/60 p-6 shadow-lift">
        <span aria-hidden className="absolute inset-x-0 top-0 h-[3px] bg-warn" style={{ boxShadow: "0 0 24px var(--warn)" }} />
        <div className="flex items-start justify-between gap-3">
          <div>
            <Label className="text-warn">Notice · action pending</Label>
            <h2 id="approval-title" className="display mt-0.5 text-[2rem] text-ink">Approval required</h2>
          </div>
          <Chip tone="warn" dot className="mt-1.5">{p.risk} risk</Chip>
        </div>
        <p className="mt-3 italic text-ink-2">The agent wants to run <span className="not-italic text-ink">{p.tool}</span>:</p>
        <code className={`${LISTING} mt-1.5 block max-h-36 overflow-auto break-all px-3 py-2.5`}>{p.summary}</code>
        {(p.reasons ?? []).length > 0 && (
          <>
            <Label className="mt-4 block">Why it was flagged</Label>
            <ol className="mt-1.5 list-decimal space-y-0.5 pl-6 text-ink marker:text-warn">
              {(p.reasons ?? []).map((r: string, i: number) => <li key={i}>{r}</li>)}
            </ol>
          </>
        )}
        {err && <p role="alert" className="mt-3 text-[0.9rem] text-bad">{err}</p>}
        <div className="mt-6 flex items-center gap-4 border-t border-rule pt-4">
          <Donut size={58} stroke={9} total={1} segments={[{ value: frac, tone: "warn" }]} label="Time left to decide">
            <span className="text-[1rem] font-bold tabular-nums text-ink">{left ?? "·"}</span>
          </Donut>
          <span className="text-[0.9rem] italic leading-snug text-ink-2">
            {left === null ? "Auto-denies on timeout." : <>Denied automatically in <b className="not-italic text-ink">{left}s</b> if nobody answers.</>}
          </span>
          <Btn variant="danger" onClick={() => decide(false)} disabled={busy} className="ml-auto">Deny</Btn>
          <Btn variant="warn" onClick={() => decide(true)} disabled={busy}>Approve</Btn>
        </div>
      </div>
    </div>
  );
}
