import { useEffect, useRef, useState } from "react";
import type { LedgerEvent, Profile, Report } from "./api";
import { listApprovals, listScenarios, resolveApproval } from "./api";
import type { ScenarioInfo } from "./api";
import { blast, describe, groupLines, measure, toolLine } from "./derive";
import { Md } from "./Md";
import type { Tone } from "./derive";

const TONE: Record<Tone, string> = { ok: "ml-positive", bad: "ml-negative", warn: "ml-warning", info: "ml-muted" };

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
  return <div className="ml-task-form">
    <div className="ml-form-head"><span className="ml-kicker">01 / TASK COMPOSER</span><span className="ml-form-asterisk">✳</span></div>
    <h2>What should the agent do?</h2>
    <p className="ml-form-subtitle">Give it a goal. We'll show what happens inside the sandbox.</p>
    {scenarios.length > 0 && <div className="ml-field"><label htmlFor="ml-scenario">STARTING POINT</label>
      <select id="ml-scenario" value={scenario} onChange={e => setScenario(e.target.value)} title="A prepared task with files and a hidden success check">
        <option value="">Custom task</option>
        {scenarios.map(s => <option key={s.id} value={s.id} disabled={!s.available}>{s.title}{s.available ? "" : s.needs_browser && s.missing_hosts.length === 0 ? " (browser image required)" : ` (requires ${s.missing_hosts.join(", ") || "browser image"})`}</option>)}
      </select>
    </div>}
    <div className="ml-field ml-prompt-field"><label htmlFor="ml-task-input">TASK INSTRUCTIONS <span>MAX 4,000</span></label>
      <textarea id="ml-task-input" value={sc ? sc.task : text} onChange={e => setText(e.target.value)} rows={6} maxLength={4000}
        readOnly={!!sc} onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); }}
        placeholder={'e.g. Inspect this project, identify the failing test and fix it. Explain each change.'} />
      <div className="ml-prompt-hint"><span>{sc ? "PREPARED SCENARIO" : "DESCRIBE THE OUTCOME, NOT JUST THE COMMAND"}</span><span>{(sc ? sc.task : text).length}/4000</span></div>
    </div>
    <div className="ml-form-options">
      <div className="ml-field"><label htmlFor="ml-profile">POLICY PROFILE</label><select id="ml-profile" value={profile} onChange={e => setProfile(e.target.value as Profile)}><option value="strict">Strict</option><option value="observe">Observe</option></select></div>
      <div className="ml-field"><label htmlFor="ml-hold">SANDBOX HOLD</label><select id="ml-hold" value={hold} onChange={e => setHold(Number(e.target.value))} title="Keep the sandbox open after the agent stops so it can be inspected or rewound"><option value={0}>No hold</option><option value={60}>1 minute</option><option value={180}>3 minutes</option><option value={600}>10 minutes</option></select></div>
    </div>
    <button className="ml-run-button" onClick={go} disabled={running || !(sc || text.trim())}><span>{running ? "Execution in progress" : "Run in sandbox"}</span><span aria-hidden="true">{running ? "◌" : "↗"}</span></button>
    <div className="ml-form-help"><span className="ml-help-glyph">◇</span> Isolated execution · Observable activity · {profile === "strict" ? "Strict policy" : "Observe policy"}</div>
    {error && <p role="alert" className="ml-form-error">{error}</p>}
  </div>;
}

const STEP_TYPES = new Set(["task.start", "llm.response", "tool.call", "tool.result", "policy.decision", "approval.requested", "approval.granted", "approval.denied", "task.end"]);

function Step({ e, calls, lastText }: { e: LedgerEvent; calls: number; lastText: string }) {
  const p = e.payload;
  const kind = e.type;
  if (kind === "task.start") return <li className="ml-step ml-step-start"><span className="ml-step-marker">◈</span><div className="ml-step-body"><span className="ml-step-tag">SESSION STARTED</span><p>Policy profile <strong>{String(p.profile ?? "unknown")}</strong></p></div></li>;
  if (kind === "llm.response") return p.text ? <li className="ml-step ml-step-response"><span className="ml-step-marker">✳</span><div className="ml-step-body"><span className="ml-step-tag">AGENT RESPONSE</span><div className="ml-step-prose"><Md>{String(p.text)}</Md></div></div></li> : null;
  if (kind === "tool.call") return <li className="ml-step ml-step-tool"><span className="ml-step-marker">›</span><div className="ml-step-body"><span className="ml-step-tag">TOOL CALL <b>{String(p.tool ?? "tool")}</b></span><code className="ml-step-code">{toolLine(p)}</code></div></li>;
  if (kind === "tool.result") return <li className="ml-step ml-step-result"><span className="ml-step-marker">·</span><div className="ml-step-body"><details><summary>View command output</summary><pre>{String(p.result ?? "")}</pre></details></div></li>;
  if (kind === "task.end") {
    const quiet = p.status === "finished" && calls === 0;
    const summary = String(p.summary ?? "");
    const repeated = summary.slice(0, 200) === lastText.slice(0, 200);
    return <li className={`ml-step ml-step-end ${p.status === "finished" ? "is-complete" : "is-warning"}`}>
      <span className="ml-step-marker">{p.status === "finished" ? "✓" : "!"}</span><div className="ml-step-body"><span className="ml-step-tag">{quiet ? "ANSWERED WITHOUT COMMANDS" : `TASK ${String(p.status).toUpperCase()}`}</span><p>{p.steps ?? 0} steps recorded</p>{summary && !repeated && <div className="ml-step-prose"><Md>{summary}</Md></div>}</div></li>;
  }
  const d = describe(e);
  return d ? <li className={`ml-step ml-step-alert ${TONE[d.tone]}`}><span className="ml-step-marker">{d.tone === "bad" ? "!" : d.tone === "warn" ? "◇" : "✓"}</span><div className="ml-step-body"><span className="ml-step-tag">{kind.replaceAll(".", " / ").toUpperCase()}</span><p>{d.text}</p></div></li> : null;
}

export function StepStream({ events }: { events: LedgerEvent[] }) {
  const bottom = useRef<HTMLDivElement>(null);
  useEffect(() => { bottom.current?.scrollIntoView({ block: "end" }); }, [events.length]);
  const steps = events.filter(e => STEP_TYPES.has(e.type));
  const calls = events.filter(e => e.type === "tool.call").length;
  const lastText = String([...events].reverse().find(e => e.type === "llm.response" && e.payload.text)?.payload.text ?? "");
  return <div className="ml-steps-scroll" aria-live="polite" aria-relevant="additions">
    {steps.length === 0 ? <div className="ml-steps-empty"><span>↳</span><strong>Nothing to trace yet.</strong><p>Once a session starts, each decision and tool action will appear here in sequence.</p></div> : null}
    <ol className="ml-step-list">{steps.map(e => <Step key={e.id} e={e} calls={calls} lastText={lastText} />)}</ol><div ref={bottom} />
  </div>;
}

function Gauge({ label, value, sub, tone, note }: { label: string; value: string | number; sub: string; tone: Tone; note?: string }) {
  return <div className="ml-gauge"><div className="ml-gauge-top"><span>{label}</span><span className={`ml-gauge-dot ${TONE[tone]}`} /></div><div className={`ml-gauge-value ${TONE[tone]}`}>{value}</div><div className="ml-gauge-sub">{sub}</div>{note && <div className="ml-gauge-note">{note}</div>}</div>;
}

const MIB = 1024 * 1024;
/** No security claim is made until the sandbox has actually been audited. */
function measuredGauges(events: LedgerEvent[], running: boolean) {
  const x = measure(events);
  const wait = running ? "Awaiting sandbox audit" : "Not measured";
  if (!x.audited) return [
    <Gauge key="fs" label="HOST FILESYSTEM" value="—" tone="info" sub={wait} />,
    <Gauge key="secrets" label="REAL SECRETS" value="—" tone="info" sub={wait} />,
    <Gauge key="compute" label="PEAK MEMORY" value="—" tone="info" sub={wait} />,
  ];
  return [
    <Gauge key="fs" label="HOST FILESYSTEM" value={x.hostBinds} tone={x.hostBinds ? "bad" : "ok"}
      sub={`Host paths mounted · ${x.rootfsChanges} system changes`} note={x.workspace ? `Workspace +${x.workspace.added} / ~${x.workspace.modified} / −${x.workspace.deleted}` : undefined} />,
    <Gauge key="secrets" label="REAL SECRETS" value={x.realSecrets.length} tone={x.realSecrets.length ? "bad" : x.decoysTripped.size ? "warn" : "ok"}
      sub={x.scanned ? "Found inside sandbox" : "Interior not scanned"} note={`${x.decoysRead.size} decoys read · ${x.decoysTripped.size} used`} />,
    <Gauge key="compute" label="PEAK MEMORY" value={`${Math.round(x.peakMem / MIB)}`} tone={x.oom ? "bad" : x.memLimit && x.peakMem / x.memLimit > 0.8 ? "warn" : "info"}
      sub={`MiB / ${Math.round(x.memLimit / MIB)} limit`} note={`${x.cpuS.toFixed(1)} CPU seconds · ${x.peakPids} PIDs${x.oom ? " · OOM KILLED" : ""}`} />,
  ];
}

export function BlastPanel({ events, report, running }: { events: LedgerEvent[]; report: Report | null; running: boolean }) {
  const m = blast(events);
  const feed = groupLines(events);
  const total = m.allowed + m.blocked;
  const pct = total ? Math.round(m.allowed / total * 100) : 0;
  return <div className="ml-blast-panel">
    <div className="ml-blast-body">
      <div className="ml-section-title"><span>NETWORK PERIMETER</span><span>01 / 03</span></div>
      <div className="ml-network-tally"><div><strong>{m.blocked}</strong><span>BLOCKED</span></div><div><strong>{m.allowed}</strong><span>ALLOWED</span></div><div><strong>{m.hosts.size}</strong><span>HOSTS SEEN</span></div></div>
      <div className="ml-network-track" aria-label={total ? `${m.allowed} allowed and ${m.blocked} blocked requests` : "No network decisions recorded"}><span style={{ width: `${pct}%` }} /></div>
      <div className="ml-track-legend"><span><i className="ml-legend-allowed" />Allowed</span><span><i className="ml-legend-blocked" />Blocked</span></div>
      <div className="ml-section-title ml-second-title"><span>POLICY & RESOURCES</span><span>02 / 03</span></div>
      <div className="ml-mini-gauges"><Gauge label="POLICY DENIALS" value={m.denied} tone={m.denied ? "warn" : "info"} sub={`${m.decisions} checks · ${m.asked} approvals`} />
        <Gauge label="SANDBOXES" value={m.created} tone="info" sub={`${m.destroyed} destroyed · ${m.rewinds} rewinds`} /></div>
      <div className="ml-mini-gauges ml-mini-gauges-three">{measuredGauges(events, running)}</div>
      <div className={`ml-integrity ${report ? report.ledger.verified ? "is-verified" : "is-failed" : "is-pending"}`}>
        <div className="ml-integrity-icon">{report ? report.ledger.verified ? "✓" : "!" : "⌁"}</div><div><strong>{report ? report.ledger.verified ? "Ledger chain verified" : "Ledger verification failed" : "Ledger verification pending"}</strong><span>{report ? report.ledger.detail : running ? "Verification follows task completion" : "Start a session to collect evidence"}</span></div>
      </div>
    </div>
    <div className="ml-security-feed"><div className="ml-section-title"><span>SECURITY EVENTS</span><span>{feed.length} ITEMS</span></div>
      <div className="ml-security-events">{feed.length === 0 ? <div className="ml-feed-empty">Events and policy interventions will be listed here as the agent works.</div> : feed.map(r => <div key={r.key} className={`ml-feed-event ${TONE[r.tone]}`}><span className="ml-feed-symbol">{r.tone === "bad" ? "!" : r.tone === "warn" ? "◇" : "↳"}</span><span>{r.text}</span>{r.count > 1 && <strong>×{r.count}</strong>}</div>)}</div>
    </div>
  </div>;
}

export function ApprovalModal({ ev, taskId }: { ev: LedgerEvent; taskId: string }) {
  const p = ev.payload;
  const [left, setLeft] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true, timer: number | undefined;
    listApprovals(taskId).then(({ pending }) => {
      const a = pending.find(x => x.id === p.id);
      if (!alive || !a) return;
      const deadline = Date.now() + (a.expires_at - ev.ts) * 1000;
      const tick = () => setLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
      tick(); timer = window.setInterval(tick, 500);
    }).catch(() => { /* the server still auto-denies on timeout */ });
    return () => { alive = false; clearInterval(timer); };
  }, [p.id, taskId, ev.ts]);
  const decide = async (approve: boolean) => {
    setBusy(true); setErr(null);
    try { await resolveApproval(p.id, approve); }
    catch (e) { setErr((e as Error).message); setBusy(false); }
  };
  return <div className="ml-modal-backdrop" role="presentation"><div className="ml-approval-modal" role="dialog" aria-modal="true" aria-labelledby="ml-approval-title">
    <div className="ml-modal-eyebrow">SECURITY GATE / HUMAN REVIEW</div><div className="ml-approval-title-row"><h2 id="ml-approval-title">Your approval is needed.</h2><span>{String(p.risk ?? "unknown").toUpperCase()} RISK</span></div>
    <p className="ml-modal-intro">The agent requested permission to execute an action that requires your decision.</p>
    <div className="ml-approval-code"><span>REQUESTED ACTION · {String(p.tool)}</span><code>{String(p.summary)}</code></div>
    <div className="ml-approval-reasons"><strong>Why this needs review</strong><ul>{(p.reasons ?? []).map((r: string, i: number) => <li key={i}>{r}</li>)}</ul></div>
    {err && <p role="alert" className="ml-form-error">{err}</p>}
    <div className="ml-approval-footer"><span>{left === null ? "Auto-denies on timeout" : `Auto-denies in ${left}s`}</span><button className="ml-deny-button" disabled={busy} onClick={() => decide(false)}>Deny action</button><button className="ml-approve-button" disabled={busy} onClick={() => decide(true)}>Approve once ↗</button></div>
  </div></div>;
}

export function Stub({ title, needs }: { title: string; needs: string }) {
  return <div className="ml-stub"><span>◇</span><h2>{title}</h2><p>{needs}</p></div>;
}
