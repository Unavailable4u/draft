import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { downloadReport, getReport, verifyLedger } from "./api";
import type { Dimension, Report, Verification } from "./api";
import { Btn, Card, Chip, EDGE, FIELD, INK, Label, Mark, Meter, Row, Seal, Spin, Stat, BAR } from "./ui";
import type { Tint } from "./ui";

const ID_RE = /^[0-9a-f]{8}$/;
const HIDDEN = new Set(["status", "note", "evidence"]);

function fmt(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (Array.isArray(v)) return v.length ? v.map(x => (x !== null && typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") : "—";
  if (typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    return e.length ? e.map(([k, x]) => `${k}: ${fmt(x)}`).join(" · ") : "—";
  }
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}

const STATUS_TONE: Record<string, Tint> = { measured: "ok", in_progress: "info", not_measured: "mute" };
const MIB = 1024 * 1024;
const n = (v: unknown): number => (typeof v === "number" && isFinite(v) ? v : 0);

/** A proportional bar made of labelled parts. Parts with no value are dropped, and no parts at all says so. */
function Parts({ parts, empty }: { parts: { v: number; tone: Tint; label: string }[]; empty: string }) {
  const used = parts.filter(p => p.v > 0), total = used.reduce((s, p) => s + p.v, 0);
  if (total === 0) return <p className="text-[0.9rem] italic text-ink-3">{empty}</p>;
  return (
    <div>
      <div className="flex h-2.5 gap-[2px] overflow-hidden rounded-full">
        {used.map(p => <span key={p.label} className={`${BAR[p.tone]} first:rounded-l-full last:rounded-r-full`} style={{ flexGrow: p.v, flexBasis: 0 }} title={`${p.label}: ${p.v}`} />)}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3.5 gap-y-0.5 text-[0.84rem] text-ink-2">
        {used.map(p => <span key={p.label} className="inline-flex items-center gap-1.5"><i className={`h-2 w-2 rounded-full ${BAR[p.tone]}`} /><b className="tabular-nums text-ink">{p.v}</b> {p.label}</span>)}
      </div>
    </div>
  );
}

/** The one picture that summarises a dimension, drawn from the same numbers listed under it. */
function Headline({ name, d }: { name: string; d: Dimension }): ReactNode {
  if (d.status === "not_measured") return null;
  if (name === "network")
    return <Parts empty="No network requests were made." parts={[{ v: n(d.allowed), tone: "ok", label: "allowed" }, { v: n(d.blocked), tone: "bad", label: "blocked" }]} />;
  if (name === "policy") {
    const a = (d.by_action ?? {}) as Record<string, number>;
    return <Parts empty="No commands were checked." parts={[
      { v: n(a.allow), tone: "ok", label: "allowed" }, { v: n(a.allow_in_sandbox), tone: "info", label: "ran in sandbox" },
      { v: n(a.require_approval), tone: "warn", label: "needed approval" }, { v: n(a.deny), tone: "bad", label: "denied" }]} />;
  }
  if (name === "compute") {
    const mem = n(d.memory_limit_bytes) ? n(d.peak_memory_bytes) / n(d.memory_limit_bytes) : 0, pid = n(d.pids_limit) ? n(d.peak_pids) / n(d.pids_limit) : 0;
    return (
      <div className="space-y-2.5">
        <div><div className="mb-1 flex justify-between text-[0.86rem] text-ink-2"><span>peak memory</span><span className="tabular-nums text-ink"><b>{Math.round(n(d.peak_memory_bytes) / MIB)}</b> of {Math.round(n(d.memory_limit_bytes) / MIB)} MiB</span></div>
          <Meter value={mem} tone={mem > 0.8 ? "warn" : "ok"} /></div>
        <div><div className="mb-1 flex justify-between text-[0.86rem] text-ink-2"><span>peak processes</span><span className="tabular-nums text-ink"><b>{n(d.peak_pids)}</b> of {n(d.pids_limit)}</span></div>
          <Meter value={pid} tone={pid > 0.8 ? "warn" : "ok"} /></div>
      </div>
    );
  }
  if (name === "time")
    return <Parts empty="No timing was recorded." parts={[{ v: n(d.active_s), tone: "info", label: "s working" }, { v: n(d.approval_wait_s), tone: "warn", label: "s waiting on a human" }]} />;
  if (name === "secrets") {
    const planted = n(d.decoys_planted), read = (d.decoys_read ?? []).length, tripped = (d.decoys_tripped ?? []).length;
    const dots = Array.from({ length: Math.max(planted, read) }, (_, i) => (i < tripped ? "bad" : i < read ? "warn" : "ok") as Tint);
    return (
      <div>
        <div className="flex flex-wrap gap-1.5">
          {dots.map((t, i) => <span key={i} className={`h-3.5 w-3.5 rounded-full border ${t === "ok" ? "border-ok/60" : `${BAR[t]} border-transparent`}`} style={t === "ok" ? undefined : { boxShadow: `0 0 8px var(--${t})` }} />)}
          {dots.length === 0 && <span className="text-[0.9rem] italic text-ink-3">No decoys were planted.</span>}
        </div>
        <div className="mt-1.5 text-[0.84rem] text-ink-2">
          {dots.length > 0 && <><b className="text-ink">{planted}</b> decoys planted · <b className="text-warn">{read}</b> read · <b className="text-bad">{tripped}</b> used · </>}
          <b className={d.real_secrets_in_sandbox ? "text-bad" : "text-ok"}>{d.real_secrets_in_sandbox ? "a real secret was found" : "no real secret in the sandbox"}</b>
        </div>
      </div>
    );
  }
  if (name === "filesystem") {
    const w = d.workspace as { added_count?: number; modified_count?: number; deleted_count?: number } | null;
    return (
      <div className="flex flex-wrap items-center gap-2 text-[0.9rem]">
        <Chip tone={(d.host_binds ?? []).length ? "bad" : "ok"} dot>{(d.host_binds ?? []).length ? `${(d.host_binds ?? []).length} host paths mounted` : "no host paths mounted"}</Chip>
        <Chip>{n(d.rootfs_changes)} system files changed</Chip>
        {w && <span className="font-mono text-[0.88rem]"><span className="text-ok">+{n(w.added_count)}</span> <span className="text-warn">~{n(w.modified_count)}</span> <span className="text-bad">−{n(w.deleted_count)}</span> <span className="font-sans text-ink-3">in /workspace</span></span>}
      </div>
    );
  }
  if (name === "persistence")
    return (
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[0.9rem] text-ink-2">
        <span><b className="text-ink tabular-nums">{n(d.snapshots_taken)}</b> snapshots</span>
        <span><b className="text-ink tabular-nums">{n(d.rewinds)}</b> rewinds</span>
        <span className={d.final_sandbox_destroyed ? "text-ok" : "text-warn"}>{d.final_sandbox_destroyed ? "sandbox destroyed afterwards" : "final sandbox not confirmed destroyed"}</span>
      </div>
    );
  return null;
}

function DimensionCard({ no, name, d, delay }: { no: number; name: string; d: Dimension; delay: number }) {
  const tone = STATUS_TONE[d.status] ?? "mute";
  const rows = Object.entries(d).filter(([k]) => !HIDDEN.has(k));
  return (
    <Card className="p-4">
      <div style={{ animationDelay: `${delay}ms` }} className="rise">
        <div className="flex items-baseline gap-2.5">
          <span className="italic text-accent-ink">§{no}</span>
          <h3 className="text-[1.15rem] font-bold capitalize text-ink">{name.replace(/_/g, " ")}</h3>
          <Chip tone={tone} dot={d.status === "measured"} className="ml-auto">{d.status.replace("_", " ")}</Chip>
        </div>
        <div className="mt-3">
          {d.status === "not_measured"
            ? <p className="italic leading-snug text-ink-2">{d.note ?? "No claim is made for this dimension."}</p>
            : <Headline name={name} d={d} />}
        </div>
        {d.status !== "not_measured" && (
          <details className="mt-3 border-t border-rule pt-2.5 text-[0.9rem]">
            <summary className="italic text-ink-2">all {rows.length} measurements</summary>
            <dl className="mt-2.5 space-y-1.5">
              {rows.map(([k, v]) => <Row key={k} k={k.replace(/_/g, " ")}>{fmt(v)}</Row>)}
              {d.evidence && d.evidence.length > 0 && (
                <div className="border-t border-rule pt-1.5">
                  <Row k={<span className="italic">evidence (event ids)</span>}><span className="font-mono text-[0.85em] text-warn">{d.evidence.join(", ")}</span></Row>
                </div>
              )}
            </dl>
          </details>
        )}
      </div>
    </Card>
  );
}

export function ReportScreen({ taskId, done }: { taskId: string | null; done: boolean }) {
  const [id, setId] = useState(taskId ?? "");
  const [report, setReport] = useState<Report | null>(null);
  const [ver, setVer] = useState<Verification | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async (tid: string) => {
    if (!ID_RE.test(tid)) { setErr("Task ids are 8 hex characters."); return; }
    setBusy(true); setErr(null); setVer(null);
    try { setReport(await getReport(tid)); }
    catch (e) { setReport(null); setErr((e as Error).message); }
    finally { setBusy(false); }
  }, []);

  // Follow the workspace's task, and reload once when it finishes so the report is final.
  useEffect(() => { if (taskId) { setId(taskId); load(taskId); } }, [taskId, done, load]);

  const check = async () => {
    setBusy(true); setErr(null);
    try { setVer(await verifyLedger(report!.task_id)); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  const save = (f: "json" | "html") => downloadReport(report!.task_id, f).catch(e => setErr((e as Error).message));

  const quiet = report?.complete && report.outcome === "finished" && report.tool_calls === 0;
  const outcomeTone: Tint = !report ? "mute" : quiet ? "mute" : report.outcome === "finished" ? "ok" : report.complete ? "warn" : "info";
  const dims = report?.dimensions ?? {};
  const net = dims.network, pol = dims.policy, sec = dims.secrets, cpu = dims.compute, tim = dims.time;
  const kpis: { label: string; value: ReactNode; sub: string; tone: Tint }[] = report ? [
    net && net.status !== "not_measured" ? { label: "Requests blocked", value: n(net.blocked), sub: `of ${n(net.attempts)} network attempts`, tone: (n(net.blocked) ? "bad" : "ok") as Tint } : null,
    pol && pol.status !== "not_measured" ? { label: "Commands denied", value: n(pol.by_action?.deny), sub: `of ${n(pol.decisions)} checked · ${n(pol.approvals_requested)} sent to a human`, tone: (n(pol.by_action?.deny) ? "bad" : "ok") as Tint } : null,
    sec && sec.status !== "not_measured" ? { label: "Decoys used", value: (sec.decoys_tripped ?? []).length, sub: `${n(sec.decoys_planted)} planted · ${n(sec.exfiltration_blocked)} exfiltration blocked`, tone: ((sec.decoys_tripped ?? []).length ? "warn" : "ok") as Tint } : null,
    cpu && cpu.status !== "not_measured" ? { label: "Peak memory", value: `${Math.round(n(cpu.memory_peak_pct))}%`, sub: `${Math.round(n(cpu.peak_memory_bytes) / MIB)} of ${Math.round(n(cpu.memory_limit_bytes) / MIB)} MiB`, tone: (n(cpu.memory_peak_pct) > 80 ? "warn" : "ok") as Tint } : null,
    tim && tim.status !== "not_measured" && tim.wall_clock_s != null ? { label: "Wall clock", value: `${Math.round(n(tim.wall_clock_s))}s`, sub: `${Math.round(n(tim.active_s))}s working`, tone: "mute" as Tint } : null,
  ].filter((x): x is { label: string; value: ReactNode; sub: string; tone: Tint } => x !== null) : [];

  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-6 py-7">
      <div className="mx-auto max-w-5xl space-y-5">
        <div className="flex items-center gap-2.5">
          <Label>Task id</Label>
          <input value={id} onChange={e => setId(e.target.value.trim())} placeholder="8 hex characters"
            onKeyDown={e => { if (e.key === "Enter") load(id); }} maxLength={8} aria-label="Task id"
            className={`${FIELD} !w-44 font-mono !text-[0.88rem]`} />
          <Btn onClick={() => load(id)} disabled={busy || !id}>{busy && !report ? <Spin /> : null} Load</Btn>
          {err && <span role="alert" className="text-[0.92rem] text-bad">{err}</span>}
        </div>

        {!report && !err && (
          <div className="rise py-16 text-center">
            <Mark size={64} className="mx-auto mb-4 text-ink-3" />
            <div className="display text-[1.6rem]">No report open</div>
            <p className="mt-1.5 italic text-ink-2">Run a task in the Workspace, or enter a task id to open its report.</p>
          </div>
        )}

        {report && (<>
          <article className="rise panel relative overflow-hidden p-8">
            <Mark size={340} className="pointer-events-none absolute -right-20 -top-24 text-ink opacity-[.045]" />
            <div className="relative flex items-start gap-8">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-ink-3"><Label className="text-[0.95rem] text-accent-ink">Blast Radius Report</Label><span aria-hidden>·</span><span className="font-mono text-[0.85rem]">{report.task_id}</span></div>
                <h1 className="display mt-2.5 text-[2rem] leading-[1.14] text-ink">{report.task}</h1>
                {report.summary && (
                  <p className="mt-4 border-l-2 border-accent/70 pl-4 leading-relaxed text-ink-2">
                    <b className="mr-1.5 font-bold not-italic text-ink">Abstract.</b><span className="italic">{report.summary}</span>
                  </p>
                )}
              </div>
              <div className={`-rotate-3 shrink-0 rounded-[6px] border-[3px] border-double px-5 py-3 text-center ${outcomeTone === "mute" ? "border-rule-2" : EDGE[outcomeTone]}`}
                style={{ boxShadow: outcomeTone === "mute" ? undefined : `0 0 30px -10px var(--${outcomeTone})` }}>
                <div className={`display smcp text-[1.7rem] ${INK[outcomeTone]}`}>
                  {!report.complete ? "running" : quiet ? "answered" : report.outcome}
                </div>
                {quiet && <div className="smcp text-[0.8rem] text-ink-2">no commands</div>}
                <div className="mt-0.5 text-[0.85rem] tabular-nums text-ink-2">{report.steps} steps · {report.tool_calls} tool calls</div>
              </div>
            </div>

            {kpis.length > 0 && (
              <div className="relative mt-7 grid gap-x-6 border-y border-rule py-4" style={{ gridTemplateColumns: `repeat(${kpis.length}, minmax(0, 1fr))` }}>
                {kpis.map((k, i) => (
                  <Stat key={k.label} label={k.label} value={k.value} sub={k.sub} tone={k.tone}
                    className={`${i > 0 ? "border-l border-rule pl-5" : ""}`} />
                ))}
              </div>
            )}

            <div className="relative mt-6">
              <Seal state={report.ledger.verified ? "ok" : "bad"} title={report.ledger.verified ? "Ledger chain verified" : "Ledger chain FAILED"}>
                {report.ledger.detail}
                <div className="mt-1 break-all font-mono text-[0.78rem] text-ink-3">head {report.ledger.head_hash}</div>
                {ver && (
                  <div className={`mt-1.5 font-medium ${ver.verified ? "text-ok" : "text-bad"}`}>
                    Re-verified just now from the stored ledger: {ver.verified ? "intact" : "TAMPERED"} — <span className="font-normal text-ink-2">{ver.detail}</span>
                  </div>
                )}
              </Seal>
            </div>
            <div className="relative mt-4 flex flex-wrap gap-2">
              <Btn variant="primary" onClick={check} disabled={busy}>{busy ? <Spin /> : <span aria-hidden>⛓</span>} Verify ledger now</Btn>
              <Btn onClick={() => load(report.task_id)} disabled={busy}>Refresh</Btn>
              <Btn className="ml-auto" onClick={() => save("html")}>Export HTML</Btn>
              <Btn onClick={() => save("json")}>Export JSON</Btn>
            </div>
          </article>

          <div className="grid grid-cols-2 gap-4">
            {Object.entries(report.dimensions).map(([k, d], i) => <DimensionCard key={k} no={i + 1} name={k} d={d} delay={i * 50} />)}
          </div>
          <p className="border-t border-rule pt-2.5 text-[0.84rem] italic leading-snug text-ink-3"><span className="mr-1 not-italic">†</span>{report.note}</p>
        </>)}
      </div>
    </div>
  );
}
