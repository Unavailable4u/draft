import { useCallback, useEffect, useState } from "react";
import { downloadReport, getReport, verifyLedger } from "./api";
import type { Dimension, Report, Verification } from "./api";

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

function DimensionCard({ name, d, index }: { name: string; d: Dimension; index: number }) {
  const rows = Object.entries(d).filter(([k]) => !HIDDEN.has(k));
  const measured = d.status === "measured";
  return <section className="ml-report-dimension">
    <div className="ml-dimension-top"><span>DIMENSION / {String(index + 1).padStart(2, "0")}</span><span className={`ml-dimension-status ${measured ? "is-measured" : d.status === "in_progress" ? "is-progress" : "is-unmeasured"}`}>{String(d.status).replaceAll("_", " ")}</span></div>
    <h3>{name.replaceAll("_", " ")}</h3>
    {d.status === "not_measured" ? <p className="ml-dimension-note">{d.note ?? "No measurement available. No safety claim is made for this dimension."}</p> : <>
      <dl className="ml-dimension-details">{rows.map(([k, v]) => <div key={k}><dt>{k.replaceAll("_", " ")}</dt><dd>{fmt(v)}</dd></div>)}</dl>
      {d.note && <p className="ml-dimension-note">{d.note}</p>}
      {d.evidence && d.evidence.length > 0 && <div className="ml-evidence-ids"><span>EVIDENCE / LEDGER IDS</span><code>{d.evidence.join(" · ")}</code></div>}
    </>}
  </section>;
}

export function ReportScreen({ taskId, done }: { taskId: string | null; done: boolean }) {
  const [id, setId] = useState(taskId ?? "");
  const [report, setReport] = useState<Report | null>(null);
  const [ver, setVer] = useState<Verification | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async (tid: string) => {
    if (!ID_RE.test(tid)) { setErr("A task ID must contain exactly eight hexadecimal characters."); return; }
    setBusy(true); setErr(null); setVer(null);
    try { setReport(await getReport(tid)); }
    catch (e) { setReport(null); setErr((e as Error).message); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => { if (taskId) { setId(taskId); load(taskId); } }, [taskId, done, load]);
  const check = async () => {
    if (!report) return;
    setBusy(true); setErr(null);
    try { setVer(await verifyLedger(report.task_id)); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  const save = (f: "json" | "html") => { if (report) downloadReport(report.task_id, f).catch(e => setErr((e as Error).message)); };
  const quiet = !!(report?.complete && report.outcome === "finished" && report.tool_calls === 0);
  return <div className="ml-report-screen">
    <div className="ml-report-wrap">
      <div className="ml-report-toolbar"><div><span className="ml-kicker">REPORT LOOKUP</span><p>Open an existing run by its short ID.</p></div>
        <div className="ml-report-lookup"><input value={id} onChange={e => setId(e.target.value.trim())} maxLength={8} aria-label="Task ID" placeholder="8-character task ID" onKeyDown={e => { if (e.key === "Enter") load(id); }} /><button onClick={() => load(id)} disabled={busy || !id}>Load report ↗</button></div>
      </div>
      {err && <div role="alert" className="ml-report-error">{err}</div>}
      {!report && !err && <div className="ml-report-empty"><span>◇</span><h2>No report selected.</h2><p>Run a task in the Workspace or enter its ID above. Actual measurements and verifiable evidence will be shown here when available.</p></div>}
      {report && <>
        <section className="ml-report-hero"><div className="ml-report-hero-main"><div className="ml-kicker">SECURITY EVIDENCE / RUN {report.task_id.toUpperCase()}</div>
          <h2>Inside the <em>blast radius.</em></h2><p className="ml-report-task">{report.task || "No task description recorded"}</p>
          {report.summary && <p className="ml-report-summary">{report.summary}</p>}</div>
          <div className={`ml-report-outcome ${report.complete && report.outcome === "finished" ? "is-success" : "is-incomplete"}`}><small>SESSION OUTCOME</small><strong>{!report.complete ? "In progress" : quiet ? "Answered only" : report.outcome}</strong><span>{quiet ? "No commands were run" : report.complete ? "Recorded in task ledger" : "Collecting evidence"}</span></div>
        </section>
        <div className="ml-report-facts"><div><span>EXECUTION STEPS</span><strong>{report.steps}</strong></div><div><span>TOOL INVOCATIONS</span><strong>{report.tool_calls}</strong></div><div><span>LEDGER EVENTS</span><strong>{report.ledger.events}</strong></div><div><span>AUDIT DIMENSIONS</span><strong>{Object.keys(report.dimensions).length}</strong></div></div>
        <section className={`ml-ledger-proof ${report.ledger.verified ? "is-verified" : "is-failed"}`}><div className="ml-ledger-proof-top"><div className="ml-ledger-proof-mark">{report.ledger.verified ? "✓" : "!"}</div><div><span>INTEGRITY / HASH CHAIN</span><h3>{report.ledger.verified ? "Verified ledger chain" : "Ledger integrity not verified"}</h3><p>{report.ledger.detail}</p></div></div>
          <div className="ml-ledger-hash"><span>CHAIN HEAD</span><code>{report.ledger.head_hash ?? "Not available"}</code></div>
          {ver && <div className={`ml-ledger-recheck ${ver.verified ? "is-verified" : "is-failed"}`}>Rechecked against the stored ledger: {ver.verified ? "intact" : "verification failed"} · {ver.detail}</div>}
          <div className="ml-report-actions"><button onClick={check} disabled={busy}>↺ Re-verify integrity</button><button onClick={() => load(report.task_id)} disabled={busy}>Refresh report</button><div className="ml-report-actions-spacer" /><button onClick={() => save("html")}>Export HTML ↗</button><button onClick={() => save("json")}>Export JSON ↗</button></div>
        </section>
        <div className="ml-report-section-label"><span>AUDIT DIMENSIONS</span><span>ONLY MEASURED DATA IS REPORTED</span></div>
        <div className="ml-report-grid">{Object.entries(report.dimensions).map(([k, d], i) => <DimensionCard key={k} name={k} d={d} index={i} />)}</div>
        <p className="ml-report-footnote">{report.note}</p>
      </>}
    </div>
  </div>;
}
