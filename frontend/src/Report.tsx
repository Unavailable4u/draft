import { useCallback, useEffect, useState } from "react";
import { downloadReport, getReport, verifyLedger } from "./api";
import type { Dimension, Report, Verification } from "./api";

const ID_RE = /^[0-9a-f]{8}$/;
const HIDDEN = new Set(["status", "note", "evidence"]);

function fmt(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
  if (typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    return e.length ? e.map(([k, x]) => `${k}: ${x}`).join(" · ") : "—";
  }
  return String(v);
}

const STATUS_STYLE: Record<string, string> = {
  measured: "border-emerald-800 text-emerald-400",
  in_progress: "border-amber-800 text-amber-400",
  not_measured: "border-zinc-700 text-zinc-500",
};

function DimensionCard({ name, d }: { name: string; d: Dimension }) {
  const style = STATUS_STYLE[d.status] ?? STATUS_STYLE.not_measured;
  const rows = Object.entries(d).filter(([k]) => !HIDDEN.has(k));
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs uppercase tracking-wide text-zinc-400">{name}</h3>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${style}`}>{d.status.replace("_", " ")}</span>
      </div>
      {d.status === "not_measured"
        ? <p className="mt-2 text-xs text-zinc-500">{d.note ?? "No claim is made for this dimension."}</p>
        : <dl className="mt-2 space-y-1 text-xs">
            {rows.map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="w-32 shrink-0 text-zinc-500">{k.replace(/_/g, " ")}</dt>
                <dd className="break-words text-zinc-200">{fmt(v)}</dd>
              </div>
            ))}
            {d.evidence && d.evidence.length > 0 && (
              <div className="flex gap-2 border-t border-zinc-800 pt-1">
                <dt className="w-32 shrink-0 text-zinc-500">evidence (event ids)</dt>
                <dd className="break-words text-amber-300">{d.evidence.join(", ")}</dd>
              </div>
            )}
          </dl>}
    </section>
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
  const btn = "rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-300 hover:border-zinc-500 disabled:opacity-40";
  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4">
      <div className="mx-auto max-w-4xl space-y-4">
        <div className="flex items-center gap-2">
          <input value={id} onChange={e => setId(e.target.value.trim())} placeholder="task id (8 hex chars)"
            onKeyDown={e => { if (e.key === "Enter") load(id); }} maxLength={8}
            className="w-44 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs outline-none focus:border-emerald-600" />
          <button className={btn} onClick={() => load(id)} disabled={busy || !id}>Load</button>
          {err && <span className="text-xs text-red-400">{err}</span>}
        </div>

        {!report && !err && <p className="text-sm text-zinc-500">Run a task in the Workspace, or enter a task id to open its report.</p>}

        {report && (<>
          <header className="rounded border border-zinc-800 bg-zinc-900 p-4">
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-xs text-zinc-500">Blast Radius report · <span className="font-mono">{report.task_id}</span></div>
                <p className="mt-1 text-zinc-200">{report.task}</p>
                {report.summary && <p className="mt-2 text-sm text-zinc-400">{report.summary}</p>}
              </div>
              <div className="text-right">
                <div className={`text-lg font-semibold ${quiet ? "text-zinc-300" : report.outcome === "finished" ? "text-emerald-400" : report.complete ? "text-amber-400" : "text-zinc-400"}`}>
                  {!report.complete ? "running" : quiet ? "answered · no commands" : report.outcome}
                </div>
                <div className="text-xs text-zinc-500">{report.steps} steps · {report.tool_calls} tool calls</div>
              </div>
            </div>
            <div className={`mt-3 rounded border p-2 text-xs ${report.ledger.verified ? "border-emerald-800" : "border-red-800"}`}>
              <span className={report.ledger.verified ? "text-emerald-400" : "text-red-400"}>
                Ledger chain {report.ledger.verified ? "verified ✓" : "FAILED ✗"}
              </span>
              <span className="text-zinc-400"> — {report.ledger.detail}</span>
              <div className="mt-1 break-all font-mono text-[11px] text-zinc-500">head {report.ledger.head_hash}</div>
              {ver && (
                <div className={`mt-1 ${ver.verified ? "text-emerald-400" : "text-red-400"}`}>
                  Re-verified just now from the stored ledger: {ver.verified ? "intact" : "TAMPERED"} — {ver.detail}
                </div>
              )}
            </div>
            <div className="mt-3 flex gap-2">
              <button className={btn} onClick={check} disabled={busy}>Verify ledger now</button>
              <button className={btn} onClick={() => load(report.task_id)} disabled={busy}>Refresh</button>
              <button className={`${btn} ml-auto`} onClick={() => save("html")}>Export HTML</button>
              <button className={btn} onClick={() => save("json")}>Export JSON</button>
            </div>
          </header>

          <div className="grid grid-cols-2 gap-3">
            {Object.entries(report.dimensions).map(([k, d]) => <DimensionCard key={k} name={k} d={d} />)}
          </div>
          <p className="text-xs text-zinc-600">{report.note}</p>
        </>)}
      </div>
    </div>
  );
}
