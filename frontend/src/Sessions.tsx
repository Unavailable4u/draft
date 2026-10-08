import { useCallback, useEffect, useState } from "react";
import { listTasks } from "./api";
import type { TaskSummary } from "./api";

type Filter = "all" | "task" | "attack";

function badge(t: TaskSummary): { text: string; cls: string } {
  const s = t.status;
  if (s === "running") return { text: "running", cls: "border-amber-700 text-amber-300" };
  if (s === "finished") {
    return t.kind === "task" && t.tool_calls === 0
      ? { text: "answered · no commands", cls: "border-zinc-700 text-zinc-400" }
      : { text: "finished", cls: "border-emerald-800 text-emerald-400" };
  }
  if (s.startsWith("halted")) return { text: s, cls: "border-amber-800 text-amber-400" };
  if (s.startsWith("error")) return { text: s, cls: "border-red-800 text-red-400" };
  return { text: s, cls: "border-zinc-700 text-zinc-500" };   // incomplete: no task.end was ever written
}

const num = (n: number, bad: boolean) => <span className={n && bad ? "text-red-400" : "text-zinc-500"}>{n}</span>;

export function SessionsScreen({ onOpen, onReport }: { onOpen: (id: string) => void; onReport: (id: string) => void }) {
  const [rows, setRows] = useState<TaskSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");

  const load = useCallback(() => {
    listTasks(100).then(r => { setRows(r.tasks); setErr(null); }).catch(e => setErr((e as Error).message));
  }, []);
  useEffect(load, [load]);
  const anyRunning = rows?.some(r => r.status === "running") ?? false;
  useEffect(() => {
    if (!anyRunning) return;
    const i = setInterval(load, 3000);
    return () => clearInterval(i);
  }, [anyRunning, load]);

  const shown = (rows ?? []).filter(r => filter === "all" || r.kind === filter);
  const btn = "rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-300 hover:border-zinc-500";
  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4">
      <div className="mx-auto max-w-6xl space-y-3">
        <div className="flex items-center gap-2">
          {(["all", "task", "attack"] as Filter[]).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`rounded px-3 py-1 text-xs ${filter === f ? "bg-zinc-800 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}>
              {f === "all" ? "All" : f === "task" ? "Tasks" : "Attacks"}
            </button>
          ))}
          <button className={`${btn} ml-auto`} onClick={load}>Refresh</button>
          {err && <span className="text-xs text-red-400">{err}</span>}
        </div>
        {rows && shown.length === 0 && (
          <p className="text-sm text-zinc-500">No sessions yet. Run a task in the Workspace or an attack in the Attack Lab.</p>
        )}
        {shown.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="text-zinc-500">
              <tr>{["Started", "", "Task", "Status", "Time", "Blocked", "Denied", "Ledger", ""].map((h, i) => (
                <th key={i} className="border-b border-zinc-800 px-2 py-1 font-normal">{h}</th>))}</tr>
            </thead>
            <tbody>
              {shown.map(r => {
                const b = badge(r);
                return (
                  <tr key={r.task_id} className="border-b border-zinc-900 hover:bg-zinc-900/60">
                    <td className="whitespace-nowrap px-2 py-1.5 text-zinc-400">{r.started ? new Date(r.started * 1000).toLocaleString() : "—"}</td>
                    <td className="px-2 py-1.5"><span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] uppercase text-zinc-400">{r.kind}</span></td>
                    <td className="max-w-md truncate px-2 py-1.5 text-zinc-200" title={r.task}>{r.task || <i className="text-zinc-600">no task text</i>}</td>
                    <td className="px-2 py-1.5"><span className={`whitespace-nowrap rounded border px-1.5 py-0.5 ${b.cls}`}>{b.text}</span></td>
                    <td className="px-2 py-1.5 text-zinc-400">{r.duration_s !== null ? `${r.duration_s.toFixed(1)}s` : "—"}</td>
                    <td className="px-2 py-1.5">{num(r.egress_blocked, true)}</td>
                    <td className="px-2 py-1.5">{num(r.denied, true)}</td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      {r.verified ? <span className="text-emerald-400">✓ {r.events}</span> : <span className="text-red-400">✗ broken</span>}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-right">
                      <button className={btn} onClick={() => onOpen(r.task_id)}>Replay</button>{" "}
                      <button className={btn} onClick={() => onReport(r.task_id)}>Report</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
