import { useCallback, useEffect, useState } from "react";
import { listTasks } from "./api";
import type { TaskSummary } from "./api";
import { Btn, Card, Chip, PageHead, Segmented, Spin, Stat } from "./ui";
import type { Tint } from "./ui";

type Filter = "all" | "task" | "attack";

function badge(t: TaskSummary): { text: string; tone: Tint } {
  const s = t.status;
  if (s === "running") return { text: "running", tone: "info" };
  if (s === "finished") {
    return t.kind === "task" && t.tool_calls === 0
      ? { text: "answered · no commands", tone: "mute" }
      : { text: "finished", tone: "ok" };
  }
  if (s.startsWith("halted")) return { text: s, tone: "warn" };
  if (s.startsWith("error")) return { text: s, tone: "bad" };
  return { text: s, tone: "mute" };   // incomplete: no task.end was ever written
}

/** A count that only draws the eye when it is not zero. */
const pill = (v: number, tone: Tint) => v > 0
  ? <span className={`inline-flex min-w-[1.7rem] justify-center rounded-full px-1.5 font-bold ${tone === "bad" ? "bg-bad-wash text-bad" : "bg-warn-wash text-warn"}`}>{v}</span>
  : <span className="text-ink-3">0</span>;

const TH = "px-3 py-2.5 text-left font-normal";

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

  const all = rows ?? [];
  const shown = all.filter(r => filter === "all" || r.kind === filter);
  const verified = all.filter(r => r.verified).length;
  const blocked = all.reduce((s, r) => s + r.egress_blocked, 0), denied = all.reduce((s, r) => s + r.denied, 0);
  const calls = all.reduce((s, r) => s + r.tool_calls, 0);
  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-6 py-7">
      <div className="mx-auto max-w-7xl space-y-5">
        <PageHead eyebrow="Recorded runs" title="Sessions" sub="Every task and attack the control plane has run, each with a ledger you can replay and verify."
          right={<>
            <Segmented<Filter> label="Filter sessions" value={filter} onChange={setFilter}
              options={[{ id: "all", label: "All" }, { id: "task", label: "Tasks" }, { id: "attack", label: "Attacks" }]} />
            <Btn size="sm" onClick={load}>↻ Refresh</Btn>
          </>} />
        {err && <p role="alert" className="text-[0.92rem] text-bad">{err}</p>}
        {!rows && !err && <div className="flex items-center justify-center gap-2 py-12 italic text-ink-3"><Spin /> Loading sessions…</div>}
        {rows && all.length > 0 && (
          <Card className="rise grid grid-cols-5 gap-x-6 px-6 py-4">
            <Stat label="Sessions" value={all.length} sub={`${all.filter(r => r.kind === "task").length} tasks · ${all.filter(r => r.kind === "attack").length} attacks`} />
            <Stat label="Tool calls" value={calls} sub="commands, writes and browses" className="border-l border-rule pl-5" />
            <Stat label="Requests blocked" value={blocked} tone={blocked ? "bad" : "ok"} sub="by the egress proxy" className="border-l border-rule pl-5" />
            <Stat label="Commands denied" value={denied} tone={denied ? "bad" : "ok"} sub="by the policy engine" className="border-l border-rule pl-5" />
            <Stat label="Ledgers intact" value={<>{verified}<span className="text-[1.3rem] text-ink-3">/{all.length}</span></>}
              tone={verified === all.length ? "ok" : "bad"} sub="hash chain verified" className="border-l border-rule pl-5" />
          </Card>
        )}
        {rows && shown.length === 0 && (
          <p className="py-10 text-center italic text-ink-2">No sessions yet. Run a task in the Workspace or an attack in the Attack Lab.</p>
        )}
        {shown.length > 0 && (
          <figure className="rise">
            <Card className="overflow-x-auto">
              <table className="w-full text-[0.93rem]">
                <thead className="smcp text-[0.88rem] text-ink-2">
                  <tr className="border-b border-rule-2 bg-sunken/50">
                    {["Started", "", "Task", "Status", "Time", "Blocked", "Denied", "Ledger", ""].map((h, i) => (
                      <th key={i} className={`${TH} ${i >= 4 && i <= 6 ? "!text-right" : ""}`}>{h}</th>))}
                  </tr>
                </thead>
                <tbody>
                  {shown.map(r => {
                    const b = badge(r);
                    return (
                      <tr key={r.task_id} className="border-b border-rule/70 transition last:border-0 hover:bg-raised">
                        <td className="whitespace-nowrap px-3 py-2.5 tabular-nums text-ink-2">{r.started ? new Date(r.started * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "—"}</td>
                        <td className="px-3 py-2.5"><Chip tone={r.kind === "attack" ? "warn" : "info"}>{r.kind}</Chip></td>
                        <td className="max-w-[18rem] truncate px-3 py-2.5 text-ink" title={r.task}>{r.task || <i className="text-ink-3">no task text</i>}</td>
                        <td className="px-3 py-2.5"><Chip tone={b.tone} dot className="max-w-[11rem]"><span className="truncate" title={b.text}>{b.text}</span></Chip></td>
                        <td className="px-3 py-2.5 text-right tabular-nums text-ink-2">{r.duration_s !== null ? `${r.duration_s.toFixed(1)}s` : "—"}</td>
                        <td className="px-3 py-2.5 text-right tabular-nums">{pill(r.egress_blocked, "bad")}</td>
                        <td className="px-3 py-2.5 text-right tabular-nums">{pill(r.denied, "bad")}</td>
                        <td className="whitespace-nowrap px-3 py-2.5 tabular-nums">
                          {r.verified ? <span className="text-ok">✓ <span className="text-ink-2">{r.events}</span></span> : <span className="font-bold text-bad">✗ broken</span>}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5 text-right">
                          <Btn size="sm" onClick={() => onOpen(r.task_id)}>Replay</Btn>{" "}
                          <Btn size="sm" onClick={() => onReport(r.task_id)}>Report</Btn>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>
            <figcaption className="mt-2.5 text-[0.85rem] italic text-ink-3"><b className="not-italic text-ink-2">Table 1.</b> Recorded sessions. “Ledger” is the hash-chain check, with its event count.</figcaption>
          </figure>
        )}
      </div>
    </div>
  );
}
