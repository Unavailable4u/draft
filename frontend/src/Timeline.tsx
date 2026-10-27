import { useState } from "react";
import { releaseTask, rewindTask } from "./api";
import type { LedgerEvent } from "./api";
import { timeline } from "./derive";
import type { TimelineNode } from "./derive";

const KIND: Record<TimelineNode["kind"], string> = {
  start: "border-zinc-600 text-zinc-300", tool: "border-emerald-800 text-emerald-300", rewind: "border-sky-700 text-sky-300",
};

function Node({ n, canRewind, busy, onRewind }: { n: TimelineNode; canRewind: boolean; busy: boolean; onRewind: (id: number) => void }) {
  const dim = n.undone ? "opacity-40" : "";
  return (
    <li className={`relative border-l-2 pl-4 pb-4 ${n.kind === "rewind" ? "border-sky-600" : n.undone ? "border-zinc-800" : "border-zinc-700"}`}>
      <span className={`absolute -left-[7px] top-1 h-3 w-3 rounded-full border-2 bg-zinc-950 ${KIND[n.kind].split(" ")[0]}`} />
      <div className={`flex items-start gap-3 ${dim}`}>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-xs">
            <span className={`rounded border px-1.5 py-0.5 uppercase tracking-wide ${KIND[n.kind]}`}>{n.label}</span>
            {n.undone && <span className="text-zinc-500">undone by a later rewind</span>}
            {n.snapshot !== null && !n.undone && (
              <span className="text-zinc-500">snapshot {n.snapshot}{n.files !== null ? ` · ${n.files} file${n.files === 1 ? "" : "s"}` : ""}</span>
            )}
          </div>
          <code className={`mt-1 block break-all text-xs ${n.kind === "rewind" ? "text-sky-200" : "text-zinc-400"} ${n.undone ? "line-through" : ""}`}>
            {n.detail}
          </code>
          {n.sha && <div className="mt-0.5 font-mono text-[10px] text-zinc-600" title="SHA-256 of the snapshot's contents, as recorded in the ledger">sha256 {n.sha.slice(0, 16)}…</div>}
        </div>
        {n.snapshot !== null && n.active && canRewind && (
          <button disabled={busy} onClick={() => onRewind(n.snapshot!)}
            className="shrink-0 rounded border border-sky-700 px-2.5 py-1 text-xs text-sky-300 hover:bg-sky-950 disabled:opacity-40">
            ↺ Rewind here
          </button>
        )}
      </div>
    </li>
  );
}

export function TimelineView({ taskId, events, running }: { taskId: string | null; events: LedgerEvent[]; running: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!taskId)
    return <Empty>Run a task in the Workspace. Every step that changes the workspace gets a snapshot, and you can rewind to any of them while the task is running or held open.</Empty>;
  const { nodes, holding, rewindPending } = timeline(events);
  if (nodes.length === 0)
    return <Empty>{running ? "Waiting for the first snapshot…" : "This task has no snapshots: its sandbox could not take them, or it ran before snapshots existed."}</Empty>;

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const canRewind = running && !rewindPending;
  const rewinds = nodes.filter(n => n.kind === "rewind");
  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-6">
      <div className="mx-auto max-w-3xl">
        <div className="mb-4 flex items-center gap-3">
          <h2 className="text-base font-medium text-zinc-200">Timeline <span className="font-mono text-xs text-zinc-500">{taskId}</span></h2>
          <span className="text-xs text-zinc-500">{nodes.filter(n => n.snapshot !== null && !n.undone).length} snapshots · {rewinds.length} rewind{rewinds.length === 1 ? "" : "s"}</span>
          {holding && (
            <button disabled={busy} onClick={() => act(() => releaseTask(taskId))}
              className="ml-auto rounded border border-amber-700 px-3 py-1 text-xs text-amber-300 hover:bg-amber-950 disabled:opacity-40">
              Release sandbox
            </button>
          )}
        </div>
        {holding && <p className="mb-3 rounded border border-amber-900 bg-amber-950/30 p-2 text-xs text-amber-200">
          The agent has stopped and its sandbox is being held open. Rewind to an earlier snapshot, or release it to finish the task.</p>}
        {rewindPending && <p className="mb-3 rounded border border-sky-900 bg-sky-950/30 p-2 text-xs text-sky-200">Rewind in progress: a fresh sandbox is being restored from the snapshot…</p>}
        {!running && <p className="mb-3 text-xs text-zinc-500">The task has ended and its sandbox is gone. The record below is read from the ledger; rewinding is only possible while a sandbox exists (start a task with “hold” to keep it open).</p>}
        {err && <p className="mb-3 text-xs text-red-400">{err}</p>}
        <ol>
          {nodes.map(n => (
            <Node key={n.key} n={n} canRewind={canRewind} busy={busy}
              onRewind={id => act(() => rewindTask(taskId, id))} />
          ))}
        </ol>
        <p className="mt-2 text-xs text-zinc-600">A rewind replaces the sandbox: the new one starts from the snapshot's files only, so whatever the agent did to processes, /tmp or the environment is gone too. The ledger keeps everything, including what was undone.</p>
      </div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-1 items-center justify-center p-6">
      <p className="max-w-md rounded-lg border border-dashed border-zinc-700 p-6 text-center text-sm text-zinc-500">{children}</p>
    </div>
  );
}
