import { useState } from "react";
import { releaseTask, rewindTask } from "./api";
import type { LedgerEvent } from "./api";
import { timeline } from "./derive";
import type { TimelineNode } from "./derive";
import { Btn, Chip, Empty, Hash, PageHead } from "./ui";

const CHIP: Record<TimelineNode["kind"], string> = {
  start: "border-rule-2 text-ink-2",
  tool: "border-accent/50 text-accent-ink",
  rewind: "border-info/55 text-info",
};
const DOT: Record<TimelineNode["kind"], string> = {
  start: "border-ink-3 bg-paper",
  tool: "border-accent bg-accent shadow-[0_0_12px_var(--accent)]",
  rewind: "border-info bg-info-wash shadow-[0_0_12px_var(--info)]",
};

function Node({ n, i, canRewind, busy, onRewind }: { n: TimelineNode; i: number; canRewind: boolean; busy: boolean; onRewind: (id: number) => void }) {
  return (
    <li className="relative pb-5 pl-9" style={{ animationDelay: `${Math.min(i, 12) * 30}ms` }}>
      <span aria-hidden className={`absolute left-0 top-[1.15rem] h-[18px] w-[18px] rounded-full border-2 ${n.undone ? "border-ink-3/50 bg-paper" : DOT[n.kind]}`} />
      <div className={`rise panel p-3.5 ${n.undone ? "opacity-45" : ""} ${n.kind === "rewind" ? "border-info/50" : ""}`}>
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`smcp rounded-[4px] border px-1.5 py-px text-[0.82rem] ${CHIP[n.kind]}`}>{n.label}</span>
              {n.undone && <Chip tone="mute">undone by a later rewind</Chip>}
              {n.snapshot !== null && !n.undone && (
                <span className="text-[0.85rem] italic tabular-nums text-ink-2">snapshot {n.snapshot}{n.files !== null ? ` · ${n.files} file${n.files === 1 ? "" : "s"}` : ""}</span>
              )}
            </div>
            <code className={`mt-1.5 block break-all font-mono text-[0.84rem] leading-relaxed ${n.kind === "rewind" ? "text-info" : "text-ink"} ${n.undone ? "line-through" : ""}`}>
              {n.detail}
            </code>
            {n.sha && <div className="mt-1 text-[0.74rem] text-ink-3" title="SHA-256 of the snapshot's contents, as recorded in the ledger">sha256 <Hash h={n.sha} /></div>}
          </div>
          {n.snapshot !== null && n.active && canRewind && (
            <Btn variant="info" size="sm" disabled={busy} onClick={() => onRewind(n.snapshot!)} className="shrink-0">
              <span aria-hidden>↺</span> Rewind here
            </Btn>
          )}
        </div>
      </div>
    </li>
  );
}

export function TimelineView({ taskId, events, running }: { taskId: string | null; events: LedgerEvent[]; running: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!taskId)
    return <Empty title="No timeline yet">Run a task in the Workspace. Every step that changes the workspace gets a snapshot, and you can rewind to any of them while the task is running or held open.</Empty>;
  const { nodes, holding, rewindPending } = timeline(events);
  if (nodes.length === 0)
    return <Empty title="No snapshots">{running ? "Waiting for the first snapshot…" : "This task has no snapshots: its sandbox could not take them, or it ran before snapshots existed."}</Empty>;

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const canRewind = running && !rewindPending;
  const rewinds = nodes.filter(n => n.kind === "rewind");
  const note = "mb-4 rounded-[6px] border px-3.5 py-2.5 text-[0.92rem] leading-snug";
  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-6 py-7">
      <div className="mx-auto max-w-3xl">
        <div className="mb-6">
          <PageHead eyebrow="Time travel" title="Timeline"
            sub={<><span className="font-mono not-italic">{taskId}</span> · <span className="tabular-nums">{nodes.filter(n => n.snapshot !== null && !n.undone).length} snapshots · {rewinds.length} rewind{rewinds.length === 1 ? "" : "s"}</span></>}
            right={holding && (
              <Btn variant="warn" disabled={busy} onClick={() => act(() => releaseTask(taskId))}>Release sandbox</Btn>
            )} />
        </div>
        {holding && <p className={`${note} border-warn/50 bg-warn-wash text-ink`}>
          The agent has stopped and its sandbox is being held open. Rewind to an earlier snapshot, or release it to finish the task.</p>}
        {rewindPending && <p className={`${note} border-info/50 bg-info-wash text-ink`}>Rewind in progress: a fresh sandbox is being restored from the snapshot…</p>}
        {!running && <p className="mb-4 text-[0.92rem] italic leading-snug text-ink-2">The task has ended and its sandbox is gone. The record below is read from the ledger; rewinding is only possible while a sandbox exists (start a task with “hold” to keep it open).</p>}
        {err && <p role="alert" className={`${note} border-bad/50 bg-bad-wash text-bad`}>{err}</p>}
        <ol className="relative ml-2 before:absolute before:bottom-2 before:left-[8px] before:top-3 before:w-px before:bg-gradient-to-b before:from-accent before:to-rule">
          {nodes.map((n, i) => (
            <Node key={n.key} n={n} i={i} canRewind={canRewind} busy={busy}
              onRewind={id => act(() => rewindTask(taskId, id))} />
          ))}
        </ol>
        <p className="mt-2 border-t border-rule pt-2.5 text-[0.84rem] italic leading-snug text-ink-3"><span className="mr-1 not-italic">†</span>A rewind replaces the sandbox: the new one starts from the snapshot's files only, so whatever the agent did to processes, /tmp or the environment is gone too. The ledger keeps everything, including what was undone.</p>
      </div>
    </div>
  );
}
