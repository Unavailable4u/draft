import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createTask, getReport, streamEvents } from "./api";
import type { EndInfo, LedgerEvent, Profile, Report } from "./api";

export function useTask() {
  const [taskId, setTaskId] = useState<string | null>(null);
  const [events, setEvents] = useState<LedgerEvent[]>([]);
  const [end, setEnd] = useState<EndInfo | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);

  const attach = useCallback((id: string) => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setEvents([]); setEnd(null); setReport(null); setError(null); setTaskId(id);
    history.replaceState(null, "", `#task=${id}`);   // reload / share link rejoins the same run
    streamEvents(id, e => setEvents(p => [...p, e]), setEnd, ac.signal);
  }, []);

  const start = useCallback(async (text: string, profile: Profile) => {
    setError(null);
    try { attach((await createTask(text, profile)).task_id); }
    catch (e) { setError((e as Error).message); }
  }, [attach]);

  useEffect(() => {
    const m = location.hash.match(/task=([0-9a-f]{8})/);
    if (m) attach(m[1]);
    return () => abort.current?.abort();
  }, [attach]);

  useEffect(() => {
    if (end && taskId) getReport(taskId).then(setReport).catch(() => { /* badge just stays hidden */ });
  }, [end, taskId]);

  // Open approvals = requested minus resolved, derived from the ledger itself.
  const approval = useMemo(() => {
    if (end) return null;
    const open = new Map<string, LedgerEvent>();
    for (const e of events) {
      if (e.type === "approval.requested") open.set(e.payload.id, e);
      else if (e.type === "approval.granted" || e.type === "approval.denied") open.delete(e.payload.id);
    }
    return [...open.values()][0] ?? null;
  }, [events, end]);

  return { taskId, events, end, report, error, approval, running: taskId !== null && end === null, start, attach };
}
export type TaskApi = ReturnType<typeof useTask>;
