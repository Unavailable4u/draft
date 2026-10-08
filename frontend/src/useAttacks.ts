import { useCallback, useRef, useState } from "react";
import { listAttacks, runAttack } from "./api";
import type { AttackInfo, AttackResult } from "./api";

export type Run = { state: "running" } | { state: "done"; result: AttackResult } | { state: "failed"; message: string };

/** Lives in App (not in the screen) so results survive switching tabs. */
export function useAttacks() {
  const [attacks, setAttacks] = useState<AttackInfo[] | null>(null);
  const [egress, setEgress] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const [all, setAll] = useState(false);
  const busy = useRef(false);   // the server runs one attack at a time; so does the UI

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      const r = await listAttacks();
      setAttacks(r.attacks); setEgress(r.egress_attached);
    } catch (e) { setLoadError((e as Error).message); }
  }, []);

  const run = useCallback(async (name: string) => {
    if (busy.current) return;
    busy.current = true;
    setRuns(p => ({ ...p, [name]: { state: "running" } }));
    try {
      const result = await runAttack(name);
      setRuns(p => ({ ...p, [name]: { state: "done", result } }));
    } catch (e) {
      setRuns(p => ({ ...p, [name]: { state: "failed", message: (e as Error).message } }));
    } finally { busy.current = false; }
  }, []);

  const runAll = useCallback(async () => {
    if (busy.current || !attacks) return;
    setAll(true);
    for (const a of attacks) if (a.available) await run(a.name);
    setAll(false);
  }, [attacks, run]);

  const running = Object.values(runs).some(r => r.state === "running");
  return { attacks, egress, loadError, runs, running, all, load, run, runAll };
}
export type AttackLabApi = ReturnType<typeof useAttacks>;
