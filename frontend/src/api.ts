export type Profile = "strict" | "observe";
export type LedgerEvent = {
  id: number; ts: number; task_id: string; actor: string; type: string;
  payload: Record<string, any>; prev_hash: string; hash: string;
};
export type EndInfo = { status: string; error?: string | null; ledger_verified?: boolean | null; replayed?: boolean };
export type Dimension = { status: string; note?: string; evidence?: number[]; [k: string]: any };
export type Report = {
  task_id: string; task: string | null; outcome: string; summary: string; complete: boolean;
  steps: number; tool_calls: number; note: string;
  ledger: { verified: boolean; detail: string; events: number; head_hash: string | null };
  dimensions: Record<string, Dimension>;
};
export type Verification = { task_id: string; verified: boolean; detail: string; events: number; head_hash: string | null };
export type PendingApproval = { id: string; task_id: string; expires_at: number };

const TOKEN_KEY = "minilocker.token";
export const getToken = () => localStorage.getItem(TOKEN_KEY) ?? "";
export const setToken = (t: string) => localStorage.setItem(TOKEN_KEY, t);

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const t = getToken();
  return { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}), ...extra };
}

async function json<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail ?? detail; } catch { /* non-JSON error body */ }
    throw new Error(`${r.status}: ${detail}`);
  }
  return r.json() as Promise<T>;
}

export const createTask = (task: string, profile: Profile) =>
  fetch("/api/tasks", { method: "POST", headers: headers(), body: JSON.stringify({ task, profile }) })
    .then(r => json<{ task_id: string; status: string }>(r));

export const getReport = (id: string) =>
  fetch(`/api/tasks/${id}/report`, { headers: headers() }).then(r => json<Report>(r));

export const verifyLedger = (id: string) =>
  fetch(`/api/ledger/verify/${id}`, { headers: headers() }).then(r => json<Verification>(r));

/** Fetch with the auth header, then save as a file (a plain <a href> can't send a bearer token). */
export async function downloadReport(id: string, format: "json" | "html") {
  const r = await fetch(`/api/tasks/${id}/report?format=${format}`, { headers: headers() });
  if (!r.ok) throw new Error(`${r.status}: ${r.statusText}`);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(await r.blob());
  a.download = `blast-radius-${id}.${format}`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export const listApprovals = (taskId: string) =>
  fetch(`/api/approvals?task_id=${taskId}`, { headers: headers() })
    .then(r => json<{ pending: PendingApproval[] }>(r));

export const resolveApproval = (id: string, approve: boolean) =>
  fetch(`/api/approvals/${id}`, { method: "POST", headers: headers(), body: JSON.stringify({ approve }) })
    .then(r => json<{ id: string; decision: string }>(r));

/** SSE over fetch (EventSource can't send the Authorization header). Reconnects
 *  with `after=<last id>`; the server's frame ids are ledger ids, so there are no
 *  gaps or duplicates. Heartbeat comments carry no data and are skipped. */
export async function streamEvents(
  taskId: string, onEvent: (e: LedgerEvent) => void, onEnd: (i: EndInfo) => void, signal: AbortSignal,
) {
  let last = -1;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const r = await fetch(`/api/tasks/${taskId}/events?after=${last}`,
        { headers: headers({ Accept: "text/event-stream" }), signal });
      if (r.status === 404) return onEnd({ status: "unknown_task" });
      if (r.status === 401) return onEnd({ status: "unauthorized" });
      if (!r.ok || !r.body) throw new Error(`stream ${r.status}`);
      const reader = r.body.getReader(), dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const frame = buf.slice(0, i); buf = buf.slice(i + 2);
          let ev = "message", data = "";
          for (const line of frame.split("\n")) {
            if (line.startsWith("event:")) ev = line.slice(6).trim();
            else if (line.startsWith("data:")) data += line.slice(5).trim();
          }
          if (!data) continue;
          if (ev === "end") return onEnd(JSON.parse(data));
          const e = JSON.parse(data) as LedgerEvent;
          if (e.id > last) { last = e.id; onEvent(e); }
        }
      }
    } catch { if (signal.aborted) return; }
    await new Promise(res => setTimeout(res, 1000 * (attempt + 1)));
  }
  onEnd({ status: "disconnected" });
}
