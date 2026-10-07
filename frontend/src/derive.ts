import type { LedgerEvent } from "./api";

export type Tone = "ok" | "bad" | "warn" | "info";

export function parseArgs(s: string): Record<string, any> | null {
  try { return JSON.parse(s); } catch { return null; }   // args are clipped server-side, so may be truncated
}

export function toolLine(p: Record<string, any>): string {
  const a = parseArgs(p.args ?? "");
  if (p.tool === "run_shell") return a?.cmd ?? p.args;
  if (p.tool === "finish") return a?.summary ?? p.args;
  return a?.path ?? p.args;
}

/** One-line human description of a notable ledger event, or null if it isn't one. */
export function describe(e: LedgerEvent): { tone: Tone; text: string } | null {
  const p = e.payload;
  switch (e.type) {
    case "egress.blocked": return { tone: "bad", text: `Egress blocked → ${p.host} (${p.reason ?? "not allowlisted"})` };
    case "egress.allowed": return { tone: "ok", text: `Egress allowed → ${p.host}` };
    case "policy.decision":
      if (p.action === "allow") return null;
      return { tone: p.action === "deny" ? "bad" : "warn", text: `Policy ${p.action} (${p.risk}): ${p.cmd}` };
    case "approval.requested": return { tone: "warn", text: `Approval requested: ${p.summary}` };
    case "approval.granted": return { tone: "ok", text: "Approval granted" };
    case "approval.denied": return { tone: "bad", text: "Approval denied or timed out" };
    case "sandbox.created": return { tone: "info", text: `Sandbox created ${p.name}` };
    case "sandbox.recreated": return { tone: "warn", text: `Sandbox force-killed and recreated (${p.reason})` };
    case "sandbox.destroyed": return { tone: "info", text: `Sandbox destroyed ${p.name}` };
    case "task.end": return { tone: p.status === "finished" ? "ok" : "warn", text: `Task ${p.status}` };
    default: return null;
  }
}

export function blast(events: LedgerEvent[]) {
  const m = { allowed: 0, blocked: 0, hosts: new Set<string>(), decisions: 0, denied: 0, asked: 0,
    created: 0, destroyed: 0, forced: 0, seconds: 0 };
  for (const e of events) {
    const p = e.payload;
    if (e.type === "egress.allowed") { m.allowed++; m.hosts.add(p.host); }
    else if (e.type === "egress.blocked") { m.blocked++; m.hosts.add(p.host); }
    else if (e.type === "policy.decision") { m.decisions++; if (p.action === "deny") m.denied++; }
    else if (e.type === "approval.requested") m.asked++;
    else if (e.type === "sandbox.created") m.created++;
    else if (e.type === "sandbox.recreated") { m.created++; m.forced++; }
    else if (e.type === "sandbox.destroyed") m.destroyed++;
  }
  // Server timestamps only: browser/WSL clock drift must not leak into the numbers.
  if (events.length > 1) m.seconds = events[events.length - 1].ts - events[0].ts;
  return m;
}
