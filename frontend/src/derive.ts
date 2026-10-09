import type { LedgerEvent } from "./api";

export type Tone = "ok" | "bad" | "warn" | "info";

export function parseArgs(s: string): Record<string, any> | null {
  try { return JSON.parse(s); } catch { return null; }   // args are clipped server-side, so may be truncated
}

export function toolLine(p: Record<string, any>): string {
  const a = parseArgs(p.args ?? "");
  if (p.tool === "run_shell") return a?.cmd ?? p.args;
  if (p.tool === "finish") return a?.summary ?? p.args;
  if (p.tool === "browse") return `${a?.action ?? "?"} ${a?.url ?? a?.selector ?? (a?.ref != null ? `ref ${a.ref}` : "")}`.trim();
  return a?.path ?? p.args;
}

/** One-line human description of a notable ledger event, or null if it isn't one. */
export function describe(e: LedgerEvent): { tone: Tone; text: string } | null {
  const p = e.payload;
  switch (e.type) {
    case "egress.blocked": return { tone: "bad", text: `Egress blocked${p.source === "browser" ? " (browser)" : ""} → ${p.host} (${p.reason ?? "not allowlisted"})` };
    case "egress.allowed": return { tone: "ok", text: `Egress allowed → ${p.host}` };
    case "policy.decision":
      if (p.action === "allow") return null;
      return { tone: p.action === "deny" ? "bad" : "warn", text: `Policy ${p.action} (${p.risk}): ${p.cmd}` };
    case "injection.suspected":
      return { tone: "bad", text: `Possible prompt injection on page ${p.seq} (score ${p.score}): ${(p.findings ?? []).map((f: any) => f.label).join("; ")}` };
    case "browser.unavailable": return { tone: "warn", text: "Browser sandbox unavailable" };
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

/** Notable events as display rows, newest first, with identical lines merged into one row and a count.
 *  A page that pulls 30 images from a blocked host is one line "x30", not 30 red lines. */
export function groupLines(events: LedgerEvent[], limit = 60) {
  const rows: { key: number; tone: Tone; text: string; count: number }[] = [];
  const at = new Map<string, number>();
  for (const e of [...events].reverse()) {
    const d = describe(e);
    if (!d || e.type === "task.end") continue;
    const i = at.get(d.text);
    if (i !== undefined) rows[i].count++;
    else { at.set(d.text, rows.length); rows.push({ key: e.id, tone: d.tone, text: d.text, count: 1 }); }
  }
  return rows.slice(0, limit);
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

export type BrowserPage = {
  seq: number; action: string; url: string; title: string; status: number | null; shot: string | null;
  popups: number; dialogs: number; downloads: number; flagged: { score: number; labels: string[] } | null;
};

/** Pages the browser visited, newest last, with injection flags joined on (page seq). */
export function browserPages(events: LedgerEvent[]): { pages: BrowserPage[]; blockedByBrowser: number; unavailable: boolean } {
  const flags = new Map<number, { score: number; labels: string[] }>();
  let blocked = 0, unavailable = false;
  for (const e of events) {
    if (e.type === "injection.suspected")
      flags.set(e.payload.seq, { score: e.payload.score, labels: (e.payload.findings ?? []).map((f: any) => String(f.label)) });
    else if (e.type === "egress.blocked" && e.payload.source === "browser") blocked++;
    else if (e.type === "browser.unavailable") unavailable = true;
  }
  const pages = events.filter(e => e.type === "browser.page").map(e => ({
    seq: e.payload.seq, action: String(e.payload.action), url: String(e.payload.url ?? ""), title: String(e.payload.title ?? ""),
    status: e.payload.status ?? null, shot: e.payload.shot ?? null, popups: e.payload.popups_blocked ?? 0,
    dialogs: e.payload.dialogs ?? 0, downloads: e.payload.downloads ?? 0, flagged: flags.get(e.payload.seq) ?? null,
  }));
  return { pages, blockedByBrowser: blocked, unavailable };
}

export type SavedFiles = {
  files: { name: string; bytes: number; sha256: string }[]; screenshots: number;
  skipped: { name: string; reason: string }[]; failed: number;
};

/** What the ledger says was saved. The ledger, not the store, is the source of truth. */
export function savedFiles(events: LedgerEvent[]): SavedFiles {
  const files = new Map<string, { name: string; bytes: number; sha256: string }>();
  let screenshots = 0, failed = 0;
  const skipped: { name: string; reason: string }[] = [];
  for (const e of events) {
    const p = e.payload;
    if (e.type === "artifact.stored") {
      if (p.kind === "screenshot") screenshots++;
      else files.set(p.name, { name: p.name, bytes: p.bytes, sha256: p.sha256 });
    } else if (e.type === "artifact.skipped") skipped.push({ name: String(p.name), reason: String(p.reason) });
    else if (e.type === "artifact.failed" || e.type === "artifact.export_failed") failed++;
  }
  return { files: [...files.values()], screenshots, skipped, failed };
}
