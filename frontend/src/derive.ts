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
    case "sandbox.recreated":
      return p.reason === "rewind" ? null : { tone: "warn", text: `Sandbox force-killed and recreated (${p.reason})` };
    case "canary.read": return { tone: "warn", text: `Decoy read: ${p.label ?? p.item}` };
    case "canary.exposed": return { tone: "warn", text: `Decoy reached the model's context: ${p.label ?? p.item}` };
    case "canary.tripped":
      return { tone: "bad", text: `Decoy used (${String(p.via).replace("_", " ")}): ${p.label ?? p.item}${p.blocked ? " · blocked" : ""}` };
    case "canary.copied": return { tone: "warn", text: `Decoy copied out: ${p.label ?? p.item}` };
    case "timeline.rewound":
      return { tone: p.verified?.matches === false ? "bad" : "ok",
        text: `Rewound to snapshot ${p.to_snapshot}${p.verified?.matches ? " · restored files match the snapshot" : p.verified?.checked === false ? " · could not re-hash" : " · MISMATCH"}` };
    case "rewind.failed": return { tone: "bad", text: `Rewind failed: ${p.reason}` };
    case "rewind.rejected": return { tone: "warn", text: `Rewind refused: ${p.reason}` };
    case "hold.start": return { tone: "info", text: `Sandbox held open for ${p.seconds}s: rewind or release it on the Timeline` };
    case "egress.brokered":
      return { tone: "ok", text: `Brokered ${p.method} ${p.service}${p.path ?? ""} → ${p.status}${p.stripped ? " · credential stripped from the request" : ""}` };
    case "sandbox.destroyed": return { tone: "info", text: `Sandbox destroyed ${p.name}` };
    case "scenario.check":
      return { tone: p.passed ? "ok" : "bad", text: `Hidden check ${p.passed ? "passed" : "failed"}${p.passed ? "" : `: ${(p.reasons ?? []).slice(0, 2).join("; ")}`}` };
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
    created: 0, destroyed: 0, forced: 0, rewinds: 0, snapshots: 0, brokered: 0, seconds: 0 };
  for (const e of events) {
    const p = e.payload;
    if (e.type === "egress.allowed") { m.allowed++; m.hosts.add(p.host); }
    else if (e.type === "egress.blocked") { m.blocked++; m.hosts.add(p.host); }
    else if (e.type === "policy.decision") { m.decisions++; if (p.action === "deny") m.denied++; }
    else if (e.type === "approval.requested") m.asked++;
    else if (e.type === "sandbox.created") m.created++;
    else if (e.type === "sandbox.recreated") { m.created++; if (p.reason !== "rewind") m.forced++; }
    else if (e.type === "timeline.rewound") m.rewinds++;
    else if (e.type === "snapshot.created") m.snapshots++;
    else if (e.type === "egress.brokered") m.brokered++;
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

/** The filesystem / secrets / compute readings, built from the same ledger events the server's report uses
 *  (`sandbox.audit` is written as each sandbox is destroyed, `canary.*` as decoys are touched). `audited` is false until
 *  the first sandbox has been measured: a gauge must then say so, not show a reassuring zero. */
export function measure(events: LedgerEvent[]) {
  const m = {
    audited: false, rootfsChanges: 0, hostBinds: 0, workspace: null as null | { files: number; added: number; modified: number; deleted: number },
    realSecrets: [] as string[], scanned: false, decoysPlanted: 0,
    decoysRead: new Set<string>(), decoysExposed: new Set<string>(), decoysTripped: new Set<string>(), decoysCopied: new Set<string>(),
    peakMem: 0, memLimit: 0, peakPids: 0, pidsLimit: 0, cpuS: 0, oom: false, incomplete: new Set<string>(),
  };
  for (const e of events) {
    const p = e.payload;
    if (e.type === "canary.seeded") m.decoysPlanted = Math.max(m.decoysPlanted, (p.items ?? []).length);
    else if (e.type === "canary.read") m.decoysRead.add(p.item);
    else if (e.type === "canary.exposed") m.decoysExposed.add(p.item);
    else if (e.type === "canary.tripped") m.decoysTripped.add(p.item);
    else if (e.type === "canary.copied") m.decoysCopied.add(p.item);
    else if (e.type === "sandbox.audit") {
      for (const x of p.incomplete ?? []) m.incomplete.add(String(x));
      const fs = p.fs, st = p.stats;
      if (fs && fs.rootfs_changes != null) {
        m.audited = true;
        m.rootfsChanges += fs.rootfs_changes; m.hostBinds += (fs.host_binds ?? []).length;
        if (p.kind === "code" && fs.workspace) {
          const w = fs.workspace;
          m.workspace = { files: w.files, added: w.added_count, modified: w.modified_count, deleted: w.deleted_count };
        }
      }
      if (st) {
        m.audited = true;
        m.peakMem = Math.max(m.peakMem, st.peak_memory_bytes ?? 0); m.memLimit = Math.max(m.memLimit, st.memory_limit_bytes ?? 0);
        m.peakPids = Math.max(m.peakPids, st.peak_pids ?? 0); m.pidsLimit = Math.max(m.pidsLimit, st.pids_limit ?? 0);
        m.cpuS += st.cpu_seconds ?? 0; if (st.oom_killed === true) m.oom = true;
      }
      if (p.secrets) {
        m.audited = true;
        if (p.secrets.inside) m.scanned = true;
        for (const n of p.secrets.found ?? []) if (!m.realSecrets.includes(n)) m.realSecrets.push(n);
      }
    }
  }
  return m;
}

export type TimelineNode = {
  key: string; kind: "start" | "tool" | "rewind"; label: string; detail: string;
  snapshot: number | null;          // the snapshot taken right after this step
  active: boolean;                  // that snapshot still exists on the live timeline
  undone: boolean;                  // this step's work was discarded by a later rewind
  files: number | null; sha: string | null;
  verified?: { checked: boolean; matches?: boolean; files?: number; missing?: number; unexpected?: number };
};

/** The task as a line of steps with the snapshot taken after each, rewinds shown where they happened and the work they
 *  threw away greyed out. Everything is read from the ledger: nothing here is remembered by the UI. */
export function timeline(events: LedgerEvent[]) {
  const nodes: TimelineNode[] = [];
  const live = new Set<number>();
  let last: TimelineNode | null = null;
  let holding = false, pending = false;
  for (const e of events) {
    const p = e.payload;
    if (e.type === "tool.call" && p.tool !== "finish") {
      last = { key: `t${e.id}`, kind: "tool", label: String(p.tool), detail: toolLine(p), snapshot: null, active: false, undone: false, files: null, sha: null };
      nodes.push(last);
    } else if (e.type === "snapshot.created") {
      if (p.tool === "start" || last === null) {
        last = { key: `s${e.id}`, kind: "start", label: "start", detail: "workspace as it was handed to the agent", snapshot: p.id,
          active: true, undone: false, files: p.files, sha: p.sha256 };
        nodes.push(last);
      } else if (last.snapshot === null) {
        last.snapshot = p.id; last.active = true; last.files = p.files; last.sha = p.sha256;
      }
      live.add(p.id);
    } else if (e.type === "rewind.requested") pending = true;
    else if (e.type === "timeline.rewound" || e.type === "rewind.failed" || e.type === "rewind.rejected") {
      pending = false;
      if (e.type === "timeline.rewound") {
        const to = nodes.findIndex(n => n.snapshot === p.to_snapshot);
        for (const d of p.discarded ?? []) live.delete(d);
        nodes.forEach((n, i) => { if (i > to && n.kind !== "rewind") { n.undone = true; n.active = false; } });
        nodes.push({ key: `r${e.id}`, kind: "rewind", label: `rewound to snapshot ${p.to_snapshot}`,
          detail: p.verified?.matches ? `restored into a fresh sandbox; ${p.verified.files} file(s) re-hashed and matched`
            : p.verified?.checked === false ? "restored into a fresh sandbox; the files could not be re-hashed" : "restored, but the files do NOT match the snapshot",
          snapshot: null, active: false, undone: false, files: null, sha: p.snapshot_sha256 ?? null, verified: p.verified });
        last = null;
      }
    } else if (e.type === "hold.start") holding = true;
    else if (e.type === "hold.end") holding = false;
  }
  for (const n of nodes) if (n.snapshot !== null && !live.has(n.snapshot)) n.active = false;
  return { nodes, holding, rewindPending: pending };
}
