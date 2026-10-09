import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { LedgerEvent } from "./api";
import { parseArgs } from "./derive";

const R = "\x1b[31m", G = "\x1b[32m", Y = "\x1b[33m", D = "\x1b[2m", X = "\x1b[0m";
// Sandbox output is untrusted: strip control bytes so it can't inject escape
// sequences that fake our [policy]/[egress] lines. \n and \t survive.
const clean = (s: string) => s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");

function render(e: LedgerEvent): string {
  const p = e.payload;
  switch (e.type) {
    case "tool.call": {
      const a = parseArgs(p.args ?? "");
      if (p.tool === "run_shell") return `${G}$${X} ${clean(String(a?.cmd ?? p.args))}\n`;
      if (p.tool === "finish") return "";
      if (p.tool === "browse")
        return `${D}# browse ${clean(String(a?.action ?? ""))} ${clean(String(a?.url ?? a?.selector ?? ""))}${X}\n`;
      return `${D}# ${p.tool} ${clean(String(a?.path ?? ""))}${X}\n`;
    }
    case "tool.result": {
      const m = clean(String(p.result ?? "")).match(/^exit_code=(-?\d+)\n?([\s\S]*)$/);
      if (!m) return `${clean(String(p.result ?? ""))}\n`;   // e.g. a policy block message
      const body = m[2].replace(/\n+$/, "");
      return `${body ? body + "\n" : ""}${m[1] === "0" ? D : R}[exit ${m[1]}]${X}\n`;
    }
    case "policy.decision":
      return p.action === "allow" ? "" : `${p.action === "deny" ? R : Y}[policy:${p.action}] ${clean((p.reasons ?? []).join("; "))}${X}\n`;
    case "injection.suspected":
      return `${R}[injection suspected] page ${clean(String(p.seq))} score ${clean(String(p.score))}: ${clean((p.findings ?? []).map((f: any) => String(f.label)).join("; "))}${X}\n`;
    case "egress.blocked": return `${R}[egress blocked${p.source === "browser" ? ": browser" : ""}] ${clean(String(p.host))} (${clean(String(p.reason ?? ""))})${X}\n`;
    case "approval.requested": return `${Y}[approval needed] ${clean(String(p.summary))}${X}\n`;
    case "approval.granted": return `${G}[approved]${X}\n`;
    case "approval.denied": return `${R}[denied]${X}\n`;
    case "task.end": return `${D}── task ${clean(String(p.status))} ──${X}\n`;
    default: return "";
  }
}

export function TerminalView({ events }: { events: LedgerEvent[] }) {
  const el = useRef<HTMLDivElement>(null);
  const term = useRef<XTerm | null>(null);
  const done = useRef(0);

  useEffect(() => {
    const t = new XTerm({ fontSize: 13, convertEol: true, disableStdin: true, scrollback: 5000,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", theme: { background: "#09090b" } });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(el.current!);
    fit.fit();
    term.current = t; done.current = 0;
    const ro = new ResizeObserver(() => { try { fit.fit(); } catch { /* hidden tab: zero size */ } });
    ro.observe(el.current!);
    return () => { ro.disconnect(); t.dispose(); term.current = null; };
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    if (events.length < done.current) { t.reset(); done.current = 0; }   // new task
    for (; done.current < events.length; done.current++) {
      const s = render(events[done.current]);
      if (s) t.write(s);
    }
  }, [events]);

  return <div ref={el} className="h-full w-full p-2" />;
}
