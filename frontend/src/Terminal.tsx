import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { LedgerEvent } from "./api";
import { parseArgs } from "./derive";

const R = "\x1b[38;2;239;151;143m", G = "\x1b[38;2;199;239;170m", Y = "\x1b[38;2;236;199;143m", D = "\x1b[38;2;113;141;117m", X = "\x1b[0m";
// Untrusted sandbox output must never be able to inject terminal escape sequences.
// Remove control bytes except newlines and tabs; only our renderer may emit ANSI codes.
const clean = (s: string) => s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");

function render(e: LedgerEvent): string {
  const p = e.payload;
  switch (e.type) {
    case "tool.call": {
      const a = parseArgs(p.args ?? "");
      if (p.tool === "run_shell") return `${G}$${X} ${clean(String(a?.cmd ?? p.args))}\n`;
      if (p.tool === "finish") return "";
      if (p.tool === "browse") return `${D}# browse ${clean(String(a?.action ?? ""))} ${clean(String(a?.url ?? a?.selector ?? ""))}${X}\n`;
      return `${D}# ${clean(String(p.tool))} ${clean(String(a?.path ?? ""))}${X}\n`;
    }
    case "tool.result": {
      const m = clean(String(p.result ?? "")).match(/^exit_code=(-?\d+)\n?([\s\S]*)$/);
      if (!m) return `${clean(String(p.result ?? ""))}\n`;
      const body = m[2].replace(/\n+$/, "");
      return `${body ? body + "\n" : ""}${m[1] === "0" ? D : R}[exit ${m[1]}]${X}\n`;
    }
    case "policy.decision":
      return p.action === "allow" ? "" : `${p.action === "deny" ? R : Y}[policy:${clean(String(p.action))}] ${clean((p.reasons ?? []).join("; "))}${X}\n`;
    case "injection.suspected":
      return `${R}[injection suspected] page ${clean(String(p.seq))} score ${clean(String(p.score))}: ${clean((p.findings ?? []).map((f: { label?: string }) => String(f.label)).join("; "))}${X}\n`;
    case "egress.blocked": return `${Y}[egress blocked${p.source === "browser" ? ": browser" : ""}] ${clean(String(p.host))} (${clean(String(p.reason ?? ""))})${X}\n`;
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
  const seen = useRef(new Map<string, { n: number; label: string }>());

  useEffect(() => {
    const t = new XTerm({ fontSize: 12, lineHeight: 1.55, letterSpacing: .15, convertEol: true,
      disableStdin: true, scrollback: 5000, fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
      theme: { background: "#0b120e", foreground: "#d4e3d3", cursor: "#c7efaa", selectionBackground: "#435e43", black: "#0c1210", brightBlack: "#708775", red: "#ed968f", brightRed: "#f1b1ab", green: "#c7efaa", brightGreen: "#e2f6ca", yellow: "#ecc78f", brightYellow: "#f4d9aa", blue: "#91bac1", brightBlue: "#bdd9df", magenta: "#c9a9c3", brightMagenta: "#ebcbe2", cyan: "#9ed6c7", brightCyan: "#c5ece1", white: "#d8e4d7", brightWhite: "#f0f4e9" } });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(el.current!);
    fit.fit();
    term.current = t; done.current = 0; seen.current.clear();
    const ro = new ResizeObserver(() => { try { fit.fit(); } catch { /* hidden tab */ } });
    ro.observe(el.current!);
    return () => { ro.disconnect(); t.dispose(); term.current = null; };
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    if (events.length < done.current) { t.reset(); done.current = 0; seen.current.clear(); }
    const flush = () => {
      for (const v of seen.current.values()) {
        if (v.n) { t.write(`${D}  … ${v.n} more blocked request(s) → ${v.label}${X}\n`); v.n = 0; }
      }
    };
    for (; done.current < events.length; done.current++) {
      const ev = events[done.current];
      if (ev.type === "egress.blocked") {
        const key = `${ev.payload.source}|${ev.payload.host}|${ev.payload.reason}`;
        const hit = seen.current.get(key);
        if (hit) { hit.n++; continue; }
        seen.current.set(key, { n: 0, label: `${clean(String(ev.payload.host))} (${clean(String(ev.payload.reason ?? ""))})` });
      } else if (ev.type === "tool.result" || ev.type === "task.end") flush();
      const s = render(ev);
      if (s) t.write(s);
    }
  }, [events]);

  return <div className="ml-terminal">
    <div ref={el} className="ml-terminal-canvas" />
    {events.length === 0 && <div className="ml-terminal-empty" aria-hidden="true">
      <div className="ml-prompt-chevron">›_ <span style={{color: "#526d54"}}>minilocker / sandbox</span></div>
      <strong>A clean slate, by design.</strong>
      <p>Your agent's commands, outputs, and blocked actions will appear here. No simulated results. No hidden steps.</p>
      <div className="ml-command-line">// awaiting first execution</div>
    </div>}
  </div>;
}
