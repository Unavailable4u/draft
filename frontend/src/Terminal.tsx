import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { LedgerEvent } from "./api";
import { parseArgs } from "./derive";
import { Mark } from "./ui";

const R = "\x1b[31m", G = "\x1b[32m", Y = "\x1b[33m", D = "\x1b[2m", X = "\x1b[0m";
// Sandbox output is untrusted: strip control bytes so it can't inject escape
// sequences that fake our [policy]/[egress] lines. \n and \t survive.
const clean = (s: string) => s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");

const FALLBACK_FONT = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
const CM_FONT = `"CMU Typewriter Text", ${FALLBACK_FONT}`;

/** The terminal is always a dark "listing", in both themes, so output stays the focal point of the page. */
const THEME = {
  background: "#070a12", foreground: "#e9e4d6", cursor: "#a3b9ff", selectionBackground: "#2b3a6b",
  black: "#070a12", red: "#ff8070", green: "#62d7a1", yellow: "#f4c55f", blue: "#8fb2f2", magenta: "#c9a0e8", cyan: "#84d0e8", white: "#e9e4d6",
  brightBlack: "#8b90a3", brightRed: "#ffa296", brightGreen: "#8be6bb", brightYellow: "#f8d98d", brightBlue: "#aec7f6", brightMagenta: "#dbbcf0", brightCyan: "#a6dcee", brightWhite: "#fbf7ea",
};

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
  const seen = useRef(new Map<string, { n: number; label: string }>());   // repeated egress blocks

  useEffect(() => {
    const t = new XTerm({ fontSize: 14, lineHeight: 1.28, convertEol: true, disableStdin: true, scrollback: 5000,
      fontFamily: FALLBACK_FONT, theme: THEME });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(el.current!);
    fit.fit();
    term.current = t; done.current = 0; seen.current.clear();
    const ro = new ResizeObserver(() => { try { fit.fit(); } catch { /* hidden tab: zero size */ } });
    ro.observe(el.current!);
    // Computer Modern Typewriter loads lazily; switch to it once it is ready so the cell grid is measured with the real glyphs.
    let alive = true;
    document.fonts.load('500 14px "CMU Typewriter Text"').then(() => {
      if (!alive) return;
      t.options.fontFamily = CM_FONT;
      try { fit.fit(); } catch { /* hidden tab */ }
    }).catch(() => { /* keep the fallback face */ });
    return () => { alive = false; ro.disconnect(); t.dispose(); term.current = null; };
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    if (events.length < done.current) { t.reset(); done.current = 0; seen.current.clear(); }   // new task
    // A page that loads 30 images from one blocked host is one red line plus a count, not 30 lines.
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
      } else if (ev.type === "tool.result" || ev.type === "task.end") {
        flush();
      }
      const s = render(ev);
      if (s) t.write(s);
    }
  }, [events]);

  return (
    <div className="relative flex h-full flex-col bg-term">
      <div className="flex shrink-0 items-center gap-3 border-b border-white/10 bg-white/[.025] px-3.5 py-2.5 text-term-dim">
        <span aria-hidden className="flex gap-1.5">
          <i className="h-2.5 w-2.5 rounded-full bg-[#f0877b]/80" /><i className="h-2.5 w-2.5 rounded-full bg-[#e8c16d]/80" /><i className="h-2.5 w-2.5 rounded-full bg-[#8fd1a4]/80" />
        </span>
        <span className="font-mono text-[0.8rem]"><span className="text-[#62d7a1]">●</span> sandbox <span className="text-term-fg/60">·</span> /workspace</span>
        <span className="ml-auto text-[0.8rem] italic tabular-nums">{events.length} ledger event{events.length === 1 ? "" : "s"}</span>
      </div>
      <div ref={el} className="min-h-0 flex-1 px-3 py-2" />
      {events.length === 0 && (
        <div className="pointer-events-none absolute inset-0 top-9 grid place-items-center p-8 text-center">
          <div className="rise max-w-sm text-term-fg">
            <div className="relative mx-auto mb-4 grid h-24 w-24 place-items-center"><span aria-hidden className="spin-center absolute inset-0 rounded-full border border-dashed border-white/20" style={{ animationDuration: "40s" }} /><Mark size={56} className="text-term-dim" /></div>
            <div className="display text-[1.5rem]">Nothing has run yet</div>
            <p className="mt-1 leading-relaxed text-term-dim">
              Describe a task on the left. The agent works inside a sandbox, and everything it touches is measured and written to the ledger.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
