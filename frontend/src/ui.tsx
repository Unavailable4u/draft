/* Shared primitives. Every screen is built from these so the whole app reads as one typeset instrument. */
import { useId } from "react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Tone } from "./derive";

export type Tint = Tone | "mute";

export const INK: Record<Tint, string> = { ok: "text-ok", bad: "text-bad", warn: "text-warn", info: "text-info", mute: "text-ink-3" };
export const EDGE: Record<Tint, string> = {
  ok: "border-ok/50", bad: "border-bad/55", warn: "border-warn/55", info: "border-info/50", mute: "border-rule",
};
export const WASH: Record<Tint, string> = {
  ok: "bg-ok-wash", bad: "bg-bad-wash", warn: "bg-warn-wash", info: "bg-info-wash", mute: "bg-sunken",
};
export const BAR: Record<Tint, string> = { ok: "bg-ok", bad: "bg-bad", warn: "bg-warn", info: "bg-info", mute: "bg-rule-2" };
export const VAR: Record<Tint, string> = {
  ok: "var(--ok)", bad: "var(--bad)", warn: "var(--warn)", info: "var(--info)", mute: "var(--ink-3)",
};

/** Field styling shared by inputs, selects and textareas: set into the page, lit on focus. */
export const FIELD =
  "w-full rounded-[5px] border border-rule bg-sunken px-3 py-2 text-[0.95rem] text-ink outline-none transition " +
  "placeholder:text-ink-3 hover:border-rule-2 focus:border-accent focus:ring-2 focus:ring-accent/20";

/** A code listing: sunken, hair-ruled, typewriter face. */
export const LISTING = "rounded-[5px] border border-rule bg-sunken font-mono text-[0.82rem] leading-relaxed text-ink";

/** The brand mark: concentric rings around a crimson point, a blast radius. */
export function Mark({ size = 28, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden className={className}>
      <circle cx="16" cy="16" r="14.8" stroke="currentColor" strokeWidth="1" strokeDasharray="1.2 2.4" opacity=".5" />
      <circle cx="16" cy="16" r="10.4" stroke="currentColor" strokeWidth="1.2" opacity=".78" />
      <circle cx="16" cy="16" r="6" stroke="currentColor" strokeWidth="1.7" />
      <circle cx="16" cy="16" r="4.4" fill="var(--accent)" opacity=".2" />
      <circle cx="16" cy="16" r="2.2" fill="var(--accent)" />
    </svg>
  );
}

export function Spin({ className = "" }: { className?: string }) {
  return <span aria-hidden className={`inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent ${className}`} />;
}

/** Small-caps label, the typeset replacement for UPPERCASE TRACKED TEXT. */
export function Label({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`smcp text-[0.84rem] text-ink-2 ${className}`}>{children}</span>;
}

export function Chip({ tone = "mute", children, title, className = "", dot = false }: {
  tone?: Tint; children: ReactNode; title?: string; className?: string; dot?: boolean;
}) {
  return (
    <span title={title}
      className={`smcp inline-flex items-center gap-1.5 whitespace-nowrap rounded-[4px] border px-1.5 py-px text-[0.8rem] leading-tight ${EDGE[tone]} ${INK[tone]} ${tone === "mute" ? "" : WASH[tone]} ${tone === "bad" ? "hatch-bad" : ""} ${className}`}>
      {dot && <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${BAR[tone]}`} />}
      {children}
    </span>
  );
}

type Variant = "primary" | "ghost" | "danger" | "warn" | "info";
const VARIANT: Record<Variant, string> = {
  primary: "border-accent/80 bg-accent text-on-accent font-bold shadow-[0_1px_0_rgba(255,255,255,.22)_inset,0_10px_26px_-12px_var(--accent)] hover:brightness-110",
  ghost: "border-rule-2 bg-raised text-ink hover:border-ink-3 hover:bg-sheet",
  danger: "border-bad/60 bg-transparent text-bad hover:bg-bad-wash",
  warn: "border-warn bg-warn text-on-warn font-bold hover:brightness-105",
  info: "border-info/60 bg-transparent text-info hover:bg-info-wash",
};

export function Btn({ variant = "ghost", size = "md", className = "", ...p }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md" }) {
  const sz = size === "sm" ? "px-2.5 py-0.5 text-[0.86rem]" : "px-4 py-1.5 text-[0.98rem]";
  return (
    <button {...p}
      className={`inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-[5px] border font-medium transition active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40 ${sz} ${VARIANT[variant]} ${className}`} />
  );
}

/** Radio-style segmented control. */
export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T; options: { id: T; label: ReactNode; title?: string }[]; onChange: (v: T) => void; label?: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex gap-0.5 rounded-[6px] border border-rule bg-sunken p-0.5">
      {options.map(o => (
        <button key={o.id} role="radio" aria-checked={o.id === value} title={o.title} onClick={() => onChange(o.id)}
          className={`rounded-[4px] px-3 py-1 text-[0.9rem] transition ${o.id === value ? "bg-accent font-bold text-on-accent shadow-sm" : "text-ink-2 hover:bg-raised hover:text-ink"}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** A framed panel. `tone` tints the frame only; the content carries the meaning. */
export function Card({ children, className = "", tone = "mute" }: { children: ReactNode; className?: string; tone?: Tint }) {
  return <section className={`panel ${tone === "mute" ? "" : EDGE[tone]} ${className}`}>{children}</section>;
}

/** "§ 2  Title" with a hairline under it, the journal section heading. */
export function SectionHead({ no, title, note, right, className = "" }: {
  no?: string | number; title: ReactNode; note?: ReactNode; right?: ReactNode; className?: string;
}) {
  return (
    <div className={className}>
      <div className="flex items-baseline gap-2.5 pb-1.5">
        {no !== undefined && <span className="italic text-accent-ink">§{no}</span>}
        <h3 className="text-[1.12rem] font-bold tracking-tight text-ink">{title}</h3>
        {note && <span className="text-[0.85rem] italic text-ink-2">{note}</span>}
        {right && <span className="ml-auto">{right}</span>}
      </div>
      <div className="hairline-accent" />
    </div>
  );
}

/** The heading of a whole screen: eyebrow, display title, one italic sentence, optional controls on the right. */
export function PageHead({ eyebrow, title, sub, right }: { eyebrow?: ReactNode; title: ReactNode; sub?: ReactNode; right?: ReactNode }) {
  return (
    <header className="rise relative flex items-end gap-4 pb-3">
      <div className="min-w-0">
        {eyebrow && <Label className="block text-[0.86rem] text-accent-ink">{eyebrow}</Label>}
        <h2 className="display mt-0.5 text-[2.5rem] text-ink">{title}</h2>
        {sub && <p className="mt-1.5 max-w-2xl text-[1.02rem] italic leading-snug text-ink-2">{sub}</p>}
      </div>
      {right && <div className="ml-auto flex shrink-0 items-center gap-2.5 pb-1">{right}</div>}
      <div className="hairline-accent absolute inset-x-0 bottom-0" />
    </header>
  );
}

/** Key ........ value, with a dotted leader like a table of contents. */
export function Row({ k, children, mono = false }: { k: ReactNode; children?: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline gap-2 leading-snug">
      <dt className="shrink-0 text-ink-2">{k}</dt>
      <span aria-hidden className="mb-[3px] min-w-3 flex-1 self-end border-b border-dotted border-ink-3/50" />
      <dd className={`min-w-0 max-w-[68%] break-words text-right text-ink ${mono ? "font-mono text-[0.85em]" : ""}`}>{children ?? "—"}</dd>
    </div>
  );
}

/** A big numeral with a small-caps caption: the unit of "show me the number". */
export function Stat({ label, value, sub, tone = "mute", className = "", size = "md" }: {
  label: ReactNode; value: ReactNode; sub?: ReactNode; tone?: Tint; className?: string; size?: "md" | "lg";
}) {
  return (
    <div className={className}>
      <Label className="block">{label}</Label>
      <div className={`display mt-1 tabular-nums ${size === "lg" ? "text-[3.4rem]" : "text-[2.3rem]"} ${tone === "mute" ? "text-ink" : INK[tone]}`}>{value}</div>
      {sub && <div className="mt-1 text-[0.84rem] italic leading-snug text-ink-2">{sub}</div>}
    </div>
  );
}

/** A thin horizontal meter. `value` is 0..1. */
export function Meter({ value, tone = "ok", title, className = "" }: { value: number; tone?: Tint; title?: string; className?: string }) {
  const v = Math.max(0, Math.min(1, value));
  return (
    <div title={title} className={`h-1.5 overflow-hidden rounded-full bg-sunken ring-1 ring-inset ring-rule ${className}`}>
      <div className={`h-full rounded-full ${BAR[tone]} transition-[width] duration-700 ease-out`} style={{ width: `${Math.max(v > 0 ? 2 : 0, v * 100)}%` }} />
    </div>
  );
}

/** A donut made of stacked arcs. Segments add up to at most `total`; the rest is the empty track. */
export function Donut({ segments, total, size = 132, stroke = 11, children, label }: {
  segments: { value: number; tone: Tint }[]; total: number; size?: number; stroke?: number; children?: ReactNode; label?: string;
}) {
  const r = 50 - stroke / 2 - 1;
  let at = 0;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={label}>
      <svg viewBox="0 0 100 100" width={size} height={size} className="-rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--rule)" strokeWidth={stroke} />
        {total > 0 && segments.filter(s => s.value > 0).map((s, i) => {
          const len = (s.value / total) * 100, off = -at;
          at += len;
          return (
            <circle key={i} cx="50" cy="50" r={r} fill="none" stroke={s.tone === "ok" ? "url(#mlk-ok)" : VAR[s.tone]} strokeWidth={stroke} pathLength={100}
              strokeDasharray={`${Math.max(0, len - 1.2)} ${100 - Math.max(0, len - 1.2)}`} strokeDashoffset={off} strokeLinecap="butt"
              className="glow" style={{ ["--glow-c" as string]: VAR[s.tone], transition: "stroke-dasharray .7s ease" }} />
          );
        })}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">{children}</div>
    </div>
  );
}

/** The ledger seal: a notary's rosette that says whether the hash chain holds. */
export function Seal({ state, title, children }: { state: "ok" | "bad" | "idle"; title: ReactNode; children?: ReactNode }) {
  const id = useId().replace(/:/g, "");
  const tone: Tint = state === "ok" ? "ok" : state === "bad" ? "bad" : "mute";
  const ring = state === "ok" ? "CHAIN VERIFIED" : state === "bad" ? "CHAIN BROKEN" : "UNVERIFIED";
  return (
    <div role="status" className={`flex items-center gap-4 rounded-[7px] border p-3.5 ${EDGE[tone]} ${state === "idle" ? "bg-sheet" : WASH[tone]} ${state === "bad" ? "hatch-bad" : ""}`}>
      <svg viewBox="0 0 100 100" className={`h-[5.6rem] w-[5.6rem] shrink-0 ${INK[tone]}`} aria-hidden>
        <defs><path id={`${id}c`} d="M50,50 m-35,0 a35,35 0 1,1 70,0 a35,35 0 1,1 -70,0" /></defs>
        <circle cx="50" cy="50" r="48" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <circle cx="50" cy="50" r="44.5" fill="none" stroke="currentColor" strokeWidth=".7" strokeDasharray="1.2 2.3" />
        <circle cx="50" cy="50" r="25.5" fill="none" stroke="currentColor" strokeWidth="1.3" />
        <text fontSize="8" letterSpacing="1.6" fontWeight="700" fill="currentColor">
          <textPath href={`#${id}c`} startOffset="25%" textAnchor="middle">{ring}</textPath>
        </text>
        {state === "ok" && <path d="M38 51.5l8.5 8.5L63 42" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />}
        {state === "bad" && <path d="M40 40l20 20M60 40L40 60" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" />}
        {state === "idle" && <g fill="currentColor"><circle cx="40" cy="50" r="2.8" /><circle cx="50" cy="50" r="2.8" /><circle cx="60" cy="50" r="2.8" /></g>}
        <path d="M18 74.5l2.2 2.2M82 74.5l-2.2 2.2" stroke="currentColor" strokeWidth="1" strokeLinecap="round" opacity=".6" />
      </svg>
      <div className="min-w-0 flex-1">
        <div className={`text-[1.12rem] font-bold leading-tight ${state === "idle" ? "text-ink-2" : INK[tone]}`}>{title}</div>
        {children && <div className="mt-1 break-words text-[0.86rem] leading-snug text-ink-2">{children}</div>}
      </div>
    </div>
  );
}

export function Empty({ title, children }: { title?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-1 items-center justify-center p-8">
      <div className="rise max-w-md text-center">
        <div className="relative mx-auto mb-4 grid h-24 w-24 place-items-center">
          <span aria-hidden className="absolute inset-0 rounded-full border border-dashed border-ink-3/40 spin-center" style={{ animationDuration: "40s" }} />
          <Mark size={58} className="text-ink-3" />
        </div>
        {title && <div className="display text-[1.5rem] text-ink">{title}</div>}
        <p className="mt-2 leading-relaxed text-ink-2">{children}</p>
      </div>
    </div>
  );
}

/** Pulsing status dot. */
export function Pulse({ tone = "warn" }: { tone?: Tint }) {
  return (
    <span aria-hidden className="relative inline-flex h-2 w-2">
      <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${BAR[tone]}`} />
      <span className={`relative inline-flex h-2 w-2 rounded-full ${BAR[tone]}`} />
    </span>
  );
}

/** A hash shown the way a git log shows one. */
export function Hash({ h, className = "" }: { h: string | null | undefined; className?: string }) {
  if (!h) return <span className={className}>—</span>;
  return <span title={h} className={`font-mono ${className}`}>{h.slice(0, 8)}<span className="opacity-50">…{h.slice(-4)}</span></span>;
}
