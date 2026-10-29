import { useEffect, useState } from "react";
import { fetchArtifact } from "./api";
import type { LedgerEvent } from "./api";
import { browserPages } from "./derive";
import type { BrowserPage } from "./derive";
import { Btn, Chip, Empty, LISTING, Pulse } from "./ui";

/** Screenshot bytes arrive through the authenticated API as a blob: an <img src> cannot send the
 *  bearer token, and the server only serves images it has confirmed by magic bytes. */
function useShot(taskId: string, name: string | null) {
  const [s, set] = useState<{ url?: string; error?: string }>({});
  useEffect(() => {
    set({});
    if (!name) return;
    let dead = false, url: string | undefined;
    fetchArtifact(taskId, name)
      .then(({ blob }) => { if (!dead) { url = URL.createObjectURL(blob); set({ url }); } })
      .catch(e => { if (!dead) set({ error: (e as Error).message }); });
    return () => { dead = true; if (url) URL.revokeObjectURL(url); };
  }, [taskId, name]);
  return s;
}

function Shot({ taskId, page, className }: { taskId: string; page: BrowserPage; className?: string }) {
  const s = useShot(taskId, page.shot);
  const ph = `flex items-center justify-center bg-sunken text-[0.85rem] italic ${className}`;
  if (!page.shot) return <div className={`${ph} text-ink-3`}>no screenshot stored</div>;
  if (s.error) return <div className={`${ph} p-2 text-center text-bad`}>{s.error}</div>;
  if (!s.url) return <div className={`${ph} animate-pulse text-ink-3`}>loading…</div>;
  return <img src={s.url} alt={`Page ${page.seq}: ${page.title}`} className={`bg-white object-contain ${className}`} />;
}

export function BrowserView({ taskId, events, running }: { taskId: string | null; events: LedgerEvent[]; running: boolean }) {
  const { pages, blockedByBrowser, unavailable } = browserPages(events);
  const [sel, setSel] = useState<number | null>(null);   // null = follow the newest page
  useEffect(() => setSel(null), [taskId]);

  if (!taskId || (pages.length === 0 && !unavailable))
    return (
      <Empty title="No browser activity in this task">
        The browser sandbox starts the first time the agent calls <code className="rounded-[3px] bg-sunken px-1 font-mono text-[0.85em]">browse</code>.
        {running ? " Waiting…" : " Try a task like “open example.org and summarize it” (the host must be in MINILOCKER_ALLOW)."}
      </Empty>
    );
  if (pages.length === 0)
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="max-w-md">
          <div className="text-[1.15rem] font-bold text-warn">The browser sandbox could not start</div>
          <p className="mt-1 text-ink-2">Build the image once, then run the task again:</p>
          <code className={`${LISTING} mt-2 block break-all p-2.5`}>docker build -f images/browser/Dockerfile -t minilocker-browser:latest .</code>
        </div>
      </div>
    );

  const i = sel === null ? pages.length - 1 : Math.min(sel, pages.length - 1);
  const page = pages[i];
  const closed = [page.popups && `${page.popups} popup(s) closed`, page.dialogs && `${page.dialogs} dialog(s) dismissed`,
    page.downloads && `${page.downloads} download(s) blocked`].filter(Boolean).join(" · ");
  return (
    <div className="flex h-full flex-col bg-sheet">
      <div className="flex items-center gap-2 border-b border-rule bg-paper/50 px-3 py-2.5">
        <Btn size="sm" onClick={() => setSel(Math.max(0, i - 1))} disabled={i === 0} aria-label="Previous page">‹</Btn>
        <Btn size="sm" onClick={() => setSel(Math.min(pages.length - 1, i + 1))} disabled={i === pages.length - 1} aria-label="Next page">›</Btn>
        {/* Plain text on purpose: the URL is attacker-controlled, so it is never rendered as a link. */}
        <div className="min-w-0 flex-1 truncate rounded-full border border-rule bg-sunken px-3.5 py-1 font-mono text-[0.82rem] text-ink" title={page.url}>{page.url}</div>
        <span className="text-[0.85rem] tabular-nums text-ink-2">{page.seq}/{pages[pages.length - 1].seq}{page.status ? ` · HTTP ${page.status}` : ""}</span>
        <button onClick={() => setSel(null)} disabled={sel === null}
          className={`smcp inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[0.88rem] ${sel === null ? "border-ok/60 bg-ok-wash text-ok" : "border-rule text-ink-2 hover:border-ink-3"}`}>
          {sel === null ? <><Pulse tone="ok" /> live</> : "go live"}
        </button>
      </div>
      {page.flagged && (
        <div role="alert" className="border-b border-bad/40 bg-bad-wash px-4 py-2 text-[0.9rem] leading-snug text-bad">
          <b>Possible prompt injection (score {page.flagged.score}):</b> {page.flagged.labels.join("; ")}.
          <span className="text-ink-2"> The model was told to treat this page as data, and network or secret access is escalated for the rest of the task.</span>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto p-4">
        <figure>
          <Shot taskId={taskId} page={page} className="aspect-video w-full rounded-[6px] border border-rule-2 shadow-lift" />
          <figcaption className="mt-2 text-[0.9rem] text-ink-2">
            <b className="not-italic text-ink">Fig. {page.seq}.</b> <span className="italic">{page.title || "(no title)"}</span> · {page.action}
            {closed && <span className="text-ink-3"> · {closed}</span>}
          </figcaption>
        </figure>
        {blockedByBrowser > 0 && (
          <div className="mt-2"><Chip tone="bad">{blockedByBrowser} request{blockedByBrowser === 1 ? "" : "s"} blocked by the egress proxy</Chip></div>
        )}
      </div>
      <div className="flex gap-2 overflow-x-auto border-t border-rule bg-paper/50 p-2.5">
        {pages.map((pg, k) => (
          <button key={pg.seq} onClick={() => setSel(k)} aria-label={`Page ${pg.seq}: ${pg.title}`} aria-pressed={k === i}
            className={`relative shrink-0 overflow-hidden rounded-[5px] border-2 transition ${k === i ? "border-accent shadow-[0_0_14px_-2px_var(--accent)]" : pg.flagged ? "border-bad" : "border-transparent opacity-80 hover:opacity-100"}`}>
            <Shot taskId={taskId} page={pg} className="h-14 w-24" />
            {pg.flagged && <span className="absolute right-0.5 top-0.5 rounded-[2px] bg-bad px-1 text-[0.7rem] text-white">⚠</span>}
          </button>
        ))}
      </div>
    </div>
  );
}
