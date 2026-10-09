import { useEffect, useState } from "react";
import { fetchArtifact } from "./api";
import type { LedgerEvent } from "./api";
import { browserPages } from "./derive";
import type { BrowserPage } from "./derive";

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
  if (!page.shot) return <div className={`flex items-center justify-center bg-zinc-900 text-xs text-zinc-600 ${className}`}>no screenshot stored</div>;
  if (s.error) return <div className={`flex items-center justify-center bg-zinc-900 p-2 text-center text-xs text-red-400 ${className}`}>{s.error}</div>;
  if (!s.url) return <div className={`flex items-center justify-center bg-zinc-900 text-xs text-zinc-600 ${className}`}>loading…</div>;
  return <img src={s.url} alt={`Page ${page.seq}: ${page.title}`} className={`bg-white object-contain ${className}`} />;
}

export function BrowserView({ taskId, events, running }: { taskId: string | null; events: LedgerEvent[]; running: boolean }) {
  const { pages, blockedByBrowser, unavailable } = browserPages(events);
  const [sel, setSel] = useState<number | null>(null);   // null = follow the newest page
  useEffect(() => setSel(null), [taskId]);

  if (!taskId || (pages.length === 0 && !unavailable))
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-sm text-zinc-500">
        <div className="max-w-sm">
          <div className="text-zinc-300">No browser activity in this task</div>
          <p className="mt-2">The browser sandbox starts the first time the agent calls <code className="text-zinc-400">browse</code>.
            {running ? " Waiting…" : " Try a task like “open example.org and summarize it” (the host must be in MINILOCKER_ALLOW)."}</p>
        </div>
      </div>
    );
  if (pages.length === 0)
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-sm">
        <div className="max-w-md">
          <div className="text-amber-400">The browser sandbox could not start</div>
          <p className="mt-2 text-zinc-500">Build the image once, then run the task again:</p>
          <code className="mt-2 block break-all rounded bg-zinc-900 p-2 text-xs text-zinc-300">docker build -f images/browser/Dockerfile -t minilocker-browser:latest .</code>
        </div>
      </div>
    );

  const i = sel === null ? pages.length - 1 : Math.min(sel, pages.length - 1);
  const page = pages[i];
  const closed = [page.popups && `${page.popups} popup(s) closed`, page.dialogs && `${page.dialogs} dialog(s) dismissed`,
    page.downloads && `${page.downloads} download(s) blocked`].filter(Boolean).join(" · ");
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-3 py-2">
        <button onClick={() => setSel(Math.max(0, i - 1))} disabled={i === 0} aria-label="Previous page"
          className="rounded px-2 text-zinc-400 hover:text-zinc-100 disabled:opacity-30">‹</button>
        <button onClick={() => setSel(Math.min(pages.length - 1, i + 1))} disabled={i === pages.length - 1} aria-label="Next page"
          className="rounded px-2 text-zinc-400 hover:text-zinc-100 disabled:opacity-30">›</button>
        {/* Plain text on purpose: the URL is attacker-controlled, so it is never rendered as a link. */}
        <div className="min-w-0 flex-1 truncate rounded bg-zinc-900 px-3 py-1 font-mono text-xs text-zinc-300" title={page.url}>{page.url}</div>
        <span className="text-xs text-zinc-500">{page.seq}/{pages[pages.length - 1].seq}{page.status ? ` · HTTP ${page.status}` : ""}</span>
        <button onClick={() => setSel(null)} disabled={sel === null}
          className={`rounded border px-2 py-0.5 text-xs ${sel === null ? "border-emerald-700 text-emerald-400" : "border-zinc-700 text-zinc-400"}`}>
          {sel === null ? "● live" : "go live"}
        </button>
      </div>
      {page.flagged && (
        <div role="alert" className="border-b border-red-900 bg-red-950/50 px-3 py-2 text-xs text-red-300">
          <b>Possible prompt injection (score {page.flagged.score}):</b> {page.flagged.labels.join("; ")}.
          The model was told to treat this page as data, and network or secret access is escalated for the rest of the task.
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto p-3">
        <Shot taskId={taskId} page={page} className="aspect-video w-full rounded border border-zinc-800" />
        <div className="mt-2 text-xs text-zinc-400">
          <span className="text-zinc-200">{page.title || "(no title)"}</span> · {page.action}
          {closed && <span className="text-zinc-500"> · {closed}</span>}
        </div>
        {blockedByBrowser > 0 && (
          <div className="mt-1 text-xs text-red-400">{blockedByBrowser} request(s) from this browser were blocked by the egress proxy (see the right panel).</div>
        )}
      </div>
      <div className="flex gap-2 overflow-x-auto border-t border-zinc-800 p-2">
        {pages.map((pg, k) => (
          <button key={pg.seq} onClick={() => setSel(k)} aria-label={`Page ${pg.seq}: ${pg.title}`} aria-pressed={k === i}
            className={`relative shrink-0 rounded border ${k === i ? "border-emerald-600" : pg.flagged ? "border-red-700" : "border-zinc-800"}`}>
            <Shot taskId={taskId} page={pg} className="h-14 w-24 rounded" />
            {pg.flagged && <span className="absolute right-0.5 top-0.5 rounded bg-red-700 px-1 text-[10px] text-white">⚠</span>}
          </button>
        ))}
      </div>
    </div>
  );
}
