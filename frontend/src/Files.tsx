import { useEffect, useState } from "react";
import { downloadArtifact, fetchArtifact } from "./api";
import type { LedgerEvent } from "./api";
import { savedFiles } from "./derive";
import { Btn, Chip, Empty, Label } from "./ui";

const TEXT = new Set(["txt", "md", "py", "js", "ts", "json", "csv", "tsv", "log", "yml", "yaml", "toml", "ini", "sh", "xml", "html", "css", "sql"]);
const IMAGE = new Set(["png", "jpg", "jpeg", "gif", "webp"]);
const PREVIEW_BYTES = 200_000;
const ext = (n: string) => (n.includes(".") ? n.split(".").pop()!.toLowerCase() : "");
const size = (b: number) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);

type Preview = { state: "loading" } | { state: "error"; message: string }
  | { state: "text"; text: string; truncated: boolean; sha: string | null }
  | { state: "image"; url: string; sha: string | null } | { state: "none"; sha: string | null };

/** Previews are produced client-side from the raw bytes: text goes into a <pre> as text, images are
 *  shown only if the server vouched for them. File content is attacker-controlled, so it is never
 *  inserted as markup. */
function usePreview(taskId: string, f: { name: string; bytes: number } | null): Preview | null {
  const [p, set] = useState<Preview | null>(null);
  useEffect(() => {
    if (!f) { set(null); return; }
    set({ state: "loading" });
    let dead = false, url: string | undefined;
    const e = ext(f.name);
    if (!TEXT.has(e) && !IMAGE.has(e)) { set({ state: "none", sha: null }); return; }
    fetchArtifact(taskId, f.name).then(async ({ blob, sha256 }) => {
      if (dead) return;
      if (IMAGE.has(e)) { url = URL.createObjectURL(blob); set({ state: "image", url, sha: sha256 }); }
      else set({ state: "text", text: await blob.slice(0, PREVIEW_BYTES).text(), truncated: blob.size > PREVIEW_BYTES, sha: sha256 });
    }).catch(err => { if (!dead) set({ state: "error", message: (err as Error).message }); });
    return () => { dead = true; if (url) URL.revokeObjectURL(url); };
  }, [taskId, f?.name]);
  return p;
}

export function FilesView({ taskId, events, running }: { taskId: string | null; events: LedgerEvent[]; running: boolean }) {
  const saved = savedFiles(events);
  const [name, setName] = useState<string | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);
  useEffect(() => { setName(null); setDlError(null); }, [taskId]);
  const file = saved.files.find(f => f.name === name) ?? null;
  const preview = usePreview(taskId ?? "", file);

  if (!taskId || (saved.files.length === 0 && saved.skipped.length === 0 && saved.failed === 0 && saved.screenshots === 0))
    return (
      <Empty title="No saved files">
        {running
          ? "Files the agent leaves in /workspace are saved when the task ends, so they outlive the sandbox."
          : "Nothing was saved for this task: it produced no files, or no artifact store was attached (set MINILOCKER_S3_*; see deploy/dev-storage.sh)."}
      </Empty>
    );

  return (
    <div className="flex h-full min-h-0 bg-sheet">
      <div className="flex w-72 shrink-0 flex-col border-r border-rule bg-paper/40">
        <div className="flex items-center gap-2 border-b border-rule px-3.5 py-2.5"><span aria-hidden className="h-3.5 w-[3px] rounded-full bg-accent" /><Label className="text-ink">Workspace files</Label><span className="ml-auto text-[0.8rem] tabular-nums text-ink-3">{saved.files.length}</span></div>
        <ul className="min-h-0 flex-1 overflow-auto p-2">
          {saved.files.length === 0 && <li className="p-2 italic text-ink-3">No workspace files were saved.</li>}
          {saved.files.map(f => (
            <li key={f.name}>
              <button onClick={() => { setName(f.name); setDlError(null); }} aria-pressed={f.name === name}
                className={`flex w-full items-baseline gap-2 rounded-[5px] px-2.5 py-1.5 text-left transition ${f.name === name ? "bg-accent font-bold text-on-accent" : "text-ink hover:bg-raised"}`}>
                <span className="min-w-0 flex-1 truncate font-mono text-[0.84rem]" title={f.name}>{f.name.replace(/^workspace\//, "")}</span>
                <span className={`shrink-0 text-[0.78rem] tabular-nums ${f.name === name ? "text-on-accent/80" : "text-ink-3"}`}>{size(f.bytes)}</span>
              </button>
            </li>
          ))}
        </ul>
        <div className="space-y-0.5 border-t border-rule p-3 text-[0.8rem] italic leading-snug text-ink-2">
          {saved.screenshots > 0 && <div>{saved.screenshots} screenshot(s) are in the Browser tab.</div>}
          {saved.skipped.length > 0 && <div className="text-warn" title={saved.skipped.map(s => `${s.name} (${s.reason})`).join("\n")}>
            {saved.skipped.length} file(s) not saved: too large or over the limit.</div>}
          {saved.failed > 0 && <div className="text-bad">{saved.failed} save error(s): see the ledger.</div>}
          <div className="text-ink-3">pkgs/, node_modules/, .git/ and caches are never saved.</div>
        </div>
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        {!file ? <div className="m-auto italic text-ink-3">Select a file to preview it.</div> : (
          <>
            <div className="border-b border-rule bg-paper/40 px-4 py-2.5">
              <div className="flex items-center gap-3">
                <span className="min-w-0 flex-1 truncate font-mono text-[0.9rem] text-ink" title={file.name}>{file.name}</span>
                <Btn size="sm" onClick={() => { setDlError(null); downloadArtifact(taskId, file.name).catch(e => setDlError((e as Error).message)); }}>Download</Btn>
              </div>
              {preview && "sha" in preview && preview.sha && (
                <div className="mt-1.5 flex items-center gap-2">
                  <Chip tone={preview.sha === file.sha256 ? "ok" : "bad"} title={`sha256 ${file.sha256}`}>
                    {preview.sha === file.sha256 ? "✓ matches ledger hash" : "✗ hash differs from ledger"}
                  </Chip>
                  <span className="font-mono text-[0.76rem] text-ink-3" title={file.sha256}>sha256 {file.sha256.slice(0, 16)}…</span>
                </div>
              )}
            </div>
            {dlError && <div role="alert" className="border-b border-bad/40 bg-bad-wash px-4 py-1.5 text-[0.88rem] text-bad">{dlError}</div>}
            <div className="min-h-0 flex-1 overflow-auto p-4">
              {!preview || preview.state === "loading" ? <span className="animate-pulse italic text-ink-3">loading…</span>
                : preview.state === "error" ? (
                  <div role="alert" className="text-[0.92rem] text-bad">
                    {preview.message}
                    {preview.message.startsWith("409") && <div className="mt-1 text-ink-2">The stored bytes or the ledger failed verification, so nothing is shown.</div>}
                    {preview.message.startsWith("503") && <div className="mt-1 text-ink-2">No artifact store is attached to this control plane.</div>}
                  </div>)
                : preview.state === "image" ? <img src={preview.url} alt={file.name} className="max-w-full rounded-[5px] border border-rule bg-white" />
                : preview.state === "text" ? (
                  <>
                    <pre className="whitespace-pre-wrap break-all rounded-[5px] border border-rule bg-sunken p-3.5 font-mono text-[0.84rem] leading-relaxed text-ink">{preview.text}</pre>
                    {preview.truncated && <div className="mt-2 text-[0.85rem] italic text-ink-2">Preview limited to the first {size(PREVIEW_BYTES)}. Download for the rest.</div>}
                  </>)
                : <div className="italic text-ink-2">No preview for this file type. Use Download.</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
