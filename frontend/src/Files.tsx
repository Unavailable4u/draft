import { useEffect, useState } from "react";
import { downloadArtifact, fetchArtifact } from "./api";
import type { LedgerEvent } from "./api";
import { savedFiles } from "./derive";

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
      <div className="flex h-full items-center justify-center p-6 text-center text-sm text-zinc-500">
        <div className="max-w-sm">
          <div className="text-zinc-300">No saved files</div>
          <p className="mt-2">{running
            ? "Files the agent leaves in /workspace are saved when the task ends, so they outlive the sandbox."
            : "Nothing was saved for this task: it produced no files, or no artifact store was attached (set MINILOCKER_S3_*; see deploy/dev-storage.sh)."}</p>
        </div>
      </div>
    );

  return (
    <div className="flex h-full min-h-0">
      <div className="flex w-72 shrink-0 flex-col border-r border-zinc-800">
        <ul className="min-h-0 flex-1 overflow-auto p-2 text-xs">
          {saved.files.length === 0 && <li className="p-2 text-zinc-500">No workspace files were saved.</li>}
          {saved.files.map(f => (
            <li key={f.name}>
              <button onClick={() => { setName(f.name); setDlError(null); }} aria-pressed={f.name === name}
                className={`flex w-full items-baseline gap-2 rounded px-2 py-1.5 text-left ${f.name === name ? "bg-zinc-800 text-zinc-100" : "text-zinc-300 hover:bg-zinc-900"}`}>
                <span className="min-w-0 flex-1 truncate font-mono" title={f.name}>{f.name.replace(/^workspace\//, "")}</span>
                <span className="shrink-0 text-zinc-500">{size(f.bytes)}</span>
              </button>
            </li>
          ))}
        </ul>
        <div className="border-t border-zinc-800 p-2 text-[11px] text-zinc-500">
          {saved.screenshots > 0 && <div>{saved.screenshots} screenshot(s) are in the Browser tab.</div>}
          {saved.skipped.length > 0 && <div className="text-amber-400" title={saved.skipped.map(s => `${s.name} (${s.reason})`).join("\n")}>
            {saved.skipped.length} file(s) not saved: too large or over the limit.</div>}
          {saved.failed > 0 && <div className="text-red-400">{saved.failed} save error(s): see the ledger.</div>}
          <div>pkgs/, node_modules/, .git/ and caches are never saved.</div>
        </div>
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        {!file ? <div className="m-auto text-sm text-zinc-500">Select a file to preview it.</div> : (
          <>
            <div className="flex items-center gap-3 border-b border-zinc-800 px-3 py-2 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono text-zinc-300" title={file.name}>{file.name}</span>
              {preview && "sha" in preview && preview.sha && (
                <span className={preview.sha === file.sha256 ? "text-emerald-400" : "text-red-400"}
                  title={`sha256 ${file.sha256}`}>
                  {preview.sha === file.sha256 ? "✓ matches ledger hash" : "✗ hash differs from ledger"} · {file.sha256.slice(0, 10)}…
                </span>
              )}
              <button onClick={() => { setDlError(null); downloadArtifact(taskId, file.name).catch(e => setDlError((e as Error).message)); }}
                className="rounded border border-zinc-700 px-2 py-0.5 text-zinc-200 hover:border-emerald-600">Download</button>
            </div>
            {dlError && <div role="alert" className="border-b border-red-900 bg-red-950/50 px-3 py-1.5 text-xs text-red-300">{dlError}</div>}
            <div className="min-h-0 flex-1 overflow-auto p-3">
              {!preview || preview.state === "loading" ? <span className="text-xs text-zinc-500">loading…</span>
                : preview.state === "error" ? (
                  <div role="alert" className="text-xs text-red-400">
                    {preview.message}
                    {preview.message.startsWith("409") && <div className="mt-1 text-zinc-500">The stored bytes or the ledger failed verification, so nothing is shown.</div>}
                    {preview.message.startsWith("503") && <div className="mt-1 text-zinc-500">No artifact store is attached to this control plane.</div>}
                  </div>)
                : preview.state === "image" ? <img src={preview.url} alt={file.name} className="max-w-full bg-white" />
                : preview.state === "text" ? (
                  <>
                    <pre className="whitespace-pre-wrap break-all font-mono text-xs text-zinc-300">{preview.text}</pre>
                    {preview.truncated && <div className="mt-2 text-xs text-zinc-500">Preview limited to the first {size(PREVIEW_BYTES)}. Download for the rest.</div>}
                  </>)
                : <div className="text-xs text-zinc-500">No preview for this file type. Use Download.</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
