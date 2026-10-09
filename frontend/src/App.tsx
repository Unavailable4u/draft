import { useEffect, useState } from "react";
import { getToken, setToken } from "./api";
import { AttackLab } from "./AttackLab";
import { BrowserView } from "./Browser";
import { ApprovalModal, BlastPanel, StepStream, Stub, TaskForm } from "./components";
import { FilesView } from "./Files";
import { ReportScreen } from "./Report";
import { SessionsScreen } from "./Sessions";
import { TerminalView } from "./Terminal";
import { useAttacks } from "./useAttacks";
import { useTask } from "./useTask";
import type { TaskApi } from "./useTask";

type Screen = "workspace" | "timeline" | "attacks" | "report" | "sessions" | "infra";
type Tab = "terminal" | "browser" | "files";

const SCREENS: { id: Screen; label: string; needs?: string }[] = [
  { id: "workspace", label: "Workspace" },
  { id: "timeline", label: "Timeline", needs: "Needs snapshots and POST /api/tasks/{id}/rewind (Week 4)." },
  { id: "attacks", label: "Attack Lab" },
  { id: "report", label: "Report" },
  { id: "sessions", label: "Sessions" },
  { id: "infra", label: "Infra", needs: "Needs an infra/status endpoint (VM, running sandboxes, resource use)." },
];

function Workspace({ t }: { t: TaskApi }) {
  const [tab, setTab] = useState<Tab>("terminal");
  const hidden = (x: Tab) => (tab === x ? "" : "hidden");
  return (
    <div className="grid min-h-0 flex-1 grid-cols-[320px_1fr_340px]">
      <section className="flex min-h-0 flex-col border-r border-zinc-800">
        <TaskForm running={t.running} error={t.error} onRun={t.start} />
        <StepStream events={t.events} />
      </section>
      <section className="flex min-h-0 flex-col">
        <div className="flex border-b border-zinc-800 text-sm">
          {(["terminal", "browser", "files"] as Tab[]).map(x => (
            <button key={x} onClick={() => setTab(x)}
              className={`px-4 py-2 capitalize ${tab === x ? "border-b-2 border-emerald-500 text-zinc-100" : "text-zinc-500"}`}>{x}</button>
          ))}
        </div>
        <div className="min-h-0 flex-1 bg-zinc-950">
          <div className={`h-full ${hidden("terminal")}`}><TerminalView events={t.events} /></div>
          {tab === "browser" && <BrowserView taskId={t.taskId} events={t.events} running={t.running} />}
          {tab === "files" && <FilesView taskId={t.taskId} events={t.events} running={t.running} />}
        </div>
      </section>
      <section className="min-h-0 border-l border-zinc-800">
        <BlastPanel events={t.events} report={t.report} running={t.running} />
      </section>
    </div>
  );
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("workspace");
  const [token, setTok] = useState(getToken());
  const t = useTask();
  const lab = useAttacks();
  // An attack's report overrides the workspace task until the workspace starts a new one.
  const [reportOverride, setReportOverride] = useState<string | null>(null);
  useEffect(() => setReportOverride(null), [t.taskId]);
  const reportId = reportOverride ?? t.taskId;
  const cur = SCREENS.find(s => s.id === screen)!;
  const status = !t.taskId ? "idle" : t.running ? "running" : (t.end?.status ?? "done");
  return (
    <div className="flex h-full flex-col bg-zinc-950 text-sm text-zinc-200">
      <header className="flex items-center gap-4 border-b border-zinc-800 px-4 py-2">
        <b className="text-emerald-400">◉ MiniLocker</b>
        <nav className="flex gap-1">
          {SCREENS.map(s => (
            <button key={s.id} onClick={() => setScreen(s.id)}
              className={`rounded px-3 py-1 ${screen === s.id ? "bg-zinc-800 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}>{s.label}</button>
          ))}
        </nav>
        <span className={`ml-auto rounded px-2 py-0.5 text-xs ${t.running ? "bg-amber-900/50 text-amber-300" : "bg-zinc-800 text-zinc-400"}`}>
          {t.taskId ? `${t.taskId} · ` : ""}{status}
        </span>
        <input type="password" value={token} placeholder="API token" title="Only needed if MINILOCKER_API_TOKEN is set"
          onChange={e => { setTok(e.target.value); setToken(e.target.value); }}
          className="w-28 rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs" />
      </header>
      {screen === "workspace" ? <Workspace t={t} />
        : screen === "attacks" ? <AttackLab lab={lab} onOpenReport={id => { setReportOverride(id); setScreen("report"); }} />
        : screen === "report" ? <ReportScreen taskId={reportId} done={reportOverride !== null || (t.taskId !== null && !t.running)} />
        : screen === "sessions" ? <SessionsScreen onOpen={id => { t.attach(id); setScreen("workspace"); }}
            onReport={id => { setReportOverride(id); setScreen("report"); }} />
        : <Stub title={cur.label} needs={cur.needs!} />}
      {t.approval && t.taskId && <ApprovalModal key={t.approval.payload.id} ev={t.approval} taskId={t.taskId} />}
    </div>
  );
}
