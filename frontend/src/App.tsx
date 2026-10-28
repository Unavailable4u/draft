import { useEffect, useState } from "react";
import { getToken, setToken } from "./api";
import { AttackLab } from "./AttackLab";
import { BrowserView } from "./Browser";
import { ApprovalModal, BlastPanel, StepStream, TaskForm } from "./components";
import { FilesView } from "./Files";
import { InfraView } from "./Infra";
import { ReportScreen } from "./Report";
import { SessionsScreen } from "./Sessions";
import { TimelineView } from "./Timeline";
import { TerminalView } from "./Terminal";
import { useAttacks } from "./useAttacks";
import { useTask } from "./useTask";
import type { TaskApi } from "./useTask";

type Screen = "workspace" | "timeline" | "attacks" | "report" | "sessions" | "infra";
type Tab = "terminal" | "browser" | "files";

const SCREENS: { id: Screen; label: string; short: string; description: string }[] = [
  { id: "workspace", label: "Workspace", short: "01", description: "Run and inspect" },
  { id: "timeline", label: "Timeline", short: "02", description: "Trace every change" },
  { id: "attacks", label: "Attack lab", short: "03", description: "Test the boundary" },
  { id: "report", label: "Reports", short: "04", description: "Review the evidence" },
  { id: "sessions", label: "Sessions", short: "05", description: "Previous runs" },
  { id: "infra", label: "Infrastructure", short: "06", description: "System health" },
];

const PATHS: Record<string, string> = {
  workspace: "M3 4.5h18v15H3z M3 9h18 M7 13l2 2-2 2 M12 17h4",
  timeline: "M4 4v16 M4 7h9 M13 7v5 M13 12h7 M4 18h7 M11 18v-4",
  attacks: "M12 2 4 5v6c0 5 3.3 8.4 8 11 4.7-2.6 8-6 8-11V5z M9 12l2 2 4-4",
  report: "M6 3h9l4 4v14H6z M15 3v4h4 M9 12h7 M9 16h7",
  sessions: "M4 5h16v4H4z M6 9v11h12V9 M10 13h4",
  infra: "M6 4h12v5H6z M6 15h12v5H6z M9 9v6 M15 9v6 M9 6.5h.01 M9 17.5h.01",
  terminal: "M4 5h16v14H4z M7 10l3 2.5L7 15 M12 15h5",
  browser: "M3 5h18v14H3z M3 9h18 M6.5 7h.01 M9 7h.01",
  files: "M6 3h8l4 4v14H6z M14 3v5h4 M9 13h6 M9 17h6",
  lock: "M6 11h12v10H6z M9 11V8a3 3 0 016 0v3 M12 15v2",
  arrow: "M5 12h14 M13 6l6 6-6 6",
};

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={PATHS[name] ?? PATHS.workspace} /></svg>;
}

const TABS: { id: Tab; label: string }[] = [
  { id: "terminal", label: "Terminal" },
  { id: "browser", label: "Browser" },
  { id: "files", label: "Artifacts" },
];

function Workspace({ t }: { t: TaskApi }) {
  const [tab, setTab] = useState<Tab>("terminal");
  const status = t.running ? "running" : t.end?.status ?? (t.taskId ? "finished" : "idle");
  return <div className="ml-screen ml-workspace-screen">
    <div className="ml-screen-intro">
      <div className="ml-intro-left">
        <div className="ml-eyebrow"><span className="ml-eyebrow-line" />THE EXECUTION CONSOLE <span className="ml-eyebrow-divider">/</span> 001</div>
        <h1>Build freely. <em>Run safely.</em></h1>
        <p>An isolated workspace for agents, with every action observable and every boundary accounted for.</p>
      </div>
      <div className="ml-intro-right" aria-label="Current task status">
        <span className={`ml-run-indicator ml-run-${status}`}><i />{t.running ? "EXECUTION IN PROGRESS" : t.taskId ? `LAST RUN · ${status.toUpperCase()}` : "READY FOR A NEW SESSION"}</span>
        <span className="ml-id">{t.taskId ? `RUN / ${t.taskId}` : "CONTROL PLANE / STANDBY"}</span>
      </div>
    </div>
    <div className="ml-workspace">
      <section className="ml-task-pane" aria-label="Task composer and event steps">
        <TaskForm running={t.running} error={t.error} onRun={t.start} />
        <div className="ml-pane-label"><span>ACTIVITY TRACE</span><span className="ml-pane-count">{t.events.filter(e => e.type === "tool.call").length} ACTIONS</span></div>
        <StepStream events={t.events} />
      </section>
      <section className="ml-console-pane" aria-label="Live execution output">
        <div className="ml-console-tabs">
          <div className="ml-tab-buttons" role="tablist" aria-label="Workspace views">
            {TABS.map(x => <button key={x.id} role="tab" aria-selected={tab === x.id}
              className={`ml-console-tab ${tab === x.id ? "is-active" : ""}`} onClick={() => setTab(x.id)}>
              <Icon name={x.id} size={16} />{x.label}</button>)}
          </div>
          <span className="ml-console-caption"><span className={t.running ? "ml-live-dot on" : "ml-live-dot"} />{t.running ? "STREAMING" : "OUTPUT"}</span>
        </div>
        <div className="ml-console-inner">
          <div className={`ml-terminal-frame ${tab === "terminal" ? "" : "hidden"}`}><TerminalView events={t.events} /></div>
          {tab === "browser" && <BrowserView taskId={t.taskId} events={t.events} running={t.running} />}
          {tab === "files" && <FilesView taskId={t.taskId} events={t.events} running={t.running} />}
        </div>
        <div className="ml-console-foot"><span>ISOLATED RUNTIME</span><span>{t.events.length} LEDGER EVENTS</span><span>READ-ONLY OUTPUT</span></div>
      </section>
      <aside className="ml-impact-pane" aria-label="Security observability panel">
        <div className="ml-impact-header"><div><span className="ml-kicker">OBSERVABILITY / 02</span><h2>Boundary monitor</h2></div><span className="ml-crosshair">✳</span></div>
        <BlastPanel events={t.events} report={t.report} running={t.running} />
      </aside>
    </div>
  </div>;
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("workspace");
  const [token, setTok] = useState(getToken());
  const [mobileMenu, setMobileMenu] = useState(false);
  const t = useTask();
  const lab = useAttacks();
  const [reportOverride, setReportOverride] = useState<string | null>(null);
  useEffect(() => setReportOverride(null), [t.taskId]);
  const reportId = reportOverride ?? t.taskId;
  const active = SCREENS.find(s => s.id === screen)!;
  return <div className="ml-shell">
    <aside className={`ml-sidebar ${mobileMenu ? "ml-menu-open" : ""}`}>
      <button className="ml-brand" onClick={() => { setScreen("workspace"); setMobileMenu(false); }} aria-label="Open MiniLocker workspace">
        <div className="ml-brand-mark"><Icon name="lock" size={22} /></div>
        <div className="ml-brand-type"><strong>mini<span>locker</span></strong><small>THE SAFE AGENT WORKSPACE</small></div>
      </button>
      <div className="ml-nav-group-label">WORKSPACE <span>↗</span></div>
      <nav className="ml-nav" aria-label="Primary navigation">
        {SCREENS.map(s => <button key={s.id} onClick={() => { setScreen(s.id); setMobileMenu(false); }}
          className={`ml-nav-item ${screen === s.id ? "is-active" : ""}`} aria-current={screen === s.id ? "page" : undefined}>
          <Icon name={s.id} size={18} /><span>{s.label}</span><small>{s.short}</small>
        </button>)}
      </nav>
      <div className="ml-sidebar-bottom">
        <div className="ml-trust-note"><div className="ml-trust-mark"><Icon name="lock" size={17} /></div><div><strong>Designed for control.</strong><span>Actions are tracked. Boundaries stay visible.</span></div></div>
        <div className="ml-sidebar-meta"><span>MINILOCKER</span><span>CONSOLE v01</span></div>
      </div>
    </aside>
    <main className="ml-main">
      <header className="ml-topbar">
        <div className="ml-topbar-path"><button className="ml-mobile-nav" onClick={() => setMobileMenu(v => !v)} aria-expanded={mobileMenu} aria-label="Toggle navigation">☰</button><span>PLATFORM</span><span className="ml-slash">/</span><strong>{active.label}</strong></div>
        <div className="ml-topbar-actions">
          <span className={`ml-topbar-state ${t.running ? "is-running" : ""}`}><i />{t.running ? "AGENT ACTIVE" : "AGENT IDLE"}</span>
          <details className="ml-auth-details"><summary><Icon name="lock" size={14} /> API ACCESS <span>⌄</span></summary>
            <div className="ml-auth-popover"><label htmlFor="ml-api-token">CONTROL PLANE TOKEN</label><p>Only required when API authentication is enabled.</p>
              <input id="ml-api-token" type="password" value={token} placeholder="Enter API token" autoComplete="off"
                onChange={e => { setTok(e.target.value); setToken(e.target.value); }} /></div>
          </details>
        </div>
      </header>
      {screen === "workspace" ? <Workspace t={t} /> : <div className="ml-screen ml-secondary-screen">
        <div className="ml-secondary-intro"><div><div className="ml-eyebrow"><span className="ml-eyebrow-line" /> MINI LOCKER / {active.short}</div><h1>{active.label}<em>.</em></h1><p>{active.description} — evidence, not assumptions.</p></div><span className="ml-secondary-index">{active.short} / 06</span></div>
        <div className="ml-secondary-content">
          {screen === "attacks" ? <AttackLab lab={lab} onOpenReport={id => { setReportOverride(id); setScreen("report"); }} />
            : screen === "report" ? <ReportScreen taskId={reportId} done={reportOverride !== null || (t.taskId !== null && !t.running)} />
            : screen === "sessions" ? <SessionsScreen onOpen={id => { t.attach(id); setScreen("workspace"); }} onReport={id => { setReportOverride(id); setScreen("report"); }} />
            : screen === "timeline" ? <TimelineView taskId={t.taskId} events={t.events} running={t.running} />
            : <InfraView active={screen === "infra"} />}
        </div>
      </div>}
    </main>
    {t.approval && t.taskId && <ApprovalModal key={t.approval.payload.id} ev={t.approval} taskId={t.taskId} />}
  </div>;
}
