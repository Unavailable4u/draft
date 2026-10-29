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
import { Chip, Mark, Pulse } from "./ui";
import type { Tint } from "./ui";

type Screen =
  | "workspace"
  | "timeline"
  | "attacks"
  | "report"
  | "sessions"
  | "infra";
type Tab = "terminal" | "browser" | "files";
type Theme = "light" | "dark";

const SCREENS: { id: Screen; label: string }[] = [
  { id: "workspace", label: "Workspace" },
  { id: "timeline", label: "Timeline" },
  { id: "attacks", label: "Attack Lab" },
  { id: "report", label: "Report" },
  { id: "sessions", label: "Sessions" },
  { id: "infra", label: "Infra" },
];

function Workspace({ t }: { t: TaskApi }) {
  const [tab, setTab] = useState<Tab>("terminal");
  const hidden = (x: Tab) => (tab === x ? "" : "hidden");
  return (
    <div className="grid min-h-0 flex-1 grid-cols-[22rem_minmax(0,1fr)_27rem]">
      <section className="flex min-h-0 flex-col border-r border-rule bg-paper/40">
        <TaskForm running={t.running} error={t.error} onRun={t.start} />
        <StepStream events={t.events} />
      </section>
      <section className="flex min-h-0 flex-col">
        <div
          role="tablist"
          className="flex shrink-0 items-center gap-1 px-4 pt-3"
        >
          {(["terminal", "browser", "files"] as Tab[]).map((x) => (
            <button
              key={x}
              role="tab"
              aria-selected={tab === x}
              onClick={() => setTab(x)}
              className={`smcp rounded-full border px-4 py-1 text-[0.95rem] transition ${
                tab === x
                  ? "border-accent/70 bg-accent/12 text-ink shadow-[0_0_18px_-6px_var(--accent)]"
                  : "border-transparent text-ink-3 hover:text-ink"
              }`}
            >
              {x}
            </button>
          ))}
        </div>
        <div className="min-h-0 flex-1 p-3">
          <div className="panel relative h-full overflow-hidden !bg-sheet">
            <div className={`h-full ${hidden("terminal")}`}>
              <TerminalView events={t.events} />
            </div>
            {tab === "browser" && (
              <BrowserView
                taskId={t.taskId}
                events={t.events}
                running={t.running}
              />
            )}
            {tab === "files" && (
              <FilesView
                taskId={t.taskId}
                events={t.events}
                running={t.running}
              />
            )}
          </div>
        </div>
      </section>
      <section className="min-h-0 border-l border-rule bg-paper/40">
        <BlastPanel events={t.events} report={t.report} running={t.running} />
      </section>
    </div>
  );
}

function statusTone(status: string): Tint {
  if (status === "idle") return "mute";
  if (status === "running") return "info";
  if (status.startsWith("error")) return "bad";
  if (status.startsWith("halted")) return "warn";
  return "ok";
}

const Sun = () => (
  <svg
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    aria-hidden
  >
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8" />
  </svg>
);
const Moon = () => (
  <svg
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden
  >
    <path d="M20.5 14.2A8.5 8.5 0 1 1 9.8 3.5a6.7 6.7 0 0 0 10.7 10.7Z" />
  </svg>
);
const Key = () => (
  <svg
    width="14"
    height="14"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden
  >
    <circle cx="8" cy="15" r="4" />
    <path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2" />
  </svg>
);

export default function App() {
  const [screen, setScreen] = useState<Screen>("workspace");
  const [token, setTok] = useState(getToken());
  // The token is applied (screens refetch) when the field loses focus or Enter is pressed, not on every keystroke.
  const [applied, setApplied] = useState(getToken());
  const [theme, setTheme] = useState<Theme>(() =>
    document.documentElement.dataset.theme === "dark" ? "dark" : "light",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("minilocker.theme", theme);
    } catch {
      /* private mode */
    }
  }, [theme]);
  const t = useTask();
  const lab = useAttacks();
  // An attack's report overrides the workspace task until the workspace starts a new one.
  const [reportOverride, setReportOverride] = useState<string | null>(null);
  useEffect(() => setReportOverride(null), [t.taskId]);
  const reportId = reportOverride ?? t.taskId;
  const status = !t.taskId
    ? "idle"
    : t.running
      ? "running"
      : (t.end?.status ?? "done");
  const apply = () => {
    const v = token.trim();
    setToken(v);
    setTok(v);
    setApplied(v);
  };
  return (
    <div className="flex h-full flex-col text-ink">
      <svg width="0" height="0" aria-hidden className="absolute">
        <defs>
          <linearGradient id="mlk-ok" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="var(--ok-a)" />
            <stop offset=".55" stopColor="var(--ok-b)" />
            <stop offset="1" stopColor="var(--ok-c)" />
          </linearGradient>
        </defs>
      </svg>
      <header className="relative z-10 shrink-0 border-b border-rule bg-paper/75 backdrop-blur-md">
        <div className="flex items-stretch gap-5 px-5 xl:gap-8">
          <div className="flex items-center gap-3 py-2.5 text-ink-2">
            <span className="grid h-10 w-10 place-items-center rounded-full border border-rule-2 bg-sheet shadow-[0_0_22px_-6px_var(--accent)]">
              <Mark size={30} />
            </span>
            <div className="leading-none">
              <div className="display text-[1.55rem] text-ink">
                Mini<span className="text-accent-ink">Locker</span>
              </div>
              <div className="smcp mt-1 hidden text-[0.74rem] text-ink-3 xl:block">
                a blast-radius ledger for AI agents
              </div>
            </div>
          </div>
          <nav className="flex items-stretch gap-0.5" aria-label="Screens">
            {SCREENS.map((s, i) => (
              <button
                key={s.id}
                onClick={() => setScreen(s.id)}
                aria-current={screen === s.id ? "page" : undefined}
                className={`relative flex items-center gap-1.5 whitespace-nowrap px-2.5 text-[1.04rem] transition xl:px-3.5 ${
                  screen === s.id
                    ? "font-bold text-ink"
                    : "text-ink-2 hover:text-ink"
                }`}
              >
                <span
                  className={`text-[0.78rem] italic ${screen === s.id ? "text-accent-ink" : "text-ink-3"}`}
                >
                  {i + 1}
                </span>
                {s.label}
                {screen === s.id && (
                  <span
                    aria-hidden
                    className="absolute inset-x-2 bottom-0 h-[3px] rounded-t-full bg-accent"
                    style={{ boxShadow: "0 0 14px var(--accent)" }}
                  />
                )}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2.5 py-2">
            <Chip
              tone={statusTone(status)}
              title="Current task"
              dot={status !== "running"}
            >
              {status === "running" && <Pulse tone="info" />}
              {t.taskId && (
                <span className="font-mono normal-case tracking-normal">
                  {t.taskId}
                </span>
              )}
              {t.taskId && <span aria-hidden>·</span>}
              {status}
            </Chip>
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label={
                theme === "dark"
                  ? "Switch to the paper theme"
                  : "Switch to the midnight theme"
              }
              title={theme === "dark" ? "Paper" : "Midnight"}
              className="grid h-8 w-8 place-items-center rounded-[5px] border border-rule bg-sheet text-ink-2 transition hover:border-accent hover:text-ink"
            >
              {theme === "dark" ? <Sun /> : <Moon />}
            </button>
            <label
              title="Only needed if MINILOCKER_API_TOKEN is set"
              className="flex items-center gap-1.5 rounded-[5px] border border-rule bg-sheet px-2 py-1 text-ink-3 transition focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/20"
            >
              <Key />
              <input
                type="password"
                value={token}
                placeholder="API token"
                aria-label="API token"
                autoComplete="off"
                onChange={(e) => {
                  setTok(e.target.value);
                  setToken(e.target.value);
                }}
                onBlur={() => {
                  if (token.trim() !== applied) apply();
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") apply();
                }}
                className="w-20 bg-transparent text-[0.88rem] text-ink outline-none placeholder:text-ink-3 xl:w-24"
              />
              {applied && (
                <span
                  aria-hidden
                  title="Token set"
                  className="h-1.5 w-1.5 rounded-full bg-ok"
                />
              )}
            </label>
          </div>
        </div>
        <div className="hairline-accent" />
      </header>
      <main key={applied} className="flex min-h-0 flex-1 flex-col">
        {screen === "workspace" ? (
          <Workspace t={t} />
        ) : screen === "attacks" ? (
          <AttackLab
            lab={lab}
            onOpenReport={(id) => {
              setReportOverride(id);
              setScreen("report");
            }}
          />
        ) : screen === "report" ? (
          <ReportScreen
            taskId={reportId}
            done={reportOverride !== null || (t.taskId !== null && !t.running)}
          />
        ) : screen === "sessions" ? (
          <SessionsScreen
            onOpen={(id) => {
              t.attach(id);
              setScreen("workspace");
            }}
            onReport={(id) => {
              setReportOverride(id);
              setScreen("report");
            }}
          />
        ) : screen === "timeline" ? (
          <TimelineView
            taskId={t.taskId}
            events={t.events}
            running={t.running}
          />
        ) : (
          <InfraView active={screen === "infra"} />
        )}
      </main>
      {t.approval && t.taskId && (
        <ApprovalModal
          key={t.approval.payload.id}
          ev={t.approval}
          taskId={t.taskId}
        />
      )}
    </div>
  );
}
