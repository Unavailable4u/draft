import { useEffect, useState } from "react";
import { getInfra } from "./api";
import type { InfraStatus } from "./api";
import { Card, Chip, Meter, PageHead, Pulse, Row, Spin } from "./ui";
import type { Tint } from "./ui";

const GIB = 1024 ** 3;
const gib = (n: number | null | undefined) => (n == null ? "—" : `${(n / GIB).toFixed(1)} GiB`);
const dur = (s: number | null | undefined) => {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${Math.floor(s % 60)}s`;
};

function Panel({ no, title, badge, tone = "info", children, delay = 0 }: {
  no: number; title: string; badge?: string; tone?: "ok" | "bad" | "info"; children: React.ReactNode; delay?: number;
}) {
  const t: Tint = tone === "info" ? "mute" : tone;
  return (
    <Card className="p-4">
      <div style={{ animationDelay: `${delay}ms` }} className="rise">
        <div className="flex items-baseline gap-2.5">
          <span className="italic text-accent">§{no}</span>
          <h3 className="text-[1.15rem] font-bold text-ink">{title}</h3>
          {badge && <Chip tone={t} dot={tone !== "info"} className="ml-auto">{badge}</Chip>}
        </div>
        <div className="hairline-accent mt-1.5" />
        <dl className="mt-3 space-y-1.5 text-[0.92rem]">{children}</dl>
      </div>
    </Card>
  );
}

/** A labelled meter: how full something is, with the numbers beside it. */
function Gauge({ label, used, total, fmtv }: { label: string; used: number | null | undefined; total: number | null | undefined; fmtv: (n: number) => string }) {
  if (used == null || !total) return null;
  const f = used / total;
  return (
    <div className="pb-1">
      <div className="mb-1 flex items-baseline justify-between text-[0.88rem]"><span className="text-ink-2">{label}</span><span className="tabular-nums text-ink">{fmtv(used)} <span className="text-ink-3">of {fmtv(total)}</span></span></div>
      <Meter value={f} tone={f > 0.9 ? "bad" : f > 0.75 ? "warn" : "ok"} />
    </div>
  );
}

/** One line of the system's wiring, as a node on the diagram. */
function Node({ name, detail, tone }: { name: string; detail: string; tone: Tint }) {
  return (
    <div className={`flex min-w-0 flex-1 flex-col items-center rounded-[7px] border px-3 py-2.5 text-center ${tone === "ok" ? "border-ok/50 bg-ok-wash" : tone === "bad" ? "border-bad/50 bg-bad-wash" : "border-rule bg-sheet"}`}>
      <span className="smcp text-[0.86rem] text-ink-2">{name}</span>
      <span className="mt-0.5 max-w-full truncate text-[0.9rem] font-bold text-ink" title={detail}>{detail}</span>
    </div>
  );
}
const Arrow = () => <span aria-hidden className="shrink-0 px-1 text-[1.2rem] text-ink-3">→</span>;

export function InfraView({ active }: { active: boolean }) {
  const [s, setS] = useState<InfraStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const load = () => getInfra().then(r => { if (alive) { setS(r); setErr(null); } }).catch(e => { if (alive) setErr((e as Error).message); });
    load();
    const t = setInterval(load, 4000);
    return () => { alive = false; clearInterval(t); };
  }, [active]);

  if (!s) return <div className="flex flex-1 items-center justify-center gap-2 italic text-ink-2">{err ? <span className="text-bad">{err}</span> : <><Spin /> Reading the host…</>}</div>;
  const { host, docker, egress, inference, storage, vultr } = s;
  return (
    <div className="min-h-0 flex-1 overflow-y-auto px-6 py-7">
      <div className="mx-auto max-w-5xl space-y-5">
        <PageHead eyebrow="Control plane" title="Infrastructure" sub="Where the control plane runs, and what it is connected to."
          right={<Chip tone="ok"><Pulse tone="ok" /> live · every 4 s</Chip>} />
        {err && <p role="alert" className="text-[0.92rem] text-bad">Refresh failed: {err}</p>}

        <Card className="rise p-4">
          <div className="mb-2.5 flex items-baseline gap-2"><span className="smcp text-[0.9rem] text-ink">How a task flows</span><span className="text-[0.84rem] italic text-ink-3">each box is a live connection</span></div>
          <div className="flex items-stretch">
            <Node name="host" detail={vultr.available ? `Vultr ${vultr.region ?? ""}` : host.hostname} tone="ok" />
            <Arrow />
            <Node name="docker" detail={docker.available ? `v${docker.version}` : "unreachable"} tone={docker.available ? "ok" : "bad"} />
            <Arrow />
            <Node name="sandboxes" detail={`${docker.sandboxes.length} live`} tone={docker.sandboxes.length ? "ok" : "info"} />
            <Arrow />
            <Node name="egress proxy" detail={egress.attached ? `${(egress.allowed_hosts ?? []).length} hosts allowed` : "no network"} tone={egress.attached ? "ok" : "bad"} />
            <Arrow />
            <Node name="inference" detail={inference.model ?? "not set"} tone={inference.configured ? "ok" : "info"} />
            <Arrow />
            <Node name="artifacts" detail={storage.attached ? storage.bucket ?? "attached" : "not attached"} tone={storage.attached ? "ok" : "info"} />
          </div>
        </Card>

        <div className="grid grid-cols-2 gap-4">
          <Panel no={1} title="Host" badge={vultr.available ? "Vultr VM" : "not a Vultr VM"} tone={vultr.available ? "ok" : "info"}>
            <Gauge label="memory in use" used={host.memory_total_bytes != null && host.memory_available_bytes != null ? host.memory_total_bytes - host.memory_available_bytes : null} total={host.memory_total_bytes} fmtv={gib} />
            <Gauge label="disk in use" used={host.disk_total_bytes - host.disk_free_bytes} total={host.disk_total_bytes} fmtv={gib} />
            <Row k="hostname">{vultr.hostname ?? host.hostname}</Row>
            <Row k="os">{host.os}</Row>
            <Row k="cpus · load">{`${host.cpus ?? "—"} · ${host.load ? host.load.join(" ") : "—"}`}</Row>
            <Row k="uptime">{dur(host.uptime_s)}</Row>
            {vultr.available
              ? <>
                  <Row k="Vultr region">{vultr.region}</Row>
                  <Row k="Vultr plan">{vultr.plan}</Row>
                  <Row k="instance" mono>{vultr.instance_id}</Row>
                </>
              : <Row k="Vultr"><span className="italic text-ink-2">{vultr.reason}</span></Row>}
          </Panel>

          <Panel no={2} title="Docker" badge={docker.available ? "up" : "unreachable"} tone={docker.available ? "ok" : "bad"} delay={50}>
            {docker.available ? <>
              <Row k="version">{docker.version}</Row>
              <Row k="storage driver">{docker.storage_driver}</Row>
              <Row k="cgroup">{`v${docker.cgroup_version ?? "?"}`}</Row>
              <Row k="runtimes">{(docker.runtimes ?? []).join(", ")}</Row>
              <Row k="containers running">{docker.containers_running}</Row>
            </> : <Row k="error"><span className="text-bad">{docker.reason}</span></Row>}
          </Panel>

          <Panel no={3} title="Sandboxes" badge={`${docker.sandboxes.length} live`} tone={docker.sandboxes.length ? "ok" : "info"} delay={100}>
            {docker.sandboxes.length === 0 && <p className="italic leading-snug text-ink-2">None right now. A sandbox exists only while a task runs, and is destroyed afterwards.</p>}
            {docker.sandboxes.map(b => (
              <Row key={b.name} k={<span className="font-mono text-[0.85em]">{b.name.replace("minilocker-", "")}</span>}>{b.role} · {b.status} · {dur(b.age_s)}</Row>
            ))}
          </Panel>

          <Panel no={4} title="Egress proxy" badge={egress.attached ? egress.proxy ?? "up" : "not attached"} tone={egress.attached ? "ok" : "bad"} delay={150}>
            {egress.attached ? <>
              <Row k="allowlist">{(egress.allowed_hosts ?? []).join(", ") || "none: everything is refused"}</Row>
              <Row k="credential broker">{(egress.brokered_services ?? []).length ? (egress.brokered_services ?? []).join(", ") : "not configured"}</Row>
            </> : <Row k="effect">sandboxes have no network at all</Row>}
          </Panel>

          <Panel no={5} title="Inference" badge={inference.vultr ? "Vultr Serverless Inference" : inference.configured ? "other provider" : "not configured"}
            tone={inference.vultr ? "ok" : "info"} delay={200}>
            <Row k="endpoint host">{inference.host}</Row>
            <Row k="model">{inference.model}</Row>
            <Row k="api key">{inference.key_set ? "set (never shown)" : "not set"}</Row>
            <Row k="tool mode">{inference.tool_mode}</Row>
          </Panel>

          <Panel no={6} title="Artifact storage" badge={storage.attached ? (storage.vultr ? "Vultr Object Storage" : "attached") : "not attached"}
            tone={storage.attached ? "ok" : "info"} delay={250}>
            <Row k="endpoint host">{storage.endpoint_host}</Row>
            <Row k="bucket">{storage.bucket}</Row>
            {storage.error && <Row k="error"><span className="text-bad">{storage.error}</span></Row>}
          </Panel>
        </div>
        <p className="border-t border-rule pt-2.5 text-[0.84rem] italic text-ink-3"><span className="mr-1 not-italic">†</span>Read from the control plane every few seconds. Secrets are never included: keys show only as set or not set.</p>
      </div>
    </div>
  );
}
