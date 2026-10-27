import { useEffect, useState } from "react";
import { getInfra } from "./api";
import type { InfraStatus } from "./api";

const GIB = 1024 ** 3;
const gib = (n: number | null | undefined) => (n == null ? "—" : `${(n / GIB).toFixed(1)} GiB`);
const dur = (s: number | null | undefined) => {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${Math.floor(s % 60)}s`;
};

function Card({ title, badge, tone = "info", children }: { title: string; badge?: string; tone?: "ok" | "bad" | "info"; children: React.ReactNode }) {
  const cls = tone === "ok" ? "border-emerald-800 text-emerald-400" : tone === "bad" ? "border-red-800 text-red-400" : "border-zinc-700 text-zinc-500";
  return (
    <section className="rounded border border-zinc-800 bg-zinc-900 p-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs uppercase tracking-wide text-zinc-400">{title}</h3>
        {badge && <span className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${cls}`}>{badge}</span>}
      </div>
      <dl className="mt-2 space-y-1 text-xs">{children}</dl>
    </section>
  );
}

const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div className="flex gap-2"><dt className="w-32 shrink-0 text-zinc-500">{k}</dt><dd className="min-w-0 break-words text-zinc-200">{v ?? "—"}</dd></div>
);

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

  if (!s) return <div className="flex flex-1 items-center justify-center text-sm text-zinc-500">{err ?? "Reading the host…"}</div>;
  const { host, docker, egress, inference, storage, vultr } = s;
  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4">
      <div className="mx-auto max-w-4xl space-y-3">
        {err && <p className="text-xs text-red-400">Refresh failed: {err}</p>}
        <div className="grid grid-cols-2 gap-3">
          <Card title="Host" badge={vultr.available ? "Vultr VM" : "not a Vultr VM"} tone={vultr.available ? "ok" : "info"}>
            <Row k="hostname" v={vultr.hostname ?? host.hostname} />
            <Row k="os" v={host.os} />
            <Row k="cpus · load" v={`${host.cpus ?? "—"} · ${host.load ? host.load.join(" ") : "—"}`} />
            <Row k="memory free" v={`${gib(host.memory_available_bytes)} of ${gib(host.memory_total_bytes)}`} />
            <Row k="disk free" v={`${gib(host.disk_free_bytes)} of ${gib(host.disk_total_bytes)}`} />
            <Row k="uptime" v={dur(host.uptime_s)} />
            {vultr.available
              ? <>
                  <Row k="Vultr region" v={vultr.region} />
                  <Row k="Vultr plan" v={vultr.plan} />
                  <Row k="instance" v={<span className="font-mono">{vultr.instance_id}</span>} />
                </>
              : <Row k="Vultr" v={<span className="text-zinc-500">{vultr.reason}</span>} />}
          </Card>

          <Card title="Docker" badge={docker.available ? "up" : "unreachable"} tone={docker.available ? "ok" : "bad"}>
            {docker.available ? <>
              <Row k="version" v={docker.version} />
              <Row k="storage driver" v={docker.storage_driver} />
              <Row k="cgroup" v={`v${docker.cgroup_version ?? "?"}`} />
              <Row k="runtimes" v={(docker.runtimes ?? []).join(", ")} />
              <Row k="containers running" v={docker.containers_running} />
            </> : <Row k="error" v={docker.reason} />}
          </Card>

          <Card title="Sandboxes" badge={`${docker.sandboxes.length} live`} tone={docker.sandboxes.length ? "ok" : "info"}>
            {docker.sandboxes.length === 0 && <p className="text-zinc-500">None right now. A sandbox exists only while a task runs, and is destroyed afterwards.</p>}
            {docker.sandboxes.map(b => (
              <div key={b.name} className="flex gap-2">
                <dt className="w-32 shrink-0 font-mono text-zinc-400">{b.name.replace("minilocker-", "")}</dt>
                <dd className="text-zinc-200">{b.role} · {b.status} · {dur(b.age_s)}</dd>
              </div>
            ))}
          </Card>

          <Card title="Egress proxy" badge={egress.attached ? egress.proxy ?? "up" : "not attached"} tone={egress.attached ? "ok" : "bad"}>
            {egress.attached ? <>
              <Row k="allowlist" v={(egress.allowed_hosts ?? []).join(", ") || "none: everything is refused"} />
              <Row k="credential broker" v={(egress.brokered_services ?? []).length ? (egress.brokered_services ?? []).join(", ") : "not configured"} />
            </> : <Row k="effect" v="sandboxes have no network at all" />}
          </Card>

          <Card title="Inference" badge={inference.vultr ? "Vultr Serverless Inference" : inference.configured ? "other provider" : "not configured"}
            tone={inference.vultr ? "ok" : "info"}>
            <Row k="endpoint host" v={inference.host} />
            <Row k="model" v={inference.model} />
            <Row k="api key" v={inference.key_set ? "set (never shown)" : "not set"} />
            <Row k="tool mode" v={inference.tool_mode} />
          </Card>

          <Card title="Artifact storage" badge={storage.attached ? (storage.vultr ? "Vultr Object Storage" : "attached") : "not attached"}
            tone={storage.attached ? "ok" : "info"}>
            <Row k="endpoint host" v={storage.endpoint_host} />
            <Row k="bucket" v={storage.bucket} />
            {storage.error && <Row k="error" v={<span className="text-red-400">{storage.error}</span>} />}
          </Card>
        </div>
        <p className="text-xs text-zinc-600">Read from the control plane every few seconds. Secrets are never included: keys show only as set or not set.</p>
      </div>
    </div>
  );
}
