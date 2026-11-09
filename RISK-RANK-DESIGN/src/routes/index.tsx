import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ShieldCheck, AlertOctagon, Flame, Crosshair } from "lucide-react";
import { useStore } from "@/lib/store";
import { num, priorityTone, sortPriorities, truthy } from "@/lib/data";
import { PageTitle } from "@/components/rr/shell";
import {
  axisProps,
  DATA_HINT,
  Empty,
  Loading,
  Panel,
  toneColor,
  tooltipStyle,
  Uploader,
} from "@/components/rr/ui";
import { cn } from "@/lib/utils";
import { ProjectSummary } from "@/components/rr/project-summary";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Overview · RiskRank-VAPT" },
      {
        name: "description",
        content:
          "Adaptive PSSS vulnerability overview: totals, critical, high and CISA KEV counts.",
      },
      { property: "og:title", content: "Overview · RiskRank-VAPT" },
      {
        property: "og:description",
        content: "Adaptive PSSS vulnerability overview and risk distribution.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Overview,
});

const TONE: Record<string, { bar: string; text: string }> = {
  info: { bar: "bg-info", text: "text-info" },
  critical: { bar: "bg-critical", text: "text-critical" },
  high: { bar: "bg-high", text: "text-high" },
  primary: { bar: "bg-primary", text: "text-primary" },
};

function Kpi({
  label,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  sub?: string | undefined;
  icon: typeof ShieldCheck;
  tone: string;
}) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <span className="eyebrow">{label}</span>
        <Icon
          className={cn(
            "size-4",
            tone === "info" || tone === "primary" ? "text-muted-foreground" : TONE[tone]?.text,
          )}
        />
      </div>
      <div className="mt-2 text-2xl font-semibold tabular">{value.toLocaleString()}</div>
      {sub && <div className="mt-1 text-[11px] text-muted-foreground tabular">{sub}</div>}
    </div>
  );
}

function Overview() {
  const { ready, data, cols, filtered } = useStore();

  const stats = useMemo(() => {
    const count = (rows: typeof filtered, pred: (r: (typeof filtered)[number]) => boolean) =>
      rows.filter(pred).length;
    const isP = (p: string) => (r: Record<string, string>) =>
      !!cols.priority && r[cols.priority]?.toLowerCase() === p;
    const isK = (r: Record<string, string>) => !!cols.kev && truthy(r[cols.kev]);
    const all = data?.rows ?? [];
    return {
      total: all.length,
      crit: count(all, isP("critical")),
      high: count(all, isP("high")),
      kev: count(all, isK),
      fTotal: filtered.length,
      fCrit: count(filtered, isP("critical")),
      fHigh: count(filtered, isP("high")),
      fKev: count(filtered, isK),
    };
  }, [data, cols, filtered]);

  const dist = useMemo(() => {
    if (!cols.priority) return [];
    const m = new Map<string, number>();
    for (const r of filtered) {
      const k = r[cols.priority] ?? "";
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return sortPriorities([...m.keys()]).map((k) => ({ priority: k, count: m.get(k)! }));
  }, [filtered, cols]);

  const scatter = useMemo(() => {
    if (!cols.cvss || !cols.psss) return { t: [], f: [], max: 0 };
    const t: object[] = [],
      f: object[] = [];
    let max = 0;
    for (const r of filtered) {
      const x = num(r[cols.cvss]),
        y = num(r[cols.psss]);
      if (x === null || y === null) continue;
      max = Math.max(max, x);
      const p = { x, y, id: cols.cve ? r[cols.cve] : "" };
      (cols.kev && truthy(r[cols.kev]) ? t : f).push(p);
    }
    return { t, f, max };
  }, [filtered, cols]);

  if (!ready) return <Loading />;
  if (!data)
    return (
      <>
        <PageTitle title="Overview" />
        <ProjectSummary />
        <Uploader kind="data" title="Upload scored vulnerability dataset" hint={DATA_HINT} />
      </>
    );

  const sub = (v: number) =>
    stats.fTotal !== stats.total ? `${v.toLocaleString()} in current filter` : undefined;

  return (
    <>
      <PageTitle title="Overview" sub="CVSS + EPSS + MITRE ATT&CK + UCKC, adaptively weighted" />
      <ProjectSummary />
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Kpi
          label="Total vulnerabilities analyzed"
          value={stats.total}
          sub={sub(stats.fTotal)}
          icon={ShieldCheck}
          tone="info"
        />
        <Kpi
          label="Critical"
          value={stats.crit}
          sub={sub(stats.fCrit)}
          icon={AlertOctagon}
          tone="critical"
        />
        <Kpi label="High" value={stats.high} sub={sub(stats.fHigh)} icon={Flame} tone="high" />
        <Kpi
          label="Known exploited (CISA KEV)"
          value={stats.kev}
          sub={sub(stats.fKev)}
          icon={Crosshair}
          tone="primary"
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel
          title="Priority distribution (Adaptive PSSS)"
          sub="Count of vulnerabilities per priority tier"
        >
          {!cols.priority ? (
            <Empty title="No priority column detected" />
          ) : dist.length === 0 ? (
            <Empty title="No vulnerabilities match the filters" hint="Try clearing a filter." />
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <BarChart data={dist} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="priority" {...axisProps} />
                <YAxis {...axisProps} tickFormatter={(v) => (v >= 1000 ? `${v / 1000}k` : v)} />
                <Tooltip
                  {...tooltipStyle}
                  formatter={(v: number) => [v.toLocaleString(), "Vulnerabilities"]}
                />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {dist.map((d) => (
                    <Cell key={d.priority} fill={toneColor[priorityTone(d.priority)]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>

        <Panel
          title="CVSS-only vs Adaptive PSSS"
          sub="Each point is one CVE, coloured by CISA KEV membership"
        >
          {!cols.cvss || !cols.psss ? (
            <Empty title="CVSS or Adaptive PSSS column not detected" />
          ) : scatter.t.length + scatter.f.length === 0 ? (
            <Empty title="No vulnerabilities match the filters" />
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <ScatterChart margin={{ top: 8, right: 8, left: 0, bottom: 16 }}>
                <CartesianGrid stroke="var(--border)" />
                <XAxis
                  type="number"
                  dataKey="x"
                  name="CVSS"
                  {...axisProps}
                  label={{
                    value: "CVSS base score",
                    position: "insideBottom",
                    offset: -10,
                    fill: "var(--muted-foreground)",
                    fontSize: 11,
                  }}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  name="Adaptive PSSS"
                  {...axisProps}
                  label={{
                    value: "Adaptive PSSS",
                    angle: -90,
                    position: "insideLeft",
                    fill: "var(--muted-foreground)",
                    fontSize: 11,
                  }}
                />
                <Tooltip
                  {...tooltipStyle}
                  cursor={{ strokeDasharray: "3 3" }}
                  content={({ payload }) => {
                    const p = payload?.[0]?.payload as
                      { x: number; y: number; id: string } | undefined;
                    if (!p) return null;
                    return (
                      <div className="rounded-md border border-border bg-popover px-3 py-2 text-xs shadow-lg">
                        {p.id && <div className="mb-1 font-mono text-primary">{p.id}</div>}
                        <div className="tabular">
                          CVSS {p.x} · PSSS {p.y}
                        </div>
                      </div>
                    );
                  }}
                />
                {scatter.max <= 10 && (
                  <ReferenceLine
                    segment={[
                      { x: 0, y: 0 },
                      { x: 10, y: 100 },
                    ]}
                    stroke="var(--muted-foreground)"
                    strokeDasharray="4 4"
                  />
                )}
                <Legend
                  verticalAlign="top"
                  align="right"
                  wrapperStyle={{ fontSize: 12, paddingBottom: 8 }}
                />
                <Scatter
                  name="Not in KEV"
                  data={scatter.f}
                  fill="var(--muted-foreground)"
                  fillOpacity={0.45}
                  isAnimationActive={false}
                />
                <Scatter
                  name="In CISA KEV"
                  data={scatter.t}
                  fill="var(--critical)"
                  isAnimationActive={false}
                />
              </ScatterChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>
    </>
  );
}
