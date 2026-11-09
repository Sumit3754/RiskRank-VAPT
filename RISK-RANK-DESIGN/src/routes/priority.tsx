import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
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

export const Route = createFileRoute("/priority")({
  head: () => ({
    meta: [
      { title: "Priority Analysis · RiskRank-VAPT" },
      {
        name: "description",
        content: "Adaptive PSSS score distribution, priority by exposure and KEV breakdown.",
      },
      { property: "og:title", content: "Priority Analysis · RiskRank-VAPT" },
      {
        property: "og:description",
        content: "How vulnerabilities spread across Adaptive PSSS priority tiers.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Priority,
});

function Priority() {
  const { ready, data, cols, filtered } = useStore();

  const hist = useMemo(() => {
    if (!cols.psss) return [];
    const vals = filtered.map((r) => num(r[cols.psss!])).filter((v): v is number => v !== null);
    if (!vals.length) return [];
    const max = Math.max(...vals),
      min = Math.min(...vals);
    const step = max <= 1 ? 0.05 : max <= 10 ? 0.5 : 5;
    const start = Math.floor(min / step) * step;
    const n = Math.max(1, Math.ceil((max - start) / step) + 1);
    const bins = Array.from({ length: n }, (_, i) => ({
      bin: +(start + i * step).toFixed(2),
      count: 0,
    }));
    for (const v of vals) {
      const b = bins[Math.min(n - 1, Math.floor((v - start) / step))];
      if (b) b.count++;
    }
    return bins;
  }, [filtered, cols]);

  const byGroup = (groupCol?: string, label?: (v: string) => string) => {
    if (!groupCol || !cols.priority) return { rows: [], tiers: [] as string[] };
    const tiers = sortPriorities([...new Set(filtered.map((r) => r[cols.priority!] ?? ""))]);
    const m = new Map<string, Record<string, number | string>>();
    const pc = cols.priority;
    for (const r of filtered) {
      const raw = r[groupCol] ?? "";
      const g = label ? label(raw) : raw;
      const o = m.get(g) ?? { group: g };
      const tier = r[pc] ?? "";
      o[tier] = ((o[tier] as number) ?? 0) + 1;
      m.set(g, o);
    }
    return { rows: [...m.values()], tiers };
  };
  const exposure = useMemo(() => byGroup(cols.exposure), [filtered, cols]);
  const kev = useMemo(
    () => byGroup(cols.kev, (v) => (truthy(v) ? "In CISA KEV" : "Not in KEV")),
    [filtered, cols],
  );

  if (!ready) return <Loading />;
  if (!data)
    return (
      <>
        <PageTitle title="Priority Analysis" />
        <Uploader kind="data" title="Upload scored vulnerability dataset" hint={DATA_HINT} />
      </>
    );

  const Stack = ({ d }: { d: ReturnType<typeof byGroup> }) => (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={d.rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="group" {...axisProps} />
        <YAxis {...axisProps} />
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        {d.tiers.map((t) => (
          <Bar key={t} dataKey={t} stackId="a" fill={toneColor[priorityTone(t)]} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );

  return (
    <>
      <PageTitle
        title="Priority Analysis"
        sub="Distribution of Adaptive PSSS scores and tiers across context"
      />
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel
          title="Adaptive PSSS score distribution"
          sub="Histogram of scores in the current filter"
          className="xl:col-span-2"
        >
          {!hist.length ? (
            <Empty title="No Adaptive PSSS values to show" />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={hist} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="bin" {...axisProps} />
                <YAxis {...axisProps} />
                <Tooltip
                  {...tooltipStyle}
                  labelFormatter={(l) => `Score ≥ ${l}`}
                  formatter={(v: number) => [v.toLocaleString(), "CVEs"]}
                />
                <Bar dataKey="count" fill="var(--chart-1)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
        <Panel title="Priority by internet exposure">
          {!exposure.rows.length ? (
            <Empty title="No exposure column detected" />
          ) : (
            <Stack d={exposure} />
          )}
        </Panel>
        <Panel title="Priority by CISA KEV membership">
          {!kev.rows.length ? <Empty title="No KEV column detected" /> : <Stack d={kev} />}
        </Panel>
      </div>
    </>
  );
}
