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
import { priorityTone, sortPriorities } from "@/lib/data";
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

export const Route = createFileRoute("/explainability")({
  head: () => ({
    meta: [
      { title: "Explainability · RiskRank-VAPT" },
      {
        name: "description",
        content:
          "Average signal values (CVSS, EPSS, ATT&CK, UCKC) behind each Adaptive PSSS priority tier.",
      },
      { property: "og:title", content: "Explainability · RiskRank-VAPT" },
      { property: "og:description", content: "What drives each priority tier." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Explain,
});

function Explain() {
  const { ready, data, cols, filtered } = useStore();

  const { chart, features, tiers } = useMemo(() => {
    if (!data || !cols.priority) return { chart: [], features: [], tiers: [] };
    const skip = new Set([cols.cve, cols.description, cols.priority, cols.kev, cols.exposure]);
    const features = data.headers.filter(
      (h) =>
        !skip.has(h) &&
        data.rows.slice(0, 200).every((r) => r[h] === "" || !isNaN(parseFloat(r[h] ?? ""))),
    );
    const tiers = sortPriorities([...new Set(filtered.map((r) => r[cols.priority!] ?? ""))]);
    const chart = features.map((f) => {
      const o: Record<string, string | number> = { feature: f };
      for (const t of tiers) {
        const vals = filtered
          .filter((r) => (r[cols.priority!] ?? "") === t)
          .map((r) => parseFloat(r[f] ?? ""))
          .filter((v) => !isNaN(v));
        o[t] = vals.length ? +(vals.reduce((a, b) => a + b, 0) / vals.length).toFixed(4) : 0;
      }
      return o;
    });
    return { chart, features, tiers };
  }, [data, cols, filtered]);

  if (!ready) return <Loading />;
  if (!data)
    return (
      <>
        <PageTitle title="Explainability" />
        <Uploader kind="data" title="Upload scored vulnerability dataset" hint={DATA_HINT} />
      </>
    );

  return (
    <>
      <PageTitle
        title="Explainability"
        sub="Mean value of each numeric signal per priority tier, read directly from your dataset"
      />
      <Panel title="Signal profile by priority tier">
        {!features.length ? (
          <Empty
            title="No numeric signal columns found"
            hint="Include columns such as cvss, epss, attack_score or uckc_stage in your export."
          />
        ) : (
          <ResponsiveContainer width="100%" height={380}>
            <BarChart data={chart} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid stroke="var(--border)" vertical={false} />
              <XAxis
                dataKey="feature"
                {...axisProps}
                interval={0}
                angle={-20}
                textAnchor="end"
                height={60}
              />
              <YAxis {...axisProps} />
              <Tooltip {...tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {tiers.map((t) => (
                <Bar key={t} dataKey={t} fill={toneColor[priorityTone(t)]} radius={[2, 2, 0, 0]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </Panel>
    </>
  );
}
