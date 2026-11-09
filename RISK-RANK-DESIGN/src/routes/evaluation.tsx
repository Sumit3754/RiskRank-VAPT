import { createFileRoute } from "@tanstack/react-router";
import { Trash2 } from "lucide-react";
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
import { PageTitle } from "@/components/rr/shell";
import { axisProps, Loading, Panel, tooltipStyle, Uploader } from "@/components/rr/ui";

export const Route = createFileRoute("/evaluation")({
  head: () => ({
    meta: [
      { title: "Comparative Evaluation · RiskRank-VAPT" },
      {
        name: "description",
        content: "CVSS-only vs Static PSSS vs Adaptive PSSS on the held-out test split.",
      },
      { property: "og:title", content: "Comparative Evaluation · RiskRank-VAPT" },
      {
        property: "og:description",
        content: "Precision, recall, F1, ROC-AUC and top-k results per model.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Evaluation,
});

const COLORS = [
  "var(--muted-foreground)",
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
];

function Evaluation() {
  const { ready, evaluation, clear, notes, setNotes } = useStore();
  if (!ready) return <Loading />;

  const hint =
    "Upload the metrics table your evaluation script outputs: one row per model (CVSS-only, Static PSSS, Adaptive PSSS) and one column per metric. Values are displayed exactly as written in the file.";

  if (!evaluation)
    return (
      <>
        <PageTitle title="Comparative Evaluation" sub="Held-out test split" />
        <Uploader kind="evaluation" title="Upload evaluation results" hint={hint} />
      </>
    );

  const modelCol = evaluation.headers[0] ?? "";
  const metricCols = evaluation.headers.slice(1);
  const numericMetrics = metricCols.filter((m) =>
    evaluation.rows.every((r) => !isNaN(parseFloat(r[m] ?? ""))),
  );
  const chartData = numericMetrics.map((m) => {
    const o: Record<string, string | number> = { metric: m };
    for (const r of evaluation.rows) o[r[modelCol] ?? ""] = parseFloat(r[m] ?? "");
    return o;
  });
  const best = Object.fromEntries(
    numericMetrics.map((m) => [m, Math.max(...evaluation.rows.map((r) => parseFloat(r[m] ?? "")))]),
  );

  return (
    <>
      <PageTitle
        title="Comparative Evaluation"
        sub={`Held-out test split · ${evaluation.name}`}
        action={
          <button
            onClick={() => clear("evaluation")}
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <Trash2 className="size-3.5" />
            Replace file
          </button>
        }
      />
      <div className="space-y-4">
        <Panel className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border">
                  <th className="eyebrow whitespace-nowrap px-4 py-2.5 text-left">{modelCol}</th>
                  {metricCols.map((m) => (
                    <th key={m} className="eyebrow whitespace-nowrap px-4 py-2.5 text-right">
                      {m}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {evaluation.rows.map((r, i) => (
                  <tr
                    key={i}
                    className="border-b border-border/60 last:border-0 hover:bg-accent/40"
                  >
                    <td className="whitespace-nowrap px-4 py-2.5 font-semibold text-primary">
                      {r[modelCol]}
                    </td>
                    {metricCols.map((m) => (
                      <td
                        key={m}
                        className={
                          "whitespace-nowrap px-4 py-2.5 text-right font-mono text-xs tabular " +
                          (parseFloat(r[m] ?? "") === best[m] ? "text-low" : "")
                        }
                      >
                        {r[m]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="border-t border-border px-4 py-2 text-[11px] text-muted-foreground">
            Best value per metric shown in green. Values unchanged from the source file.
          </div>
        </Panel>

        {chartData.length > 0 && (
          <Panel title="Metric comparison by model">
            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis
                  dataKey="metric"
                  {...axisProps}
                  interval={0}
                  angle={-25}
                  textAnchor="end"
                  height={60}
                />
                <YAxis {...axisProps} />
                <Tooltip {...tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                {evaluation.rows.map((r, i) => (
                  <Bar
                    key={r[modelCol]}
                    dataKey={r[modelCol] ?? ""}
                    fill={COLORS[i % COLORS.length]}
                    radius={[2, 2, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        )}

        <Panel
          title="Ground truth & methodology"
          sub="Paste your existing explanation here; it is saved in this browser."
        >
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={6}
            placeholder="e.g. Ground truth = CVE present in CISA KEV. Stratified 80/20 train/test split…"
            className="w-full rounded-md border border-input bg-background p-3 text-[13px] leading-relaxed placeholder:text-muted-foreground focus:border-ring focus:outline-none"
          />
        </Panel>
      </div>
    </>
  );
}
