import { createFileRoute } from "@tanstack/react-router";
import Papa from "papaparse";
import { Download, Trash2 } from "lucide-react";
import { useStore } from "@/lib/store";
import type { ColumnKey } from "@/lib/data";
import { PageTitle } from "@/components/rr/shell";
import { DATA_HINT, Loading, Panel, Uploader } from "@/components/rr/ui";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports · RiskRank-VAPT" },
      {
        name: "description",
        content: "Export filtered vulnerability data and manage loaded datasets.",
      },
      { property: "og:title", content: "Reports · RiskRank-VAPT" },
      { property: "og:description", content: "Export filtered RiskRank-VAPT results as CSV." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Reports,
});

const LABELS: Record<ColumnKey, string> = {
  cve: "CVE ID",
  description: "Description",
  cvss: "CVSS",
  psss: "Adaptive PSSS",
  staticPsss: "Static PSSS",
  epss: "EPSS",
  priority: "Priority",
  kev: "CISA KEV",
  exposure: "Internet exposure",
};

function Reports() {
  const { ready, data, cols, filtered, clear } = useStore();
  if (!ready) return <Loading />;
  if (!data)
    return (
      <>
        <PageTitle title="Reports" />
        <Uploader kind="data" title="Upload scored vulnerability dataset" hint={DATA_HINT} />
      </>
    );

  const exportCsv = () => {
    const blob = new Blob([Papa.unparse(filtered, { columns: data.headers })], {
      type: "text/csv",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `riskrank_filtered_${filtered.length}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <>
      <PageTitle title="Reports" sub="Export the current filtered view" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Export filtered dataset"
          sub={`${filtered.length.toLocaleString()} of ${data.rows.length.toLocaleString()} rows, all original columns`}
        >
          <button
            onClick={exportCsv}
            disabled={!filtered.length}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-40"
          >
            <Download className="size-3.5" /> Download CSV
          </button>
        </Panel>
        <Panel
          title="Loaded dataset"
          sub={data.name}
          action={
            <button
              onClick={() => clear("data")}
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-destructive"
            >
              <Trash2 className="size-3.5" />
              Remove
            </button>
          }
        >
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            {(Object.keys(LABELS) as ColumnKey[]).map((k) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{LABELS[k]}</dt>
                <dd className="font-mono">
                  {cols[k] ?? <span className="text-muted-foreground">not detected</span>}
                </dd>
              </div>
            ))}
          </dl>
        </Panel>
      </div>
    </>
  );
}
