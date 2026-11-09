import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import { useStore } from "@/lib/store";
import { priorityTone, truthy } from "@/lib/data";
import { PageTitle } from "@/components/rr/shell";
import { DATA_HINT, Empty, Loading, Panel, Uploader } from "@/components/rr/ui";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/intelligence")({
  head: () => ({
    meta: [
      { title: "Vulnerability Intelligence · RiskRank-VAPT" },
      {
        name: "description",
        content:
          "Searchable table of every scored CVE with CVSS, EPSS, Adaptive PSSS and KEV status.",
      },
      { property: "og:title", content: "Vulnerability Intelligence · RiskRank-VAPT" },
      { property: "og:description", content: "Searchable, sortable scored CVE table." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Intelligence,
});

const badge: Record<string, string> = {
  critical: "bg-critical/15 text-critical border-critical/30",
  high: "bg-high/15 text-high border-high/30",
  medium: "bg-medium/15 text-medium border-medium/30",
  low: "bg-low/15 text-low border-low/30",
  info: "bg-info/15 text-info border-info/30",
};

const PAGE = 50;

function Intelligence() {
  const { ready, data, cols, filtered } = useStore();
  const [sort, setSort] = useState<{ col: string; dir: 1 | -1 } | null>(null);
  const [page, setPage] = useState(0);

  const shown = useMemo(() => {
    const keys = [
      cols.cve,
      cols.description,
      cols.cvss,
      cols.epss,
      cols.psss,
      cols.priority,
      cols.kev,
      cols.exposure,
    ].filter(Boolean) as string[];
    return keys.length ? keys : (data?.headers.slice(0, 8) ?? []);
  }, [cols, data]);

  const rows = useMemo(() => {
    if (!sort) return filtered;
    const { col, dir } = sort;
    return [...filtered].sort((a, b) => {
      const x = parseFloat(a[col] ?? ""),
        y = parseFloat(b[col] ?? "");
      if (!isNaN(x) && !isNaN(y)) return (x - y) * dir;
      return (a[col] ?? "").localeCompare(b[col] ?? "") * dir;
    });
  }, [filtered, sort]);

  if (!ready) return <Loading />;
  if (!data)
    return (
      <>
        <PageTitle title="Vulnerability Intelligence" />
        <Uploader kind="data" title="Upload scored vulnerability dataset" hint={DATA_HINT} />
      </>
    );

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const p = Math.min(page, pages - 1);
  const slice = rows.slice(p * PAGE, p * PAGE + PAGE);

  return (
    <>
      <PageTitle
        title="Vulnerability Intelligence"
        sub={`${rows.length.toLocaleString()} vulnerabilities match the current filters`}
      />
      <Panel className="p-0">
        {slice.length === 0 ? (
          <div className="p-4">
            <Empty
              title="No vulnerabilities match the filters"
              hint="Adjust or clear filters in the sidebar."
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border">
                  {shown.map((h) => (
                    <th key={h} className="whitespace-nowrap px-3 py-2.5 text-left">
                      <button
                        className="eyebrow inline-flex items-center gap-1 hover:text-foreground"
                        onClick={() =>
                          setSort(
                            sort?.col === h
                              ? { col: h, dir: sort.dir === 1 ? -1 : 1 }
                              : { col: h, dir: -1 },
                          )
                        }
                      >
                        {h}
                        {sort?.col === h &&
                          (sort.dir === 1 ? (
                            <ArrowUp className="size-3" />
                          ) : (
                            <ArrowDown className="size-3" />
                          ))}
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {slice.map((r, i) => (
                  <tr
                    key={i}
                    className="border-b border-border/60 transition-colors last:border-0 hover:bg-accent/40"
                  >
                    {shown.map((h) => {
                      const v = r[h];
                      if (h === cols.cve)
                        return (
                          <td
                            key={h}
                            className="whitespace-nowrap px-3 py-2 font-mono text-xs text-primary"
                          >
                            {v}
                          </td>
                        );
                      if (h === cols.description)
                        return (
                          <td
                            key={h}
                            className="max-w-md truncate px-3 py-2 text-muted-foreground"
                            title={v}
                          >
                            {v}
                          </td>
                        );
                      if (h === cols.priority)
                        return (
                          <td key={h} className="px-3 py-2">
                            <span
                              className={cn(
                                "rounded border px-1.5 py-0.5 text-[11px] font-medium",
                                badge[priorityTone(v ?? "")],
                              )}
                            >
                              {v}
                            </span>
                          </td>
                        );
                      if (h === cols.kev)
                        return (
                          <td key={h} className="px-3 py-2">
                            {truthy(v) ? (
                              <span className="text-[11px] font-medium text-critical">KEV</span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>
                        );
                      return (
                        <td key={h} className="whitespace-nowrap px-3 py-2 tabular">
                          {v}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-border px-3 py-2 text-xs text-muted-foreground">
          <span className="tabular">
            Page {p + 1} of {pages}
          </span>
          <div className="flex gap-1">
            <button
              disabled={p === 0}
              onClick={() => setPage(p - 1)}
              className="rounded border border-border px-2 py-1 hover:text-foreground disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={p >= pages - 1}
              onClick={() => setPage(p + 1)}
              className="rounded border border-border px-2 py-1 hover:text-foreground disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </Panel>
    </>
  );
}
