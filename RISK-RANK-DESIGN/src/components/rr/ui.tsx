import { useRef, useState, type ReactNode } from "react";
import { Upload, Loader2, Inbox, FileSpreadsheet } from "lucide-react";
import { useStore } from "@/lib/store";
import { cn } from "@/lib/utils";
export function Panel({
  title,
  sub,
  children,
  className,
  action,
}: {
  title?: string;
  sub?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}) {
  return (
    <section className={cn("panel p-4", className)}>
      {(title || action) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Loading() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="panel h-24 animate-pulse" />
        ))}
      </div>
      <div className="panel h-80 animate-pulse" />
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border py-12 text-center">
      <Inbox className="mb-2 size-6 text-muted-foreground" />
      <div className="text-sm font-medium">{title}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

export function Uploader({
  kind,
  title,
  hint,
}: {
  kind: "data" | "evaluation";
  title: string;
  hint: string;
}) {
  const { loadFile } = useStore();
  const ref = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [drag, setDrag] = useState(false);

  const handle = async (f?: File) => {
    if (!f) return;
    setBusy(true);
    setErr("");
    try {
      await loadFile(f, kind);
    } catch {
      setErr("Couldn't read that file. Please upload a CSV.");
    }
    setBusy(false);
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDrag(false);
        handle(e.dataTransfer.files[0]);
      }}
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-14 text-center transition-colors",
        drag ? "border-primary bg-primary/5" : "border-border",
      )}
    >
      <div className="mb-3 text-muted-foreground">
        {busy ? (
          <Loader2 className="size-6 animate-spin" />
        ) : (
          <FileSpreadsheet className="size-6" />
        )}
      </div>
      <div className="text-sm font-semibold">{title}</div>
      <p className="mt-1 max-w-md text-xs text-muted-foreground">{hint}</p>
      <input
        ref={ref}
        type="file"
        accept=".csv,text/csv"
        className="hidden"
        onChange={(e) => handle(e.target.files?.[0])}
      />
      <button
        onClick={() => ref.current?.click()}
        disabled={busy}
        className="mt-4 inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        <Upload className="size-3.5" /> {busy ? "Reading…" : "Choose CSV file"}
      </button>
      {err && <p className="mt-3 text-xs text-destructive">{err}</p>}
    </div>
  );
}

export const DATA_HINT =
  "Export the scored vulnerability table from your Python pipeline (e.g. df.to_csv). Columns like cve_id, description, cvss, adaptive_psss, priority, in_kev and exposure are detected automatically. Nothing is recalculated.";

export const tooltipStyle = {
  contentStyle: {
    background: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    fontSize: 12,
    color: "var(--popover-foreground)",
  },
  labelStyle: { color: "var(--muted-foreground)", marginBottom: 4 },
  itemStyle: { color: "var(--popover-foreground)" },
  cursor: { fill: "var(--accent)", opacity: 0.4 },
};
export const axisProps = {
  stroke: "var(--muted-foreground)",
  fontSize: 11,
  tickLine: false,
  axisLine: { stroke: "var(--border)" },
};
export const toneColor: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
};
