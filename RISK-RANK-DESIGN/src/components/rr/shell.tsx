import { Link, useRouterState } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  ListOrdered,
  Scale,
  Lightbulb,
  FileText,
  Shield,
  Menu,
  X,
  ChevronDown,
  Search,
  Database,
  BookOpen,
  Workflow,
} from "lucide-react";
import { useStore } from "@/lib/store";
import { sortPriorities, uniqueValues, EMPTY_FILTERS, priorityTone } from "@/lib/data";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/intelligence", label: "Vulnerability Intelligence", icon: ShieldAlert },
  { to: "/priority", label: "Priority Analysis", icon: ListOrdered },
  { to: "/evaluation", label: "Comparative Evaluation", icon: Scale },
  { to: "/explainability", label: "Explainability", icon: Lightbulb },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/how-it-works", label: "How it works", icon: Workflow },
  { to: "/project", label: "Project details", icon: BookOpen },
] as const;

const toneDot: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
};

function Chip({
  active,
  onClick,
  children,
  tone,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
  tone?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors",
        active
          ? "border-primary/60 bg-primary/10 text-foreground"
          : "border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/40",
      )}
    >
      {tone && <span className={cn("size-1.5 rounded-full", toneDot[tone])} />}
      {children}
    </button>
  );
}

function FilterPanel() {
  const { data, cols, filters, setFilters } = useStore();
  const [open, setOpen] = useState(true);
  if (!data) return null;
  const priorities = sortPriorities(uniqueValues(data.rows, cols.priority));
  const exposures = uniqueValues(data.rows, cols.exposure).sort();
  const toggle = (list: string[], v: string) =>
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
  const active =
    filters.priorities.length +
    filters.exposures.length +
    (filters.kevOnly ? 1 : 0) +
    (filters.search ? 1 : 0);

  return (
    <div className="border-t border-sidebar-border px-3 pt-3">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-1 py-1"
        aria-expanded={open}
      >
        <span className="eyebrow">Filters{active ? ` · ${active}` : ""}</span>
        <ChevronDown
          className={cn(
            "size-3.5 text-muted-foreground transition-transform",
            !open && "-rotate-90",
          )}
        />
      </button>
      {open && (
        <div className="space-y-4 px-1 pb-4 pt-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              placeholder="CVE ID or description"
              aria-label="Search CVE ID or description"
              className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-2 text-xs placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20"
            />
          </div>
          {cols.priority && (
            <div className="space-y-2">
              <div className="text-xs text-muted-foreground">Priority (Adaptive PSSS)</div>
              <div className="flex flex-wrap gap-1.5">
                {priorities.map((p) => (
                  <Chip
                    key={p}
                    tone={priorityTone(p)}
                    active={filters.priorities.includes(p)}
                    onClick={() =>
                      setFilters({ ...filters, priorities: toggle(filters.priorities, p) })
                    }
                  >
                    {p}
                  </Chip>
                ))}
              </div>
            </div>
          )}
          {cols.kev && (
            <label className="flex cursor-pointer items-center justify-between text-xs">
              <span>Show only CISA KEV</span>
              <input
                type="checkbox"
                className="size-4 accent-primary"
                checked={filters.kevOnly}
                onChange={(e) => setFilters({ ...filters, kevOnly: e.target.checked })}
              />
            </label>
          )}
          {cols.exposure && (
            <div className="space-y-2">
              <div className="text-xs text-muted-foreground">Internet exposure</div>
              <div className="flex flex-wrap gap-1.5">
                {exposures.map((p) => (
                  <Chip
                    key={p}
                    active={filters.exposures.includes(p)}
                    onClick={() =>
                      setFilters({ ...filters, exposures: toggle(filters.exposures, p) })
                    }
                  >
                    {p}
                  </Chip>
                ))}
              </div>
            </div>
          )}
          {active > 0 && (
            <button
              onClick={() => setFilters(EMPTY_FILTERS)}
              className="text-xs text-primary hover:underline"
            >
              Clear all filters
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [mobile, setMobile] = useState(false);
  const { data, filtered } = useStore();

  const sidebar = (
    <aside className="flex h-full w-64 flex-col overflow-y-auto border-r border-sidebar-border bg-sidebar">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <Shield className="size-5 text-primary" />
        <div className="leading-tight">
          <div className="text-sm font-semibold">RiskRank-VAPT</div>
        </div>
      </div>
      <nav className="space-y-0.5 px-2 pb-3" aria-label="Main">
        {NAV.map((n) => {
          const active = path === n.to;
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={() => setMobile(false)}
              className={cn(
                "relative flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
              )}
            >
              <n.icon className="size-4" />
              {n.label}
            </Link>
          );
        })}
      </nav>
      <FilterPanel />
    </aside>
  );

  return (
    <div className="flex min-h-screen w-full">
      <div className="sticky top-0 hidden h-screen lg:block">{sidebar}</div>
      {mobile && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-background/70" onClick={() => setMobile(false)} />
          <div className="relative h-full">{sidebar}</div>
        </div>
      )}
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/90 px-4 lg:px-6">
          <button className="lg:hidden" onClick={() => setMobile(!mobile)} aria-label="Toggle menu">
            {mobile ? <X className="size-5" /> : <Menu className="size-5" />}
          </button>
          <div className="min-w-0">
            <div className="text-sm font-semibold">RiskRank-VAPT</div>
            <div className="hidden text-[11px] text-muted-foreground sm:block">
              Dynamic Vulnerability Prioritization
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1">
              <span
                className={cn("size-1.5 rounded-full", data ? "bg-low" : "bg-muted-foreground")}
              />
              <Database className="size-3" />
              {data ? (
                <span className="tabular">
                  {filtered.length.toLocaleString()} / {data.rows.length.toLocaleString()} records
                </span>
              ) : (
                "No dataset"
              )}
            </span>
            {data && (
              <span className="hidden md:inline">
                Loaded {new Date(data.loadedAt).toLocaleString()}
              </span>
            )}
          </div>
        </header>
        <main className="mx-auto max-w-[1500px] p-4 lg:p-6">{children}</main>
      </div>
    </div>
  );
}

export function PageTitle({
  title,
  sub,
  action,
}: {
  title: string;
  sub?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {sub && <p className="mt-0.5 text-[13px] text-muted-foreground">{sub}</p>}
      </div>
      {action}
    </div>
  );
}
