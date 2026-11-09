// Pure presentation helpers: detect columns in the user's exported CSV and read values.
// Nothing here computes scores — every value shown comes straight from the uploaded file.
export type Row = Record<string, string>;

export type ColumnKey =
  "cve" | "description" | "cvss" | "psss" | "staticPsss" | "epss" | "priority" | "kev" | "exposure";

export type ColumnMap = Partial<Record<ColumnKey, string>>;

const PATTERNS: [ColumnKey, RegExp][] = [
  ["cve", /^(cve(_|\s)?id|cve|id)$/i],
  ["description", /desc/i],
  ["staticPsss", /static/i],
  ["psss", /adaptive|^psss|psss_score|risk_score/i],
  ["cvss", /cvss/i],
  ["epss", /epss/i],
  ["priority", /priority|tier|severity_label|risk_level/i],
  ["kev", /kev/i],
  ["exposure", /expos|internet/i],
];

export function detectColumns(headers: string[]): ColumnMap {
  const map: ColumnMap = {};
  const used = new Set<string>();
  for (const [key, re] of PATTERNS) {
    const h = headers.find((x) => !used.has(x) && re.test(x.trim()));
    if (h) {
      map[key] = h;
      used.add(h);
    }
  }
  return map;
}

export function truthy(v: string | undefined) {
  return /^(true|1|yes|y|t)$/i.test((v ?? "").trim());
}

export function num(v: string | undefined) {
  const n = parseFloat(v ?? "");
  return Number.isFinite(n) ? n : null;
}

export const PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"];

export function priorityTone(p: string) {
  const k = p.trim().toLowerCase();
  if (k.startsWith("crit")) return "critical";
  if (k.startsWith("high")) return "high";
  if (k.startsWith("med")) return "medium";
  if (k.startsWith("low")) return "low";
  return "info";
}

export function sortPriorities(list: string[]) {
  return [...list].sort((a, b) => {
    const ia = PRIORITY_ORDER.findIndex((p) => p.toLowerCase() === a.toLowerCase());
    const ib = PRIORITY_ORDER.findIndex((p) => p.toLowerCase() === b.toLowerCase());
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
  });
}

export interface Filters {
  priorities: string[];
  kevOnly: boolean;
  exposures: string[];
  search: string;
}

export const EMPTY_FILTERS: Filters = { priorities: [], kevOnly: false, exposures: [], search: "" };

export function applyFilters(rows: Row[], cols: ColumnMap, f: Filters) {
  const q = f.search.trim().toLowerCase();
  return rows.filter((r) => {
    if (f.priorities.length && cols.priority && !f.priorities.includes(r[cols.priority] ?? ""))
      return false;
    if (f.kevOnly && cols.kev && !truthy(r[cols.kev])) return false;
    if (f.exposures.length && cols.exposure && !f.exposures.includes(r[cols.exposure] ?? ""))
      return false;
    if (q) {
      const id = cols.cve ? (r[cols.cve]?.toLowerCase() ?? "") : "";
      const d = cols.description ? (r[cols.description]?.toLowerCase() ?? "") : "";
      if (!id.includes(q) && !d.includes(q)) return false;
    }
    return true;
  });
}

export function uniqueValues(rows: Row[], col?: string) {
  if (!col) return [];
  const s = new Set<string>();
  for (const r of rows) if (r[col] !== undefined && r[col] !== "") s.add(r[col]);
  return [...s];
}
