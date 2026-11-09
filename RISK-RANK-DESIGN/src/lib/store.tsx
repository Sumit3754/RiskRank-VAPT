import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import Papa from "papaparse";
import { get, set, del } from "idb-keyval";
import {
  applyFilters,
  detectColumns,
  EMPTY_FILTERS,
  type ColumnMap,
  type Filters,
  type Row,
} from "./data";

interface Dataset {
  name: string;
  loadedAt: string;
  headers: string[];
  rows: Row[];
}

interface Ctx {
  ready: boolean;
  data: Dataset | null;
  evaluation: Dataset | null;
  notes: string;
  cols: ColumnMap;
  filters: Filters;
  filtered: Row[];
  setFilters: (f: Filters) => void;
  loadFile: (file: File, kind: "data" | "evaluation") => Promise<void>;
  clear: (kind: "data" | "evaluation") => Promise<void>;
  setNotes: (n: string) => void;
}

const StoreCtx = createContext<Ctx | null>(null);

function parse(file: File): Promise<Dataset> {
  return new Promise((resolve, reject) =>
    Papa.parse<Row>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (res) =>
        resolve({
          name: file.name,
          loadedAt: new Date().toISOString(),
          headers: res.meta.fields ?? [],
          rows: res.data,
        }),
      error: reject,
    }),
  );
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [data, setData] = useState<Dataset | null>(null);
  const [evaluation, setEvaluation] = useState<Dataset | null>(null);
  const [notes, setNotesState] = useState("");
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);

  useEffect(() => {
    Promise.all([get("rr:data"), get("rr:eval"), get("rr:notes")]).then(([d, e, n]) => {
      if (d) setData(d);
      if (e) setEvaluation(e);
      if (n) setNotesState(n);
      setReady(true);
    });
  }, []);

  const cols = useMemo(() => (data ? detectColumns(data.headers) : {}), [data]);
  const filtered = useMemo(
    () => (data ? applyFilters(data.rows, cols, filters) : []),
    [data, cols, filters],
  );

  const value: Ctx = {
    ready,
    data,
    evaluation,
    notes,
    cols,
    filters,
    filtered,
    setFilters,
    loadFile: async (file, kind) => {
      const ds = await parse(file);
      if (kind === "data") {
        setData(ds);
        setFilters(EMPTY_FILTERS);
        await set("rr:data", ds);
      } else {
        setEvaluation(ds);
        await set("rr:eval", ds);
      }
    },
    clear: async (kind) => {
      if (kind === "data") {
        setData(null);
        await del("rr:data");
      } else {
        setEvaluation(null);
        await del("rr:eval");
      }
    },
    setNotes: (n) => {
      setNotesState(n);
      set("rr:notes", n);
    },
  };
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}

export function useStore() {
  const c = useContext(StoreCtx);
  if (!c) throw new Error("useStore outside provider");
  return c;
}
