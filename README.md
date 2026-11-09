# RiskRank-VAPT

**Dynamic Vulnerability Prioritization Using Machine Learning**

BCA research prototype (GLA University, Mathura) implementing the pipeline
described in the project PPT:

```
NVD/CVE Dataset → Preprocessing → CVSS + EPSS + CISA KEV Enrichment
  → MITRE ATT&CK Mapping → UCKC Attack-Phase Mapping
  → Adaptive ML Risk Scoring → Vulnerability Prioritization
  → Dashboard & Research Evaluation
```

Builds on, and credits, the reference implementation
[Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework](https://github.com/shreyas23dev/Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework)
(MIT License). See [`NOTICE.md`](NOTICE.md) for exactly what was reused and
what was fixed/modified.

## What it does

Three comparable vulnerability-prioritization approaches, evaluated with a
proper train/test split against CISA KEV (Known Exploited Vulnerabilities)
as ground truth:

1. **CVSS-only baseline** — raw CVSS v3.1 base score.
2. **Static PSSS** — fixed-weight `0.4·CVSS + 0.4·EPSS + 0.2·ATT&CK`.
3. **Adaptive PSSS (UCKC)** — ML-learned weights over CVSS, EPSS, ATT&CK
   technique criticality, and Unified Cyber Kill Chain phase weight.

Results are classified into **Critical / High / Medium / Low** priority and
shown in an interactive Streamlit dashboard with SHAP/permutation-based
explainability, top-N ranking, search/filter, and CSV export.

## Project structure

```
RiskRank-VAPT/
├── app.py                      Streamlit dashboard
├── requirements.txt
├── scripts/
│   ├── fetch_raw_data.py       one-time downloader (NVD, EPSS, KEV, ATT&CK)
│   └── run_pipeline.py         runs the full pipeline, writes results/
├── data/
│   ├── raw/                    downloaded source data (not committed)
│   └── processed/
├── src/
│   ├── data_loader.py          parse NVD CVE / CVSS v3.1 records
│   ├── data_enrichment.py      EPSS + CISA KEV + simulated asset context
│   ├── feature_engineering.py  ATT&CK → UCKC phase mapping
│   ├── risk_scoring.py         CVSS-only + Static PSSS, classification
│   ├── adaptive_model.py       ML-learned adaptive PSSS weights
│   ├── explainability.py       SHAP / permutation feature importance
│   └── evaluation.py           train/test split, 3-way comparison, metrics
├── models/
├── results/
│   ├── figures/
│   └── reports/
├── docs/
│   ├── methodology.md
│   └── research_results.md
└── RISK-RANK-DESIGN/            web dashboard (React/TanStack Start, see below)
```

## Setup (Windows)

```powershell
cd RiskRank-VAPT
pip install -r requirements.txt

# One-time: download real NVD/EPSS/KEV/ATT&CK data into data/raw/
python scripts/fetch_raw_data.py

# Run the full pipeline (loads data, enriches, scores, trains, evaluates)
python scripts/run_pipeline.py

# Launch the dashboard
streamlit run app.py
```

No database, Docker, or cloud deployment required — everything runs from
local CSV/JSON files on an ordinary laptop (tested on 16 GB RAM, no GPU).

## Keeping the dataset current (rolling updates)

CVE volume is now high enough (150-200+/day) that a one-time historical
snapshot can go stale quickly. Rather than re-running the full historical
bootstrap, fetch newly disclosed CVEs on demand and merge them in:

```powershell
# Pull CVEs published in the last 300 days (also refreshes EPSS/KEV), merged
# into the existing dataset by CVE ID — no need to re-fetch historical years
python scripts/fetch_raw_data.py --latest 300

# Re-run the pipeline so results reflect the newly added CVEs
python scripts/run_pipeline.py
```

Use a smaller `--latest N` (e.g. `--latest 30`) for a quick refresh of just
the most recent month. `--max-records` (default 6000) caps how many of the
most recent CVEs are pulled per run, since 2025/2026 volume can exceed that
in under a month.

## Web dashboard (RISK-RANK-DESIGN)

`RISK-RANK-DESIGN/` is a separate, static React (TanStack Start) dashboard —
a polished, shareable alternative to the Streamlit app for presenting
results. It is a **bring-your-own-CSV** viewer: it never runs the model or
fetches live data itself, it only reads whatever scored CSV you export from
the Python pipeline. All parsing happens client-side in the browser
(nothing is uploaded to a server); the dataset is kept in the browser's
IndexedDB so it survives a refresh.

```powershell
cd RISK-RANK-DESIGN
npm install
npm run dev      # http://localhost:8080
```

> **Windows note:** a known npm bug ([npm/cli#4828](https://github.com/npm/cli/issues/4828))
> can make `npm install` silently skip the platform-specific native binaries
> (`@rolldown/binding-win32-x64-msvc`, `@oxc-parser/binding-win32-x64-msvc`,
> `@tailwindcss/oxide-win32-x64-msvc`, `lightningcss-win32-x64-msvc`). If
> `npm run dev` fails with "Cannot find native binding", fetch and extract
> the missing package manually, e.g.
> `npm pack @rolldown/binding-win32-x64-msvc@<version> && tar -xzf <tgz> -C node_modules/@rolldown/binding-win32-x64-msvc --strip-components=1`
> (match the version pinned in `package-lock.json`). This is a local Windows
> dev-install quirk only — CI/deploy platforms (Linux) are not affected.

**Feeding it data:** on the Overview page, upload
`results/reports/prioritized_cves.csv` (or the Streamlit app's "Export
with standard column names" download). On Comparative Evaluation, upload
`results/reports/evaluation_metrics.csv`. Column names are auto-detected
(`cve_id`, `cvss`/`CVSS_base`, `adaptive_psss`/`score_adaptive_psss`,
`priority`, `in_kev`, `exposure`, …) — see `RISK-RANK-DESIGN/src/lib/data.ts`.

**Deploying it:** `npm run build` outputs a Nitro build (Cloudflare
Workers/Pages preset by default, configurable in `vite.config.ts`). Since
the project is connected to [Lovable](https://lovable.dev), the simplest
path is the **Publish** button in the Lovable editor; alternatively deploy
`.output/` to Cloudflare, Vercel, or Netlify as a standard Node/edge build.

## Data sources

- NVD CVE / CVSS v3.1 — https://nvd.nist.gov/
- EPSS — https://www.first.org/epss/
- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK → CVE mapping — Center for Threat-Informed Defense `attack_to_cve`

## Important caveats (read before citing results)

- **Asset criticality / internet exposure** are *simulated, configurable*
  contextual fields (no live asset inventory exists for this prototype).
  They appear in the dashboard for demonstration but are **excluded** from
  the ML training/evaluation so they cannot inflate reported metrics.
- **ATT&CK mapping coverage is partial** — the public `attack_to_cve`
  dataset only maps ~800 CVEs. See `docs/research_results.md` for the exact
  coverage percentage on the fetched sample.
- **CISA KEV membership is a proxy label** for "actually exploited," not a
  complete measure of real-world risk.

Full methodology, data pipeline, scoring formulas, and measured results are
documented in [`docs/methodology.md`](docs/methodology.md) and
[`docs/research_results.md`](docs/research_results.md).
