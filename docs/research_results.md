# Research Results

**Last generated:** 2026-11-09, against data refreshed the same day via
`python scripts/fetch_raw_data.py --latest 300` and
`python scripts/fetch_raw_data.py --fill-year 2025 --year-cap 6000` (see
§1a), which pull the most recently published CVEs directly from NVD and
merge them into the historical dataset. Re-running `scripts/fetch_raw_data.py
--latest N` (or `--fill-year YYYY` to backfill a specific year) followed by
`scripts/run_pipeline.py` regenerates this document's numbers against
whatever is current at the time — the figures below are a snapshot, not a
fixed, aging result.

All numbers below are from an actual run of `scripts/run_pipeline.py`
(`random_state=42`, 70/30 train/test split) against the data in `data/raw/`,
fetched live from NVD, FIRST EPSS, CISA KEV and the Center for
Threat-Informed Defense `attack_to_cve` dataset. Nothing here is simulated
or hand-adjusted; re-running the pipeline against the same raw files
reproduces these exact figures.

## 1. Dataset

| Step | Count |
|---|---|
| NVD CVE records fetched (2017-2024 historical sample + 2025/2026 CVEs) | 59,446 |
| Dropped — no CVSS v3.1 metric block | 12,329 (20.7%) |
| Usable records | 47,117 |
| CISA KEV matches (ground-truth positive class) | 361 (0.77%) |
| ATT&CK-mapped (technique IDs recognized) | 0.76% of usable records |
| Train / test split (stratified on KEV) | 32,981 / 14,136 |

The severe class imbalance (0.77% positive) is realistic — most CVEs are
never observed being exploited in the wild — but it means every metric
below should be read against that base rate, not in isolation.

## 1a. Dataset currency (published-year breakdown)

| Published year | Records |
|---|---|
| 2017 | 99 |
| 2018 | 96 |
| 2019 | 9,171 |
| 2020 | 18,199 |
| 2021 | 999 |
| 2022 | 1,000 |
| 2023 | 1,000 |
| 2024 | 1,000 |
| **2025** (Nov 16 – Dec 31, 2025) | **5,000** |
| **2026** (Oct 25 – Nov 9, 2026) | **10,553** |

The 2025/2026 slices were pulled with the rolling-update mechanism
(`fetch_latest()` / `fetch_year()` in `scripts/fetch_raw_data.py`), which
walks backward from the target date in small windows so the cap on records
fetched is spent on the **most recent** CVEs in that range rather than the
oldest ones — important because 2025/2026 CVE publication volume
(~150-200/day) means a naive forward fetch would exhaust its cap before
reaching the end of the range at all. This matters in practice: a specific
CVE check (`CVE-2025-55182`, published 2025-12-03, CISA KEV-listed) was
initially missing from the dashboard precisely because of this kind of gap
— first the 2026-only rolling update left all of 2025 uncovered, then a
naive year-fetch would have covered only early 2025 and still missed
December. `--fill-year 2025` closed it correctly by walking backward from
Dec 31. There is still a gap for January–mid-November 2025; running
`--fill-year 2025` with a larger `--year-cap` (or no cap, for the full
year) would close it.

## 2. Learned adaptive weights

Fit by logistic regression on the **training split only**, predicting CISA
KEV membership from `[CVSS_norm, EPSS, attack_criticality, uckc_weight]`
(standardized), then normalizing `|coefficients|` to sum to 1:

| Weight | Value | Feature |
|---|---|---|
| α | 0.241 | CVSS (normalized base score) |
| β | 0.608 | EPSS (exploit probability) |
| γ | 0.037 | ATT&CK critical-technique flag |
| δ | 0.115 | UCKC phase weight |

EPSS dominates the learned weighting — consistent with EPSS being
purpose-built to predict near-term exploitation, which is exactly the
signal CISA KEV membership captures after the fact. CVSS still carries
meaningful weight; ATT&CK/UCKC contribute less, in large part because they
are only available for 0.76% of records (see §5, Limitations).

## 3. Feature importance (mean |SHAP value| per feature)

| Feature | Importance |
|---|---|
| epss | 0.504 |
| CVSS_norm | 0.388 |
| uckc_weight | 0.017 |
| attack_criticality | 0.005 |

SHAP ran successfully against the fitted logistic-regression pipeline
(figures saved to `results/figures/shap_importance_bar.png` and
`shap_summary.png`). `src/explainability.py` also implements a permutation-
importance fallback for environments where SHAP is unavailable or
incompatible with the installed scikit-learn version.

## 4. Comparative evaluation (held-out test split, n=14,136)

Ground truth: CISA KEV membership. Classification metrics use a fixed
score threshold of ≥60 ("High or above").

| Approach | Precision | Recall | F1 | ROC-AUC | P@10 | R@10 | P@20 | R@20 | P@50 | R@50 |
|---|---|---|---|---|---|---|---|---|---|---|
| CVSS-only | 0.010 | 0.954 | 0.020 | 0.742 | 0.10 | 0.009 | 0.20 | 0.037 | 0.12 | 0.056 |
| Static PSSS | 0.416 | 0.546 | 0.472 | 0.909 | 0.90 | 0.083 | 0.95 | 0.176 | **0.74** | **0.343** |
| **Adaptive PSSS (UCKC)** | 0.372 | 0.565 | 0.449 | **0.931** | 0.90 | 0.083 | 0.85 | 0.157 | 0.72 | 0.333 |

**Ranking correlation (Spearman ρ) between approaches, test split:**

| Pair | ρ |
|---|---|
| CVSS-only vs Static PSSS | 0.973 |
| CVSS-only vs Adaptive PSSS | 0.950 |
| Static PSSS vs Adaptive PSSS | 0.990 |

### What the numbers actually show

- **CVSS-only ranking is close to useless for prioritization.** Its
  Precision@50 is 0.12 — of the top 50 CVEs it ranks highest, only 6 are
  actually known-exploited — because CVSS scores cluster at the high end
  (thousands of CVEs score 9.8-10.0) with no way to break ties toward the
  ones that matter. This is the exact problem motivating the project (PPT,
  Problem Statement slide), and the data confirms it directly rather than
  assuming it.
- **Both PSSS variants substantially improve ranking quality** over
  CVSS-only: Precision@50 6x higher, ROC-AUC 0.91-0.93 vs 0.74.
- **On this run, Static PSSS edges out Adaptive PSSS on Precision@50/F1,
  while Adaptive PSSS has the higher ROC-AUC (0.931 vs 0.909).** This
  flipped slightly from the previous (2026-only) snapshot, where Adaptive
  PSSS led on Precision@50 too. Report this honestly rather than picking
  whichever run favors the "adaptive wins" narrative: **the consistent,
  reproducible finding across every run so far is that ROC-AUC ranks
  Adaptive PSSS (UCKC) above Static PSSS above CVSS-only; Precision@K at
  specific cutoffs is noisier and has swapped between the two PSSS
  variants as the dataset composition changed.** A project report should
  state the ROC-AUC ordering as the primary claim and note the Precision@K
  variability as a genuine, disclosed finding — not a result to average
  away or cherry-pick.
- **CVSS-only vs Adaptive PSSS rankings are still highly correlated**
  (ρ=0.950) — adaptive weighting *reorders* the list meaningfully at the
  top (where it matters for triage) without being a wholesale departure
  from CVSS across the full distribution.
- **This result holds with 2025/2026 CVEs included** — the dataset now
  spans disclosures made within the last two weeks, plus a December 2025
  slice (see §1a), not only historical ones, so this is not an artifact of
  an aging snapshot.

## 5. Limitations

- **CISA KEV is a proxy label, not ground truth for "true risk."** It
  reflects vulnerabilities CISA has confirmed as exploited in the wild and
  deemed significant enough to catalog — a real but incomplete and
  retrospective signal. A vulnerability can be dangerous without (yet)
  appearing in KEV, and KEV additions lag actual exploitation.
- **ATT&CK/UCKC mapping coverage is low (0.76%, down from 1.14% in the
  original 2017-2024 snapshot)** — the public `attack_to_cve` dataset only
  covers 359 CVEs within this sample (fixed, since the mapping source is
  static), mostly 2017-2020, so every newly added 2025/2026 CVE dilutes the
  coverage *percentage* further without changing the mapped *count*. The
  large majority of CVEs in this sample fall back to `uckc_weight = 0.4`
  ("Unknown" phase) and `attack_criticality = 0`. The non-zero learned
  weight for UCKC (δ=0.115) and its measurable SHAP importance suggest the
  signal is real where present, but conclusions about ATT&CK/UCKC's
  contribution should be read as based on this small, fixed mapped subset,
  not the full (and growing) dataset. A more current/comprehensive
  ATT&CK-to-CVE mapping source is the single highest-value future
  enhancement (see §7) — it is now the clear coverage bottleneck, more so
  than when the dataset was smaller.
- **A real, previously silent bug was found and fixed during this
  project**: the reference implementation's UCKC mapping looked up the
  `attack_to_cve` dataset's `Phase` column (values `"Phase 1"`/`"Phase 2"`,
  that dataset's own internal categorization) against a table keyed by
  MITRE ATT&CK tactic names (`"Initial Access"`, etc.). The lookup always
  missed, silently defaulting every CVE to `"Unknown"` — meaning the
  reference repo's own UCKC integration never actually varied by CVE. This
  implementation instead derives the tactic from the CVE's ATT&CK technique
  IDs directly (`src/feature_engineering.py`, `TECHNIQUE_TO_TACTIC`), which
  is why UCKC phases here are non-trivially distributed (see §6) and why
  δ learns a non-zero weight.
- **`TECHNIQUE_TO_TACTIC` is a partial, manually curated mapping.** It
  covers the common Enterprise ATT&CK technique IDs appearing in the
  dataset; ICS-matrix technique IDs (`T08xx`) and a handful of malformed
  IDs in the source CSV (e.g. `"T11190"`, `"TT1565"`) are intentionally
  left unmapped rather than guessed, so the 0.76% coverage figure is
  conservative, not inflated.
- **Asset criticality / internet exposure are simulated**, not sourced
  from a real asset inventory (none exists for this research prototype).
  They are shown in the dashboard for contextual-scoring demonstration and
  are excluded from every number in this document.
- **Class imbalance (0.77% positive)** means precision at any reasonable
  operating point will look low in absolute terms; Precision@K and ROC-AUC
  are more informative than accuracy for this task, which is why they are
  the headline metrics here.
- **Single ground-truth source.** Using only CISA KEV (rather than KEV plus
  e.g. exploit-DB or vendor advisories) limits the positive class to
  vulnerabilities CISA specifically chose to catalog, which skews toward
  US-government-relevant, high-profile exploitation.

## 6. ATT&CK/UCKC phase distribution (mapped subset only, n=359)

| UCKC phase | Count |
|---|---|
| Lateral Movement | 110 |
| Act on Objectives | 93 |
| Exploitation | 69 |
| Delivery | 37 |
| Unknown (mapped technique had no recognized tactic) | 29 |
| Installation | 11 |
| Command & Control | 9 |
| Reconnaissance | 1 |

## 7. Future scope

As noted in the project PPT: support for multiple vulnerability scanners
(this prototype uses NVD records as a stand-in for live scan findings),
improved false-positive handling, a larger/more current ATT&CK-to-CVE
mapping source, and optional cloud deployment of the dashboard.

Beyond the PPT's original scope, two extensions are now straightforward
given the rolling-update mechanism (§1a):

- **Continuous re-validation.** Because `fetch_latest()` can pull newly
  disclosed CVEs on any cadence (daily/weekly/monthly) and merge them in
  without disturbing historical data, this evaluation can be re-run
  periodically to check whether the learned weights and reported metrics
  remain stable as new exploitation data (KEV additions, EPSS updates)
  accumulates — turning this from a one-time study into a monitorable
  research artifact, suitable for a journal submission that reports
  results over a longer observation window rather than a single snapshot.
- **Drift analysis.** Re-running the pipeline at different points in time
  and comparing the learned α/β/γ/δ weights across runs would let a future
  extension of this work quantify whether, and how fast, the relative
  importance of CVSS/EPSS/ATT&CK/UCKC shifts over time — itself a
  publishable finding independent of the prioritization system's accuracy.
