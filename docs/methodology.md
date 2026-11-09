# Methodology

## 1. System architecture

```
NVD CVE/CVSS v3.1 (2017-2024 sample, data_loader.py)
        │
        ▼
EPSS + CISA KEV + simulated asset context (data_enrichment.py)
        │
        ▼
MITRE ATT&CK technique mapping (feature_engineering.py)
        │
        ▼
ATT&CK → UCKC attack-phase mapping + phase weight (feature_engineering.py)
        │
        ▼
┌─────────────────────────────┬─────────────────────────────┐
│ CVSS-only baseline          │ Static PSSS                  │
│ (risk_scoring.py)           │ (risk_scoring.py)            │
└─────────────────────────────┴─────────────────────────────┘
        │
        ▼
Train/test split, stratified on CISA-KEV label (evaluation.py)
        │
        ▼
Adaptive weight learning on TRAIN split only (adaptive_model.py)
        │
        ▼
Adaptive PSSS (UCKC) applied to TEST split
        │
        ▼
Evaluation: Precision/Recall/F1/ROC-AUC, Precision@K/Recall@K,
rank correlation (evaluation.py)
        │
        ▼
SHAP / permutation feature importance (explainability.py)
        │
        ▼
results/reports/*.csv, results/figures/*.png → Streamlit dashboard (app.py)
```

## 2. Data sources and preprocessing

| Source | Field(s) used | Notes |
|---|---|---|
| NVD CVE API 2.0 | `cve_id`, description, CVSS v3.1 vector + base score | Sampled across 2017-2024 (see `scripts/fetch_raw_data.py`) rather than a single year, so the sample has real overlap with the ATT&CK mapping dataset, which is concentrated in 2017-2020. |
| FIRST EPSS | `epss` (exploit probability, 0-1), `percentile` | Current snapshot, merged on `cve_id`. |
| CISA KEV catalog | `in_kev` (boolean membership) | Used both as an enrichment field (shown in dashboard) and as the ground-truth label for evaluation and adaptive-weight training. |
| Center for Threat-Informed Defense `attack_to_cve` | ATT&CK technique IDs, kill-chain `Phase` | Small (~800 CVEs); coverage is reported transparently, not padded. |

**Missing-value handling.** CVEs published without a CVSS v3.1 metric block
(common before NVD's v3.1 adoption, and for some rejected/disputed records)
are dropped from the usable dataset, with the exact count logged by
`evaluation.run_full_pipeline()` and reported in `research_results.md`.
EPSS is filled with 0.0 where a CVE has no EPSS record (none expected, FIRST
scores essentially all published CVEs). ATT&CK/UCKC fields default to
"Unknown" / weight 0.4 where no mapping exists, rather than being silently
imputed as a specific phase.

**Asset criticality / internet exposure.** No live asset inventory exists
for this research prototype. These two fields are assigned deterministically
per CVE (seeded by CVE ID hash, not randomized per run) to stand in for the
"configurable contextual inputs" described in the project PPT. They are
shown in the dashboard's scenario view only and are **excluded** from every
ML/evaluation computation, so they cannot influence reported metrics.

## 3. Scoring formulas

All three scores are expressed on a common 0-100 scale.

**CVSS-only baseline**

```
score_cvss_only = (CVSS_base / 10) × 100
```

**Static PSSS** (weights reused from the reference implementation)

```
PSSS_static = 0.4·CVSS_norm + 0.4·EPSS + 0.2·attack_criticality
score_static_psss = PSSS_static × 100
```

where `attack_criticality ∈ {0,1}` flags whether any ATT&CK technique
mapped to the CVE is one of a small set of high-impact techniques
(T1190, T1078, T1068, T1574, T1021 — Initial Access / Privilege Escalation
/ Lateral Movement), reused from the reference implementation.

**Adaptive PSSS (UCKC-integrated)**

```
PSSS_adaptive = α·CVSS_norm + β·EPSS + γ·attack_criticality + δ·uckc_weight
score_adaptive_psss = PSSS_adaptive × 100
```

`α, β, γ, δ` are **learned**, not fixed: a logistic regression is fit on the
**training split only**, predicting CISA KEV membership from
`[CVSS_norm, EPSS, attack_criticality, uckc_weight]` (each standardized).
The absolute value of its coefficients, normalized to sum to 1, become
`α, β, γ, δ`. `uckc_weight` comes from mapping the CVE's ATT&CK phase to a
Unified Cyber Kill Chain stage and looking up that stage's weight (0.3 for
Reconnaissance up to 1.0 for Act on Objectives), reused from the reference
implementation.

**Priority classification** (same thresholds applied to all three scores):

| Score range | Priority |
|---|---|
| ≥ 80 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| < 40 | Low |

## 4. Why CISA KEV, not an EPSS-derived label

The reference implementation's adaptive-weighting step trained its
classifier on `epss > threshold` while also using `epss` as an input
feature — the label is a deterministic function of a feature, which is
leakage: the model can trivially learn "predict high when EPSS is high."

This implementation instead uses **CISA KEV membership**, a label sourced
independently of the EPSS/CVSS/ATT&CK features being weighted. EPSS itself
is influenced by observed exploitation signals (which can correlate with
KEV additions), so KEV is not a *perfectly* independent label either — this
residual correlation is disclosed as a limitation in `research_results.md`
— but it is materially less circular than training on a direct function of
one of the input features.

## 5. Experimental setup

- **Split**: 70/30 train/test, stratified on the `in_kev` label
  (`sklearn.model_selection.train_test_split`, `random_state=42`).
- **No leakage**: adaptive weights are fit on the training split only;
  every reported metric is computed on the held-out test split.
- **Metrics**: precision, recall, F1 at a fixed score threshold (≥60,
  i.e. "High or above"), ROC-AUC on the continuous score, Precision@K and
  Recall@K for K ∈ {10, 20, 50}, and Spearman rank correlation between the
  three scoring methods' orderings.
- **Explainability**: SHAP (if the installed `shap` version supports the
  fitted pipeline) with automatic fallback to permutation importance
  (`sklearn.inspection.permutation_importance`, scored on ROC-AUC).

## 6. Reproducing the results

```powershell
python scripts/fetch_raw_data.py   # one-time; skips files that already exist
python scripts/run_pipeline.py     # deterministic given the same data/raw/ files
streamlit run app.py
```

`run_pipeline.py` uses a fixed `random_state=42` throughout, so re-running it
against the same `data/raw/` files reproduces identical weights and metrics.
