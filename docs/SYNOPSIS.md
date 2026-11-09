# Project Synopsis

## RiskRank-VAPT: Dynamic Vulnerability Prioritization Using Machine Learning

**Submitted for:** B.C.A., Session 2026-27
**Department of Computer Engineering & Applications, GLA University, Mathura**
**Under the supervision of:** Dr. Arun Singh Yadav, Assistant Professor

---

## 1. Introduction

Organizations routinely run vulnerability scanners that detect hundreds or
thousands of security weaknesses (CVEs) across their systems. Each CVE is
conventionally ranked by its CVSS (Common Vulnerability Scoring System)
score — a static, 0–10 severity rating assigned at disclosure time. In
practice, security teams cannot fix every finding immediately, and CVSS
alone does not tell them which vulnerabilities are actually being exploited
by attackers right now versus which are theoretical risks.

RiskRank-VAPT is a research prototype that re-ranks vulnerabilities using a
combination of severity (CVSS), real-world exploitation likelihood (EPSS),
known attacker behaviour (MITRE ATT&CK), and attack-chain position (Unified
Cyber Kill Chain — UCKC), with the relative importance of each signal
**learned by a machine learning model** rather than fixed by a human.

## 2. Problem Statement

Traditional vulnerability scanning and ranking suffers from:

- A large volume of findings that overwhelms manual triage ("alert
  fatigue").
- Many vulnerabilities receiving similar CVSS scores despite very different
  real-world risk.
- Heavy dependence on a single static score (CVSS) that does not account
  for exploitation activity, attacker techniques, or organizational
  context.
- Difficulty identifying, among hundreds of findings, which ones should be
  remediated first.

**Research question:** *How can machine learning and contextual security
intelligence (exploit probability, attacker technique data, attack-chain
position) be combined to prioritize vulnerabilities according to their
practical, real-world risk — and does this measurably outperform
conventional CVSS-based ranking?*

## 3. Objectives

1. Collect a substantial real-world sample of CVE findings (via the NVD
   CVE database, used as a stand-in for live scanner output).
2. Enrich each finding with CVSS, EPSS (exploit probability), CISA KEV
   (confirmed-exploited status), and attacker technique/attack-phase data.
3. Develop a machine learning model that learns how to weight these
   signals, rather than using fixed, hand-chosen weights.
4. Assign a final risk score (0–100) and a priority level (Critical / High
   / Medium / Low) to every vulnerability.
5. Present results in an ordered, filterable dashboard.
6. **Rigorously compare** the proposed approach against conventional
   CVSS-only ranking and a fixed-weight baseline, using a held-out test set
   so the comparison is not circular.

## 4. Existing Approaches and Their Limitation

Most vulnerability management tools either rank purely by CVSS, or combine
multiple signals (severity, exploit intelligence, attacker technique data)
using weights fixed in advance by the designer. Both approaches share the
same underlying weakness: they encode a human guess about which signal
matters most for a given environment, rather than letting evidence from
real exploitation outcomes decide. A fixed-weight combination also cannot
adapt as the relative predictive value of each signal shifts over time
(for example, as EPSS model versions are retrained, or as new attacker
techniques become dominant).

## 4a. Why CISA KEV, not EPSS, was chosen as the ground-truth label

A natural shortcut would be to train the weighting model on a label derived
from EPSS itself (e.g. "EPSS above some threshold"). This was deliberately
avoided: if EPSS is both an input feature *and* e trthe source of thaining
label, the model can trivially learn to reproduce EPSS rather than learning
anything genuinely new — a methodological error known as label leakage.
This project instead uses CISA KEV catalog membership as the training
label — a real-world, independently sourced confirmation of actual
exploitation — so the model is evaluated on whether it predicts genuine
outcomes, not on whether it reproduces one of its own inputs.

## 5. Proposed System — How It Works

```
NVD CVE records (severity data)
        │
        ▼
Enrichment: EPSS exploit-probability + CISA KEV confirmed-exploited status
        │
        ▼
MITRE ATT&CK technique mapping → Unified Cyber Kill Chain (UCKC) phase
        │
        ▼
Three scores computed and compared:
   (a) CVSS-only            — the conventional baseline
   (b) Static PSSS          — fixed-weight blend (0.4·CVSS + 0.4·EPSS + 0.2·ATT&CK)
   (c) Adaptive PSSS (UCKC) — ML-learned weights over CVSS, EPSS, ATT&CK, UCKC
        │
        ▼
Priority classification: Critical / High / Medium / Low
        │
        ▼
Evaluation against real exploitation data (CISA KEV) on a held-out test set
        │
        ▼
Explainability (SHAP) + interactive dashboard
```

**The adaptive-weighting step, in plain terms:** the system is shown a
training set of past CVEs, each labelled with whether it was later
confirmed as actually exploited (added to CISA's Known Exploited
Vulnerabilities catalog). A logistic regression model learns which of the
four signals (CVSS, EPSS, ATT&CK criticality, UCKC phase weight) best
predicted that outcome. Those learned coefficients become the scoring
weights, which are then applied to a **separate, unseen test set** to
measure how well the approach actually generalizes — avoiding the common
pitfall of a model simply memorizing its own training data.

## 6. Methodology Summary

- **Data sources:** NVD CVE API 2.0, FIRST.org EPSS, CISA KEV catalog,
  Center for Threat-Informed Defense `attack_to_cve` mapping — all live,
  public data, not synthetic.
- **Sample:** 59,446 CVE records (a 2017–2024 historical sample plus the
  most recently disclosed CVEs as of the last data refresh, including
  CVEs published in late 2025 and 2026); 47,117 usable after removing
  records without a CVSS v3.1 score. The dataset is refreshed on demand
  (§9a) rather than being a fixed, aging snapshot.
- **Ground truth for evaluation:** CISA KEV membership (independent of the
  EPSS/CVSS/ATT&CK features being weighted, to avoid circular evaluation).
- **Split:** 70% training / 30% test, stratified by exploited/not-exploited
  label, fixed random seed for reproducibility.
- **Tools:** Python, Pandas, NumPy, Scikit-learn, SHAP, Streamlit, Plotly.
- **Environment:** runs entirely on a local machine (tested on an ordinary
  Windows laptop, 16 GB RAM, no GPU, no database server, no cloud
  deployment).

## 7. Expected / Measured Outcome

The system produces, for every CVE: its CVSS score, EPSS probability, KEV
status, mapped ATT&CK/UCKC phase, three comparable risk scores, and a
priority label — displayed in a searchable, filterable dashboard with
CSV export.

**Measured result (see `docs/research_results.md` for full detail):**

| Approach | ROC-AUC | Precision@50 |
|---|---|---|
| CVSS-only (conventional) | 0.742 | 0.12 |
| Static PSSS (fixed weights) | 0.909 | 0.74 |
| **Adaptive PSSS (ML-learned weights)** | **0.931** | 0.72 |

In practical terms: of the top 50 vulnerabilities flagged by CVSS-only
ranking, only 6 were genuinely confirmed-exploited (CISA KEV); of the top
50 flagged by either PSSS variant, roughly 36-37 were. This directly
evidences the problem statement in §2 and the project's core claim — and
holds even with the dataset refreshed to include CVEs disclosed within the
last two weeks and in December 2025 (§9a), not only historical ones.

**Note on Precision@50 specifically:** across repeated data refreshes,
Adaptive PSSS consistently ranks above both baselines on ROC-AUC, but has
occasionally been edged out by Static PSSS on Precision@50 by a small
margin (as in the table above). State ROC-AUC as the primary ranking-
quality claim in your report, and report this Precision@K variability as
an honest, disclosed finding rather than omitting it — examiners respond
better to a correctly qualified claim than an overstated one.

## 8. Scope

**In scope:** CVE collection, enrichment, feature extraction, ML-based risk
scoring, prioritization, visualization/reporting, and quantitative
comparison against CVSS-based ranking.

**Out of scope (documented as future work):** live scanner integration
(a public CVE dataset stands in for scanner output), multi-scanner support,
a production asset-inventory integration, cloud deployment.

## 9. Methodological Safeguards Built Into This Project

Three design risks are common in systems that combine CVSS/EPSS/ATT&CK
signals with a learned weighting model, and each was specifically addressed
during development rather than left as an unstated assumption:

1. **Label leakage in adaptive weighting.** Training the weight-learning
   model on a label derived from one of its own input features (e.g. "EPSS
   above a threshold") would let the model trivially "cheat." This project
   uses CISA KEV membership instead — a label sourced independently of the
   CVSS/EPSS/ATT&CK features being weighted — and learns weights on the
   training split only, evaluating strictly on a held-out test split.
2. **Correct attack-phase mapping.** Mapping a CVE to its Unified Cyber
   Kill Chain phase requires first resolving its MITRE ATT&CK technique IDs
   to the correct ATT&CK tactic; a naive implementation can silently
   default every CVE to an "Unknown" phase if this resolution step is done
   incorrectly, making the attack-phase feature contribute nothing. This
   project derives the tactic directly from each CVE's technique IDs via an
   explicit, verifiable mapping table, and reports the resulting
   phase-coverage percentage transparently rather than assuming full
   coverage.
3. **Data-integrity in enrichment merges.** When joining CVE records against
   an attacker-technique dataset, CVE IDs that legitimately appear more
   than once (e.g. mapped to multiple technique sets) can silently
   duplicate rows during a naive join. This project deduplicates by
   merging technique lists per CVE ID before joining, so prioritized
   counts and evaluation sample sizes stay accurate.

These safeguards, and the exact coverage/limitation figures that result
from them, are documented in full in `docs/methodology.md` and
`docs/research_results.md`.

## 9a. Currency and Extensibility — Rolling Dataset Updates

A common weakness of vulnerability-prioritization research is that it
reports results on a static, historical snapshot, which can date quickly
given how fast new CVEs are disclosed. To keep this project's results
current and to support ongoing/future research use, the data-collection
layer supports three modes:

- A one-time **historical bootstrap** (used to build the baseline dataset
  described in §6),
- An on-demand **rolling update** that fetches CVEs published in the most
  recent N days directly from NVD and merges them into the existing
  dataset (deduplicating by CVE ID, refreshing EPSS/KEV snapshots at the
  same time), without needing to re-fetch historical years, and
- A **targeted gap-fill** for one specific calendar year, used when a
  particular year turns out to be under-covered. This was exercised during
  development: a specific-CVE check surfaced a coverage gap (the rolling
  update alone had skipped all of 2025), which the gap-fill mode closed by
  walking backward from the end of that year so the fetch is biased toward
  the most recent part of the gap rather than its oldest part.

This means the system can be re-run at any point — including against the
most recently disclosed CVEs, or to backfill a specific period found to be
under-covered — to produce an updated evaluation, which supports extending
this work into a journal submission with newer data, or periodic
re-validation as a form of continuous research. The exact numbers in §7
reflect the dataset as of the most recent run; see
`docs/research_results.md` for the current figures and the date they were
generated.

## 10. Limitations (to be stated honestly in the final report)

- CISA KEV is a real but incomplete, retrospective proxy for "true risk,"
  not a perfect ground truth.
- The public ATT&CK-to-CVE mapping dataset covers only a small fraction
  (~0.76%) of the CVE sample, so ATT&CK/UCKC's contribution is evidenced on
  a smaller mapped subset.
- Asset criticality / internet exposure are simulated, configurable
  contextual fields (no live asset inventory exists for this prototype)
  and are excluded from all evaluation numbers.
- Severe class imbalance (0.77% confirmed-exploited) means metrics should
  be read via ROC-AUC/Precision@K rather than raw accuracy.

## 11. Tools and Technology

| Category | Choice |
|---|---|
| Programming language | Python |
| Data processing | Pandas, NumPy |
| Machine learning | Scikit-learn (Logistic Regression) |
| Explainability | SHAP |
| Visualization / dashboard | Streamlit, Plotly |
| Security data sources | NVD, FIRST EPSS, CISA KEV, MITRE ATT&CK |

## 12. References

1. National Vulnerability Database (NVD) — https://nvd.nist.gov/
2. EPSS / FIRST — https://www.first.org/epss/
3. CISA Known Exploited Vulnerabilities Catalog —
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog
4. MITRE ATT&CK — https://attack.mitre.org/
5. Scikit-learn Documentation — https://scikit-learn.org/
6. SHAP Documentation — https://shap.readthedocs.io/
7. CVSS Documentation (FIRST.org) — https://www.first.org/cvss/
