# Attribution Notice

RiskRank-VAPT reuses scoring formulas and mapping logic from:

**Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework**
Copyright (c) 2025 Shreyas.A
Licensed under the MIT License.
https://github.com/shreyas23dev/Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework

Specifically reused (and in places adapted/fixed — see inline docstrings in
each module):

| Reused from the reference repo | Used in |
|---|---|
| NVD CVE / CVSS v3.1 parsing loop | `src/data_loader.py` |
| Static PSSS formula (`0.4·CVSS + 0.4·EPSS + 0.2·ATT&CK`) | `src/risk_scoring.py` |
| ATT&CK technique → UCKC phase mapping dictionary | `src/feature_engineering.py` |
| UCKC phase weight table | `src/feature_engineering.py` |
| Adaptive weighting via logistic regression (concept) | `src/adaptive_model.py` |
| SHAP explainability (concept) | `src/explainability.py` |

### Modifications made to the reused logic

- Removed Colab-only code (`google.colab.files.upload()`, inline `!pip install`).
- Fixed **label leakage**: the original adaptive-weighting step trained a
  classifier on a label derived from the EPSS feature itself
  (`epss > threshold`) while also using EPSS as an input feature. This
  implementation instead uses **CISA KEV membership** — an independent,
  external, real-world exploitation signal — as the training label, and
  learns weights on a training split only (see `src/evaluation.py`).
- Fixed undefined names in the original script's explainability section
  (`_HAS_SHAP`, `_HAS_MPL`, `compute_perm`) with a proper SHAP-with-
  permutation-importance-fallback implementation (`src/explainability.py`).
- Fixed a **silent UCKC-mapping bug**: the original script looked up the
  `attack_to_cve` dataset's `Phase` column (values `"Phase 1"`/`"Phase 2"`
  in the real data — that dataset's own internal categorization) against a
  table keyed by MITRE ATT&CK tactic names. The lookup always missed,
  so every CVE silently fell back to `uckc_weight = 0.4` regardless of its
  actual attack phase — the UCKC feature never varied. This implementation
  derives the ATT&CK tactic from each CVE's technique IDs directly
  (`src/feature_engineering.py`, `TECHNIQUE_TO_TACTIC`), so UCKC phase
  assignment is non-trivial. See `docs/research_results.md` §5.
- Fixed a merge-fanout bug: a few CVE IDs appear on more than one row of
  the `attack_to_cve` dataset; the original left-join style merge would
  have silently duplicated those CVE records. `feature_engineering.py` now
  deduplicates by merging technique lists per CVE ID before joining.
- Restructured the single linear Colab export into modular, importable
  Python files under `src/`.

The MIT License permits this reuse and modification; this notice and the
original repository's `LICENSE` text are preserved.

See the original license text in `LICENSE_UPSTREAM.md`.
