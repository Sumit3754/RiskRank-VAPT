"""
Implements the three comparable prioritization approaches described in the
RiskRank-VAPT project PPT:

  1. CVSS-only baseline        -> CVSS_norm, scaled to 0-100
  2. Static PSSS                -> fixed-weight CVSS + EPSS + ATT&CK
                                    (formula reused from the reference repo,
                                    see NOTICE.md)
  3. Adaptive PSSS (UCKC)        -> ML-learned weights, see adaptive_model.py

All three are expressed on a common 0-100 scale so they can be compared and
classified with the same Critical/High/Medium/Low thresholds.
"""
import pandas as pd

# Static PSSS weights, reused from the reference implementation
STATIC_WEIGHTS = {"alpha": 0.4, "beta": 0.4, "gamma": 0.2}

PRIORITY_THRESHOLDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (0, "Low"),
]


def classify(score_0_100: float) -> str:
    for threshold, label in PRIORITY_THRESHOLDS:
        if score_0_100 >= threshold:
            return label
    return "Low"


def compute_cvss_baseline(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["CVSS_norm"] = df["CVSS_base"].fillna(0) / 10.0
    df["score_cvss_only"] = df["CVSS_norm"] * 100
    df["priority_cvss_only"] = df["score_cvss_only"].apply(classify)
    return df


def compute_static_psss(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    a, b, g = STATIC_WEIGHTS["alpha"], STATIC_WEIGHTS["beta"], STATIC_WEIGHTS["gamma"]
    psss = (
        a * df["CVSS_norm"].fillna(0)
        + b * df["epss"].fillna(0)
        + g * df["attack_criticality"].fillna(0)
    )
    df["score_static_psss"] = psss * 100
    df["priority_static_psss"] = df["score_static_psss"].apply(classify)
    return df


def compute_all_baselines(df: pd.DataFrame) -> pd.DataFrame:
    df = compute_cvss_baseline(df)
    df = compute_static_psss(df)
    return df


if __name__ == "__main__":
    from data_loader import load_nvd_cves
    from data_enrichment import enrich
    from feature_engineering import add_attack_uckc_features

    df = add_attack_uckc_features(enrich(load_nvd_cves()))
    df = compute_all_baselines(df)
    print(df[["cve_id", "score_cvss_only", "priority_cvss_only",
              "score_static_psss", "priority_static_psss"]].head(10))
