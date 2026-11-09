"""
Adaptive ML weighting for PSSS (Prioritized Security Scoring System).

Learns alpha/beta/gamma/delta weights over {CVSS, EPSS, ATT&CK, UCKC} by
fitting a logistic regression that predicts CISA KEV membership (the only
independent, real-world "actually exploited" ground truth available), then
normalizes the absolute coefficients into weights that sum to 1.

This is a cleaned-up, leakage-free rewrite of the adaptive-weighting idea in
the reference implementation (Attack-Phase-Aware-Dynamic-Vulnerability-
Prioritization-Framework, MIT licensed, see NOTICE.md). The original script
trained on a label *derived from the EPSS feature itself*
(`epss > threshold`) while also using EPSS as an input feature — that is
label leakage. Here the label is CISA KEV membership instead, which is an
independent external source, and weights are learned on a training split
only (see evaluation.py) so they are never fit on the data they are later
scored against.
"""
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = ["CVSS_norm", "epss", "attack_criticality", "uckc_weight"]
LABEL_COLUMN = "in_kev"

FALLBACK_WEIGHTS = {"alpha": 0.3, "beta": 0.3, "gamma": 0.2, "delta": 0.2}


def learn_adaptive_weights(train_df: pd.DataFrame):
    """Fit on TRAINING data only. Returns (weights_dict, fitted_model_or_None)."""
    X = train_df[FEATURE_COLUMNS].fillna(0)
    y = train_df[LABEL_COLUMN].astype(int)

    if y.nunique() < 2:
        print("[WARN] Only one class present in training labels; using fallback weights.")
        return dict(FALLBACK_WEIGHTS), None

    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    )
    model.fit(X, y)

    coefs = model.named_steps["logisticregression"].coef_[0]
    abs_coefs = np.abs(coefs)
    weights = abs_coefs / (abs_coefs.sum() + 1e-8)

    weights_dict = {
        "alpha": float(weights[0]), "beta": float(weights[1]),
        "gamma": float(weights[2]), "delta": float(weights[3]),
    }
    return weights_dict, model


def compute_adaptive_psss(df: pd.DataFrame, weights: dict) -> pd.DataFrame:
    df = df.copy()
    psss = (
        weights["alpha"] * df["CVSS_norm"].fillna(0)
        + weights["beta"] * df["epss"].fillna(0)
        + weights["gamma"] * df["attack_criticality"].fillna(0)
        + weights["delta"] * df["uckc_weight"].fillna(0.4)
    )
    df["score_adaptive_psss"] = psss * 100
    from risk_scoring import classify
    df["priority_adaptive_psss"] = df["score_adaptive_psss"].apply(classify)
    return df


if __name__ == "__main__":
    from data_loader import load_nvd_cves
    from data_enrichment import enrich
    from feature_engineering import add_attack_uckc_features
    from risk_scoring import compute_all_baselines
    from sklearn.model_selection import train_test_split

    df = compute_all_baselines(add_attack_uckc_features(enrich(load_nvd_cves())))
    train_df, test_df = train_test_split(
        df, test_size=0.3, random_state=42, stratify=df["in_kev"]
    )

    weights, model = learn_adaptive_weights(train_df)
    print("Learned weights:", weights)

    test_df = compute_adaptive_psss(test_df, weights)
    print(test_df[["cve_id", "score_adaptive_psss", "priority_adaptive_psss",
                   "in_kev"]].sort_values("score_adaptive_psss", ascending=False).head(10))
