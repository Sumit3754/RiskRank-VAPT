"""
Reproducible comparison of the three prioritization approaches:
  1. CVSS-only baseline
  2. Static PSSS
  3. Adaptive PSSS (ML-weighted, UCKC-integrated)

Ground truth: CISA KEV membership (`in_kev`) — an independent, real-world
signal of actual exploitation. This is a PROXY label, not a complete measure
of "true risk" (see docs/research_results.md for limitations).

Adaptive weights are learned on the TRAIN split only (adaptive_model.py) and
every metric below is computed on the held-out TEST split, so no scoring
approach sees the labels it is evaluated against.
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from adaptive_model import compute_adaptive_psss, learn_adaptive_weights
from data_enrichment import enrich
from data_loader import load_nvd_cves
from explainability import explain
from feature_engineering import add_attack_uckc_features
from risk_scoring import compute_all_baselines

REPORTS_DIR = Path(__file__).resolve().parent.parent / "results" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

SCORE_COLUMNS = {
    "CVSS-only": "score_cvss_only",
    "Static PSSS": "score_static_psss",
    "Adaptive PSSS (UCKC)": "score_adaptive_psss",
}


def precision_recall_at_k(y_true, scores, k):
    order = np.argsort(-scores)[:k]
    k_true = np.asarray(y_true)[order]
    n_pos_total = np.asarray(y_true).sum()
    precision = k_true.sum() / k if k > 0 else 0.0
    recall = k_true.sum() / n_pos_total if n_pos_total > 0 else 0.0
    return precision, recall


def evaluate_approach(df: pd.DataFrame, score_col: str, label_col="in_kev",
                       classify_threshold=60, ks=(10, 20, 50)):
    y_true = df[label_col].astype(int).values
    scores = df[score_col].values
    y_pred = (scores >= classify_threshold).astype(int)

    metrics = {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = roc_auc_score(y_true, scores)
    else:
        metrics["roc_auc"] = float("nan")

    for k in ks:
        p_at_k, r_at_k = precision_recall_at_k(y_true, scores, k)
        metrics[f"precision@{k}"] = p_at_k
        metrics[f"recall@{k}"] = r_at_k

    return metrics


def run_full_pipeline(test_size=0.3, random_state=42):
    print("[1/6] Loading NVD CVE data ...")
    df = load_nvd_cves()
    n_raw = len(df)

    df = df.dropna(subset=["CVSS_base"]).reset_index(drop=True)
    print(f"      {n_raw} loaded, {n_raw - len(df)} dropped (no CVSS v3.1), "
          f"{len(df)} usable records")

    print("[2/6] Enriching with EPSS + CISA KEV + context ...")
    df = enrich(df)

    print("[3/6] Mapping ATT&CK -> UCKC phases ...")
    df = add_attack_uckc_features(df)
    print(f"      ATT&CK mapping coverage: {df['attack_mapped'].mean():.2%}")

    print("[4/6] Computing CVSS-only and Static PSSS baselines ...")
    df = compute_all_baselines(df)

    print("[5/6] Learning adaptive weights (train split only) ...")
    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=df["in_kev"]
    )
    weights, model = learn_adaptive_weights(train_df)
    print(f"      Learned weights: {weights}")

    train_df = compute_adaptive_psss(train_df, weights)
    test_df = compute_adaptive_psss(test_df, weights)
    full_df = pd.concat([train_df, test_df]).sort_index()

    print("[6/6] Evaluating on held-out test split ...")
    results = {}
    for name, col in SCORE_COLUMNS.items():
        results[name] = evaluate_approach(test_df, col)
    metrics_df = pd.DataFrame(results).T
    print(metrics_df.round(4))

    # Ranking correlation between approaches (test split)
    rank_corr = {}
    cols = list(SCORE_COLUMNS.values())
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            corr, _ = spearmanr(test_df[cols[i]], test_df[cols[j]])
            rank_corr[f"{cols[i]} vs {cols[j]}"] = corr

    # Explainability (only if the model was actually fit)
    importances = None
    if model is not None:
        from adaptive_model import FEATURE_COLUMNS, LABEL_COLUMN
        X_test = test_df[FEATURE_COLUMNS].fillna(0)
        y_test = test_df[LABEL_COLUMN].astype(int)
        importances = explain(model, X_test, y_test)
        print("\nFeature importance:\n", importances)

    # Save artifacts
    if model is not None:
        joblib.dump(model, MODELS_DIR / "adaptive_psss_model.joblib")
    full_df.to_csv(REPORTS_DIR / "prioritized_cves.csv", index=False)
    metrics_df.to_csv(REPORTS_DIR / "evaluation_metrics.csv")
    pd.Series(weights).to_csv(REPORTS_DIR / "adaptive_weights.csv")
    pd.Series(rank_corr).to_csv(REPORTS_DIR / "rank_correlation.csv")
    if importances is not None:
        importances.to_csv(REPORTS_DIR / "feature_importance.csv")

    print(f"\nSaved: {REPORTS_DIR / 'prioritized_cves.csv'}")
    print(f"Saved: {REPORTS_DIR / 'evaluation_metrics.csv'}")

    return full_df, metrics_df, weights, rank_corr, importances


if __name__ == "__main__":
    run_full_pipeline()
