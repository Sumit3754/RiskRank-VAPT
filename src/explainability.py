"""
Explainability for the adaptive PSSS model: SHAP values when available,
falling back to permutation importance otherwise.

The reference implementation referenced undefined names (`_HAS_SHAP`,
`_HAS_MPL`, `compute_perm`) at this point in its script; this module defines
them properly so explainability always produces a usable result.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False

FIGURES_DIR = Path(__file__).resolve().parent.parent / "results" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def compute_permutation_importance(model, X: pd.DataFrame, y: pd.Series):
    result = permutation_importance(
        model, X, y, n_repeats=20, random_state=42, scoring="roc_auc"
    )
    imp = pd.Series(result.importances_mean, index=X.columns).sort_values(ascending=False)
    std = pd.Series(result.importances_std, index=X.columns).loc[imp.index]
    return imp, std


def explain(model, X: pd.DataFrame, y: pd.Series, save_prefix="shap"):
    """Produces a feature-importance figure. Returns a Series of importances."""
    if HAS_SHAP:
        try:
            clf = model.named_steps["logisticregression"]
            scaler = model.named_steps["standardscaler"]
            X_scaled = pd.DataFrame(scaler.transform(X), columns=X.columns, index=X.index)

            explainer = shap.Explainer(clf, X_scaled)
            shap_values = explainer(X_scaled)

            plt.figure()
            shap.summary_plot(shap_values, X_scaled, plot_type="bar", show=False)
            plt.title("Global Feature Importance (SHAP) - Adaptive PSSS Model")
            plt.tight_layout()
            plt.savefig(FIGURES_DIR / f"{save_prefix}_importance_bar.png", dpi=150)
            plt.close()

            plt.figure()
            shap.summary_plot(shap_values, X_scaled, show=False)
            plt.title("Feature Influence on KEV-Exploitation Likelihood")
            plt.tight_layout()
            plt.savefig(FIGURES_DIR / f"{save_prefix}_summary.png", dpi=150)
            plt.close()

            mean_abs = np.abs(shap_values.values).mean(axis=0)
            return pd.Series(mean_abs, index=X.columns).sort_values(ascending=False)
        except Exception as e:
            print(f"[WARN] SHAP failed ({e}); falling back to permutation importance.")

    imp, std = compute_permutation_importance(model, X, y)
    plt.figure(figsize=(7, 3 + 0.5 * len(imp)))
    plt.barh(imp.index, imp.values, xerr=std.values, capsize=5, color="skyblue")
    plt.xlabel("Importance (permutation mean, ROC-AUC drop)")
    plt.title("Adaptive PSSS Feature Importance (Permutation)")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / f"{save_prefix}_importance_bar.png", dpi=150)
    plt.close()
    return imp
