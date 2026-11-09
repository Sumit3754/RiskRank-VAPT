"""
RiskRank-VAPT — Dynamic Vulnerability Prioritization Dashboard

Reads the outputs produced by `python scripts/run_pipeline.py` from
results/reports/ and results/figures/. Run the pipeline at least once before
launching this dashboard.

Launch:  streamlit run app.py
"""
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

REPORTS_DIR = Path(__file__).resolve().parent / "results" / "reports"
FIGURES_DIR = Path(__file__).resolve().parent / "results" / "figures"

st.set_page_config(page_title="RiskRank-VAPT", layout="wide", page_icon="🛡️")


@st.cache_data
def load_results():
    cves_path = REPORTS_DIR / "prioritized_cves.csv"
    if not cves_path.exists():
        return None, None, None, None
    df = pd.read_csv(cves_path)
    metrics_df = pd.read_csv(REPORTS_DIR / "evaluation_metrics.csv", index_col=0)
    weights = pd.read_csv(REPORTS_DIR / "adaptive_weights.csv", index_col=0).iloc[:, 0]
    importance_path = REPORTS_DIR / "feature_importance.csv"
    importance = pd.read_csv(importance_path, index_col=0).iloc[:, 0] if importance_path.exists() else None
    return df, metrics_df, weights, importance


df, metrics_df, weights, importance = load_results()

st.title("🛡️ RiskRank-VAPT")
st.caption("Dynamic Vulnerability Prioritization Using Machine Learning — CVSS + EPSS + "
           "MITRE ATT&CK + UCKC, adaptively weighted")

if df is None:
    st.error("No results found. Run `python scripts/run_pipeline.py` first, then reload.")
    st.stop()

# ---------------------------------------------------------------- Sidebar ---
st.sidebar.header("Filters")
priority_filter = st.sidebar.multiselect(
    "Priority (Adaptive PSSS)",
    options=["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"],
)
kev_only = st.sidebar.checkbox("Show only CISA KEV (known exploited)", value=False)
exposure_filter = st.sidebar.multiselect(
    "Internet exposure (simulated context)",
    options=sorted(df["internet_exposure"].dropna().unique()),
    default=sorted(df["internet_exposure"].dropna().unique()),
)
search = st.sidebar.text_input("Search CVE ID or description contains")

filtered = df[df["priority_adaptive_psss"].isin(priority_filter)]
filtered = filtered[filtered["internet_exposure"].isin(exposure_filter)]
if kev_only:
    filtered = filtered[filtered["in_kev"]]
if search:
    mask = filtered["cve_id"].str.contains(search, case=False, na=False) | \
        filtered["cve_text"].str.contains(search, case=False, na=False)
    filtered = filtered[mask]

# ------------------------------------------------------------- KPI row -----
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total vulnerabilities analyzed", f"{len(df):,}")
col2.metric("Critical", int((df["priority_adaptive_psss"] == "Critical").sum()))
col3.metric("High", int((df["priority_adaptive_psss"] == "High").sum()))
col4.metric("Known exploited (CISA KEV)", int(df["in_kev"].sum()))

st.divider()

# --------------------------------------------------------- Distribution ----
left, right = st.columns([1, 1])
with left:
    st.subheader("Priority distribution (Adaptive PSSS)")
    dist = df["priority_adaptive_psss"].value_counts().reindex(
        ["Critical", "High", "Medium", "Low"]
    ).fillna(0)
    fig = px.bar(dist, x=dist.index, y=dist.values,
                 labels={"x": "Priority", "y": "Count"},
                 color=dist.index,
                 color_discrete_map={"Critical": "#B00020", "High": "#F57C00",
                                     "Medium": "#FBC02D", "Low": "#388E3C"})
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, width='stretch')

with right:
    st.subheader("CVSS-only vs Adaptive PSSS")
    sample = df.sample(min(1000, len(df)), random_state=1)
    fig2 = px.scatter(
        sample, x="score_cvss_only", y="score_adaptive_psss", color="in_kev",
        labels={"score_cvss_only": "CVSS-only score (0-100)",
                "score_adaptive_psss": "Adaptive PSSS score (0-100)",
                "in_kev": "In CISA KEV"},
        color_discrete_map={True: "#B00020", False: "#90A4AE"},
        opacity=0.6,
    )
    fig2.add_shape(type="line", x0=0, y0=0, x1=100, y1=100,
                   line=dict(color="gray", dash="dash"))
    st.plotly_chart(fig2, width='stretch')

# --------------------------------------------------- Evaluation metrics ----
st.subheader("Comparative evaluation (held-out test split)")
st.caption("Ground truth = CISA KEV membership. See docs/research_results.md for "
           "methodology and limitations.")
st.dataframe(metrics_df.style.format("{:.3f}"), width='stretch')

m1, m2 = st.columns([1, 1])
with m1:
    st.subheader("Learned adaptive weights")
    st.caption("α (CVSS) · β (EPSS) · γ (ATT&CK) · δ (UCKC) — learned on the training split only")
    w_fig = px.bar(weights, x=weights.index, y=weights.values,
                   labels={"x": "Weight", "y": "Normalized coefficient"})
    st.plotly_chart(w_fig, width='stretch')

with m2:
    st.subheader("Feature importance")
    if importance is not None:
        imp_fig = px.bar(importance, x=importance.values, y=importance.index,
                         orientation="h",
                         labels={"x": "Importance", "y": "Feature"})
        st.plotly_chart(imp_fig, width='stretch')
    else:
        st.info("No feature-importance artifact found.")
    shap_bar = FIGURES_DIR / "shap_importance_bar.png"
    if shap_bar.exists():
        st.image(str(shap_bar), caption="SHAP / permutation feature importance")

st.divider()

# ---------------------------------------------------------- Top-N table ----
st.subheader("Top prioritized CVEs (Adaptive PSSS)")
top_n = st.slider("Show top N", min_value=5, max_value=50, value=20, step=5)
display_cols = [
    "cve_id", "CVSS_base", "epss", "in_kev", "uckc_phase",
    "score_cvss_only", "score_static_psss", "score_adaptive_psss",
    "priority_adaptive_psss", "asset_criticality", "internet_exposure",
]
top_table = filtered.sort_values("score_adaptive_psss", ascending=False).head(top_n)
st.dataframe(top_table[display_cols], width='stretch', hide_index=True)

st.download_button(
    "⬇ Export filtered results as CSV",
    data=filtered[display_cols + ["cve_text"]].to_csv(index=False).encode("utf-8"),
    file_name="riskrank_vapt_prioritized_cves.csv",
    mime="text/csv",
)

standard_export = filtered[[
    "cve_id", "cve_text", "CVSS_base", "score_adaptive_psss",
    "priority_adaptive_psss", "in_kev", "internet_exposure",
]].rename(columns={
    "cve_text": "description",
    "CVSS_base": "cvss",
    "score_adaptive_psss": "adaptive_psss",
    "priority_adaptive_psss": "priority",
    "internet_exposure": "exposure",
})
st.download_button(
    "⬇ Export with standard column names (cve_id, description, cvss, "
    "adaptive_psss, priority, in_kev, exposure)",
    data=standard_export.to_csv(index=False).encode("utf-8"),
    file_name="riskrank_vapt_standard_export.csv",
    mime="text/csv",
    help="Same scored data as the export above, with column names renamed "
         "to a common convention for tools that auto-detect columns by name.",
)

with st.expander("ℹ️ About the scores and contextual fields"):
    st.markdown(
        """
- **CVSS-only**: raw NVD CVSS v3.1 base score, rescaled to 0-100.
- **Static PSSS**: fixed-weight `0.4·CVSS + 0.4·EPSS + 0.2·ATT&CK` (reused from the
  reference implementation).
- **Adaptive PSSS (UCKC)**: ML-learned weights over CVSS, EPSS, ATT&CK and UCKC
  attack-phase weight, fit on CISA KEV membership as ground truth (training split only).
- **Asset criticality / Internet exposure**: *simulated, configurable* contextual fields —
  no live asset inventory exists for this research prototype, so these are deterministically
  assigned per CVE for demonstration only. They are **not** used in the ML evaluation above.
        """
    )
