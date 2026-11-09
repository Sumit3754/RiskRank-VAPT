"""
Enriches the base CVE DataFrame with:
  - EPSS exploit-probability scores (FIRST.org)
  - CISA KEV (Known Exploited Vulnerabilities) membership
  - Exploit-availability flag (derived from KEV; the only reliable public
    signal of real-world exploitation available to this project)
  - Asset criticality / internet exposure — a CONFIGURABLE, SIMULATED
    organizational-context layer. No live asset inventory or CMDB exists for
    this research prototype, so these two fields are assigned deterministically
    (seeded by CVE ID, not random per run) to stand in for the "asset context"
    inputs described in the project PPT. They are used only for the dashboard's
    contextual-scoring demonstration, never as a feature in the ML evaluation,
    so no fabricated field can influence reported accuracy/F1/ranking metrics.
"""
import hashlib
from pathlib import Path

import pandas as pd

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

ASSET_CRITICALITY_LEVELS = ["Critical", "High", "Medium", "Low"]
EXPOSURE_LEVELS = ["Internet-facing", "Internal"]


def _deterministic_bucket(key: str, buckets: list):
    h = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
    return buckets[h % len(buckets)]


def load_epss(path: Path = None) -> pd.DataFrame:
    path = path or (RAW_DIR / "epss_scores.csv")
    epss_df = pd.read_csv(path)
    epss_df.rename(columns={epss_df.columns[0]: "cve_id"}, inplace=True)
    epss_df["epss"] = pd.to_numeric(epss_df["epss"], errors="coerce")
    return epss_df[["cve_id", "epss", "percentile"]]


def load_kev(path: Path = None) -> set:
    path = path or (RAW_DIR / "cisa_kev.json")
    import json
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    epss_df = load_epss()
    df = df.merge(epss_df, on="cve_id", how="left")
    df["epss"] = df["epss"].fillna(0.0)

    kev_ids = load_kev()
    df["in_kev"] = df["cve_id"].isin(kev_ids)
    df["exploit_available"] = df["in_kev"]  # only reliable public signal we have

    df["asset_criticality"] = df["cve_id"].apply(
        lambda cid: _deterministic_bucket(cid + "|asset", ASSET_CRITICALITY_LEVELS)
    )
    df["internet_exposure"] = df["cve_id"].apply(
        lambda cid: _deterministic_bucket(cid + "|exposure", EXPOSURE_LEVELS)
    )

    return df


if __name__ == "__main__":
    from data_loader import load_nvd_cves

    df = load_nvd_cves()
    df = enrich(df)
    print(f"Enriched {len(df)} records")
    print(f"KEV matches: {df['in_kev'].sum()}")
    print(f"EPSS coverage: {(df['epss'] > 0).mean():.1%} nonzero")
    print(df[["cve_id", "CVSS_base", "epss", "in_kev", "asset_criticality",
              "internet_exposure"]].head())
