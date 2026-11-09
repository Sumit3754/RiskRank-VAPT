"""
Loads raw NVD CVE records (CVSS v3.1) into a flat pandas DataFrame.

Adapted from the CVE-parsing loop in the reused reference implementation
(Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework, MIT
licensed, see NOTICE.md) with the Colab-specific upload step removed and
robustness added for missing/partial metric blocks.
"""
from pathlib import Path
import json

import pandas as pd

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def load_nvd_cves(path: Path = None) -> pd.DataFrame:
    """Parse data/raw/nvd_cves.json into a DataFrame of CVE records."""
    path = path or (RAW_DIR / "nvd_cves.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

        av = ac = pr = ui = s = c = i = a = score = severity = None
        metrics_data = cve.get("metrics", {})
        if "cvssMetricV31" in metrics_data and metrics_data["cvssMetricV31"]:
            cvss_entry = metrics_data["cvssMetricV31"][0]
            m = cvss_entry.get("cvssData", {})
            av = m.get("attackVector")
            ac = m.get("attackComplexity")
            pr = m.get("privilegesRequired")
            ui = m.get("userInteraction")
            s = m.get("scope")
            c = m.get("confidentialityImpact")
            i = m.get("integrityImpact")
            a = m.get("availabilityImpact")
            score = m.get("baseScore")
            severity = m.get("baseSeverity")

        records.append({
            "cve_id": cve_id,
            "cve_text": desc,
            "published": cve.get("published"),
            "AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s,
            "C": c, "I": i, "A": a,
            "CVSS_base": score,
            "CVSS_severity": severity,
        })

    df = pd.DataFrame(records).dropna(subset=["cve_id"]).drop_duplicates("cve_id")
    df["has_cvss"] = df["CVSS_base"].notna()
    return df.reset_index(drop=True)


if __name__ == "__main__":
    df = load_nvd_cves()
    print(f"Loaded {len(df)} CVE records")
    print(f"With CVSS v3.1 score: {df['has_cvss'].sum()} "
          f"({df['has_cvss'].mean():.1%})")
    print(df.head())
