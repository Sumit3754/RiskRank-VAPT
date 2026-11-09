"""
Maps CVEs to MITRE ATT&CK techniques and then to Unified Cyber Kill Chain
(UCKC) phases, producing the feature columns used by the scoring models.

UCKC phase-mapping table and UCKC phase weights are reused from the
reference implementation (Attack-Phase-Aware-Dynamic-Vulnerability-
Prioritization-Framework, MIT licensed, see NOTICE.md). That table is keyed
by MITRE ATT&CK *tactic* name (e.g. "Initial Access").

IMPORTANT FIX vs. the reference implementation: the reference script fed
the `Phase` column of the attack_to_cve dataset directly into this table.
In the real dataset that column holds values "Phase 1"/"Phase 2" — the
source dataset's own internal 2-bucket categorization, not MITRE ATT&CK
tactic names — so that lookup always missed and silently fell back to
"Unknown" for every CVE, making the UCKC feature a constant. This module
instead derives the ATT&CK *tactic* from the technique IDs themselves via
TECHNIQUE_TO_TACTIC, a partial, manually curated mapping of well-known
Enterprise ATT&CK technique IDs to their primary tactic (public MITRE
ATT&CK documentation). Technique IDs from the ICS matrix, or appearing
malformed in the source CSV (e.g. "T11190", "TT1565"), are intentionally
left unmapped rather than guessed — this is reported as a coverage
limitation in docs/research_results.md, not silently patched.
"""
from pathlib import Path

import pandas as pd

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

# Reused from the reference repository
CRITICAL_TECHNIQUES = {
    "T1190": "Initial Access", "T1078": "Initial Access",
    "T1068": "Privilege Escalation", "T1574": "Privilege Escalation",
    "T1021": "Lateral Movement",
}

# Partial technique-ID -> primary MITRE ATT&CK tactic mapping, covering the
# most common Enterprise technique IDs found in the attack_to_cve dataset.
# Built from public MITRE ATT&CK documentation; techniques with more than
# one associated tactic are assigned their most kill-chain-relevant one.
TECHNIQUE_TO_TACTIC = {
    **CRITICAL_TECHNIQUES,
    "T1003": "Credential Access", "T1005": "Collection",
    "T1036": "Defense Evasion", "T1040": "Credential Access",
    "T1046": "Discovery", "T1053": "Execution", "T1055": "Privilege Escalation",
    "T1057": "Discovery", "T1059": "Execution",
    "T1080": "Lateral Movement", "T1083": "Discovery", "T1087": "Discovery",
    "T1091": "Lateral Movement", "T1098": "Persistence",
    "T1105": "Command and Control", "T1110": "Credential Access",
    "T1114": "Collection", "T1133": "Initial Access",
    "T1134": "Privilege Escalation", "T1136": "Persistence",
    "T1185": "Collection", "T1189": "Initial Access", "T1200": "Initial Access",
    "T1202": "Defense Evasion", "T1203": "Execution", "T1204": "Execution",
    "T1210": "Lateral Movement", "T1211": "Defense Evasion",
    "T1212": "Credential Access", "T1213": "Collection",
    "T1480": "Defense Evasion", "T1485": "Impact", "T1489": "Impact",
    "T1491": "Impact", "T1496": "Impact", "T1497": "Defense Evasion",
    "T1499": "Impact", "T1505": "Persistence", "T1518": "Discovery",
    "T1525": "Persistence", "T1528": "Credential Access", "T1529": "Impact",
    "T1531": "Impact", "T1539": "Credential Access", "T1542": "Persistence",
    "T1546": "Persistence", "T1548": "Privilege Escalation",
    "T1550": "Lateral Movement", "T1552": "Credential Access",
    "T1553": "Defense Evasion", "T1554": "Persistence",
    "T1557": "Credential Access", "T1558": "Credential Access",
    "T1562": "Defense Evasion", "T1563": "Lateral Movement",
    "T1565": "Impact", "T1566": "Initial Access", "T1569": "Execution",
    "T1600": "Defense Evasion",
}

UCKC_MAPPING = {
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Lateral Movement",
    "Defense Evasion": "Installation",
    "Credential Access": "Lateral Movement",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Command & Control",
    "Command and Control": "Command & Control",
    "Collection": "Act on Objectives",
    "Exfiltration": "Act on Objectives",
    "Impact": "Act on Objectives",
}

UCKC_WEIGHTS = {
    "Reconnaissance": 0.3, "Delivery": 0.5, "Exploitation": 0.8,
    "Installation": 0.6, "Lateral Movement": 0.9, "Command & Control": 0.7,
    "Act on Objectives": 1.0, "Unknown": 0.4,
}

TECHNIQUE_COLUMNS = ["Primary Impact", "Secondary Impact",
                     "Exploitation Technique", "Uncategorized"]


def load_attack_map(path: Path = None) -> pd.DataFrame:
    path = path or (RAW_DIR / "attack_to_cve.csv")
    attack_map = pd.read_csv(path)
    attack_map.rename(columns={"CVE ID": "cve_id"}, inplace=True)

    def collect_techniques(row):
        techniques = []
        for col in TECHNIQUE_COLUMNS:
            val = row.get(col)
            if pd.notna(val):
                techniques.extend(t.strip() for t in str(val).split(";"))
        return list(set(techniques))

    attack_map["techniques"] = attack_map.apply(collect_techniques, axis=1)

    # A small number of CVE IDs appear on more than one row (different
    # technique sets). Merge their technique lists rather than letting a
    # left-join fan them out into duplicate CVE records downstream.
    attack_map = (
        attack_map.groupby("cve_id")["techniques"]
        .apply(lambda lists: list(set(t for lst in lists for t in lst)))
        .reset_index()
    )
    return attack_map


def _is_critical(tech_list):
    if not isinstance(tech_list, list):
        return 0
    return int(any(t in CRITICAL_TECHNIQUES for t in tech_list))


def _techniques_to_uckc(tech_list):
    """Map a CVE's technique IDs -> primary tactic -> UCKC phase.

    When techniques map to several tactics, the one with the highest UCKC
    weight is kept (i.e. the most kill-chain-advanced stage the CVE's
    mapped techniques could plausibly reach).
    """
    if not isinstance(tech_list, list) or not tech_list:
        return "Unknown"

    tactics = {TECHNIQUE_TO_TACTIC[t] for t in tech_list if t in TECHNIQUE_TO_TACTIC}
    if not tactics:
        return "Unknown"

    phases = {UCKC_MAPPING.get(t, "Unknown") for t in tactics}
    return max(phases, key=lambda p: UCKC_WEIGHTS.get(p, 0.0))


def add_attack_uckc_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    attack_map = load_attack_map()
    df = df.merge(attack_map, on="cve_id", how="left")

    df["attack_criticality"] = df["techniques"].apply(_is_critical)
    df["uckc_phase"] = df["techniques"].apply(_techniques_to_uckc)
    df["uckc_weight"] = df["uckc_phase"].map(UCKC_WEIGHTS).fillna(0.4)
    df["attack_mapped"] = df["techniques"].apply(
        lambda t: isinstance(t, list) and len(t) > 0
    )

    return df


if __name__ == "__main__":
    from data_loader import load_nvd_cves
    from data_enrichment import enrich

    df = enrich(load_nvd_cves())
    df = add_attack_uckc_features(df)
    print(f"ATT&CK mapping coverage: {df['attack_mapped'].mean():.2%}")
    print(df["uckc_phase"].value_counts())
