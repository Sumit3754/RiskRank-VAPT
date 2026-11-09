"""
Raw data fetcher for RiskRank-VAPT.

Pulls real, publicly available data (no API key required) and saves it under
data/raw/ so the rest of the pipeline can run entirely offline afterwards:

  - NVD CVE records (CVSS v3.1) across several 120-day windows, 2017-present
  - FIRST EPSS current snapshot (exploit prediction scores for ~all CVEs)
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - Center for Threat-Informed Defense ATT&CK-to-CVE mapping

Two modes:

  Historical bootstrap (first-time setup; skips any file that already exists):
      python scripts/fetch_raw_data.py

  Rolling update — pull newly published CVEs from the last N days and merge
  them into the existing dataset (dedup by CVE ID), so results can include
  the most recently disclosed vulnerabilities without re-fetching everything:
      python scripts/fetch_raw_data.py --latest 180
      python scripts/fetch_raw_data.py --latest 180 --max-records 6000

  After either mode, re-run scripts/run_pipeline.py to regenerate results.
"""
import argparse
import gzip
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACK_MAP_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/master/Att%26ckToCveMappings.csv"
)

# Years chosen to span the coverage of the ATT&CK-to-CVE mapping dataset
# (mostly 2017-2020) as well as recent years, so the UCKC/ATT&CK features
# have real overlap to learn from instead of being entirely absent.
# 2019/2020 are pulled in FULL (not capped) because they hold the largest
# share of the ~839 CVEs in the ATT&CK-to-CVE mapping dataset (186 and 223
# respectively) — capping them, as the first pass did, left ATT&CK/UCKC
# features almost entirely empty (<0.2% coverage).
PER_YEAR_TARGET = {
    2017: 1000, 2018: 1000, 2019: None, 2020: None,
    2021: 1000, 2022: 1000, 2023: 1000, 2024: 1000,
}
WINDOW_DAYS = 120  # NVD API 2.0's hard limit on pubStartDate..pubEndDate span


def _fetch_date_range(pub_start: datetime, pub_end: datetime, cap=None):
    """Fetch all CVE records published in [pub_start, pub_end), paginating
    both across >120-day spans (outer loop) and across >2000-result windows
    (inner loop). Stops early once `cap` records have been collected, if set.
    """
    all_vulns = []
    window_start = pub_start

    while window_start < pub_end and (cap is None or len(all_vulns) < cap):
        window_end = min(window_start + timedelta(days=WINDOW_DAYS), pub_end)
        start_index = 0
        window_total = None

        while window_total is None or start_index < window_total:
            remaining = (cap - len(all_vulns)) if cap is not None else None
            page_size = 2000 if remaining is None else max(1, min(2000, remaining))

            params = {
                "pubStartDate": window_start.strftime("%Y-%m-%dT00:00:00.000-00:00"),
                "pubEndDate": window_end.strftime("%Y-%m-%dT00:00:00.000-00:00"),
                "resultsPerPage": page_size,
                "startIndex": start_index,
                "noRejected": "",
            }
            for attempt in range(3):
                resp = requests.get(NVD_URL, params=params, timeout=30)
                if resp.status_code == 200:
                    break
                print(f"  retry ({resp.status_code}) ...")
                time.sleep(10)
            else:
                print(f"[warn] giving up on window {window_start.date()}..{window_end.date()} "
                      f"startIndex={start_index}")
                break

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            window_total = data.get("totalResults", len(vulns))
            all_vulns.extend(vulns)
            start_index += len(vulns)
            print(f"  {window_start.date()}..{window_end.date()} "
                  f"[{start_index}/{window_total}]: +{len(vulns)} "
                  f"(running total {len(all_vulns)})")

            if cap is not None and len(all_vulns) >= cap:
                break
            if len(vulns) == 0:
                break
            time.sleep(7)  # stay well under the 5 req / 30s public rate limit

        window_start = window_end
        time.sleep(7)

    return all_vulns[:cap] if cap is not None else all_vulns


def _load_existing_nvd():
    out_file = RAW_DIR / "nvd_cves.json"
    if not out_file.exists():
        return {}, out_file
    data = json.loads(out_file.read_text(encoding="utf-8"))
    by_id = {v["cve"]["id"]: v for v in data.get("vulnerabilities", []) if v.get("cve", {}).get("id")}
    return by_id, out_file


def fetch_nvd(per_year_target=PER_YEAR_TARGET):
    """Historical bootstrap: skips entirely if nvd_cves.json already exists."""
    out_file = RAW_DIR / "nvd_cves.json"
    if out_file.exists():
        print(f"[skip] {out_file} already exists")
        return

    all_vulns = []
    for year, cap in per_year_target.items():
        year_vulns = _fetch_date_range(datetime(year, 1, 1), datetime(year, 12, 31), cap)
        print(f"  year {year}: {len(year_vulns)} records (grand total so far "
              f"{len(all_vulns) + len(year_vulns)})")
        all_vulns.extend(year_vulns)

    out_file.write_text(json.dumps({"vulnerabilities": all_vulns}), encoding="utf-8")
    print(f"[ok] saved {len(all_vulns)} CVE records -> {out_file}")


def _fetch_backward(range_start: datetime, range_end: datetime, max_records=None, chunk_days=15):
    """Fetch CVEs published in [range_start, range_end), walking BACKWARD
    from range_end in `chunk_days`-sized windows (most recent window first).

    This ordering matters whenever `max_records` might be hit before the
    whole range is covered: NVD now publishes ~150-200 CVEs/day, so even a
    120-day window can hold 20,000+ records. A naive forward walk from
    range_start would spend the cap on the OLDEST part of the range and
    never reach the newest records in it; walking backward from range_end
    spends the cap on the most recent/relevant records instead.
    """
    new_vulns = []
    chunk_end = range_end

    while chunk_end > range_start and (max_records is None or len(new_vulns) < max_records):
        chunk_start = max(chunk_end - timedelta(days=chunk_days), range_start)
        remaining = (max_records - len(new_vulns)) if max_records is not None else None
        chunk_vulns = _fetch_date_range(chunk_start, chunk_end, cap=remaining)
        new_vulns.extend(chunk_vulns)
        print(f"  chunk {chunk_start.date()}..{chunk_end.date()}: +{len(chunk_vulns)} "
              f"(running total {len(new_vulns)}"
              f"{'/' + str(max_records) if max_records is not None else ''})")
        chunk_end = chunk_start

    return new_vulns


def fetch_latest(days=180, max_records=6000, chunk_days=15):
    """Rolling update: pull CVEs published in the last `days` days (capped
    at `max_records`) and MERGE them into the existing nvd_cves.json,
    deduplicating by CVE ID (a freshly re-fetched record replaces the old
    one, e.g. if NVD has since added/updated its CVSS score). This is what
    lets the dataset — and therefore every downstream score and the
    evaluation — include newly disclosed CVEs without re-running the full
    historical bootstrap.
    """
    existing, out_file = _load_existing_nvd()
    print(f"[fetch] latest {days} days of NVD CVEs (existing dataset: {len(existing)} records) ...")

    now = datetime.utcnow()
    new_vulns = _fetch_backward(now - timedelta(days=days), now, max_records, chunk_days)
    _merge_and_save(existing, out_file, new_vulns)


def _merge_and_save(existing: dict, out_file: Path, new_vulns: list):
    added, updated = 0, 0
    for v in new_vulns:
        cve_id = v.get("cve", {}).get("id")
        if not cve_id:
            continue
        if cve_id in existing:
            updated += 1
        else:
            added += 1
        existing[cve_id] = v

    out_file.write_text(
        json.dumps({"vulnerabilities": list(existing.values())}), encoding="utf-8"
    )
    print(f"[ok] merged: +{added} new, {updated} refreshed, {len(existing)} total -> {out_file}")


def fetch_year(year: int, cap: int = None):
    """Fill a gap for a specific calendar year (e.g. a year skipped by both
    the historical bootstrap's YEARS list and a --latest window) and merge
    it into the existing dataset, deduplicating by CVE ID. Use this when
    `docs/research_results.md` §1a shows a year with zero/low coverage that
    you need for completeness.

    Walks backward from Dec 31 of that year (via _fetch_backward), so a
    capped fetch covers the END of the year first — the part most likely
    to be "recent" relative to the rest of the dataset — rather than
    silently only covering January like a naive forward fetch would.
    """
    existing, out_file = _load_existing_nvd()
    print(f"[fetch] year {year} (cap={cap}) (existing dataset: {len(existing)} records) ...")
    year_end = min(datetime(year, 12, 31), datetime.utcnow())
    new_vulns = _fetch_backward(datetime(year, 1, 1), year_end, max_records=cap)
    _merge_and_save(existing, out_file, new_vulns)


def fetch_epss(force=False):
    out_file = RAW_DIR / "epss_scores.csv"
    if out_file.exists() and not force:
        print(f"[skip] {out_file} already exists")
        return
    print("[fetch] EPSS current snapshot ...")
    resp = requests.get(EPSS_URL, timeout=60)
    resp.raise_for_status()
    raw = gzip.decompress(resp.content).decode("utf-8")
    # First line is a comment (#model_version,score_date); real header is line 2
    lines = raw.splitlines()
    out_file.write_text("\n".join(lines[1:]), encoding="utf-8")
    print(f"[ok] saved EPSS snapshot -> {out_file}")


def fetch_kev(force=False):
    out_file = RAW_DIR / "cisa_kev.json"
    if out_file.exists() and not force:
        print(f"[skip] {out_file} already exists")
        return
    print("[fetch] CISA KEV catalog ...")
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    out_file.write_bytes(resp.content)
    print(f"[ok] saved CISA KEV catalog -> {out_file}")


def fetch_attack_map():
    out_file = RAW_DIR / "attack_to_cve.csv"
    if out_file.exists():
        print(f"[skip] {out_file} already exists")
        return
    print("[fetch] MITRE ATT&CK -> CVE mapping ...")
    resp = requests.get(ATTACK_MAP_URL, timeout=30)
    resp.raise_for_status()
    out_file.write_bytes(resp.content)
    print(f"[ok] saved ATT&CK mapping -> {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--latest", type=int, metavar="DAYS", default=None,
                        help="Rolling update: fetch CVEs published in the last DAYS days "
                             "and merge into the existing dataset, instead of the one-time "
                             "historical bootstrap.")
    parser.add_argument("--max-records", type=int, default=6000,
                        help="Cap on records fetched by --latest (default: 6000).")
    parser.add_argument("--fill-year", type=int, metavar="YYYY", default=None,
                        help="Fill a coverage gap for one specific calendar year "
                             "(e.g. --fill-year 2025) and merge into the existing "
                             "dataset, instead of the historical bootstrap or --latest.")
    parser.add_argument("--year-cap", type=int, default=None,
                        help="Cap on records fetched by --fill-year (default: no cap, "
                             "i.e. the full year — can be large for 2025/2026).")
    args = parser.parse_args()

    if args.fill_year is not None:
        fetch_year(args.fill_year, cap=args.year_cap)
        fetch_epss(force=True)
        fetch_kev(force=True)
    elif args.latest is not None:
        fetch_latest(days=args.latest, max_records=args.max_records)
        fetch_epss(force=True)  # EPSS/KEV change often; always refresh on a latest-update run
        fetch_kev(force=True)
    else:
        fetch_nvd()
        fetch_epss()
        fetch_kev()
        fetch_attack_map()
        print("\nAll raw data fetched into data/raw/")
