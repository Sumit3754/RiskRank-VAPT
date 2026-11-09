"""
Runs the full RiskRank-VAPT pipeline end to end and writes results to
results/reports/ and results/figures/. The Streamlit dashboard (app.py)
reads those outputs.

Usage:  python scripts/run_pipeline.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from evaluation import run_full_pipeline  # noqa: E402

if __name__ == "__main__":
    run_full_pipeline()
