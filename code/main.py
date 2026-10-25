"""Ghost Data Still Exists - full pipeline.

  1. normalize  every evidence file -> code/build/observations.csv (+ links.csv)
  2. engine     deletion_requests.csv -> output.csv at the repository root
  3. samples    (optional) run the 32 public samples and score them against sample_output.csv

Screenshots and PDFs are read by a vision model when an API key is set (see
src/llm_client.py). Without one, the normalizer uses cached model answers and then
the hand-read observations in code/data/visual_observations_manual.json.

Usage (from anywhere):
  python code/main.py                 # full run -> output.csv
  python code/main.py --samples       # also score the public samples
  python code/main.py --no-llm        # rules only for request classification
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CODE = Path(__file__).resolve().parent
ROOT = CODE.parent
SRC = CODE / "src"


def run(script: str, *args: str) -> None:
    cmd = [sys.executable, str(SRC / script), *args]
    print(f"\n$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(ROOT / "dataset"))
    ap.add_argument("--build", default=str(CODE / "build"))
    ap.add_argument("--out", default=str(ROOT / "output.csv"))
    ap.add_argument("--visual-fallback", default=str(CODE / "data" / "visual_observations_manual.json"))
    ap.add_argument("--samples", action="store_true", help="also run and score the public samples")
    ap.add_argument("--no-llm", action="store_true", help="skip LLM request classification")
    ap.add_argument("--skip-normalize", action="store_true", help="reuse an existing build/observations.csv")
    a = ap.parse_args()

    run_id = datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
    build = Path(a.build)
    llm = ["--no-llm"] if a.no_llm else []
    if not a.skip_normalize:
        fallback = ["--visual-fallback", a.visual_fallback] if Path(a.visual_fallback).exists() else []
        run("normalize.py", "--dataset", a.dataset, "--out", str(build), "--run-id", run_id, *fallback)
    run("engine.py", "--dataset", a.dataset, "--build", str(build), "--out", a.out, "--run-id", run_id, *llm)
    if a.samples:
        pred = str(build / "sample_pred.csv")
        run("engine.py", "--dataset", a.dataset, "--build", str(build), "--run-id", run_id,
            "--requests", "sample_deletion_requests.csv", "--out", pred, *llm)
        run("score.py", "--pred", pred, "--gold", str(Path(a.dataset) / "sample_output.csv"),
            "--report", str(build / "sample_score.md"))
    print(f"\noutput -> {a.out}")


if __name__ == "__main__":
    main()
