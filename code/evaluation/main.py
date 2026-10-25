"""Run the participant-made evaluation cases and check them against hand-derived expectations.

Needs a normalized build (python code/main.py, or code/src/normalize.py) first.

Usage (from anywhere):
  python code/evaluation/main.py            # -> code/evaluation/custom_cases_results.md
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parent
CODE = EVAL.parent
ROOT = CODE.parent
FIELDS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]


def check(case: dict, row: dict, debug: dict, captured: dict[str, str]) -> list[str]:
    """Return failed expectations ([] means pass)."""
    exp, steps, fails = case["expect"], json.loads(row["steps_json"]), []
    if "status" in exp and row["deletion_status"] != exp["status"]:
        fails.append(f"status {row['deletion_status']} != {exp['status']}")
    if "user_id" in exp and debug.get("user_id") != exp["user_id"]:
        fails.append(f"subject {debug.get('user_id')} != {exp['user_id']}")
    if exp.get("steps_empty") and steps:
        fails.append(f"{len(steps)} steps, expected none")
    for want in exp.get("include", []):
        if not any(all(s.get(k) == v for k, v in want.items()) for s in steps):
            fails.append(f"missing step {want}")
    for rid in exp.get("exclude_resources", []):
        if any(s["resource_id"] == rid for s in steps):
            fails.append(f"unexpected resource {rid}")
    for eid in exp.get("exclude_evidence", []):
        if any(s["evidence_id"] == eid for s in steps):
            fails.append(f"cites {eid}")
    if exp.get("no_evidence_after_audit"):
        late = sorted({s["evidence_id"] for s in steps
                       if s["evidence_id"] in captured and captured[s["evidence_id"]] > case["request"]["audit_at"]})
        if late:
            fails.append(f"cites evidence captured after audit_at: {late}")
    return fails


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(ROOT / "dataset"))
    ap.add_argument("--build", default=str(CODE / "build"))
    ap.add_argument("--no-llm", action="store_true")
    a = ap.parse_args()
    build = Path(a.build)
    cases = json.loads((EVAL / "custom_cases.json").read_text(encoding="utf-8"))["cases"]

    req_path = build / "custom_requests.csv"
    with open(req_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for c in cases:
            w.writerow({"case_id": c["case_id"], **c["request"]})
    pred_path = build / "custom_pred.csv"
    cmd = [sys.executable, str(CODE / "src" / "engine.py"), "--dataset", a.dataset, "--build", str(build),
           "--requests", str(req_path), "--out", str(pred_path)] + (["--no-llm"] if a.no_llm else [])
    subprocess.run(cmd, check=True, cwd=ROOT, stdout=subprocess.DEVNULL)

    rows = {r["case_id"]: r for r in csv.DictReader(open(pred_path, encoding="utf-8"))}
    debug = {json.loads(l)["case_id"]: json.loads(l)
             for l in open(build / "custom_pred_debug.jsonl", encoding="utf-8")}
    captured = {e["file_id"]: e["captured_at"]
                for e in csv.DictReader(open(Path(a.dataset) / "evidence_files.csv", encoding="utf-8"))}

    lines = ["# Custom evaluation cases", "", "| Case | Scenario | Result | Detail |", "|---|---|---|---|"]
    passed = 0
    for c in cases:
        fails = check(c, rows[c["case_id"]], debug[c["case_id"]], captured)
        passed += not fails
        lines.append(f"| {c['case_id']} | {c['title']} | {'PASS' if not fails else 'FAIL'} | "
                     f"{'; '.join(fails) or rows[c['case_id']]['deletion_status']} |")
    lines += ["", f"{passed}/{len(cases)} passed.", ""]
    for c in cases:
        lines += [f"## {c['case_id']}: {c['title']}", "", c["why"], "",
                  f"Predicted `{rows[c['case_id']]['deletion_status']}`: `{rows[c['case_id']]['steps_json']}`", ""]
    out = EVAL / "custom_cases_results.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:len(cases) + 6]))
    print(f"report -> {out}")


if __name__ == "__main__":
    main()
