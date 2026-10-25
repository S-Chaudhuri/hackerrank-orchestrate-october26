"""Score a predictions CSV against a gold CSV (e.g. sample_output.csv).

Metrics (written to JSON and a Markdown report):
  status_accuracy         deletion_status exact match per case
  step precision/recall/F1 full step match (phase, system, resource, operation, state, evidence)
  field accuracy          for gold steps matched on (system_id, resource_id, operation):
                          phase / state / evidence_id correct; missing gold steps count as wrong
  identity (resource) P/R resources mentioned in steps, ignoring operations
  sequence accuracy       steps_json identical as ordered lists
  sequence similarity     1 - normalized edit distance over the ordered step keys

Usage (from the repo root):
  python code/src/score.py --pred build/sample_pred.csv --gold dataset/sample_output.csv --report build/sample_score.md
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def load(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8", newline="") as f:
        out = {}
        for r in csv.DictReader(f):
            try:
                steps = json.loads(r["steps_json"] or "[]")
            except json.JSONDecodeError:
                steps = None
            out[r["case_id"]] = {"status": r["deletion_status"], "steps": steps}
        return out


def full(s):
    return tuple(str(s.get(k, "") or "") for k in FIELDS)


def key(s):
    return (s.get("system_id", ""), s.get("resource_id", ""), s.get("operation", ""))


def edit_distance(a: list, b: list) -> int:
    prev = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x != y)))
        prev = cur
    return prev[-1]


def score(pred: dict, gold: dict) -> tuple[dict, list[dict]]:
    tot = Counter()
    per_case = []
    for cid in sorted(gold, key=lambda c: (int(re.sub(r"\D", "", c) or 0), c)):
        g = gold[cid]
        p = pred.get(cid, {"status": "MISSING", "steps": []})
        ps, gs = p["steps"] or [], g["steps"] or []
        valid = p["steps"] is not None
        tot["cases"] += 1
        tot["status_ok"] += p["status"] == g["status"]
        tot["json_valid"] += valid
        pc, gc = Counter(map(full, ps)), Counter(map(full, gs))
        tp = sum((pc & gc).values())
        tot["tp"] += tp
        tot["pred_steps"] += len(ps)
        tot["gold_steps"] += len(gs)
        pk = {key(s): s for s in ps}
        for s in gs:
            m = pk.get(key(s))
            tot["field_total"] += 1
            for f in ("phase", "state", "evidence_id"):
                tot[f"field_{f}"] += bool(m) and str(m.get(f, "") or "") == str(s.get(f, "") or "")
            tot["field_key"] += bool(m)
        pr = {(s["system_id"], s["resource_id"]) for s in ps}
        gr = {(s["system_id"], s["resource_id"]) for s in gs}
        tot["res_tp"] += len(pr & gr)
        tot["res_pred"] += len(pr)
        tot["res_gold"] += len(gr)
        exact = [full(s) for s in ps] == [full(s) for s in gs]
        tot["seq_exact"] += exact
        a, b = [key(s) for s in ps], [key(s) for s in gs]
        sim = 1 - edit_distance(a, b) / max(len(a), len(b), 1)
        tot["seq_sim_sum"] += sim
        step_nos_ok = [s.get("step_no") for s in ps] == list(range(1, len(ps) + 1))
        tot["step_no_ok"] += step_nos_ok
        per_case.append({
            "case_id": cid, "gold_status": g["status"], "pred_status": p["status"],
            "exact": exact, "seq_similarity": round(sim, 3),
            "missing": [list(x) for x in (gc - pc).elements()],
            "extra": [list(x) for x in (pc - gc).elements()],
        })
    n = max(tot["cases"], 1)
    prec = tot["tp"] / tot["pred_steps"] if tot["pred_steps"] else 1.0
    rec = tot["tp"] / tot["gold_steps"] if tot["gold_steps"] else 1.0
    rp = tot["res_tp"] / tot["res_pred"] if tot["res_pred"] else 1.0
    rr = tot["res_tp"] / tot["res_gold"] if tot["res_gold"] else 1.0
    ft = max(tot["field_total"], 1)
    metrics = {
        "cases": tot["cases"],
        "status_accuracy": round(tot["status_ok"] / n, 4),
        "json_valid": round(tot["json_valid"] / n, 4),
        "step_numbering_ok": round(tot["step_no_ok"] / n, 4),
        "step_precision": round(prec, 4), "step_recall": round(rec, 4),
        "step_f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "resource_precision": round(rp, 4), "resource_recall": round(rr, 4),
        "field_accuracy": {f: round(tot[f"field_{f}"] / ft, 4)
                           for f in ("key", "phase", "state", "evidence_id")},
        "sequence_exact": round(tot["seq_exact"] / n, 4),
        "sequence_similarity": round(tot["seq_sim_sum"] / n, 4),
        "pred_steps": tot["pred_steps"], "gold_steps": tot["gold_steps"],
    }
    return metrics, per_case


def write_report(metrics: dict, per_case: list[dict], path: Path) -> None:
    lines = ["# Score report", "", "| Metric | Value |", "|---|---|"]
    for k, v in metrics.items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                lines.append(f"| {k}.{kk} | {vv} |")
        else:
            lines.append(f"| {k} | {v} |")
    bad = [c for c in per_case if not c["exact"] or c["gold_status"] != c["pred_status"]]
    lines += ["", f"## Cases not exactly right ({len(bad)})", ""]
    for c in bad:
        lines.append(f"### {c['case_id']}: gold {c['gold_status']}, predicted {c['pred_status']}, "
                     f"sequence similarity {c['seq_similarity']}")
        for x in c["missing"]:
            lines.append(f"- missing: `{' | '.join(x)}`")
        for x in c["extra"]:
            lines.append(f"- extra: `{' | '.join(x)}`")
        if not c["missing"] and not c["extra"]:
            lines.append("- same steps, different order")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pred", required=True)
    ap.add_argument("--gold", required=True)
    ap.add_argument("--report", default="")
    a = ap.parse_args()
    metrics, per_case = score(load(Path(a.pred)), load(Path(a.gold)))
    print(json.dumps(metrics, indent=2))
    if a.report:
        rp = Path(a.report)
        write_report(metrics, per_case, rp)
        rp.with_suffix(".json").write_text(json.dumps({"metrics": metrics, "cases": per_case}, indent=2),
                                           encoding="utf-8")
        print(f"report -> {rp}")


if __name__ == "__main__":
    main()
