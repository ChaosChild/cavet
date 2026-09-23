#!/usr/bin/env python3
"""Run-to-run consistency analysis over the three clean repetition sweeps.

For each project, loads the three rep files (clean1/clean2/clean3) and, over
the union of finding ids, computes:
  (a) unanimous-status rate  (all three reps same status)
  (b) mean pairwise status-agreement rate (3 pairs)
  (c) mean per-finding sample standard deviation of step1_noul across reps
      (findings present in all three reps only)
  (d) per-rep totals: findings, calls, wall_s, input+output tokens
Findings missing from a rep count as disagreements and are reported.

Output: consistency-report.json next to this script; summary printed.

Usage:
  python consistency.py
"""

import json
import statistics
from itertools import combinations
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPS = ["clean1", "clean2", "clean3"]
REPSWEEP = 3  # sample stddev ddof; n=3 reps

PROJECTS = {
    "cavet":    ROOT / "batch-runs" / "similarity-40-{rep}.json",
    "fragmt":   ROOT / "batch-runs" / "similarity-40-fragmt-svcx-{rep}.json",
    "corpus-2": HERE / "runs" / "similarity-40-corpus-2-svcx-{rep}.json",
    "corpus-3": HERE / "runs" / "similarity-40-corpus-3-svcx-{rep}.json",
    "corpus-4": HERE / "runs" / "similarity-40-corpus-4-svcx-{rep}.json",
    "corpus-5": HERE / "runs" / "similarity-40-corpus-5-svcx-{rep}.json",
}


def load(project, pattern):
    reps = {}
    for rep in REPS:
        path = Path(str(pattern).format(rep=rep))
        doc = json.loads(path.read_text(encoding="utf-8"))
        reps[rep] = doc
    return reps


def statuses_by_id(doc):
    return {fid: rec.get("status") for fid, rec in doc["findings"].items()}


def p1_by_id(doc):
    return {fid: rec.get("step1_noul") for fid, rec in doc["findings"].items()}


def analyze(project, reps):
    docs = load(project, reps)
    st = {rep: statuses_by_id(docs[rep]) for rep in REPS}
    p1 = {rep: p1_by_id(docs[rep]) for rep in REPS}

    universe = set()
    for rep in REPS:
        universe |= set(st[rep])
    common = set.intersection(*(set(st[rep]) for rep in REPS))
    missing = sorted(universe - common)
    per_rep_missing = {rep: sorted(universe - set(st[rep])) for rep in REPS}

    # (a) unanimous status: all three reps present and identical status.
    # A finding missing from any rep cannot be unanimous -> disagreement.
    unanimous = sum(1 for fid in universe
                    if len({st[rep].get(fid) for rep in REPS}) == 1
                    and all(fid in st[rep] for rep in REPS))
    unan_rate = unanimous / len(universe) if universe else None

    # (b) mean pairwise agreement over the union; absent-on-either-side = disagree.
    pair_rates = []
    for ra, rb in combinations(REPS, 2):
        agree = sum(1 for fid in universe
                    if fid in st[ra] and fid in st[rb]
                    and st[ra][fid] == st[rb][fid])
        pair_rates.append(agree / len(universe) if universe else None)
    mean_pair = statistics.mean(pair_rates) if universe else None

    # (c) per-finding stddev of step1_noul across reps (common ids only).
    stds = []
    for fid in common:
        vals = [p1[rep][fid] for rep in REPS]
        if all(isinstance(v, (int, float)) for v in vals):
            stds.append(statistics.stdev(vals))
    mean_std = statistics.mean(stds) if stds else None

    rep_totals = {}
    for rep in REPS:
        t = docs[rep]["totals"]
        rep_totals[rep] = {
            "findings": len(docs[rep]["findings"]),
            "calls": t["calls"],
            "wall_s": t["wall_s"],
            "input_tokens": t["input_tokens"],
            "output_tokens": t["output_tokens"],
            "tokens_total": t["input_tokens"] + t["output_tokens"],
            "errors": t.get("errors"),
        }

    return {
        "project": project,
        "universe": len(universe),
        "common_ids": len(common),
        "unanimous": unanimous,
        "unanimous_status_rate": unan_rate,
        "pairwise_agreement_rates": pair_rates,
        "mean_pairwise_agreement": mean_pair,
        "n_p1_stdev": len(stds),
        "mean_step1_noul_stdev": mean_std,
        "missing_ids_union_vs_common": missing,
        "missing_ids_per_rep": per_rep_missing,
        "rep_totals": rep_totals,
    }


def main():
    per_project = [analyze(name, pat) for name, pat in PROJECTS.items()]

    total_universe = sum(p["universe"] for p in per_project)
    total_unanimous = sum(p["unanimous"] for p in per_project)
    pooled_unan = total_unanimous / total_universe if total_universe else None
    pooled_pair = statistics.mean(
        [p["mean_pairwise_agreement"] for p in per_project
         if p["mean_pairwise_agreement"] is not None])
    pooled_std = statistics.mean(
        [p["mean_step1_noul_stdev"] for p in per_project
         if p["mean_step1_noul_stdev"] is not None])
    total_missing = sum(len(p["missing_ids_union_vs_common"])
                        for p in per_project)

    summary = {
        "reps": REPS,
        "projects": len(per_project),
        "total_findings_per_rep_pooled_universe": total_universe,
        "pooled_unanimous_status_rate": pooled_unan,
        "pooled_mean_pairwise_agreement": pooled_pair,
        "pooled_mean_step1_noul_stdev": pooled_std,
        "total_missing_findings": total_missing,
        "per_project": {
            p["project"]: {
                "universe": p["universe"],
                "unanimous_status_rate": p["unanimous_status_rate"],
                "mean_pairwise_agreement": p["mean_pairwise_agreement"],
                "mean_step1_noul_stdev": p["mean_step1_noul_stdev"],
                "missing_findings": len(p["missing_ids_union_vs_common"]),
            }
            for p in per_project
        },
        "rep_totals": {
            p["project"]: p["rep_totals"] for p in per_project
        },
    }

    report = {"summary": summary, "projects": per_project}
    out = HERE / "consistency-report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
