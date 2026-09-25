"""Seven-repetition (clean4..clean10) consistency + majority-vote recall analysis.

Reads the batch-run JSON docs produced by batch.py / s0b.py for the reps
clean4..clean10 and the read-only benchmark ground truth. Writes
consistency7-report.json next to this script. Read-only over all inputs
except its own report file.

Metrics per project (cavet, fragmt, corpus-2..corpus-5):
  - unanimous-status rate over findings with a non-None status in all 7 reps
  - mean pairwise status agreement (21 rep pairs)
  - mean per-finding population standard deviation of step1_noul
  - per-rep totals (findings, calls, wall_s, input+output tokens)

Majority-vote recall (corpus-2..corpus-5 only): ground-truth confirmed ids
joined against the run outputs; majority status across the 7 reps; ties
reported separately; recall computed both over ids with a computable
majority and over all joined ids.
"""

import json
import statistics
from itertools import combinations
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
BATCH_RUNS = EXPERIMENT / "batch-runs"
S0B_RUNS = HERE / "runs"
GROUND_TRUTH = Path("C:/Development/cavet-docs-export/benchmark/ground-truth")
OUT_PATH = HERE / "consistency7-report.json"

REPS = ["clean4", "clean5", "clean6", "clean7", "clean8", "clean9", "clean10"]

PROJECTS = {
    "cavet": str(BATCH_RUNS / "similarity-40-{rep}.json"),
    "fragmt": str(BATCH_RUNS / "similarity-40-fragmt-svcx-{rep}.json"),
    "corpus-2": str(S0B_RUNS / "similarity-40-corpus-2-svcx-{rep}.json"),
    "corpus-3": str(S0B_RUNS / "similarity-40-corpus-3-svcx-{rep}.json"),
    "corpus-4": str(S0B_RUNS / "similarity-40-corpus-4-svcx-{rep}.json"),
    "corpus-5": str(S0B_RUNS / "similarity-40-corpus-5-svcx-{rep}.json"),
}

STATUS = "confirmed"  # positive label for recall


def load_run(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def analyze_project(paths):
    docs = {rep: load_run(paths[rep]) for rep in REPS}
    findings = {rep: doc["findings"] for rep, doc in docs.items()}

    universes = {rep: len(fs) for rep, fs in findings.items()}
    universe = universes[REPS[0]]

    ids_in_all7 = set(findings[REPS[0]])
    for rep in REPS[1:]:
        ids_in_all7 &= set(findings[rep])

    def status_of(rep, fid):
        return findings[rep].get(fid, {}).get("status")

    def noul_of(rep, fid):
        return findings[rep].get(fid, {}).get("step1_noul")

    ids_statused_all7 = [
        fid for fid in ids_in_all7
        if all(status_of(rep, fid) is not None for rep in REPS)
    ]

    unanimous = sum(
        1 for fid in ids_statused_all7
        if len({status_of(rep, fid) for rep in REPS}) == 1
    )

    pairwise = []
    for rep_a, rep_b in combinations(REPS, 2):
        shared = [
            fid for fid in ids_in_all7
            if status_of(rep_a, fid) is not None and status_of(rep_b, fid) is not None
        ]
        if shared:
            agree = sum(
                1 for fid in shared if status_of(rep_a, fid) == status_of(rep_b, fid)
            )
            pairwise.append(agree / len(shared))

    stdevs = []
    for fid in ids_in_all7:
        vals = [noul_of(rep, fid) for rep in REPS]
        vals = [v for v in vals if v is not None]
        if len(vals) >= 2:
            stdevs.append(statistics.pstdev(vals))

    per_rep = {}
    for rep in REPS:
        totals = docs[rep]["totals"]
        fs = findings[rep]
        per_rep[rep] = {
            "findings": len(fs),
            "calls": totals["calls"],
            "wall_s": totals["wall_s"],
            "input_tokens": totals["input_tokens"],
            "output_tokens": totals["output_tokens"],
            "errors": totals["errors"],
            "status_none_count": sum(
                1 for v in fs.values() if v.get("status") is None
            ),
            "none_status_batches": sorted(
                {
                    v.get("batch")
                    for v in fs.values()
                    if v.get("status") is None and v.get("batch") is not None
                }
            ),
        }

    return {
        "universe": universe,
        "universes_per_rep": universes,
        "ids_in_all7": len(ids_in_all7),
        "ids_statused_in_all7": len(ids_statused_all7),
        "unanimous_status_rate": unanimous / len(ids_statused_all7) if ids_statused_all7 else None,
        "mean_pairwise_agreement": sum(pairwise) / len(pairwise) if pairwise else None,
        "mean_step1_noul_stdev": sum(stdevs) / len(stdevs) if stdevs else None,
        "findings_with_stdev": len(stdevs),
        "per_rep": per_rep,
    }


def analyze_recall(project, template):
    gt_path = GROUND_TRUTH / f"{project}.json"
    with open(gt_path, encoding="utf-8") as fh:
        gt = json.load(fh)
    gt_ids = [entry["id"] for entry in gt["confirmed_findings"]]

    docs = {
        rep: load_run(template.format(rep=rep))["findings"] for rep in REPS
    }

    joined, not_joined = [], []
    records = {}
    for fid in gt_ids:
        statuses = [docs[rep].get(fid, {}).get("status") for rep in REPS]
        present = [s for s in statuses if s is not None]
        if all(s is None for s in statuses) and fid not in set().union(
            *(set(docs[rep]) for rep in REPS)
        ):
            not_joined.append(fid)
            continue
        joined.append(fid)
        counts = {}
        for s in present:
            counts[s] = counts.get(s, 0) + 1
        top = max(counts.values()) if counts else 0
        leaders = [s for s, c in counts.items() if c == top] if counts else []
        records[fid] = {
            "statuses": statuses,
            "confirmed_k": counts.get(STATUS, 0),
            "has_status": bool(counts),
            "tie": len(leaders) > 1,
            "majority": leaders[0] if len(leaders) == 1 else None,
        }

    statused = [r for r in records.values() if r["has_status"]]
    ties = [r for r in statused if r["tie"]]
    decided = [r for r in statused if not r["tie"]]
    confirmed_majority = sum(1 for r in decided if r["majority"] == STATUS)

    histogram = {k: 0 for k in range(8)}
    for r in statused:
        histogram[r["confirmed_k"]] += 1

    return {
        "ground_truth_confirmed_ids": len(gt_ids),
        "joined_ids": len(joined),
        "not_joined_ids": len(not_joined),
        "ids_with_status": len(statused),
        "ties": len(ties),
        "recall_over_decided": confirmed_majority / len(decided) if decided else None,
        "recall_over_joined": confirmed_majority / len(joined) if joined else None,
        "majority_confirmed_count": confirmed_majority,
        "confirmed_in_k_of_7_histogram_over_statused": histogram,
        "joined_ids_without_any_status": sum(1 for r in records.values() if not r["has_status"]),
    }


def main():
    report = {
        "reps": REPS,
        "stddev_method": "population (pstdev) over reps with non-None step1_noul, findings with >=2 values",
        "pairwise_basis": "ids with non-None status in both reps of the pair",
        "unanimous_basis": "ids with non-None status in all 7 reps",
        "projects": {},
        "majority_vote_recall": {},
    }

    for project, template in PROJECTS.items():
        paths = {rep: Path(template.format(rep=rep)) for rep in REPS}
        missing = [str(p) for p in paths.values() if not p.exists()]
        if missing:
            report["projects"][project] = {"missing_files": missing}
            continue
        report["projects"][project] = analyze_project(paths)
        if project.startswith("corpus-") and project != "corpus-1":
            report["majority_vote_recall"][project] = analyze_recall(project, template)

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
