"""Final consistency and majority-vote recall analysis over the final1..final5 sweeps.

Reads (all read-only except its own output):
  - jev-triage-experiment/batch-runs/similarity-40-final{N}.json        (cavet)
  - jev-triage-experiment/batch-runs/similarity-40-fragmt-svcx-final{N}.json (fragmt)
  - jev-triage-experiment/s0b/runs/similarity-40-corpus-{i}-svcx-final{N}.json (corpus i=2..5)
  - the local benchmark tree's ground-truth/corpus-{i}.json (READ-ONLY; passed via --gt-root)

Writes:
  - jev-triage-experiment/s0b/final-analysis.json
"""

import json
import os
from collections import Counter
from pathlib import Path
from statistics import pstdev

HERE = Path(__file__).resolve().parent
EXPER = HERE.parent
# ground-truth root is a local, machine-specific path; pass it via --gt-root
GT_ROOT = Path(os.environ.get("JEV_GT_ROOT", "ground-truth"))

REPS = [1, 2, 3, 4, 5]
CORPORA = [2, 3, 4, 5]

PROJECTS = {
    "cavet": [EXPER / "batch-runs" / f"similarity-40-final{n}.json" for n in REPS],
    "fragmt": [EXPER / "batch-runs" / f"similarity-40-fragmt-svcx-final{n}.json" for n in REPS],
}
for i in CORPORA:
    PROJECTS[f"corpus-{i}"] = [
        HERE / "runs" / f"similarity-40-corpus-{i}-svcx-final{n}.json" for n in REPS
    ]


def load_run(path):
    return json.loads(path.read_text(encoding="utf-8"))


def per_rep_totals(name, paths):
    rows = {}
    for n, p in zip(REPS, paths):
        d = load_run(p)
        t = d["totals"]
        rows[f"final{n}"] = {
            "file": p.name,
            "findings": len(d["findings"]),
            "calls": t["calls"],
            "wall_s": t["wall_s"],
            "input_tokens": t["input_tokens"],
            "output_tokens": t["output_tokens"],
            "errors": t["errors"],
            "none_status": sum(1 for v in d["findings"].values() if v.get("status") is None),
        }
    return rows


def consistency(name, paths):
    runs = [load_run(p) for p in paths]
    id_sets = [set(r["findings"]) for r in runs]
    common = set.intersection(*id_sets)
    per_rep_ids = {f"final{n}": len(s) for n, s in zip(REPS, id_sets)}

    # status inventory across all reps
    status_values = Counter()
    for r in runs:
        for v in r["findings"].values():
            status_values[v.get("status")] += 1

    unanimous = 0
    closure_only_disagree = 0
    confirmed_involved_disagree = 0
    other_disagree = 0
    stdevs = []

    for fid in common:
        stats = [r["findings"][fid].get("status") for r in runs]
        if len(set(stats)) == 1:
            unanimous += 1
        else:
            sset = set(stats)
            if "confirmed" in sset:
                confirmed_involved_disagree += 1
            elif sset <= {"dismissed", "not-security"}:
                closure_only_disagree += 1
            else:
                other_disagree += 1
        nouls = [r["findings"][fid].get("step1_noul") for r in runs]
        if all(x is not None for x in nouls):
            stdevs.append(pstdev(nouls))

    n = len(common)
    n_pairs = 0
    pair_agree_sum = 0.0
    for a in range(len(runs)):
        for b in range(a + 1, len(runs)):
            fa, fb = runs[a]["findings"], runs[b]["findings"]
            agree = sum(1 for fid in common if fa[fid].get("status") == fb[fid].get("status"))
            pair_agree_sum += agree / n
            n_pairs += 1

    return {
        "findings_in_all_5": n,
        "per_rep_finding_counts": per_rep_ids,
        "status_value_inventory": dict(status_values),
        "unanimous_status_rate": unanimous / n if n else None,
        "unanimous_count": unanimous,
        "mean_pairwise_status_agreement": pair_agree_sum / n_pairs if n_pairs else None,
        "mean_per_finding_step1_noul_pstdev": sum(stdevs) / len(stdevs) if stdevs else None,
        "nonunanimous_total": n - unanimous,
        "nonunanimous_closure_label_noise_only": closure_only_disagree,
        "nonunanimous_involving_confirmed": confirmed_involved_disagree,
        "nonunanimous_other": other_disagree,
    }


def majority_and_recall(corpus_id, paths):
    gt_path = GT_ROOT / f"corpus-{corpus_id}.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    gt_confirmed_ids = [f["id"] for f in gt["confirmed_findings"]]

    runs = [load_run(p) for p in paths]
    run_ids = set(runs[0]["findings"])
    for r in runs[1:]:
        run_ids &= set(r["findings"])

    joined = [i for i in gt_confirmed_ids if i in run_ids]
    missing_from_runs = [i for i in gt_confirmed_ids if i not in run_ids]

    majority_status = {}
    ties = []
    k_hist = Counter()
    for fid in joined:
        stats = [r["findings"][fid].get("status") for r in runs]
        c = Counter(stats)
        top, cnt = c.most_common(1)[0]
        if cnt >= 3:
            majority_status[fid] = top
        else:
            ties.append({"id": fid, "counts": dict(c)})
            majority_status[fid] = None
        k_hist[stats.count("confirmed")] += 1

    conf_majority = sum(1 for v in majority_status.values() if v == "confirmed")
    recall_majority = conf_majority / len(joined) if joined else None

    per_rep_recall = {}
    for n, r in zip(REPS, runs):
        hits = sum(1 for fid in joined if r["findings"][fid].get("status") == "confirmed")
        per_rep_recall[f"final{n}"] = hits / len(joined) if joined else None

    return {
        "ground_truth_confirmed": len(gt_confirmed_ids),
        "joined_ids": len(joined),
        "gt_ids_missing_from_runs": missing_from_runs,
        "majority_confirmed": conf_majority,
        "majority_recall": recall_majority,
        "majority_ties": ties,
        "n_majority_ties": len(ties),
        "confirmed_in_k_of_5_histogram": {str(k): k_hist.get(k, 0) for k in range(6)},
        "per_rep_recall": per_rep_recall,
    }


def main():
    out = {"reps": REPS, "projects": {}}

    # corpus-1 note (zero findings, vacuous, skipped)
    out["corpus_1"] = {
        "skipped": True,
        "reason": "zero findings in universe; all 5 reps vacuous",
    }

    # (c) per-rep totals
    totals = {}
    grand = {"findings": 0, "calls": 0, "wall_s": 0.0, "input_tokens": 0, "output_tokens": 0}
    for name, paths in PROJECTS.items():
        rows = per_rep_totals(name, paths)
        totals[name] = rows
        for r in rows.values():
            for k in grand:
                grand[k] += r[k]
    totals["grand_all_project_reps"] = dict(grand)
    totals["grand_project_reps_count"] = sum(len(v) for v in PROJECTS.values()) * 1
    totals["grand_project_reps_count"] = len(PROJECTS) * len(REPS)
    # per-rep totals summed across projects
    per_rep_sum = {}
    for n in REPS:
        s = {"findings": 0, "calls": 0, "wall_s": 0.0, "input_tokens": 0, "output_tokens": 0}
        for name in PROJECTS:
            for k in s:
                s[k] += totals[name][f"final{n}"][k]
        per_rep_sum[f"final{n}"] = s
    totals["per_rep_sum_across_projects"] = per_rep_sum
    out["totals"] = totals

    # (a) consistency
    out["consistency"] = {
        name: consistency(name, paths) for name, paths in PROJECTS.items()
    }

    # (b)+(d) majority recall + per-rep recall for corpora
    out["recall"] = {f"corpus-{i}": majority_and_recall(i, PROJECTS[f"corpus-{i}"]) for i in CORPORA}

    dest = HERE / "final-analysis.json"
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {dest}")

    # console summary
    print("\n== totals (grand across all %d project-reps) ==" % totals["grand_project_reps_count"])
    print(json.dumps(grand))
    for n in REPS:
        print(f"final{n} sum across projects:", json.dumps(per_rep_sum[f"final{n}"]))

    print("\n== consistency ==")
    for name, c in out["consistency"].items():
        print(
            name,
            "n=%d" % c["findings_in_all_5"],
            "unanimous=%.4f" % c["unanimous_status_rate"],
            "pairwise=%.4f" % c["mean_pairwise_status_agreement"],
            "mean_std_step1_noul=%.5f" % c["mean_per_finding_step1_noul_pstdev"],
            "closure_noise=%d confirmed_involved=%d other=%d"
            % (
                c["nonunanimous_closure_label_noise_only"],
                c["nonunanimous_involving_confirmed"],
                c["nonunanimous_other"],
            ),
        )

    print("\n== recall ==")
    for name, r in out["recall"].items():
        print(
            name,
            "gt=%d joined=%d" % (r["ground_truth_confirmed"], r["joined_ids"]),
            "majority_recall=%.4f" % r["majority_recall"],
            "ties=%d" % r["n_majority_ties"],
            "hist=" + json.dumps(r["confirmed_in_k_of_5_histogram"]),
        )
        print("  per-rep recall:", json.dumps(r["per_rep_recall"]))


if __name__ == "__main__":
    main()
