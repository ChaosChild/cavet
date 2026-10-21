"""A/A rerun control on leak-free cavet states (paper 1's Section 3.3
statistic, re-measured).

Sources: the five clean repetitions = batch-runs/similarity-40-cleanfx.json
(rep 1, the leak-free rerun) plus runs/clean5-cavet-rep2..5.json (byte-
identical payload replays). Definitions follow the paper: status per finding
from the run record; a decision flip means the confirmed/not-confirmed
outcome differs between two runs; closure-only flips (dismissed versus
not-security among below-gate findings) are reported separately, as is the
any-status rate that the published triple actually matches.

Usage:  .venv-cpu/Scripts/python aa_clean_control.py
Output: analysis/aa-clean-control.json + stdout.
"""
import itertools
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
JEV = HERE.parent / "jev-triage-experiment"
sys.path.insert(0, str(JEV))
from replay_cleanfx import score_rep1  # noqa: E402  (statuses from cleanfx responses)

REPS = ["cleanfx(r1)"] + [f"replay{r}" for r in range(2, 6)]


def load_five():
    d = json.loads((JEV / "batch-runs" / "similarity-40-cleanfx.json").read_text(encoding="utf-8"))
    reps = [score_rep1(d)]
    for r in range(2, 6):
        reps.append(json.loads((HERE / "runs" / f"clean5-cavet-rep{r}.json").read_text(encoding="utf-8"))["findings"])
    return reps


def main():
    reps = load_five()
    n = len(reps[0])
    rows = []
    for i, j in itertools.combinations(range(5), 2):
        ra, rb = reps[i], reps[j]
        ids = [k for k in ra if k in rb and ra[k].get("status") and rb[k].get("status")]
        dec = sum(1 for k in ids if (ra[k]["status"] == "confirmed") != (rb[k]["status"] == "confirmed"))
        stat = sum(1 for k in ids if ra[k]["status"] != rb[k]["status"])
        rows.append({"pair": f"{REPS[i]}-{REPS[j]}", "n": len(ids),
                     "decision_flips": dec, "decision_pct": round(100 * dec / len(ids), 2),
                     "closure_only_flips": stat - dec,
                     "any_status_flips": stat, "any_status_pct": round(100 * stat / len(ids), 2)})
        print(f"{rows[-1]['pair']}: decision {dec}/{len(ids)} = {rows[-1]['decision_pct']}%, "
              f"closure-only {stat - dec}, any-status {stat}/{len(ids)} = {rows[-1]['any_status_pct']}%")

    for key in ("decision_pct", "any_status_pct"):
        vals = [r[key] for r in rows]
        print(f"{key}: min {min(vals)} max {max(vals)} mean {sum(vals)/len(vals):.2f}")

    dec_totals = sum(r["decision_flips"] for r in rows)
    stat_totals = sum(r["any_status_flips"] for r in rows)
    total_n = sum(r["n"] for r in rows)
    out = {"meta": {"statistic": "A/A rerun control, paper 1 Section 3.3, re-measured on leak-free states",
                    "reps": REPS,
                    "sources": ["batch-runs/similarity-40-cleanfx.json (rep 1)",
                                "runs/clean5-cavet-rep2..5.json (verbatim payload replays)"],
                    "verdict_line_counts": "cleanfx 0; published family clean1-10/final1-5: 196 per file"},
           "pairs": rows,
           "summary": {"decision_pct_min": min(r["decision_pct"] for r in rows),
                       "decision_pct_max": max(r["decision_pct"] for r in rows),
                       "decision_pct_mean": round(sum(r["decision_pct"] for r in rows) / len(rows), 2),
                       "pooled_decision_pct": round(100 * dec_totals / total_n, 2),
                       "any_status_pct_min": min(r["any_status_pct"] for r in rows),
                       "any_status_pct_max": max(r["any_status_pct"] for r in rows),
                       "any_status_pct_mean": round(sum(r["any_status_pct"] for r in rows) / len(rows), 2),
                       "closure_only_total": stat_totals - dec_totals},
           "published_provenance": {"files": "clean1/clean2/clean3 (consistency.py family)",
                                    "verdict_lines_per_file": 196,
                                    "note": "published 0.75/1.06/1.21 matches the any-status "
                                            "flip rates of the three clean1-3 pairs; under the "
                                            "paper's decision-only definition those pairs give "
                                            "0.75/0.90/1.06"}}
    (HERE / "analysis" / "aa-clean-control.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print("\nwritten analysis/aa-clean-control.json")


if __name__ == "__main__":
    main()
