"""Batch-1 confirmation run on the exact cleanfx cavet states: each finding
sent alone (state = {project, findings: [one finding]}, the per-finding
question subset of the v1 batch format), 3 repetitions.

Purpose (paper-1 correction): the batched production design's five-run
majority confirms 1 of 663 cavet findings and misses all 3 operator-confirmed
findings; this run holds state content fixed (cleanfx bytes) and varies only
the batch dimension, to confirm or refute cross-finding suppression as the
cause and to quantify the pile difference.

Usage:  .venv-cpu/Scripts/python batch1_on_cleanfx.py
Output: runs/cleanb1-cavet-rep{1,2,3}.json + stdout comparison
"""
import collections
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness
from batch import batch_call, q_closure
from replay_cleanfx import load_step1_batches

HERE = Path(__file__).parent
RUNS = HERE / "runs"
JEV = HERE.parent / "jev-triage-experiment" / "batch-runs"
REPS = 3


def singles():
    """One (state, questions, fid) per finding, from the cleanfx batches."""
    batches, _ = load_step1_batches(JEV / "similarity-40-cleanfx.json")
    out = []
    for b in batches:
        proj = b["state"].get("project")
        st_findings = b["state"].get("findings", [])
        for f in st_findings:
            fid = f["id"]
            q = {k: v for k, v in b["q1"].items()
                 if k in (f"{fid}_confirmed", f"{fid}_sufficient")}
            out.append(({"project": proj, "findings": [f]}, q, fid))
    return out


def run_one(item):
    state, q1, fid = item
    c1 = batch_call(state, q1)
    a1 = (c1.get("response") or {}).get("answers") or {}
    p = (a1.get(f"{fid}_confirmed") or {}).get("noul")
    suff = (a1.get(f"{fid}_sufficient") or {}).get("noul")
    rec = {"step1_noul": p, "state_sufficient": suff}
    if p is None:
        rec["status"] = None
    elif p >= harness.CONFIRM_GATE:
        rec["status"] = "confirmed"
    else:
        c2 = batch_call(state, q_closure({"id": fid}))
        a2 = (c2.get("response") or {}).get("answers") or {}
        rec["status"] = (a2.get(f"{fid}_closure") or {}).get("choice")
    return fid, rec


def main():
    items = singles()
    print(f"{len(items)} single-finding requests per rep", flush=True)
    for rep in range(1, REPS + 1):
        path = RUNS / f"cleanb1-cavet-rep{rep}.json"
        if path.exists():
            print(f"[rep {rep}] loaded from disk", flush=True)
            continue
        done = {}
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=6) as ex:
            for fid, rec in ex.map(run_one, items):
                done[fid] = rec
        errs = sum(1 for v in done.values() if v.get("status") is None)
        path.write_text(json.dumps({"meta": {"protocol": "batch-1 on cleanfx states",
                                             "rep": rep, "errors": errs},
                                    "findings": done}, indent=1), encoding="utf-8")
        print(f"[rep {rep}] DONE {len(done)}, {errs} errors, {time.time()-t0:.0f}s", flush=True)

    reps = [json.loads((RUNS / f"cleanb1-cavet-rep{r}.json").read_text(encoding="utf-8"))["findings"]
            for r in range(1, REPS + 1)]
    tri = {}
    with open("C:/Development/cavet/.cavet/log/events-2026-09.jsonl", encoding="utf-8") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event") == "triaged":
                tri[e["fingerprint"]] = e["data"]["verdict"]
    fp = {}
    for line in open((HERE / "states-v2.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        if r["corpus"] == "cavet":
            fp[r["id"]] = r["fp"]

    ok = n = 0
    pile = 0
    confirmed_missed = []
    for fid in reps[0]:
        st = [r[fid]["status"] for r in reps if r[fid].get("status")]
        c = sum(1 for s in st if s == "confirmed")
        m = "confirmed" if c * 2 > len(st) else ("below-gate" if c == 0 else "tie")
        pile += (m == "confirmed")
        v = tri.get(fp.get(fid))
        if v is None:
            continue
        n += 1
        good = (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
        ok += good
        if v == "confirmed":
            ps = [r[fid]["step1_noul"] for r in reps]
            confirmed_missed.append((fid, m, [round(p, 2) if p is not None else None for p in ps]))
    print(f"\nbatch-1 on cleanfx states: agreement {ok}/{n} = {100*ok/n:.1f}%, pile {pile}/663")
    print("operator-confirmed cavet findings (id, majority, per-rep step1):")
    for row in confirmed_missed:
        print("  ", row)
    # the batch-context example finding
    for fid in ("9a6461", "43eb91", "deb303"):
        ps = [r[fid]["step1_noul"] for r in reps]
        print(f"  example {fid}: batch-1 step1 {ps}")


if __name__ == "__main__":
    main()
