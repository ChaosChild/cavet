"""Paper-1 correction: replay the clean rerun's exact request payloads four
more times to produce the five clean repetitions the paper describes.

Source of truth: similarity-40-cleanfx.json (cavet) and
similarity-40-fragmt-svcx-cleanfx.json (fragmt), the single clean reruns
committed with the v1 audit. Step-1 call payloads (state + questions) are
replayed verbatim; step-2 closure requests are rebuilt per repetition with
the v1 question format, because their question sets depend on that
repetition's below-gate findings. Rep 1 = the original cleanfx responses.

Usage:  .venv-cpu/Scripts/python replay_cleanfx.py
Output: runs/clean5-{cavet,fragmt}-rep{1..5}.json (rep 1 from cleanfx) +
        stdout five-rep majority, agreement, consistency.
"""
import collections
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness
from batch import batch_call, q_closure

HERE = Path(__file__).parent
RUNS = HERE / "runs"
JEV = HERE.parent / "jev-triage-experiment" / "batch-runs"
REPS = 5

SOURCES = {
    "cavet": JEV / "similarity-40-cleanfx.json",
    "fragmt": JEV / "similarity-40-fragmt-svcx-cleanfx.json",
}


def load_step1_batches(path):
    """Unique step-1 calls (state + confirm/sufficiency questions) in order."""
    d = json.loads(path.read_text(encoding="utf-8"))
    batches = []
    seen = set()
    for c in d["calls"]:
        q = (c.get("request") or {}).get("questions") or {}
        if not any(k.endswith("_confirmed") for k in q):
            continue
        st = (c["request"]).get("state") or {}
        key = json.dumps(st, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        fids = [k[:-len("_confirmed")] for k in q if k.endswith("_confirmed")]
        batches.append({"state": st, "q1": q, "fids": fids})
    return batches, d


def score_rep1(d):
    """Per-finding step-1 + status from the original cleanfx responses."""
    per = {}
    closure = {}
    for c in d["calls"]:
        q = (c.get("request") or {}).get("questions") or {}
        a = (c.get("response") or {}).get("answers") or {}
        if any(k.endswith("_confirmed") for k in q):
            for k in q:
                if k.endswith("_confirmed"):
                    fid = k[:-len("_confirmed")]
                    per[fid] = {"step1_noul": (a.get(k) or {}).get("noul"),
                                "state_sufficient": (a.get(f"{fid}_sufficient") or {}).get("noul")}
        elif any(k.endswith("_closure") for k in q):
            for k in q:
                if k.endswith("_closure"):
                    closure[k[:-len("_closure")]] = (a.get(k) or {}).get("choice")
    for fid, cl in closure.items():
        if fid in per:
            per[fid]["status"] = cl
    for fid, v in per.items():
        p = v.get("step1_noul")
        if "status" not in v:
            v["status"] = "confirmed" if (p is not None and p >= 0.5) else None
    return per


def run_batch(batch):
    st = batch["state"]
    c1 = batch_call(st, batch["q1"])
    a1 = (c1.get("response") or {}).get("answers") or {}
    per = {}
    below = []
    for fid in batch["fids"]:
        p = (a1.get(f"{fid}_confirmed") or {}).get("noul")
        per[fid] = {"step1_noul": p,
                    "state_sufficient": (a1.get(f"{fid}_sufficient") or {}).get("noul")}
        if p is None:
            per[fid]["status"] = None
        elif p >= harness.CONFIRM_GATE:
            per[fid]["status"] = "confirmed"
        else:
            below.append(fid)
    if below:
        s2q = {}
        for fid in below:
            s2q.update(q_closure({"id": fid}))
        c2 = batch_call(st, s2q)
        a2 = (c2.get("response") or {}).get("answers") or {}
        for fid in below:
            per[fid]["status"] = (a2.get(f"{fid}_closure") or {}).get("choice")
    return per


def main():
    report = {}
    for uni, path in SOURCES.items():
        batches, doc = load_step1_batches(path)
        n_findings = sum(len(b["fids"]) for b in batches)
        print(f"[{uni}] {n_findings} findings in {len(batches)} step-1 batches", flush=True)
        reps = {1: score_rep1(doc)}
        missing1 = sum(1 for v in reps[1].values() if v["status"] is None)
        print(f"[{uni}] rep1 (cleanfx original): {len(reps[1])} findings, {missing1} unscored", flush=True)
        for rep in range(2, REPS + 1):
            out_path = RUNS / f"clean5-{uni}-rep{rep}.json"
            if out_path.exists():
                reps[rep] = json.loads(out_path.read_text(encoding="utf-8"))["findings"]
                print(f"[{uni}] rep{rep}: loaded from disk", flush=True)
                continue
            t0 = time.time()
            per = {}
            with ThreadPoolExecutor(max_workers=6) as ex:
                for batch_per in ex.map(run_batch, batches):
                    per.update(batch_per)
            errs = sum(1 for v in per.values() if v["status"] is None)
            out_path.write_text(json.dumps({"meta": {"universe": uni, "rep": rep,
                                                     "source": "cleanfx payload replay",
                                                     "errors": errs},
                                            "findings": per}, indent=1), encoding="utf-8")
            reps[rep] = per
            print(f"[{uni}] rep{rep}: {len(per)} findings, {errs} errors, {time.time()-t0:.0f}s", flush=True)

        # five-rep majority + consistency
        fids = sorted(reps[1])
        n_rep = len(reps)
        maj = {}
        unam = 0
        sds = []
        for fid in fids:
            st = [reps[r][fid]["status"] for r in reps if reps[r][fid].get("status")]
            c = sum(1 for s in st if s == "confirmed")
            maj[fid] = "confirmed" if c * 2 > len(st) else ("below-gate" if c == 0 else "tie")
            if len(set(st)) == 1:
                unam += 1
            p = [reps[r][fid]["step1_noul"] for r in reps
                 if reps[r][fid].get("step1_noul") is not None]
            if len(p) >= 2:
                mu = sum(p) / len(p)
                sds.append((sum((x - mu) ** 2 for x in p) / len(p)) ** 0.5)
        pile = sum(1 for f in maj if maj[f] == "confirmed")
        res = {"n": len(fids), "reps": n_rep, "pile": pile,
               "unanimous_pct": round(100 * unam / len(fids), 2),
               "mean_sd": round(sum(sds) / len(sds), 4),
               "max_sd": round(max(sds), 4)}
        report[uni] = res
        print(f"[{uni}] 5-rep: pile {pile}/{len(fids)}, unanimous {res['unanimous_pct']}%, "
              f"step1 SD mean {res['mean_sd']} max {res['max_sd']}", flush=True)
        (RUNS / f"clean5-{uni}-majority.json").write_text(
            json.dumps({"summary": res, "majority": maj}, indent=1), encoding="utf-8")

    (RUNS / "clean5-summary.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
