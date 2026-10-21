"""Controlled batch-size test: the v1 similarity-40 batch protocol versus the
batch-1 protocol of this evaluation, on the same clean v2 cavet states,
3 repetitions each (the batch-1 side is the existing jev-b1 runs).

Motivation: this evaluation's Jev 1.13 cavet actionability (89.8 percent)
differs from the v1 paper's published 93.9 (a clean single pass at batch-40),
with the two runs missing different findings. The verdict-leak repair
excluded state contamination as the cause; the remaining candidates are batch
size, state version, and sampling noise. This test holds the states fixed
(v2 cavet, clean) and varies only the protocol.

Usage:  .venv-cpu/Scripts/python batchtest.py
Output: runs/batchtest-40-rep{1,2,3}.json + stdout comparison
"""
import collections
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness
from batch import batch_call, q_confirmed, q_closure, rule_family

HERE = Path(__file__).parent
RUNS = HERE / "runs"
REPS = 3

cavet = [json.loads(line) for line in (HERE / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]
cavet = [r for r in cavet if r["corpus"] == "cavet"]
PROJECT = cavet[0]["state"]["project"]


def make_batches(states, size=40):
    key = lambda r: (r["state"]["finding"]["location"].rsplit(":", 1)[0],
                     rule_family(r["state"]["finding"]["rule_id"]))
    ordered = sorted(states, key=lambda r: (key(r), r["fp"]))
    groups = {}
    for r in ordered:
        groups.setdefault(key(r), []).append(r)
    batches = []
    for _, group in sorted(groups.items()):
        for i in range(0, len(group), size):
            batches.append(group[i:i + size])
    return batches


def process_batch(batch, bi):
    state = {"project": PROJECT,
             "findings": [r["state"]["finding"] for r in batch]}
    questions = {}
    for r in batch:
        questions.update(q_confirmed({"id": r["id"]}))
    c1 = batch_call(state, questions)
    a1 = (c1.get("response") or {}).get("answers") or {}
    per = {}
    step2 = []
    for r in batch:
        fid = r["id"]
        p1 = (a1.get(f"{fid}_confirmed") or {}).get("noul")
        suff = (a1.get(f"{fid}_sufficient") or {}).get("noul")
        per[fid] = {"step1_noul": p1, "state_sufficient": suff, "batch": bi,
                    "fp": r["fp"]}
        if p1 is None:
            per[fid]["status"] = None
            per[fid]["error"] = "missing step1 answer"
        elif p1 >= harness.CONFIRM_GATE:
            per[fid]["status"] = "confirmed"
        else:
            step2.append(r)
    if step2:
        s2q = {}
        for r in step2:
            s2q.update(q_closure({"id": r["id"]}))
        c2 = batch_call(state, s2q)
        a2 = (c2.get("response") or {}).get("answers") or {}
        for r in step2:
            fid = r["id"]
            per[fid]["status"] = (a2.get(f"{fid}_closure") or {}).get("choice")
    return per


def main():
    batches = make_batches(cavet)
    print(f"{len(cavet)} findings in {len(batches)} batches "
          f"(sizes {collections.Counter(len(b) for b in batches)})", flush=True)
    for rep in range(1, REPS + 1):
        path = RUNS / f"batchtest-40-rep{rep}.json"
        done = {}
        if path.exists():
            done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        todo = [b for b in batches
                if any(r["id"] not in done for r in b)]
        print(f"[rep {rep}] {len(done)} done, {len(todo)} batches to run", flush=True)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=6) as ex:
            for per in ex.map(lambda b: process_batch(b, b[0]["id"]), todo):
                for fid, rec in per.items():
                    done[fid] = rec
        errors = sum(1 for v in done.values() if v.get("error") or v.get("status") is None)
        path.write_text(json.dumps({"meta": {"protocol": "v1 similarity-40 batch, "
                                              "v2 cavet states, project block from v2",
                                             "rep": rep, "errors": errors},
                                    "findings": done}, indent=1), encoding="utf-8")
        print(f"[rep {rep}] DONE {len(done)}, {errors} errors, {time.time()-t0:.0f}s", flush=True)

    # majority across the 3 reps, then the comparison
    reps = [json.loads((RUNS / f"batchtest-40-rep{r}.json").read_text(encoding="utf-8"))["findings"]
            for r in range(1, REPS + 1)]
    tri = {}
    with open("C:/Development/cavet/.cavet/log/events-2026-09.jsonl", encoding="utf-8") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event") == "triaged":
                tri[e["fingerprint"]] = e["data"]["verdict"]

    def majority(fid):
        st = [r[fid]["status"] for r in reps if r[fid].get("status")]
        if not st:
            return None
        c = sum(1 for s in st if s == "confirmed")
        return "confirmed" if c * 2 > len(st) else ("below-gate" if c == 0 else "tie")

    ok = n = 0
    misses = []
    pile = 0
    for fid, rec in reps[0].items():
        m = majority(fid)
        pile += (m == "confirmed")
        v = tri.get(rec["fp"])
        if v is None:
            continue
        n += 1
        good = (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
        ok += good
        if not good:
            p = [r[fid]["step1_noul"] for r in reps]
            misses.append((fid, v, m, round(sum(p) / len(p), 3)))
    print(f"\nbatch-40 on v2 cavet: actionability {ok}/{n} = {100*ok/n:.1f}%, pile {pile}/663")
    print("misses (id, verdict, majority, mean step1):")
    for m in misses:
        print("  ", m)

    # batch-1 side for reference
    b1 = {}
    for r in (1, 2, 3):
        d = json.loads((RUNS / f"jev-b1-rep{r}.json").read_text(encoding="utf-8"))["findings"]
        for k, v in d.items():
            if k.startswith("cavet:"):
                b1.setdefault(k, []).append(v)
    ok1 = n1 = 0
    for k, recs in b1.items():
        st = [x["status"] for x in recs if x.get("status")]
        c = sum(1 for s in st if s == "confirmed")
        m = "confirmed" if c * 2 > len(st) else ("below-gate" if c == 0 else "tie")
        v = tri.get(recs[0]["fp"])
        if v is None:
            continue
        n1 += 1
        ok1 += (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
    print(f"batch-1 reference: actionability {ok1}/{n1} = {100*ok1/n1:.1f}%")


if __name__ == "__main__":
    main()
