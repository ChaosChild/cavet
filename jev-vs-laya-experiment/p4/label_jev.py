"""P4: teacher labeling — triage the vite findings with Jev (shipped production
configuration), recording every request/response pair as the training signal.

Same two-step cascade as run_sweep_jev.py: q_confirm + q_missing at mv
verbosity, gate 0.5, q_closure with r3 wording below the gate, severity-blind
instruction for lockfile findings. One repetition: the Jev study measured
3-rep step-1 SD at 0.001-0.013, so a single teacher pass carries the same
signal the recipe's single-shot teacher annotations do, at half the cost.

Usage:  .venv-cpu/Scripts/python p4/label_jev.py [--limit N]
Output: p4/runs/jev-labels.json (resumable; rerun continues where it stopped)
"""
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import harness  # noqa: E402

RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
WORKERS = 6
OUT = RUNS / "jev-labels.json"

SV_INSTRUCTION = (" Severity labels are not grounds for dismissal for manifest "
                  "findings: the affected version is pinned in this project's "
                  "dependency manifest, which the state establishes directly.")
s2q = harness.q_closure("mv", harness.WORDINGS["r3"])


def s1q_for(rec):
    q = harness.q_confirm("mv")
    q.update(harness.q_missing("mv"))
    if rec.get("lockfile"):
        q["is_confirmed"]["instructions"] += SV_INSTRUCTION
    return q


def key_of(rec):
    return f'{rec["corpus"]}:{rec["id"]}'


def run_finding(rec):
    st = rec["state"]
    t0 = time.perf_counter()
    c1 = harness.call_jev(st, s1q_for(rec))
    a1 = (c1.get("response") or {}).get("answers") or {}
    p_yes = (a1.get("is_confirmed") or {}).get("noul")
    out = {"corpus": rec["corpus"], "id": rec["id"], "fp": rec["fp"],
           "lockfile": rec.get("lockfile", False),
           "calls": [c1], "wall_ms": round((time.perf_counter() - t0) * 1000, 1)}
    if p_yes is None:
        out["error"] = (c1.get("error") or "no answer")[:200]
        return key_of(rec), out
    out["step1_noul"] = p_yes
    out["state_sufficient"] = (a1.get("state_sufficient") or {}).get("noul")
    if p_yes >= harness.CONFIRM_GATE:
        out["status"] = "confirmed"
        out["step2_ran"] = False
    else:
        c2 = harness.call_jev(st, s2q)
        out["calls"].append(c2)
        a2 = (c2.get("response") or {}).get("answers") or {}
        cl = a2.get("closure") or {}
        out["status"] = cl.get("choice")
        out["step2_ran"] = True
        out["closure_confidence"] = cl.get("confidence")
        out["closure_probabilities"] = cl.get("probabilities")
        out["wall_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if cl.get("choice") is None:
            out["error"] = (c2.get("error") or "no closure answer")[:200]
    return key_of(rec), out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="cap the universe (smoke tests)")
    args = ap.parse_args()

    states = [json.loads(line) for line in
              (HERE / "states-p4.jsonl").read_text(encoding="utf-8").splitlines()]
    if args.limit:
        states = states[: args.limit]
    meta = {"role": "teacher-labels", "model": harness.MODEL,
            "config": "batch-1, 6 workers, 1 rep", "gate": harness.CONFIRM_GATE,
            "wording": "r3", "verbosity": "mv", "states": len(states)}
    done = {}
    if OUT.exists():
        done = json.loads(OUT.read_text(encoding="utf-8")).get("findings", {})
    todo = [r for r in states if key_of(r) not in done]
    print(f"{len(done)} labeled, {len(todo)} to run", flush=True)
    if not todo:
        return
    n = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for fid, out in ex.map(run_finding, todo):
            done[fid] = out
            n += 1
            if n % 50 == 0:
                print(f"{n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
                OUT.write_text(json.dumps({"meta": meta, "findings": done}, indent=1),
                               encoding="utf-8")
    errors = sum(1 for v in done.values() if v.get("error"))
    OUT.write_text(json.dumps({"meta": {**meta, "errors": errors},
                               "findings": done}, indent=1), encoding="utf-8")
    import collections
    statuses = collections.Counter(v.get("status") for v in done.values() if not v.get("error"))
    print(f"DONE {len(done)} labeled, {errors} errors, {time.time() - t0:.0f}s")
    print("status mix:", dict(statuses))


if __name__ == "__main__":
    main()
