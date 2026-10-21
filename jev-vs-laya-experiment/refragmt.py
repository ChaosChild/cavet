"""Re-measure the fragmt universe on the fixed (verdict-line-stripped) states
for the Jev arms, after the contamination finding: every v2 fragmt state
carried the operator's verdict text inherited from the v1 fragmt payload.

Runs the standard cascade (3 reps, batch-1) over states-fragmt-fixed.jsonl
for jev-1.13.0 and jev-1.14.0, writing fragment files that the merge step
substitutes for the fragmt:* keys in the main run files.

Usage:  .venv-cpu/Scripts/python refragment_jev.py <1.13|1.14>
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness

HERE = Path(__file__).parent
RUNS = HERE / "runs"
WORKERS = 6
REPS = 3

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
    return key_of(rec), out


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else "1.13"
    model = "jev-1.13.0" if version == "1.13" else "jev-1.14.0"
    harness.MODEL = model
    tag = f"fragmtfix-jev{version.replace('.',')')}"
    states = [json.loads(line) for line in
              (HERE / "states-fragmt-fixed.jsonl").read_text(encoding="utf-8").splitlines()]
    print(f"[{model}] {len(states)} fixed fragmt states, {REPS} reps", flush=True)
    for rep in range(1, REPS + 1):
        path = RUNS / f"fragmtfix-jev{version}-rep{rep}.json"
        done = {}
        if path.exists():
            done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        todo = [r for r in states if key_of(r) not in done]
        if not todo:
            continue
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for fid, out in ex.map(run_finding, todo):
                done[fid] = out
        errors = sum(1 for v in done.values() if v.get("error"))
        path.write_text(json.dumps({"meta": {"model": model, "rep": rep,
                                             "states": "states-fragmt-fixed.jsonl",
                                             "errors": errors},
                                    "findings": done}, indent=1), encoding="utf-8")
        print(f"[{model} rep {rep}] DONE {len(done)}, {errors} errors, {time.time()-t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
