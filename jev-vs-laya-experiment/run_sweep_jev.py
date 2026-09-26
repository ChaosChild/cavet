"""P1: Jev batch-1 sweeps, 3 repetitions, all universes, over the frozen states.

Judges every frozen state with the exact two-step cascade (q_confirm + q_missing
at mv verbosity, gate 0.5, q_closure with r3 wording below the gate), three
independent repetitions, six concurrent workers over findings. Writes one JSON
per repetition with the full request/response record per call.

Usage:  .venv-cpu/Scripts/python run_sweep_jev.py
"""
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
REPS = 3
WORKERS = 6

states = [json.loads(line) for line in (HERE / "states.jsonl").read_text(encoding="utf-8").splitlines()]
s1q = harness.q_confirm("mv")
s1q.update(harness.q_missing("mv"))
s2q = harness.q_closure("mv", harness.WORDINGS["r3"])

meta = {
    "arm": "A", "model": harness.MODEL, "config": "batch-1, 6 workers, 3 reps",
    "gate": harness.CONFIRM_GATE, "wording": "r3", "verbosity": "mv",
    "states": len(states),
    "pricing_basis": "vendor blog $0.042/Mtok input, verified 2026-09-26",
}


def run_finding(rec):
    st = rec["state"]
    t0 = time.perf_counter()
    c1 = harness.call_jev(st, s1q)
    a1 = (c1.get("response") or {}).get("answers") or {}
    p_yes = (a1.get("is_confirmed") or {}).get("noul")
    out = {"corpus": rec["corpus"], "id": rec["id"], "fp": rec["fp"],
           "calls": [c1], "wall_ms": round((time.perf_counter() - t0) * 1000, 1)}
    if p_yes is None:
        out["error"] = (c1.get("error") or "no answer")[:200]
        return rec["id"], out
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
        out["wall_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if cl.get("choice") is None:
            out["error"] = (c2.get("error") or "no closure answer")[:200]
    return rec["id"], out


def run_rep(rep):
    path = RUNS / f"jev-b1-rep{rep}.json"
    done = {}
    if path.exists():
        done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
    todo = [r for r in states if r["id"] not in done]
    print(f"[rep {rep}] {len(done)} done, {len(todo)} to run", flush=True)
    if not todo:
        return
    n = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for fid, out in ex.map(run_finding, todo):
            done[fid] = out
            n += 1
            if n % 200 == 0:
                print(f"[rep {rep}] {n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
                path.write_text(json.dumps({"meta": meta, "findings": done}, indent=1), encoding="utf-8")
    errors = sum(1 for v in done.values() if v.get("error"))
    path.write_text(json.dumps({"meta": {**meta, "rep": rep, "errors": errors},
                                "findings": done}, indent=1), encoding="utf-8")
    print(f"[rep {rep}] DONE {len(done)} findings, {errors} errors, "
          f"{time.time() - t0:.0f}s total", flush=True)


if __name__ == "__main__":
    tele = subprocess.Popen([sys.executable, str(HERE / "telemetry.py"),
                             "--out", str(RUNS / "telemetry-jev-b1.jsonl"),
                             "--label", "jev-b1-3rep"])
    try:
        for rep in range(1, REPS + 1):
            run_rep(rep)
    finally:
        tele.kill()
    print("P1 complete")
