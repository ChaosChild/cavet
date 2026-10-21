"""Extension: Jev 1.14 rerun over the frozen states-v2, 3 repetitions (same
batch-1 protocol as the 1.13 arm), to measure version-over-version change.

The vendor bumped Jev to 1.14 behind `jev-preview`; this arm pins the explicit
model id `jev-1.14.0` (echo-verified per response; the run aborts the finding
count as an error row if the echo mismatches). Output files are separate from
the 1.13 arm (jev-b1-*): runs/jev-114-rep{1,2,3}.json.

Usage:  .venv-cpu/Scripts/python run_sweep_jev114.py
"""
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import harness

harness.MODEL = "jev-1.14.0"

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
REPS = 3
WORKERS = 6
ARM = "jev-114"

SV_INSTRUCTION = (" Severity labels are not grounds for dismissal for manifest "
                  "findings: the affected version is pinned in this project's "
                  "dependency manifest, which the state establishes directly.")


def s1q_for(rec):
    q = harness.q_confirm("mv")
    q.update(harness.q_missing("mv"))
    if rec.get("lockfile"):
        q["is_confirmed"]["instructions"] += SV_INSTRUCTION
    return q


s2q = harness.q_closure("mv", harness.WORDINGS["r3"])


def key_of(rec):
    return f'{rec["corpus"]}:{rec["id"]}'


meta = {"arm": "A-v114", "model": harness.MODEL,
        "config": "batch-1, 6 workers, 3 reps", "gate": harness.CONFIRM_GATE,
        "wording": "r3", "verbosity": "mv", "states": 1793,
        "pricing_basis": "vendor blog $0.042/Mtok input, verified 2026-09-26"}


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
        if cl.get("choice") is None:
            out["error"] = (c2.get("error") or "no closure answer")[:200]
    return key_of(rec), out


def version_echo_ok(out):
    for c in out.get("calls", []):
        m = (c.get("response") or {}).get("model")
        if m is not None and m != harness.MODEL:
            return False
    return True


def run_rep(rep):
    path = RUNS / f"{ARM}-rep{rep}.json"
    done = {}
    if path.exists():
        done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
    todo = [r for r in states if key_of(r) not in done]
    print(f"[{ARM} rep {rep}] {len(done)} done, {len(todo)} to run", flush=True)
    if not todo:
        return
    n = 0
    t0 = time.time()
    bad_echo = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for fid, out in ex.map(run_finding, todo):
            done[fid] = out
            n += 1
            if not version_echo_ok(out):
                bad_echo += 1
                print(f"  [{fid}] VERSION ECHO MISMATCH", flush=True)
            if n % 200 == 0:
                print(f"[{ARM} rep {rep}] {n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
                path.write_text(json.dumps({"meta": meta, "findings": done}, indent=1), encoding="utf-8")
    errors = sum(1 for v in done.values() if v.get("error"))
    path.write_text(json.dumps({"meta": {**meta, "rep": rep, "errors": errors,
                                         "version_echo_mismatches": bad_echo},
                                "findings": done}, indent=1), encoding="utf-8")
    print(f"[{ARM} rep {rep}] DONE {len(done)} findings, {errors} errors, "
          f"{bad_echo} echo mismatches, {time.time() - t0:.0f}s total", flush=True)


states = [json.loads(line) for line in (HERE / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]

if __name__ == "__main__":
    tele = subprocess.Popen([sys.executable, str(HERE / "telemetry.py"),
                             "--out", str(RUNS / f"telemetry-{ARM}.jsonl"),
                             "--label", "jev-114-3rep"])
    try:
        for rep in range(1, REPS + 1):
            run_rep(rep)
    finally:
        tele.kill()
    print("jev-114 rerun complete")
