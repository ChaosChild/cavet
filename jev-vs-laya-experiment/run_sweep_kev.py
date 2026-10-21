"""Extension arm sweep: kev-4b (jaredpalmer/kev-4b on Qwen3.5-4B-Base) over
the frozen states-v2, same protocol and output format as the other runners
(2 reps = determinism check, sequential per-state cascade, gate 0.5, r3
closure wording).

Serving: kev.serve (the project's own server, the TypeSafe /v1/systemone
contract) on port 8009, running on the ROCm torch build (kev's torch>=2.6,<2.9
pin has no Windows GPU wheel; served on torch 2.9.1+rocm7.13 with the DeltaNet
layers on their reference fallback kernels - correct but ~6-8 s per question).
Served temperature 2.41 is the checkpoint's own fitted value (as-served, like
Jev). One multi-question request per cascade step, per the contract.

Usage:
  .venv-cpu/Scripts/python run_sweep_kev.py [--limit N] [--reps 2]
Output: runs/kev-4b-rep{1,2}.json (+ telemetry sidecar)
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import harness

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
ARM = "kev-4b"
BASE = "http://127.0.0.1:8009"

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


def call_kev(state, questions):
    body = json.dumps({"model": "kev-latest", "state": state,
                       "questions": questions}).encode("utf-8")
    for attempt in range(3):
        req = urllib.request.Request(
            BASE + "/v1/systemone", data=body, method="POST",
            headers={"Content-Type": "application/json"})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read()), round((time.perf_counter() - t0) * 1000, 1)
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 2:
                raise
            print(f"  retry after {e}", flush=True)
            time.sleep(5 * (attempt + 1))


def meta_for(rep=None):
    m = {"arm": "extension-KEV", "checkpoint": "jaredpalmer/kev-4b (Qwen3.5-4B-Base + LoRA r16 + pointer head)",
         "server": "kev.serve (kev 0.1.0), torch 2.9.1+rocm7.13.0a20260416, bf16 on GPU",
         "kernels": "DeltaNet reference fallback (no Windows flash-linear-attention)",
         "served_temperature": 2.41, "context": "8,192-token serving context",
         "reps": 2, "config": "sequential per-state cascade",
         "gate": harness.CONFIRM_GATE, "wording": "r3", "verbosity": "mv",
         "truncated_states": 0}
    if rep:
        m["rep"] = rep
    return m


def run_rep(rep, states):
    path = RUNS / f"{ARM}-rep{rep}.json"
    done = {}
    if path.exists():
        done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
    todo = [r for r in states if key_of(r) not in done]
    print(f"[{ARM} rep {rep}] {len(done)} done, {len(todo)} to run", flush=True)
    if not todo:
        return
    t0 = time.time()
    n = 0
    for rec in todo:
        st = rec["state"]
        ft0 = time.perf_counter()
        r1, _ = call_kev(st, s1q_for(rec))
        a1 = r1["answers"]
        p_yes = a1["is_confirmed"]["noul"]
        out = {"corpus": rec["corpus"], "id": rec["id"], "fp": rec["fp"],
               "wall_ms": round((time.perf_counter() - ft0) * 1000, 1)}
        out["step1_noul"] = p_yes
        out["state_sufficient"] = a1["state_sufficient"]["noul"]
        if p_yes >= harness.CONFIRM_GATE:
            out["status"] = "confirmed"
            out["step2_ran"] = False
        else:
            r2, _ = call_kev(st, s2q)
            cl = r2["answers"]["closure"]
            out["status"] = cl.get("choice")
            out["step2_ran"] = True
            out["closure_confidence"] = cl.get("confidence")
            if cl.get("probabilities"):
                out["closure_probabilities"] = cl["probabilities"]
            out["wall_ms"] = round((time.perf_counter() - ft0) * 1000, 1)
        done[key_of(rec)] = out
        n += 1
        if n % 25 == 0:
            print(f"[{ARM} rep {rep}] {n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
            path.write_text(json.dumps({"meta": meta_for(rep), "findings": done}, indent=1),
                            encoding="utf-8")
    path.write_text(json.dumps({"meta": meta_for(rep), "findings": done}, indent=1),
                    encoding="utf-8")
    print(f"[{ARM} rep {rep}] DONE {len(done)}, {time.time() - t0:.0f}s", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="cap the universe (smoke tests)")
    ap.add_argument("--reps", type=int, default=2)
    args = ap.parse_args()

    try:
        with urllib.request.urlopen(BASE + "/v1/models", timeout=10) as r:
            assert "kev" in json.loads(r.read())["models"][0]["name"]
    except Exception as e:
        sys.exit(f"kev.serve not healthy at {BASE}: {e}")

    states = [json.loads(line) for line in
              (HERE / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]
    if args.limit:
        states = states[: args.limit]
    print(f"[{ARM}] {len(states)} states", flush=True)
    for rep in range(1, args.reps + 1):
        run_rep(rep, states)


if __name__ == "__main__":
    tele = subprocess.Popen([str(HERE / ".venv-cpu" / "Scripts" / "python.exe"),
                             str(HERE / "telemetry.py"),
                             "--out", str(RUNS / f"telemetry-{ARM}.jsonl"),
                             "--label", f"{ARM}-sweep"])
    try:
        main()
    finally:
        tele.kill()
    print("kev sweep complete")
