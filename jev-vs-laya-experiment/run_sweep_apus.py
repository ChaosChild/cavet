"""Extension arm sweep: APUS-OpenJev-v1-9B (Q6_K GGUF) over the frozen
states-v2, same protocol and output format as the other runners (2 reps =
determinism check, sequential per-state cascade, gate 0.5, r3 closure).

Serving: llama-server (Vulkan, all layers on GPU) on port 8091, driven through
apus_client.py, a faithful reimplementation of the shipped runtime contract
(apus-ailab/APUS-OpenJev-v1 9B-3000: jev.dynamic.prompt.v2, chat template with
thinking disabled, letter-token logprob scoring at the answer boundary; noul =
canonical yes/no candidates). One question per HTTP request, as the contract
specifies. Determinism expectation from bring-up: not bit-identical (Vulkan
kernel drift ~0.004 on step-1, no decision flips) - the consistency section
quantifies it over the full universe.

Usage:
  .venv-cpu/Scripts/python run_sweep_apus.py [--limit N] [--reps 2]
Output: runs/apus-openjev-9b-rep{1,2}.json (+ telemetry sidecar)
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import apus_client
import apus_client as ac

import harness

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
ARM = "apus-openjev-9b"

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


def meta_for(rep=None):
    m = {"arm": "extension-APUS", "checkpoint": "apus-ailab/APUS-OpenJev-v1 9B-3000",
         "quant": "prithivMLmods/APUS-OpenJev-v1-9B-GGUF Q6_K (merged checkpoint)",
         "server": "llama.cpp b11224 llama-server, Vulkan, -ngl 99, ctx 8192",
         "engine": "apus_client.py (shipped jev.dynamic.prompt.v2 contract reimplementation)",
         "effort": "full depth (32 layers; the 16-layer early-exit path is native-runtime-only)",
         "device": "GPU",
         "reps": 2, "config": "sequential per-state cascade, one question per request",
         "gate": harness.CONFIRM_GATE, "wording": "r3", "verbosity": "mv",
         "truncated_states": 0,
         "note": "probabilities are relative to each question's candidate set (contract semantics)"}
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
        st_text = ac.state_to_text(rec["state"])
        ft0 = time.perf_counter()
        r1 = ac.decide(st_text, s1q_for(rec)["is_confirmed"]["instructions"], "noul", None)
        p_yes = r1["yes_probability"]
        out = {"corpus": rec["corpus"], "id": rec["id"], "fp": rec["fp"],
               "wall_ms": round((time.perf_counter() - ft0) * 1000, 1)}
        out["step1_noul"] = p_yes
        suff = ac.decide(st_text, s1q_for(rec)["state_sufficient"]["instructions"],
                         "noul", None)
        out["state_sufficient"] = suff["yes_probability"]
        if p_yes >= harness.CONFIRM_GATE:
            out["status"] = "confirmed"
            out["step2_ran"] = False
        else:
            cl_def = s2q["closure"]
            crit = [{"id": k, "description": v} for k, v in cl_def["criteria"].items()]
            r2 = ac.decide(st_text, cl_def["instructions"], "choice", crit)
            out["status"] = r2["choice"]
            out["step2_ran"] = True
            out["closure_confidence"] = max(r2["probabilities"].values())
            out["closure_probabilities"] = r2["probabilities"]
            out["wall_ms"] = round((time.perf_counter() - ft0) * 1000, 1)
        done[key_of(rec)] = out
        n += 1
        if n % 100 == 0:
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
        with urllib.request.urlopen(apus_client.BASE + "/health", timeout=5) as r:
            assert json.loads(r.read())["status"] == "ok"
    except Exception as e:
        sys.exit(f"llama-server not healthy at {apus_client.BASE}: {e}")

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
    print("APUS sweep complete")
