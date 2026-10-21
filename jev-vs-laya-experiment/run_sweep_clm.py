"""Extension arm sweep: CLM-8B (czl GGUF Q8_0) over the frozen states-v2,
same protocol and output format as the laya runners (2 reps = determinism
check, sequential per-state cascade, gate 0.5, r3 closure wording).

Serving: llama-server (Vulkan, all layers on GPU) exposing /v1/embeddings,
plus the official clm package's Engine (projection heads) on CPU. The server
must already be up (CLM_LLAMA_URL, default http://127.0.0.1:8090); this
runner fails fast if it is not. No state truncation applies: the effective
context is llama-server's 8192 tokens and the frozen states peak below 3.5k
(real-tokenizer preflight); an over-budget prompt would error rather than
silently truncate.

Usage:
  .venv-cpu/Scripts/python run_sweep_clm.py [--limit N] [--reps 2]
Output: runs/clm-8b-q8-rep{1,2}.json (+ telemetry sidecar)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

os.environ.setdefault("CLM_EMB_URL", "http://127.0.0.1:8090/v1/embeddings")
os.environ.setdefault("CLM_DEVICE", "cpu")
from clm import Engine  # noqa: E402  (clm-venv on PYTHONPATH via caller)

import harness  # noqa: E402

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
ARM = "clm-8b-q8"

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
    m = {"arm": "extension-CLM", "checkpoint": "Contrastive-LM/CLM-v0.1-8B",
         "quant": "czl/CLM-v0.1-8B-GGUF Q8_0 (encoder; converter-recommended quant)",
         "heads": "CLM_v0.1-8B.pt (official state/action projection heads)",
         "server": "llama.cpp b11224 llama-server, Vulkan, -ngl 99, ctx 8192",
         "engine": "clm 0.1.0 Engine (system_one protocol over embeddings)",
         "device": "GPU (encoder) + CPU (heads)",
         "reps": 2, "config": "sequential per-state cascade",
         "gate": harness.CONFIRM_GATE, "wording": "r3", "verbosity": "mv",
         "truncated_states": 0,
         "note": "probabilities are relative to each question's candidate set (InfoNCE head semantics)"}
    if rep:
        m["rep"] = rep
    return m


def run_rep(rep, states, engine):
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
        r1 = engine.answer(st, s1q_for(rec))
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
            r2 = engine.answer(st, s2q)
            cl = r2["answers"]["closure"]
            out["status"] = cl.get("choice")
            out["step2_ran"] = True
            out["closure_confidence"] = cl.get("confidence")
            out["closure_probabilities"] = cl.get("probabilities")
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

    import urllib.request
    try:
        with urllib.request.urlopen(os.environ["CLM_EMB_URL"].rsplit("/", 1)[0] + "/health",
                                    timeout=5) as r:
            assert json.loads(r.read())["status"] == "ok"
    except Exception as e:
        sys.exit(f"llama-server not healthy at {os.environ['CLM_EMB_URL']}: {e}")

    states = [json.loads(line) for line in
              (HERE / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]
    if args.limit:
        states = states[: args.limit]
    print(f"[{ARM}] {len(states)} states, engine loading...", flush=True)
    engine = Engine()
    for rep in range(1, args.reps + 1):
        run_rep(rep, states, engine)


if __name__ == "__main__":
    tele = subprocess.Popen([str(HERE / ".venv-cpu" / "Scripts" / "python.exe"),
                             str(HERE / "telemetry.py"),
                             "--out", str(RUNS / f"telemetry-{ARM}.jsonl"),
                             "--label", f"{ARM}-sweep"])
    try:
        main()
    finally:
        tele.kill()
    print("CLM sweep complete")
