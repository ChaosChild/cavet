"""P4: Laya sweep over an arbitrary states file with the same output format as
run_sweep_laya.py (2 reps = bit-identity determinism check, sequential
single-state predicts, frozen truncation policy, telemetry sidecar).

Usage:
  .venv-rocm/Scripts/python p4/run_sweep_p4.py <checkpoint-dir-name> <states.jsonl> <out-prefix> [cuda|cpu]

Examples:
  ... run_sweep_p4.py multilingual      p4/data/states-p4-val.jsonl p4-val-base
  ... run_sweep_p4.py multilingual-ft   p4/data/states-p4-val.jsonl p4-val-ft
  ... run_sweep_p4.py multilingual      states-v2.jsonl             statesv2-base

Output: runs/<out-prefix>-rep{1,2}.json in the run_sweep_laya.py format.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import laya
from transformers import AutoTokenizer

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
sys.path.insert(0, str(PARENT))
import harness  # noqa: E402

RUNS = PARENT / "runs"
RUNS.mkdir(exist_ok=True)
REPS = 2
DEVICE = sys.argv[4] if len(sys.argv) > 4 else "cuda"

CKPT_NAME = sys.argv[1]
STATES_FILE = (PARENT / sys.argv[2]) if not Path(sys.argv[2]).is_absolute() else Path(sys.argv[2])
PREFIX = sys.argv[3]
CKPT = (HERE / "models" / CKPT_NAME) if (HERE / "models" / CKPT_NAME).exists() \
    else (PARENT / "models" / CKPT_NAME)
MAX_LEN = 8192  # the multilingual checkpoint's context (all P4 states fit)

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


def fit_state(st, tk, budget):
    """Frozen truncation policy: cavet_lookup first, then source_excerpt tail."""
    s = json.dumps(st, ensure_ascii=False)
    actions = []
    if len(tk(s)["input_ids"]) <= budget:
        return st, actions
    st = json.loads(s)
    if "cavet_lookup" in st:
        st.pop("cavet_lookup")
        actions.append("dropped cavet_lookup")
    f = st.get("finding") or {}
    mc = st.get("mechanical_context") or {}
    exc_holder = [mc, f]
    for _ in range(6):
        if len(tk(json.dumps(st, ensure_ascii=False))["input_ids"]) <= budget:
            return st, actions
        exc = None
        for holder in exc_holder:
            if holder.get("source_excerpt"):
                exc = holder
                break
        if exc is None:
            break
        exc["source_excerpt"] = exc["source_excerpt"][: max(len(exc["source_excerpt"]) // 2, 100)]
        actions.append("halved source_excerpt")
    if len(tk(json.dumps(st, ensure_ascii=False))["input_ids"]) > budget:
        actions.append("STILL OVER BUDGET: shipped as-is, runtime truncates at max_len")
    return st, actions


def meta_for(trunc_total, fitted, rep=None):
    m = {"arm": f"p4-{CKPT_NAME}", "checkpoint": CKPT_NAME, "device": DEVICE,
         "states_file": str(STATES_FILE.relative_to(PARENT)) if STATES_FILE.is_relative_to(PARENT) else str(STATES_FILE),
         "max_len": MAX_LEN, "head_max_len": 256, "state_budget": MAX_LEN - 256,
         "reps": REPS, "config": "sequential single-state predicts",
         "truncated_states": trunc_total, "truncation_detail": fitted,
         "laya_version": laya.__version__ if hasattr(laya, "__version__") else "0.3.20"}
    if rep:
        m["rep"] = rep
    return m


def main():
    states = [json.loads(line) for line in
              STATES_FILE.read_text(encoding="utf-8").splitlines()]
    tk = AutoTokenizer.from_pretrained(str(CKPT / "tokenizer"))
    budget = MAX_LEN - 256
    agent = laya.load(str(CKPT), device=DEVICE)
    print(f"[{CKPT_NAME}] device={DEVICE} max_len={MAX_LEN} state_budget={budget} "
          f"states={len(states)}", flush=True)

    fitted = {}
    trunc_total = 0
    run_states = []
    for rec in states:
        st, actions = fit_state(rec["state"], tk, budget)
        if actions:
            fitted[rec["id"]] = actions
            trunc_total += 1
            print(f"truncated {rec['id']}: {actions}", flush=True)
        run_states.append((rec, st))

    for rep in range(1, REPS + 1):
        path = RUNS / f"{PREFIX}-rep{rep}.json"
        done = {}
        if path.exists():
            done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        todo = [r for r in run_states if key_of(r[0]) not in done]
        print(f"[{PREFIX} rep {rep}] {len(done)} done, {len(todo)} to run", flush=True)
        t0 = time.time()
        n = 0
        for rec, st in todo:
            ft0 = time.perf_counter()
            r1 = agent.predict(st, s1q_for(rec), max_len=MAX_LEN)
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
                r2 = agent.predict(st, s2q, max_len=MAX_LEN)
                a2 = r2["answers"]["closure"]
                out["status"] = a2["choice"]
                out["step2_ran"] = True
                out["closure_confidence"] = a2.get("confidence")
                out["closure_probabilities"] = a2.get("probabilities")
                out["wall_ms"] = round((time.perf_counter() - ft0) * 1000, 1)
            done[key_of(rec)] = out
            n += 1
            if n % 400 == 0:
                print(f"[{PREFIX} rep {rep}] {n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
                path.write_text(json.dumps({"meta": meta_for(trunc_total, fitted), "findings": done}, indent=1),
                                encoding="utf-8")
        path.write_text(json.dumps({"meta": meta_for(trunc_total, fitted, rep=rep), "findings": done}, indent=1),
                        encoding="utf-8")
        print(f"[{PREFIX} rep {rep}] DONE {len(done)}, {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    tele = subprocess.Popen([str(PARENT / ".venv-cpu" / "Scripts" / "python.exe"),
                             str(PARENT / "telemetry.py"),
                             "--out", str(RUNS / f"telemetry-{PREFIX}.jsonl"),
                             "--label", f"p4-{PREFIX}-{DEVICE}"])
    try:
        main()
    finally:
        tele.kill()
    print("sweep complete")
