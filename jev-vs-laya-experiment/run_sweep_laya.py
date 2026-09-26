"""P2: Laya sweeps, 2 repetitions (bit-identity determinism check), all universes,
over the frozen states. Sequential single-state predicts (the batch-size spike
showed batching is accuracy-neutral but not bit-reproducible and no faster).

State budgets: typed-decisions ships max_len=1024 with head_max_len=256, so the
state budget is 768 tokens; multilingual runs at max_len=8192 (budget 7936).
Over-budget states are truncated per the frozen policy: cavet_lookup dropped
first, then source_excerpt tail, never the finding core.

Usage:  .venv-rocm/Scripts/python run_sweep_laya.py [cuda|cpu]
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import laya
from transformers import AutoTokenizer

import harness

HERE = Path(__file__).parent
RUNS = HERE / "runs"
RUNS.mkdir(exist_ok=True)
REPS = 2
DEVICE = sys.argv[1] if len(sys.argv) > 1 else "cuda"

CHECKPOINTS = {
    "typed-decisions": {"path": HERE / "models" / "typed-decisions", "max_len": None},
    "multilingual": {"path": HERE / "models" / "multilingual", "max_len": 8192},
}

s1q = harness.q_confirm("mv")
s1q.update(harness.q_missing("mv"))
s2q = harness.q_closure("mv", harness.WORDINGS["r3"])


def key_of(rec):
    """Findings are keyed by corpus:id: 6-char id prefixes collide across corpora."""
    return f'{rec["corpus"]}:{rec["id"]}'

states = [json.loads(line) for line in (HERE / "states.jsonl").read_text(encoding="utf-8").splitlines()]


def fit_state(st, tk, budget):
    """Apply the frozen truncation policy; returns (state, actions)."""
    s = json.dumps(st, ensure_ascii=False)
    actions = []
    if len(tk(s)["input_ids"]) <= budget:
        return st, actions
    st = json.loads(s)
    if "cavet_lookup" in st:
        st.pop("cavet_lookup")
        actions.append("dropped cavet_lookup")
    mc = st.get("mechanical_context") or {}
    while "source_excerpt" in mc and len(tk(json.dumps(st, ensure_ascii=False))["input_ids"]) > budget:
        exc = mc["source_excerpt"]
        mc["source_excerpt"] = exc[: max(len(exc) // 2, 200)]
        actions.append("halved source_excerpt")
    if len(tk(json.dumps(st, ensure_ascii=False))["input_ids"]) > budget:
        actions.append("STILL OVER BUDGET")
    return st, actions


def run_checkpoint(name, cfg):
    tk = AutoTokenizer.from_pretrained(str(cfg["path"] / "tokenizer"))
    head = 256
    max_len = cfg["max_len"] or 1024
    budget = max_len - head
    agent = laya.load(str(cfg["path"]), device=DEVICE)
    print(f"[{name}] device={DEVICE} max_len={max_len} state_budget={budget}", flush=True)

    fitted = {}
    run_states = []
    trunc_total = 0
    for rec in states:
        st, actions = fit_state(rec["state"], tk, budget)
        if actions:
            fitted[rec["id"]] = actions
            trunc_total += 1
            print(f"[{name}] truncated {rec['id']}: {actions}", flush=True)
        run_states.append((rec, st))

    for rep in range(1, REPS + 1):
        path = RUNS / f"laya-{name}-rep{rep}.json"
        done = {}
        if path.exists():
            done = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        todo = [r for r in run_states if key_of(r[0]) not in done]
        print(f"[{name} rep {rep}] {len(done)} done, {len(todo)} to run", flush=True)
        t0 = time.time()
        n = 0
        for rec, st in todo:
            ft0 = time.perf_counter()
            r1 = agent.predict(st, s1q, max_len=cfg["max_len"])
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
                r2 = agent.predict(st, s2q, max_len=cfg["max_len"])
                a2 = r2["answers"]["closure"]
                out["status"] = a2["choice"]
                out["step2_ran"] = True
                out["closure_confidence"] = a2.get("confidence")
                out["closure_probabilities"] = a2.get("probabilities")
                out["wall_ms"] = round((time.perf_counter() - ft0) * 1000, 1)
            done[key_of(rec)] = out
            n += 1
            if n % 400 == 0:
                print(f"[{name} rep {rep}] {n}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
                path.write_text(json.dumps({"meta": meta_for(name, cfg, trunc_total, fitted), "findings": done}, indent=1), encoding="utf-8")
        path.write_text(json.dumps({"meta": meta_for(name, cfg, trunc_total, fitted, rep=rep),
                                    "findings": done}, indent=1), encoding="utf-8")
        print(f"[{name} rep {rep}] DONE {len(done)}, {time.time() - t0:.0f}s", flush=True)
    del agent


def meta_for(name, cfg, trunc_total, fitted, rep=None):
    m = {"arm": "B" if name == "typed-decisions" else "C",
         "checkpoint": f"convaiinnovations/laya-{name}", "device": DEVICE,
         "max_len": cfg["max_len"] or 1024, "head_max_len": 256,
         "state_budget": (cfg["max_len"] or 1024) - 256,
         "reps": REPS, "config": "sequential single-state predicts",
         "truncated_states": trunc_total, "truncation_detail": fitted,
         "laya_version": laya.__version__ if hasattr(laya, "__version__") else "0.3.20"}
    if rep:
        m["rep"] = rep
    return m


if __name__ == "__main__":
    tele = subprocess.Popen([str(HERE / ".venv-cpu" / "Scripts" / "python.exe"),
                             str(HERE / "telemetry.py"),
                             "--out", str(RUNS / "telemetry-laya.jsonl"),
                             "--label", f"laya-2x2rep-{DEVICE}"])
    try:
        for name, cfg in CHECKPOINTS.items():
            run_checkpoint(name, cfg)
    finally:
        tele.kill()
    print("P2 complete")
