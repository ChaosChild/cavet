"""P0 smoke test: load both Laya checkpoints on CPU, judge real cavet states
with the exact two-step cascade questions, and verify bit-identical determinism.
"""
import json
import sys
import time
from pathlib import Path

import laya

import harness

DEVICE = sys.argv[1] if len(sys.argv) > 1 else "cpu"
print("device:", DEVICE)

HERE = Path(__file__).parent
VAR = harness.VARIANTS["final"]
print("variant:", VAR)

cache = json.loads((HERE / "details-cache.json").read_text(encoding="utf-8"))

# two representative findings: the operator-confirmed missing-USER pair and a
# plain fixture finding, one of each disposition family
picks = {}
for fp, d in cache.items():
    key = None
    if "missing-user" in d["rule"] or d["rule"] == "DS-0002":
        key = "missing-user"
    elif "fixture" in d["location"]:
        key = "fixture"
    if key and key not in picks:
        picks[key] = (fp, d)
    if len(picks) == 2:
        break

states = {}
for key, (fp, d) in picks.items():
    st = harness.build_state(VAR, d)
    states[key] = st
    print(f"state[{key}]: {d['rule']} chars={len(json.dumps(st))}")

s1q = harness.q_confirm(VAR["verbosity"])
s1q.update(harness.q_missing(VAR["verbosity"]))
s2q = harness.q_closure(VAR["verbosity"], harness.WORDINGS[VAR["wording"]])
print("step-1 questions:", sorted(s1q), "| step-2 questions:", sorted(s2q))

for name, path in [
    ("typed-decisions", HERE / "models" / "typed-decisions"),
    ("multilingual", HERE / "models" / "multilingual"),
]:
    print(f"\n=== {name} ===")
    t0 = time.time()
    agent = laya.load(str(path), device=DEVICE)
    print(f"loaded in {time.time() - t0:.1f}s")

    for key, st in states.items():
        runs = []
        for i in range(2):
            t0 = time.time()
            r1 = agent.predict(st, s1q)
            p_yes = r1["answers"]["is_confirmed"]["noul"]
            suff = r1["answers"]["state_sufficient"]["noul"]
            gate = p_yes >= harness.CONFIRM_GATE
            r2 = None
            if not gate:
                r2 = agent.predict(st, s2q)
            dt = (time.time() - t0) * 1000
            runs.append((r1, r2, dt))
            status = "confirmed" if gate else r2["answers"]["closure"]["choice"]
            print(
                f"  run{i + 1} [{key}] step1={p_yes:.4f} suff={suff:.4f} "
                f"status={status} closure_conf="
                f"{None if gate else round(r2['answers']['closure']['confidence'], 4)} "
                f"wall={dt:.0f}ms"
            )
        identical = json.dumps(runs[0][0], sort_keys=True) == json.dumps(runs[1][0], sort_keys=True) and (
            (runs[0][1] is None) == (runs[1][1] is None)
            and (runs[0][1] is None or json.dumps(runs[0][1], sort_keys=True) == json.dumps(runs[1][1], sort_keys=True))
        )
        print(f"  [{key}] determinism: {'BIT-IDENTICAL' if identical else 'DIVERGED'}")

    del agent
print("\nsmoke done")
