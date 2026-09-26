"""P0 batch-size spike: does GPU batch width change any answer?

For each Laya checkpoint, judge a deterministic 128-state slice with the exact
step-1 questions once sequentially (batch size 1) and then through predict_batch
at sizes 8, 16, 32. Compares every answer against the sequential baseline and
reports bit-identity, max absolute drift, and gate flips. On the corpus-2 slice
members it also reports recall against the operator gold at each batch size.
"""
import json
import sys
import time
from pathlib import Path

import laya

import harness

HERE = Path(__file__).parent
DEVICE = sys.argv[1] if len(sys.argv) > 1 else "cuda"
STRIDE = 14
BATCH_SIZES = [8, 16, 32]

s1q = harness.q_confirm("mv")
s1q.update(harness.q_missing("mv"))

states = [json.loads(line) for line in (HERE / "states.jsonl").read_text(encoding="utf-8").splitlines()]
slice_states = states[::STRIDE]
print(f"slice: {len(slice_states)} states (stride {STRIDE}) from {len(states)}")

gt2 = {f["id"] for f in json.loads(
    Path("C:/Development/cavet-docs-export/benchmark/ground-truth/corpus-2.json").read_text(encoding="utf-8")
)["confirmed_findings"]}
slice2 = [r for r in slice_states if r["corpus"] == "corpus-2"]
print(f"corpus-2 slice members with GT: {len(slice2)}")


def answers_of(rec):
    a = rec["answers"]
    return a["is_confirmed"]["noul"], a["state_sufficient"]["noul"]


report = {"device": DEVICE, "slice": len(slice_states), "checkpoints": {}}
for name in ("typed-decisions", "multilingual"):
    pass_len = 8192 if name == "multilingual" else None
    agent = laya.load(str(HERE / "models" / name), device=DEVICE)
    sts = [r["state"] for r in slice_states]

    t0 = time.time()
    base = [answers_of(r) for r in agent.predict_batch(sts, s1q, batch_size=1, max_len=pass_len)]
    base_s = time.time() - t0
    ck = {"baseline_s": round(base_s, 1), "batch_runs": {}}
    print(f"\n=== {name}: sequential {base_s:.1f}s "
          f"({base_s / len(sts) * 1000:.0f} ms/state) ===")

    for bs in BATCH_SIZES:
        t0 = time.time()
        out = [answers_of(r) for r in agent.predict_batch(sts, s1q, batch_size=bs, max_len=pass_len)]
        dt = time.time() - t0
        diffs = [abs(a[0] - b[0]) for a, b in zip(base, out)]
        ident = sum(1 for a, b in zip(base, out) if a == b)
        flips = sum(1 for a, b in zip(base, out) if (a[0] >= 0.5) != (b[0] >= 0.5))
        rec = None
        if slice2:
            slice2_out = [b for r, b in zip(slice_states, out) if r["corpus"] == "corpus-2"]
            hit = sum(1 for r, b in zip(slice2, slice2_out)
                      if (b[0] >= 0.5) == (r["id"] in gt2))
            rec = f"{hit}/{len(slice2)}"
        ck["batch_runs"][bs] = {
            "wall_s": round(dt, 1), "ms_per_state": round(dt / len(sts) * 1000, 1),
            "bit_identical": f"{ident}/{len(out)}",
            "max_abs_diff": max(diffs), "gate_flips": flips, "corpus2_gt_recall": rec,
        }
        print(f"  bs={bs:2d}: {dt:5.1f}s ({dt / len(sts) * 1000:5.1f} ms/state) "
              f"identical {ident}/{len(out)} max_diff {max(diffs):.6f} "
              f"gate_flips {flips} corpus2_recall {rec}")
    report["checkpoints"][name] = ck
    del agent

(HERE / "spike-batch.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
print("\nspike written: spike-batch.json")
