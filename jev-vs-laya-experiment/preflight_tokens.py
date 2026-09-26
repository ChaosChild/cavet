"""P0 preflight: freeze the 1,793-finding state set and measure per-checkpoint
token budgets with the real Laya tokenizers.

Outputs:
  states.jsonl   one line per finding: {corpus, id, fp, state}
  preflight.json token distributions per checkpoint per corpus + overflow rates
"""
import json
import sys
from pathlib import Path

from transformers import AutoTokenizer

import harness

HERE = Path(__file__).parent
JEV = HERE.parent / "jev-triage-experiment"
VAR = harness.VARIANTS["final"]

# universe ids per corpus, taken from the Jev study's final sweeps (reference reads)
universes = {}
fr = json.loads((HERE / "full-run.json").read_text(encoding="utf-8"))
universes["cavet"] = sorted(f["id"] for f in fr["findings"])
universes["fragmt"] = sorted(json.loads(
    (JEV / "batch-runs" / "similarity-40-fragmt-svcx-final1.json").read_text(encoding="utf-8")
)["findings"].keys())
for c in (2, 3, 4, 5):
    universes[f"corpus-{c}"] = sorted(json.loads(
        (JEV / "s0b" / "runs" / f"similarity-40-corpus-{c}-svcx-final1.json").read_text(encoding="utf-8")
    )["findings"].keys())

cache_files = {
    "cavet": HERE / "details-cache.json",
    "fragmt": HERE / "details-cache-fragmt.json",
    "corpus-2": HERE / "details-cache-corpus-2.json",
    "corpus-3": HERE / "details-cache-corpus-3.json",
    "corpus-4": HERE / "details-cache-corpus-4.json",
    "corpus-5": HERE / "details-cache-corpus-5.json",
}

# build frozen states for every universe finding
fp_by_prefix = {}
for corpus, cf in cache_files.items():
    cache = json.loads(cf.read_text(encoding="utf-8"))
    for fp in cache:
        fp_by_prefix.setdefault(fp[:6], (corpus, fp, cache[fp]))

states = []
missing = []
for corpus, ids in universes.items():
    for fid in ids:
        hit = fp_by_prefix.get(fid)
        if hit is None:
            missing.append((corpus, fid))
            continue
        _, fp, d = hit
        st = harness.build_state(VAR, d)
        states.append({"corpus": corpus, "id": fid, "fp": fp, "state": st})

print(f"states built: {len(states)} (missing {len(missing)})")
for m in missing[:10]:
    print("  missing:", m)

with (HERE / "states.jsonl").open("w", encoding="utf-8") as fh:
    for rec in states:
        fh.write(json.dumps(rec) + "\n")

# tokenize with each checkpoint's real tokenizer
toks = {}
for name in ("typed-decisions", "multilingual"):
    root = HERE / "models" / name
    for sub in ("", "tokenizer", "encoder"):
        try:
            tk = AutoTokenizer.from_pretrained(str(root / sub) if sub else str(root))
            toks[name] = tk
            print(f"tokenizer[{name}] loaded from '{sub or 'root'}'")
            break
        except Exception as e:
            if sub == "encoder":
                print(f"tokenizer[{name}] FAILED: {e}")

report = {"states": len(states), "missing": missing, "per_checkpoint": {}}
for name, tk in toks.items():
    per_corpus = {}
    all_lens = []
    for rec in states:
        n = len(tk(json.dumps(rec["state"], ensure_ascii=False))["input_ids"])
        all_lens.append(n)
        per_corpus.setdefault(rec["corpus"], []).append(n)
    all_lens.sort()
    n = len(all_lens)
    pct = lambda p: all_lens[min(n - 1, int(n * p))]
    summary = {
        "median": pct(0.5), "p90": pct(0.9), "p95": pct(0.95), "p99": pct(0.99),
        "max": all_lens[-1], "mean": round(sum(all_lens) / n, 1),
        "over_320": round(100 * sum(1 for x in all_lens if x > 320) / n, 2),
        "over_768": round(100 * sum(1 for x in all_lens if x > 768) / n, 2),
        "over_1024": round(100 * sum(1 for x in all_lens if x > 1024) / n, 2),
        "over_7680": round(100 * sum(1 for x in all_lens if x > 7680) / n, 2),
        "per_corpus_median": {k: sorted(v)[len(v) // 2] for k, v in per_corpus.items()},
    }
    report["per_checkpoint"][name] = summary
    print(f"\n[{name}] tokens: median={summary['median']} p95={summary['p95']} "
          f"p99={summary['p99']} max={summary['max']}")
    print(f"  over 320={summary['over_320']}%  over 768={summary['over_768']}%  "
          f"over 1024={summary['over_1024']}%  over 7680={summary['over_7680']}%")

(HERE / "preflight.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
print("\npreflight written: states.jsonl + preflight.json")
