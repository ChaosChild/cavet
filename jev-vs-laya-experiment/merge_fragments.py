"""Merge the fragmt re-measurement fragments into the main run files,
replacing every fragmt:* key (the contaminated-state results) with the
clean-state results from states-fragmt-fixed.jsonl.

Usage:  .venv-cpu/Scripts/python merge_fragments.py   (skips missing fragments)
"""
import json
from pathlib import Path

RUNS = Path(__file__).parent / "runs"

MAP = [
    ("fragmtfix-jev1.13-rep{n}.json", "jev-b1-rep{n}.json", 3),
    ("fragmtfix-jev1.14-rep{n}.json", "jev-114-rep{n}.json", 3),
    ("fragmtfix-laya-typed-decisions-rep{n}.json", "laya-typed-decisions-rep{n}.json", 2),
    ("fragmtfix-laya-multilingual-rep{n}.json", "laya-multilingual-rep{n}.json", 2),
    ("fragmtfix-statesv2-ft-rep{n}.json", "statesv2-ft-rep{n}.json", 2),
    ("fragmtfix-apus-openjev-9b-rep{n}.json", "apus-openjev-9b-rep{n}.json", 2),
    ("fragmtfix-clm-8b-q8-rep{n}.json", "clm-8b-q8-rep{n}.json", 2),
    ("fragmtfix-kev-4b-rep{n}.json", "kev-4b-rep{n}.json", 2),
]

NOTE = ("fragmt re-measured on states-fragmt-fixed.jsonl after the verdict-line "
        "contamination repair; all other universes unchanged")

for frag_pat, target_pat, reps in MAP:
    for n in range(1, reps + 1):
        frag_p = RUNS / frag_pat.format(n=n)
        targ_p = RUNS / target_pat.format(n=n)
        if not frag_p.exists():
            print(f"skip (no fragment): {frag_p.name}")
            continue
        if not targ_p.exists():
            print(f"skip (no target): {targ_p.name}")
            continue
        frag = json.loads(frag_p.read_text(encoding="utf-8"))["findings"]
        doc = json.loads(targ_p.read_text(encoding="utf-8"))
        out = {k: v for k, v in doc["findings"].items() if not k.startswith("fragmt:")}
        replaced = len(doc["findings"]) - len(out)
        out.update(frag)
        doc["findings"] = out
        doc["meta"]["fragmt_remeasured"] = NOTE
        doc["meta"]["errors"] = sum(1 for v in out.values() if v.get("error"))
        targ_p.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        print(f"merged {frag_p.name} -> {targ_p.name}: replaced {replaced}, now {len(out)} findings")
