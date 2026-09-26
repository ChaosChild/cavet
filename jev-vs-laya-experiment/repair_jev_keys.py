"""Repair P1 rep files: re-key by corpus:id and re-judge the colliding
findings whose results were overwritten by the bare-id keying.

The old rep files hold one result per 6-char id; each surviving entry carries
the fp of the record that actually produced it. Every state record whose fp
does not match its id's surviving entry gets re-judged (at most 20 per rep).
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from run_sweep_jev import key_of, meta, run_finding, states

RUNS = Path(__file__).parent / "runs"
WORKERS = 6

for rep in (1, 2, 3):
    path = RUNS / f"jev-b1-rep{rep}.json"
    old = json.loads(path.read_text(encoding="utf-8"))["findings"]
    by_fp = {v.get("fp"): v for v in old.values()}
    new = {}
    missing = []
    for rec in states:
        k = key_of(rec)
        survivor = old.get(rec["id"])
        if survivor and survivor.get("fp") == rec["fp"] and survivor.get("corpus") == rec["corpus"]:
            new[k] = survivor
        else:
            missing.append(rec)
    print(f"[rep {rep}] re-keyed {len(new)}, missing {len(missing)}", flush=True)
    if missing:
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for k, out in ex.map(run_finding, missing):
                new[k] = out
        print(f"[rep {rep}] re-judged {len(missing)} in {time.time() - t0:.0f}s", flush=True)
    errors = sum(1 for v in new.values() if v.get("error"))
    path.write_text(json.dumps({"meta": {**meta, "rep": rep, "errors": errors,
                                         "keying": "corpus:id"},
                                "findings": new}, indent=1), encoding="utf-8")
    print(f"[rep {rep}] DONE {len(new)} findings, {errors} errors", flush=True)
print("repair complete")
