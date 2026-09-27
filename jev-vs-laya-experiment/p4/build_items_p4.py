"""P4: split teacher-labeled findings into train/validation/test and build the
tokenized RLCD training items.

Split is deterministic by md5 of the finding key (corpus:id), 70/20/10, so no
finding leaks across splits. Train items follow the laya RLCD recipe's item
shape: one question per item, {"ids", "markers", "qtype", "target", "label",
"qid"} with build_sequence over the finding's state. Targets are the teacher's
SOFT distributions (RLCD gold-distribution targets):

  is_confirmed    noul   target [1 - p_yes, p_yes]          (option order [false, true])
  state_sufficient noul  target [1 - p_suff, p_suff]
  closure         choice target [p_dismissed, p_not-security] (criteria order)

Errors from the teacher are skipped. Validation and test splits are written as
sweepable state JSONL (same record shape as states-v2.jsonl) for the
before/after evaluation.

Usage:  .venv-cpu/Scripts/python p4/build_items_p4.py
Output: p4/data/train_items.pt, p4/data/states-p4-{val,test}.jsonl, report
"""
import collections
import hashlib
import json
import sys
from pathlib import Path

import torch
from transformers import AutoTokenizer

from laya.common import QTYPES, build_sequence

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
sys.path.insert(0, str(PARENT))
import harness  # noqa: E402

DATA = HERE / "data"
DATA.mkdir(exist_ok=True)
BASE = PARENT / "models" / "multilingual"
MAX_LEN = 8192          # matches the P2/P3 multilingual arm
HEAD_MAX_LEN = 256

SV_INSTRUCTION = (" Severity labels are not grounds for dismissal for manifest "
                  "findings: the affected version is pinned in this project's "
                  "dependency manifest, which the state establishes directly.")


def split_of(key):
    """Deterministic finding-level split: md5 first byte, 70/20/10."""
    b = hashlib.md5(key.encode()).digest()[0]
    if b < 51:
        return "val"
    if b < 76:
        return "test"
    return "train"


def q_internal(qdef):
    """Mirror the agent's _to_internal normalization exactly."""
    return {"t": qdef["type"], "ins": qdef["instructions"], "crit": qdef.get("criteria")}


def main():
    states = {f'{r["corpus"]}:{r["id"]}': r for r in
              (json.loads(l) for l in (HERE / "states-p4.jsonl").read_text(encoding="utf-8").splitlines())}
    labels = json.loads((HERE / "runs" / "jev-labels.json").read_text(encoding="utf-8"))["findings"]

    tok = AutoTokenizer.from_pretrained(str(BASE / "tokenizer"))
    s2q = harness.q_closure("mv", harness.WORDINGS["r3"])

    splits = collections.defaultdict(list)
    skipped = 0
    for key, lab in labels.items():
        if lab.get("error") or lab.get("step1_noul") is None:
            skipped += 1
            continue
        rec = states[key]
        s = split_of(key)
        if s != "train":
            splits[s].append(rec)
            continue
        st = rec["state"]
        p_yes = lab["step1_noul"]
        s1q = {"is_confirmed": {"type": "noul",
                                "instructions": harness.q_confirm("mv")["is_confirmed"]["instructions"],
                                "criteria": harness.q_confirm("mv")["is_confirmed"]["criteria"]}}
        if rec.get("lockfile"):
            s1q["is_confirmed"]["instructions"] += SV_INSTRUCTION
        suff = harness.q_missing("mv")
        items_for = [
            ("is_confirmed", s1q["is_confirmed"], [1.0 - p_yes, p_yes]),
            ("state_sufficient", suff["state_sufficient"],
             [1.0 - lab["state_sufficient"], lab["state_sufficient"]]),
        ]
        if lab.get("step2_ran") and lab.get("closure_probabilities"):
            cp = lab["closure_probabilities"]
            items_for.append(("closure", s2q["closure"],
                              [float(cp.get("dismissed", 0.0)), float(cp.get("not-security", 0.0))]))
        for qid, qdef, target in items_for:
            q = q_internal(qdef)
            seq, markers = build_sequence(tok, st, q, MAX_LEN, HEAD_MAX_LEN)
            opts = len(markers)
            if opts != len(target):
                skipped += 1
                continue
            splits["train"].append({
                "ids": seq, "markers": markers, "qtype": QTYPES[q["t"]],
                "target": target, "label": target.index(max(target)),
                "qid": qid, "key": key,
            })

    torch.save(splits["train"], DATA / "train_items.pt")
    for s in ("val", "test"):
        with (DATA / f"states-p4-{s}.jsonl").open("w", encoding="utf-8") as fh:
            for r in splits[s]:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    lens = [len(i["ids"]) for i in splits["train"]]
    by_q = collections.Counter(i["qid"] for i in splits["train"])
    keys = {i["key"] for i in splits["train"]}
    conf_train = sum(1 for k in keys if labels[k].get("status") == "confirmed")
    report = {
        "labeled": len(labels), "skipped": skipped,
        "train_findings": len(keys), "train_items": len(splits["train"]),
        "items_by_qid": dict(by_q),
        "train_confirmed_findings": conf_train,
        "val_findings": len(splits["val"]), "test_findings": len(splits["test"]),
        "seq_len_mean": round(sum(lens) / max(1, len(lens))),
        "seq_len_max": max(lens) if lens else 0,
    }
    (DATA / "build-items-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
