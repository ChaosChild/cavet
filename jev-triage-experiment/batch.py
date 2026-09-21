#!/usr/bin/env python3
"""Batching experiment for the Jev triage pipeline.

Yesterday's S0a final run triaged 663 findings one request per finding
(1323 calls, 23.5 min, $0.0631). This script re-triages the same frozen
universe with BATCHED requests: N findings per call, two-step cascade kept
(step 1: per-finding is_confirmed + state_sensitive nouls; step 2: closure
choice for the below-gate subset), same state tier as the settled default
(mv + mechanical enrichment + cavet lookup, r3 wording).

Batching strategies:
  similarity  group by (source file, rule family), then chunk to batch size
  severity    group by severity, then chunk to batch size

Question IDs are not sent to the model, so each instruction names its
finding by id (the state carries a matching id field per record).

Usage:
  python batch.py --strategy similarity --sizes 10      # one plan
  python batch.py --all                                  # full sweep
  python batch.py --smoke                                # 6 findings, size 5
"""

import argparse
import json
import sys
import time
from pathlib import Path

import harness
from harness import (KEY, MODEL, CONFIRM_GATE, WORDINGS, PROJECT,
                     path_class, source_excerpt, lookup_output,
                     finding_details, summarize)

HERE = Path(__file__).resolve().parent
FULL = HERE / "full-run.json"
OUT = HERE / "batch-runs"
DETAILS_CACHE = HERE / "details-cache.json"
SIZES = [5, 10, 20, 40]
STRATEGIES = ["similarity", "severity"]
TIMEOUT_S = 120


def rule_family(rule):
    r = rule.lower()
    if r.startswith(("aws-", "ds-", "ckv")):
        return "checkov"
    if "gitleaks" in r or r in ("generic-api-key", "sourcegraph-access-token"):
        return "gitleaks"
    if r.startswith(("cve-", "go-", "ghsa-")):
        return "trivy"
    return "opengrep"


def load_universe():
    full = json.loads(FULL.read_text(encoding="utf-8"))
    cache = (json.loads(DETAILS_CACHE.read_text(encoding="utf-8"))
             if DETAILS_CACHE.exists() else {})
    out = []
    fetched = 0
    for x in full["findings"]:
        fp = x["fingerprint"]
        if fp not in cache:
            cache[fp] = finding_details(fp)
            fetched += 1
        out.append({"fingerprint": fp, "id": x["id"],
                    "severity": x["severity"], "rule": x["rule"],
                    "location": x["location"], "details": cache[fp]})
    if fetched:
        DETAILS_CACHE.write_text(json.dumps(cache), encoding="utf-8")
        print(f"fetched {fetched} finding details via cavet CLI")
    return out


def finding_record(find):
    d = find["details"]
    return {
        "id": find["id"],
        "rule_id": d["rule"],
        "severity": d["severity"],
        "location": d["location"],
        "description": d["description"],
        "path_class": path_class(d["location"].rsplit(":", 1)[0]),
        "source_excerpt": source_excerpt(d["location"]),
        "cavet_lookup": lookup_output(d["rule"]),
    }


def make_batches(findings, strategy, size):
    if strategy == "severity":
        key = lambda f: f["severity"]
    else:
        key = lambda f: (f["location"].rsplit(":", 1)[0],
                         rule_family(f["rule"]))
    ordered = sorted(findings, key=lambda f: (key(f), f["fingerprint"]))
    groups = {}
    for f in ordered:
        groups.setdefault(key(f), []).append(f)
    batches = []
    for _, group in sorted(groups.items()):
        for i in range(0, len(group), size):
            batches.append(group[i:i + size])
    return batches


def batch_call(state, questions):
    payload = {"model": MODEL, "state": state, "questions": questions}
    body = json.dumps(payload).encode("utf-8")
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for attempt in range(4):
        t0 = time.perf_counter()
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            harness.API_URL, data=body, method="POST",
            headers={"Authorization": "Bearer " + KEY,
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                ms = round((time.perf_counter() - t0) * 1000, 1)
                return {"ts": ts, "http": r.status, "wall_ms": ms,
                        "request": payload, "response": json.loads(r.read())}
        except urllib.error.HTTPError as e:
            ms = round((time.perf_counter() - t0) * 1000, 1)
            err = e.read().decode(errors="replace")[:500]
            if e.code in (429, 529) and attempt < 3:
                time.sleep(2 * (2 ** attempt))
                continue
            return {"ts": ts, "http": e.code, "wall_ms": ms,
                    "request": payload, "error": err}
        except urllib.error.URLError as e:
            if attempt < 3:
                time.sleep(2 * (2 ** attempt))
                continue
            return {"ts": ts, "http": None, "wall_ms":
                    round((time.perf_counter() - t0) * 1000, 1),
                    "request": payload, "error": str(e)}


def q_confirmed(find):
    fid = find["id"]
    return {f"{fid}_confirmed": {
        "type": "noul",
        "instructions": (
            f"The finding with id `{fid}` in the state: does it describe a "
            "genuine security issue that warrants action in this project? "
            "Judge only from that finding's record and the project context."
        ),
        "criteria": {
            "true": "A real security issue in this project that warrants action.",
            "false": "Not actionable as a security issue in this project: either the security claim is wrong here (false positive, misread, safe as used) or the observation is genuinely valid but not a security concern (test fixture, non-shipped code, deliberate engineering choice).",
        },
    }, f"{fid}_sufficient": {
        "type": "noul",
        "instructions": (
            f"For the finding with id `{fid}` in the state: does the state "
            "contain everything a knowledgeable reviewer would need to "
            "decide it with confidence? Answer no if a specific kind of "
            "information is missing, for example whether the flagged file "
            "is production code or a test fixture, whether the affected "
            "package is imported by production code, whether a flagged "
            "secret is real, or whether a fix is available."
        ),
        "criteria": {
            "true": "The state is sufficient; the decision can be made from what is provided.",
            "false": "Specific information is missing from the state and the status decision would be a guess.",
        },
    }}


def q_closure(find):
    fid = find["id"]
    defs = WORDINGS["r3"]
    return {f"{fid}_closure": {
        "type": "choice",
        "instructions": (
            f"The finding with id `{fid}` in the state is not actionable "
            "as a security issue in this project. Which closure fits it best?"
        ),
        "criteria": {
            "dismissed": defs["dismissed"],
            "not-security": defs["not-security"],
        },
    }}


def run_plan(findings, strategy, size, force=False):
    out_path = OUT / f"{strategy}-{size:02d}.json"
    if out_path.exists() and not force:
        print(f"[{strategy}-{size:02d}] recorded, skipping")
        return json.loads(out_path.read_text(encoding="utf-8"))
    batches = make_batches(findings, strategy, size)
    calls = []
    per_finding = {}
    t0 = time.perf_counter()

    def absorb(call):
        calls.append(call)
        resp = call.get("response") or {}
        u = resp.get("usage") or {}
        return u.get("input_tokens", 0), u.get("output_tokens", 0)

    in_tok = out_tok = 0
    step2_hold = []
    for bi, batch in enumerate(batches):
        state = {"project": PROJECT,
                 "findings": [finding_record(f) for f in batch]}
        questions = {}
        for f in batch:
            questions.update(q_confirmed(f))
        c1 = batch_call(state, questions)
        it, ot = absorb(c1)
        in_tok += it
        out_tok += ot
        a1 = (c1.get("response") or {}).get("answers") or {}
        for f in batch:
            fid = f["id"]
            p1 = (a1.get(f"{fid}_confirmed") or {}).get("noul")
            suff = (a1.get(f"{fid}_sufficient") or {}).get("noul")
            per_finding[fid] = {"step1_noul": p1, "state_sufficient": suff,
                                "batch": bi}
            if p1 is None:
                per_finding[fid]["status"] = None
                per_finding[fid]["error"] = "missing step1 answer"
            elif p1 >= CONFIRM_GATE:
                per_finding[fid]["status"] = "confirmed"
            else:
                step2_hold.append((f, bi))
        c2 = None
        if step2_hold:
            s2q = {}
            for f, _ in step2_hold:
                s2q.update(q_closure(f))
            c2 = batch_call(state, s2q)
            it, ot = absorb(c2)
            in_tok += it
            out_tok += ot
            a2 = (c2.get("response") or {}).get("answers") or {}
            for f, bi2 in step2_hold:
                fid = f["id"]
                ans = a2.get(f"{fid}_closure") or {}
                per_finding[fid]["status"] = ans.get("choice")
                per_finding[fid]["closure_confidence"] = ans.get("confidence")
                per_finding[fid]["closure_probabilities"] = ans.get("probabilities")
            step2_hold = []
        if (bi + 1) % 10 == 0:
            print(f"  [{strategy}-{size:02d}] batch {bi + 1}/{len(batches)}")

    doc = {
        "strategy": strategy, "size": size,
        "wording": "r3",
        "batches": len(batches),
        "calls": calls,
        "findings": per_finding,
        "totals": {
            "calls": len(calls),
            "wall_s": round(time.perf_counter() - t0, 1),
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "errors": sum(1 for v in per_finding.values() if v.get("error")),
        },
    }
    OUT.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    errs = doc["totals"]["errors"]
    print(f"[{strategy}-{size:02d}] done: {len(batches)} batches, "
          f"{len(calls)} calls, {doc['totals']['wall_s']} s, "
          f"{in_tok}/{out_tok} tok, {errs} missing answers")
    return doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strategy", choices=STRATEGIES)
    ap.add_argument("--sizes", help="comma-separated batch sizes")
    ap.add_argument("--all", action="store_true", help="full sweep")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    findings = load_universe()
    if args.smoke:
        findings = findings[:6]
        plans = [("similarity", 5)]
    elif args.all:
        plans = [(s, z) for s in STRATEGIES for z in SIZES]
    else:
        if not args.strategy or not args.sizes:
            sys.exit("need --strategy and --sizes, or --all, or --smoke")
        plans = [(args.strategy, int(z))
                 for z in args.sizes.split(",")]

    for strategy, size in plans:
        run_plan(findings, strategy, size, force=args.force)


if __name__ == "__main__":
    main()
