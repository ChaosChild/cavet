#!/usr/bin/env python3
"""S0a shape-studio harness: run cavet findings through Jev variants.

Reads finding ids from dataset.json, fetches finding details with the cavet
CLI, submits them to the TypeSafe System One API across the variant matrix,
and records full request/response pairs under runs/ plus per-variant results
back into dataset.json.

Variants (12 calls per finding, 120 across the dataset):
  single-lv(-missing), single-mv(-missing)  one call, full status vocabulary
  twostep-{lv,mv}(-missing)                 step 1: confirmed? (noul, gate at
                                            0.5); if not confirmed, step 2:
                                            dismissed vs not-security choice
Verbosity: lv = string state, terse instructions, bare criteria labels.
           mv = named-field object state, spelled-out instructions and
           criteria definitions (per docs.typesafe.ai guidance: prefer
           objects so each part of the state has a descriptive name).
Missing: adds a state_sufficient noul asking whether anything needed for the
decision is absent from the state.

Usage:
  python harness.py                     # run everything not already recorded
  python harness.py --findings 215a27   # subset by short id
  python harness.py --variants single-mv
  python harness.py --force             # re-run even if recorded
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATASET = HERE / "dataset.json"
RUNS = HERE / "runs"
API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
CONFIRM_GATE = 0.5

# Triage vocabulary: confirmed/dismissed exist today; not-security, deferred
# (reworked with an until-date) and worked-elsewhere are the additions tracked
# in docs/BACKLOG.md. deferred stays an option only in the optimistic
# single-step run; the two-step flow deliberately cannot produce it.
STATUSES = ["confirmed", "dismissed", "not-security", "deferred", "worked-elsewhere"]

PROJECT = {
    "name": "cavet",
    "description": (
        "A Go CLI security-triage tool for coding agents. It runs scanners "
        "(trivy, opengrep, gitleaks, checkov) inside an offline container "
        "engine and records every finding and decision in an append-only "
        "audit log."
    ),
    "note": "This finding comes from a scan of the cavet repository itself.",
}

MV_STATUS_DEFS = {
    "confirmed": (
        "A real security issue in this project that warrants action."
    ),
    "dismissed": (
        "Not worth acting on: a false positive, or a deliberate pattern with "
        "no remaining value to track."
    ),
    "not-security": (
        "Technically real as reported but not a security issue for this "
        "project; it may still be worth tracking outside the security gate."
    ),
    "deferred": (
        "Real and relevant, but action should wait for a later horizon. "
        "Deciding this needs information about fix availability, package "
        "management and shipped usage that is rarely in the finding alone."
    ),
    "worked-elsewhere": (
        "Already being addressed in another tracker or workflow."
    ),
}


def load_key():
    key = os.environ.get("TYPESAFE_API_KEY")
    if key:
        return key
    env = REPO / ".env"
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith("TYPESAFE_API_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("TYPESAFE_API_KEY not found in environment or .env")


KEY = load_key()


def finding_details(fingerprint):
    """Fetch one finding's details through the cavet CLI."""
    out = subprocess.run(
        ["cavet", "finding", fingerprint],
        capture_output=True, text=True, check=True,
    ).stdout
    lines = out.strip().splitlines()
    head = [p.strip() for p in lines[0].split("·")]
    return {
        "id": head[0],
        "severity": head[1],
        "rule": head[2],
        "status": head[3],
        "location": lines[1].strip(),
        "description": "\n".join(ln.strip() for ln in lines[2:]).strip(),
    }


def state_lv(d):
    return (
        f"{d['rule']} ({d['severity']}) at {d['location']}: {d['description']} "
        f"Project: {PROJECT['name']}, {PROJECT['description']} {PROJECT['note']}"
    )


def state_mv(d):
    return {
        "project": {
            "name": PROJECT["name"],
            "description": PROJECT["description"],
            "context": PROJECT["note"],
        },
        "finding": {
            "rule_id": d["rule"],
            "severity": d["severity"],
            "location": d["location"],
            "description": d["description"],
            "current_status": d["status"],
        },
    }


def q_single(verbosity):
    if verbosity == "lv":
        return {"status": {
            "type": "choice",
            "instructions": "Which triage status fits this finding?",
            "criteria": {s: None for s in STATUSES},
        }}
    return {"status": {
        "type": "choice",
        "instructions": (
            "You are triaging a security scanner finding for the project "
            "described in the state. Using only the finding and the project "
            "context provided, which triage status fits it best?"
        ),
        "criteria": MV_STATUS_DEFS,
    }}


def q_missing(verbosity):
    if verbosity == "lv":
        return {"state_sufficient": {
            "type": "noul",
            "instructions": (
                "Is the information provided sufficient to choose the "
                "correct status?"
            ),
        }}
    return {"state_sufficient": {
        "type": "noul",
        "instructions": (
            "Before deciding the triage status: does the state contain "
            "everything a knowledgeable reviewer would need to decide this "
            "finding with confidence? Answer no if a specific kind of "
            "information is missing, for example whether the flagged file is "
            "production code or a test fixture, whether the affected package "
            "is imported by production code, whether a flagged secret is "
            "real, or whether a fix is available."
        ),
        "criteria": {
            "true": "The state is sufficient; the decision can be made from what is provided.",
            "false": "Specific information is missing from the state and the status decision would be a guess.",
        },
    }}


def q_confirm(verbosity):
    if verbosity == "lv":
        return {"is_confirmed": {
            "type": "noul",
            "instructions": (
                "Is this a genuine security finding that warrants action in "
                "this project?"
            ),
        }}
    return {"is_confirmed": {
        "type": "noul",
        "instructions": (
            "You are triaging a security scanner finding for the project "
            "described in the state. Does this finding describe a genuine "
            "security issue that warrants action in this project? Judge "
            "only from the finding and the project context provided."
        ),
        "criteria": {
            "true": "A real security issue in this project that warrants action.",
            "false": "Not actionable as a security issue in this project: a false positive, a test fixture or fake value, a deliberate pattern, or real but without security impact here.",
        },
    }}


def q_closure(verbosity):
    if verbosity == "lv":
        return {"closure": {
            "type": "choice",
            "instructions": (
                "The finding is not actionable as a security issue. Which "
                "closure fits it?"
            ),
            "criteria": {"dismissed": None, "not-security": None},
        }}
    return {"closure": {
        "type": "choice",
        "instructions": (
            "The finding is not actionable as a security issue in this "
            "project. Which closure fits it best?"
        ),
        "criteria": {
            "dismissed": MV_STATUS_DEFS["dismissed"],
            "not-security": MV_STATUS_DEFS["not-security"],
        },
    }}


VARIANTS = {
    "single-lv":          {"flow": "single",  "verbosity": "lv", "missing": False},
    "single-lv-missing":  {"flow": "single",  "verbosity": "lv", "missing": True},
    "single-mv":          {"flow": "single",  "verbosity": "mv", "missing": False},
    "single-mv-missing":  {"flow": "single",  "verbosity": "mv", "missing": True},
    "twostep-lv":         {"flow": "twostep", "verbosity": "lv", "missing": False},
    "twostep-lv-missing": {"flow": "twostep", "verbosity": "lv", "missing": True},
    "twostep-mv":         {"flow": "twostep", "verbosity": "mv", "missing": False},
    "twostep-mv-missing": {"flow": "twostep", "verbosity": "mv", "missing": True},
}


def call_jev(state, questions):
    payload = {"model": MODEL, "state": state, "questions": questions}
    body = json.dumps(payload).encode("utf-8")
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for attempt in range(4):
        t0 = time.perf_counter()
        req = urllib.request.Request(
            API_URL, data=body, method="POST",
            headers={"Authorization": "Bearer " + KEY,
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
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


def summarize(resp):
    """Compact answer view for dataset.json."""
    out = {}
    for qid, a in (resp.get("answers") or {}).items():
        if a.get("type") == "noul":
            out[qid] = {"noul": a.get("noul")}
        elif a.get("type") == "choice":
            out[qid] = {"choice": a.get("choice"),
                        "confidence": a.get("confidence"),
                        "probabilities": a.get("probabilities")}
        else:
            out[qid] = a
    return out


def run_single(finding, details, var):
    state = state_lv(details) if var["verbosity"] == "lv" else state_mv(details)
    questions = q_single(var["verbosity"])
    if var["missing"]:
        questions.update(q_missing(var["verbosity"]))
    call = call_jev(state, questions)
    resp = call.get("response") or {}
    answers = resp.get("answers") or {}
    final = answers.get("status", {}).get("choice")
    return {"calls": [call],
            "final": {"status": final,
                      "state_sufficient": (answers.get("state_sufficient") or {}).get("noul")}}


def run_twostep(finding, details, var):
    state = state_lv(details) if var["verbosity"] == "lv" else state_mv(details)
    s1q = q_confirm(var["verbosity"])
    if var["missing"]:
        s1q.update(q_missing(var["verbosity"]))
    c1 = call_jev(state, s1q)
    a1 = (c1.get("response") or {}).get("answers") or {}
    p_yes = (a1.get("is_confirmed") or {}).get("noul")
    calls = [c1]
    final = {"step1_noul": p_yes,
             "state_sufficient": (a1.get("state_sufficient") or {}).get("noul")}
    if p_yes is not None and p_yes >= CONFIRM_GATE:
        final["status"] = "confirmed"
        final["step2_ran"] = False
    else:
        c2 = call_jev(state, q_closure(var["verbosity"]))
        a2 = (c2.get("response") or {}).get("answers") or {}
        calls.append(c2)
        final["status"] = a2.get("closure", {}).get("choice")
        final["step2_ran"] = True
        final["closure_confidence"] = a2.get("closure", {}).get("confidence")
    return {"calls": calls, "final": final}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", help="comma-separated short ids")
    ap.add_argument("--variants", help="comma-separated variant names")
    ap.add_argument("--force", action="store_true",
                    help="re-run variants already recorded")
    args = ap.parse_args()

    doc = json.loads(DATASET.read_text(encoding="utf-8"))
    want_f = set(args.findings.split(",")) if args.findings else None
    want_v = set(args.variants.split(",")) if args.variants else set(VARIANTS)
    RUNS.mkdir(exist_ok=True)

    total_calls = 0
    for f in doc["findings"]:
        if want_f and f["id"] not in want_f:
            continue
        details = finding_details(f["fingerprint"])
        print(f"[{f['id']}] {details['severity']} {details['rule']} "
              f"({details['status']})")
        for name in want_v:
            var = VARIANTS[name]
            if not args.force and name in f["results"]:
                print(f"    {name}: recorded, skipping")
                continue
            runner = run_single if var["flow"] == "single" else run_twostep
            rec = runner(f, details, var)
            rec.update({"finding": f["id"], "fingerprint": f["fingerprint"],
                        "variant": name})
            (RUNS / f"{f['id']}__{name}.json").write_text(
                json.dumps(rec, indent=2), encoding="utf-8")
            models = {(c.get("response") or {}).get("model") for c in rec["calls"]}
            wall = round(sum(c["wall_ms"] for c in rec["calls"]), 1)
            f["results"][name] = {
                "final": rec["final"],
                "calls": len(rec["calls"]),
                "wall_ms": wall,
                "models": sorted(m for m in models if m),
                "answers": [summarize(c.get("response") or {})
                            for c in rec["calls"]],
            }
            total_calls += len(rec["calls"])
            err = [c for c in rec["calls"] if c.get("error")]
            tag = " ERROR" if err else ""
            print(f"    {name}: {rec['final'].get('status')} "
                  f"({len(rec['calls'])} call(s), {wall} ms){tag}")
            DATASET.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"done, {total_calls} call(s) this run")


if __name__ == "__main__":
    main()
