#!/usr/bin/env python3
"""S0a shape-studio harness: run cavet findings through Jev variants.

Reads finding ids from dataset.json, fetches finding details with the cavet
CLI, submits them to the TypeSafe System One API across the variant matrix,
and records full request/response pairs under runs/ plus per-variant results
back into dataset.json.

State tiers:
  lv            string state, terse instructions, bare criteria labels
  mv            named-field object state, spelled-out instructions and
                criteria (docs.typesafe.ai: prefer objects with descriptive
                names; give every option a description)
  +enriched     mv plus mechanical_context: a deterministic path-class rule
                and a fixed-width source excerpt around the finding location
                (file reads and prefix rules only, no agent involvement)
  +lookup       lv/mv plus the raw `cavet lookup <identifier>` output (CVE
                advisory data: fixed version, KEV, EPSS, CVSS; rule -> CWE
                mapping; deterministic CLI, identifiers only)

Flows: single (one call, full status vocabulary) and twostep (step 1
is_confirmed noul, gate at 0.5; step 2 closure choice dismissed vs
not-security). Optional state_sufficient noul ("anything missing?").

Wording versions (MV criteria definitions only):
  r2  not-security = valid observation, no security concern; dismissed =
      security claim wrong here
  r3  r2 with the not-security examples spelled out (documented deliberate
      choices, design artifacts/docs/mocks, test fixtures)

Usage:
  python harness.py                     # run everything not already recorded
  python harness.py --findings 215a27   # subset by short id
  python harness.py --variants single-mv
  python harness.py --force             # re-run even if recorded
"""

import argparse
import glob
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

WORDINGS = {
    "r2": {
        "confirmed": "A real security issue in this project that warrants action.",
        "dismissed": (
            "The security claim itself is wrong for this project: a false "
            "positive, a misread of the code, or a pattern that is safe as "
            "used. Nothing valid remains to track."
        ),
        "not-security": (
            "A genuinely valid observation about this project's code or "
            "dependencies, but not a security concern here: a deliberate "
            "engineering choice, test fixtures or other non-shipped code, or a "
            "quality issue. Worth tracking as ordinary engineering work."
        ),
        "deferred": (
            "Real and relevant, but action should wait for a later horizon. "
            "Deciding this needs information about fix availability, package "
            "management and shipped usage that is rarely in the finding alone."
        ),
        "worked-elsewhere": (
            "Already being addressed in another tracker or workflow."
        ),
    },
    "r3": {
        "confirmed": "A real security issue in this project that warrants action.",
        "dismissed": (
            "The security claim itself is wrong for this project: a false "
            "positive, a misread of the code, or a pattern that is safe as "
            "used. Nothing valid remains to track."
        ),
        "not-security": (
            "A genuinely valid observation about this project's code or "
            "dependencies, but not a security concern here. Examples: a "
            "documented, deliberate engineering choice; a test fixture or "
            "other non-shipped code such as design artifacts, mocks and "
            "documentation; a quality or correctness issue. These deserve "
            "tracking as ordinary engineering work, outside the security gate."
        ),
        "deferred": (
            "Real and relevant, but action should wait for a later horizon. "
            "Deciding this needs information about fix availability, package "
            "management and shipped usage that is rarely in the finding alone."
        ),
        "worked-elsewhere": (
            "Already being addressed in another tracker or workflow."
        ),
    },
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


def path_class(path):
    """Deterministic path classification: prefix rules only."""
    p = path.replace("\\", "/")
    if "testdata" in p or "fixture" in p:
        return "test fixture or test data (non-shipped; consumed by tests)"
    if p.startswith("docs/"):
        return "documentation or design artifact (not executed by the product)"
    if p.startswith("internal/serve/assets/"):
        return "shipped dashboard asset (executed by cavet serve on loopback)"
    if p.startswith("engine/"):
        return "container image build definition (shipped as the scanner engine image)"
    if p.startswith("internal/") or p.startswith("cmd/"):
        return "production code"
    return "repository file"


def source_excerpt(location, before=6, after=6, line_cap=200, total_cap=800):
    """Fixed-width source excerpt around the finding location.

    Lockfile and minified lines can be tens of KB long, so both per-line
    and total length are capped: an unbounded excerpt at batch size 40
    deterministically exceeds the API's request-size limit.
    """
    try:
        path, line = location.rsplit(":", 1)
        line = int(line)
    except ValueError:
        return None
    full = REPO / path
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    out = "\n".join(f"{n:5d} | {lines[n - 1][:line_cap]}" for n in range(lo, hi + 1))
    if len(out) > total_cap:
        out = out[:total_cap] + " …[truncated]"
    return out


def lookup_output(rule):
    """Raw `cavet lookup` output for the finding's rule identifier."""
    out = subprocess.run(
        ["cavet", "lookup", rule],
        capture_output=True, text=True,
    )
    text = (out.stdout or "").strip() or (out.stderr or "").strip()
    return text or "no lookup output"


def state_lv(d):
    return (
        f"{d['rule']} ({d['severity']}) at {d['location']}: {d['description']} "
        f"Project: {PROJECT['name']}, {PROJECT['description']} {PROJECT['note']}"
    )


def state_mv(d, fresh=False):
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
            # fresh-init simulation: a just-scanned finding is open; never
            # leak an existing operator verdict into the state
            "current_status": "open" if fresh else d["status"],
        },
    }


def build_state(var, d):
    if var["verbosity"] == "lv":
        st = state_lv(d)
        if var.get("lookup"):
            st = st + " cavet lookup output: " + " ".join(
                lookup_output(d["rule"]).split())
        return st
    st = state_mv(d, fresh=var.get("fresh", False))
    if var.get("enriched"):
        st["mechanical_context"] = {
            "path_class": path_class(d["location"].rsplit(":", 1)[0]),
            "source_excerpt": source_excerpt(d["location"]),
        }
    if var.get("lookup"):
        st["cavet_lookup"] = lookup_output(d["rule"])
    return st


def q_single(verbosity, defs):
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
        "criteria": defs,
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
            "false": "Not actionable as a security issue in this project: either the security claim is wrong here (false positive, misread, safe as used) or the observation is genuinely valid but not a security concern (test fixture, non-shipped code, deliberate engineering choice).",
        },
    }}


def q_closure(verbosity, defs):
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
            "dismissed": defs["dismissed"],
            "not-security": defs["not-security"],
        },
    }}


VARIANTS = {
    # rounds 1-2 baseline matrix (wording r2)
    "single-lv":          {"flow": "single",  "verbosity": "lv", "missing": False, "wording": "r2"},
    "single-lv-missing":  {"flow": "single",  "verbosity": "lv", "missing": True,  "wording": "r2"},
    "single-mv":          {"flow": "single",  "verbosity": "mv", "missing": False, "wording": "r2"},
    "single-mv-missing":  {"flow": "single",  "verbosity": "mv", "missing": True,  "wording": "r2"},
    "twostep-lv":         {"flow": "twostep", "verbosity": "lv", "missing": False, "wording": "r2"},
    "twostep-lv-missing": {"flow": "twostep", "verbosity": "lv", "missing": True,  "wording": "r2"},
    "twostep-mv":         {"flow": "twostep", "verbosity": "mv", "missing": False, "wording": "r2"},
    "twostep-mv-missing": {"flow": "twostep", "verbosity": "mv", "missing": True,  "wording": "r2"},
    # r3 wording nudge (mv only: lv carries no definitions)
    "single-mv-r3":           {"flow": "single",  "verbosity": "mv", "missing": False, "wording": "r3"},
    "single-mv-r3-missing":   {"flow": "single",  "verbosity": "mv", "missing": True,  "wording": "r3"},
    "twostep-mv-r3":          {"flow": "twostep", "verbosity": "mv", "missing": False, "wording": "r3"},
    "twostep-mv-r3-missing":  {"flow": "twostep", "verbosity": "mv", "missing": True,  "wording": "r3"},
    # mechanical enrichment (mv, r2 defs to isolate the axis)
    "single-mv-enriched":          {"flow": "single",  "verbosity": "mv", "missing": False, "wording": "r2", "enriched": True},
    "single-mv-enriched-missing":  {"flow": "single",  "verbosity": "mv", "missing": True,  "wording": "r2", "enriched": True},
    "twostep-mv-enriched-missing": {"flow": "twostep", "verbosity": "mv", "missing": True,  "wording": "r2", "enriched": True},
    # r2-wording baselines for round-1 findings whose mv-missing rows are r1 wording
    "single-mv-missing-r2": {"flow": "single",  "verbosity": "mv", "missing": True,  "wording": "r2"},
    "twostep-mv-missing-r2": {"flow": "twostep", "verbosity": "mv", "missing": True,  "wording": "r2"},
    # settled S0a default: mv + mechanical enrichment + lookup, r3 wording,
    # fresh-init semantics (current_status is always open)
    "final": {"flow": "twostep", "verbosity": "mv", "missing": True,  "wording": "r3", "enriched": True, "lookup": True, "fresh": True},
    # cavet lookup axis (lv/mv, with the missing question so sufficiency moves are visible)
    "single-lv-lookup-m": {"flow": "single",  "verbosity": "lv", "missing": True, "wording": "r2", "lookup": True},
    "single-mv-lookup-m": {"flow": "single",  "verbosity": "mv", "missing": True, "wording": "r2", "lookup": True},
    "twostep-lv-lookup-m": {"flow": "twostep", "verbosity": "lv", "missing": True, "wording": "r2", "lookup": True},
    "twostep-mv-lookup-m": {"flow": "twostep", "verbosity": "mv", "missing": True, "wording": "r2", "lookup": True},
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


def run_single(state, var):
    questions = q_single(var["verbosity"], WORDINGS[var["wording"]])
    if var["missing"]:
        questions.update(q_missing(var["verbosity"]))
    call = call_jev(state, questions)
    answers = (call.get("response") or {}).get("answers") or {}
    return {"calls": [call],
            "final": {"status": answers.get("status", {}).get("choice"),
                      "state_sufficient": (answers.get("state_sufficient") or {}).get("noul")}}


def run_twostep(state, var):
    defs = WORDINGS[var["wording"]]
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
        c2 = call_jev(state, q_closure(var["verbosity"], defs))
        a2 = (c2.get("response") or {}).get("answers") or {}
        calls.append(c2)
        final["status"] = a2.get("closure", {}).get("choice")
        final["step2_ran"] = True
        final["closure_confidence"] = a2.get("closure", {}).get("confidence")
    return {"calls": calls, "final": final}


def enumerate_all_findings():
    """Every distinct fingerprint cavet has flagged, minus remediated ones.

    Read-only enumeration from the append-only log (the CLI's log view caps
    at 50 rows today); a fresh cavet init would re-flag exactly this set.
    """
    events = []
    for f in glob.glob(str(REPO / ".cavet" / "log" / "events-*.jsonl")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    det, rem = {}, set()
    for e in events:
        if e["event"] == "detected":
            det.setdefault(e["fingerprint"], e)
        elif e["event"] == "remediated" and e.get("fingerprint"):
            rem.add(e["fingerprint"])
    return [fp for fp in det if fp not in rem]


def run_full(args):
    full_path = HERE / "full-run.json"
    if full_path.exists():
        doc = json.loads(full_path.read_text(encoding="utf-8"))
    else:
        doc = {
            "experiment": "jev-triage-s0a-final",
            "note": (
                "Fresh-init simulation: every finding cavet has flagged "
                "(detected events, remediated excluded), triaged by Jev with "
                "current_status open, mv state + mechanical enrichment + "
                "cavet lookup, r3 wording, two-step flow with the "
                "state_sufficient question."
            ),
            "variant": "final",
            "findings": [],
        }
    byfp = {x["fingerprint"]: x for x in doc["findings"]}
    fps = enumerate_all_findings()
    if args.limit:
        fps = fps[: args.limit]
    todo = [fp for fp in fps if "final" not in byfp.get(fp, {}).get("results", {})]
    print(f"full run: {len(fps)} findings in universe, {len(todo)} to run")
    var = VARIANTS["final"]
    done = errors = 0
    for fp in todo:
        try:
            d = finding_details(fp)
        except subprocess.CalledProcessError:
            print(f"  [{fp[:6]}] cavet finding failed, skipping")
            errors += 1
            continue
        rec = byfp.setdefault(fp, {
            "id": fp[:6], "fingerprint": fp,
            "severity": d["severity"], "rule": d["rule"],
            "location": d["location"], "results": {}})
        out = run_twostep(build_state(var, d), var)
        out.update({"finding": rec["id"], "fingerprint": fp,
                    "variant": "final", "wording": var["wording"],
                    "enriched": True, "lookup": True, "fresh": True})
        (RUNS / f"{rec['id']}__final.json").write_text(
            json.dumps(out, indent=2), encoding="utf-8")
        models = {(c.get("response") or {}).get("model") for c in out["calls"]}
        rec["results"]["final"] = {
            "final": out["final"],
            "calls": len(out["calls"]),
            "wall_ms": round(sum(c["wall_ms"] for c in out["calls"]), 1),
            "wording": var["wording"],
            "models": sorted(m for m in models if m),
            "answers": [summarize(c.get("response") or {}) for c in out["calls"]],
        }
        doc["findings"] = list(byfp.values())
        full_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        done += 1
        if done % 25 == 0:
            print(f"  ... {done}/{len(todo)} done")
    print(f"full run complete: {done} processed, {errors} cli errors")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", help="comma-separated short ids")
    ap.add_argument("--variants", help="comma-separated variant names")
    ap.add_argument("--force", action="store_true",
                    help="re-run variants already recorded")
    ap.add_argument("--all", action="store_true",
                    help="fresh-init run over every finding in the log "
                         "into full-run.json")
    ap.add_argument("--limit", type=int,
                    help="cap the --all universe (smoke tests)")
    args = ap.parse_args()

    if args.all:
        run_full(args)
        return

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
        for name in sorted(want_v):
            var = VARIANTS[name]
            if not args.force and name in f["results"]:
                print(f"    {name}: recorded, skipping")
                continue
            state = build_state(var, details)
            runner = run_single if var["flow"] == "single" else run_twostep
            rec = runner(state, var)
            rec.update({"finding": f["id"], "fingerprint": f["fingerprint"],
                        "variant": name, "wording": var["wording"],
                        "enriched": bool(var.get("enriched")),
                        "lookup": bool(var.get("lookup"))})
            (RUNS / f"{f['id']}__{name}.json").write_text(
                json.dumps(rec, indent=2), encoding="utf-8")
            models = {(c.get("response") or {}).get("model") for c in rec["calls"]}
            wall = round(sum(c["wall_ms"] for c in rec["calls"]), 1)
            f["results"][name] = {
                "final": rec["final"],
                "calls": len(rec["calls"]),
                "wall_ms": wall,
                "wording": var["wording"],
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
