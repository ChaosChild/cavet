#!/usr/bin/env python3
"""S0b expansion runner: run the adopted Jev triage configuration against
another repository (JS projects first).

The project directory comes from --project-dir at invocation time (never
committed). Project identity is read mechanically from package.json
(name, description). Path classification uses generic JS-project prefix
rules. Everything else is the adopted default: batched two-step cascade,
similarity grouping, mv state + mechanical enrichment + cavet lookup,
r3 wording, current_status always open, sufficiency question included.

Usage:
  python s0b.py --project-dir ../fragmt            # full run
  python s0b.py --project-dir ../fragmt --limit 6  # smoke
"""

import argparse
import json
import glob
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import batch
from batch import run_plan

OUT_NAME = "s0b-{project}.json"


def js_path_class(path):
    """Generic JS-project path classification: prefix rules only."""
    p = path.replace("\\", "/")
    parts = p.split("/")
    low = p.lower()
    if "test" in low or "spec." in low or "fixture" in low:
        return "test code or fixture (non-shipped)"
    if parts and parts[0] == "docs":
        return "documentation (not executed by the product)"
    if parts and parts[0] in ("dist", "build-logs", "build", "out"):
        return "generated build output (not source)"
    if "dockerfile" in p or "docker-compose" in p:
        return "container image build definition"
    if parts and parts[0] in ("src", "ui", "app", "lib"):
        return "production code"
    return "repository file"


def load_project_universe(project_dir):
    """Detected minus remediated, from the project's own cavet log."""
    events = []
    for f in glob.glob(str(project_dir / ".cavet" / "log" / "events-*.jsonl")):
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
    out = []
    for fp, e in det.items():
        if fp in rem:
            continue
        d = e["data"]
        out.append({"fingerprint": fp, "id": fp[:6],
                    "severity": d.get("severity"), "rule": d.get("rule"),
                    "location": f"{d.get('path')}:{d.get('line')}",
                    "details": None})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--size", type=int, default=40)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    proj = Path(args.project_dir).resolve()
    if not (proj / ".cavet").exists():
        sys.exit(f"no .cavet state in {proj}")
    import re
    if re.fullmatch(r"corpus-\d+", proj.name):
        # benchmark subjects: never read package.json identity — the
        # subject's own name must not reach the model or any record
        name = proj.name
        desc = "De-identified benchmark repository used for triage research."
    else:
        pkg_path = proj / "package.json"
        if pkg_path.exists():
            pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
            name = pkg.get("name") or proj.name
            desc = pkg.get("description") or ""
        else:
            name = proj.name
            desc = "De-identified benchmark repository used for triage research."
    os.chdir(proj)  # cavet CLI calls resolve against the project repo

    batch.PROJECT = {
        "name": name,
        "description": desc,
        "note": f"This finding comes from a scan of the {name} repository itself.",
    }
    if name.startswith("corpus-"):
        # benchmark subjects: finding-level records (paths, descriptions)
        # stay under the gitignored s0b/ area, never in committed files
        batch.OUT = HERE / "s0b" / "runs"
        batch.DETAILS_CACHE = HERE / "s0b" / f"details-cache-{name}.json"
    batch.path_class = js_path_class
    batch.DETAILS_CACHE = HERE / f"details-cache-{name}.json"

    findings = load_project_universe(proj)
    cache = (json.loads(batch.DETAILS_CACHE.read_text(encoding="utf-8"))
             if batch.DETAILS_CACHE.exists() else {})
    fetched = 0
    for f in findings:
        if f["fingerprint"] not in cache:
            cache[f["fingerprint"]] = batch.finding_details(f["fingerprint"])
            fetched += 1
        f["details"] = cache[f["fingerprint"]]
    if fetched:
        batch.DETAILS_CACHE.write_text(json.dumps(cache), encoding="utf-8")
        print(f"fetched {fetched} finding details via cavet CLI")
    if args.limit:
        findings = findings[: args.limit]

    print(f"S0b run: project={name}, findings={len(findings)}, "
          f"size={args.size}, workers={args.workers}")
    run_plan(findings, "similarity", args.size, force=args.force,
             workers=args.workers, tag=f"-{name}")


if __name__ == "__main__":
    main()
