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
  python s0b.py --project-dir ... --variant svcx   # SV+CX counterfactual

Variants (mechanical counterfactuals, recorded in the output doc):
  sv   severity-blind lockfile findings: drop the severity field from
       lockfile-finding records and append the severity-blind instruction
       to their is_confirmed question
  cx   code-context: widen the source excerpt of non-lockfile findings
       to before=25, after=25
  svcx both at once
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


LOCKFILE_BASENAMES = {
    "bun.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "requirements.txt", "poetry.lock", "uv.lock",
    "pipfile.lock", "cargo.lock", "composer.lock", "gemfile.lock",
}
LOCKFILE_CLASS = ("dependency manifest (lockfile) pinning the exact "
                  "dependency versions installed in deployments of this project")
SV_INSTRUCTION = (" Severity labels are not grounds for dismissal for manifest "
                  "findings: the affected version is pinned in this project's "
                  "dependency manifest, which the state establishes directly.")


def is_lockfile_finding(location):
    """True when the location basename (lowercase, before :line) is a lockfile."""
    return Path(location.rsplit(":", 1)[0]).name.lower() in LOCKFILE_BASENAMES


def apply_variant(variant):
    """Wrap the batch hooks so the SV/CX counterfactuals reach the requests."""
    if variant == "none":
        return
    orig_record, orig_q, orig_excerpt = (
        batch.finding_record, batch.q_confirmed, batch.source_excerpt)

    def finding_record(find):
        rec = orig_record(find)
        if "sv" in variant and is_lockfile_finding(find["location"]):
            rec.pop("severity", None)
        return rec

    def q_confirmed(find):
        questions = orig_q(find)
        if "sv" in variant and is_lockfile_finding(find["location"]):
            key = f"{find['id']}_confirmed"
            questions[key]["instructions"] += SV_INSTRUCTION
        return questions

    def source_excerpt(location, before=6, after=6):
        if "cx" in variant and not is_lockfile_finding(location):
            before = after = 25
        return orig_excerpt(location, before, after)

    batch.finding_record = finding_record
    batch.q_confirmed = q_confirmed
    batch.source_excerpt = source_excerpt


def detect_archetype(project_dir):
    """Mechanical, identity-free project context from tree markers only."""
    entries = {p.name.lower() for p in project_dir.iterdir() if p.is_file()}
    if "go.mod" in entries:
        return ("A Go software project: its go.sum pins the exact checksums of "
                "the dependency versions compiled into this project's builds, "
                "and dependency findings against the manifest describe versions "
                "present in those builds.")
    if "package.json" in entries and entries & {
            "bun.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        return ("A Node.js software project that ships a dependency lockfile: "
                "its declared dependencies are installed verbatim in "
                "production deployments of this project.")
    if entries & {"pyproject.toml", "requirements.txt", "uv.lock"}:
        return ("A Python software project whose dependency manifests pin the "
                "exact dependency versions installed in deployments of this "
                "project.")
    return None


def js_path_class(path):
    """Generic JS-project path classification: prefix rules only."""
    p = path.replace("\\", "/")
    parts = p.split("/")
    low = p.lower()
    if parts and parts[-1].lower() in LOCKFILE_BASENAMES:
        return LOCKFILE_CLASS
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
    ap.add_argument("--variant", choices=["none", "svcx"], default="svcx",
                    help="severity-blind lockfile handling (adopted default: "
                         "svcx); none restores pre-adoption behavior")
    ap.add_argument("--tag", default="",
                    help="extra output-file suffix, e.g. run repetitions")
    args = ap.parse_args()

    proj = Path(args.project_dir).resolve()
    if not (proj / ".cavet").exists():
        sys.exit(f"no .cavet state in {proj}")
    import re
    if re.fullmatch(r"corpus-\d+", proj.name):
        # benchmark subjects: never read package.json identity — the
        # subject's own name must not reach the model or any record
        name = proj.name
        archetype = detect_archetype(proj)
        desc = archetype or ("De-identified benchmark repository used for "
                             "triage research.")
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
    batch.REPO = proj  # source excerpts resolve against this project, not
    # the cavet root (the s0b excerpt gap found 2026-09-21)

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
    elif name == "fragmt":
        batch.DETAILS_CACHE = HERE / "details-cache-fragmt.json"
    else:
        batch.DETAILS_CACHE = HERE / f"details-cache-{name}.json"
    batch.path_class = js_path_class

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
          f"size={args.size}, workers={args.workers}, variant={args.variant}")
    apply_variant(args.variant)
    tag = f"-{name}" if args.variant == "none" else f"-{name}-{args.variant}"
    tag += args.tag
    doc = run_plan(findings, "similarity", args.size, force=args.force,
                   workers=args.workers, tag=tag)
    if args.variant != "none":
        # run_plan already wrote the doc; re-record it with the variant stamp
        # (calls and per-finding records are carried in the doc unchanged).
        doc["variant"] = args.variant
        out_path = batch.OUT / f"similarity-{args.size:02d}{tag}.json"
        out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
