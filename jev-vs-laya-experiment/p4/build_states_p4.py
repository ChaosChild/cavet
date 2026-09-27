"""P4: build the training-state set from a cavet scan of the public vite repository.

Enumerates every detected-minus-remediated fingerprint in the target repo's
.cavet log, fetches finding details through the cavet CLI, and writes states in
the svcx shape used by the frozen v2 corpus states: finding{id, rule_id,
severity (dropped for lockfile findings), location, description, path_class,
source_excerpt, cavet_lookup}. Excerpt geometry matches the v2 states: 25-line
window (before=12, after=12), per-line cap 200, total cap 800.

Repository choice (recorded): vitejs/vite, MIT-licensed public TypeScript
build tool. Chosen for a large dependency manifest (SCA signal), extensive test
fixtures and docs (closure variety), and manageable deep-scan size. No personal
repositories; the clone lives outside this repository and states stay
local-only (embedded source excerpts trip secret scanners, same rule as v2).

Usage:  P4_REPO=<clone> .venv-cpu/Scripts/python p4/build_states_p4.py
Output: p4/states-p4.jsonl + p4/states-p4-report.json
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The fine-tune target repository is machine-local (a shallow clone outside
# this repository) and stays out of committed code: set P4_REPO to the clone
# path. The gitignored states-p4-report.json records which repository ran.
REPO = Path(os.environ["P4_REPO"]) if os.environ.get("P4_REPO") else None
OUT = HERE / "states-p4.jsonl"

PROJECT = {
    "name": "vite",
    "description": (
        "An open-source TypeScript frontend build tool: a dev server that "
        "serves source files over native ES modules with hot reload, and a "
        "production build pipeline that bundles, minifies and code-splits "
        "web applications. Its declared dependencies are installed verbatim "
        "in the development and CI environments of this project; a small "
        "subset ships inside the published npm package."
    ),
    "note": "This finding comes from a scan of the vite repository itself.",
}

LOCKFILE_NAMES = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock",
                  "npm-shrinkwrap.json", "bun.lock", "bun.lockb", "deno.lock"}

LOCKFILE_CLASS = ("dependency manifest (lockfile) pinning the exact dependency "
                  "versions installed in deployments of this project")


def path_class(path):
    """Prefix-rule classification for the vite layout, mirroring the v2 states."""
    p = path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    if base in LOCKFILE_NAMES:
        return LOCKFILE_CLASS
    parts = p.split("/")
    first = parts[0] if parts else ""
    if first == "docs":
        return "documentation (not executed by the product)"
    if first in ("__tests__", "test", "tests", "e2e", "playground") \
            or base.endswith((".test.ts", ".test.js", ".test.tsx", ".spec.ts", ".spec.js")):
        return "test code or fixture (non-shipped)"
    if len(parts) >= 3 and parts[0] == "packages" and parts[2] == "src":
        return "production code"
    return "repository file"


def source_excerpt(location, before=12, after=12, line_cap=200, total_cap=800):
    """Fixed-width excerpt around the finding location, same caps as v2."""
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


def finding_details(fp):
    """One finding's details through the cavet CLI; verdict lines stripped."""
    out = subprocess.run(
        ["cavet", "finding", fp], capture_output=True, text=True, check=True,
        cwd=str(REPO),
    ).stdout
    lines = out.strip().splitlines()
    head = [p.strip() for p in lines[0].split("·")]
    body = [ln.strip() for ln in lines[2:]
            if not ln.strip().startswith("verdict:")]
    return {
        "id": head[0],
        "severity": head[1],
        "rule": head[2],
        "status": head[3],
        "location": lines[1].strip(),
        "description": "\n".join(body).strip(),
    }


def lookup_output(rule):
    out = subprocess.run(["cavet", "lookup", rule], capture_output=True, text=True,
                         cwd=str(REPO))
    text = (out.stdout or "").strip() or (out.stderr or "").strip()
    return text or "no lookup output"


def enumerate_findings():
    det, rem = {}, set()
    for f in sorted((REPO / ".cavet" / "log").glob("events-*.jsonl")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                if e["event"] == "detected":
                    det.setdefault(e["fingerprint"], e)
                elif e["event"] == "remediated" and e.get("fingerprint"):
                    rem.add(e["fingerprint"])
    return [fp for fp in det if fp not in rem]


def main():
    if REPO is None or not REPO.exists():
        sys.exit("set P4_REPO to the cloned target repository (a shallow clone outside this repository)")
    fps = enumerate_findings()
    print(f"universe: {len(fps)} findings", flush=True)
    out, errors = [], 0
    for i, fp in enumerate(fps):
        try:
            d = finding_details(fp)
        except subprocess.CalledProcessError as e:
            print(f"  [{fp[:6]}] cavet finding failed: {e.stderr[:120]}", flush=True)
            errors += 1
            continue
        lockfile = path_class(d["location"].rsplit(":", 1)[0]) == LOCKFILE_CLASS
        finding = {
            "id": d["id"],
            "rule_id": d["rule"],
            "location": d["location"],
            "description": d["description"],
            "path_class": path_class(d["location"].rsplit(":", 1)[0]),
            "source_excerpt": source_excerpt(d["location"]),
            "cavet_lookup": lookup_output(d["rule"]),
        }
        if not lockfile:
            finding["severity"] = d["severity"]
        out.append({"corpus": "vite-p4", "id": d["id"], "fp": fp,
                    "state": {"project": PROJECT, "finding": finding},
                    "lockfile": lockfile})
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(fps)} built", flush=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    import collections
    report = {
        "repo": "vitejs/vite (public, MIT)",
        "total_states": len(out),
        "cli_errors": errors,
        "lockfile_records": sum(1 for r in out if r["lockfile"]),
        "path_classes": dict(collections.Counter(
            r["state"]["finding"]["path_class"][:44] for r in out)),
        "severity_dropped": sum(1 for r in out if "severity" not in r["state"]["finding"]),
    }
    (HERE / "states-p4-report.json").write_text(json.dumps(report, indent=1),
                                                encoding="utf-8")
    print(json.dumps(report, indent=1))
    print(f"written: {OUT.name} ({len(out)} states, {errors} errors)")


if __name__ == "__main__":
    sys.exit(main())
