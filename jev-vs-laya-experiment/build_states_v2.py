"""Rebuild the frozen state set (v2) with the Jev study's shipped svcx context.

v1 states used the cavet fresh-init variant for every universe, so corpora and
fragmt were judged with cavet's project identity and without the severity-blind
manifest handling that produced the Jev paper's corpus numbers. v2 extracts the
exact per-finding svcx states (identity-free archetype project block, severity
dropped from lockfile findings, wide 25-line non-lockfile excerpts, cavet_lookup)
from the Jev study's final sweep payloads. The cavet universe keeps its v1
states, which already match the cavet finals configuration.

Output: states-v2.jsonl (local-only, like states.jsonl). Corpus:id keys are
restored by matching ids within each corpus against states.jsonl.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
JEV = HERE.parent / "jev-triage-experiment"

SV_INSTRUCTION = (" Severity labels are not grounds for dismissal for manifest "
                  "findings: the affected version is pinned in this project's "
                  "dependency manifest, which the state establishes directly.")

SOURCES = {
    "fragmt": JEV / "batch-runs" / "similarity-40-fragmt-svcx-final1.json",
    "corpus-2": JEV / "s0b" / "runs" / "similarity-40-corpus-2-svcx-final1.json",
    "corpus-3": JEV / "s0b" / "runs" / "similarity-40-corpus-3-svcx-final1.json",
    "corpus-4": JEV / "s0b" / "runs" / "similarity-40-corpus-4-svcx-final1.json",
    "corpus-5": JEV / "s0b" / "runs" / "similarity-40-corpus-5-svcx-final1.json",
}

v1 = [json.loads(line) for line in (HERE / "states.jsonl").read_text(encoding="utf-8").splitlines()]
fp_by_corpus_id = {(r["corpus"], r["id"]): r["fp"] for r in v1}

out = [r for r in v1 if r["corpus"] == "cavet"]
kept_cavet = len(out)
report = {"cavet_from_v1": kept_cavet, "per_corpus": {}}

for corpus, path in SOURCES.items():
    d = json.loads(path.read_text(encoding="utf-8"))
    project = None
    per_call_findings = []
    for c in d["calls"]:
        st = (c.get("request") or {}).get("state") or {}
        if project is None and st.get("project"):
            project = st["project"]
        per_call_findings.extend(st.get("findings") or [])
    # dedupe by id (a finding appears in exactly one batch per sweep)
    by_id = {}
    for f in per_call_findings:
        by_id.setdefault(f["id"], f)
    matched, unmatched = 0, []
    for fid, f in sorted(by_id.items()):
        fp = fp_by_corpus_id.get((corpus, fid))
        if fp is None:
            unmatched.append(fid)
            continue
        out.append({"corpus": corpus, "id": fid, "fp": fp,
                    "state": {"project": project, "finding": f},
                    "lockfile": (f.get("path_class") or "").startswith("dependency manifest")})
        matched += 1
    report["per_corpus"][corpus] = {
        "project_block": {k: (v[:80] if isinstance(v, str) else v) for k, v in (project or {}).items()},
        "findings_extracted": len(by_id), "matched_to_universe": matched, "unmatched": unmatched,
        "sample_excerpt_len": len(next(iter(by_id.values())).get("source_excerpt") or ""),
        "lockfile_records": sum(1 for f in by_id.values()
                                if (f.get("path_class") or "").startswith("dependency manifest")),
    }
    print(f"[{corpus}] extracted {len(by_id)}, matched {matched}, unmatched {len(unmatched)}")

total = len(out)
with (HERE / "states-v2.jsonl").open("w", encoding="utf-8") as fh:
    for r in out:
        fh.write(json.dumps(r) + "\n")
report["total_states"] = total
print(f"total v2 states: {total} (cavet {kept_cavet} from v1 + extracted)")
(HERE / "states-v2-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
print("written: states-v2.jsonl + states-v2-report.json")
