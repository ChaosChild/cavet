#!/usr/bin/env python3
"""Build full-run-report.md: Jev's fresh-init triage of the whole cavet
finding set, diffed against the operator's recorded verdicts.

Read-only over .cavet/log (verdicts and reasons are already public in the
committed log). Writes full-run-report.md next to this script.
"""

import glob
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def load_log_verdicts():
    tri = {}
    for f in glob.glob(str(REPO / ".cavet" / "log" / "events-*.jsonl")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                if e["event"] == "triaged":
                    tri[e["fingerprint"]] = e["data"]
    return tri


def main():
    full = json.loads((HERE / "full-run.json").read_text(encoding="utf-8"))
    ds = json.loads((HERE / "dataset.json").read_text(encoding="utf-8"))
    curated = {f["fingerprint"]: f for f in ds["findings"]}
    tri = load_log_verdicts()

    findings = full["findings"]
    calls = sum(x["results"]["final"]["calls"] for x in findings)
    wall = sum(x["results"]["final"]["wall_ms"] for x in findings)

    by_status = {}
    for x in findings:
        s = x["results"]["final"]["final"].get("status")
        by_status[s] = by_status.get(s, 0) + 1

    # classification
    serious = []        # operator and Jev disagree on actionable vs not
    closure_dis = []    # both say not actionable, but different closure
    confirmed_match = 0
    not_actionable_match = 0
    jev_confirmed_open = []
    untriaged = 0
    suff_all = []

    for x in findings:
        r = x["results"]["final"]["final"]
        status = r.get("status")
        suff = r.get("state_sufficient")
        if suff is not None:
            suff_all.append(suff)
        t = tri.get(x["fingerprint"])
        c = curated.get(x["fingerprint"], {})
        exp_c = c.get("expected_closure")
        row = {
            "id": x["id"], "sev": x["severity"], "rule": x["rule"],
            "loc": x["location"], "status": status,
            "p1": r.get("step1_noul"), "suff": suff,
            "closure_conf": r.get("closure_confidence"),
            "opv": t["verdict"] if t else None,
            "reason": (t.get("reason", "") if t else ""),
            "exp_c": exp_c,
        }
        if t is None:
            untriaged += 1
            if status == "confirmed":
                jev_confirmed_open.append(row)
            continue
        if row["opv"] == "confirmed" and status == "confirmed":
            confirmed_match += 1
        elif row["opv"] == "dismissed" and status in ("dismissed", "not-security"):
            not_actionable_match += 1
            if exp_c and status != exp_c:
                closure_dis.append(row)
        else:
            serious.append(row)

    lines = []
    w = lines.append
    w("# S0a final run: fresh-init Jev triage of the entire cavet finding set")
    w("")
    w(f"Universe: {len(findings)} findings (every fingerprint cavet has "
      f"flagged, remediated excluded). Calls: {calls}. Wall: {wall/1000:.0f} s. "
      f"Fresh-init semantics: current_status was open for every finding; "
      f"state = mv + mechanical enrichment (path class, source excerpt) + "
      f"cavet lookup; r3 wording; two-step flow with the state_sufficient "
      f"question.")
    w("")
    w("Methodology note: rounds 1-3 of S0a included the operator verdict as "
      "current_status in the mv state for already-triaged findings, so their "
      "accuracy numbers are contaminated and only the wording-movement, "
      "sufficiency and timing observations stand. This run corrects that.")
    w("")
    w("## Jev's proposal distribution")
    w("")
    w("| status | count |")
    w("|---|---|")
    for s, n in sorted(by_status.items(), key=lambda kv: -kv[1]):
        w(f"| {s} | {n} |")
    w("")
    if suff_all:
        w(f"state_sufficient: mean {statistics.mean(suff_all):.2f}, "
          f"min {min(suff_all):.2f}, max {max(suff_all):.2f} "
          f"(n={len(suff_all)})")
        w("")
    w(f"## Disagreements with recorded operator verdicts ({len(serious)})")
    w("")
    w("Operator and Jev disagree on actionable vs not actionable. Each row "
      "is a candidate for individual review.")
    w("")
    if serious:
        w("| id | sev | rule | location | operator | jev | p(confirmed) | suff | operator reason |")
        w("|---|---|---|---|---|---|---|---|---|")
        for r in sorted(serious, key=lambda r: -r["p1"] if r["p1"] is not None else 0):
            w(f"| {r['id']} | {r['sev']} | {r['rule']} | {r['loc']} | "
              f"{r['opv']} | {r['status']} | {r['p1']} | {r['suff']} | "
              f"{r['reason'][:140]} |")
    else:
        w("None.")
    w("")
    w(f"## Agreement summary on triaged findings "
      f"({confirmed_match + not_actionable_match + len(serious)} triaged)")
    w("")
    w(f"- operator confirmed & Jev confirmed: {confirmed_match}")
    w(f"- operator dismissed & Jev not actionable (dismissed or "
      f"not-security): {not_actionable_match}")
    w(f"- actionable disagreements: {len(serious)}")
    w("")
    w(f"## Closure-layer disagreements on curated findings ({len(closure_dis)})")
    w("")
    w("Both said not actionable, but Jev's closure differs from the "
      "suggested mapping (dismissed = security claim wrong here; "
      "not-security = valid observation, no security concern). These are "
      "arbitration candidates, not errors.")
    w("")
    if closure_dis:
        w("| id | sev | rule | suggested | jev closure | p(not-security) tier |")
        w("|---|---|---|---|---|---|")
        for r in closure_dis:
            w(f"| {r['id']} | {r['sev']} | {r['rule']} | {r['exp_c']} | "
              f"{r['status']} | {r['suff']} |")
    else:
        w("None.")
    w("")
    w(f"## Untriaged findings Jev would confirm ({len(jev_confirmed_open)})")
    w("")
    w("No operator verdict exists for these; Jev's step 1 crossed the 0.5 "
      "gate. Highest-priority review queue.")
    w("")
    if jev_confirmed_open:
        w("| id | sev | rule | location | p(confirmed) | suff |")
        w("|---|---|---|---|---|---|")
        for r in sorted(jev_confirmed_open, key=lambda r: -r["p1"] if r["p1"] is not None else 0):
            w(f"| {r['id']} | {r['sev']} | {r['rule']} | {r['loc']} | "
              f"{r['p1']} | {r['suff']} |")
    else:
        w("None.")
    w("")
    w(f"Untriaged pile: {untriaged} findings carried no operator verdict; "
      "Jev proposes the distribution above covers them.")
    w("")

    out = HERE / "full-run-report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")
    print(f"status distribution: {by_status}")
    print(f"triaged: {confirmed_match} confirmed-match, "
          f"{not_actionable_match} not-actionable-match, "
          f"{len(serious)} DISAGREEMENTS")
    print(f"closure disagreements: {len(closure_dis)}")
    print(f"jev-confirmed untriaged: {len(jev_confirmed_open)}")


if __name__ == "__main__":
    main()
