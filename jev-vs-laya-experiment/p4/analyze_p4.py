"""P4 analysis: the fine-tune delta, in the P3 metric format.

Part 1, the P4 validation split (76 held-out vite findings): teacher (Jev
labels) versus base multilingual versus fine-tuned, on identical states and
questions. The teacher's labels ARE Jev's outputs, so agreement here measures
how well the student reproduces its teacher on unseen findings of the training
distribution, not correctness (the plan's guardrail).

Part 2, the frozen states-v2 universes (1,793 states): base versus fine-tuned
with exactly the P3 metrics: actionability against operator verdicts,
per-corpus recall/precision with Wilson intervals, bit-identity determinism,
and calibration (Brier, ECE, NLL, AUROC) against operator labels with the
temperature fitted on the cavet dev split and frozen (plan Section 4).

The teacher set has zero confirmed findings (302 not-security, 70 dismissed),
so gate-axis AUROC is undefined on the val split (single class) and is
reported as null; gate quality there is measured against the teacher's SOFT
step-1 probability instead (Brier against soft targets).

Usage:  .venv-cpu/Scripts/python p4/analyze_p4.py
Output: analysis/p4-analysis.json + stdout summary.
"""
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
RUNS = PARENT / "runs"
OUT = PARENT / "analysis"
OUT.mkdir(exist_ok=True)

CAVET_LOG = Path("C:/Development/cavet/.cavet/log/events-2026-09.jsonl")
FRAGMT_LOG = Path("C:/Development/fragmt/.cavet/log/events-2026-09.jsonl")
GT = Path("C:/Development/cavet-docs-export/benchmark/ground-truth")


def rm(x, nd=4):
    return None if x is None else round(x, nd)


def load_events(path):
    tri = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e.get("event") == "triaged":
                tri[e["fingerprint"]] = e["data"]["verdict"]
    return tri


def wilson(k, n, z=1.959963985):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def ece10(pairs):
    if not pairs:
        return None
    bins = [[] for _ in range(10)]
    for p, y in pairs:
        bins[min(9, int(p * 10))].append((p, y))
    total = len(pairs)
    e = 0.0
    for b in bins:
        if not b:
            continue
        acc = sum(y for _, y in b) / len(b)
        conf = sum(p for p, _ in b) / len(b)
        e += len(b) / total * abs(acc - conf)
    return e


def brier(pairs):
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs) if pairs else None


def brier_soft(pairs):
    """Brier against SOFT targets: pairs of (p, q) with q the reference probability."""
    return sum((p - q) ** 2 for p, q in pairs) / len(pairs) if pairs else None


def nll(pairs):
    eps = 1e-9
    return -sum(math.log(max(p, eps)) if y else math.log(max(1 - p, eps))
                for p, y in pairs) / len(pairs) if pairs else None


def auroc(pairs):
    if not pairs:
        return None
    pos = sum(y for _, y in pairs)
    neg = len(pairs) - pos
    if not pos or not neg:
        return None
    ranked = sorted(pairs, key=lambda t: t[0])
    r = 0.0
    i = 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2
        r += sum(avg_rank for _, y in ranked[i:j] if y)
        i = j
    return (r - pos * (pos + 1) / 2) / (pos * neg)


def fit_temperature(pairs, lo=0.2, hi=10.0, steps=200):
    best_t, best_n = 1.0, float("inf")
    for i in range(steps):
        t = lo * (hi / lo) ** (i / (steps - 1))
        scaled = [(1 / (1 + math.exp(-(math.log(max(p, 1e-9) / max(1 - p, 1e-9))) / t)), y)
                  for p, y in pairs]
        n = nll(scaled)
        if n < best_n:
            best_t, best_n = t, n
    return round(best_t, 4)


def apply_temperature(pairs, t):
    return [(1 / (1 + math.exp(-(math.log(max(p, 1e-9) / max(1 - p, 1e-9))) / t)), y)
            for p, y in pairs]


def load_arm(pattern, n_reps):
    files = sorted(RUNS.glob(pattern))
    if not files:
        return None
    reps = []
    for f in files[:n_reps]:
        d = json.loads(f.read_text(encoding="utf-8"))
        reps.append(d["findings"])
    keys = set(reps[0])
    for r in reps[1:]:
        keys &= set(r)
    return {k: [r[k] for r in reps] for k in keys}, [f.name for f in files[:n_reps]]


def majority(recs):
    vals = [r.get("status") for r in recs if r.get("status")]
    if not vals:
        return None
    conf = sum(1 for v in vals if v == "confirmed")
    return "confirmed" if conf * 2 > len(vals) else ("below-gate" if not any(
        v == "confirmed" for v in vals) else "tie")


def step1_mean(recs):
    p = [r["step1_noul"] for r in recs if r.get("step1_noul") is not None]
    return sum(p) / len(p) if p else None


def cal_metrics(pairs, t=None):
    out = {"n": len(pairs), "brier": rm(brier(pairs)), "ece": rm(ece10(pairs)),
           "nll": rm(nll(pairs)), "auroc": rm(auroc(pairs))}
    if t is not None:
        f = apply_temperature(pairs, t)
        out["fitted"] = {"t": t, "brier": rm(brier(f)), "ece": rm(ece10(f)),
                         "nll": rm(nll(f)), "auroc": rm(auroc(f))}
    return out


# ---------------------------------------------------------------- part 1
def analyze_val_split(report):
    labels = json.loads((HERE / "runs" / "jev-labels.json").read_text(encoding="utf-8"))["findings"]
    val_keys = set()
    for line in (HERE / "data" / "states-p4-val.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        val_keys.add(f'{r["corpus"]}:{r["id"]}')

    teacher = {}
    for k in val_keys:
        lab = labels[k]
        teacher[k] = {"step1_noul": lab["step1_noul"],
                      "status": lab.get("status"),
                      "closure_probabilities": lab.get("closure_probabilities")}
    arms = {"teacher-jev": {k: [v] for k, v in teacher.items()}}
    for name, pat in (("base-multilingual", "p4-val-base-rep*.json"),
                      ("fine-tuned", "p4-val-ft-rep*.json")):
        loaded = load_arm(pat, 2)
        if loaded:
            arms[name] = loaded[0]
        print(f"[val] {name}: {'missing' if not loaded else f'{len(loaded[0])} findings'}")

    res = {"n_findings": len(val_keys),
           "teacher_status_mix": {}, "arms": {}}
    import collections
    res["teacher_status_mix"] = dict(collections.Counter(v["status"] for v in teacher.values()))
    t_prob = {k: v["step1_noul"] for k, v in teacher.items()}

    for arm, data in arms.items():
        gate_pairs_bin, gate_pairs_soft, clos_soft, clos_dis = [], [], 0, 0
        for k in val_keys:
            recs = data.get(k)
            if not recs:
                continue
            p = step1_mean(recs)
            if p is not None:
                gate_pairs_soft.append((p, t_prob[k]))
                gate_pairs_bin.append((p, 1.0 if teacher[k]["status"] == "confirmed" else 0.0))
            # closure distribution comparison where the teacher ran step 2
            cp = teacher[k]["closure_probabilities"]
            if cp:
                sp = recs[0].get("closure_probabilities")
                if arm == "teacher-jev":
                    sp = cp
                if sp:
                    clos_dis += abs(sp.get("dismissed", 0) - cp.get("dismissed", 0)) / 2
                    clos_soft += 1
        r = {
            "gate_vs_teacher_binarized": cal_metrics(gate_pairs_bin),
            "gate_vs_teacher_soft_brier": rm(brier_soft(gate_pairs_soft)),
            "closure_mean_total_variation": rm(clos_dis / clos_soft, 4) if clos_soft else None,
            "closure_n": clos_soft,
            "step1_mean": rm(sum(p for p, _ in gate_pairs_bin) / max(1, len(gate_pairs_bin)), 4),
        }
        if len(arms[arm][next(iter(val_keys))]) >= 2:
            ident = sum(1 for k in val_keys if len(data.get(k, [])) >= 2
                        and data[k][0].get("step1_noul") == data[k][1].get("step1_noul")
                        and data[k][0].get("status") == data[k][1].get("status"))
            r["bit_identical_reps"] = f"{ident}/{len(val_keys)}"
        # gate actionability: does the arm's gate decision match the teacher's?
        ok = n = 0
        for k in val_keys:
            recs = data.get(k)
            if not recs:
                continue
            m = majority(recs)
            t_conf = teacher[k]["status"] == "confirmed"
            n += 1
            ok += (m == "confirmed") == t_conf
        r["gate_decision_agreement"] = {"agree": ok, "n": n,
                                        "pct": round(100 * ok / n, 1) if n else None}
        res["arms"][arm] = r
    report["p4_val_split"] = res


# ---------------------------------------------------------------- part 2
def analyze_states_v2(report):
    states = [json.loads(line) for line in (PARENT / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]
    by_corpus = {}
    for s in states:
        by_corpus.setdefault(s["corpus"], {})[f"{s['corpus']}:{s['id']}"] = s
    cav_tri = load_events(CAVET_LOG)
    fra_tri = load_events(FRAGMT_LOG)
    gt_conf = {c: {f["id"] for f in json.loads((GT / f"corpus-{n}.json").read_text(encoding="utf-8"))["confirmed_findings"]}
               for c, n in (("corpus-2", 2), ("corpus-3", 3), ("corpus-4", 4), ("corpus-5", 5))}

    res = {"arms": {}}
    for arm, pat in (("base-multilingual", "statesv2-base-rep*.json"),
                     ("fine-tuned", "statesv2-ft-rep*.json")):
        loaded = load_arm(pat, 2)
        if not loaded:
            print(f"[states-v2] {arm}: missing")
            continue
        data, files = loaded
        print(f"[states-v2] {arm}: {len(data)} findings from {files}")
        r = {"files": files, "n_findings": len(data)}

        agree = {}
        for corpus, tri in (("cavet", cav_tri), ("fragmt", fra_tri)):
            ok = n = 0
            for s in by_corpus[corpus].values():
                v = tri.get(s["fp"])
                if v is None:
                    continue
                recs = data.get(f"{s['corpus']}:{s['id']}")
                if recs is None:
                    continue
                m = majority(recs)
                n += 1
                ok += (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
            agree[corpus] = {"agree": ok, "n": n, "pct": round(100 * ok / n, 1) if n else None}
        r["actionability"] = agree

        corpus_res = {}
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            conf_ids = gt_conf[corpus]
            recalled = pile = pile_true = conf_n = 0
            for k, recs in data.items():
                if not k.startswith(corpus + ":"):
                    continue
                m = majority(recs)
                fid = k.split(":", 1)[1]
                if fid in conf_ids:
                    conf_n += 1
                    recalled += (m == "confirmed")
                if m == "confirmed":
                    pile += 1
                    pile_true += (fid in conf_ids)
            lo, hi = wilson(recalled, conf_n) if conf_n else (None, None)
            corpus_res[corpus] = {
                "confirmed": conf_n, "recalled": recalled,
                "recall": round(100 * recalled / conf_n, 1) if conf_n else None,
                "wilson95": [round(100 * lo, 1), round(100 * hi, 1)] if conf_n else None,
                "confirmed_pile": pile, "pile_true": pile_true,
                "precision": round(pile_true / pile, 2) if pile else None,
            }
        r["corpora"] = corpus_res

        ident = 0
        maxd = 0.0
        for recs in data.values():
            if len(recs) >= 2 and recs[0].get("step1_noul") is not None and recs[1].get("step1_noul") is not None:
                if recs[0]["step1_noul"] == recs[1]["step1_noul"] and recs[0].get("status") == recs[1].get("status"):
                    ident += 1
                maxd = max(maxd, abs(recs[0]["step1_noul"] - recs[1]["step1_noul"]))
        r["consistency"] = {"bit_identical_reps": f"{ident}/{len(data)}", "max_abs_diff": round(maxd, 6)}

        def label_pairs(corpus, tri_map=None):
            pairs = []
            for k, recs in data.items():
                if not k.startswith(corpus + ":"):
                    continue
                p = step1_mean(recs)
                if p is None:
                    continue
                fid = k.split(":", 1)[1]
                if tri_map is not None:
                    v = tri_map.get(by_corpus[corpus][k]["fp"])
                    if v is None:
                        continue
                    pairs.append((p, 1.0 if v == "confirmed" else 0.0))
                else:
                    pairs.append((p, 1.0 if fid in gt_conf[corpus] else 0.0))
            return pairs

        cal = {}
        cav_pairs = label_pairs("cavet", cav_tri)
        fra_pairs = label_pairs("fragmt", fra_tri)
        t = fit_temperature(cav_pairs)
        cal["fitted_temperature"] = t
        cal["cavet_dev"] = cal_metrics(cav_pairs, t)
        cal["fragmt_eval"] = cal_metrics(fra_pairs, t)
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            raw = label_pairs(corpus)
            cal[corpus] = cal_metrics(raw, t)
        r["calibration"] = cal
        res["arms"][arm] = r
    report["states_v2_before_after"] = res


def main():
    report = {}
    analyze_val_split(report)
    analyze_states_v2(report)
    (OUT / "p4-analysis.json").write_text(json.dumps(report, indent=1), encoding="utf-8")

    v = report.get("p4_val_split") or {}
    print(f"\n=== P4 validation split ({v.get('n_findings')} findings) ===")
    print("teacher status mix:", v.get("teacher_status_mix"))
    for arm, r in (v.get("arms") or {}).items():
        print(f"  {arm}: step1_mean {r['step1_mean']} "
              f"gate_agree {r['gate_decision_agreement']['pct']}% "
              f"soft_brier {r['gate_vs_teacher_soft_brier']} "
              f"closure_TV {r['closure_mean_total_variation']} (n={r['closure_n']}) "
              f"bit-identical {r.get('bit_identical_reps')}")
    b = report.get("states_v2_before_after") or {}
    for arm, r in (b.get("arms") or {}).items():
        print(f"\n=== states-v2 {arm} ({r['n_findings']} findings) ===")
        for c, a in r["actionability"].items():
            print(f"  actionability {c}: {a['agree']}/{a['n']} = {a['pct']}%")
        for c, x in r["corpora"].items():
            print(f"  {c}: recall {x['recalled']}/{x['confirmed']} = {x['recall']}% "
                  f"precision {x['precision']}")
        print(f"  consistency: {r['consistency']}")
        c = r["calibration"]
        print(f"  calibration: T={c['fitted_temperature']} cavet_dev {c['cavet_dev']}")
        print(f"  fragmt_eval {c['fragmt_eval']}")
    print("\nanalysis written to analysis/p4-analysis.json")


if __name__ == "__main__":
    main()
