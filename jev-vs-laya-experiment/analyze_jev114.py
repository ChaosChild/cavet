"""Jev 1.13 vs 1.14 comparison over the frozen states (both arms: 3 reps,
batch-1, majority voting), in the P3 metric format.

Usage:  .venv-cpu/Scripts/python analyze_jev114.py
Output: analysis/jev114-comparison.json + stdout summary.
"""
import collections
import json
import math
from pathlib import Path

HERE = Path(__file__).parent
RUNS = HERE / "runs"
OUT = HERE / "analysis"

CAVET_LOG = Path("C:/Development/cavet/.cavet/log/events-2026-09.jsonl")
FRAGMT_LOG = Path("C:/Development/fragmt/.cavet/log/events-2026-09.jsonl")
GT = Path("C:/Development/cavet-docs-export/benchmark/ground-truth")

ARMS = [("jev-1.13", "jev-b1-rep*.json"), ("jev-1.14", "jev-114-rep*.json")]


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


def rm(x, nd=4):
    return None if x is None else round(x, nd)


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


def main():
    states = [json.loads(line) for line in (HERE / "states-v2.jsonl").read_text(encoding="utf-8").splitlines()]
    by_corpus = {}
    for s in states:
        by_corpus.setdefault(s["corpus"], {})[f"{s['corpus']}:{s['id']}"] = s
    cav_tri = load_events(CAVET_LOG)
    fra_tri = load_events(FRAGMT_LOG)
    gt_conf = {c: {f["id"] for f in json.loads((GT / f"corpus-{n}.json").read_text(encoding="utf-8"))["confirmed_findings"]}
               for c, n in (("corpus-2", 2), ("corpus-3", 3), ("corpus-4", 4), ("corpus-5", 5))}

    report = {"arms": {}}
    results = {}
    for arm, pat in ARMS:
        files = sorted(RUNS.glob(pat))[:3]
        reps = [json.loads(f.read_text(encoding="utf-8"))["findings"] for f in files]
        keys = set(reps[0])
        for r in reps[1:]:
            keys &= set(r)
        data = {k: [r[k] for r in reps] for k in keys}
        res = {"n_findings": len(data)}

        all_p = [step1_mean(v) for v in data.values()]
        all_p = [p for p in all_p if p is not None]
        res["step1"] = {"mean": rm(sum(all_p) / len(all_p)),
                        "median": rm(sorted(all_p)[len(all_p) // 2]),
                        "max": rm(max(all_p)),
                        "over_gate_majority": sum(1 for v in data.values() if majority(v) == "confirmed")}
        res["status_mix_majority"] = dict(collections.Counter(majority(v) for v in data.values()))

        agree = {}
        for corpus, tri in (("cavet", cav_tri), ("fragmt", fra_tri)):
            ok = n = 0
            misses = []
            for s in by_corpus[corpus].values():
                v = tri.get(s["fp"])
                if v is None:
                    continue
                recs = data.get(f"{s['corpus']}:{s['id']}")
                if recs is None:
                    continue
                m = majority(recs)
                n += 1
                good = (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
                ok += good
                if not good:
                    misses.append(s["id"])
            agree[corpus] = {"agree": ok, "n": n, "pct": round(100 * ok / n, 1) if n else None,
                             "disagreement_ids": misses}
        res["actionability"] = agree

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
            corpus_res[corpus] = {"confirmed": conf_n, "recalled": recalled,
                                  "recall": round(100 * recalled / conf_n, 1) if conf_n else None,
                                  "wilson95": [round(100 * lo, 1), round(100 * hi, 1)] if conf_n else None,
                                  "confirmed_pile": pile, "pile_true": pile_true,
                                  "precision": round(pile_true / pile, 2) if pile else None}
        res["corpora"] = corpus_res

        unam = 0
        sd_list = []
        walls = []
        for recs in data.values():
            vals = [r.get("status") for r in recs]
            if all(vals):
                unam += (len(set(vals)) == 1)
            p = [r["step1_noul"] for r in recs if r.get("step1_noul") is not None]
            if len(p) >= 2:
                mu = sum(p) / len(p)
                sd_list.append(math.sqrt(sum((x - mu) ** 2 for x in p) / len(p)))
            walls.append(min(r["wall_ms"] for r in recs))
        res["consistency"] = {"unanimous_pct": round(100 * unam / len(data), 2),
                              "mean_step1_sd": rm(sum(sd_list) / len(sd_list)),
                              "max_step1_sd": rm(max(sd_list))}
        res["latency"] = {"median_wall_ms": rm(sorted(walls)[len(walls) // 2], 1),
                          "p95_wall_ms": rm(sorted(walls)[int(0.95 * len(walls))], 1)}

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
        for name, pairs in (("cavet_dev", label_pairs("cavet", cav_tri)),
                            ("fragmt_eval", label_pairs("fragmt", fra_tri)),
                            ("corpus-2", label_pairs("corpus-2")),
                            ("corpus-3", label_pairs("corpus-3")),
                            ("corpus-4", label_pairs("corpus-4")),
                            ("corpus-5", label_pairs("corpus-5"))):
            cal[name] = {"n": len(pairs), "brier": rm(brier(pairs)), "ece": rm(ece10(pairs)),
                         "nll": rm(nll(pairs)), "auroc": rm(auroc(pairs), 3)}
        res["calibration"] = cal
        report["arms"][arm] = res
        results[arm] = res

        print(f"\n=== {arm} (3-rep majority) ===")
        print(f"  step1: {res['step1']}  mix: {res['status_mix_majority']}")
        for c, a in res["actionability"].items():
            print(f"  actionability {c}: {a['agree']}/{a['n']} = {a['pct']}%")
        for c, x in res["corpora"].items():
            print(f"  {c}: recall {x['recalled']}/{x['confirmed']} = {x['recall']}% pile {x['confirmed_pile']} prec {x['precision']}")
        print(f"  consistency: {res['consistency']}  latency: {res['latency']}")
        c = res["calibration"]
        print(f"  cal cavet_dev: {c['cavet_dev']}")
        print(f"  cal corpus-2: {c['corpus-2']}")

    # deltas where directly comparable
    a, b = results["jev-1.13"], results["jev-1.14"]
    flips = {"cavet_actionability": [a["actionability"]["cavet"]["pct"], b["actionability"]["cavet"]["pct"]],
             "corpus2_recall": [a["corpora"]["corpus-2"]["recall"], b["corpora"]["corpus-2"]["recall"]],
             "corpus5_recall": [a["corpora"]["corpus-5"]["recall"], b["corpora"]["corpus-5"]["recall"]],
             "confirmed_pile_majority": [a["step1"]["over_gate_majority"], b["step1"]["over_gate_majority"]],
             "cavet_dev_brier": [a["calibration"]["cavet_dev"]["brier"], b["calibration"]["cavet_dev"]["brier"]],
             "cavet_dev_ece": [a["calibration"]["cavet_dev"]["ece"], b["calibration"]["cavet_dev"]["ece"]],
             "cavet_dev_auroc": [a["calibration"]["cavet_dev"]["auroc"], b["calibration"]["cavet_dev"]["auroc"]],
             "unanimous_pct": [a["consistency"]["unanimous_pct"], b["consistency"]["unanimous_pct"]],
             "median_wall_ms": [a["latency"]["median_wall_ms"], b["latency"]["median_wall_ms"]]}
    report["deltas_113_to_114"] = flips
    print("\n=== deltas 1.13 -> 1.14 ===")
    for k, v in flips.items():
        print(f"  {k}: {v[0]} -> {v[1]}")

    (OUT / "jev114-comparison.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print("\nanalysis written to analysis/jev114-comparison.json")


if __name__ == "__main__":
    main()
