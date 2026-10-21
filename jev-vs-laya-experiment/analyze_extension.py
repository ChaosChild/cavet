"""Extension arms analysis: same metrics as analyze_p3.py for the bandwagon
arms (CLM-8B Q8_0, APUS-OpenJev-9B Q6_K, kev-4b), from their run files.

Usage:  .venv-cpu/Scripts/python analyze_extension.py
Output: analysis/extension-analysis.json + stdout summary.
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

ARMS = [
    ("clm-8b-q8", "clm-8b-q8-rep*.json", 2),
    ("apus-openjev-9b", "apus-openjev-9b-rep*.json", 2),
    ("kev-4b", "kev-4b-rep*.json", 2),
]


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


def cal_metrics(pairs, t=None):
    out = {"n": len(pairs), "brier": rm(brier(pairs)), "ece": rm(ece10(pairs)),
           "nll": rm(nll(pairs)), "auroc": rm(auroc(pairs))}
    if t is not None:
        f = apply_temperature(pairs, t)
        out["fitted"] = {"t": t, "brier": rm(brier(f)), "ece": rm(ece10(f)),
                         "nll": rm(nll(f)), "auroc": rm(auroc(f))}
    return out


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
    for arm, pat, n_reps in ARMS:
        files = sorted(RUNS.glob(pat))
        if not files:
            print(f"[{arm}] missing, skipped")
            continue
        reps = [json.loads(f.read_text(encoding="utf-8"))["findings"] for f in files[:n_reps]]
        keys = set(reps[0])
        for r in reps[1:]:
            keys &= set(r)
        data = {k: [r[k] for r in reps] for k in keys}
        res = {"files": [f.name for f in files[:n_reps]], "n_findings": len(data)}

        def p_of(recs):
            p = [r["step1_noul"] for r in recs if r.get("step1_noul") is not None]
            return sum(p) / len(p) if p else None

        def status_of(recs):
            return recs[0].get("status")

        # distribution
        all_p = [p_of(v) for v in data.values()]
        all_p = [p for p in all_p if p is not None]
        res["step1"] = {"mean": rm(sum(all_p) / len(all_p)),
                        "median": rm(sorted(all_p)[len(all_p) // 2]),
                        "max": rm(max(all_p)),
                        "over_gate": sum(p >= 0.5 for p in all_p)}
        res["status_mix"] = dict(collections.Counter(status_of(v) for v in data.values()))

        # actionability
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
                m = status_of(recs)
                n += 1
                ok += (m == "confirmed") if v == "confirmed" else (m in ("dismissed", "not-security", "below-gate"))
            agree[corpus] = {"agree": ok, "n": n, "pct": round(100 * ok / n, 1) if n else None}
        res["actionability"] = agree

        # corpora
        corpus_res = {}
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            conf_ids = gt_conf[corpus]
            recalled = pile = pile_true = conf_n = 0
            for k, recs in data.items():
                if not k.startswith(corpus + ":"):
                    continue
                m = status_of(recs)
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

        # consistency
        if n_reps >= 2:
            ident = 0
            maxd = 0.0
            for recs in data.values():
                if recs[0].get("step1_noul") is not None and recs[1].get("step1_noul") is not None:
                    if recs[0]["step1_noul"] == recs[1]["step1_noul"] and recs[0].get("status") == recs[1].get("status"):
                        ident += 1
                    maxd = max(maxd, abs(recs[0]["step1_noul"] - recs[1]["step1_noul"]))
            res["consistency"] = {"bit_identical_reps": f"{ident}/{len(data)}",
                                  "max_abs_diff": round(maxd, 6),
                                  "note": "identical = exact float equality on step1 + same status"}

        # calibration
        def label_pairs(corpus, tri_map=None):
            pairs = []
            for k, recs in data.items():
                if not k.startswith(corpus + ":"):
                    continue
                p = p_of(recs)
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

        cav = label_pairs("cavet", cav_tri)
        t = fit_temperature(cav)
        res["calibration"] = {"fitted_temperature": t,
                              "cavet_dev": cal_metrics(cav, t),
                              "fragmt_eval": cal_metrics(label_pairs("fragmt", fra_tri), t)}
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            res["calibration"][corpus] = cal_metrics(label_pairs(corpus), t)
        report["arms"][arm] = res

        print(f"\n=== {arm} ({len(data)} findings) ===")
        print(f"  step1: {res['step1']}  mix: {res['status_mix']}")
        for c, a in res["actionability"].items():
            print(f"  actionability {c}: {a['agree']}/{a['n']} = {a['pct']}%")
        for c, x in res["corpora"].items():
            print(f"  {c}: recall {x['recalled']}/{x['confirmed']} = {x['recall']}% pile {x['confirmed_pile']} prec {x['precision']}")
        if "consistency" in res:
            print(f"  consistency: {res['consistency']}")
        c = res["calibration"]
        print(f"  calibration: T={c['fitted_temperature']} cavet_dev {c['cavet_dev']}")

    OUT.mkdir(exist_ok=True)
    (OUT / "extension-analysis.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print("\nanalysis written to analysis/extension-analysis.json")


if __name__ == "__main__":
    main()
