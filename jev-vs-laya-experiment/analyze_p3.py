"""P3: comparative analysis of the Jev and Laya arms over the frozen states.

Metrics per arm (plan Sections 4 and 9):
  - actionability agreement on the 98 cavet + 40 fragmt operator verdicts
    (majority status vs verdict; Jev majority over 3 reps, Laya single pass,
    verified identical across its 2 reps)
  - per-corpus majority recall + 95% Wilson interval, confirmed-pile precision
  - consistency: Jev 3-rep unanimous-status rate and step-1 SD; Laya rep1-vs-rep2
    bit-identity rate and max abs diff (the determinism check)
  - calibration: Brier, ECE (10 equal-width bins), NLL, AUROC of step-1
    P(confirmed) vs operator labels. Laya temperature is fitted on the cavet
    dev split (NLL over a T grid in logit space), frozen, then reported raw and
    fitted on fragmt + corpora. Jev is scored as served.

Usage:  .venv-cpu/Scripts/python analyze_p3.py
Output: analysis/p3-analysis.json + stdout summary. Tolerates missing arms so it
can be smoke-tested before every file exists.
"""
import json
import math
from pathlib import Path

HERE = Path(__file__).parent
RUNS = HERE / "runs"
OUT = HERE / "analysis"
OUT.mkdir(exist_ok=True)

CAVET_LOG = Path("C:/Development/cavet/.cavet/log/events-2026-09.jsonl")
FRAGMT_LOG = Path("C:/Development/fragmt/.cavet/log/events-2026-09.jsonl")
GT = Path("C:/Development/cavet-docs-export/benchmark/ground-truth")


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
    """None-safe round: AUROC and friends are undefined on single-class sets."""
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
    """pairs: list of (prob, correct). 10 equal-width bins."""
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
    """1-D temperature scaling on the logit; returns T minimizing NLL."""
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
    """Returns {key: [rep records]} for the arm, or None if no files."""
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


def step1_series(recs):
    return [r["step1_noul"] for r in recs if r.get("step1_noul") is not None]


states = [json.loads(line) for line in (HERE / "states.jsonl").read_text(encoding="utf-8").splitlines()]
by_corpus = {}
for s in states:
    by_corpus.setdefault(s["corpus"], {})[f"{s['corpus']}:{s['id']}"] = s

cav_tri = load_events(CAVET_LOG)
fra_tri = load_events(FRAGMT_LOG)
gt_conf = {c: {f["id"] for f in json.loads((GT / f"corpus-{n}.json").read_text(encoding="utf-8"))["confirmed_findings"]}
           for c, n in (("corpus-2", 2), ("corpus-3", 3), ("corpus-4", 4), ("corpus-5", 5))}

arms = {}
for arm, pat, n in (("jev-b1", "jev-b1-rep*.json", 3),
                    ("laya-typed-decisions", "laya-typed-decisions-rep*.json", 2),
                    ("laya-multilingual", "laya-multilingual-rep*.json", 2)):
    loaded = load_arm(pat, n)
    arms[arm] = loaded
    print(f"[{arm}] {'missing' if loaded is None else f'{len(loaded[0])} findings from {loaded[1]}'}")

report = {"arms": {}}
for arm, loaded in arms.items():
    if loaded is None:
        continue
    data, files = loaded
    res = {"files": files, "n_findings": len(data)}

    # actionability agreement (cavet, fragmt)
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
                misses.append({"id": s["id"], "verdict": v, "majority": m,
                               "step1": round(sum(step1_series(recs)) / len(step1_series(recs)), 3)})
        agree[corpus] = {"agree": ok, "n": n, "pct": round(100 * ok / n, 1) if n else None,
                         "disagreements": misses}
    res["actionability"] = agree

    # per-corpus recall / precision on benchmark gold
    corpus_res = {}
    for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
        conf_ids = gt_conf[corpus]
        recalled = pile = pile_true = 0
        conf_n = 0
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
    res["corpora"] = corpus_res

    # consistency
    if arm == "jev-b1":
        unam = sd = 0
        sd_list = []
        for recs in data.values():
            vals = [r.get("status") for r in recs]
            if all(vals):
                unam += (len(set(vals)) == 1)
            p = step1_series(recs)
            if len(p) >= 2:
                mu = sum(p) / len(p)
                sd_list.append(math.sqrt(sum((x - mu) ** 2 for x in p) / len(p)))
        res["consistency"] = {"unanimous_pct": round(100 * unam / len(data), 2),
                              "mean_step1_sd": round(sum(sd_list) / len(sd_list), 4),
                              "max_step1_sd": round(max(sd_list), 4)}
    else:
        ident = 0
        maxd = 0.0
        for recs in data.values():
            if len(recs) >= 2 and recs[0].get("step1_noul") is not None and recs[1].get("step1_noul") is not None:
                if recs[0]["step1_noul"] == recs[1]["step1_noul"] and recs[0].get("status") == recs[1].get("status"):
                    ident += 1
                maxd = max(maxd, abs(recs[0]["step1_noul"] - recs[1]["step1_noul"]))
        res["consistency"] = {"bit_identical_reps": f"{ident}/{len(data)}", "max_abs_diff": round(maxd, 6)}

    # calibration label sets
    def label_pairs(corpus, tri_map=None):
        pairs = []
        for k, recs in data.items():
            if not k.startswith(corpus + ":"):
                continue
            p = step1_series(recs)
            if not p:
                continue
            p = sum(p) / len(p)
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
    cal["cavet_dev"] = {"n": len(cav_pairs), "brier": rm(brier(cav_pairs), 4),
                        "ece": rm(ece10(cav_pairs), 4), "nll": rm(nll(cav_pairs), 4),
                        "auroc": rm(auroc(cav_pairs), 3)}
    if arm.startswith("laya"):
        t = fit_temperature(cav_pairs)
        cal["fitted_temperature"] = t
        for name, pairs in (("fragmt_eval", fra_pairs),
                            ("cavet_dev_fitted", apply_temperature(cav_pairs, t))):
            cal[name] = {"n": len(pairs), "brier": rm(brier(pairs), 4),
                         "ece": rm(ece10(pairs), 4), "nll": rm(nll(pairs), 4),
                         "auroc": rm(auroc(pairs), 3)}
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            raw = label_pairs(corpus)
            fit = apply_temperature(raw, t)
            cal[corpus] = {"n": len(raw),
                           "raw": {"brier": rm(brier(raw), 4), "ece": rm(ece10(raw), 4),
                                   "nll": rm(nll(raw), 4), "auroc": rm(auroc(raw), 3)},
                           "fitted": {"brier": rm(brier(fit), 4), "ece": rm(ece10(fit), 4),
                                      "nll": rm(nll(fit), 4), "auroc": rm(auroc(fit), 3)}}
    else:
        cal["fragmt_eval"] = {"n": len(fra_pairs), "brier": rm(brier(fra_pairs), 4),
                              "ece": rm(ece10(fra_pairs), 4), "nll": rm(nll(fra_pairs), 4),
                              "auroc": rm(auroc(fra_pairs), 3)}
        for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
            raw = label_pairs(corpus)
            cal[corpus] = {"n": len(raw), "as_served": {"brier": rm(brier(raw), 4),
                                                        "ece": rm(ece10(raw), 4),
                                                        "nll": rm(nll(raw), 4),
                                                        "auroc": rm(auroc(raw), 3)}}
    res["calibration"] = cal
    report["arms"][arm] = res

(OUT / "p3-analysis.json").write_text(json.dumps(report, indent=1), encoding="utf-8")

for arm, res in report["arms"].items():
    print(f"\n=== {arm} ({res['n_findings']} findings) ===")
    for c, a in res["actionability"].items():
        print(f"  actionability {c}: {a['agree']}/{a['n']} = {a['pct']}%")
        for m in a["disagreements"][:5]:
            print(f"    miss {m['id']}: verdict={m['verdict']} majority={m['majority']} step1={m['step1']}")
    for c, r in res["corpora"].items():
        print(f"  {c}: recall {r['recalled']}/{r['confirmed']} = {r['recall']}% "
              f"wilson {r['wilson95']} precision {r['precision']}")
    print(f"  consistency: {res['consistency']}")
    c = res["calibration"]
    print(f"  calibration cavet_dev: {c['cavet_dev']}")
    if "fitted_temperature" in c:
        print(f"  fitted T={c['fitted_temperature']}; fragmt_eval {c['fragmt_eval']}")
    for corpus in ("corpus-2", "corpus-3", "corpus-4", "corpus-5"):
        print(f"  {corpus}: {c[corpus]}")
print("\nanalysis written to analysis/p3-analysis.json")
