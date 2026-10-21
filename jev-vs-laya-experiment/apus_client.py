"""APUS-OpenJev-v1 decision client over llama-server, faithful to the shipped
runtime contract (apus-ailab/APUS-OpenJev-v1 9B-3000: contracts.py
`jev.dynamic.prompt.v2`, chat_template.jinja with enable_thinking=False,
letter-token logits at the answer boundary).

Mechanism notes:
  - request: {id, group_id, state(str), instructions, primitive:
    choice|noul|score_level, criteria: [{id, description} x 2..16]}
  - noul uses the canonical yes/no criteria (yes_probability = P(true)).
  - prompt: "Shared state:\n{state}\n\n{json task}\nReturn only the selected
    letter: A[, B...].\nAnswer:" as one user message; the Qwen3.5 chat tail
    with thinking disabled ends "<|im_start|>assistant\n<think>\n\n</think>\n\n".
  - scoring: softmax over the letter tokens' logits at the first answer
    position. llama-server /completion with n_probs returns full-vocab
    softmax probabilities for the top-n tokens; renormalizing over the letter
    subset is invariant to that (softmax renormalization), so we recover the
    runtime's relative distribution without logit access.
  - effort: full depth (the GGUF carries all layers; the 16-layer low-effort
    early-exit path is a native-runtime feature and is not reproducible here).

The GGUF arm is a Q6_K quantization of the merged 9B-3000 checkpoint; every
result row for this arm records that.

Usage:
  APUS_LLAMA_URL=http://127.0.0.1:8091 python apus_client.py  (smoke)
"""
import json
import math
import time
import urllib.request

BASE = "http://127.0.0.1:8091"
LABELS = tuple("ABCDEFGHIJKLMNOP")
BINARY_CRITERIA = [
    {"id": "yes", "description": "The stated proposition is true."},
    {"id": "no", "description": "The stated proposition is false."},
]


def render_prompt(state, instructions, primitive, criteria):
    task = {
        "primitive": primitive,
        "instructions": instructions,
        "criteria": [
            {"label": label, "description": c["description"]}
            for label, c in zip(LABELS, criteria)
        ],
    }
    text = "Shared state:\n" + state + "\n\n"
    text += json.dumps(task, ensure_ascii=False, sort_keys=True)
    text += ("\nReturn only the selected letter: "
             + ", ".join(LABELS[: len(criteria)]) + ".\nAnswer:")
    return ("<|im_start|>user\n" + text + "<|im_end|>\n"
            "<|im_start|>assistant\n<think>\n\n</think>\n\n")


def _post(path, payload, timeout=120):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read())
    return out, round((time.perf_counter() - t0) * 1000, 1)


def letter_probs(prompt, n_letters):
    """Logprob of each letter token at the answer position (top-64), softmaxed
    over the letter subset; a letter absent from the top-64 scores 0."""
    out, ms = _post("/completion", {"prompt": prompt, "n_predict": 1,
                                    "n_probs": 64, "temperature": 0.0,
                                    "stream": False})
    top = out["completion_probabilities"][0]["top_logprobs"]
    lp = {}
    for t in top:
        tok = t["tok_str"] if "tok_str" in t else t["token"]
        for letter in LABELS[:n_letters]:
            if tok.strip() == letter and letter not in lp:
                lp[letter] = t["logprob"]
                break
    if not lp:
        raise RuntimeError("no letter tokens in top logprobs: "
                           + json.dumps(top[:5]))
    mx = max(lp.values())
    ex = {k: math.exp(v - mx) for k, v in lp.items()}
    s = sum(ex.values())
    return {k: v / s for k, v in ex.items()}, ms, out.get("tokens_evaluated")


def decide(state, instructions, primitive, criteria):
    """state: str; criteria: list of {id, description}; returns the runtime's
    response shape (format_response from contracts.py)."""
    if primitive != "choice":
        criteria = BINARY_CRITERIA
    prompt = render_prompt(state, instructions, primitive, criteria)
    dist, ms, _ = letter_probs(prompt, len(criteria))
    ordered = [dist.get(l, 0.0) for l in LABELS[: len(criteria)]]
    s = sum(ordered)
    ordered = [p / s for p in ordered]
    ids = [c["id"] for c in criteria]
    distribution = dict(zip(ids, ordered))
    result = {"type": primitive, "probabilities": distribution,
              "wall_ms": ms}
    if primitive == "choice":
        result["choice"] = max(distribution, key=distribution.get)
    else:
        result["yes_probability"] = distribution["yes"]
    return result


def state_to_text(state):
    """The contract takes a string state; our harness states are objects.
    Serialize as compact JSON (mechanical, mirrors what laya/kev receive)."""
    return json.dumps(state, ensure_ascii=False)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    import harness

    states = [json.loads(l) for l in open("states-v2.jsonl", encoding="utf-8")]
    picks = [next(r for r in states if r["corpus"] == "corpus-2" and r.get("lockfile")),
             next(r for r in states if r["corpus"] == "corpus-2" and not r.get("lockfile"))]
    SV = (" Severity labels are not grounds for dismissal for manifest findings: the "
          "affected version is pinned in this project's dependency manifest, which the "
          "state establishes directly.")

    for rec in picks:
        st_text = state_to_text(rec["state"])
        q1 = harness.q_confirm("mv")
        q1.update(harness.q_missing("mv"))
        ins = q1["is_confirmed"]["instructions"]
        if rec.get("lockfile"):
            ins += SV
        for rep in (1, 2):
            t0 = time.perf_counter()
            r1 = decide(st_text, ins, "noul", None)
            r2 = decide(st_text, q1["state_sufficient"]["instructions"], "noul", None)
            line = (f"{rec['id']} rep{rep}: step1={r1['yes_probability']:.4f} "
                    f"suff={r2['yes_probability']:.4f}")
            if r1["yes_probability"] < 0.5:
                cl = harness.q_closure("mv", harness.WORDINGS["r3"])["closure"]
                crit = [{"id": k, "description": v} for k, v in cl["criteria"].items()]
                rc = decide(st_text, cl["instructions"], "choice", crit)
                line += (f" closure={rc['choice']} "
                         f"probs={ {k: round(v, 3) for k, v in rc['probabilities'].items()} }")
            print(line, f"wall={1000 * (time.perf_counter() - t0):.0f}ms", flush=True)
