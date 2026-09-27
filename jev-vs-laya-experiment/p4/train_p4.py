"""P4: single-GPU RLCD fine-tune of the multilingual checkpoint on the vite
teacher labels, following the laya recipe (docs/finetune_browser_agent.md,
code/finetune/train.py in cklxx/laya-browser): GRPO-style noisy-logit policy
gradient over a proper-scoring-rule reward + soft-target cross-entropy.

Adaptations from the recipe:
  - base checkpoint: laya-multilingual 322M (operator amendment; recipe
    demonstrated 421M on the same 16 GB class), max_len 8192, head 256 to
    match the P2/P3 multilingual arm
  - torch.compile OFF by default (COMPILE=1 to opt in): dynamic compile is
    unreliable on the Windows ROCm preview stack
  - micro-batch 4 x accumulated 8, LR 2.5e-5 encoder / 1e-4 head, sigma 0.4
    to 0.1 across epochs, 4 epochs: all recipe defaults, kept

Usage:
  .venv-rocm/Scripts/python p4/train_p4.py [epochs=4]
  LIMIT=8 epochs smoke:  LIMIT=8 .venv-rocm/Scripts/python p4/train_p4.py 1
Output: p4/models/multilingual-ft/ (full laya checkpoint directory)
"""
import json
import os
import random
import signal
import sys
import time
from pathlib import Path

import torch
from safetensors.torch import load_file, save_file
from transformers import AutoTokenizer

from laya.common import build_model, proper_reward

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "models" / "multilingual"
OUT = HERE / "models" / "multilingual-ft"
ITEMS = HERE / "data" / "train_items.pt"

MAX_LEN, HEAD_MAX_LEN = 8192, 256


def collate(items, pad_id):
    n, L = len(items), max(len(it["ids"]) for it in items)
    kmax = max(len(it["markers"]) for it in items)
    ids = torch.full((n, L), pad_id, dtype=torch.long)
    att = torch.zeros((n, L), dtype=torch.long)
    mpos = torch.zeros((n, kmax), dtype=torch.long)
    mmask = torch.zeros((n, kmax), dtype=torch.bool)
    target = torch.zeros((n, kmax))
    for i, it in enumerate(items):
        ids[i, :len(it["ids"])] = torch.tensor(it["ids"])
        att[i, :len(it["ids"])] = 1
        k = len(it["markers"])
        mpos[i, :k] = torch.tensor(it["markers"])
        mmask[i, :k] = True
        target[i, :len(it["target"])] = torch.tensor(it["target"])
    return dict(input_ids=ids, attention_mask=att, marker_pos=mpos,
                marker_mask=mmask, target=target,
                qtype=torch.tensor([it["qtype"] for it in items]))


def main():
    epochs = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    limit = int(os.environ.get("LIMIT", "0"))
    dev = torch.device("cuda")
    cfg = json.loads((BASE / "rl_agent_config.json").read_text(encoding="utf-8"))
    cfg.update(max_len=MAX_LEN, head_max_len=HEAD_MAX_LEN)
    tok = AutoTokenizer.from_pretrained(str(BASE / "tokenizer"))
    model = build_model(cfg, encoder_dir=str(BASE / "encoder"))
    model.load_state_dict(load_file(str(BASE / "model.safetensors")), strict=True)
    model.encoder.config.reference_compile = False
    model.to(dev).train()
    if os.environ.get("COMPILE", "0") == "1":
        model.encoder = torch.compile(model.encoder, dynamic=True)
    items = torch.load(ITEMS, weights_only=False)
    if limit:
        items = items[:limit]
    MICRO = int(os.environ.get("MICRO", "4"))  # 4 fits 16 GB at recipe seq lens; drop to 2 if a long-state batch OOMs
    ACCUM = int(os.environ.get("ACCUM", "8"))  # keep MICRO*ACCUM = 32 when changing MICRO: same effective batch
    G, LR_ENC, LR_HEAD, S0, S1 = 4, 2.5e-5, 1e-4, 0.4, 0.1
    enc = [p for n, p in model.named_parameters() if "encoder." in n]
    head = [p for n, p in model.named_parameters() if "encoder." not in n]
    opt = torch.optim.AdamW([{"params": enc, "lr": LR_ENC},
                             {"params": head, "lr": LR_HEAD}], weight_decay=0.01)
    total = max(1, (len(items) // (MICRO * ACCUM)) * epochs)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=total, eta_min=1e-6)
    t0 = time.time()
    step = 0
    ck_path = OUT / "resume.pt"
    OUT.mkdir(parents=True, exist_ok=True)
    start_ep, start_b = 0, 0
    if ck_path.exists() and limit == 0:
        ck = torch.load(ck_path, map_location=dev, weights_only=False)
        model.load_state_dict(ck["model"], strict=False)
        opt.load_state_dict(ck["opt"])
        sched.load_state_dict(ck["sched"])
        step = ck["step"]
        start_ep, start_b = ck["epoch"], ck["b"]
        print(f"resumed from {ck_path}: epoch {start_ep + 1}, item {start_b}, step {step}",
              flush=True)
    SAVE_EVERY = int(os.environ.get("SAVE_EVERY", "300"))

    def save_resume(ep_, b_):
        tmp = str(ck_path) + ".tmp"
        torch.save({"model": model.state_dict(), "opt": opt.state_dict(),
                    "sched": sched.state_dict(), "step": step, "epoch": ep_, "b": b_}, tmp)
        os.replace(tmp, ck_path)

    stop = {"flag": False}

    def _on_signal(sig, frame):
        stop["flag"] = True
        print(f"signal {sig}: saving the resume point after this micro-batch", flush=True)

    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError):
            pass

    for ep0 in range(start_ep):
        random.seed(42 + ep0)
        random.shuffle(items)
    for ep in range(start_ep, epochs):
        random.seed(42 + ep)
        random.shuffle(items)
        sigma = S0 + (S1 - S0) * ep / max(1, epochs - 1)
        tot_loss, nb = 0.0, 0
        opt.zero_grad(set_to_none=True)
        for b in range((start_b if ep == start_ep else 0), len(items), MICRO):
            batch = collate(items[b:b + MICRO], tok.pad_token_id)
            batch = {k: v.to(dev) for k, v in batch.items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                logits, act = model(batch["input_ids"], batch["attention_mask"],
                                    batch["marker_pos"], batch["marker_mask"], batch["qtype"])
            logits = logits.float()
            mask = batch["marker_mask"]
            k = mask.sum(-1, keepdim=True).float()
            target = batch["target"]
            eps = torch.randn((G,) + logits.shape, device=dev) * sigma * mask
            eps = (eps - eps.sum(-1, keepdim=True) / k) * mask
            z = logits.detach().unsqueeze(0) + eps
            q = torch.softmax(z.masked_fill(~mask, -1e4), -1)
            with torch.no_grad():
                r = proper_reward(q, target.unsqueeze(0), batch["qtype"], mask,
                                  w_sph=0.75, w_rps=1.0)
                adv = r - r.mean(0, keepdim=True)
                adv = adv / (adv.std() + 1e-6)
            logp = -(((z - logits.unsqueeze(0)) ** 2) * mask).sum(-1) / (2 * sigma ** 2)
            loss_rl = -(adv * logp).mean()
            loss_ce = -(target * torch.log_softmax(logits.masked_fill(~mask, -1e4), -1)).sum(-1).mean()
            loss = (loss_rl + loss_ce) / ACCUM + 0.0 * act.sum()
            loss.backward()
            nb += 1
            tot_loss += loss.item() * ACCUM
            if nb % ACCUM == 0 or b + MICRO >= len(items):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                sched.step()
                opt.zero_grad(set_to_none=True)
                step += 1
                if step % 20 == 0:
                    print(f"  ep {ep + 1} step {step}/{total} "
                          f"loss {loss.item() * ACCUM:.3f} ce {loss_ce.item():.3f} "
                          f"reward {r.mean().item():.3f} "
                          f"mem {torch.cuda.max_memory_allocated() / 2**30:.1f}GiB "
                          f"{time.time() - t0:.0f}s", flush=True)
                if step % SAVE_EVERY == 0 and limit == 0:
                    save_resume(ep, b + MICRO)
            if stop["flag"]:
                save_resume(ep, b + MICRO)
                print(f"saved {ck_path} at epoch {ep + 1}, item {b + MICRO}; exiting", flush=True)
                sys.exit(0)
        print(f"=== epoch {ep + 1}/{epochs} avg loss {tot_loss / max(1, nb):.4f} "
              f"{time.time() - t0:.0f}s", flush=True)
        if limit == 0:
            save_resume(ep + 1, 0)

    model.eval()
    if hasattr(model.encoder, "_orig_mod"):
        model.encoder = model.encoder._orig_mod
    OUT.mkdir(parents=True, exist_ok=True)
    save_file({k: v.half().contiguous().cpu() for k, v in model.state_dict().items()},
              str(OUT / "model.safetensors"))
    model.encoder.config.save_pretrained(str(OUT / "encoder"))
    tok.save_pretrained(str(OUT / "tokenizer"))
    cfg.update(fine_tuned=True, model_name="laya-multilingual-cybersec-p4",
               temperature=[1.0, 1.0, 1.0], temperature_by_options={},
               head_max_len_train=HEAD_MAX_LEN,
               training={**cfg.get("training", {}),
                         "epochs_completed": epochs, "items": len(items),
                         "recipe": "RLCD (laya finetune_browser_agent.md), Jev teacher labels on vitejs/vite"})
    (OUT / "rl_agent_config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print("saved", OUT, f"({time.time() - t0:.0f}s total)", flush=True)


if __name__ == "__main__":
    main()
