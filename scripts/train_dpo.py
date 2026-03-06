#!/usr/bin/env python3
"""
train_dpo.py -- Direct Preference Optimization alignment.

Trains the model to prefer higher-quality threat analysis responses using
DPO (Rafailov et al. 2023) -- no reward model or RL needed.

Usage:
    python scripts/train_dpo.py \\
        --sft_ckpt   checkpoints/instruct/final.pt \\
        --data_file  data/dpo/preferences.jsonl \\
        --out_dir    checkpoints/dpo

Data format (preferences.jsonl):
    {"instruction": "...", "chosen": "...", "rejected": "..."}

Requires:
    pip install torch sentencepiece tqdm
"""

import argparse
import json
import os
import time
import torch
import torch.nn.functional as F
from torch.optim import AdamW


DPO_BETA = 0.1  # KL penalty (higher = stay closer to reference)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sft_ckpt",    required=True)
    ap.add_argument("--data_file",   default="data/dpo/preferences.jsonl")
    ap.add_argument("--vocab_model", default="data/vocab/threataform_bpe.model")
    ap.add_argument("--out_dir",     default="checkpoints/dpo")
    ap.add_argument("--steps",       type=int, default=2000)
    ap.add_argument("--lr",          type=float, default=5e-6)
    ap.add_argument("--beta",        type=float, default=DPO_BETA)
    ap.add_argument("--max_len",     type=int, default=1024)
    args = ap.parse_args()

    import sentencepiece as spm
    from train_base import ThreataformLM

    os.makedirs(args.out_dir, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    sp = spm.SentencePieceProcessor()
    sp.Load(args.vocab_model)

    ckpt   = torch.load(args.sft_ckpt, map_location="cpu")
    policy = ThreataformLM(ckpt["config"]).to(device)
    policy.load_state_dict(ckpt["model"])

    ref = ThreataformLM(ckpt["config"]).to(device)
    ref.load_state_dict(ckpt["model"])
    ref.eval()
    for p in ref.parameters(): p.requires_grad_(False)

    pairs = [json.loads(l) for l in open(args.data_file, encoding="utf-8")]
    print(f"Loaded {len(pairs)} preference pairs")

    opt = AdamW(policy.parameters(), lr=args.lr, weight_decay=0.0)
    import random
    t0 = time.time()

    for step in range(1, args.steps + 1):
        p      = random.choice(pairs)
        prefix = (
            "<|begin_of_text|><|start_header_id|>user<|end_header_id|>

"
            f"{p['instruction']}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"
        )
        prefix_ids   = sp.EncodeAsIds(prefix)
        chosen_ids   = (prefix_ids + sp.EncodeAsIds(p["chosen"]))[:args.max_len]
        rejected_ids = (prefix_ids + sp.EncodeAsIds(p["rejected"]))[:args.max_len]

        def seq_logprob(mdl, ids):
            x = torch.tensor(ids[:-1], dtype=torch.long, device=device).unsqueeze(0)
            y = torch.tensor(ids[1:],  dtype=torch.long, device=device)
            logits = mdl(x).squeeze(0)
            lp = F.log_softmax(logits, dim=-1)
            return lp[range(len(y)), y].sum()

        policy.train()
        pi_cho  = seq_logprob(policy, chosen_ids)
        pi_rej  = seq_logprob(policy, rejected_ids)

        with torch.no_grad():
            ref_cho = seq_logprob(ref, chosen_ids)
            ref_rej = seq_logprob(ref, rejected_ids)

        log_ratio = (pi_cho - ref_cho) - (pi_rej - ref_rej)
        loss      = -F.logsigmoid(args.beta * log_ratio)

        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(policy.parameters(), 1.0)
        opt.step()

        if step % 100 == 0:
            print(f"step {step:5d}  loss {loss.item():.4f}  {time.time()-t0:.1f}s")
            t0 = time.time()

    final = os.path.join(args.out_dir, "final.pt")
    torch.save({"model": policy.state_dict(), "config": ckpt["config"]}, final)
    print(f"DPO complete -> {final}")


if __name__ == "__main__":
    main()