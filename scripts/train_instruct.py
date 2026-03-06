#!/usr/bin/env python3
"""
train_instruct.py -- Supervised Fine-Tuning on threat modeling Q&A.

Usage:
    python scripts/train_instruct.py \\
        --base_ckpt  checkpoints/base/final.pt \\
        --data_file  data/synth/synth_qa.jsonl \\
        --out_dir    checkpoints/instruct

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
from pathlib import Path


INSTRUCT_TEMPLATE = (
    "<|begin_of_text|><|start_header_id|>system<|end_header_id|>

"
    "{system}<|eot_id|>"
    "<|start_header_id|>user<|end_header_id|>

"
    "{instruction}<|eot_id|>"
    "<|start_header_id|>assistant<|end_header_id|>

"
    "{response}<|eot_id|>"
)

SYSTEM_PROMPT = (
    "You are ThreataformLM, a cybersecurity expert specialising in threat modeling, "
    "cloud infrastructure security, and compliance. Provide clear, actionable analysis."
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base_ckpt",   required=True)
    ap.add_argument("--data_file",   default="data/synth/synth_qa.jsonl")
    ap.add_argument("--vocab_model", default="data/vocab/threataform_bpe.model")
    ap.add_argument("--out_dir",     default="checkpoints/instruct")
    ap.add_argument("--steps",       type=int, default=5000)
    ap.add_argument("--batch",       type=int, default=4)
    ap.add_argument("--lr",          type=float, default=1e-5)
    ap.add_argument("--max_len",     type=int, default=2048)
    args = ap.parse_args()

    import sentencepiece as spm
    from train_base import ThreataformLM

    os.makedirs(args.out_dir, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    sp = spm.SentencePieceProcessor()
    sp.Load(args.vocab_model)

    ckpt  = torch.load(args.base_ckpt, map_location="cpu")
    model = ThreataformLM(ckpt["config"]).to(device)
    model.load_state_dict(ckpt["model"])

    pairs = [json.loads(l) for l in open(args.data_file, encoding="utf-8")]
    print(f"Loaded {len(pairs)} training pairs")

    opt = AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)

    model.train()
    import random
    t0 = time.time()

    for step in range(1, args.steps + 1):
        batch_loss = 0.0
        opt.zero_grad()

        for _ in range(args.batch):
            p   = random.choice(pairs)
            txt = INSTRUCT_TEMPLATE.format(
                system=SYSTEM_PROMPT,
                instruction=p["instruction"],
                response=p["response"],
            )
            ids = sp.EncodeAsIds(txt)[:args.max_len]
            if len(ids) < 4:
                continue

            asst_marker = sp.EncodeAsIds("<|start_header_id|>assistant<|end_header_id|>

")
            asst_start  = len(ids)
            for i in range(len(ids) - len(asst_marker)):
                if ids[i:i+len(asst_marker)] == asst_marker:
                    asst_start = i + len(asst_marker)
                    break

            x = torch.tensor(ids[:-1], dtype=torch.long, device=device).unsqueeze(0)
            y = torch.tensor(ids[1:],  dtype=torch.long, device=device).unsqueeze(0)

            logits = model(x)

            mask = torch.zeros(y.shape, device=device)
            mask[:, asst_start:] = 1.0

            loss = (F.cross_entropy(logits.view(-1, logits.size(-1)), y.view(-1),
                                    reduction="none") * mask.view(-1)).mean()
            (loss / args.batch).backward()
            batch_loss += loss.item() / args.batch

        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()

        if step % 50 == 0:
            print(f"step {step:5d}  loss {batch_loss:.4f}  {time.time()-t0:.1f}s")
            t0 = time.time()

        if step % 1000 == 0:
            path = os.path.join(args.out_dir, f"step_{step}.pt")
            torch.save({"model": model.state_dict(), "config": ckpt["config"]}, path)

    final = os.path.join(args.out_dir, "final.pt")
    torch.save({"model": model.state_dict(), "config": ckpt["config"]}, final)
    print(f"SFT complete -> {final}")


if __name__ == "__main__":
    main()