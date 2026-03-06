#!/usr/bin/env python3
"""
train_base.py -- Pre-train ThreataformLM-200M from scratch.

Architecture:
    vocab_size=32000, context_len=4096, dim=1024,
    n_layers=24, n_heads=16, n_kv_heads=4, ffn_hidden=4096

Hardware requirements (estimated):
    1x A100 80GB  ->  ~3 days  (batch=32, grad_accum=4)
    4x RTX 4090   ->  ~5 days  (use torchrun --nproc_per_node=4)

Usage:
    python scripts/train_base.py \\
        --data_dir  data/corpus \\
        --vocab_dir data/vocab \\
        --out_dir   checkpoints/base

Requires:
    pip install torch sentencepiece h5py tqdm
"""

import argparse
import os
import math
import glob
import time
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR

# -- Model config --------------------------------------------------------------
CFG = dict(
    vocab_size   = 32000,
    context_len  = 4096,
    dim          = 1024,
    n_layers     = 24,
    n_heads      = 16,
    n_kv_heads   = 4,
    ffn_hidden   = 4096,
    norm_eps     = 1e-5,
    rope_theta   = 10000,
)


class RMSNorm(nn.Module):
    def __init__(self, dim, eps=1e-5):
        super().__init__()
        self.w   = nn.Parameter(torch.ones(dim))
        self.eps = eps

    def forward(self, x):
        return x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + self.eps) * self.w


def precompute_freqs(dim, max_seq, theta=10000):
    freqs = 1.0 / (theta ** (torch.arange(0, dim, 2).float() / dim))
    t     = torch.arange(max_seq)
    freqs = torch.outer(t, freqs)
    return torch.polar(torch.ones_like(freqs), freqs)


def apply_rope(x, freqs_cis):
    B, T, H, D = x.shape
    x_c = torch.view_as_complex(x.float().reshape(B, T, H, D//2, 2))
    x_r = torch.view_as_real(x_c * freqs_cis[:T].unsqueeze(0).unsqueeze(2)).flatten(-2)
    return x_r.type_as(x)


class Attention(nn.Module):
    def __init__(self, cfg):
        super().__init__()
        self.n_heads    = cfg["n_heads"]
        self.n_kv_heads = cfg["n_kv_heads"]
        self.head_dim   = cfg["dim"] // cfg["n_heads"]
        self.q_per_kv   = self.n_heads // self.n_kv_heads
        dim    = cfg["dim"]
        kv_dim = self.n_kv_heads * self.head_dim

        self.wq = nn.Linear(dim, self.n_heads * self.head_dim, bias=False)
        self.wk = nn.Linear(dim, kv_dim, bias=False)
        self.wv = nn.Linear(dim, kv_dim, bias=False)
        self.wo = nn.Linear(self.n_heads * self.head_dim, dim, bias=False)

    def forward(self, x, freqs_cis, mask=None):
        B, T, D = x.shape
        hd = self.head_dim

        q = self.wq(x).view(B, T, self.n_heads, hd)
        k = self.wk(x).view(B, T, self.n_kv_heads, hd)
        v = self.wv(x).view(B, T, self.n_kv_heads, hd)

        q = apply_rope(q, freqs_cis)
        k = apply_rope(k, freqs_cis)

        # Expand KV for GQA
        k = k.repeat_interleave(self.q_per_kv, dim=2)
        v = v.repeat_interleave(self.q_per_kv, dim=2)

        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        scale = hd ** -0.5
        scores = torch.matmul(q, k.transpose(-2, -1)) * scale
        if mask is not None:
            scores = scores + mask
        scores = F.softmax(scores.float(), dim=-1).type_as(q)
        out = torch.matmul(scores, v).transpose(1, 2).contiguous().view(B, T, -1)
        return self.wo(out)


class FFN(nn.Module):
    def __init__(self, cfg):
        super().__init__()
        self.w1 = nn.Linear(cfg["dim"], cfg["ffn_hidden"], bias=False)
        self.w2 = nn.Linear(cfg["ffn_hidden"], cfg["dim"], bias=False)
        self.w3 = nn.Linear(cfg["dim"], cfg["ffn_hidden"], bias=False)

    def forward(self, x):
        return self.w2(F.silu(self.w1(x)) * self.w3(x))


class TransformerBlock(nn.Module):
    def __init__(self, cfg):
        super().__init__()
        self.attn      = Attention(cfg)
        self.ffn       = FFN(cfg)
        self.attn_norm = RMSNorm(cfg["dim"], cfg["norm_eps"])
        self.ffn_norm  = RMSNorm(cfg["dim"], cfg["norm_eps"])

    def forward(self, x, freqs_cis, mask):
        x = x + self.attn(self.attn_norm(x), freqs_cis, mask)
        x = x + self.ffn(self.ffn_norm(x))
        return x


class ThreataformLM(nn.Module):
    def __init__(self, cfg):
        super().__init__()
        self.cfg    = cfg
        self.embed  = nn.Embedding(cfg["vocab_size"], cfg["dim"])
        self.layers = nn.ModuleList([TransformerBlock(cfg) for _ in range(cfg["n_layers"])])
        self.norm   = RMSNorm(cfg["dim"], cfg["norm_eps"])
        # Tied output projection
        self.register_buffer("freqs_cis",
            precompute_freqs(cfg["dim"] // cfg["n_heads"], cfg["context_len"], cfg["rope_theta"]))

    def forward(self, x):
        B, T = x.shape
        h    = self.embed(x)
        mask = torch.full((T, T), float("-inf"), device=x.device).triu(1)

        for layer in self.layers:
            h = layer(h, self.freqs_cis, mask)

        h   = self.norm(h)
        out = F.linear(h, self.embed.weight)  # tied LM head
        return out

    def num_params(self):
        return sum(p.numel() for p in self.parameters())


def get_batch(tokens, batch_size, context_len, device):
    """Sample a random batch of (inputs, targets) from a flat token tensor."""
    ix = torch.randint(len(tokens) - context_len, (batch_size,))
    x  = torch.stack([tokens[i:i+context_len]     for i in ix]).to(device)
    y  = torch.stack([tokens[i+1:i+context_len+1] for i in ix]).to(device)
    return x, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_dir",   default="data/corpus")
    ap.add_argument("--vocab_dir",  default="data/vocab")
    ap.add_argument("--out_dir",    default="checkpoints/base")
    ap.add_argument("--steps",      type=int, default=200_000)
    ap.add_argument("--batch",      type=int, default=8)
    ap.add_argument("--lr",         type=float, default=3e-4)
    ap.add_argument("--warmup",     type=int, default=2000)
    ap.add_argument("--grad_accum", type=int, default=4)
    ap.add_argument("--resume",     default=None)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")

    data_file = os.path.join(args.data_dir, "tokens.pt")
    if not os.path.exists(data_file):
        print(f"Expected pre-tokenised file at {data_file}.")
        print("To create it, tokenise your corpus with sentencepiece and save as a 1D int32 tensor.")
        return

    tokens = torch.load(data_file, map_location="cpu")
    print(f"Loaded {len(tokens):,} tokens")

    model = ThreataformLM(CFG).to(device)
    print(f"Model parameters: {model.num_params()/1e6:.1f}M")

    opt   = AdamW(model.parameters(), lr=args.lr, betas=(0.9, 0.95),
                  eps=1e-8, weight_decay=0.1)
    sched = CosineAnnealingLR(opt, T_max=args.steps - args.warmup, eta_min=args.lr * 0.1)

    start_step = 0
    if args.resume and os.path.exists(args.resume):
        ckpt = torch.load(args.resume, map_location=device)
        model.load_state_dict(ckpt["model"])
        opt.load_state_dict(ckpt["opt"])
        start_step = ckpt.get("step", 0)
        print(f"Resumed from step {start_step}")

    model.train()
    opt.zero_grad()
    t0 = time.time()

    for step in range(start_step + 1, args.steps + 1):
        # Warmup LR
        if step <= args.warmup:
            lr = args.lr * step / args.warmup
            for g in opt.param_groups: g['lr'] = lr

        x, y = get_batch(tokens, args.batch, CFG["context_len"], device)
        logits = model(x)
        loss   = F.cross_entropy(logits.view(-1, CFG["vocab_size"]), y.view(-1))
        (loss / args.grad_accum).backward()

        if step % args.grad_accum == 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            if step > args.warmup:
                sched.step()
            opt.zero_grad()

        if step % 100 == 0:
            dt = time.time() - t0
            print(f"step {step:6d}  loss {loss.item():.4f}  lr {opt.param_groups[0]['lr']:.2e}  {dt:.1f}s")
            t0 = time.time()

        if step % 5000 == 0:
            ckpt_path = os.path.join(args.out_dir, f"step_{step}.pt")
            torch.save({"model": model.state_dict(), "opt": opt.state_dict(), "step": step,
                        "config": CFG}, ckpt_path)
            print(f"  Checkpoint saved: {ckpt_path}")

    final_path = os.path.join(args.out_dir, "final.pt")
    torch.save({"model": model.state_dict(), "config": CFG}, final_path)
    print(f"Training complete -> {final_path}")


if __name__ == "__main__":
    main()