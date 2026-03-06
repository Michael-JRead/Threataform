#!/usr/bin/env python3
"""
quantize.py -- Post-training quantization F32->Q4/Q8 + export to .tnlm format.

Q4 block format  (18 bytes per 32 weights):
    [2B f16 scale][16B nibbles: 32 weights packed as 4-bit values]

Q8 block format  (34 bytes per 32 weights):
    [2B f16 scale][32B int8 values]

Output: public/model.tnlm  (~50MB for 200M params with Q4)

Usage:
    python scripts/quantize.py \\
        --ckpt     checkpoints/dpo/final.pt \\
        --out      public/model.tnlm

Requires:
    pip install torch numpy
"""

import argparse
import os
import struct
import json
import numpy as np
import torch


MAGIC   = b"TNLM"
VERSION = 2

DTYPE_F32 = 0
DTYPE_Q4  = 1
DTYPE_Q8  = 2
DTYPE_F16 = 3

Q_BLOCK = 32  # weights per quantization block

# Layers to quantize to Q8 (higher precision for critical projections)
Q8_PATTERNS = {"attention.wo", "feed_forward.w2", "output"}


def quantize_q4_block(weights_32):
    """Quantize 32 float32 weights to Q4 block (18 bytes)."""
    scale = np.max(np.abs(weights_32)) / 7.0
    if scale < 1e-30:
        return bytes(18)
    quant   = np.clip(np.round(weights_32 / scale).astype(np.int32), -7, 7)
    nibbles = (quant + 8).astype(np.uint8)
    packed  = np.zeros(16, dtype=np.uint8)
    for i in range(16):
        packed[i] = nibbles[2*i] | (nibbles[2*i+1] << 4)
    scale_f16 = np.float16(scale).view(np.uint16)
    return struct.pack("<H", scale_f16) + packed.tobytes()


def quantize_q8_block(weights_32):
    """Quantize 32 float32 weights to Q8 block (34 bytes)."""
    scale = np.max(np.abs(weights_32)) / 127.0
    if scale < 1e-30:
        return bytes(34)
    quant     = np.clip(np.round(weights_32 / scale).astype(np.int32), -127, 127).astype(np.int8)
    scale_f16 = np.float16(scale).view(np.uint16)
    return struct.pack("<H", scale_f16) + quant.tobytes()


def quantize_tensor(weights, use_q8=False):
    """Quantize a full 2D weight tensor (rows x cols)."""
    flat   = weights.flatten().numpy().astype(np.float32)
    n      = len(flat)
    n_blks = (n + Q_BLOCK - 1) // Q_BLOCK
    out    = bytearray()

    for b in range(n_blks):
        chunk = flat[b*Q_BLOCK : (b+1)*Q_BLOCK]
        if len(chunk) < Q_BLOCK:
            chunk = np.pad(chunk, (0, Q_BLOCK - len(chunk)))
        out += quantize_q8_block(chunk) if use_q8 else quantize_q4_block(chunk)

    return bytes(out)


def write_tensor(f, name, data, dtype, shape):
    name_enc = name.encode("utf-8")
    f.write(struct.pack(">I", len(name_enc)))
    f.write(name_enc)
    f.write(struct.pack(">I", dtype))
    f.write(struct.pack(">I", len(shape)))
    for d in shape: f.write(struct.pack(">I", d))
    f.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt",       required=True)
    ap.add_argument("--out",        default="public/model.tnlm")
    ap.add_argument("--vocab_json", default=None,
                    help="Optionally embed vocab JSON in the .tnlm")
    args = ap.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    print(f"Loading checkpoint: {args.ckpt}")
    ckpt = torch.load(args.ckpt, map_location="cpu")
    cfg  = ckpt["config"]
    sd   = ckpt["model"]

    config_json = json.dumps({**cfg, "format": "tnlm", "quant": "mixed_q4q8"}).encode("utf-8")

    print(f"Exporting to: {args.out}")
    with open(args.out, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">I", VERSION))
        f.write(struct.pack(">I", len(config_json)))
        f.write(config_json)

        total_bytes = 0
        for name, tensor in sd.items():
            if tensor.dtype != torch.float32:
                tensor = tensor.float()
            weights = tensor.detach()

            use_q8   = any(p in name for p in Q8_PATTERNS)
            is_1d    = len(weights.shape) == 1
            is_embed = "embed" in name

            if is_1d or is_embed:
                data  = weights.numpy().astype(np.float32).tobytes()
                dtype = DTYPE_F32
                shape = list(weights.shape)
            elif use_q8:
                data  = quantize_tensor(weights, use_q8=True)
                dtype = DTYPE_Q8
                shape = list(weights.shape)
            else:
                data  = quantize_tensor(weights, use_q8=False)
                dtype = DTYPE_Q4
                shape = list(weights.shape)

            write_tensor(f, name, data, dtype, shape)
            total_bytes += len(data)
            print(f"  {name:60s} {dtype}  {list(weights.shape)} -> {len(data)//1024}KB")

        if args.vocab_json and os.path.exists(args.vocab_json):
            vocab_data = open(args.vocab_json, "rb").read()
            f.write(struct.pack(">I", len(b"__vocab__")))
            f.write(b"__vocab__")
            f.write(struct.pack(">I", DTYPE_F32))
            f.write(struct.pack(">I", 1))
            f.write(struct.pack(">I", 1))
            f.write(struct.pack(">I", len(vocab_data)))
            f.write(vocab_data)

    size_mb = os.path.getsize(args.out) / 1024 / 1024
    print(f"
.tnlm file: {args.out}  ({size_mb:.1f} MB)")
    print("Done. Place public/model.tnlm in the app and run npm run build.")


if __name__ == "__main__":
    main()