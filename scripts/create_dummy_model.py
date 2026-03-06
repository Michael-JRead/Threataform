#!/usr/bin/env python3
"""
scripts/create_dummy_model.py
Generate a minimal smoke-test .tnlm model with random weights.

Uses stdlib only (struct, json, math, random) — no PyTorch, no NumPy required.

Nano config (exercises the full browser LLM pipeline in < 50ms load time):
  vocab_size = 1000, dim = 64, n_layers = 2, n_heads = 4,
  n_kv_heads = 1, ffn_hidden = 128, context_len = 128

Output is ~70KB.  All weights are random — inference produces garbage text,
but this is intentional: the goal is to verify the loading pipeline, IDB cache,
and streaming generation all work correctly before running real training.

Usage:
  python scripts/create_dummy_model.py
  python scripts/create_dummy_model.py --out public/model.tnlm --seed 42
"""

import argparse
import json
import math
import random
import struct
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
#  Nano config
# ──────────────────────────────────────────────────────────────────────────────

NANO_CONFIG = {
    "vocab_size":     1000,
    "context_len":    128,
    "dim":            64,
    "n_layers":       2,
    "n_heads":        4,       # head_dim = 64 / 4 = 16
    "n_kv_heads":     1,       # GQA: 4 Q heads share 1 KV head
    "ffn_hidden":     128,
    "norm_eps":       1e-5,
    "rope_theta":     10000,
    "yarn_scale":     1.0,
    "tie_embeddings": True,    # lm_head = tok_embeddings.T
    "format":         "tnlm",
    "quant":          "mixed_q4q8",
}

# .tnlm dtype constants (must match WeightsLoader.js)
DTYPE_F32 = 0
DTYPE_Q4  = 1
DTYPE_Q8  = 2

Q4_BLOCK_SIZE  = 32   # weights per Q4 block
Q4_BLOCK_BYTES = 18   # 2B f16 scale + 16B nibbles
Q8_BLOCK_SIZE  = 32   # weights per Q8 block
Q8_BLOCK_BYTES = 34   # 2B f16 scale + 32B int8

# These name substrings get Q8 (higher precision for critical projections)
# Must match Ops.js / quantize.py logic
Q8_PATTERNS = {"attention.wo", "feed_forward.w2", "output"}

# ──────────────────────────────────────────────────────────────────────────────
#  Random weight generation (pure Python, no numpy)
# ──────────────────────────────────────────────────────────────────────────────

def randn(n: int, scale: float = 0.02) -> list[float]:
    """Box-Muller normal distribution, n samples from N(0, scale²)."""
    out = []
    i = 0
    while len(out) < n:
        u1 = random.random() + 1e-12
        u2 = random.random()
        mag = scale * math.sqrt(-2.0 * math.log(u1))
        out.append(mag * math.cos(2.0 * math.pi * u2))
        out.append(mag * math.sin(2.0 * math.pi * u2))
    return out[:n]

def ones(n: int) -> list[float]:
    return [1.0] * n

# ──────────────────────────────────────────────────────────────────────────────
#  Float16 helper (IEEE 754 half-precision, little-endian)
#  struct 'e' format is supported in Python 3.6+
# ──────────────────────────────────────────────────────────────────────────────

def f32_to_f16_le(v: float) -> bytes:
    try:
        return struct.pack('<e', v)
    except (struct.error, OverflowError):
        return struct.pack('<e', max(-65504.0, min(65504.0, v)))

# ──────────────────────────────────────────────────────────────────────────────
#  Quantization — must exactly match Ops.js dequantization
# ──────────────────────────────────────────────────────────────────────────────

def encode_f32(weights: list[float]) -> bytes:
    return struct.pack(f'<{len(weights)}f', *weights)


def encode_q4(weights: list[float]) -> bytearray:
    """
    Q4 block format (18 bytes per 32 weights):
      [2B f16 scale LE] [16B nibbles]

    Nibble layout (from Ops.js dequantQ4Block):
      byte i:  low  nibble = weight[i]      → dequant: (nibble & 0x0F) - 8) * scale
               high nibble = weight[i + 16] → dequant: ((nibble >> 4) - 8) * scale

    Scale = max_abs / 7  (range [-7, 7] → multiply by scale)
    Stored: unsigned nibble = quantized_value + 8  (so [-8,7] → [0,15])
    """
    buf = bytearray()
    n = len(weights)

    for blk in range(0, n, Q4_BLOCK_SIZE):
        block = weights[blk: blk + Q4_BLOCK_SIZE]
        # Pad last block with zeros if short
        while len(block) < Q4_BLOCK_SIZE:
            block.append(0.0)

        # Scale = max_abs / 7
        max_abs = max(abs(w) for w in block)
        scale   = max_abs / 7.0 if max_abs > 1e-30 else 1.0

        buf += f32_to_f16_le(scale)

        # Quantize: q ∈ [-7, 7], stored as q + 8 ∈ [1, 15] (0 unused but valid)
        inv = 1.0 / scale
        q = [max(-8, min(7, int(round(w * inv)))) for w in block]

        # Pack: byte i = low(weight[i]) | high(weight[i+16])
        for i in range(16):
            lo = (q[i]      + 8) & 0xF
            hi = (q[i + 16] + 8) & 0xF
            buf.append(lo | (hi << 4))

    return buf


def encode_q8(weights: list[float]) -> bytearray:
    """
    Q8 block format (34 bytes per 32 weights):
      [2B f16 scale LE] [32B int8]

    Scale = max_abs / 127, stored int8 ∈ [-127, 127]
    Dequant: int8 * scale
    """
    buf = bytearray()
    n = len(weights)

    for blk in range(0, n, Q8_BLOCK_SIZE):
        block = weights[blk: blk + Q8_BLOCK_SIZE]
        while len(block) < Q8_BLOCK_SIZE:
            block.append(0.0)

        max_abs = max(abs(w) for w in block)
        scale   = max_abs / 127.0 if max_abs > 1e-30 else 1.0

        buf += f32_to_f16_le(scale)

        inv = 1.0 / scale
        for w in block:
            q = max(-127, min(127, int(round(w * inv))))
            buf += struct.pack('<b', q)

    return buf

# ──────────────────────────────────────────────────────────────────────────────
#  Tensor list — one entry per weight matrix
# ──────────────────────────────────────────────────────────────────────────────

def build_tensor_list(cfg: dict) -> list[tuple]:
    """
    Returns list of (name, shape, weights_flat, dtype).
    Follows the same naming convention as Model.js and quantize.py.
    """
    V   = cfg['vocab_size']
    D   = cfg['dim']
    L   = cfg['n_layers']
    NH  = cfg['n_heads']
    NKV = cfg['n_kv_heads']
    FFN = cfg['ffn_hidden']
    HD  = D // NH  # head_dim

    tensors = []

    # ── Global ──────────────────────────────────────────────────────────────
    # tok_embeddings is treated as embedding → F32
    tensors.append(('tok_embeddings', [V, D], randn(V * D, 0.02), DTYPE_F32))
    # Final RMSNorm — 1D → F32
    tensors.append(('norm', [D], ones(D), DTYPE_F32))

    # ── Per-layer ────────────────────────────────────────────────────────────
    for l in range(L):
        p = f'layers.{l}'

        # Attention pre-norm — 1D → F32
        tensors.append((f'{p}.attention_norm', [D], ones(D), DTYPE_F32))

        # Q projection: [n_heads * head_dim, dim] → Q4
        tensors.append((f'{p}.attention.wq',
                        [NH * HD, D], randn(NH * HD * D, 0.02), DTYPE_Q4))

        # K/V projections: [n_kv_heads * head_dim, dim] → Q4
        tensors.append((f'{p}.attention.wk',
                        [NKV * HD, D], randn(NKV * HD * D, 0.02), DTYPE_Q4))
        tensors.append((f'{p}.attention.wv',
                        [NKV * HD, D], randn(NKV * HD * D, 0.02), DTYPE_Q4))

        # O projection: [dim, dim] → Q8  (matches Q8_PATTERNS "attention.wo")
        tensors.append((f'{p}.attention.wo',
                        [D, D], randn(D * D, 0.02), DTYPE_Q8))

        # FFN pre-norm — 1D → F32
        tensors.append((f'{p}.ffn_norm', [D], ones(D), DTYPE_F32))

        # FFN gate (w1) and up (w3): [ffn_hidden, dim] → Q4
        tensors.append((f'{p}.feed_forward.w1',
                        [FFN, D], randn(FFN * D, 0.02), DTYPE_Q4))
        tensors.append((f'{p}.feed_forward.w3',
                        [FFN, D], randn(FFN * D, 0.02), DTYPE_Q4))

        # FFN down (w2): [dim, ffn_hidden] → Q8  (matches "feed_forward.w2")
        tensors.append((f'{p}.feed_forward.w2',
                        [D, FFN], randn(D * FFN, 0.02), DTYPE_Q8))

    return tensors

# ──────────────────────────────────────────────────────────────────────────────
#  .tnlm binary writer
# ──────────────────────────────────────────────────────────────────────────────

def write_tnlm(path: Path, cfg: dict, tensors: list[tuple]) -> int:
    """Write the .tnlm file. Returns bytes written."""
    config_json = json.dumps(cfg).encode('utf-8')

    with open(path, 'wb') as f:
        # ── Header ──────────────────────────────────────────────────────────
        f.write(b'TNLM')
        f.write(struct.pack('<I', 2))                   # version = 2
        f.write(struct.pack('<I', len(config_json)))
        f.write(config_json)

        # ── Tensors ─────────────────────────────────────────────────────────
        for name, shape, weights, dtype in tensors:
            name_bytes = name.encode('utf-8')
            f.write(struct.pack('<I', len(name_bytes)))
            f.write(name_bytes)
            f.write(struct.pack('<I', dtype))
            f.write(struct.pack('<I', len(shape)))
            for d in shape:
                f.write(struct.pack('<I', d))

            if dtype == DTYPE_F32:
                f.write(encode_f32(weights))
            elif dtype == DTYPE_Q4:
                f.write(encode_q4(weights))
            elif dtype == DTYPE_Q8:
                f.write(encode_q8(weights))
            else:
                raise ValueError(f"Unknown dtype {dtype} for '{name}'")

    return path.stat().st_size

# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Generate a smoke-test ThreataformLM model with random weights'
    )
    ap.add_argument('--out',  default='public/model.tnlm',
                    help='Output .tnlm path (default: public/model.tnlm)')
    ap.add_argument('--seed', type=int, default=42,
                    help='Random seed for reproducible weights (default: 42)')
    ap.add_argument('--verbose', action='store_true',
                    help='Print every tensor name and size')
    args = ap.parse_args()

    random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    cfg     = NANO_CONFIG.copy()
    tensors = build_tensor_list(cfg)

    print('Creating smoke-test ThreataformLM model...')
    print(f'  Config : vocab={cfg["vocab_size"]} dim={cfg["dim"]} '
          f'layers={cfg["n_layers"]} heads={cfg["n_heads"]}/'
          f'{cfg["n_kv_heads"]} ffn={cfg["ffn_hidden"]}')

    total_params = 0
    dtype_names  = {DTYPE_F32: 'f32', DTYPE_Q4: 'q4', DTYPE_Q8: 'q8'}

    for name, shape, _weights, dtype in tensors:
        n = 1
        for d in shape: n *= d
        total_params += n
        if args.verbose:
            print(f'  {dtype_names[dtype]:3s}  {name:45s}  {shape}  ({n:,} params)')

    n_bytes = write_tnlm(out, cfg, tensors)

    print(f'  Params : {total_params:,}')
    print(f'  Output : {out}  ({n_bytes / 1024:.1f} KB)')
    print()
    print('Done. To test in the browser:')
    print('  npm run dev:web   ->  http://127.0.0.1:5173')
    print('  Create a threat model -> Intelligence -> AI Assistant')
    print('  The engine will auto-load /model.tnlm and show "Ready"')
    print()
    print('NOTE: Random weights produce garbage tokens - that is expected.')
    print('      Run train_base.py + quantize.py for real model weights.')


if __name__ == '__main__':
    main()
