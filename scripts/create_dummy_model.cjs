#!/usr/bin/env node
/**
 * scripts/create_dummy_model.js
 * Generate a minimal smoke-test .tnlm model with random weights.
 * No dependencies beyond Node.js built-ins.
 *
 * Nano config:  vocab=1000, dim=64, layers=2, heads=4/1, ffn=128, ctx=128
 * Output size:  ~70KB
 * Purpose:      Verify full browser LLM pipeline without GPU training
 *
 * Usage:
 *   node scripts/create_dummy_model.js
 *   node scripts/create_dummy_model.js --out public/model.tnlm --verbose
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─── CLI args ────────────────────────────────────────────────────────────────
const args    = process.argv.slice(2);
const outPath = args.includes('--out') ? args[args.indexOf('--out') + 1] : 'public/model.tnlm';
const verbose = args.includes('--verbose') || args.includes('-v');
const seed    = args.includes('--seed') ? parseInt(args[args.indexOf('--seed') + 1]) : 42;

// ─── Nano config ─────────────────────────────────────────────────────────────
const CFG = {
  vocab_size:     1000,
  context_len:    128,
  dim:            64,
  n_layers:       2,
  n_heads:        4,       // head_dim = 64/4 = 16
  n_kv_heads:     1,       // GQA: 4 Q heads share 1 KV head
  ffn_hidden:     128,
  norm_eps:       1e-5,
  rope_theta:     10000,
  yarn_scale:     1.0,
  tie_embeddings: true,    // lm_head = tok_embeddings.T (no separate output tensor)
  format:         'tnlm',
  quant:          'mixed_q4q8',
};

// .tnlm dtype constants — must match WeightsLoader.js
const DTYPE_F32 = 0;
const DTYPE_Q4  = 1;
const DTYPE_Q8  = 2;

const Q4_BLOCK  = 32;   // weights per Q4 block
const Q4_BYTES  = 18;   // 2B f16 scale + 16B nibbles
const Q8_BLOCK  = 32;   // weights per Q8 block
const Q8_BYTES  = 34;   // 2B f16 scale + 32B int8

const Q8_PATTERNS = ['attention.wo', 'feed_forward.w2', 'output'];

// ─── Seeded PRNG (xorshift32) ─────────────────────────────────────────────────
let _state = seed >>> 0 || 1;
function _rand() {
  _state ^= _state << 13;
  _state ^= _state >>> 17;
  _state ^= _state << 5;
  return (_state >>> 0) / 4294967296;
}

// Box-Muller normal distribution N(0, scale²)
function randn(n, scale = 0.02) {
  const out = new Float32Array(n);
  for (let i = 0; i < n; i += 2) {
    const u1 = _rand() + 1e-12;
    const u2 = _rand();
    const mag = scale * Math.sqrt(-2 * Math.log(u1));
    out[i]     = mag * Math.cos(2 * Math.PI * u2);
    if (i + 1 < n) out[i + 1] = mag * Math.sin(2 * Math.PI * u2);
  }
  return out;
}

function ones(n) {
  return new Float32Array(n).fill(1.0);
}

// ─── Float16 (IEEE 754 half-precision) — matches Ops.js f32ToF16 ─────────────
function f32ToF16(v) {
  // Reference: https://en.wikipedia.org/wiki/Half-precision_floating-point_format
  const buf = Buffer.alloc(4);
  buf.writeFloatLE(v, 0);
  const x = buf.readUInt32LE(0);

  const sign = (x >>> 31) & 0x1;
  let exp    = (x >>> 23) & 0xFF;
  let frac   = (x & 0x7FFFFF);

  if (exp === 0xFF) {
    // NaN / Inf
    return (sign << 15) | 0x7C00 | (frac ? 0x200 : 0);
  }
  exp = exp - 127 + 15;
  if (exp >= 31) {
    // Overflow → Inf
    return (sign << 15) | 0x7C00;
  }
  if (exp <= 0) {
    // Underflow → zero (or denormal, simplify to zero)
    return (sign << 15);
  }
  frac = frac >>> 13;  // 23-bit → 10-bit mantissa
  return (sign << 15) | (exp << 10) | frac;
}

function writeF16LE(buf, offset, v) {
  const u16 = f32ToF16(v);
  buf[offset]     = u16 & 0xFF;
  buf[offset + 1] = (u16 >>> 8) & 0xFF;
}

// ─── Quantization — must exactly match Ops.js dequantization ─────────────────

function encodeF32(weights) {
  const out = Buffer.alloc(weights.length * 4);
  for (let i = 0; i < weights.length; i++) {
    out.writeFloatLE(weights[i], i * 4);
  }
  return out;
}

/**
 * Q4 block format (18 bytes per 32 weights):
 *   [2B f16 scale LE] [16B nibbles]
 *
 * Nibble layout — MUST match Ops.js dequantQ4Block:
 *   byte[i]:  low  nibble = weight[i]      → dequant: (nibble & 0x0F) - 8) * scale
 *             high nibble = weight[i + 16] → dequant: ((nibble >> 4) - 8) * scale
 *   i = 0..15
 *
 * Scale = maxAbs / 7;  quantized ∈ [-7,7], stored as q+8 ∈ [1,15]
 */
function encodeQ4(weights) {
  const n       = weights.length;
  const nBlocks = Math.ceil(n / Q4_BLOCK);
  const out     = Buffer.alloc(nBlocks * Q4_BYTES);
  let off = 0;

  for (let blk = 0; blk < nBlocks; blk++) {
    const start   = blk * Q4_BLOCK;
    const end     = Math.min(start + Q4_BLOCK, n);

    // Find max absolute value in this block
    let maxAbs = 0;
    for (let i = start; i < end; i++) {
      const a = Math.abs(weights[i]);
      if (a > maxAbs) maxAbs = a;
    }
    const scale    = maxAbs > 1e-30 ? maxAbs / 7 : 1.0;
    const invScale = 1.0 / scale;

    // Write f16 scale
    writeF16LE(out, off, scale);
    off += 2;

    // Quantize all 32 weights (pad with 0 if block is short)
    const q = new Uint8Array(32);   // unsigned nibble values [0,15]
    for (let i = 0; i < 32; i++) {
      const w = (start + i < n) ? weights[start + i] : 0;
      let qi  = Math.round(w * invScale);
      qi      = Math.max(-8, Math.min(7, qi));
      q[i]    = qi + 8;  // shift to [0,15]
    }

    // Pack: byte[i] = low(weight[i]) | high(weight[i+16])
    for (let i = 0; i < 16; i++) {
      out[off++] = (q[i] & 0xF) | ((q[i + 16] & 0xF) << 4);
    }
  }
  return out;
}

/**
 * Q8 block format (34 bytes per 32 weights):
 *   [2B f16 scale LE] [32B int8]
 * Scale = maxAbs / 127; dequant: int8 * scale
 */
function encodeQ8(weights) {
  const n       = weights.length;
  const nBlocks = Math.ceil(n / Q8_BLOCK);
  const out     = Buffer.alloc(nBlocks * Q8_BYTES);
  let off = 0;

  for (let blk = 0; blk < nBlocks; blk++) {
    const start = blk * Q8_BLOCK;
    const end   = Math.min(start + Q8_BLOCK, n);

    let maxAbs = 0;
    for (let i = start; i < end; i++) {
      const a = Math.abs(weights[i]);
      if (a > maxAbs) maxAbs = a;
    }
    const scale    = maxAbs > 1e-30 ? maxAbs / 127 : 1.0;
    const invScale = 1.0 / scale;

    writeF16LE(out, off, scale);
    off += 2;

    for (let i = 0; i < 32; i++) {
      const w = (start + i < n) ? weights[start + i] : 0;
      let qi  = Math.round(w * invScale);
      qi      = Math.max(-127, Math.min(127, qi));
      out.writeInt8(qi, off++);
    }
  }
  return out;
}

// ─── Tensor list ─────────────────────────────────────────────────────────────

function buildTensorList(cfg) {
  const { vocab_size: V, dim: D, n_layers: L, n_heads: NH,
          n_kv_heads: NKV, ffn_hidden: FFN } = cfg;
  const HD = D / NH;  // head_dim

  const tensors = [];

  // Global
  tensors.push(['tok_embeddings', [V, D],      randn(V * D, 0.02),       DTYPE_F32]);
  tensors.push(['norm',           [D],          ones(D),                  DTYPE_F32]);

  for (let l = 0; l < L; l++) {
    const p = `layers.${l}`;
    tensors.push([`${p}.attention_norm`,    [D],          ones(D),                   DTYPE_F32]);
    tensors.push([`${p}.attention.wq`,      [NH*HD, D],   randn(NH*HD*D, 0.02),      DTYPE_Q4]);
    tensors.push([`${p}.attention.wk`,      [NKV*HD, D],  randn(NKV*HD*D, 0.02),     DTYPE_Q4]);
    tensors.push([`${p}.attention.wv`,      [NKV*HD, D],  randn(NKV*HD*D, 0.02),     DTYPE_Q4]);
    tensors.push([`${p}.attention.wo`,      [D, D],       randn(D*D, 0.02),           DTYPE_Q8]);
    tensors.push([`${p}.ffn_norm`,          [D],          ones(D),                   DTYPE_F32]);
    tensors.push([`${p}.feed_forward.w1`,   [FFN, D],     randn(FFN*D, 0.02),        DTYPE_Q4]);
    tensors.push([`${p}.feed_forward.w3`,   [FFN, D],     randn(FFN*D, 0.02),        DTYPE_Q4]);
    tensors.push([`${p}.feed_forward.w2`,   [D, FFN],     randn(D*FFN, 0.02),        DTYPE_Q8]);
  }

  return tensors;
}

// ─── .tnlm writer ────────────────────────────────────────────────────────────

function writeTnlm(outFile, cfg, tensors) {
  const chunks = [];
  const dtypeNames = { [DTYPE_F32]: 'f32', [DTYPE_Q4]: 'q4', [DTYPE_Q8]: 'q8' };

  // Header
  const cfgJson    = Buffer.from(JSON.stringify(cfg), 'utf8');
  const hdr        = Buffer.alloc(4 + 4 + 4);
  hdr.write('TNLM', 0, 'ascii');
  hdr.writeUInt32LE(2, 4);                   // version
  hdr.writeUInt32LE(cfgJson.length, 8);      // config length
  chunks.push(hdr, cfgJson);

  let totalParams = 0;
  for (const [name, shape, weights, dtype] of tensors) {
    const nameBytes = Buffer.from(name, 'utf8');
    const nDims     = shape.length;
    const meta      = Buffer.alloc(4 + nameBytes.length + 4 + 4 + nDims * 4);
    let mo = 0;
    meta.writeUInt32LE(nameBytes.length, mo); mo += 4;
    nameBytes.copy(meta, mo);                 mo += nameBytes.length;
    meta.writeUInt32LE(dtype, mo);            mo += 4;
    meta.writeUInt32LE(nDims, mo);            mo += 4;
    for (const d of shape) { meta.writeUInt32LE(d, mo); mo += 4; }
    chunks.push(meta);

    let data;
    if      (dtype === DTYPE_F32) data = encodeF32(weights);
    else if (dtype === DTYPE_Q4)  data = encodeQ4(weights);
    else if (dtype === DTYPE_Q8)  data = encodeQ8(weights);
    chunks.push(data);

    const n = shape.reduce((a, b) => a * b, 1);
    totalParams += n;

    if (verbose) {
      console.log(`  ${dtypeNames[dtype]}  ${name.padEnd(45)}  [${shape.join(',')}]  (${n.toLocaleString()} params)`);
    }
  }

  const buf = Buffer.concat(chunks);
  fs.mkdirSync(path.dirname(path.resolve(outFile)), { recursive: true });
  fs.writeFileSync(outFile, buf);
  return { bytes: buf.length, totalParams };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const tensors       = buildTensorList(CFG);
const { bytes, totalParams } = writeTnlm(outPath, CFG, tensors);

const cfg = CFG;
console.log('Smoke-test ThreataformLM model created.');
console.log(`  Config : vocab=${cfg.vocab_size} dim=${cfg.dim} layers=${cfg.n_layers} heads=${cfg.n_heads}/${cfg.n_kv_heads} ffn=${cfg.ffn_hidden}`);
console.log(`  Params : ${totalParams.toLocaleString()}`);
console.log(`  Output : ${outPath}  (${(bytes / 1024).toFixed(1)} KB)`);
console.log('');
console.log('To test in the browser:');
console.log('  npm run dev:web   →  http://127.0.0.1:5173');
console.log('  Create a threat model → Intelligence → AI Assistant');
console.log('  Engine will auto-load /model.tnlm and show "Ready"');
console.log('');
console.log('NOTE: Random weights produce garbage tokens — expected behaviour.');
console.log('      Run train_base.py + quantize.py for production model weights.');
