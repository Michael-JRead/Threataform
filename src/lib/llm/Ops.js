/**
 * Ops.js — ThreataformLM Math Primitives
 *
 * All transformer operations implemented from scratch in pure JavaScript.
 * No WASM, no WebGPU, no external libraries. Every operation runs on
 * Float32Array / Uint8Array using standard JS typed-array loops.
 *
 * Architecture reference:
 *   rasbt/LLMs-from-scratch (GPT-2 style)
 *   FareedKhan-dev/Building-llama3-from-scratch (LLaMA-3 style)
 *   epicure/llama2.js (pure-JS inference kernel)
 */

// ─── Float16 ↔ Float32 ────────────────────────────────────────────────────────

/** Convert IEEE 754 float16 (uint16) to float32. Pure bit manipulation. */
export function f16ToF32(h) {
  const sign = (h >> 15) & 1;
  const exp  = (h >> 10) & 0x1F;
  const mant =  h        & 0x3FF;
  if (exp === 0)  return (sign ? -1 : 1) * 5.9604644775390625e-8 * mant;
  if (exp === 31) return mant ? NaN : (sign ? -Infinity : Infinity);
  return (sign ? -1 : 1) * Math.pow(2, exp - 15) * (1 + mant / 1024);
}

/** Convert float32 to float16 bits (uint16). Used in quantization. */
export function f32ToF16(f) {
  const buf = new ArrayBuffer(4);
  new Float32Array(buf)[0] = f;
  const u = new Uint32Array(buf)[0];
  const sign = (u >> 31) & 1;
  const exp  = ((u >> 23) & 0xFF) - 127 + 15;
  const mant = (u >> 13) & 0x3FF;
  if (exp <= 0)  return sign << 15;
  if (exp >= 31) return (sign << 15) | 0x7C00;
  return (sign << 15) | (exp << 10) | mant;
}

// ─── Dense Matrix × Vector ────────────────────────────────────────────────────

/**
 * Dense matrix-vector multiply: out[rows] = W[rows × cols] @ x[cols]
 * W is row-major: W[i * cols + j] = W[i][j]
 * This is the hot path — every transformer operation flows through here.
 */
export function matmul(out, W, x, rows, cols) {
  for (let i = 0; i < rows; i++) {
    let val = 0.0;
    const row = i * cols;
    for (let j = 0; j < cols; j++) val += W[row + j] * x[j];
    out[i] = val;
  }
}

/**
 * Accumulate matrix-vector multiply into out (out += W @ x).
 * Used for LoRA delta application.
 */
export function matmulAccum(out, W, x, rows, cols) {
  for (let i = 0; i < rows; i++) {
    let val = 0.0;
    const row = i * cols;
    for (let j = 0; j < cols; j++) val += W[row + j] * x[j];
    out[i] += val;
  }
}

// ─── Q4 Quantization (our format: 18 bytes per 32 weights) ──────────────────

const Q4_BLOCK_SIZE = 32;  // weights per block
const Q4_BLOCK_BYTES = 18; // 2 (f16 scale) + 16 (nibbles)

/**
 * Quantize 32 float32 values into a Q4 block.
 * Block layout: [f16_scale (2 bytes)] [nibbles (16 bytes)]
 * Each nibble: uint4 ∈ [0, 15], dequant: scale * (nibble - 8)
 */
export function quantizeQ4Block(f32arr, f32Offset, rawOut, rawOffset) {
  // Find max absolute value → scale
  let maxAbs = 0;
  for (let i = 0; i < 32; i++) {
    const v = Math.abs(f32arr[f32Offset + i]);
    if (v > maxAbs) maxAbs = v;
  }
  const scale = maxAbs / 7;          // map [-7,7] → [-maxAbs, maxAbs]
  const invScale = scale > 0 ? 1 / scale : 0;

  // Write f16 scale
  const scaleU16 = f32ToF16(scale);
  rawOut[rawOffset]     = scaleU16 & 0xFF;
  rawOut[rawOffset + 1] = (scaleU16 >> 8) & 0xFF;

  // Pack nibbles
  for (let i = 0; i < 16; i++) {
    const lo = Math.max(0, Math.min(15, Math.round(f32arr[f32Offset + i]      * invScale + 8)));
    const hi = Math.max(0, Math.min(15, Math.round(f32arr[f32Offset + i + 16] * invScale + 8)));
    rawOut[rawOffset + 2 + i] = (hi << 4) | lo;
  }
}

/**
 * Dequantize a Q4 block back to 32 float32 values.
 */
export function dequantQ4Block(raw, rawOffset, f32Out, f32Offset) {
  const scaleU16 = raw[rawOffset] | (raw[rawOffset + 1] << 8);
  const scale = f16ToF32(scaleU16);
  for (let i = 0; i < 16; i++) {
    const byte = raw[rawOffset + 2 + i];
    f32Out[f32Offset + i]      = scale * ((byte & 0x0F) - 8);
    f32Out[f32Offset + i + 16] = scale * ((byte >> 4)   - 8);
  }
}

/**
 * Quantize a full weight matrix (rows × cols) to Q4.
 * Returns Uint8Array of Q4 blocks.
 */
export function quantizeQ4(f32, rows, cols) {
  const n = rows * cols;
  const nBlocks = Math.ceil(n / Q4_BLOCK_SIZE);
  const raw = new Uint8Array(nBlocks * Q4_BLOCK_BYTES);
  for (let b = 0; b < nBlocks; b++) {
    // Pad last block with zeros if needed
    const src = new Float32Array(32);
    const start = b * 32;
    for (let i = 0; i < 32 && start + i < n; i++) src[i] = f32[start + i];
    quantizeQ4Block(src, 0, raw, b * Q4_BLOCK_BYTES);
  }
  return raw;
}

/**
 * Q4 matrix-vector multiply: out[rows] = Q4(W)[rows × cols] @ x[cols]
 * Dequantizes row-by-row during multiply — avoids materializing the full
 * F32 weight matrix (which would be 4× larger than the Q4 file).
 */
export function matmulQ4(out, wRaw, x, rows, cols) {
  const blocksPerRow = Math.ceil(cols / Q4_BLOCK_SIZE);
  for (let i = 0; i < rows; i++) {
    let val = 0.0;
    const rowBlockOffset = i * blocksPerRow * Q4_BLOCK_BYTES;
    for (let b = 0; b < blocksPerRow; b++) {
      const bOff = rowBlockOffset + b * Q4_BLOCK_BYTES;
      const scaleU16 = wRaw[bOff] | (wRaw[bOff + 1] << 8);
      const scale = f16ToF32(scaleU16);
      const jBase = b * Q4_BLOCK_SIZE;
      for (let k = 0; k < 16 && jBase + k < cols; k++) {
        const byte = wRaw[bOff + 2 + k];
        if (jBase + k < cols)      val += scale * ((byte & 0x0F) - 8) * x[jBase + k];
        if (jBase + k + 16 < cols) val += scale * ((byte >> 4)   - 8) * x[jBase + k + 16];
      }
    }
    out[i] = val;
  }
}

// ─── Q8 Quantization (34 bytes per 32 weights) ───────────────────────────────

const Q8_BLOCK_SIZE  = 32;
const Q8_BLOCK_BYTES = 34; // 2 (f16 scale) + 32 (int8)

export function quantizeQ8Block(f32arr, f32Offset, rawOut, rawOffset) {
  let maxAbs = 0;
  for (let i = 0; i < 32; i++) {
    const v = Math.abs(f32arr[f32Offset + i]);
    if (v > maxAbs) maxAbs = v;
  }
  const scale = maxAbs / 127;
  const invScale = scale > 0 ? 1 / scale : 0;
  const scaleU16 = f32ToF16(scale);
  rawOut[rawOffset]     = scaleU16 & 0xFF;
  rawOut[rawOffset + 1] = (scaleU16 >> 8) & 0xFF;
  for (let i = 0; i < 32; i++) {
    const q = Math.max(-127, Math.min(127, Math.round(f32arr[f32Offset + i] * invScale)));
    rawOut[rawOffset + 2 + i] = q & 0xFF; // two's complement stored as uint8
  }
}

export function matmulQ8(out, wRaw, x, rows, cols) {
  const blocksPerRow = Math.ceil(cols / Q8_BLOCK_SIZE);
  const view = new DataView(wRaw.buffer ?? wRaw);
  const wOff = wRaw.byteOffset ?? 0;
  for (let i = 0; i < rows; i++) {
    let val = 0.0;
    const rowBlockOff = i * blocksPerRow * Q8_BLOCK_BYTES;
    for (let b = 0; b < blocksPerRow; b++) {
      const bOff = wOff + rowBlockOff + b * Q8_BLOCK_BYTES;
      const scaleU16 = view.getUint16(bOff, true);
      const scale = f16ToF32(scaleU16);
      const jBase = b * Q8_BLOCK_SIZE;
      for (let k = 0; k < 32 && jBase + k < cols; k++) {
        const q = view.getInt8(bOff + 2 + k);
        val += scale * q * x[jBase + k];
      }
    }
    out[i] = val;
  }
}

// ─── Normalization ────────────────────────────────────────────────────────────

/**
 * RMSNorm (LLaMA-style) — no mean subtraction, only RMS scaling.
 * out[i] = x[i] / sqrt(mean(x²) + eps) * weight[i]
 */
export function rmsnorm(out, x, weight, n, eps = 1e-5) {
  let ss = 0.0;
  for (let i = 0; i < n; i++) ss += x[i] * x[i];
  const scale = 1.0 / Math.sqrt(ss / n + eps);
  for (let i = 0; i < n; i++) out[i] = weight[i] * (scale * x[i]);
}

/**
 * LayerNorm (GPT-2 style) — subtracts mean, divides by std, scales + biases.
 * out[i] = (x[i] - mean) / sqrt(var + eps) * weight[i] + bias[i]
 */
export function layernorm(out, x, weight, bias, n, eps = 1e-5) {
  let mean = 0.0;
  for (let i = 0; i < n; i++) mean += x[i];
  mean /= n;
  let vari = 0.0;
  for (let i = 0; i < n; i++) { const d = x[i] - mean; vari += d * d; }
  vari /= n;
  const scale = 1.0 / Math.sqrt(vari + eps);
  for (let i = 0; i < n; i++) out[i] = weight[i] * ((x[i] - mean) * scale) + bias[i];
}

// ─── Softmax ──────────────────────────────────────────────────────────────────

/**
 * Numerically stable softmax in-place over arr[offset .. offset+n].
 * Subtracts max before exp to prevent overflow.
 */
export function softmax(arr, offset, n) {
  let maxVal = arr[offset];
  for (let i = 1; i < n; i++) if (arr[offset + i] > maxVal) maxVal = arr[offset + i];
  let sum = 0.0;
  for (let i = 0; i < n; i++) { arr[offset + i] = Math.exp(arr[offset + i] - maxVal); sum += arr[offset + i]; }
  const inv = 1.0 / sum;
  for (let i = 0; i < n; i++) arr[offset + i] *= inv;
}

// ─── Activations ─────────────────────────────────────────────────────────────

/** SiLU (Swish): x * sigmoid(x) = x / (1 + exp(-x)) — SwiGLU gate. */
export function silu(x) { return x / (1.0 + Math.exp(-x)); }

/** GELU: 0.5x(1 + tanh(√(2/π)(x + 0.044715x³))) — GPT-2 activation. */
export function gelu(x) {
  return 0.5 * x * (1 + Math.tanh(Math.sqrt(2 / Math.PI) * (x + 0.044715 * x * x * x)));
}

// ─── Vector Ops ───────────────────────────────────────────────────────────────

/** In-place add: a[i] += b[i] */
export function vecAdd(a, b, n) { for (let i = 0; i < n; i++) a[i] += b[i]; }

/** Cosine similarity between two Float32Arrays. */
export function cosineSim(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i]*b[i]; na += a[i]*a[i]; nb += b[i]*b[i]; }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
}

/** Dot product of two Float32Arrays. */
export function dotProduct(a, aOff, b, bOff, n) {
  let s = 0;
  for (let i = 0; i < n; i++) s += a[aOff + i] * b[bOff + i];
  return s;
}

/** L2-normalize a Float32Array in-place. */
export function l2Normalize(v, n) {
  let norm = 0;
  for (let i = 0; i < n; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm) + 1e-10;
  for (let i = 0; i < n; i++) v[i] /= norm;
}

/** Copy n floats from src[srcOff] to dst[dstOff]. */
export function fcopy(dst, dstOff, src, srcOff, n) {
  for (let i = 0; i < n; i++) dst[dstOff + i] = src[srcOff + i];
}

// ─── Rotary Positional Embeddings (RoPE) ─────────────────────────────────────

/**
 * Build RoPE frequency table for all positions up to maxSeq.
 * Supports YaRN scaling for context extension beyond training length.
 *
 * Returns { real: Float32Array, imag: Float32Array }
 * Shape: [maxSeq * headDim/2]
 */
export function buildRoPETable(headDim, maxSeq, theta = 10000.0, yarnScale = 1.0) {
  const half = headDim >> 1;
  const real = new Float32Array(maxSeq * half);
  const imag = new Float32Array(maxSeq * half);
  for (let pos = 0; pos < maxSeq; pos++) {
    for (let i = 0; i < half; i++) {
      const freq = 1.0 / (Math.pow(theta, (2 * i) / headDim) * yarnScale);
      const angle = pos * freq;
      real[pos * half + i] = Math.cos(angle);
      imag[pos * half + i] = Math.sin(angle);
    }
  }
  return { real, imag };
}

/**
 * Apply RoPE in-place to a Q or K vector at sequence position `pos`.
 * vec: Float32Array, vecOffset: start index, headDim: per-head dimension
 */
export function applyRoPE(vec, vecOffset, headDim, pos, ropeReal, ropeImag) {
  const half = headDim >> 1;
  const base = pos * half;
  for (let i = 0; i < half; i++) {
    const x0 = vec[vecOffset + 2 * i];
    const x1 = vec[vecOffset + 2 * i + 1];
    const cr  = ropeReal[base + i];
    const ci  = ropeImag[base + i];
    vec[vecOffset + 2 * i]     = x0 * cr - x1 * ci;
    vec[vecOffset + 2 * i + 1] = x0 * ci + x1 * cr;
  }
}

// ─── Sampling ─────────────────────────────────────────────────────────────────

/**
 * Greedy sampling: return argmax of logits.
 * Deterministic (temperature = 0).
 */
export function greedySample(logits) {
  let best = 0;
  for (let i = 1; i < logits.length; i++) if (logits[i] > logits[best]) best = i;
  return best;
}

/**
 * Top-P (nucleus) sampling with temperature.
 * Sorts by probability, accumulates until cumProb >= p, samples from that set.
 */
export function sampleTopP(logits, temp, topP) {
  const n = logits.length;
  // Apply temperature
  const scaled = new Float32Array(n);
  for (let i = 0; i < n; i++) scaled[i] = logits[i] / (temp + 1e-10);
  // Softmax
  softmax(scaled, 0, n);
  // Sort indices by probability descending
  const indices = Array.from({ length: n }, (_, i) => i);
  indices.sort((a, b) => scaled[b] - scaled[a]);
  // Accumulate until topP
  let cumProb = 0;
  let cutoff = n;
  for (let i = 0; i < n; i++) {
    cumProb += scaled[indices[i]];
    if (cumProb >= topP) { cutoff = i + 1; break; }
  }
  // Sample from nucleus
  const r = Math.random() * cumProb;
  let acc = 0;
  for (let i = 0; i < cutoff; i++) {
    acc += scaled[indices[i]];
    if (acc >= r) return indices[i];
  }
  return indices[0];
}

/**
 * Top-K sampling with temperature.
 */
export function sampleTopK(logits, temp, topK) {
  const n = logits.length;
  const scaled = new Float32Array(n);
  for (let i = 0; i < n; i++) scaled[i] = logits[i] / (temp + 1e-10);
  softmax(scaled, 0, n);
  const indices = Array.from({ length: n }, (_, i) => i);
  indices.sort((a, b) => scaled[b] - scaled[a]);
  const k = Math.min(topK, n);
  let sum = 0;
  for (let i = 0; i < k; i++) sum += scaled[indices[i]];
  const r = Math.random() * sum;
  let acc = 0;
  for (let i = 0; i < k; i++) {
    acc += scaled[indices[i]];
    if (acc >= r) return indices[i];
  }
  return indices[0];
}

// ─── Attention with KV Cache ──────────────────────────────────────────────────

/**
 * Multi-head attention with Grouped Query Attention (GQA) and KV cache.
 *
 * q:        Float32Array [nHeads * headDim]   — current query
 * keyCache: Float32Array [nLayers * maxSeq * dim]  — accumulated keys
 * valCache: Float32Array [nLayers * maxSeq * dim]  — accumulated values
 * attn:     Float32Array [maxSeq]             — scratch buffer for attention weights
 * xb:       Float32Array [dim]                — output buffer
 *
 * GQA: nKVHeads query heads share key/value heads (nHeads/nKVHeads per KV head)
 */
export function groupedQueryAttention(xb, q, keyCache, valCache, attn, pos,
    layer, nHeads, nKVHeads, headDim, maxSeq, dim) {
  const kvMul  = (nHeads / nKVHeads) | 0;  // query heads per KV head
  const layOff = layer * maxSeq * dim;
  const invSqrt = 1.0 / Math.sqrt(headDim);

  for (let h = 0; h < nHeads; h++) {
    const kvHead = (h / kvMul) | 0;
    const qOff   = h * headDim;

    // Dot q[h] against all past keys for this KV head
    for (let t = 0; t <= pos; t++) {
      const kOff = layOff + t * dim + kvHead * headDim;
      let score = 0.0;
      for (let i = 0; i < headDim; i++) score += q[qOff + i] * keyCache[kOff + i];
      attn[t] = score * invSqrt;
    }

    // Causal softmax over positions 0..pos
    softmax(attn, 0, pos + 1);

    // Weighted sum of value vectors
    const xbOff = h * headDim;
    for (let i = 0; i < headDim; i++) xb[xbOff + i] = 0;
    for (let t = 0; t <= pos; t++) {
      const vOff = layOff + t * dim + kvHead * headDim;
      const a = attn[t];
      for (let i = 0; i < headDim; i++) xb[xbOff + i] += a * valCache[vOff + i];
    }
  }
}
