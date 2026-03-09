/**
 * Ops.js — ThreataformLM Math Primitives
 *
 * Primary hot-path operations for transformer inference.  When ops.wasm is
 * present (compiled from ops.as.ts via AssemblyScript), the critical kernels
 * route through SIMD-accelerated WebAssembly for a 3-5× throughput gain.
 * When the WASM binary is absent the pure-JS fallbacks run transparently.
 *
 * Architecture reference:
 *   rasbt/LLMs-from-scratch (GPT-2 style)
 *   FareedKhan-dev/Building-llama3-from-scratch (LLaMA-3 style)
 *   epicure/llama2.js (pure-JS inference kernel)
 *
 * Build the WASM module (one-time, needs AssemblyScript installed):
 *   npm install -g assemblyscript
 *   node scripts/build_wasm.js
 */

// ─── WASM Acceleration ───────────────────────────────────────────────────────
//
// WASM memory layout (32 MiB = 512 × 64 KiB pages):
//   [0,      128K) — output buffer  (≤ 32K f32 = 128 KB)
//   [128K,   256K) — x input vector (≤ 32K f32 = 128 KB)
//   [256K,    32M) — W weight region (≤ 7.93M f32 ≈ 31.7 MB)
//                    covers any single 4096×1024 FFN or 1024×1024 attn weight
//
// WASM dispatch is enabled when:
//   rows * cols ≤ _WASM_MAX_W_F32   (weight matrix fits in W region)
//   rows        ≤ _WASM_MAX_OUT_F32 (output vector fits in out region)
//   cols        ≤ _WASM_MAX_X_F32   (input vector fits in x region)
//
// For matrices too large for WASM (e.g. vocab projection ≥ 32 M floats),
// the pure-JS fallback is used automatically with no API change.

const _WASM_OUT_PTR   =            0; // byte offset: output  start
const _WASM_X_PTR     =  128 * 1024; // byte offset: x input start (128 KB)
const _WASM_W_PTR     =  256 * 1024; // byte offset: W matrix start (256 KB)
const _WASM_MEM_PAGES =          512; // 512 × 64 KB = 32 MiB
const _WASM_MAX_OUT_F32 =  32 * 1024; // 32K f32 = 128 KB (rows limit)
const _WASM_MAX_X_F32   =  32 * 1024; // 32K f32 = 128 KB (cols limit)
const _WASM_MAX_W_F32   = 7 * 1024 * 1024 + 928 * 1024; // ~7.9M f32 ≈ 31.7 MB

/** WASM module instance — null until loadOpsWasm() succeeds. */
let _wasm = null;

/**
 * Attempt to load the WASM acceleration module.
 * Safe to call multiple times (idempotent after first success).
 * Called once by ThreataformLM constructor; never blocks inference.
 *
 * @returns {Promise<boolean>} true if WASM loaded, false if JS fallback.
 */
export async function loadOpsWasm() {
  if (_wasm) return true;
  try {
    const url = new URL('./ops.wasm', import.meta.url);
    const buf = await fetch(url).then(r => {
      if (!r.ok) throw new Error(`WASM fetch ${r.status}: ${url}`);
      return r.arrayBuffer();
    });
    const mem = new WebAssembly.Memory({ initial: _WASM_MEM_PAGES });
    const { instance } = await WebAssembly.instantiate(buf, { env: { memory: mem } });
    _wasm = { ...instance.exports, _mem: mem };
    console.log('[Ops] WASM acceleration loaded — SIMD matmul active');
    return true;
  } catch (e) {
    // Expected when ops.wasm hasn't been built yet.
    console.debug('[Ops] WASM not available, using JS fallback:', e.message);
    _wasm = null;
    return false;
  }
}

/** @returns {boolean} True when WASM is loaded and dispatch is active. */
export function isWasmReady() { return _wasm !== null; }

// ─── Internal WASM copy helpers ───────────────────────────────────────────────

/**
 * Copy a Float32Array slice into the WASM linear memory at a given byte offset.
 * Uses a typed-array view for a single bulk memcpy — no element-by-element loop.
 */
function _copyToWasm(src, srcLen, byteOffset) {
  const view = new Float32Array(_wasm._mem.buffer, byteOffset, srcLen);
  if (src instanceof Float32Array) {
    view.set(src.length === srcLen ? src : src.subarray(0, srcLen));
  } else {
    for (let i = 0; i < srcLen; i++) view[i] = src[i];
  }
}

/**
 * Copy WASM linear memory back into a Float32Array output buffer.
 */
function _copyFromWasm(dst, dstLen, byteOffset) {
  const view = new Float32Array(_wasm._mem.buffer, byteOffset, dstLen);
  dst.set(view);
}

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
 *
 * Routes through SIMD WASM when:
 *   - ops.wasm is loaded (loadOpsWasm() succeeded), AND
 *   - the matrix fits within pre-allocated WASM memory regions
 * Otherwise falls back to pure JS (transparent to callers).
 */
export function matmul(out, W, x, rows, cols) {
  if (_wasm
      && rows * cols <= _WASM_MAX_W_F32
      && rows <= _WASM_MAX_OUT_F32
      && cols <= _WASM_MAX_X_F32) {
    _copyToWasm(W, rows * cols, _WASM_W_PTR);
    _copyToWasm(x, cols,        _WASM_X_PTR);
    _wasm.matmulF32(_WASM_OUT_PTR, _WASM_W_PTR, _WASM_X_PTR, rows, cols);
    _copyFromWasm(out, rows, _WASM_OUT_PTR);
    return;
  }
  // Pure-JS fallback
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
 * Routes through WASM matmulAccumF32 when available.
 */
export function matmulAccum(out, W, x, rows, cols) {
  if (_wasm
      && rows * cols <= _WASM_MAX_W_F32
      && rows <= _WASM_MAX_OUT_F32
      && cols <= _WASM_MAX_X_F32) {
    // Seed the output region with current out values so WASM can accumulate
    _copyToWasm(out, rows, _WASM_OUT_PTR);
    _copyToWasm(W,   rows * cols, _WASM_W_PTR);
    _copyToWasm(x,   cols,        _WASM_X_PTR);
    _wasm.matmulAccumF32(_WASM_OUT_PTR, _WASM_W_PTR, _WASM_X_PTR, rows, cols);
    _copyFromWasm(out, rows, _WASM_OUT_PTR);
    return;
  }
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
 * Routes through WASM rmsNorm for n ≥ 256 (SIMD benefit outweighs copy cost).
 */
export function rmsnorm(out, x, weight, n, eps = 1e-5) {
  if (_wasm && n >= 256 && n <= _WASM_MAX_OUT_F32) {
    _copyToWasm(x,      n, _WASM_X_PTR);
    _copyToWasm(weight, n, _WASM_W_PTR);
    _wasm.rmsNorm(_WASM_OUT_PTR, _WASM_X_PTR, _WASM_W_PTR, n, eps);
    _copyFromWasm(out, n, _WASM_OUT_PTR);
    return;
  }
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
 * For large n (final vocab logits) routes through WASM when loaded.
 */
export function softmax(arr, offset, n) {
  // WASM in-place path: only when arr is a Float32Array (has .subarray) and fits in memory
  if (_wasm && n >= 512 && arr instanceof Float32Array && offset + n <= _WASM_MAX_OUT_F32) {
    const slice = arr.subarray(offset, offset + n);
    _copyToWasm(slice, n, _WASM_OUT_PTR);
    _wasm.softmaxInplace(_WASM_OUT_PTR, 0, n);
    arr.set(new Float32Array(_wasm._mem.buffer, _WASM_OUT_PTR, n), offset);
    return;
  }
  // Pure-JS fallback
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
 * vec: Float32Array, vecOffset: start index, headDim: per-head dimension.
 * Routes through WASM ropeInplace; falls back to JS for very small dims.
 */
export function applyRoPE(vec, vecOffset, headDim, pos, ropeReal, ropeImag) {
  const half = headDim >> 1;
  const base = pos * half;

  if (_wasm && headDim >= 64) {
    // Copy the vec slice (from vecOffset, length headDim) into x region
    // Copy ropeReal/ropeImag tables (base .. base+half) into W region
    const tableLen = base + half; // entries from position 0 to pos
    if (headDim <= _WASM_MAX_OUT_F32 && tableLen <= _WASM_MAX_W_F32 / 2) {
      // Copy vec[vecOffset..vecOffset+headDim] into x region
      const vecSlice = vec.subarray ? vec.subarray(vecOffset, vecOffset + headDim) : null;
      if (vecSlice) _copyToWasm(vecSlice, headDim, _WASM_X_PTR);
      // Copy frequency tables (full from 0..base+half)
      _copyToWasm(ropeReal, tableLen, _WASM_W_PTR);
      _copyToWasm(ropeImag, tableLen, _WASM_W_PTR + tableLen * 4);
      // Call WASM (vecPtr=_WASM_X_PTR, vecOffset=0, headDim, pos, realPtr, imagPtr)
      _wasm.ropeInplace(_WASM_X_PTR, 0, headDim, pos,
                        _WASM_W_PTR, _WASM_W_PTR + tableLen * 4);
      // Write result back
      const outView = new Float32Array(_wasm._mem.buffer, _WASM_X_PTR, headDim);
      vec.set(outView, vecOffset);
      return;
    }
  }

  // Pure-JS fallback
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
