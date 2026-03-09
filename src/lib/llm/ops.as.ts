/**
 * ops.as.ts — ThreataformLM WASM Acceleration Layer
 * AssemblyScript source for SIMD-tiled ML operations.
 *
 * Implements the hot-path math primitives for the transformer forward pass.
 * When compiled, this replaces the pure-JS fallbacks in Ops.js for a
 * 3-8× throughput improvement via SIMD f32x4 vectorization.
 *
 * Build (requires Node.js):
 *   npm install -g assemblyscript
 *   asc src/lib/llm/ops.as.ts \
 *       -o src/lib/llm/ops.wasm \
 *       --enable simd \
 *       --optimize -O3 \
 *       --runtime stub \
 *       --exportRuntime false
 *
 * Or use the helper script:
 *   node scripts/build_wasm.js    (Windows)
 *   bash scripts/build_wasm.sh   (Linux/macOS)
 *
 * Memory layout in the shared 32 MiB WebAssembly.Memory (initial: 512 pages):
 *   [0,       128K)  — output buffer  (max 32K f32)
 *   [128K,    256K)  — x / input vec  (max 32K f32)
 *   [256K,   32M)    — W weight mat   (max ~7.9M f32, covers any single attention
 *                                       or FFN weight in a 200M model)
 *
 * JS caller (Ops.js) copies inputs to these regions, calls the export, then
 * reads the output region. All pointers are byte offsets into linear memory.
 */

// ─── Dense matrix × vector (SIMD) ────────────────────────────────────────────
// out[rows] = W[rows × cols] @ x[cols]
// W is row-major stored (W[i][j] = W_byte_offset[i*cols + j]).
// Pointers: byte offsets into WASM linear memory.
//
// SIMD strategy: process 4 consecutive columns per iteration using f32x4,
// horizontal-sum the accumulator, handle the tail (cols % 4) as scalar.
//
// Expected gain over pure JS: 3-4× (SIMD) × 1.3× (WASM JIT) ≈ 4-5×.
export function matmulF32(
  outPtr: i32,
  WPtr:   i32,
  xPtr:   i32,
  rows:   i32,
  cols:   i32,
): void {
  const cols4: i32 = cols & ~3;    // largest multiple of 4 ≤ cols (scalar tail start)
  const colsBytes: i32 = cols << 2; // cols * sizeof(f32)

  for (let i: i32 = 0; i < rows; i++) {
    let acc: v128  = f32x4.splat(0.0);
    const wBase: i32 = WPtr + i * colsBytes;

    // SIMD lane: 4 f32 per cycle
    let j: i32 = 0;
    for (; j < cols4; j += 4) {
      const jOff: i32 = j << 2;
      acc = f32x4.add(acc, f32x4.mul(
        v128.load(wBase + jOff),
        v128.load(xPtr  + jOff),
      ));
    }

    // Horizontal sum of the SIMD accumulator
    let val: f32 = f32x4.extract_lane(acc, 0)
                 + f32x4.extract_lane(acc, 1)
                 + f32x4.extract_lane(acc, 2)
                 + f32x4.extract_lane(acc, 3);

    // Scalar tail (cols % 4 remaining elements)
    for (; j < cols; j++) {
      val += load<f32>(wBase + (j << 2)) * load<f32>(xPtr + (j << 2));
    }

    store<f32>(outPtr + (i << 2), val);
  }
}

// ─── Accumulating matrix × vector (for LoRA delta) ───────────────────────────
// out[rows] += W[rows × cols] @ x[cols]
// Same SIMD strategy as matmulF32 but adds into the existing output.
export function matmulAccumF32(
  outPtr: i32,
  WPtr:   i32,
  xPtr:   i32,
  rows:   i32,
  cols:   i32,
): void {
  const cols4:  i32 = cols & ~3;
  const colsBytes: i32 = cols << 2;

  for (let i: i32 = 0; i < rows; i++) {
    let acc: v128    = f32x4.splat(0.0);
    const wBase: i32 = WPtr + i * colsBytes;

    let j: i32 = 0;
    for (; j < cols4; j += 4) {
      const jOff: i32 = j << 2;
      acc = f32x4.add(acc, f32x4.mul(
        v128.load(wBase + jOff),
        v128.load(xPtr  + jOff),
      ));
    }

    let delta: f32 = f32x4.extract_lane(acc, 0)
                   + f32x4.extract_lane(acc, 1)
                   + f32x4.extract_lane(acc, 2)
                   + f32x4.extract_lane(acc, 3);

    for (; j < cols; j++) {
      delta += load<f32>(wBase + (j << 2)) * load<f32>(xPtr + (j << 2));
    }

    const p: i32 = outPtr + (i << 2);
    store<f32>(p, load<f32>(p) + delta);
  }
}

// ─── RMSNorm ──────────────────────────────────────────────────────────────────
// out[i] = weight[i] * x[i] / sqrt(mean(x²) + eps)
// LLaMA-style: no mean subtraction, RMS scaling only.
export function rmsNorm(
  outPtr:    i32,
  xPtr:      i32,
  weightPtr: i32,
  n:         i32,
  eps:       f32,
): void {
  // Compute sum-of-squares using SIMD
  const n4: i32 = n & ~3;
  let accSS: v128 = f32x4.splat(0.0);
  let j: i32 = 0;
  for (; j < n4; j += 4) {
    const v4 = v128.load(xPtr + (j << 2));
    accSS = f32x4.add(accSS, f32x4.mul(v4, v4));
  }
  let ss: f32 = f32x4.extract_lane(accSS, 0)
              + f32x4.extract_lane(accSS, 1)
              + f32x4.extract_lane(accSS, 2)
              + f32x4.extract_lane(accSS, 3);
  for (; j < n; j++) {
    const v = load<f32>(xPtr + (j << 2));
    ss += v * v;
  }

  const scale: f32 = 1.0 / Mathf.sqrt(ss / <f32>n + eps);
  const scaleVec: v128 = f32x4.splat(scale);

  // Apply scale + weight using SIMD
  j = 0;
  for (; j < n4; j += 4) {
    const jOff: i32 = j << 2;
    const x4 = v128.load(xPtr      + jOff);
    const w4 = v128.load(weightPtr + jOff);
    v128.store(outPtr + jOff, f32x4.mul(w4, f32x4.mul(scaleVec, x4)));
  }
  for (; j < n; j++) {
    const jOff: i32 = j << 2;
    store<f32>(outPtr + jOff,
      load<f32>(weightPtr + jOff) * (scale * load<f32>(xPtr + jOff)));
  }
}

// ─── Softmax in-place ─────────────────────────────────────────────────────────
// arr[offset .. offset+n] = softmax(arr[offset .. offset+n])
// Numerically stable: subtract max before exp.
export function softmaxInplace(arrPtr: i32, offset: i32, n: i32): void {
  const base: i32 = arrPtr + (offset << 2);

  // Pass 1: find max
  let maxVal: f32 = load<f32>(base);
  for (let i: i32 = 1; i < n; i++) {
    const v = load<f32>(base + (i << 2));
    if (v > maxVal) maxVal = v;
  }

  // Pass 2: exp(x - max) and sum
  let sum: f32 = 0.0;
  for (let i: i32 = 0; i < n; i++) {
    const ptr: i32 = base + (i << 2);
    const e: f32   = Mathf.exp(load<f32>(ptr) - maxVal);
    store<f32>(ptr, e);
    sum += e;
  }

  // Pass 3: normalize
  const inv: f32 = 1.0 / sum;
  const invVec: v128 = f32x4.splat(inv);
  const n4: i32 = n & ~3;
  let j: i32 = 0;
  for (; j < n4; j += 4) {
    const ptr: i32 = base + (j << 2);
    v128.store(ptr, f32x4.mul(v128.load(ptr), invVec));
  }
  for (; j < n; j++) {
    const ptr: i32 = base + (j << 2);
    store<f32>(ptr, load<f32>(ptr) * inv);
  }
}

// ─── RoPE: apply rotary positional embeddings in-place ───────────────────────
// Rotates Q or K at token position `pos`.
// vecPtr/vecOffset: byte pointer + element offset into the Q or K vector
// realPtr/imagPtr:  RoPE frequency table (Float32Array, [maxSeq * headDim/2])
export function ropeInplace(
  vecPtr:    i32,
  vecOffset: i32,
  headDim:   i32,
  pos:       i32,
  realPtr:   i32,
  imagPtr:   i32,
): void {
  const half: i32   = headDim >> 1;
  const tableBase   = pos * half;
  const vBase: i32  = vecPtr + (vecOffset << 2);

  for (let i: i32 = 0; i < half; i++) {
    const p0: i32 = vBase + ((2 * i)     << 2);
    const p1: i32 = vBase + ((2 * i + 1) << 2);
    const x0: f32 = load<f32>(p0);
    const x1: f32 = load<f32>(p1);
    const cr: f32 = load<f32>(realPtr + ((tableBase + i) << 2));
    const ci: f32 = load<f32>(imagPtr + ((tableBase + i) << 2));
    store<f32>(p0, x0 * cr - x1 * ci);
    store<f32>(p1, x0 * ci + x1 * cr);
  }
}

// ─── Q4 block dequantize (one 32-weight block → 32 f32) ──────────────────────
// Block layout: [f16_scale(2 bytes)] [nibbles(16 bytes)]
// Each nibble = uint4 ∈ [0,15]; value = scale * (nibble - 8)
export function dequantQ4Block(
  rawPtr:    i32,
  rawOffset: i32,
  f32OutPtr: i32,
  f32Offset: i32,
): void {
  const bOff: i32 = rawPtr + rawOffset;
  const scale: f32 = f16ToF32(load<u8>(bOff) | (<u32>load<u8>(bOff + 1) << 8));

  for (let i: i32 = 0; i < 16; i++) {
    const byte: u8  = load<u8>(bOff + 2 + i);
    const lo:   i32 = (byte & 0x0F) - 8;
    const hi:   i32 = (byte >> 4)   - 8;
    store<f32>(f32OutPtr + ((f32Offset + i)      << 2), scale * <f32>lo);
    store<f32>(f32OutPtr + ((f32Offset + i + 16) << 2), scale * <f32>hi);
  }
}

// ─── Q8 block dequantize (one 32-weight block → 32 f32) ──────────────────────
// Block layout: [f16_scale(2 bytes)] [int8 × 32]
export function dequantQ8Block(
  rawPtr:    i32,
  rawOffset: i32,
  f32OutPtr: i32,
  f32Offset: i32,
): void {
  const bOff: i32  = rawPtr + rawOffset;
  const scale: f32 = f16ToF32(load<u8>(bOff) | (<u32>load<u8>(bOff + 1) << 8));

  for (let i: i32 = 0; i < 32; i++) {
    const q: i32 = <i32>load<i8>(bOff + 2 + i); // sign-extend to i32
    store<f32>(f32OutPtr + ((f32Offset + i) << 2), scale * <f32>q);
  }
}

// ─── Cosine similarity (two f32 vectors in WASM memory) ─────────────────────
// Returns cosine similarity as a f32 result stored at outPtr.
// Used by dense retrieval / HNSW search from a potential future WASM path.
export function cosineSim(aPtr: i32, bPtr: i32, n: i32, outPtr: i32): void {
  const n4: i32 = n & ~3;
  let dot: v128 = f32x4.splat(0.0);
  let na:  v128 = f32x4.splat(0.0);
  let nb:  v128 = f32x4.splat(0.0);

  let j: i32 = 0;
  for (; j < n4; j += 4) {
    const jOff: i32 = j << 2;
    const a4 = v128.load(aPtr + jOff);
    const b4 = v128.load(bPtr + jOff);
    dot = f32x4.add(dot, f32x4.mul(a4, b4));
    na  = f32x4.add(na,  f32x4.mul(a4, a4));
    nb  = f32x4.add(nb,  f32x4.mul(b4, b4));
  }

  let dotS: f32 = f32x4.extract_lane(dot, 0) + f32x4.extract_lane(dot, 1)
                + f32x4.extract_lane(dot, 2) + f32x4.extract_lane(dot, 3);
  let naS:  f32 = f32x4.extract_lane(na,  0) + f32x4.extract_lane(na,  1)
                + f32x4.extract_lane(na,  2) + f32x4.extract_lane(na,  3);
  let nbS:  f32 = f32x4.extract_lane(nb,  0) + f32x4.extract_lane(nb,  1)
                + f32x4.extract_lane(nb,  2) + f32x4.extract_lane(nb,  3);

  for (; j < n; j++) {
    const ai: f32 = load<f32>(aPtr + (j << 2));
    const bi: f32 = load<f32>(bPtr + (j << 2));
    dotS += ai * bi;
    naS  += ai * ai;
    nbS  += bi * bi;
  }

  const denom: f32 = Mathf.sqrt(naS) * Mathf.sqrt(nbS) + 1e-10;
  store<f32>(outPtr, dotS / denom);
}

// ─── Internal: f16 bit pattern → f32 ─────────────────────────────────────────
@inline
function f16ToF32(h: u32): f32 {
  const exp:  u32 = (h >> 10) & 0x1F;
  const mant: u32 =  h        & 0x3FF;
  const sign: u32 = (h >> 15) & 1;

  if (exp == 0) {
    // Denormalized
    return (sign != 0 ? -1.0 : 1.0) * 5.9604644775390625e-8 * <f32>mant;
  }
  if (exp == 31) {
    // Inf / NaN — reinterpret bits directly
    const bits: u32 = (sign << 31) | 0x7F800000 | (mant << 13);
    return reinterpret<f32>(bits);
  }
  // Normalized: shift exponent bias (15 → 127) and mantissa
  const bits: u32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
  return reinterpret<f32>(bits);
}
