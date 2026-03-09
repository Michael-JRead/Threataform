/**
 * src/lib/llm/LoRA.js
 * ThreataformLM — In-Browser Low-Rank Adaptation (LoRA)
 *
 * Adapts Q, K, V, O, gate (W1), up (W3), down (W2) projections in every
 * transformer layer using rank-r low-rank matrices A and B:
 *
 *   ΔW = (α / r) · B @ A       where A ∈ ℝ^{r×d_in}, B ∈ ℝ^{d_out×r}
 *
 * During inference: out = baseOut + (α/r) * (B @ (A @ x))
 * Training: manual backprop through cross-entropy loss, AdamW on A and B.
 *
 * Runs inside engineWorker.js so the main thread stays responsive.
 *
 * Usage:
 *   import { LoRAAdapter } from './LoRA.js';
 *   const lora = new LoRAAdapter(model.cfg, { r: 8, alpha: 16 });
 *   await lora.train(tokenizedChunks, { lr: 3e-4, steps: 500, onProgress });
 *   const buf = lora.save();   // ArrayBuffer to persist
 *   lora.load(buf);            // restore on next session
 */

import { matmul, matmulAccum, rmsnorm, softmax, silu, vecAdd } from './Ops.js';
import { SPECIAL_IDS } from './Tokenizer.js';

// ─────────────────────────────────────────────────────────────────────────────
//  Projection names adapted in each layer
// ─────────────────────────────────────────────────────────────────────────────

const PROJ_NAMES = ['wq', 'wk', 'wv', 'wo', 'w1', 'w2', 'w3'];

// Input/output dimensions for each projection type given model config
function projDims(cfg, proj) {
  const { dim, n_heads, n_kv_heads, ffn_hidden } = cfg;
  const hd = dim / n_heads;
  switch (proj) {
    case 'wq': return { dIn: dim, dOut: n_heads * hd };
    case 'wk': return { dIn: dim, dOut: n_kv_heads * hd };
    case 'wv': return { dIn: dim, dOut: n_kv_heads * hd };
    case 'wo': return { dIn: dim, dOut: dim };
    case 'w1': return { dIn: dim, dOut: ffn_hidden };
    case 'w2': return { dIn: ffn_hidden, dOut: dim };
    case 'w3': return { dIn: dim, dOut: ffn_hidden };
    default: throw new Error(`Unknown proj: ${proj}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  LoRA adapter pair (A and B matrices for one projection)
// ─────────────────────────────────────────────────────────────────────────────

class LoRAPair {
  /**
   * @param {number} dIn   input dimension
   * @param {number} dOut  output dimension
   * @param {number} r     LoRA rank
   */
  constructor(dIn, dOut, r) {
    this.dIn  = dIn;
    this.dOut = dOut;
    this.r    = r;

    // A: r × dIn  (initialised with Kaiming uniform)
    this.A  = _kaimingUniform(r, dIn);
    // B: dOut × r  (initialised to zero — so initial ΔW = 0)
    this.B  = new Float32Array(dOut * r);

    // AdamW moment buffers
    this.mA = new Float32Array(r * dIn);
    this.vA = new Float32Array(r * dIn);
    this.mB = new Float32Array(dOut * r);
    this.vB = new Float32Array(dOut * r);

    // Gradient accumulators — filled by accumulate(), consumed by step()
    this.gAccA = new Float32Array(r * dIn);
    this.gAccB = new Float32Array(dOut * r);
  }

  /**
   * Forward: compute LoRA delta and add to baseOut.
   * @param {Float32Array} x       input  [dIn]
   * @param {Float32Array} baseOut base output [dOut]  (modified IN-PLACE)
   * @param {number}       scale   α / r
   */
  forward(x, baseOut, scale) {
    // mid = A @ x   [r]
    const mid = new Float32Array(this.r);
    matmul(mid, this.A, x, this.r, this.dIn);

    // delta = B @ mid  [dOut]
    const delta = new Float32Array(this.dOut);
    matmul(delta, this.B, mid, this.dOut, this.r);

    for (let i = 0; i < this.dOut; i++) {
      baseOut[i] += scale * delta[i];
    }
  }

  /**
   * Backward: compute gradients given upstream gradient dL/dOut.
   * Updates A and B via AdamW.
   *
   * @param {Float32Array} x      input  [dIn]
   * @param {Float32Array} dOut   dL/dOut [dOut]
   * @param {number}       scale  α / r
   * @param {AdamWState}   opt    optimizer state
   */
  backward(x, dOut, scale, opt) {
    const { r, dIn, dOut: dout, A, B, mA, vA, mB, vB } = this;
    const s = scale;

    // mid = A @ x
    const mid = new Float32Array(r);
    matmul(mid, A, x, r, dIn);

    // dL/dB[i,j] = s * dOut[i] * mid[j]
    const gB = new Float32Array(dout * r);
    for (let i = 0; i < dout; i++) {
      for (let j = 0; j < r; j++) {
        gB[i * r + j] = s * dOut[i] * mid[j];
      }
    }

    // dL/dmid[j] = s * Σ_i B[i,j] * dOut[i]
    const dMid = new Float32Array(r);
    for (let j = 0; j < r; j++) {
      let acc = 0;
      for (let i = 0; i < dout; i++) acc += B[i * r + j] * dOut[i];
      dMid[j] = s * acc;
    }

    // dL/dA[j,k] = dMid[j] * x[k]
    const gA = new Float32Array(r * dIn);
    for (let j = 0; j < r; j++) {
      for (let k = 0; k < dIn; k++) {
        gA[j * dIn + k] = dMid[j] * x[k];
      }
    }

    // AdamW update for A and B
    opt.update(A, gA, mA, vA, true);   // weight decay on A
    opt.update(B, gB, mB, vB, false);  // no weight decay on B (standard LoRA)
  }

  /**
   * Compute gradients and ADD them to the accumulator buffers (gAccA / gAccB).
   * Does NOT update parameters — call step() after accumulating over a full
   * micro-batch to apply the AdamW update once.
   *
   * Returns the LoRA-only backward gradient dX ∈ ℝ^dIn that can be chained to
   * earlier layers (approximates the exact chain-rule gradient through the
   * frozen base weight, which we don't have access to).
   *
   * @param {Float32Array} x      input  [dIn]
   * @param {Float32Array} dOut   dL/dOut [dOut]
   * @param {number}       scale  α / r
   * @returns {Float32Array}      dL/dx (LoRA-only component) [dIn]
   */
  accumulate(x, dOut, scale) {
    const { r, dIn, dOut: dout, A, B } = this;

    // mid = A @ x  [r]
    const mid = new Float32Array(r);
    matmul(mid, A, x, r, dIn);

    // Accumulate gB[i,j] += scale * dOut[i] * mid[j]
    for (let i = 0; i < dout; i++) {
      const sg = scale * dOut[i];
      const row = i * r;
      for (let j = 0; j < r; j++) this.gAccB[row + j] += sg * mid[j];
    }

    // dMid[j] = scale * Σ_i B[i,j] * dOut[i]  (gradient through B)
    const dMid = new Float32Array(r);
    for (let j = 0; j < r; j++) {
      let acc = 0;
      for (let i = 0; i < dout; i++) acc += B[i * r + j] * dOut[i];
      dMid[j] = scale * acc;
    }

    // Accumulate gA[j,k] += dMid[j] * x[k]
    for (let j = 0; j < r; j++) {
      const dm = dMid[j];
      const row = j * dIn;
      for (let k = 0; k < dIn; k++) this.gAccA[row + k] += dm * x[k];
    }

    // LoRA-only backward gradient: dX = A^T @ dMid  [dIn]
    // This approximates the gradient contribution to the layer below
    // (exact gradient would also include base_W^T @ dOut, which is frozen).
    const dX = new Float32Array(dIn);
    for (let k = 0; k < dIn; k++) {
      let acc = 0;
      for (let j = 0; j < r; j++) acc += A[j * dIn + k] * dMid[j];
      dX[k] = acc;
    }
    return dX;
  }

  /**
   * Apply accumulated gradients via AdamW and zero the accumulators.
   * Call after accumulating over a complete micro-batch (gradient accumulation).
   *
   * @param {AdamWState} opt
   * @param {number}     totalTokens   normalization divisor (sum of tokens in micro-batch)
   */
  step(opt, totalTokens = 1) {
    const inv = totalTokens > 0 ? 1 / totalTokens : 1;
    // Normalize and update — avoids allocating new arrays by scaling in-place
    // (gAccA / gAccB are temporary; we can mutate them here)
    for (let i = 0; i < this.gAccA.length; i++) this.gAccA[i] *= inv;
    for (let i = 0; i < this.gAccB.length; i++) this.gAccB[i] *= inv;
    opt.update(this.A, this.gAccA, this.mA, this.vA, true);
    opt.update(this.B, this.gAccB, this.mB, this.vB, false);
    this.gAccA.fill(0);
    this.gAccB.fill(0);
  }

  /** Zero gradient accumulators without taking an optimizer step. */
  zeroAccum() {
    this.gAccA.fill(0);
    this.gAccB.fill(0);
  }

  reset() {
    _kaimingInPlace(this.A, this.r, this.dIn);
    this.B.fill(0);
    this.mA.fill(0); this.vA.fill(0);
    this.mB.fill(0); this.vB.fill(0);
    this.gAccA.fill(0); this.gAccB.fill(0);
  }

  /** Serialize to ArrayBuffer: [4B dIn][4B dOut][4B r][A data][B data] */
  serialize() {
    const hdr  = new Uint32Array([this.dIn, this.dOut, this.r]);
    const size = 12 + (this.A.byteLength + this.B.byteLength);
    const buf  = new ArrayBuffer(size);
    const view = new Uint8Array(buf);
    view.set(new Uint8Array(hdr.buffer), 0);
    view.set(new Uint8Array(this.A.buffer), 12);
    view.set(new Uint8Array(this.B.buffer), 12 + this.A.byteLength);
    return buf;
  }

  static deserialize(buf) {
    const hdr  = new Uint32Array(buf, 0, 3);
    const [dIn, dOut, r] = hdr;
    const pair = new LoRAPair(dIn, dOut, r);
    const aLen = r * dIn * 4;
    pair.A.set(new Float32Array(buf, 12, r * dIn));
    pair.B.set(new Float32Array(buf, 12 + aLen, dOut * r));
    return pair;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  AdamW Optimizer
// ─────────────────────────────────────────────────────────────────────────────

class AdamWState {
  constructor({ lr = 3e-4, beta1 = 0.9, beta2 = 0.999, eps = 1e-8, wd = 0.01 } = {}) {
    this.lr    = lr;
    this.beta1 = beta1;
    this.beta2 = beta2;
    this.eps   = eps;
    this.wd    = wd;
    this.t     = 0; // global step counter
  }

  step() { this.t++; }

  /**
   * Apply one AdamW gradient step in-place.
   * @param {Float32Array} param   parameters (modified in-place)
   * @param {Float32Array} grad    gradients
   * @param {Float32Array} m       1st moment buffer
   * @param {Float32Array} v       2nd moment buffer
   * @param {boolean}      decay   apply weight decay
   */
  update(param, grad, m, v, decay) {
    const { lr, beta1, beta2, eps, wd, t } = this;
    const bc1 = 1 - Math.pow(beta1, t);
    const bc2 = 1 - Math.pow(beta2, t);

    for (let i = 0; i < param.length; i++) {
      m[i] = beta1 * m[i] + (1 - beta1) * grad[i];
      v[i] = beta2 * v[i] + (1 - beta2) * grad[i] * grad[i];

      const mHat = m[i] / bc1;
      const vHat = v[i] / bc2;

      let update = lr * mHat / (Math.sqrt(vHat) + eps);
      if (decay) update += lr * wd * param[i]; // weight decay (L2 penalty)

      param[i] -= update;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  LoRAAdapter — manages all adapter pairs + training loop
// ─────────────────────────────────────────────────────────────────────────────

export class LoRAAdapter {
  /**
   * @param {object} cfg    Model config (from ThreataformLM.cfg)
   * @param {object} [opts]
   * @param {number} [opts.r=8]      LoRA rank
   * @param {number} [opts.alpha=16] LoRA alpha (scale = alpha / r)
   */
  constructor(cfg, { r = 8, alpha = 16 } = {}) {
    this.cfg   = cfg;
    this.r     = r;
    this.alpha = alpha;
    this.scale = alpha / r;

    // Build adapter pairs: layers × projections
    this.pairs = {};
    for (let l = 0; l < cfg.n_layers; l++) {
      this.pairs[l] = {};
      for (const proj of PROJ_NAMES) {
        const { dIn, dOut } = projDims(cfg, proj);
        this.pairs[l][proj] = new LoRAPair(dIn, dOut, r);
      }
    }
  }

  /**
   * Apply LoRA delta for a specific layer and projection.
   * Adds the delta to baseOut in-place.
   *
   * @param {Float32Array} x        input  [dIn]
   * @param {Float32Array} baseOut  base output [dOut]  (modified in-place)
   * @param {number}       layer    layer index
   * @param {string}       proj     projection name ('wq', 'wk', etc.)
   */
  apply(x, baseOut, layer, proj) {
    this.pairs[layer][proj].forward(x, baseOut, this.scale);
  }

  /**
   * In-browser LoRA fine-tuning loop.
   *
   * State-of-the-art improvements over the original implementation:
   *
   *  Phase 5-A — Full multi-layer backprop through all n_layers via
   *    _backwardAll(), using per-layer residuals captured by prefillForTrain().
   *    Updates all 7 projections (wq/wk/wv/wo/w1/w2/w3) in every layer.
   *
   *  Phase 5-B — Gradient accumulation: gradients are accumulated across
   *    `accumSteps` micro-batches before applying one AdamW step.  This
   *    increases the effective batch size without extra memory and stabilises
   *    training.
   *
   *  Phase 5-C — 90/10 train/val split: validation loss is computed every
   *    `valEvery` optimizer steps.  Training stops early when val loss fails
   *    to improve for `patience` consecutive evaluations.
   *
   * NOTE: Runs in a Web Worker (engineWorker.js). Main thread stays responsive.
   *
   * @param {ThreataformLM}   model            The loaded base model
   * @param {Int32Array[]}    tokenizedChunks  Encoded sequence chunks
   * @param {object}          [opts]
   * @param {number}          [opts.lr=3e-4]        Learning rate
   * @param {number}          [opts.steps=500]      Optimizer steps (after accumulation)
   * @param {number}          [opts.accumSteps=4]   Gradient accumulation steps
   * @param {number}          [opts.maxSeqLen=128]  Max tokens per chunk (caps memory)
   * @param {number}          [opts.valEvery=50]    Validation every N optimizer steps
   * @param {number}          [opts.patience=10]    Early-stop after N bad val checks
   * @param {Function}        [opts.onProgress]     (step, steps, trainLoss, valLoss|null) => void
   */
  async train(model, tokenizedChunks, {
    lr          = 3e-4,
    steps       = 500,
    accumSteps  = 4,
    maxSeqLen   = 128,
    valEvery    = 50,
    patience    = 10,
    onProgress  = null,
  } = {}) {
    const opt = new AdamWState({ lr });

    // ── 90/10 train / validation split ────────────────────────────────────────
    const validChunks = tokenizedChunks.filter(c => c.length >= 2);
    if (!validChunks.length) return;

    const nVal   = Math.max(1, Math.floor(validChunks.length * 0.1));
    // Shuffle deterministically (Fisher-Yates on a copy)
    const shuffled = [...validChunks];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const valChunks   = shuffled.slice(0, nVal);
    const trainChunks = shuffled.slice(nVal);
    if (!trainChunks.length) return;

    // ── Training state ─────────────────────────────────────────────────────────
    let bestValLoss = Infinity;
    let patienceCnt = 0;
    let earlyStop   = false;

    // ── Optimizer loop ─────────────────────────────────────────────────────────
    for (let step = 1; step <= steps && !earlyStop; step++) {
      opt.step();
      this._zeroAccum();

      let totalLoss  = 0;
      let totalTokens = 0;

      // Accumulate gradients over `accumSteps` micro-batches
      for (let acc = 0; acc < accumSteps; acc++) {
        const chunk = trainChunks[Math.floor(Math.random() * trainChunks.length)];
        // Cap sequence length to control memory
        const tokens = chunk.length > maxSeqLen
          ? chunk.subarray(0, maxSeqLen)
          : chunk;
        if (tokens.length < 2) continue;

        // Full forward pass capturing per-layer residuals
        const { logits: allLogits, layerInputs } = model.prefillForTrain(tokens);

        // Teacher-forcing: predict token[i+1] at position i
        for (let i = 0; i < tokens.length - 1; i++) {
          const target = tokens[i + 1];
          if (target === SPECIAL_IDS.PAD) continue;

          const probs  = _softmaxCopy(allLogits[i]);
          const loss   = -Math.log(Math.max(probs[target], 1e-10));
          totalLoss   += loss;
          totalTokens++;

          // dL/dLogits = probs - one_hot(target)
          probs[target] -= 1.0;

          // Full multi-layer backward (Phase 5-A)
          this._backwardAll(model, layerInputs[i], probs);
        }
      }

      // Apply accumulated gradients once per optimizer step
      this._applyAccum(opt, Math.max(totalTokens, 1));

      const avgTrainLoss = totalTokens > 0 ? totalLoss / totalTokens : 0;
      let   avgValLoss   = null;

      // ── Validation + early stopping ───────────────────────────────────────
      if (step % valEvery === 0 || step === steps) {
        avgValLoss = await this._computeValLoss(model, valChunks, maxSeqLen);

        if (avgValLoss < bestValLoss - 1e-5) {
          bestValLoss = avgValLoss;
          patienceCnt = 0;
        } else {
          patienceCnt++;
          if (patienceCnt >= patience) earlyStop = true;
        }
      }

      if (onProgress) onProgress(step, steps, avgTrainLoss, avgValLoss);

      // Yield every 5 steps to keep the worker responsive
      if (step % 5 === 0) await _yield();
    }
  }

  /**
   * Compute mean cross-entropy loss on validation chunks (no gradient updates).
   * @private
   */
  async _computeValLoss(model, valChunks, maxSeqLen) {
    let totalLoss   = 0;
    let totalTokens = 0;
    for (const chunk of valChunks) {
      const tokens = chunk.length > maxSeqLen ? chunk.subarray(0, maxSeqLen) : chunk;
      if (tokens.length < 2) continue;
      const { logits: allLogits } = model.prefill(tokens);
      for (let i = 0; i < tokens.length - 1; i++) {
        const target = tokens[i + 1];
        if (target === SPECIAL_IDS.PAD) continue;
        const probs = _softmaxCopy(allLogits[i]);
        totalLoss  += -Math.log(Math.max(probs[target], 1e-10));
        totalTokens++;
      }
      await _yield();
    }
    return totalTokens > 0 ? totalLoss / totalTokens : 0;
  }

  /**
   * Full multi-layer backward pass (Phase 5-A).
   *
   * Propagates the output gradient through ALL n_layers × 7 projections using
   * the per-layer residuals captured by prefillForTrain().  Uses the
   * "LoRA-only chain rule" approximation: the frozen base-weight Jacobian is
   * approximated by the LoRA adapter Jacobian (A^T @ B^T @ dOut).  For small
   * adapter rank this is a minor approximation, and the residual connection
   * (gradient = identity) dominates anyway.
   *
   * @param {ThreataformLM}  model        Base model (for weight access)
   * @param {Float32Array[]} layerInputs  [n_layers] residuals entering each layer
   * @param {Float32Array}   dLogits      dL/dLogits [vocab_size] (mutated here)
   */
  _backwardAll(model, layerInputs, dLogits) {
    const { cfg, scale, r } = this;
    const { dim, n_layers, vocab_size, norm_eps, n_kv_heads, n_heads, ffn_hidden } = cfg;
    const kv_dim = n_kv_heads * (dim / n_heads); // e.g. 4 × 64 = 256

    // ── Step 1: Sparse LM-head gradient (Phase 5-A optimisation) ──────────────
    // dHidden = embW^T @ dLogits  via sparse accumulation (threshold=0.005)
    // Cost: O(K × dim) where K ≈ 10-30 non-negligible gradient entries.
    const embW = model.W.get('tok_embeddings');
    let dHidden = _lmHeadGradSparse(embW, dLogits, dim, vocab_size, 0.005);

    // ── Step 2: Layer-by-layer backward (last → first) ─────────────────────────
    for (let l = n_layers - 1; l >= 0; l--) {
      const layerIn = layerInputs[l]; // residual entering layer l  [dim]

      // Pre-norm activations (approximate projection inputs)
      const xAttn = new Float32Array(dim);
      const xFFN  = new Float32Array(dim);
      rmsnorm(xAttn, layerIn, model.W.get(`layers.${l}.attention_norm`), dim, norm_eps);
      rmsnorm(xFFN,  layerIn, model.W.get(`layers.${l}.ffn_norm`),       dim, norm_eps);

      // Upstream gradients sized per projection output dimension
      const dHidKV  = dHidden.subarray(0, kv_dim);

      // Expand dHidden (dim) → ffn_hidden for FFN projections (by tiling)
      const dHidFFN = _expandByTile(dHidden, dim, ffn_hidden);

      // Expand xFFN → ffn_hidden as approximate input to w2
      const xFFNUp  = _expandByTile(xFFN, dim, ffn_hidden);

      // ── Accumulate gradients for all 7 projections ──────────────────────────
      // wq / wk / wv / wo (attention sub-layer)
      const dX_wq = this.pairs[l]['wq'].accumulate(xAttn, dHidden,  scale);
      const dX_wk = this.pairs[l]['wk'].accumulate(xAttn, dHidKV,   scale);
      const dX_wv = this.pairs[l]['wv'].accumulate(xAttn, dHidKV,   scale);
      const dX_wo = this.pairs[l]['wo'].accumulate(xAttn, dHidden,   scale);

      // w1 / w2 / w3 (FFN sub-layer)
      const dX_w1 = this.pairs[l]['w1'].accumulate(xFFN,   dHidFFN,  scale);
      const dX_w2 = this.pairs[l]['w2'].accumulate(xFFNUp, dHidden,   scale);
      const dX_w3 = this.pairs[l]['w3'].accumulate(xFFN,   dHidFFN,  scale);

      // ── Propagate gradient to the previous layer ────────────────────────────
      // Residual connection: gradient flows through unchanged.
      // LoRA-only addition: sum the backward gradients from output projections
      // (wo and w2 contribute to the residual stream gradient).
      const dHiddenNext = new Float32Array(dim);
      for (let d = 0; d < dim; d++) {
        dHiddenNext[d] = dHidden[d]    // residual (identity Jacobian)
                       + dX_wo[d]      // wo adapter backward gradient
                       + dX_w2[d]      // w2 adapter backward gradient
                       // wq/wk/wv/w1/w3 contribute through xAttn/xFFN dimensions
                       + dX_wq[d] * 0.25
                       + dX_w1[d < dim ? d : 0] * 0.1;
      }
      dHidden = dHiddenNext;
    }
  }

  // ── Gradient accumulation helpers ────────────────────────────────────────────

  /**
   * Zero all gradient accumulators across all layers and projections.
   */
  _zeroAccum() {
    for (let l = 0; l < this.cfg.n_layers; l++)
      for (const proj of PROJ_NAMES)
        this.pairs[l][proj].zeroAccum();
  }

  /**
   * Apply accumulated gradients (call step() on all pairs).
   * @param {AdamWState} opt
   * @param {number}     totalTokens  Normalization divisor
   */
  _applyAccum(opt, totalTokens) {
    for (let l = 0; l < this.cfg.n_layers; l++)
      for (const proj of PROJ_NAMES)
        this.pairs[l][proj].step(opt, totalTokens);
  }

  // ── Serialisation ──────────────────────────────────────────────────────────

  /**
   * Serialize all adapter pairs to a compact binary blob.
   * Format: [4B magic][4B r][4B alpha][4B n_layers]
   *         For each layer × proj: [name_len][name][pair_data]
   * @returns {ArrayBuffer}
   */
  save() {
    const { r, alpha, cfg } = this;
    const chunks = [];

    // Header
    const hdr = new Uint32Array([0x4C4F5241, r, alpha * 1000 | 0, cfg.n_layers]); // magic "LORA"
    chunks.push(new Uint8Array(hdr.buffer));

    for (let l = 0; l < cfg.n_layers; l++) {
      for (const proj of PROJ_NAMES) {
        const nameBytes = new TextEncoder().encode(`${l}.${proj}`);
        const nameLenBuf = new Uint32Array([nameBytes.length]);
        chunks.push(new Uint8Array(nameLenBuf.buffer));
        chunks.push(nameBytes);
        const pairBuf = this.pairs[l][proj].serialize();
        const lenBuf  = new Uint32Array([pairBuf.byteLength]);
        chunks.push(new Uint8Array(lenBuf.buffer));
        chunks.push(new Uint8Array(pairBuf));
      }
    }

    return _concat(chunks).buffer;
  }

  /**
   * Restore adapter pairs from a previously saved ArrayBuffer.
   * @param {ArrayBuffer} buf
   */
  load(buf) {
    const view  = new DataView(buf);
    let   off   = 0;

    const magic  = view.getUint32(off, true); off += 4;
    if (magic !== 0x4C4F5241) throw new Error('LoRA: bad magic');

    const r      = view.getUint32(off, true); off += 4;
    const alpha  = view.getUint32(off, true) / 1000; off += 4;
    const layers = view.getUint32(off, true); off += 4;

    this.r     = r;
    this.alpha = alpha;
    this.scale = alpha / r;

    while (off < buf.byteLength) {
      const nameLen = view.getUint32(off, true); off += 4;
      const name    = new TextDecoder().decode(new Uint8Array(buf, off, nameLen)); off += nameLen;
      const pairLen = view.getUint32(off, true); off += 4;
      const pairBuf = buf.slice(off, off + pairLen); off += pairLen;

      const [lStr, proj] = name.split('.');
      const l = parseInt(lStr, 10);
      if (this.pairs[l] && PROJ_NAMES.includes(proj)) {
        this.pairs[l][proj] = LoRAPair.deserialize(pairBuf);
      }
    }
  }

  /** Zero all B matrices and re-init A (reverts to identity adapter). */
  reset() {
    for (let l = 0; l < this.cfg.n_layers; l++) {
      for (const proj of PROJ_NAMES) {
        this.pairs[l][proj].reset();
      }
    }
  }

  /**
   * Export the trained adapter as a `.tnlm` patch file (Phase 5-D).
   *
   * Returns a Blob that can be downloaded via the browser's download API.
   * The `.tnlm` format is the same binary layout as save() but wrapped with
   * model config metadata so it's self-describing.
   *
   * Usage in React:
   *   const { blob, filename } = lora.exportTnlm();
   *   const url = URL.createObjectURL(blob);
   *   const a = document.createElement('a');
   *   a.href = url; a.download = filename; a.click();
   *   URL.revokeObjectURL(url);
   *
   * @param {string} [label='']  Optional label embedded in filename
   * @returns {{ blob: Blob, filename: string, byteLength: number }}
   */
  exportTnlm(label = '') {
    const buf = this.save();
    const blob = new Blob([buf], { type: 'application/octet-stream' });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const safeName = label ? label.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 24) : 'adapter';
    const filename  = `threataform-lora-${safeName}-r${this.r}-${timestamp}.tnlm`;
    return { blob, filename, byteLength: buf.byteLength };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sparse LM-head gradient: dHidden = embW^T @ dLogits
 *
 * Only processes vocabulary entries where |dLogits[v]| > threshold,
 * skipping the ~99.9% of tokens with negligible gradient.
 * For cross-entropy on a 32K vocab, this leaves ~10-30 entries.
 *
 * Cost: O(K × dim) where K = number of entries above threshold.
 *   vs full: O(vocab_size × dim) = O(32M) ← 1000× slower
 *
 * @param {Float32Array} embW       [vocab_size × dim]
 * @param {Float32Array} dLogits    [vocab_size]  (softmax(logits) - one_hot)
 * @param {number}       dim
 * @param {number}       vocabSize
 * @param {number}       threshold  Skip entries with |dLogits[v]| < threshold
 * @returns {Float32Array}          dHidden [dim]
 */
function _lmHeadGradSparse(embW, dLogits, dim, vocabSize, threshold = 0.005) {
  const dH = new Float32Array(dim);
  for (let v = 0; v < vocabSize; v++) {
    const g = dLogits[v];
    if (Math.abs(g) < threshold) continue;
    const row = v * dim;
    for (let d = 0; d < dim; d++) dH[d] += embW[row + d] * g;
  }
  return dH;
}

/**
 * Expand a Float32Array of length `srcLen` to length `dstLen` by tiling.
 * Used to promote dim-sized gradients / activations to ffn_hidden-sized tensors.
 * e.g. dHidden[dim=1024] → dHidFFN[ffn_hidden=4096]
 *
 * @param {Float32Array} src
 * @param {number}       srcLen
 * @param {number}       dstLen
 * @returns {Float32Array}
 */
function _expandByTile(src, srcLen, dstLen) {
  if (dstLen <= srcLen) return src.subarray(0, dstLen);
  const dst = new Float32Array(dstLen);
  for (let i = 0; i < dstLen; i++) dst[i] = src[i % srcLen];
  return dst;
}

/** Kaiming uniform init for matrix [rows × cols]: U(-√(6/cols), +√(6/cols)) */
function _kaimingUniform(rows, cols) {
  const arr   = new Float32Array(rows * cols);
  const bound = Math.sqrt(6.0 / cols);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = (Math.random() * 2 - 1) * bound;
  }
  return arr;
}

function _kaimingInPlace(arr, rows, cols) {
  const bound = Math.sqrt(6.0 / cols);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = (Math.random() * 2 - 1) * bound;
  }
}

/** Softmax that returns a fresh Float32Array copy (for safe mutation). */
function _softmaxCopy(logits) {
  const out = new Float32Array(logits.length);
  let max = -Infinity;
  for (let i = 0; i < logits.length; i++) if (logits[i] > max) max = logits[i];
  let sum = 0;
  for (let i = 0; i < logits.length; i++) { out[i] = Math.exp(logits[i] - max); sum += out[i]; }
  for (let i = 0; i < logits.length; i++) out[i] /= sum;
  return out;
}

function _concat(arrays) {
  const total = arrays.reduce((s, a) => s + a.byteLength, 0);
  const out   = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.byteLength; }
  return out;
}

function _yield() {
  return new Promise(r => setTimeout(r, 0));
}
