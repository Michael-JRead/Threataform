/**
 * src/lib/llm/Model.js
 * ThreataformLM — Causal Transformer Forward Pass (pure JavaScript)
 *
 * Architecture (ThreataformLM-200M defaults):
 *   vocab_size  = 32 000
 *   context_len = 4 096   (extended to ~32K via YaRN RoPE)
 *   dim         = 1 024
 *   n_layers    = 24
 *   n_heads     = 16       (each head_dim = 64)
 *   n_kv_heads  = 4        (GQA: 4 Q heads share 1 KV head)
 *   ffn_hidden  = 4 096    (SwiGLU: 3 weight matrices)
 *   norm        = RMSNorm  (eps = 1e-5)
 *   pos_enc     = RoPE with YaRN context extension
 *   init        = muP (Maximal Update Parametrization)
 *
 * Weights are loaded from a .tnlm file via WeightsLoader.js and passed in as
 * a Map<name, Float32Array|Uint8Array>.
 *
 * Usage:
 *   import { ThreataformLM } from './Model.js';
 *   const model = new ThreataformLM(config, weights);
 *   for await (const tok of model.generate(promptIds)) {
 *     console.log(tokenizer.decode([tok]));
 *   }
 */

import {
  matmul, matmulAccum, matmulQ4, matmulQ8,
  rmsnorm, softmax, silu, vecAdd, fcopy,
  cosineSim, l2Normalize, dotProduct,
  buildRoPETable, applyRoPE,
  greedySample, sampleTopP, sampleTopK,
} from './Ops.js';

import { SPECIAL_IDS } from './Tokenizer.js';

// ─────────────────────────────────────────────────────────────────────────────
//  Default model configuration (ThreataformLM-200M)
// ─────────────────────────────────────────────────────────────────────────────

export const DEFAULT_CONFIG = Object.freeze({
  vocab_size:   32000,
  context_len:  4096,
  dim:          1024,
  n_layers:     24,
  n_heads:      16,
  n_kv_heads:   4,    // GQA: each KV head serves (n_heads / n_kv_heads) = 4 Q-heads
  ffn_hidden:   4096,
  norm_eps:     1e-5,
  rope_theta:   10000,
  yarn_scale:   1.0,  // >1 extends context via YaRN; set by WeightsLoader from config
  tie_embeddings: true, // output projection reuses embedding weights (saves ~128MB F32)
});

// ─────────────────────────────────────────────────────────────────────────────
//  KV Cache
// ─────────────────────────────────────────────────────────────────────────────

class KVCache {
  /**
   * @param {number} n_layers
   * @param {number} n_kv_heads
   * @param {number} head_dim
   * @param {number} max_seq
   */
  constructor(n_layers, n_kv_heads, head_dim, max_seq) {
    this.n_layers   = n_layers;
    this.n_kv_heads = n_kv_heads;
    this.head_dim   = head_dim;
    this.max_seq    = max_seq;
    // k[layer][head][pos * head_dim … (pos+1)*head_dim]
    const sz = n_kv_heads * max_seq * head_dim;
    this.k = Array.from({ length: n_layers }, () => new Float32Array(sz));
    this.v = Array.from({ length: n_layers }, () => new Float32Array(sz));
  }

  clear() {
    for (let l = 0; l < this.n_layers; l++) {
      this.k[l].fill(0);
      this.v[l].fill(0);
    }
  }

  /** Write one K or V vector for layer l, kv_head h, position pos. */
  writeK(l, h, pos, vec, vecOff) {
    const dst = (h * this.max_seq + pos) * this.head_dim;
    fcopy(this.k[l], dst, vec, vecOff, this.head_dim);
  }

  writeV(l, h, pos, vec, vecOff) {
    const dst = (h * this.max_seq + pos) * this.head_dim;
    fcopy(this.v[l], dst, vec, vecOff, this.head_dim);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ThreataformLM
// ─────────────────────────────────────────────────────────────────────────────

export class ThreataformLM {
  /**
   * @param {object}                  config   Model configuration (see DEFAULT_CONFIG)
   * @param {Map<string, TypedArray>} weights  Weight tensors keyed by name
   */
  constructor(config = {}, weights = new Map()) {
    this.cfg = { ...DEFAULT_CONFIG, ...config };
    this.W   = weights; // Map<string, Float32Array|Uint8Array>

    const { dim, n_heads, n_kv_heads, context_len, rope_theta, yarn_scale } = this.cfg;
    this.head_dim    = dim / n_heads;            // 64
    this.kv_dim      = n_kv_heads * this.head_dim;
    this.q_per_kv    = n_heads / n_kv_heads;     // GQA ratio: 4
    this.scale       = 1.0 / Math.sqrt(this.head_dim);

    // Pre-compute RoPE tables
    const { ropeReal, ropeImag } = buildRoPETable(
      this.head_dim, context_len, rope_theta, yarn_scale
    );
    this.ropeReal = ropeReal;
    this.ropeImag = ropeImag;

    // Scratch buffers (reused each forward pass to avoid GC pressure)
    this._alloc();
  }

  _alloc() {
    const { dim, n_heads, n_kv_heads, ffn_hidden, vocab_size } = this.cfg;
    const hd = this.head_dim;

    this._x    = new Float32Array(dim);      // current residual
    this._xb   = new Float32Array(dim);      // norm output / attention output
    this._xb2  = new Float32Array(dim);      // second scratch
    this._hb   = new Float32Array(ffn_hidden); // FFN hidden (gate branch)
    this._hb2  = new Float32Array(ffn_hidden); // FFN hidden (up branch)
    this._q    = new Float32Array(n_heads  * hd); // query buffer
    this._k    = new Float32Array(n_kv_heads * hd); // key buffer
    this._v    = new Float32Array(n_kv_heads * hd); // value buffer
    this._att  = new Float32Array(n_heads * this.cfg.context_len); // attention scores
    this._logits = new Float32Array(vocab_size);
  }

  /**
   * Allocate a fresh KV cache (call once before generation; reuse across tokens).
   * @param {number} [maxSeq]  defaults to context_len
   * @returns {KVCache}
   */
  allocateKVCache(maxSeq) {
    const { n_layers, n_kv_heads, context_len } = this.cfg;
    return new KVCache(n_layers, n_kv_heads, this.head_dim, maxSeq ?? context_len);
  }

  // ── Weight accessors ───────────────────────────────────────────────────────

  /** Get a weight tensor, checking dtype suffix for Q4/Q8. */
  _w(name) {
    const w = this.W.get(name);
    if (!w) throw new Error(`Weight not found: ${name}`);
    return w;
  }

  /** Detect quantisation from weight tensor type and size. */
  _dtype(name) {
    const tag = this.W.get(name + '__dtype');
    if (tag) return tag;
    return 'f32'; // default: Float32Array
  }

  /**
   * Matrix-vector multiply dispatching on weight dtype.
   * @param {Float32Array} out    output buffer
   * @param {string}       name   weight name
   * @param {Float32Array} x      input vector
   * @param {number}       rows   output dimension
   * @param {number}       cols   input dimension
   */
  _mv(out, name, x, rows, cols) {
    const W = this._w(name);
    const dt = this._dtype(name);
    if (dt === 'q4') return matmulQ4(out, W, x, rows, cols);
    if (dt === 'q8') return matmulQ8(out, W, x, rows, cols);
    return matmul(out, W, x, rows, cols);
  }

  // ── Forward pass ──────────────────────────────────────────────────────────

  /**
   * Single-token forward pass with KV cache.
   *
   * @param {number}  tokenId  Input token ID
   * @param {number}  pos      Position in sequence (0-based)
   * @param {KVCache} kvc      KV cache (updated in place)
   * @returns {Float32Array}   Logits (vocab_size)
   */
  forward(tokenId, pos, kvc) {
    const { dim, n_layers, n_heads, n_kv_heads, ffn_hidden, vocab_size, norm_eps } = this.cfg;
    const hd = this.head_dim;

    // 1. Token embedding
    const embW = this._w('tok_embeddings');
    fcopy(this._x, 0, embW, tokenId * dim, dim);

    // 2. Transformer layers
    for (let l = 0; l < n_layers; l++) {
      this._layer(l, pos, kvc);
    }

    // 3. Final RMSNorm
    rmsnorm(this._xb, this._x, this._w('norm'), dim, norm_eps);

    // 4. Language model head  (tied embeddings: reuse tok_embeddings as output proj)
    const outW = this.cfg.tie_embeddings ? this._w('tok_embeddings') : this._w('output');
    matmul(this._logits, outW, this._xb, vocab_size, dim);

    return this._logits;
  }

  /** Process one transformer layer at position `pos`. */
  _layer(l, pos, kvc) {
    const { dim, n_heads, n_kv_heads, ffn_hidden, norm_eps } = this.cfg;
    const hd = this.head_dim;

    // ── Attention pre-norm ────────────────────────────────────────────────────
    rmsnorm(this._xb, this._x, this._w(`layers.${l}.attention_norm`), dim, norm_eps);

    // ── QKV projections ───────────────────────────────────────────────────────
    this._mv(this._q,            `layers.${l}.attention.wq`, this._xb, n_heads    * hd, dim);
    this._mv(this._k,            `layers.${l}.attention.wk`, this._xb, n_kv_heads * hd, dim);
    this._mv(this._v,            `layers.${l}.attention.wv`, this._xb, n_kv_heads * hd, dim);

    // ── Apply RoPE to Q and K ─────────────────────────────────────────────────
    for (let h = 0; h < n_heads; h++) {
      applyRoPE(this._q, h * hd, hd, pos, this.ropeReal, this.ropeImag);
    }
    for (let h = 0; h < n_kv_heads; h++) {
      applyRoPE(this._k, h * hd, hd, pos, this.ropeReal, this.ropeImag);
    }

    // ── Write K/V into cache ──────────────────────────────────────────────────
    for (let h = 0; h < n_kv_heads; h++) {
      kvc.writeK(l, h, pos, this._k, h * hd);
      kvc.writeV(l, h, pos, this._v, h * hd);
    }

    // ── Grouped Query Attention ───────────────────────────────────────────────
    this._gqa(l, pos, kvc, n_heads, n_kv_heads, hd, dim);

    // ── Attention output projection + residual ────────────────────────────────
    this._mv(this._xb2, `layers.${l}.attention.wo`, this._xb, dim, dim);
    vecAdd(this._x, this._xb2, dim);

    // ── FFN pre-norm ──────────────────────────────────────────────────────────
    rmsnorm(this._xb, this._x, this._w(`layers.${l}.ffn_norm`), dim, norm_eps);

    // ── SwiGLU FFN: out = W_down( silu(W_gate @ x) ⊙ (W_up @ x) ) ──────────
    this._mv(this._hb,  `layers.${l}.feed_forward.w1`, this._xb, ffn_hidden, dim); // gate
    this._mv(this._hb2, `layers.${l}.feed_forward.w3`, this._xb, ffn_hidden, dim); // up
    for (let i = 0; i < ffn_hidden; i++) {
      this._hb[i] = silu(this._hb[i]) * this._hb2[i];
    }
    this._mv(this._xb2, `layers.${l}.feed_forward.w2`, this._hb, dim, ffn_hidden); // down

    // FFN residual
    vecAdd(this._x, this._xb2, dim);
  }

  /** Grouped Query Attention forward — writes output into this._xb. */
  _gqa(l, pos, kvc, nH, nKV, hd, dim) {
    const scale   = this.scale;
    const seqLen  = pos + 1;
    const qPerKV  = this.q_per_kv;

    // Process each query head
    for (let qh = 0; qh < nH; qh++) {
      const kh    = Math.floor(qh / qPerKV); // which KV head to use
      const qOff  = qh * hd;
      const attOff = qh * this.cfg.context_len;

      // Compute attention scores: att[t] = Q·K_t * scale
      for (let t = 0; t <= pos; t++) {
        const kOff = (kh * kvc.max_seq + t) * hd;
        this._att[attOff + t] = dotProduct(this._q, qOff, kvc.k[l], kOff, hd) * scale;
      }

      // Causal softmax over positions 0..pos
      softmax(this._att, attOff, seqLen);

      // Weighted sum of values
      const outOff = qh * hd;
      this._xb.fill(0, outOff, outOff + hd);
      for (let t = 0; t <= pos; t++) {
        const vOff = (kh * kvc.max_seq + t) * hd;
        const a    = this._att[attOff + t];
        for (let i = 0; i < hd; i++) {
          this._xb[outOff + i] += a * kvc.v[l][vOff + i];
        }
      }
    }
  }

  // ── Embedding (for RAG) ──────────────────────────────────────────────────

  /**
   * Embed a token sequence to a single sentence vector.
   * Returns the mean-pooled hidden state of the last transformer layer,
   * before the LM head.  Suitable for dense retrieval.
   *
   * @param {Int32Array|number[]} tokenIds
   * @returns {Float32Array}  shape [dim], L2-normalised
   */
  embed(tokenIds) {
    const { dim } = this.cfg;
    const kvc     = this.allocateKVCache(tokenIds.length + 1);
    const acc     = new Float32Array(dim);

    for (let i = 0; i < tokenIds.length; i++) {
      this.forward(tokenIds[i], i, kvc);
      for (let d = 0; d < dim; d++) acc[d] += this._x[d];
    }
    for (let d = 0; d < dim; d++) acc[d] /= tokenIds.length;
    l2Normalize(acc, dim);
    return acc;
  }

  /**
   * Multi-vector embed (ColBERT style): one L2-normalised vector per token.
   * Used for late-interaction retrieval (MaxSim scoring).
   *
   * @param {Int32Array|number[]} tokenIds
   * @returns {Float32Array[]}  array of [dim] vectors
   */
  embedMulti(tokenIds) {
    const { dim } = this.cfg;
    const kvc     = this.allocateKVCache(tokenIds.length + 1);
    const vecs    = [];

    for (let i = 0; i < tokenIds.length; i++) {
      this.forward(tokenIds[i], i, kvc);
      const v = this._x.slice(); // copy current hidden state
      l2Normalize(v, dim);
      vecs.push(v);
    }
    return vecs;
  }

  /**
   * Predict a single next token (no sampling — returns logits).
   * Useful for SELF-RAG relevance/support scoring.
   *
   * @param {Int32Array|number[]} tokenIds  prompt tokens
   * @returns {Float32Array}               logits [vocab_size]
   */
  predictLogits(tokenIds) {
    const kvc = this.allocateKVCache(tokenIds.length + 1);
    let logits;
    for (let i = 0; i < tokenIds.length; i++) {
      logits = this.forward(tokenIds[i], i, kvc);
    }
    return logits; // Float32Array view (reused buffer — copy if needed)
  }

  /**
   * Binary classification: returns probability that targetTokenId is the next token.
   * Used for SELF-RAG IsRel / IsSup / IsUse scoring.
   *
   * @param {Int32Array|number[]} tokenIds
   * @param {number}              targetTokenId
   * @returns {number}  probability in [0, 1]
   */
  predictTokenProb(tokenIds, targetTokenId) {
    const logits = this.predictLogits(tokenIds).slice(); // copy to avoid mutation
    softmax(logits, 0, logits.length);
    return logits[targetTokenId];
  }

  // ── Autoregressive generation ────────────────────────────────────────────

  /**
   * Autoregressive text generation with streaming.
   *
   * @param {Int32Array|number[]} promptIds   Encoded prompt
   * @param {object}              [opts]
   * @param {number}   [opts.maxNew=512]      Max new tokens to generate
   * @param {number}   [opts.temp=0.7]        Sampling temperature (0 = greedy)
   * @param {number}   [opts.topP=0.9]        Nucleus sampling p
   * @param {number}   [opts.topK=0]          Top-K sampling (0 = disabled)
   * @param {number[]} [opts.stopIds]         Additional stop token IDs
   * @param {Function} [opts.onToken]         Called with each new token ID
   * @yields {number}  Generated token IDs (not including prompt)
   */
  async *generate(promptIds, {
    maxNew   = 512,
    temp     = 0.7,
    topP     = 0.9,
    topK     = 0,
    stopIds  = [],
    onToken  = null,
  } = {}) {
    const { context_len } = this.cfg;
    const kvc   = this.allocateKVCache(context_len);
    const stops = new Set([SPECIAL_IDS.EOS, SPECIAL_IDS.EOT, ...stopIds]);

    let pos = 0;

    // Prefill: feed all prompt tokens
    for (let i = 0; i < promptIds.length; i++) {
      this.forward(promptIds[i], pos++, kvc);
      // Yield control to the event loop every 16 tokens to avoid blocking
      if (i % 16 === 15) await _yield();
    }

    // Generate
    let prevId = promptIds[promptIds.length - 1];
    for (let step = 0; step < maxNew; step++) {
      if (pos >= context_len) break;

      const logits = this.forward(prevId, pos++, kvc);

      // Sample next token
      let nextId;
      if (temp <= 0 || temp < 1e-6) {
        nextId = greedySample(logits);
      } else if (topK > 0) {
        nextId = sampleTopK(logits, temp, topK);
      } else {
        nextId = sampleTopP(logits, temp, topP);
      }

      if (stops.has(nextId)) break;

      if (onToken) onToken(nextId);
      yield nextId;
      prevId = nextId;

      await _yield(); // yield control every token for streaming responsiveness
    }

    kvc.clear();
  }

  /**
   * Synchronous batch prefill (no token generation).
   * Used by LoRA training to get hidden states / logits for a full sequence.
   *
   * @param {Int32Array|number[]} tokenIds
   * @returns {{ logits: Float32Array[], hiddens: Float32Array[] }}
   *   Per-position logits and last-layer hidden states.
   */
  prefill(tokenIds) {
    const kvc     = this.allocateKVCache(tokenIds.length + 1);
    const logits  = [];
    const hiddens = [];

    for (let i = 0; i < tokenIds.length; i++) {
      const l = this.forward(tokenIds[i], i, kvc);
      logits.push(l.slice());
      hiddens.push(this._x.slice());
    }

    kvc.clear();
    return { logits, hiddens };
  }

  /**
   * Batch prefill with per-layer activation capture for LoRA backward pass.
   *
   * Captures `layerInputs[pos][l]` = the residual stream at the INPUT of layer l
   * at token position pos (i.e. before the attention pre-norm of layer l).
   * This is the activation needed to compute LoRA adapter gradients correctly.
   *
   * Memory: tokenIds.length × n_layers × dim × 4 bytes
   *   e.g. 128 tokens × 24 layers × 1024 dim = 12 MB — safe for browsers.
   *
   * @param {Int32Array|number[]} tokenIds
   * @returns {{
   *   logits:      Float32Array[],   logits[pos]         = output logits
   *   hiddens:     Float32Array[],   hiddens[pos]        = final hidden state
   *   layerInputs: Float32Array[][], layerInputs[pos][l] = residual entering layer l
   * }}
   */
  prefillForTrain(tokenIds) {
    const kvc = this.allocateKVCache(tokenIds.length + 1);
    const { dim, n_layers, vocab_size, norm_eps } = this.cfg;
    const outW = this.cfg.tie_embeddings ? this._w('tok_embeddings') : this._w('output');
    const embW = this._w('tok_embeddings');

    const logits      = [];
    const hiddens     = [];
    // Allocate activation buffers up front (avoids per-position GC churn)
    const layerInputs = Array.from({ length: tokenIds.length }, () =>
      Array.from({ length: n_layers }, () => new Float32Array(dim)),
    );

    for (let i = 0; i < tokenIds.length; i++) {
      // 1. Token embedding
      fcopy(this._x, 0, embW, tokenIds[i] * dim, dim);

      // 2. Run each layer, capturing the residual BEFORE each layer's norm
      for (let l = 0; l < n_layers; l++) {
        layerInputs[i][l].set(this._x); // snapshot residual entering layer l
        this._layer(l, i, kvc);
      }

      // 3. Final RMSNorm + LM head
      rmsnorm(this._xb, this._x, this._w('norm'), dim, norm_eps);
      matmul(this._logits, outW, this._xb, vocab_size, dim);

      logits.push(this._logits.slice());
      hiddens.push(this._x.slice());
    }

    kvc.clear();
    return { logits, hiddens, layerInputs };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Yield control to the browser event loop (keeps UI responsive). */
function _yield() {
  return new Promise(r => setTimeout(r, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Model factory (used by ThreataformEngine.js)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a ThreataformLM instance from a config object and weight map.
 * @param {object}                  config
 * @param {Map<string, TypedArray>} weights
 * @returns {ThreataformLM}
 */
export function createModel(config, weights) {
  return new ThreataformLM(config, weights);
}
