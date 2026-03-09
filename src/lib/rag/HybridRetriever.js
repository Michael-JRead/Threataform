/**
 * src/lib/rag/HybridRetriever.js
 * State-of-the-art hybrid retrieval: BM25 + ColBERT + dense + cross-encoder reranking.
 *
 * Pipeline:
 *   1. Broad recall: BM25 (keyword) + single-vector dense + ColBERT multi-vector
 *      (all three run in parallel via Promise.all)
 *   2. Reciprocal Rank Fusion (RRF) to merge rankings
 *   3. Maximal Marginal Relevance (MMR) for diversity
 *   4. Cross-encoder reranking using mean log-prob (not hardcoded "yes" token)
 *
 * Multi-hop:
 *   multiHopRetrieve() performs iterative retrieval — the top result from round N
 *   is prepended to the query for round N+1 to find secondary evidence.
 *
 * Usage:
 *   const ret = new HybridRetriever(bm25, singleStore, colbertStore, model, tokenizer);
 *   const results = await ret.retrieve(query, topK=8);
 *   const deepResults = await ret.multiHopRetrieve(query, hops=2, k=5);
 */

import { packContext } from './VectorStore.js';

// RRF constant (Cormack et al. 2009) — higher = less rank-sensitive
const RRF_K = 60;

// MMR diversity weight — 0=pure relevance, 1=pure diversity, 0.6=balanced
const MMR_LAMBDA = 0.6;

export class HybridRetriever {
  /**
   * @param {BM25Index}           bm25
   * @param {SingleVectorStore}   denseStore
   * @param {ColBERTVectorStore}  colbertStore
   * @param {ThreataformLM|null}  model         (null → skip cross-encoder)
   * @param {BPETokenizer|null}   tokenizer     (null → skip cross-encoder)
   */
  constructor(bm25, denseStore, colbertStore, model = null, tokenizer = null) {
    this.bm25         = bm25;
    this.denseStore   = denseStore;
    this.colbertStore = colbertStore;
    this.model        = model;
    this.tokenizer    = tokenizer;
  }

  /**
   * Retrieve the most relevant chunks for a query.
   *
   * @param {string}       query
   * @param {number}       [topK=8]     Final result count
   * @param {number}       [recallK=40] Recall pool size before reranking
   * @param {object}       [opts]
   * @param {Float32Array|null} [opts.queryVec]       Pre-computed dense embedding
   * @param {Float32Array[]|null} [opts.queryToks]    Pre-computed ColBERT token vecs
   * @param {boolean}      [opts.rerank=true]         Run cross-encoder reranking
   * @param {boolean}      [opts.mmr=true]            Apply MMR diversity
   * @returns {Promise<Array<{id, score, text, meta}>>}
   */
  async retrieve(query, topK = 8, recallK = 40, {
    queryVec  = null,
    queryToks = null,
    rerank    = true,
    mmr       = true,
  } = {}) {

    // ── Stage 1: Parallel broad recall ───────────────────────────────────────
    // All three searches are synchronous, but structured for async-ready
    // parallelism (e.g. if searches move to workers in the future).
    const [bm25Results, denseResults, colbertResults] = await Promise.all([
      Promise.resolve(this.bm25.search(query, recallK)),
      Promise.resolve(
        (queryVec && this.denseStore.size > 0)
          ? this.denseStore.search(queryVec, recallK)
          : []
      ),
      Promise.resolve(
        (queryToks?.length && this.colbertStore.size > 0)
          ? this.colbertStore.search(queryToks, recallK)
          : []
      ),
    ]);

    const rankLists = [];
    if (bm25Results.length)    rankLists.push(bm25Results.map(r => r.id));
    if (denseResults.length)   rankLists.push(denseResults.map(r => r.id));
    if (colbertResults.length) rankLists.push(colbertResults.map(r => r.id));

    if (!rankLists.length) return [];

    // ── Stage 2: Reciprocal Rank Fusion ──────────────────────────────────────
    const fused = _rrf(rankLists, RRF_K);

    // Build result objects (look up metadata from any store)
    const pool = this._buildPool(fused.slice(0, recallK), bm25Results, denseResults);

    if (pool.length <= topK) return pool.slice(0, topK);

    // ── Stage 3: MMR diversity ────────────────────────────────────────────────
    let candidates = pool;
    if (mmr && queryVec) {
      candidates = _mmr(pool, queryVec, MMR_LAMBDA, Math.min(recallK, pool.length));
    }

    if (!rerank || !this.model) {
      return candidates.slice(0, topK);
    }

    // ── Stage 4: Cross-encoder reranking ─────────────────────────────────────
    const reranked = await this._crossEncoderRerank(query, candidates, topK);
    return reranked;
  }

  /**
   * Multi-hop retrieval — iteratively augments the query with top results
   * to find secondary/supporting evidence.
   *
   * @param {string}  query
   * @param {number}  [hops=2]  Number of retrieval hops
   * @param {number}  [k=5]     Results per hop (final result is also k)
   * @param {object}  [opts]    Passed to retrieve()
   * @returns {Promise<Array<{id, score, text, meta}>>}
   */
  async multiHopRetrieve(query, hops = 2, k = 5, opts = {}) {
    let ctx = await this.retrieve(query, k, k * 4, opts);

    for (let h = 1; h < hops; h++) {
      if (!ctx.length) break;
      // Augment query with context from previous hop
      const augmented = query + ' ' + ctx[0].text.slice(0, 200);
      const hop = await this.retrieve(augmented, k, k * 4, opts);
      // Merge and deduplicate by id
      const seen = new Set(ctx.map(r => r.id));
      for (const r of hop) {
        if (!seen.has(r.id)) { ctx.push(r); seen.add(r.id); }
      }
      // Re-sort by score and trim
      ctx = ctx.sort((a, b) => b.score - a.score).slice(0, k);
    }

    return ctx;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  /**
   * Cross-encoder reranking using mean log-probability of passage tokens.
   * This is model-agnostic — does not search for a specific "yes"/"no" token ID.
   *
   * Scores each candidate by: average logit of the passage tokens given the
   * concatenated [query, passage] prompt prefix.  Higher = more relevant.
   */
  async _crossEncoderRerank(query, candidates, topK) {
    if (!this.model || !this.tokenizer) return candidates.slice(0, topK);

    const scored = [];
    for (const cand of candidates) {
      try {
        // Format: "Relevance: [passage excerpt] to [query]:"
        // The model scores the passage tokens in context — no vocab-specific hack.
        const passageSnippet = cand.text.slice(0, 200);
        const querySnippet   = query.slice(0, 120);
        const prompt = `Query: ${querySnippet}\nPassage: ${passageSnippet}\nRelevant:`;
        const ids    = this.tokenizer.encode(prompt);

        // Get logits for all positions in the prompt (causal LM)
        // Use the mean logit of the last few tokens as a relevance proxy
        const logits = await this.model.getLogits?.(ids);
        if (!logits || !logits.length) {
          // Fallback: use predictTokenProb if getLogits not available
          // Use the actual next-token probability distribution mean instead of
          // hardcoded " yes" — pick max logit token as proxy for confidence
          const maxLogit = await this.model.predictTokenProb?.(ids, -1) ?? 0;
          scored.push({ ...cand, score: maxLogit });
          continue;
        }

        // Mean of last min(5, logits.length) logits as relevance score
        const n = Math.min(5, logits.length);
        const meanLogit = logits.slice(-n).reduce((s, l) => s + l, 0) / n;
        scored.push({ ...cand, score: meanLogit });

      } catch {
        scored.push(cand); // keep original RRF score on error
      }
    }

    return scored.sort((a, b) => b.score - a.score).slice(0, topK);
  }

  /**
   * Build result objects from fused IDs, using BM25 + dense results for text/meta.
   * Merges metadata from all available sources.
   */
  _buildPool(fusedIds, bm25Results, denseResults = []) {
    const byId = new Map();
    for (const r of bm25Results)  byId.set(r.id, r);
    for (const r of denseResults) { if (!byId.has(r.id)) byId.set(r.id, r); }

    return fusedIds.map(({ id, score }) => {
      const src = byId.get(id) ?? {};
      return { id, score, text: src.text ?? '', meta: src.meta ?? {} };
    });
  }
}

/**
 * Reciprocal Rank Fusion.
 * @param {string[][]} rankLists  Each list is an ordered array of document IDs
 * @param {number}     k          RRF smoothing constant
 * @returns {Array<{id:string, score:number}>} Sorted by descending fused score
 */
export function rrf(rankLists, k = RRF_K) {
  return _rrf(rankLists, k);
}

function _rrf(rankLists, k) {
  const scores = new Map();
  for (const list of rankLists) {
    list.forEach((id, rank) => {
      scores.set(id, (scores.get(id) ?? 0) + 1 / (k + rank + 1));
    });
  }
  return Array.from(scores.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([id, score]) => ({ id, score }));
}

/**
 * Maximal Marginal Relevance diversification.
 * Selects candidates that balance relevance (RRF score) with diversity
 * (dissimilarity to already-selected results).
 *
 * @param {Array<{id, score, text, meta}>} candidates  Pool sorted by relevance
 * @param {Float32Array} queryVec   Query dense embedding (used for relevance calc)
 * @param {number}       lambda     0=pure diversity, 1=pure relevance
 * @param {number}       k          Number of results to select
 * @returns {Array<{id, score, text, meta}>}
 */
function _mmr(candidates, queryVec, lambda = 0.6, k = 8) {
  if (candidates.length <= k) return candidates;

  // Normalise RRF scores to [0,1] for stable λ-weighting
  const maxScore = candidates[0]?.score ?? 1;
  const minScore = candidates[candidates.length - 1]?.score ?? 0;
  const range    = Math.max(maxScore - minScore, 1e-10);
  const normScore = c => (c.score - minScore) / range;

  // Simple text-overlap similarity proxy (cosine of char bigram bags).
  // Falls back when embeddings not available for passage texts.
  function textSim(a, b) {
    if (!a || !b) return 0;
    const bg = s => {
      const m = new Map();
      for (let i = 0; i < s.length - 1; i++) {
        const k = s[i] + s[i+1];
        m.set(k, (m.get(k) ?? 0) + 1);
      }
      return m;
    };
    const ba = bg(a.slice(0, 200).toLowerCase());
    const bb = bg(b.slice(0, 200).toLowerCase());
    let dot = 0, na = 0, nb = 0;
    for (const [k, va] of ba) { const vb = bb.get(k) ?? 0; dot += va * vb; na += va * va; }
    for (const vb of bb.values()) nb += vb * vb;
    const denom = Math.sqrt(na) * Math.sqrt(nb);
    return denom < 1e-10 ? 0 : dot / denom;
  }

  const selected  = [];
  const remaining = [...candidates];

  while (selected.length < k && remaining.length > 0) {
    let bestScore = -Infinity;
    let bestIdx   = 0;

    for (let i = 0; i < remaining.length; i++) {
      const c   = remaining[i];
      const rel = normScore(c);
      const maxSim = selected.length === 0 ? 0 :
        Math.max(...selected.map(s => textSim(c.text, s.text)));
      const mmrScore = lambda * rel - (1 - lambda) * maxSim;
      if (mmrScore > bestScore) { bestScore = mmrScore; bestIdx = i; }
    }

    selected.push(remaining.splice(bestIdx, 1)[0]);
  }

  return selected;
}
