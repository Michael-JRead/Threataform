/**
 * src/lib/rag/HybridRetriever.js
 * State-of-the-art hybrid retrieval: BM25 + ColBERT + dense + cross-encoder reranking.
 *
 * Pipeline:
 *   1. Broad recall: BM25 (keyword) + single-vector dense + ColBERT multi-vector
 *   2. Reciprocal Rank Fusion (RRF) to merge rankings
 *   3. Cross-encoder reranking using the base LLM as a relevance classifier
 *
 * Usage:
 *   const ret = new HybridRetriever(bm25, singleStore, colbertStore, model, tokenizer);
 *   const results = await ret.retrieve(query, topK=8);
 */

import { packContext } from './VectorStore.js';

// RRF constant (Cormack et al. 2009)
const RRF_K = 60;

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
   * @returns {Promise<Array<{id, score, text, meta}>>}
   */
  async retrieve(query, topK = 8, recallK = 40, {
    queryVec  = null,
    queryToks = null,
    rerank    = true,
  } = {}) {
    const rankLists = [];

    // ── Stage 1: BM25 keyword search ─────────────────────────────────────────
    const bm25Results = this.bm25.search(query, recallK);
    if (bm25Results.length) rankLists.push(bm25Results.map(r => r.id));

    // ── Stage 2: Dense vector search ─────────────────────────────────────────
    if (queryVec && this.denseStore.size > 0) {
      const denseResults = this.denseStore.search(queryVec, recallK);
      rankLists.push(denseResults.map(r => r.id));
    }

    // ── Stage 3: ColBERT multi-vector search ──────────────────────────────────
    if (queryToks?.length && this.colbertStore.size > 0) {
      const colbertResults = this.colbertStore.search(queryToks, recallK);
      rankLists.push(colbertResults.map(r => r.id));
    }

    if (!rankLists.length) return [];

    // ── Stage 4: Reciprocal Rank Fusion ──────────────────────────────────────
    const fused = _rrf(rankLists, RRF_K);

    // Build result objects (look up metadata from any store)
    const pool = this._buildPool(fused.slice(0, recallK), bm25Results);

    if (!rerank || !this.model || pool.length <= topK) {
      return pool.slice(0, topK);
    }

    // ── Stage 5: Cross-encoder reranking ─────────────────────────────────────
    const reranked = await this._crossEncoderRerank(query, pool, topK);
    return reranked;
  }

  /**
   * Cross-encoder reranking: concatenate query + chunk, let the LLM score relevance.
   * Uses next-token probability of a relevance token as the score.
   */
  async _crossEncoderRerank(query, candidates, topK) {
    if (!this.model || !this.tokenizer) return candidates.slice(0, topK);

    const scored = [];
    for (const cand of candidates) {
      try {
        // Prompt: "Query: {q}\nPassage: {p}\nRelevant:"
        const prompt = `Query: ${query}\nPassage: ${cand.text.slice(0, 300)}\nRelevant:`;
        const ids    = this.tokenizer.encode(prompt);

        // Use probability of "yes"/"relevant" token as relevance score
        // Token " yes" and "Yes" are common in most BPE vocabs
        const yesId  = this.tokenizer._str2id.get(' yes') ??
                       this.tokenizer._str2id.get('Yes')  ??
                       this.tokenizer._str2id.get('yes')  ?? 0;

        const prob   = this.model.predictTokenProb(ids, yesId);
        scored.push({ ...cand, score: prob });
      } catch {
        scored.push(cand); // keep original score on error
      }
    }

    return scored.sort((a, b) => b.score - a.score).slice(0, topK);
  }

  /** Build result objects from fused IDs, using BM25 results for text/meta. */
  _buildPool(fusedIds, bm25Results) {
    const byId = new Map(bm25Results.map(r => [r.id, r]));
    return fusedIds.map(({ id, score }) => {
      const bm = byId.get(id) ?? {};
      return { id, score, text: bm.text ?? '', meta: bm.meta ?? {} };
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
