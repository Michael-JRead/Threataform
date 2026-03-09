/**
 * src/lib/rag/VectorStore.js
 * Multi-vector ColBERT-style vector store + HNSW approximate nearest-neighbour.
 *
 * Two storage modes:
 *   SingleVectorStore   — one embedding per document chunk (dense retrieval)
 *   ColBERTVectorStore  — one embedding per token (late-interaction MaxSim)
 *
 * HNSW (Hierarchical Navigable Small World) provides O(log N) ANN search.
 *
 * Enhancements:
 *   - Embedding LRU cache (500 entries, keyed by djb2 hash of text)
 *   - HNSW serialization/persistence to IndexedDB
 *
 * Usage:
 *   const store = new SingleVectorStore(dim);
 *   store.add('chunk-1', embedding, metadata);
 *   const results = store.search(queryVec, 5);
 *   await store.persistHNSW('my-index-key');
 *   // on next load:
 *   const restored = await store.loadHNSW('my-index-key', itemsArray);
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Embedding LRU cache
//  Module-level so it is shared across all VectorStore instances in the session.
//  Key: djb2 hash of the text string. Value: Float32Array embedding.
// ─────────────────────────────────────────────────────────────────────────────
const _EMB_CACHE_MAX = 500;
const _embCache = new Map();

/** djb2 hash — fast, good distribution for short strings */
function _djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(36);
}

/**
 * Wrap an async embed function with LRU caching.
 * @param {string}   text
 * @param {Function} embedFn  async (text) => Float32Array
 * @returns {Promise<Float32Array>}
 */
export async function cachedEmbed(text, embedFn) {
  const key = _djb2(text);
  if (_embCache.has(key)) return _embCache.get(key);
  const vec = await embedFn(text);
  if (_embCache.size >= _EMB_CACHE_MAX) {
    // Evict oldest entry (Map preserves insertion order)
    _embCache.delete(_embCache.keys().next().value);
  }
  _embCache.set(key, vec);
  return vec;
}

/** Invalidate entire embedding cache (call after re-ingesting documents). */
export function clearEmbedCache() { _embCache.clear(); }

// ─────────────────────────────────────────────────────────────────────────────
//  Lightweight IndexedDB helpers for HNSW persistence
// ─────────────────────────────────────────────────────────────────────────────
async function _idbOpen() {
  return new Promise((res, rej) => {
    const req = indexedDB.open('threataform-vectors', 2);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
    };
    req.onsuccess = e => res(e.target.result);
    req.onerror   = () => rej(req.error);
  });
}
async function _idbGet(key) {
  try {
    const db = await _idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', 'readonly');
      const r  = tx.objectStore('kv').get(key);
      r.onsuccess = () => { db.close(); res(r.result); };
      r.onerror   = () => { db.close(); rej(r.error); };
    });
  } catch { return undefined; }
}
async function _idbPut(key, value) {
  try {
    const db = await _idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', 'readwrite');
      const r  = tx.objectStore('kv').put(value, key);
      r.onsuccess = () => { db.close(); res(); };
      r.onerror   = () => { db.close(); rej(r.error); };
    });
  } catch { /* silently ignore */ }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Math helpers
// ─────────────────────────────────────────────────────────────────────────────

function cosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na  += a[i] * a[i];
    nb  += b[i] * b[i];
  }
  const d = Math.sqrt(na) * Math.sqrt(nb);
  return d < 1e-10 ? 0 : dot / d;
}

function l2(a, b) {
  let s = 0;
  for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; s += d * d; }
  return Math.sqrt(s);
}

// ─────────────────────────────────────────────────────────────────────────────
//  HNSW — Hierarchical Navigable Small World
// ─────────────────────────────────────────────────────────────────────────────

class HNSW {
  /**
   * @param {number} dim        Vector dimensionality
   * @param {number} [M=16]     Max connections per node per layer
   * @param {number} [efC=200]  ef during construction
   * @param {number} [efS=50]   ef during search
   */
  constructor(dim, M = 16, efC = 200, efS = 50) {
    this.dim   = dim;
    this.M     = M;
    this.efC   = efC;
    this.efS   = efS;
    this.mL    = 1 / Math.log(M);  // level multiplier

    this._data    = [];  // { id, vec, level, neighbors: Array<Set<number>> }
    this._entryPt = -1;  // index of entry-point node
    this._maxLvl  = -1;
  }

  /** Insert a vector with an external id. */
  insert(id, vec) {
    const level = Math.floor(-Math.log(Math.random()) * this.mL);
    const node  = { id, vec, level, neighbors: Array.from({ length: level + 1 }, () => new Set()) };
    const idx   = this._data.push(node) - 1;

    if (this._entryPt === -1) {
      this._entryPt = idx;
      this._maxLvl  = level;
      return;
    }

    let curr = [this._entryPt];
    for (let lc = this._maxLvl; lc > level; lc--) {
      curr = this._greedySearch(vec, curr, 1, lc);
    }

    for (let lc = Math.min(level, this._maxLvl); lc >= 0; lc--) {
      const cands = this._searchLayer(vec, curr, this.efC, lc);
      const nbrs  = this._selectNeighbors(vec, cands, this.M);
      for (const n of nbrs) {
        node.neighbors[lc].add(n);
        this._data[n].neighbors[lc] ??= new Set();
        this._data[n].neighbors[lc].add(idx);
        // Prune neighbours that exceed M
        if (this._data[n].neighbors[lc].size > this.M) {
          const pruned = this._selectNeighbors(
            this._data[n].vec,
            Array.from(this._data[n].neighbors[lc]).map(j => ({ idx: j, dist: l2(this._data[n].vec, this._data[j].vec) })),
            this.M
          );
          this._data[n].neighbors[lc] = new Set(pruned);
        }
      }
      curr = nbrs;
    }

    if (level > this._maxLvl) { this._entryPt = idx; this._maxLvl = level; }
  }

  /**
   * K-nearest-neighbour search.
   * @param {Float32Array} query
   * @param {number}       K
   * @returns {Array<{idx: number, dist: number}>}
   */
  search(query, K) {
    if (this._entryPt === -1) return [];
    let curr = [this._entryPt];
    for (let lc = this._maxLvl; lc > 0; lc--) {
      curr = this._greedySearch(query, curr, 1, lc);
    }
    const cands = this._searchLayer(query, curr, Math.max(this.efS, K), 0);
    return cands.slice(0, K);
  }

  _dist(a, b) { return 1 - cosine(a, b); } // cosine distance

  _greedySearch(query, entry, ef, lc) {
    const visited  = new Set(entry);
    const frontier = entry.map(idx => ({ idx, dist: this._dist(query, this._data[idx].vec) }));
    frontier.sort((a, b) => a.dist - b.dist);
    let best = [...frontier];

    while (frontier.length) {
      const curr = frontier.shift();
      if (best.length >= ef && curr.dist > best[ef - 1].dist) break;

      const nbrs = this._data[curr.idx].neighbors[lc] ?? new Set();
      for (const n of nbrs) {
        if (!visited.has(n)) {
          visited.add(n);
          const d = this._dist(query, this._data[n].vec);
          frontier.push({ idx: n, dist: d });
          best.push({ idx: n, dist: d });
        }
      }
      frontier.sort((a, b) => a.dist - b.dist);
      best.sort((a, b) => a.dist - b.dist);
      if (best.length > ef) best.length = ef;
    }
    return best.slice(0, ef).map(c => c.idx);
  }

  _searchLayer(query, entry, ef, lc) {
    const visited  = new Set(entry);
    let   cands    = entry.map(idx => ({ idx, dist: this._dist(query, this._data[idx].vec) }));
    let   result   = [...cands];

    while (cands.length) {
      cands.sort((a, b) => a.dist - b.dist);
      const curr = cands.shift();
      const worst = result[result.length - 1]?.dist ?? Infinity;
      if (curr.dist > worst && result.length >= ef) break;

      const nbrs = this._data[curr.idx].neighbors[lc] ?? new Set();
      for (const n of nbrs) {
        if (!visited.has(n)) {
          visited.add(n);
          const d = this._dist(query, this._data[n].vec);
          if (result.length < ef || d < (result[result.length - 1]?.dist ?? Infinity)) {
            cands.push({ idx: n, dist: d });
            result.push({ idx: n, dist: d });
            result.sort((a, b) => a.dist - b.dist);
            if (result.length > ef) result.length = ef;
          }
        }
      }
    }
    return result;
  }

  _selectNeighbors(query, cands, M) {
    if (!Array.isArray(cands)) {
      cands = Array.from(cands).map(idx => ({ idx, dist: l2(query, this._data[idx].vec) }));
    }
    cands.sort((a, b) => a.dist - b.dist);
    return cands.slice(0, M).map(c => c.idx);
  }

  get size() { return this._data.length; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SingleVectorStore — one embedding per chunk
// ─────────────────────────────────────────────────────────────────────────────

export class SingleVectorStore {
  /**
   * @param {number} dim  Embedding dimensionality
   */
  constructor(dim) {
    this.dim    = dim;
    this._items = [];  // { id, vec, meta, text }
    this._hnsw  = new HNSW(dim);
    this._idMap = new Map(); // id → array index
  }

  /**
   * Add a document chunk.
   * @param {string}      id    Unique chunk identifier
   * @param {Float32Array} vec  Embedding vector [dim]
   * @param {object}      meta  { text, filename, chunkIdx, … }
   */
  add(id, vec, meta = {}) {
    const idx = this._items.length;
    this._items.push({ id, vec, meta });
    this._idMap.set(id, idx);
    this._hnsw.insert(idx, vec);
  }

  /**
   * Search for the K nearest chunks.
   * @param {Float32Array} query
   * @param {number}       [K=10]
   * @returns {Array<{id, score, meta}>}
   */
  search(query, K = 10) {
    if (this._hnsw.size === 0) return [];
    const results = this._hnsw.search(query, K);
    return results.map(({ idx, dist }) => {
      const item = this._items[idx];
      return { id: item.id, score: 1 - dist, ...item.meta };
    });
  }

  /** Brute-force search (exact, slower — use for small stores or verification). */
  searchExact(query, K = 10) {
    return this._items
      .map(item => ({ id: item.id, score: cosine(query, item.vec), ...item.meta }))
      .sort((a, b) => b.score - a.score)
      .slice(0, K);
  }

  clear() {
    this._items = [];
    this._hnsw  = new HNSW(this.dim);
    this._idMap.clear();
  }

  get size() { return this._items.length; }

  // ── HNSW Persistence ─────────────────────────────────────────────────────

  /**
   * Serialize the HNSW graph to IndexedDB.
   * Key convention: `tf-hnsw-v1-${chunkCount}` — include count so stale
   * caches are automatically ignored when the index changes.
   *
   * @param {string} idbKey  e.g. 'tf-hnsw-v1-42'
   */
  async persistHNSW(idbKey) {
    try {
      const nodes = this._hnsw._data.map(n => ({
        id:        n.id,
        vec:       Array.from(n.vec),   // Float32Array → plain array for JSON
        level:     n.level,
        neighbors: n.neighbors.map(s => Array.from(s)),
      }));
      await _idbPut(idbKey, {
        nodes,
        entryPt: this._hnsw._entryPt,
        maxLvl:  this._hnsw._maxLvl,
        dim:     this.dim,
        count:   this._items.length,
      });
    } catch { /* persistence failures are non-fatal */ }
  }

  /**
   * Restore the HNSW graph from IndexedDB.
   * Items (id/vec/meta) must be re-passed since they are not stored in HNSW.
   *
   * @param {string} idbKey
   * @param {Array<{id,vec,meta}>} items  Must match the persisted order
   * @returns {Promise<boolean>}  true if restored, false if not found or stale
   */
  async loadHNSW(idbKey, items) {
    try {
      const data = await _idbGet(idbKey);
      if (!data || data.count !== items.length || data.dim !== this.dim) return false;

      // Restore items
      this._items = items;
      this._idMap.clear();
      items.forEach((item, i) => this._idMap.set(item.id, i));

      // Restore HNSW graph
      this._hnsw._data = data.nodes.map(n => ({
        id:        n.id,
        vec:       new Float32Array(n.vec),
        level:     n.level,
        neighbors: n.neighbors.map(arr => new Set(arr)),
      }));
      this._hnsw._entryPt = data.entryPt;
      this._hnsw._maxLvl  = data.maxLvl;
      return true;
    } catch { return false; }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ColBERTVectorStore — one embedding per token (late-interaction MaxSim)
// ─────────────────────────────────────────────────────────────────────────────

export class ColBERTVectorStore {
  /**
   * @param {number} dim  Embedding dimensionality (per token)
   */
  constructor(dim) {
    this.dim    = dim;
    this._docs  = new Map(); // id → { tokenVecs: Float32Array[], meta }
  }

  /**
   * Add a document with per-token embeddings.
   * @param {string}        id
   * @param {Float32Array[]} tokenVecs  One [dim] vector per token
   * @param {object}        meta
   */
  add(id, tokenVecs, meta = {}) {
    this._docs.set(id, { tokenVecs, meta });
  }

  /**
   * MaxSim late-interaction scoring.
   * Score(Q, D) = Σ_{qi in Q} max_{dj in D} cosine(qi, dj)
   *
   * @param {Float32Array[]} queryVecs  Per-token query embeddings
   * @param {number}         [K=10]
   * @returns {Array<{id, score, meta}>}
   */
  search(queryVecs, K = 10) {
    const scores = [];

    for (const [id, { tokenVecs, meta }] of this._docs) {
      let score = 0;
      for (const qv of queryVecs) {
        let maxSim = -Infinity;
        for (const dv of tokenVecs) {
          const sim = cosine(qv, dv);
          if (sim > maxSim) maxSim = sim;
        }
        score += Math.max(0, maxSim); // only add positive contributions
      }
      scores.push({ id, score: score / queryVecs.length, ...meta });
    }

    return scores.sort((a, b) => b.score - a.score).slice(0, K);
  }

  remove(id) { this._docs.delete(id); }
  clear()    { this._docs.clear(); }
  get size() { return this._docs.size; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ContextPacker — fill a context window with top-scoring chunks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Pack retrieved chunks into a context string that fits within maxTokens.
 * Chunks are ordered by score (best first) and truncated to fit.
 *
 * @param {Array<{text:string, score:number, id:string}>} chunks
 * @param {number} maxTokens  Approximate token budget (1 token ≈ 4 chars)
 * @param {string} [header]
 * @returns {string}
 */
export function packContext(chunks, maxTokens = 2000, header = 'Retrieved Context') {
  const maxChars = maxTokens * 4;
  let   used     = header.length + 4;
  const parts    = [`${header}:\n`];

  for (const chunk of chunks) {
    const block  = `\n[${chunk.id ?? 'doc'}] ${chunk.text}\n`;
    if (used + block.length > maxChars) break;
    parts.push(block);
    used += block.length;
  }

  return parts.join('');
}
