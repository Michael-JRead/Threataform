/**
 * src/lib/rag/BM25Index.js
 * BM25+ full-text index — pure JavaScript, zero dependencies.
 *
 * Implements Okapi BM25 with:
 *   - Robertson–Sparck Jones IDF (with +1 smoothing to avoid divide-by-zero)
 *   - BM25+ delta term to prevent zero scoring for rare terms
 *   - Security domain stop-word list
 *
 * Usage:
 *   const idx = new BM25Index();
 *   idx.addDocument('doc-1', 'S3 bucket lacks encryption at rest');
 *   const results = idx.search('s3 encryption', 5);
 *   // → [{ id: 'doc-1', score: 3.12 }, …]
 */

const K1   = 1.5;   // term frequency saturation
const B    = 0.75;  // length normalisation
const DELTA = 0.5;  // BM25+ lower bound

const STOP_WORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
  'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
  'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
  'should', 'could', 'may', 'might', 'it', 'its', 'this', 'that', 'these',
  'those', 'not', 'no', 'so', 'as', 'if', 'then', 'than', 'when', 'where',
  'which', 'who', 'what', 'how', 'can', 'also', 'all', 'any', 'each',
  'both', 'few', 'more', 'most', 'other', 'some', 'such', 'into', 'about',
  'up', 'out', 'use', 'used', 'using', 'used', 'per', 'via',
]);

export class BM25Index {
  constructor() {
    /** @type {Map<string, {id:string, tf:Map<string,number>, len:number}>} */
    this._docs  = new Map();
    /** @type {Map<string, number>} term → document frequency */
    this._df    = new Map();
    this._avgdl = 0;
    this._dirty = true;  // true when index needs recomputing after adds
  }

  /**
   * Add a document to the index.
   * @param {string} id    Unique document identifier
   * @param {string} text  Document text
   * @param {object} [meta] Optional metadata stored alongside
   */
  addDocument(id, text, meta = {}) {
    const terms = this._tokenize(text);
    const tf    = new Map();
    for (const t of terms) tf.set(t, (tf.get(t) ?? 0) + 1);
    this._docs.set(id, { id, tf, len: terms.length, meta, text });
    for (const t of tf.keys()) this._df.set(t, (this._df.get(t) ?? 0) + 1);
    this._dirty = true;
  }

  /** Remove a document from the index. */
  removeDocument(id) {
    const doc = this._docs.get(id);
    if (!doc) return;
    for (const t of doc.tf.keys()) {
      const df = (this._df.get(t) ?? 1) - 1;
      if (df <= 0) this._df.delete(t);
      else this._df.set(t, df);
    }
    this._docs.delete(id);
    this._dirty = true;
  }

  /** Clear all documents. */
  clear() {
    this._docs.clear();
    this._df.clear();
    this._avgdl = 0;
    this._dirty = true;
  }

  /**
   * Search for documents matching a query.
   * @param {string} query
   * @param {number} [topK=10]
   * @returns {Array<{id:string, score:number, meta:object, text:string}>}
   */
  search(query, topK = 10) {
    this._build();
    const qTerms = this._tokenize(query);
    if (!qTerms.length || !this._docs.size) return [];

    const N      = this._docs.size;
    const scores = new Map();

    for (const term of new Set(qTerms)) {
      const df  = this._df.get(term) ?? 0;
      if (df === 0) continue;
      const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));

      for (const doc of this._docs.values()) {
        const tf  = doc.tf.get(term) ?? 0;
        if (tf === 0) continue;
        const norm = K1 * (1 - B + B * (doc.len / this._avgdl));
        const bm25 = idf * (DELTA + tf * (K1 + 1) / (tf + norm));
        scores.set(doc.id, (scores.get(doc.id) ?? 0) + bm25);
      }
    }

    return Array.from(scores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, topK)
      .map(([id, score]) => {
        const doc = this._docs.get(id);
        return { id, score, text: doc.text, meta: doc.meta };
      });
  }

  /** Number of indexed documents. */
  get size() { return this._docs.size; }

  // ── Private ──────────────────────────────────────────────────────────────

  _build() {
    if (!this._dirty) return;
    if (!this._docs.size) { this._avgdl = 0; this._dirty = false; return; }
    let total = 0;
    for (const doc of this._docs.values()) total += doc.len;
    this._avgdl = total / this._docs.size;
    this._dirty = false;
  }

  _tokenize(text) {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9_.-]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length >= 2 && !STOP_WORDS.has(t));
  }

  /** Serialize to a plain object for persistence. */
  toJSON() {
    const docs = {};
    for (const [id, doc] of this._docs) {
      docs[id] = { tf: Object.fromEntries(doc.tf), len: doc.len, meta: doc.meta, text: doc.text };
    }
    return { docs, df: Object.fromEntries(this._df) };
  }

  /** Restore from a serialized object. */
  fromJSON(data) {
    this.clear();
    for (const [id, d] of Object.entries(data.docs)) {
      this._docs.set(id, { id, tf: new Map(Object.entries(d.tf)), len: d.len, meta: d.meta, text: d.text });
    }
    for (const [t, df] of Object.entries(data.df)) this._df.set(t, df);
    this._dirty = true;
  }
}
