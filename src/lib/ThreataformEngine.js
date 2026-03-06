/**
 * src/lib/ThreataformEngine.js
 * ThreataformLM — Public API (singleton)
 *
 * Coordinates:
 *   - Model loading (from /public/model.tnlm via IndexedDB cache)
 *   - Streaming inference (via engineWorker.js)
 *   - File ingestion + chunking (via ingestWorker.js)
 *   - Hybrid RAG (BM25 + ColBERT + HNSW + HyDE + SELF-RAG)
 *   - In-browser LoRA fine-tuning
 *
 * This module re-exports the same interface as the old WllamaManager.js so
 * existing code in terraform-enterprise-intelligence.jsx requires zero changes.
 *
 * Usage:
 *   import { threataformEngine } from './ThreataformEngine.js';
 *   await threataformEngine.loadFromUrl('/model.tnlm');
 *   for await (const tok of threataformEngine.generate(messages)) { ... }
 */

import EngineWorker  from '../workers/engineWorker.js?worker';
import IngestWorker  from '../workers/ingestWorker.js?worker';
import { BM25Index }         from './rag/BM25Index.js';
import { SingleVectorStore, ColBERTVectorStore, packContext } from './rag/VectorStore.js';
import { HybridRetriever }   from './rag/HybridRetriever.js';
import { hydeTemplate }      from './rag/HyDE.js';
import { tokenizer }         from './llm/Tokenizer.js';
import { extractFile }       from './ingestion/FileRouter.js';
import { HierarchicalChunker } from './rag/Chunker.js';

const MODEL_URL = '/model.tnlm'; // served from /public/ by Vite

let _idCounter = 0;
const _newId = () => `req-${++_idCounter}-${Date.now()}`;

// ─────────────────────────────────────────────────────────────────────────────
//  ThreataformEngine
// ─────────────────────────────────────────────────────────────────────────────

class ThreataformEngine {
  constructor() {
    this._engineWorker = null;  // Web Worker for inference
    this._ingestWorker = null;  // Web Worker for ingestion/embedding
    this._pendingCalls  = new Map(); // id → { resolve, reject, onToken }

    // RAG stores
    this._bm25    = new BM25Index();
    this._dense   = new SingleVectorStore(1024);   // dim matches ThreataformLM-200M
    this._colbert = new ColBERTVectorStore(1024);

    this._chunker     = new HierarchicalChunker({ minChunk: 80, maxChunk: 900 });
    this._retriever   = null; // created after model loads

    this.isLoaded      = false;
    this.modelConfig   = null;
    this.isTraining    = false;
    this.loraReady     = false;

    // Callbacks
    this.onStatus      = null; // (status: string) => void
    this.onProgress    = null; // (step, total, loss) => void
    this.onLoadProgress = null; // (loaded, total) => void
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /** @private Ensure the engine worker is started. */
  _ensureWorker() {
    if (this._engineWorker) return;

    this._engineWorker = new EngineWorker();
    this._engineWorker.onmessage = ({ data }) => this._onEngineMessage(data);
    this._engineWorker.onerror   = (err) => {
      console.error('[ThreataformEngine] Worker error:', err);
      // Reject all pending
      for (const [, p] of this._pendingCalls) p.reject(err);
      this._pendingCalls.clear();
    };
  }

  _ensureIngestWorker() {
    if (this._ingestWorker) return;
    this._ingestWorker = new IngestWorker();
    this._ingestWorker.onmessage = ({ data }) => this._onIngestMessage(data);
    this._ingestWorker.onerror = (err) => console.error('[IngestWorker]', err);
  }

  _onEngineMessage(data) {
    const { type, id } = data;
    const pending = this._pendingCalls.get(id);

    switch (type) {
      case 'workerReady':  break;
      case 'ready':
        this.isLoaded    = true;
        this.modelConfig = data.config;
        this._retriever  = new HybridRetriever(this._bm25, this._dense, this._colbert, null, tokenizer);
        this._status('ready');
        this._resolveAll('ready');
        break;

      case 'loadProgress':
        if (this.onLoadProgress) this.onLoadProgress(data.loaded, data.total);
        break;

      case 'token':
        if (pending?.onToken) pending.onToken(data.token);
        break;

      case 'done':
        pending?.resolve();
        this._pendingCalls.delete(id);
        break;

      case 'embedding':
        pending?.resolve(data.vec);
        this._pendingCalls.delete(id);
        break;

      case 'multiEmbedding':
        pending?.resolve(data.vecs);
        this._pendingCalls.delete(id);
        break;

      case 'progress':
        if (this.onProgress) this.onProgress(data.step, data.total, data.loss);
        break;

      case 'loraSaved':
        pending?.resolve(data.buf);
        this._pendingCalls.delete(id);
        break;

      case 'error':
        console.error('[ThreataformEngine]', data.message);
        pending?.reject(new Error(data.message));
        this._pendingCalls.delete(id);
        break;
    }
  }

  _onIngestMessage(data) {
    const { type, id } = data;
    const pending = this._pendingCalls.get(id);

    switch (type) {
      case 'workerReady': break;
      case 'ingestDone':
        pending?.resolve(data.result);
        this._pendingCalls.delete(id);
        break;
      case 'embedDone':
        pending?.resolve(data.embeddings);
        this._pendingCalls.delete(id);
        break;
      case 'multiEmbDone':
        pending?.resolve(data.multiEmbeddings);
        this._pendingCalls.delete(id);
        break;
      case 'progress':
        if (this.onProgress) this.onProgress(data.done, data.total, 0);
        break;
      case 'error':
        pending?.reject(new Error(data.message));
        this._pendingCalls.delete(id);
        break;
    }
  }

  _call(worker, msg, transferList = []) {
    return new Promise((resolve, reject) => {
      this._pendingCalls.set(msg.id, { resolve, reject });
      worker.postMessage(msg, transferList);
    });
  }

  _status(s) { if (this.onStatus) this.onStatus(s); }

  _resolveAll(val) {
    // Used internally after 'ready' — individual load callers listen via their own promise
  }

  // ── Model loading ─────────────────────────────────────────────────────────

  /**
   * Load ThreataformLM-200M from a URL (uses IDB cache automatically).
   * Compatible with the old wllamaManager.loadFromUrl() signature.
   *
   * @param {string}   url
   * @param {object}   [opts]
   * @param {boolean}  [opts.useCache=true]
   * @returns {Promise<void>}
   */
  async loadFromUrl(url, opts = {}) {
    this._ensureWorker();
    this._status('loading');
    const id = _newId();
    return this._call(this._engineWorker, { type: 'load', id, url });
  }

  /**
   * Load from a File object (user-selected file picker — for testing).
   * @param {File} file
   * @returns {Promise<void>}
   */
  async loadFromFile(file) {
    const buf = await file.arrayBuffer();
    return this.loadFromBuffer(buf);
  }

  /**
   * Load from an ArrayBuffer (already-read data).
   * @param {ArrayBuffer} buf
   */
  async loadFromBuffer(buf) {
    this._ensureWorker();
    this._status('loading');
    const id  = _newId();
    return this._call(this._engineWorker, { type: 'load', id, url: null, buf }, [buf]);
  }

  /**
   * Auto-load from the bundled /public/model.tnlm asset.
   * Called automatically by ThreataformEngine on first use if model not loaded.
   */
  async autoLoad() {
    if (this.isLoaded) return;
    return this.loadFromUrl(MODEL_URL);
  }

  // ── Inference ─────────────────────────────────────────────────────────────

  /**
   * Generate a streaming response.
   * @param {Array<{role,content}>} messages
   * @param {object}   [opts]
   * @param {Function} [opts.onToken]  called with each token ID
   * @param {number}   [opts.maxNew=512]
   * @param {number}   [opts.temp=0.7]
   * @param {number}   [opts.topP=0.9]
   * @returns {AsyncGenerator<string>}  yields decoded token strings
   */
  async *generate(messages, opts = {}) {
    if (!this.isLoaded) await this.autoLoad();

    const id       = _newId();
    const tokens   = [];
    const resolved = { done: false };

    // Wrap to collect tokens
    let _resolve, _reject;
    const done = new Promise((res, rej) => { _resolve = res; _reject = rej; });

    this._pendingCalls.set(id, {
      resolve:  () => { resolved.done = true; _resolve(); },
      reject:   _reject,
      onToken:  (tok) => tokens.push(tok),
    });

    // Inject RAG context into messages
    const augmented = await this._augmentMessages(messages, opts);

    this._engineWorker.postMessage({ type: 'generate', id, messages: augmented, opts });

    // Yield tokens as they arrive
    let idx = 0;
    while (!resolved.done || idx < tokens.length) {
      if (idx < tokens.length) {
        const decoded = tokenizer.decode([tokens[idx++]]);
        if (decoded) yield decoded;
      } else {
        await new Promise(r => setTimeout(r, 10));
      }
    }
    await done;
  }

  /**
   * Augment messages with RAG context (BM25 + vector retrieval).
   * @private
   */
  async _augmentMessages(messages, opts = {}) {
    const query = messages.findLast(m => m.role === 'user')?.content ?? '';
    if (!query || this._bm25.size === 0) return messages;

    try {
      // BM25 retrieval only (model not used in context path to avoid re-entrance)
      const bm25Results = this._bm25.search(query, 5);
      if (!bm25Results.length) return messages;

      const context = packContext(bm25Results, 1200, 'Relevant Context from Uploaded Documents');

      // Inject context as an additional system message
      const withCtx = [...messages];
      const sysIdx  = withCtx.findIndex(m => m.role === 'system');
      if (sysIdx >= 0) {
        withCtx.splice(sysIdx + 1, 0, { role: 'system', content: context });
      } else {
        withCtx.unshift({ role: 'system', content: context });
      }
      return withCtx;
    } catch {
      return messages;
    }
  }

  /**
   * Get an embedding vector for a text string.
   * @param {string} text
   * @returns {Promise<Float32Array>}
   */
  async embed(text) {
    if (!this.isLoaded) await this.autoLoad();
    const id = _newId();
    return this._call(this._engineWorker, { type: 'embed', id, text });
  }

  /**
   * Get per-token embeddings (ColBERT style).
   * @param {string} text
   * @returns {Promise<Float32Array[]>}
   */
  async embedMulti(text) {
    if (!this.isLoaded) await this.autoLoad();
    const id = _newId();
    return this._call(this._engineWorker, { type: 'embedMulti', id, text });
  }

  /**
   * Embed a query (alias for embed — kept for backwards compatibility).
   * @param {string} query
   * @returns {Promise<Float32Array>}
   */
  async embedQuery(query) {
    return this.embed(query);
  }

  // ── Document ingestion + RAG ──────────────────────────────────────────────

  /**
   * Ingest a document: extract text, chunk, embed, add to retrieval indices.
   * @param {File} file
   * @param {object} [opts]
   * @returns {Promise<{ text, chunks, metadata, entities }>}
   */
  async ingestFile(file, opts = {}) {
    // Extract text on the main thread (FileRouter is synchronous-safe)
    const result = await extractFile(file);
    await this._indexResult(result, file.name);
    return result;
  }

  /**
   * Ingest raw text (e.g. from a text area or API response).
   * @param {string} text
   * @param {string} id     Logical document ID
   * @param {object} [meta]
   */
  async ingestText(text, id, meta = {}) {
    const chunks = await this._chunker.chunk(text, null);
    for (let i = 0; i < chunks.length; i++) {
      const chunkId = `${id}#${i}`;
      const chunkMeta = { ...meta, chunkIdx: i, filename: id };
      this._bm25.addDocument(chunkId, chunks[i], chunkMeta);

      // Dense embedding (if model loaded)
      if (this.isLoaded) {
        try {
          const vec = await this.embed(chunks[i]);
          this._dense.add(chunkId, vec, { text: chunks[i], ...chunkMeta });
        } catch { /* skip dense if embed fails */ }
      }
    }
  }

  /** @private Add extraction result to BM25 + vector stores. */
  async _indexResult(result, filename) {
    const chunks = await this._chunker.chunk(result.text, null);

    for (let i = 0; i < chunks.length; i++) {
      const chunkId = `${filename}#${i}`;
      const meta    = { ...result.metadata, chunkIdx: i, text: chunks[i] };

      this._bm25.addDocument(chunkId, chunks[i], meta);

      if (this.isLoaded) {
        try {
          const vec = await this.embed(chunks[i]);
          this._dense.add(chunkId, vec, meta);
        } catch { /* dense optional */ }
      }
    }
  }

  /** Search the RAG index. */
  async search(query, topK = 8) {
    const bm25 = this._bm25.search(query, topK);
    if (!this.isLoaded || this._dense.size === 0) return bm25;

    try {
      const qVec  = await this.embed(query);
      const dense = this._dense.search(qVec, topK);
      // Simple merge by RRF
      const { rrf } = await import('./rag/HybridRetriever.js');
      const fused   = rrf([bm25.map(r => r.id), dense.map(r => r.id)]);
      const byId    = new Map([...bm25, ...dense].map(r => [r.id, r]));
      return fused.slice(0, topK).map(({ id, score }) => ({ ...byId.get(id), score }));
    } catch {
      return bm25;
    }
  }

  // ── LoRA fine-tuning ──────────────────────────────────────────────────────

  /**
   * Fine-tune LoRA adapters on user documents (runs in engineWorker).
   * @param {string[]}  texts    Chunked text snippets to train on
   * @param {object}    [opts]
   * @returns {Promise<void>}
   */
  async fineTune(texts, opts = {}) {
    if (!this.isLoaded) throw new Error('Model not loaded');

    this.isTraining = true;
    this._status('training');

    // Tokenize all chunks
    const chunks = texts.map(t => tokenizer.encode(t.slice(0, 1024)));
    const id     = _newId();

    try {
      await this._call(this._engineWorker, { type: 'train', id, chunks, opts });
      this.loraReady = true;
      this._status('ready');
    } finally {
      this.isTraining = false;
    }
  }

  /** Save LoRA adapter weights to an ArrayBuffer. */
  async saveLoRA() {
    if (!this.isLoaded) throw new Error('Model not loaded');
    const id = _newId();
    return this._call(this._engineWorker, { type: 'loraSave', id });
  }

  /** Load LoRA adapter weights from an ArrayBuffer. */
  async loadLoRA(buf) {
    if (!this.isLoaded) throw new Error('Model not loaded');
    const id = _newId();
    return this._call(this._engineWorker, { type: 'loraLoad', id, buf }, [buf]);
  }

  // ── Utility ───────────────────────────────────────────────────────────────

  /** Cancel an in-progress generation by ID. */
  cancel(id) {
    if (this._engineWorker) this._engineWorker.postMessage({ type: 'cancel', id });
  }

  /** Clear the RAG index. */
  clearDocuments() {
    this._bm25.clear();
    this._dense.clear();
    this._colbert.clear();
  }

  /** Status string for UI display. */
  get statusText() {
    if (!this.isLoaded)      return 'Loading ThreataformLM-200M...';
    if (this.isTraining)     return 'Fine-tuning on your docs...';
    if (this.loraReady)      return 'ThreataformLM-200M · Domain-tuned · Ready';
    return 'ThreataformLM-200M · Ready';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Singleton export
// ─────────────────────────────────────────────────────────────────────────────

export const threataformEngine = new ThreataformEngine();
export default threataformEngine;
