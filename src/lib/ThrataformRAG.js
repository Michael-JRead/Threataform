/**
 * ThrataformRAG — Custom LLM/RAG Engine Built From Scratch
 *
 * A pure JavaScript implementation of:
 *   1. RecursiveTextSplitter   — semantic chunking (no external deps)
 *   2. BM25Index               — term-frequency inverse-document-frequency retrieval
 *   3. VectorStore             — in-memory dense vector store (cosine similarity)
 *   4. ContextPacker           — greedy context window filling + overflow summarization
 *   5. hybridSearch            — BM25 + dense vector search merged with RRF fusion
 *   6. buildRAGPrompt          — structured prompt construction for security analysis
 *
 * Designed for: Threataform security intelligence
 * Architecture inspired by: pguso/rag-from-scratch, rasbt/LLMs-from-scratch
 * Runs 100% offline. No internet. No API. No external dependencies.
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. RECURSIVE TEXT SPLITTER
// Splits documents at natural boundaries (paragraphs → sentences → words)
// Produces overlapping chunks for better retrieval coverage
// ═══════════════════════════════════════════════════════════════════════════

export class RecursiveTextSplitter {
  constructor({
    chunkSize    = 512,   // target chars per chunk (~128 tokens)
    chunkOverlap = 64,    // overlap between consecutive chunks
    separators   = ['\n\n', '\n', '. ', '! ', '? ', '; ', ', ', ' ', ''],
  } = {}) {
    this.chunkSize    = chunkSize;
    this.chunkOverlap = chunkOverlap;
    this.separators   = separators;
  }

  split(text) {
    if (!text?.trim()) return [];
    return this._splitRecursive(text.trim(), this.separators).filter(c => c.trim().length > 20);
  }

  _splitRecursive(text, separators) {
    if (text.length <= this.chunkSize) return [text.trim()];

    // Find the highest-priority separator that exists in the text
    const sep = separators.find(s => s && text.includes(s)) ?? '';
    const parts = sep ? text.split(sep) : [...text];

    const chunks = [];
    let current = '';

    for (const part of parts) {
      const candidate = current ? current + sep + part : part;
      if (candidate.length <= this.chunkSize) {
        current = candidate;
      } else {
        if (current.trim()) chunks.push(current.trim());
        // Overlap: carry the tail of the previous chunk into the next
        const tail = current.length > this.chunkOverlap
          ? current.slice(-this.chunkOverlap)
          : current;
        current = tail ? tail + sep + part : part;
      }
    }
    if (current.trim()) chunks.push(current.trim());

    // Recursively split any chunks still over the limit
    return chunks.flatMap(c =>
      c.length > this.chunkSize * 1.5
        ? this._splitRecursive(c, separators.slice(1))
        : [c]
    );
  }

  // Split a document and tag chunks with metadata
  splitDocument(text, metadata = {}) {
    return this.split(text).map((chunkText, i) => ({
      text:     chunkText,
      charIdx:  text.indexOf(chunkText),
      chunkIdx: i,
      ...metadata,
    }));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. BM25 INDEX
// Okapi BM25 — the gold standard for keyword-based retrieval
// k1=1.5, b=0.75 are the standard parameters
// ═══════════════════════════════════════════════════════════════════════════

export class BM25Index {
  constructor({ k1 = 1.5, b = 0.75 } = {}) {
    this.k1   = k1;
    this.b    = b;
    this.docs = [];       // original chunk objects
    this.tf   = [];       // [{ freq: Map<term,count>, len: number }]
    this.df   = new Map(); // term → document frequency
    this.avgdl = 0;
    this.N    = 0;
  }

  tokenize(text) {
    return text.toLowerCase()
      .replace(/[^a-z0-9_\-./\s]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 1 && !STOP_WORDS.has(t));
  }

  build(chunks) {
    this.docs  = chunks;
    this.N     = chunks.length;
    this.df    = new Map();

    this.tf = chunks.map(c => {
      const tokens = this.tokenize(c.text || c);
      const freq   = new Map();
      for (const t of tokens) freq.set(t, (freq.get(t) ?? 0) + 1);
      // Document frequency update
      for (const t of freq.keys()) this.df.set(t, (this.df.get(t) ?? 0) + 1);
      return { freq, len: tokens.length };
    });

    this.avgdl = this.tf.reduce((s, d) => s + d.len, 0) / Math.max(this.N, 1);
    return this;
  }

  query(q, topK = 8) {
    if (!this.N) return [];
    const terms = this.tokenize(q);
    if (!terms.length) return [];

    const scores = this.tf.map((doc, i) => {
      let score = 0;
      for (const term of terms) {
        const tf = doc.freq.get(term) ?? 0;
        if (!tf) continue;
        const df  = this.df.get(term) ?? 0;
        const idf = Math.log((this.N - df + 0.5) / (df + 0.5) + 1);
        const norm = tf * (this.k1 + 1) /
          (tf + this.k1 * (1 - this.b + this.b * doc.len / this.avgdl));
        score += idf * norm;
      }
      return { score, idx: i };
    });

    return scores
      .filter(x => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, topK)
      .map(x => ({ ...this.docs[x.idx], bm25: x.score, idx: x.idx }));
  }
}

// BM25 stop words for security documents
const STOP_WORDS = new Set([
  'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'any', 'can',
  'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him',
  'his', 'how', 'its', 'may', 'now', 'own', 'see', 'set', 'she', 'too',
  'was', 'with', 'that', 'this', 'from', 'they', 'will', 'been', 'have',
  'more', 'also', 'into', 'than', 'then', 'when', 'what', 'your', 'able',
  'each', 'just', 'over', 'such', 'take', 'them', 'well', 'were',
]);

// ═══════════════════════════════════════════════════════════════════════════
// 3. PURE JS VECTOR STORE
// In-memory dense vector store with cosine similarity
// Supports incremental builds (add chunks as they're embedded)
// ═══════════════════════════════════════════════════════════════════════════

export class VectorStore {
  constructor() {
    this.items = []; // [{ id, vector: number[], text, ...metadata }]
  }

  add(id, vector, metadata = {}) {
    // Replace if same id already exists
    const existing = this.items.findIndex(x => x.id === id);
    const entry = { id, vector, ...metadata };
    if (existing >= 0) this.items[existing] = entry;
    else this.items.push(entry);
  }

  addBatch(entries) {
    for (const e of entries) this.add(e.id, e.vector, e);
  }

  // Cosine similarity search
  search(queryVector, topK = 8, threshold = 0.05) {
    if (!this.items.length || !queryVector?.length) return [];
    return this.items
      .filter(item => item.vector?.length === queryVector.length)
      .map(item => ({ ...item, sim: cosine(queryVector, item.vector) }))
      .filter(r => r.sim >= threshold)
      .sort((a, b) => b.sim - a.sim)
      .slice(0, topK);
  }

  clear() { this.items = []; }
  get size() { return this.items.length; }
}

function cosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom > 0 ? dot / denom : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. RECIPROCAL RANK FUSION
// Merges BM25 and dense search results without needing score normalization
// k=60 is standard; higher k reduces the impact of rank position
// ═══════════════════════════════════════════════════════════════════════════

export function reciprocalRankFusion(bm25Results, denseResults, allChunks, k = 60) {
  const scoreMap = new Map(); // key → score
  const chunkMap = new Map(); // key → chunk obj

  const key = (item) => (item.text || '').substring(0, 60) + '_' + (item.idx ?? item.id ?? '');

  bm25Results.forEach((item, rank) => {
    const k_ = key(item);
    scoreMap.set(k_, (scoreMap.get(k_) ?? 0) + 1 / (k + rank + 1));
    if (!chunkMap.has(k_)) chunkMap.set(k_, { ...item, searchType: 'bm25' });
  });

  denseResults.forEach((item, rank) => {
    const k_ = key(item);
    scoreMap.set(k_, (scoreMap.get(k_) ?? 0) + 1 / (k + rank + 1));
    if (!chunkMap.has(k_)) chunkMap.set(k_, { ...item, searchType: 'dense' });
    else chunkMap.set(k_, { ...chunkMap.get(k_), searchType: 'hybrid', sim: item.sim });
  });

  return [...scoreMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([k_]) => chunkMap.get(k_))
    .filter(Boolean);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. CONTEXT PACKER — "Unlimited Tokens"
// Greedy context window packing with recursive summarization for overflow
// Solves the problem of large document sets exceeding the LLM's context window
// ═══════════════════════════════════════════════════════════════════════════

export class ContextPacker {
  constructor({
    tokenBudget     = 3000,   // tokens reserved for retrieved context
    charsPerToken   = 4,      // English approximation (conservative)
    systemOverhead  = 600,    // system prompt + query + answer prefix
    summaryBudget   = 200,    // tokens per batch summary
    batchSize       = 6,      // chunks per summarization batch
  } = {}) {
    this.tokenBudget    = tokenBudget;
    this.charsPerToken  = charsPerToken;
    this.systemOverhead = systemOverhead;
    this.summaryBudget  = summaryBudget;
    this.batchSize      = batchSize;
    this.effectiveBudget = (tokenBudget - systemOverhead) * charsPerToken;
  }

  estimateTokens(text) {
    return Math.ceil(text.length / this.charsPerToken);
  }

  // Greedily fill context window with best chunks
  // Returns { selected, overflow }
  packGreedy(rankedChunks) {
    let charBudget = this.effectiveBudget;
    const selected = [];
    const overflow = [];

    for (const chunk of rankedChunks) {
      const chars = (chunk.text || '').length;
      if (chars <= charBudget) {
        selected.push(chunk);
        charBudget -= chars;
      } else {
        overflow.push(chunk);
      }
    }
    return { selected, overflow };
  }

  // Summarize overflow chunks via LLM and return compact text
  // generateFn: async (messages) => string
  async summarizeOverflow(overflowChunks, generateFn) {
    if (!overflowChunks.length || !generateFn) return '';

    const summaries = [];
    for (let i = 0; i < overflowChunks.length; i += this.batchSize) {
      const batch = overflowChunks.slice(i, i + this.batchSize);
      const batchText = batch.map(c => c.text || '').join('\n---\n');

      try {
        const summary = await generateFn([
          {
            role: 'system',
            content: 'Summarize the following security/infrastructure text concisely. Preserve: control IDs (e.g. AC-1), resource types, security requirements, CVEs, misconfigurations. Be terse.',
          },
          { role: 'user', content: batchText.substring(0, 2000) },
        ], { maxTokens: this.summaryBudget, temperature: 0.1 });

        if (summary?.trim()) summaries.push(summary.trim());
      } catch { /* skip failed summaries */ }
    }

    return summaries.length ? '[ADDITIONAL CONTEXT (summarized)]\n' + summaries.join('\n\n') : '';
  }

  // Full pack: greedy primary context + optional summarized overflow
  // Returns context string ready to inject into prompt
  async pack(rankedChunks, generateFn = null, includeOverflow = true) {
    const { selected, overflow } = this.packGreedy(rankedChunks);

    const primary = selected.map((c, i) => {
      const src = c.source || c.filename || c.category || '';
      return `[${i + 1}${src ? ` — ${src}` : ''}]\n${c.text || ''}`;
    }).join('\n\n');

    if (!overflow.length || !includeOverflow || !generateFn) return primary;

    const overflowSummary = await this.summarizeOverflow(overflow, generateFn);
    return overflowSummary ? primary + '\n\n' + overflowSummary : primary;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. HYBRID SEARCH (BM25 + Dense + RRF)
// Pass bm25Chunks from existing BM25 index
// Pass vectorStore for dense similarity search
// Pass queryVec (pre-computed embedding) for vector search
// ═══════════════════════════════════════════════════════════════════════════

export function hybridSearch({ bm25Chunks, vectorStore, queryVec, topK = 8 }) {
  // Dense results from vector store
  const denseResults = queryVec?.length && vectorStore?.size > 0
    ? vectorStore.search(queryVec, topK * 2, 0.05)
    : [];

  if (!bm25Chunks?.length && !denseResults.length) return [];

  // If only one source available, return it directly
  if (!bm25Chunks?.length) return denseResults.slice(0, topK);
  if (!denseResults.length) return bm25Chunks.slice(0, topK);

  return reciprocalRankFusion(bm25Chunks, denseResults, [], 60).slice(0, topK);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. RAG PROMPT BUILDER
// Constructs structured prompts for the Threataform security assistant
// ═══════════════════════════════════════════════════════════════════════════

export function buildRAGPrompt({
  query,
  contextText,
  conversationHistory = [],
  modelName = '',
  environment = '',
  frameworks = [],
  systemExtra = '',
}) {
  const modelCtx = [
    modelName  && `Product: ${modelName}`,
    environment && `Environment: ${environment}`,
    frameworks?.length && `Compliance: ${frameworks.join(', ')}`,
  ].filter(Boolean).join('\n');

  const systemPrompt = [
    'You are Threataform Assistant, an expert in infrastructure security, threat modeling, and compliance.',
    'Answer ONLY from the provided context. Do not hallucinate. If context is insufficient, say so.',
    'Format responses with clear headers. Cite control IDs (e.g. AC-1, CC6.1) when present.',
    'Be precise, technical, and structured.',
    modelCtx && `\nArchitecture context:\n${modelCtx}`,
    systemExtra,
  ].filter(Boolean).join('\n');

  return [
    { role: 'system', content: systemPrompt },
    ...conversationHistory,
    {
      role: 'user',
      content: contextText
        ? `Context from uploaded documents:\n${contextText}\n\nQuestion: ${query}`
        : query,
    },
  ];
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. DOCUMENT CHUNKER — integrates with existing userDocs structure
// Takes userDocs array (from app state) and produces indexed chunks
// ═══════════════════════════════════════════════════════════════════════════

const _splitter = new RecursiveTextSplitter({ chunkSize: 600, chunkOverlap: 80 });

export function chunkUserDocs(userDocs) {
  const chunks = [];
  for (const doc of userDocs) {
    if (!doc.content?.trim()) continue;
    const docChunks = _splitter.splitDocument(doc.content, {
      source:   doc.name,
      filename: doc.name,
      category: doc.docCategory || 'general',
      docPath:  doc.path,
    });
    chunks.push(...docChunks);
  }
  return chunks;
}
