/**
 * Threataform Embed Worker — Ollama backend
 * Uses Ollama /api/embed for dense vector embeddings.
 * Default model: nomic-embed-text (270MB, 768-dim, L2-normalized)
 *
 * Requires: ollama pull nomic-embed-text
 * Ollama returns L2-normalized vectors — dot product == cosine similarity.
 */

const OLLAMA_BASE = 'http://localhost:11434';
let embedModel = 'nomic-embed-text';

// Fast dot product (Ollama vectors are L2-normalized → dot = cosine similarity)
function dotProduct(a, b) {
  let d = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) d += a[i] * b[i];
  return d;
}

self.onmessage = async ({ data }) => {
  const { type, id } = data;

  if (type === 'init') {
    embedModel = data.embedModel || 'nomic-embed-text';
    try {
      // Warmup: verify the embed model is available
      const res = await fetch(`${OLLAMA_BASE}/api/embed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: embedModel, input: 'warmup' }),
      });
      if (!res.ok) {
        throw new Error(
          `Embed model "${embedModel}" not available (HTTP ${res.status}). ` +
          `Run: ollama pull ${embedModel}`
        );
      }
      self.postMessage({ type: 'ready', modelId: embedModel });
    } catch (err) {
      const msg = err.message.includes('fetch')
        ? `Cannot reach Ollama. Run: ollama pull ${embedModel}`
        : err.message;
      self.postMessage({ type: 'error', error: msg });
    }
  }

  else if (type === 'embed') {
    // Batch embed: { texts: string[], batchId: string }
    try {
      const texts = (data.texts || []).map(t => t?.trim() || '').filter(Boolean);
      if (!texts.length) {
        self.postMessage({ type: 'embeddings', id, batchId: data.batchId, vectors: [] });
        return;
      }
      // Ollama /api/embed supports string arrays natively
      const res = await fetch(`${OLLAMA_BASE}/api/embed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: embedModel, input: texts }),
      });
      if (!res.ok) throw new Error(`Embed batch error ${res.status}`);
      const { embeddings = [] } = await res.json();
      self.postMessage({ type: 'embeddings', id, batchId: data.batchId, vectors: embeddings });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  }

  else if (type === 'embed_query') {
    try {
      const res = await fetch(`${OLLAMA_BASE}/api/embed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: embedModel, input: data.query }),
      });
      const { embeddings = [] } = await res.json();
      self.postMessage({ type: 'query_embedding', id, vector: embeddings[0] || [] });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  }

  else if (type === 'similarity_search') {
    try {
      const res = await fetch(`${OLLAMA_BASE}/api/embed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: embedModel, input: data.query }),
      });
      const { embeddings = [] } = await res.json();
      const qVec = embeddings[0];
      if (!qVec?.length) {
        self.postMessage({ type: 'search_results', id, results: [] });
        return;
      }
      const scored = (data.store || [])
        .map((item, idx) => ({
          idx,
          sim: item.vector?.length === qVec.length ? dotProduct(qVec, item.vector) : 0,
        }))
        .filter(r => r.sim >= (data.threshold ?? 0.2))
        .sort((a, b) => b.sim - a.sim)
        .slice(0, data.topK || 8);
      self.postMessage({ type: 'search_results', id, results: scored });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  }
};
