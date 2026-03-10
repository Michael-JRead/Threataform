/**
 * useVectorStore — Vector store instance management
 *
 * Manages:
 *   - vectorStoreRef  (primary dense store — cosine similarity)
 *   - colbertStoreRef (late-interaction ColBERT store — optional GPU path)
 *
 * rebuildVectorStore() and hybridSearch() are App-level callbacks
 * that depend on wllamaManager, intelligenceRef, and IDB helpers.
 * They are passed into the hook as optional callbacks for future
 * consolidation, but currently live in App to avoid TDZ issues.
 */
import { useRef } from 'react';
import { VectorStore } from '../lib/ThrataformRAG.js';
import { ColBERTVectorStore } from '../lib/rag/VectorStore.js';

export function useVectorStore() {
  const vectorStoreRef  = useRef(new VectorStore());
  const colbertStoreRef = useRef(new ColBERTVectorStore(1024));

  return { vectorStoreRef, colbertStoreRef };
}
