/**
 * useUserDocs — per-model user document management
 *
 * Manages:
 *   - userDocs array (persisted to IDB 'docs' store + OPFS for extracted text)
 *   - saveUserDocs(docsOrFn)
 *   - removeUserDoc(pathOrName) — also purges cached IDB vectors (H1)
 *
 * Storage:
 *   - Doc metadata → IndexedDB 'docs' store (no localStorage quota issues)
 *   - Extracted text → OPFS when available, inline IDB 'docs'.content as fallback
 *   - In-memory: full content array kept in React state for the active session
 */
import { useState, useCallback, useRef, useEffect } from 'react';
import {
  docStorePutAll, docStoreGetAll, docStoreDelete,
  opfsWriteText, opfsReadText, opfsDeleteText,
  simpleHash, vecDeleteKeys,
} from '../lib/storage/DocStore.js';

export function useUserDocs({
  currentModel,
  updateModelMeta,
  intelligenceRef,
  chunkHashFn,
  vdbDeleteKeysFn,
}) {
  const [userDocs, setUserDocsState] = useState([]);

  // H1: tracks current model ID for IDB key construction
  const vdbModelIdRef = useRef(currentModel?.id || 'global');
  useEffect(() => {
    vdbModelIdRef.current = currentModel?.id || 'global';
  }, [currentModel]);

  // Load docs from IDB + OPFS when model changes
  useEffect(() => {
    const modelId = currentModel?.id;
    if (!modelId) {
      // No model — load from legacy localStorage fallback
      try {
        const s = localStorage.getItem('tf-intel-user-docs');
        setUserDocsState(s ? JSON.parse(s) : []);
      } catch { setUserDocsState([]); }
      return;
    }

    let cancelled = false;
    docStoreGetAll(modelId).then(async (metas) => {
      if (cancelled) return;
      if (!metas.length) {
        // Migration path: first open after upgrade — check old localStorage key
        try {
          const old = localStorage.getItem(`tf-model-${modelId}-docs`);
          if (old) {
            const parsed = JSON.parse(old);
            if (parsed.length) {
              // Persist to IDB and remove from localStorage
              await docStorePutAll(modelId, parsed.map(d => ({
                ...d,
                contentSnippet: (d.content || '').slice(0, 200),
              })));
              // Cache text in OPFS for each doc
              await Promise.all(parsed.map(async d => {
                if (d.content) {
                  const ph = simpleHash(d.path || d.name);
                  const wrote = await opfsWriteText(modelId, ph, d.content);
                  if (wrote) {
                    // Update IDB record to reflect OPFS path
                    await docStorePutAll(modelId, [{ ...d, content: undefined, contentSnippet: d.content.slice(0, 200), opfsPath: `threataform/${modelId}/${ph}.txt` }]);
                  }
                }
              }));
              localStorage.removeItem(`tf-model-${modelId}-docs`);
              if (!cancelled) setUserDocsState(parsed);
              return;
            }
          }
        } catch {}
        if (!cancelled) setUserDocsState([]);
        return;
      }

      // Restore content from OPFS or inline IDB field
      const withContent = await Promise.all(metas.map(async (meta) => {
        if (cancelled) return null;
        const ph = simpleHash(meta.path || meta.name);
        let content = await opfsReadText(modelId, ph);
        if (content === null) content = meta.content || meta.contentSnippet || '';
        return { ...meta, content };
      }));
      if (!cancelled) setUserDocsState(withContent.filter(Boolean));
    }).catch(() => { if (!cancelled) setUserDocsState([]); });

    return () => { cancelled = true; };
  }, [currentModel?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const saveUserDocs = useCallback((docsOrFn) => {
    setUserDocsState(prev => {
      const next = typeof docsOrFn === 'function' ? docsOrFn(prev) : docsOrFn;
      const modelId = currentModel?.id;

      if (modelId) {
        // Persist metadata to IDB; write text to OPFS asynchronously (fire-and-forget)
        const records = next.map(d => ({
          modelId,
          path: d.path || d.name,
          name: d.name,
          ext: d.ext,
          size: d.size,
          docCategory: d.docCategory,
          extractedAt: d.extractedAt || Date.now(),
          contentSnippet: (d.content || '').slice(0, 200),
          chunkCount: d.chunkCount || 0,
          _synthetic: d._synthetic || false,
        }));
        docStorePutAll(modelId, records);

        // Write full text to OPFS for each doc that has content
        next.forEach(async d => {
          if (d.content && !d._synthetic) {
            const ph = simpleHash(d.path || d.name);
            await opfsWriteText(modelId, ph, d.content);
          }
        });
      } else {
        // No model — fall back to localStorage (global docs, small set)
        try { localStorage.setItem('tf-intel-user-docs', JSON.stringify(next)); } catch {}
      }

      if (currentModel) updateModelMeta?.({ docCount: next.length });
      return next;
    });
  }, [currentModel, updateModelMeta]);

  const removeUserDoc = useCallback((pathOrName) => {
    const modelId = vdbModelIdRef.current;

    // H1: purge cached IDB vectors before removing from state
    const intel = intelligenceRef?.current;
    if (intel?.chunks?.length && chunkHashFn && vdbDeleteKeysFn) {
      const docChunks = intel.chunks.filter(c =>
        c.source === pathOrName ||
        c.source === pathOrName.replace(/^.*[\\/]/, '')
      );
      if (docChunks.length) {
        const keys = docChunks.map(c => `vec_${modelId}_${chunkHashFn(c.text)}`);
        vdbDeleteKeysFn(keys);
      }
    }

    // Remove from IDB docs store and OPFS
    if (modelId && modelId !== 'global') {
      docStoreDelete(modelId, pathOrName);
      opfsDeleteText(modelId, simpleHash(pathOrName));
    }

    saveUserDocs(prev => prev.filter(d => (d.path || d.name) !== pathOrName));
  }, [saveUserDocs, intelligenceRef, chunkHashFn, vdbDeleteKeysFn]);

  return { userDocs, setUserDocsState, saveUserDocs, removeUserDoc, vdbModelIdRef };
}
