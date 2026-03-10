/**
 * useUserDocs — per-model user document management
 *
 * Manages:
 *   - userDocs array (persisted to localStorage per model)
 *   - saveUserDocs(docsOrFn)
 *   - removeUserDoc(pathOrName) — also purges cached IDB vectors (H1)
 *
 * vdbModelIdRef is created internally and kept in sync with currentModel.
 */
import { useState, useCallback, useRef, useEffect } from 'react';

export function useUserDocs({
  currentModel,
  updateModelMeta,
  intelligenceRef,
  chunkHashFn,
  vdbDeleteKeysFn,
}) {
  const [userDocs, setUserDocsState] = useState(() => {
    try {
      const s = localStorage.getItem('tf-intel-user-docs');
      return s ? JSON.parse(s) : [];
    } catch { return []; }
  });

  // H1: tracks current model ID for IDB key construction
  const vdbModelIdRef = useRef(currentModel?.id || 'global');
  useEffect(() => {
    vdbModelIdRef.current = currentModel?.id || 'global';
  }, [currentModel]);

  const saveUserDocs = useCallback((docsOrFn) => {
    setUserDocsState(prev => {
      const next = typeof docsOrFn === 'function' ? docsOrFn(prev) : docsOrFn;
      const key = currentModel
        ? `tf-model-${currentModel.id}-docs`
        : 'tf-intel-user-docs';
      try { localStorage.setItem(key, JSON.stringify(next)); } catch {}
      if (currentModel) updateModelMeta?.({ docCount: next.length });
      return next;
    });
  }, [currentModel, updateModelMeta]);

  const removeUserDoc = useCallback((pathOrName) => {
    // H1: purge cached IDB vectors before removing from state
    const intel = intelligenceRef?.current;
    if (intel?.chunks?.length && chunkHashFn && vdbDeleteKeysFn) {
      const modelId = vdbModelIdRef.current;
      const docChunks = intel.chunks.filter(c =>
        c.source === pathOrName ||
        c.source === pathOrName.replace(/^.*[\\/]/, '')
      );
      if (docChunks.length) {
        const keys = docChunks.map(c => `vec_${modelId}_${chunkHashFn(c.text)}`);
        vdbDeleteKeysFn(keys);
      }
    }
    saveUserDocs(prev => prev.filter(d => (d.path || d.name) !== pathOrName));
  }, [saveUserDocs, intelligenceRef, chunkHashFn, vdbDeleteKeysFn]);

  return { userDocs, setUserDocsState, saveUserDocs, removeUserDoc, vdbModelIdRef };
}
