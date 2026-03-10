/**
 * useModelManager — Threat Model CRUD + metadata persistence
 *
 * Manages:
 *   - threatModels list (localStorage "tf-threat-models" — tiny, always safe)
 *   - currentModel (active model object)
 *   - modelDetails (environment, scope, frameworks, etc.) → IDB model-meta store
 *
 * createModel / openModel return the new/selected model so the caller
 * can perform app-level side effects (clearing files, resetting parse state).
 *
 * Storage:
 *   - tf-threat-models → localStorage (model list metadata only, ~1KB max)
 *   - tf-model-${id}-details → IDB model-meta (replaces localStorage)
 *   - Docs, TF files, arch-analysis, diagram-image → handled by DocStore / main app
 */
import { useState, useCallback, useEffect } from 'react';
import {
  modelMetaPut, modelMetaGet, modelMetaDeleteAll,
  docStoreDeleteAll, tfFilesDeleteAll, opfsDeleteDir,
} from '../lib/storage/DocStore.js';

const EMPTY_DETAILS = {
  environment: '', scope: '', dataClassification: [], frameworks: [],
  owner: '', description: '', threatFrameworks: [], keyFeatures: '',
};

export function useModelManager() {
  const [threatModels, setThreatModels] = useState(() => {
    try { return JSON.parse(localStorage.getItem('tf-threat-models') || '[]'); }
    catch { return []; }
  });

  const [currentModel, setCurrentModel] = useState(null);

  const [modelDetails, setModelDetails] = useState(EMPTY_DETAILS);

  // ── Persistence ──────────────────────────────────────────────────────────
  const saveModels = useCallback((models) => {
    setThreatModels(models);
    try { localStorage.setItem('tf-threat-models', JSON.stringify(models)); } catch {}
  }, []);

  // ── CRUD ─────────────────────────────────────────────────────────────────
  const createModel = useCallback((name) => {
    const id = Date.now().toString();
    const model = {
      id, name,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      environment: '', tfFileCount: 0, docCount: 0, grade: null,
    };
    saveModels([model, ...threatModels]);
    setCurrentModel(model);
    setModelDetails(EMPTY_DETAILS);
    return model; // caller handles app-mode + state resets
  }, [threatModels, saveModels]);

  const openModel = useCallback((model) => {
    setCurrentModel(model);
    // Load model details from IDB; fall back to localStorage for migration
    modelMetaGet(model.id, 'details').then(details => {
      if (details) {
        setModelDetails(details);
      } else {
        // Migration: check old localStorage key
        try {
          const old = localStorage.getItem(`tf-model-${model.id}-details`);
          const parsed = old ? JSON.parse(old) : null;
          if (parsed) {
            setModelDetails(parsed);
            // Migrate to IDB and remove from localStorage
            modelMetaPut(model.id, 'details', parsed);
            localStorage.removeItem(`tf-model-${model.id}-details`);
          } else {
            setModelDetails(EMPTY_DETAILS);
          }
        } catch {
          setModelDetails(EMPTY_DETAILS);
        }
      }
    }).catch(() => setModelDetails(EMPTY_DETAILS));
    return model; // caller handles file/doc restoration
  }, []);

  const deleteModel = useCallback((id) => {
    saveModels(threatModels.filter(m => m.id !== id));

    // Remove from IDB stores (async, fire-and-forget)
    docStoreDeleteAll(id);
    tfFilesDeleteAll(id);
    modelMetaDeleteAll(id);
    opfsDeleteDir(id);

    // Also clean up any lingering localStorage keys from before migration
    ['docs', 'arch-analysis', 'details', 'diagram-image', 'files'].forEach(k => {
      try { localStorage.removeItem(`tf-model-${id}-${k}`); } catch {}
    });
  }, [threatModels, saveModels]);

  const updateModelMeta = useCallback((patch) => {
    if (!currentModel) return;
    const ts = new Date().toISOString();
    setCurrentModel(prev => ({ ...prev, ...patch, updatedAt: ts }));
    setThreatModels(prev => {
      const updated = prev.map(m =>
        m.id === currentModel.id ? { ...m, ...patch, updatedAt: ts } : m
      );
      try { localStorage.setItem('tf-threat-models', JSON.stringify(updated)); } catch {}
      return updated;
    });
  }, [currentModel]);

  const saveModelDetails = useCallback((details) => {
    setModelDetails(details);
    if (currentModel) {
      modelMetaPut(currentModel.id, 'details', details); // async, fire-and-forget
    }
  }, [currentModel]);

  return {
    threatModels,
    currentModel, setCurrentModel,
    modelDetails, setModelDetails,
    createModel,
    openModel,
    deleteModel,
    updateModelMeta,
    saveModelDetails,
  };
}
