/**
 * useModelManager — Threat Model CRUD + metadata persistence
 *
 * Manages:
 *   - threatModels list (localStorage "tf-threat-models")
 *   - currentModel (active model object)
 *   - modelDetails (environment, scope, frameworks, etc.)
 *
 * createModel / openModel return the new/selected model so the caller
 * can perform app-level side effects (clearing files, resetting parse state).
 */
import { useState, useCallback } from 'react';

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
    setModelDetails(() => {
      try {
        return JSON.parse(localStorage.getItem(`tf-model-${model.id}-details`) || '{}');
      } catch {
        return EMPTY_DETAILS;
      }
    });
    return model; // caller handles file/doc restoration
  }, []);

  const deleteModel = useCallback((id) => {
    saveModels(threatModels.filter(m => m.id !== id));
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
      try {
        localStorage.setItem(`tf-model-${currentModel.id}-details`, JSON.stringify(details));
      } catch {}
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
