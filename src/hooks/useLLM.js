/**
 * useLLM — LLM status state management
 *
 * Encapsulates all wllama/embed state declarations.
 * The loadWllama callback stays in App since it depends on rebuildVectorStore.
 * Restores last-used model name from localStorage (H3).
 */
import { useState } from 'react';

export function useLLM() {
  const [llmStatus,      setLlmStatus]      = useState('idle');  // idle|loading|ready|error
  const [llmProgress,    setLlmProgress]    = useState(0);
  const [llmStatusText,  setLlmStatusText]  = useState('');
  const [embedStatus,    setEmbedStatus]    = useState('idle');  // idle|ready
  const [embedProgress,  setEmbedProgress]  = useState(null);   // null | {done, total}
  const [selectedLlmModel, setSelectedLlmModel] = useState('');
  const [wllamaModelSize,  setWllamaModelSize]  = useState(0);

  // H3: restore last-used model name as display hint
  const [wllamaModelName, setWllamaModelName] = useState(() => {
    try { return localStorage.getItem('tf-last-model-name') || ''; } catch { return ''; }
  });

  return {
    llmStatus,      setLlmStatus,
    llmProgress,    setLlmProgress,
    llmStatusText,  setLlmStatusText,
    embedStatus,    setEmbedStatus,
    embedProgress,  setEmbedProgress,
    selectedLlmModel, setSelectedLlmModel,
    wllamaModelName,  setWllamaModelName,
    wllamaModelSize,  setWllamaModelSize,
  };
}
