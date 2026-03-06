/**
 * Threataform LLM Worker — Ollama backend
 * Connects to local Ollama at http://localhost:11434
 * No internet required. No WebGPU. No CORS issues.
 *
 * Install Ollama: https://ollama.com
 * Pull a model:   ollama pull llama3.2
 */

const OLLAMA_BASE = 'http://localhost:11434';
let currentModel = null;

self.onmessage = async ({ data }) => {
  const { type, id } = data;

  if (type === 'init') {
    const desired = data.modelId || 'llama3.2';
    try {
      const res = await fetch(`${OLLAMA_BASE}/api/tags`);
      if (!res.ok) throw new Error(`Ollama not reachable (HTTP ${res.status}). Make sure Ollama is running.`);
      const { models = [] } = await res.json();
      currentModel = desired;
      self.postMessage({ type: 'ready', modelId: currentModel, models: models.map(m => m.name) });
    } catch (err) {
      // Friendly error message for enterprise users
      const msg = err.message.includes('fetch')
        ? 'Cannot connect to Ollama at localhost:11434. Start Ollama and run: ollama pull llama3.2'
        : err.message;
      self.postMessage({ type: 'error', id, error: msg });
    }
  }

  else if (type === 'generate') {
    const model = data.modelId || currentModel;
    if (!model) {
      self.postMessage({ type: 'error', id, error: 'No model selected. Is Ollama running?' });
      return;
    }
    try {
      const res = await fetch(`${OLLAMA_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages: data.messages,
          stream: true,
          options: {
            temperature: data.temperature ?? 0.2,
            num_predict: data.maxTokens ?? 2048,
          },
        }),
      });
      if (!res.ok) {
        throw new Error(`Ollama error ${res.status}: ${await res.text()}`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = '';
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete last line in buffer
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const obj = JSON.parse(line);
            const token = obj.message?.content;
            if (token) {
              fullText += token;
              self.postMessage({ type: 'token', id, token });
            }
            if (obj.done) self.postMessage({ type: 'done', id, fullText });
          } catch { /* skip malformed line */ }
        }
      }
      // Flush remaining buffer
      if (buffer.trim()) {
        try {
          const obj = JSON.parse(buffer);
          const token = obj.message?.content;
          if (token) self.postMessage({ type: 'token', id, token });
          if (obj.done) self.postMessage({ type: 'done', id, fullText });
        } catch { }
      }
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  }

  else if (type === 'reset') {
    // Ollama is stateless per-request — nothing to reset
    self.postMessage({ type: 'reset_done', id });
  }

  else if (type === 'abort') {
    // Future: use AbortController on the fetch
    self.postMessage({ type: 'aborted', id });
  }
};
