/**
 * src/workers/engineWorker.js
 * Web Worker for ThreataformLM inference + LoRA training.
 *
 * Runs in a dedicated Worker thread so inference never blocks the main thread.
 *
 * Message protocol (main → worker):
 *   { type: 'load',     url: string, onProgress: false }
 *   { type: 'generate', id: string, messages: [], opts: {} }
 *   { type: 'embed',    id: string, text: string }
 *   { type: 'embedMulti', id: string, text: string }
 *   { type: 'train',    id: string, chunks: Int32Array[], opts: {} }
 *   { type: 'loraLoad', buf: ArrayBuffer }
 *   { type: 'loraSave' }
 *   { type: 'cancel',   id: string }
 *
 * Message protocol (worker → main):
 *   { type: 'ready' }
 *   { type: 'token',     id, token: number }
 *   { type: 'done',      id }
 *   { type: 'embedding', id, vec: Float32Array }
 *   { type: 'progress',  id, step, total, loss }
 *   { type: 'loraSaved', buf: ArrayBuffer }
 *   { type: 'error',     id, message }
 *   { type: 'loadProgress', loaded, total }
 */

import { loadModel }        from '../lib/llm/WeightsLoader.js';
import { createModel }      from '../lib/llm/Model.js';
import { tokenizer }        from '../lib/llm/Tokenizer.js';
import { LoRAAdapter }      from '../lib/llm/LoRA.js';

let model  = null;
let lora   = null;
let _cancel = new Set(); // active generation IDs that should be cancelled

// ── Message handler ───────────────────────────────────────────────────────────

self.onmessage = async ({ data }) => {
  const { type, id } = data;

  try {
    switch (type) {

      case 'load': {
        const { url, vocabData } = data;
        const { config, weights, vocab } = await loadModel(url, (loaded, total) => {
          self.postMessage({ type: 'loadProgress', loaded, total });
        });

        model = createModel(config, weights);
        lora  = new LoRAAdapter(model.cfg, { r: 8, alpha: 16 });

        // Load embedded vocab if present
        if (vocab) tokenizer.loadVocab(vocab);
        if (vocabData) tokenizer.loadVocab(vocabData);

        self.postMessage({ type: 'ready', config });
        break;
      }

      case 'generate': {
        if (!model) { self.postMessage({ type: 'error', id, message: 'Model not loaded' }); return; }

        const { messages, opts = {} } = data;
        const promptIds = tokenizer.encodeChat(messages);

        _cancel.delete(id); // reset cancel flag

        for await (const tok of model.generate(promptIds, {
          maxNew:  opts.maxNew  ?? 512,
          temp:    opts.temp    ?? 0.7,
          topP:    opts.topP    ?? 0.9,
          topK:    opts.topK    ?? 0,
          stopIds: opts.stopIds ?? [],
        })) {
          if (_cancel.has(id)) break;
          self.postMessage({ type: 'token', id, token: tok });
        }
        self.postMessage({ type: 'done', id });
        break;
      }

      case 'embed': {
        if (!model) { self.postMessage({ type: 'error', id, message: 'Model not loaded' }); return; }
        const { text } = data;
        const ids = tokenizer.encode(text.slice(0, 2000));
        const vec = model.embed(ids);
        self.postMessage({ type: 'embedding', id, vec }, [vec.buffer]);
        break;
      }

      case 'embedMulti': {
        if (!model) { self.postMessage({ type: 'error', id, message: 'Model not loaded' }); return; }
        const { text } = data;
        const ids  = tokenizer.encode(text.slice(0, 2000));
        const vecs = model.embedMulti(ids);
        // Transfer all buffers
        const bufs = vecs.map(v => v.buffer);
        self.postMessage({ type: 'multiEmbedding', id, vecs }, bufs);
        break;
      }

      case 'train': {
        if (!model) { self.postMessage({ type: 'error', id, message: 'Model not loaded' }); return; }
        const { chunks, opts = {} } = data;

        await lora.train(model, chunks, {
          lr:        opts.lr        ?? 3e-4,
          steps:     opts.steps     ?? 500,
          batchSize: opts.batchSize ?? 4,
          onProgress: (step, total, loss) => {
            self.postMessage({ type: 'progress', id, step, total, loss });
          },
        });

        self.postMessage({ type: 'done', id });
        break;
      }

      case 'loraLoad': {
        if (!lora) { self.postMessage({ type: 'error', id, message: 'LoRA not initialised' }); return; }
        lora.load(data.buf);
        self.postMessage({ type: 'done', id });
        break;
      }

      case 'loraSave': {
        if (!lora) { self.postMessage({ type: 'error', id, message: 'LoRA not initialised' }); return; }
        const buf = lora.save();
        self.postMessage({ type: 'loraSaved', id, buf }, [buf]);
        break;
      }

      case 'cancel': {
        _cancel.add(id);
        break;
      }

      default:
        self.postMessage({ type: 'error', id, message: `Unknown message type: ${type}` });
    }
  } catch (err) {
    self.postMessage({ type: 'error', id, message: err.message ?? String(err) });
  }
};

// Signal ready immediately (model load is separate)
self.postMessage({ type: 'workerReady' });
