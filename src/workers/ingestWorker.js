/**
 * src/workers/ingestWorker.js
 * Web Worker for file ingestion + embedding.
 *
 * Runs file extraction and chunk embedding in a separate thread so the main
 * thread stays responsive during large batch ingestion.
 *
 * Message protocol (main → worker):
 *   { type: 'ingestFile', id, file: File, opts: {} }
 *   { type: 'ingestText', id, text: string, filename: string, opts: {} }
 *   { type: 'embedChunks', id, chunks: string[], chunkIds: string[] }
 *   { type: 'setModel',   model: ThreataformLM, tokenizer: BPETokenizer }
 *
 * Message protocol (worker → main):
 *   { type: 'ingestDone',   id, result: { text, chunks, metadata, entities } }
 *   { type: 'embedDone',    id, embeddings: { chunkId → Float32Array } }
 *   { type: 'multiEmbDone', id, embeddings: { chunkId → Float32Array[] } }
 *   { type: 'progress',     id, done, total }
 *   { type: 'error',        id, message }
 */

import { extractFile }        from '../lib/ingestion/FileRouter.js';
import { HierarchicalChunker } from '../lib/rag/Chunker.js';
import { tokenizer }           from '../lib/llm/Tokenizer.js';

// Model reference — set via 'setModel' message
let _model = null;

const chunker = new HierarchicalChunker({ minChunk: 100, maxChunk: 1000 });

self.onmessage = async ({ data }) => {
  const { type, id } = data;

  try {
    switch (type) {

      // Set the model for embedding (transfer object with weights via structured clone)
      // Note: in practice, the worker re-creates the model from serialized weights
      case 'setModel': {
        // Model is passed as { config, weights } because class instances
        // can't be structurally cloned. Re-create here.
        const { createModel } = await import('../lib/llm/Model.js');
        const weights = new Map(Object.entries(data.weights).map(([k, v]) => [k, v]));
        _model = createModel(data.config, weights);
        self.postMessage({ type: 'modelReady' });
        break;
      }

      case 'ingestFile': {
        const { file, opts = {} } = data;
        const result = await extractFile(file, { runNER: opts.runNER ?? true });

        // Chunk the extracted text
        const embedFn = _model
          ? async (txt) => {
              const ids = tokenizer.encode(txt.slice(0, 1000));
              return _model.embed(ids);
            }
          : null;

        const chunks = await chunker.chunk(result.text, embedFn);

        self.postMessage({ type: 'ingestDone', id, result: {
          text:     result.text,
          chunks,
          metadata: result.metadata,
          entities: result.entities,
          tables:   result.tables,
        }});
        break;
      }

      case 'ingestText': {
        const { text, filename = 'text', opts = {} } = data;
        const embedFn = _model
          ? async (txt) => {
              const ids = tokenizer.encode(txt.slice(0, 1000));
              return _model.embed(ids);
            }
          : null;

        const chunks = await chunker.chunk(text, embedFn);

        self.postMessage({ type: 'ingestDone', id, result: {
          text,
          chunks,
          metadata: { filename, type: 'text' },
          entities: [],
          tables:   [],
        }});
        break;
      }

      case 'embedChunks': {
        const { chunks, chunkIds } = data;
        if (!_model) {
          self.postMessage({ type: 'error', id, message: 'Model not set in ingestWorker' });
          return;
        }

        const embeddings = {};
        for (let i = 0; i < chunks.length; i++) {
          const ids = tokenizer.encode(chunks[i].slice(0, 2000));
          const vec = _model.embed(ids);
          embeddings[chunkIds[i]] = vec;

          if (i % 10 === 0) {
            self.postMessage({ type: 'progress', id, done: i + 1, total: chunks.length });
          }
        }

        // Collect transferable buffers
        const transferList = Object.values(embeddings).map(v => v.buffer);
        self.postMessage({ type: 'embedDone', id, embeddings }, transferList);
        break;
      }

      case 'embedMultiChunks': {
        const { chunks, chunkIds } = data;
        if (!_model) {
          self.postMessage({ type: 'error', id, message: 'Model not set in ingestWorker' });
          return;
        }

        const multiEmbeddings = {};
        for (let i = 0; i < chunks.length; i++) {
          const ids  = tokenizer.encode(chunks[i].slice(0, 2000));
          const vecs = _model.embedMulti(ids);
          multiEmbeddings[chunkIds[i]] = vecs;

          if (i % 5 === 0) {
            self.postMessage({ type: 'progress', id, done: i + 1, total: chunks.length });
          }
        }

        // Transfer all Float32Array buffers
        const transferList = Object.values(multiEmbeddings).flatMap(vs => vs.map(v => v.buffer));
        self.postMessage({ type: 'multiEmbDone', id, multiEmbeddings }, transferList);
        break;
      }

      default:
        self.postMessage({ type: 'error', id, message: `Unknown type: ${type}` });
    }
  } catch (err) {
    self.postMessage({ type: 'error', id, message: err.message ?? String(err) });
  }
};

self.postMessage({ type: 'workerReady' });
