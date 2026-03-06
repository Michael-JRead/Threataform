/**
 * src/lib/llm/WeightsLoader.js
 * ThreataformLM — .tnlm Binary Parser + IndexedDB Cache
 *
 * .tnlm format (produced by scripts/quantize.py + scripts/export.py):
 *
 *   [4B  magic    "TNLM"  (0x544E4C4D)]
 *   [4B  version  uint32  (= 2)       ]
 *   [4B  cfg_len  uint32              ]
 *   [cfg_len B  config JSON (UTF-8)   ]
 *   For each tensor:
 *     [4B  name_len  uint32                 ]
 *     [name_len B  name UTF-8               ]
 *     [4B  dtype    uint32  (0=f32, 1=q4, 2=q8, 3=f16)]
 *     [4B  ndim     uint32                  ]
 *     [ndim × 4B  dims uint32[]             ]
 *     [data bytes                           ]
 *
 * IndexedDB schema:
 *   DB:    'threataform-model'
 *   Store: 'weights'   (key = model hash string)
 *   Each record: { hash, config, tensors: { name → ArrayBuffer } }
 *
 * Usage:
 *   import { loadModel } from './WeightsLoader.js';
 *   const { config, weights, tokenizer } = await loadModel('/model.tnlm', onProgress);
 *   // weights: Map<string, Float32Array|Uint8Array>
 *   // tokenizer is loaded if the .tnlm bundles a vocab section
 */

const MAGIC   = 0x544E4C4D; // "TNLM"
const VERSION = 2;

const DTYPE = Object.freeze({ F32: 0, Q4: 1, Q8: 2, F16: 3 });
const DTYPE_STR = ['f32', 'q4', 'q8', 'f16'];

// Bytes per element for each dtype (for raw data allocation)
const DTYPE_BYTES = [4, 0, 0, 2]; // Q4/Q8 have variable packing (handled separately)

// Q4: 18 bytes per 32 weights  (16-nibble data + 2-byte f16 scale)
const Q4_BLOCK = 32;
const Q4_BYTES = 18;

// Q8: 34 bytes per 32 weights  (32-byte int8 data + 2-byte f16 scale)
const Q8_BLOCK = 32;
const Q8_BYTES = 34;

// IDB config
const IDB_NAME    = 'threataform-model';
const IDB_VERSION = 1;
const IDB_STORE   = 'weights';

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Load a ThreataformLM model, using the IndexedDB cache when possible.
 *
 * @param {string|ArrayBuffer} src
 *   URL string (fetched with progress tracking) OR a pre-loaded ArrayBuffer.
 * @param {function} [onProgress]
 *   Called with (bytesLoaded, totalBytes) during download.
 * @returns {Promise<{ config: object, weights: Map<string, TypedArray>, vocab?: object }>}
 */
export async function loadModel(src, onProgress = null) {
  let buf;
  let hash;

  if (typeof src === 'string') {
    // Try cache first
    hash = await _urlHash(src);
    const cached = await _idbGet(hash);
    if (cached) {
      console.log('[WeightsLoader] Loaded from IndexedDB cache');
      return _buildResult(cached.config, cached.tensors, cached.vocab);
    }

    // Fetch with progress
    buf = await _fetchWithProgress(src, onProgress);
  } else {
    buf = src;
    hash = await _bufHash(buf);
    const cached = await _idbGet(hash);
    if (cached) {
      return _buildResult(cached.config, cached.tensors, cached.vocab);
    }
  }

  // Parse the binary
  const { config, tensors, vocab } = _parseTnlm(buf);

  // Cache to IDB
  _idbPut(hash, config, tensors, vocab).catch(e =>
    console.warn('[WeightsLoader] IDB cache write failed:', e)
  );

  return _buildResult(config, tensors, vocab);
}

/**
 * Check if a model is already cached in IndexedDB.
 * @param {string} url
 * @returns {Promise<boolean>}
 */
export async function isModelCached(url) {
  const hash = await _urlHash(url);
  return (await _idbGet(hash)) !== null;
}

/**
 * Clear the model cache (all cached models).
 * @returns {Promise<void>}
 */
export async function clearCache() {
  const db = await _openIDB();
  return new Promise((res, rej) => {
    const tx  = db.transaction(IDB_STORE, 'readwrite');
    const req = tx.objectStore(IDB_STORE).clear();
    req.onsuccess = () => res();
    req.onerror   = () => rej(req.error);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  .tnlm parser
// ─────────────────────────────────────────────────────────────────────────────

function _parseTnlm(buf) {
  const view = new DataView(buf);
  let off = 0;

  // Magic
  const magic = view.getUint32(off, false); off += 4;
  if (magic !== MAGIC) {
    throw new Error(`[WeightsLoader] Bad magic: expected 0x${MAGIC.toString(16)}, got 0x${magic.toString(16)}`);
  }

  // Version
  const ver = view.getUint32(off, false); off += 4;
  if (ver !== VERSION) {
    throw new Error(`[WeightsLoader] Unsupported .tnlm version ${ver} (expected ${VERSION})`);
  }

  // Config JSON
  const cfgLen  = view.getUint32(off, false); off += 4;
  const cfgJson = new TextDecoder().decode(new Uint8Array(buf, off, cfgLen));
  const config  = JSON.parse(cfgJson);
  off += cfgLen;

  // Tensors
  const tensors = {};
  let vocab = null;

  while (off < buf.byteLength) {
    // Name
    const nameLen = view.getUint32(off, false); off += 4;
    const name    = new TextDecoder().decode(new Uint8Array(buf, off, nameLen));
    off += nameLen;

    // Dtype
    const dtype = view.getUint32(off, false); off += 4;

    // Shape
    const ndim = view.getUint32(off, false); off += 4;
    const dims = [];
    let nelems = 1;
    for (let i = 0; i < ndim; i++) {
      const d = view.getUint32(off, false); off += 4;
      dims.push(d);
      nelems *= d;
    }

    // Data
    let data;
    const dataBytes = _tensorBytes(dtype, nelems);

    if (name === '__vocab__') {
      // Embedded vocabulary section (JSON blob stored as f32 shape=[1])
      const jsonBytes = view.getUint32(off, false); off += 4;
      const jsonStr   = new TextDecoder().decode(new Uint8Array(buf, off, jsonBytes));
      vocab = JSON.parse(jsonStr);
      off += jsonBytes;
      continue;
    }

    data = buf.slice(off, off + dataBytes);
    off += dataBytes;

    tensors[name] = { dtype: DTYPE_STR[dtype], dims, data };

    // Store dtype tag alongside the tensor for Model.js dispatch
    // (separate key '<name>__dtype')
    tensors[name + '__dtype'] = { dtype: 'tag', data: DTYPE_STR[dtype] };
  }

  return { config, tensors, vocab };
}

/** Compute raw byte length for a tensor given dtype and element count. */
function _tensorBytes(dtype, nelems) {
  switch (dtype) {
    case DTYPE.F32: return nelems * 4;
    case DTYPE.F16: return nelems * 2;
    case DTYPE.Q4:  return Math.ceil(nelems / Q4_BLOCK) * Q4_BYTES;
    case DTYPE.Q8:  return Math.ceil(nelems / Q8_BLOCK) * Q8_BYTES;
    default: throw new Error(`Unknown dtype: ${dtype}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Build result: convert raw ArrayBuffers → TypedArrays
// ─────────────────────────────────────────────────────────────────────────────

function _buildResult(config, rawTensors, vocab) {
  const weights = new Map();

  for (const [name, entry] of Object.entries(rawTensors)) {
    if (name.endsWith('__dtype')) {
      // Store string tag directly
      weights.set(name, entry.data ?? entry);
      continue;
    }

    const { dtype, data } = entry;
    let buf = data instanceof ArrayBuffer ? data : data.buffer;

    if (dtype === 'f32') {
      weights.set(name, new Float32Array(buf));
    } else if (dtype === 'f16') {
      // Dequantise f16 → f32 (Model.js works in f32)
      weights.set(name, _f16ToF32Array(new Uint16Array(buf)));
    } else {
      // Q4 / Q8: keep raw Uint8Array for quantised matmul in Ops.js
      weights.set(name, new Uint8Array(buf));
      weights.set(name + '__dtype', dtype);
    }
  }

  return { config, weights, vocab };
}

/** Dequantise a Float16 array to Float32. */
function _f16ToF32Array(u16) {
  const out = new Float32Array(u16.length);
  for (let i = 0; i < u16.length; i++) {
    out[i] = _f16(u16[i]);
  }
  return out;
}

function _f16(h) {
  const s  = (h & 0x8000) ? -1 : 1;
  const e  = (h >>> 10) & 0x1F;
  const m  =  h         & 0x3FF;
  if (e === 0)  return s * Math.pow(2, -14) * (m / 1024);
  if (e === 31) return m ? NaN : s * Infinity;
  return s * Math.pow(2, e - 15) * (1 + m / 1024);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fetch with progress
// ─────────────────────────────────────────────────────────────────────────────

async function _fetchWithProgress(url, onProgress) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`[WeightsLoader] Fetch failed: ${resp.status} ${url}`);

  const total  = parseInt(resp.headers.get('content-length') ?? '0', 10);
  const reader = resp.body.getReader();
  const chunks = [];
  let loaded   = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.byteLength;
    if (onProgress) onProgress(loaded, total);
  }

  // Concatenate chunks into one ArrayBuffer
  const full = new Uint8Array(loaded);
  let pos    = 0;
  for (const c of chunks) { full.set(c, pos); pos += c.byteLength; }
  return full.buffer;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hashing (for IDB cache key)
// ─────────────────────────────────────────────────────────────────────────────

async function _urlHash(url) {
  const enc  = new TextEncoder().encode(url);
  const dig  = await crypto.subtle.digest('SHA-256', enc);
  return _hex(dig);
}

async function _bufHash(buf) {
  // Hash first 64KB + last 64KB + total length to avoid reading the whole buffer
  const chunk = 64 * 1024;
  const a = buf.slice(0, chunk);
  const b = buf.slice(Math.max(0, buf.byteLength - chunk));
  const len = new Uint32Array([buf.byteLength]);
  const combined = _concat([new Uint8Array(a), new Uint8Array(b), new Uint8Array(len.buffer)]);
  const dig = await crypto.subtle.digest('SHA-256', combined);
  return _hex(dig);
}

function _concat(arrays) {
  const total = arrays.reduce((s, a) => s + a.byteLength, 0);
  const out   = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.byteLength; }
  return out;
}

function _hex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
//  IndexedDB helpers
// ─────────────────────────────────────────────────────────────────────────────

function _openIDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = e => {
      e.target.result.createObjectStore(IDB_STORE, { keyPath: 'hash' });
    };
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  });
}

async function _idbGet(hash) {
  try {
    const db = await _openIDB();
    return new Promise((res, rej) => {
      const tx  = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(hash);
      req.onsuccess = () => res(req.result ?? null);
      req.onerror   = () => rej(req.error);
    });
  } catch {
    return null; // IDB unavailable (e.g. private browsing with certain browsers)
  }
}

async function _idbPut(hash, config, tensors, vocab) {
  const db = await _openIDB();
  return new Promise((res, rej) => {
    const tx    = db.transaction(IDB_STORE, 'readwrite');
    const store = tx.objectStore(IDB_STORE);
    const req   = store.put({ hash, config, tensors, vocab });
    req.onsuccess = () => res();
    req.onerror   = () => rej(req.error);
  });
}
