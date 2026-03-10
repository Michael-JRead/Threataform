/**
 * src/lib/storage/DocStore.js
 *
 * Single source of truth for all Threataform persistence.
 * Upgrades IndexedDB from v3 → v4 (adding docs, tf-files, model-meta stores).
 * All existing vectors + sessions stores are preserved unchanged.
 *
 * OPFS (Origin Private File System) is used to cache extracted text for large
 * files. If OPFS is unavailable, content falls back to the IDB 'docs' store.
 *
 * Exports:
 *   getDB()
 *   docStorePut / docStoreGet / docStoreGetAll / docStoreDelete / docStoreDeleteAll
 *   tfFilesPutAll / tfFilesGetAll / tfFilesDeleteAll
 *   modelMetaPut / modelMetaGet / modelMetaDelete / modelMetaDeleteAll
 *   opfsWriteText / opfsReadText / opfsDeleteText / opfsDeleteDir
 *   vecGet / vecPut / vecGetMany / vecPutMany / vecDeleteKeys  (replaces vdbGet etc.)
 *   chunkHash   (re-export for convenience)
 *   sessionDbPut / sessionDbGetRecent
 */

// ─────────────────────────────────────────────────────────────────────────────
// DB CONNECTION
// ─────────────────────────────────────────────────────────────────────────────
let _dbConn = null;

export function getDB() {
  if (!_dbConn) {
    _dbConn = new Promise((resolve) => {
      const req = indexedDB.open('threataform-vectors', 4);

      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        const oldVersion = e.oldVersion;

        // ── Preserve existing stores (v1-v3) ─────────────────────────────────
        if (!db.objectStoreNames.contains('vectors')) {
          db.createObjectStore('vectors');
        }
        if (!db.objectStoreNames.contains('sessions')) {
          const s = db.createObjectStore('sessions', { keyPath: 'id' });
          s.createIndex('createdAt', 'createdAt');
        }

        // ── v4 new stores ─────────────────────────────────────────────────────
        if (oldVersion < 4) {
          // Context documents (PDFs, DOCX, security docs, etc.)
          if (!db.objectStoreNames.contains('docs')) {
            const docs = db.createObjectStore('docs', { keyPath: 'key' });
            docs.createIndex('modelId', 'modelId');
          }

          // Terraform / HCL files (stored inline — always small)
          if (!db.objectStoreNames.contains('tf-files')) {
            const tf = db.createObjectStore('tf-files', { keyPath: 'key' });
            tf.createIndex('modelId', 'modelId');
          }

          // Per-model metadata (details, arch-analysis, diagram-image)
          if (!db.objectStoreNames.contains('model-meta')) {
            const meta = db.createObjectStore('model-meta', { keyPath: 'key' });
            meta.createIndex('modelId', 'modelId');
          }
        }
      };

      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror   = () => { _dbConn = null; resolve(null); };
    });
  }
  return _dbConn;
}

// ─────────────────────────────────────────────────────────────────────────────
// STABLE CHUNK HASH (same algorithm as main app's chunkHash)
// ─────────────────────────────────────────────────────────────────────────────
export function chunkHash(text) {
  return (text.substring(0, 50) + '|' + text.length).replace(/[^\w|]/g, '_');
}

// Simple string hash for file paths (for OPFS filenames + IDB keys)
export function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}

// ─────────────────────────────────────────────────────────────────────────────
// DOCS STORE — context documents (PDF, DOCX, MD, etc.)
// Key format: `doc_${modelId}_${simpleHash(path)}`
// ─────────────────────────────────────────────────────────────────────────────

/** Upsert one doc record. `record` must include at minimum: modelId, path, name. */
export async function docStorePut(record) {
  const db = await getDB();
  if (!db) return;
  const key = `doc_${record.modelId}_${simpleHash(record.path || record.name)}`;
  const full = { ...record, key };
  return new Promise((res) => {
    try {
      const tx = db.transaction('docs', 'readwrite');
      tx.objectStore('docs').put(full);
      tx.oncomplete = () => res(full);
      tx.onerror    = () => res(null);
    } catch { res(null); }
  });
}

/** Upsert multiple doc records in a single transaction. */
export async function docStorePutAll(modelId, records) {
  const db = await getDB();
  if (!db || !records?.length) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('docs', 'readwrite');
      const store = tx.objectStore('docs');
      records.forEach(r => {
        const key = `doc_${modelId}_${simpleHash(r.path || r.name)}`;
        store.put({ ...r, key, modelId });
      });
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

/** Get one doc record by path. */
export async function docStoreGet(modelId, path) {
  const db = await getDB();
  if (!db) return null;
  const key = `doc_${modelId}_${simpleHash(path)}`;
  return new Promise((res) => {
    try {
      const r = db.transaction('docs').objectStore('docs').get(key);
      r.onsuccess = () => res(r.result ?? null);
      r.onerror   = () => res(null);
    } catch { res(null); }
  });
}

/** Get all doc records for a model. */
export async function docStoreGetAll(modelId) {
  const db = await getDB();
  if (!db) return [];
  return new Promise((res) => {
    try {
      const tx    = db.transaction('docs');
      const idx   = tx.objectStore('docs').index('modelId');
      const req   = idx.getAll(modelId);
      req.onsuccess = () => res(req.result || []);
      req.onerror   = () => res([]);
    } catch { res([]); }
  });
}

/** Delete one doc record by path. */
export async function docStoreDelete(modelId, path) {
  const db = await getDB();
  if (!db) return;
  const key = `doc_${modelId}_${simpleHash(path)}`;
  return new Promise((res) => {
    try {
      const tx = db.transaction('docs', 'readwrite');
      tx.objectStore('docs').delete(key);
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

/** Delete all doc records for a model. */
export async function docStoreDeleteAll(modelId) {
  const db = await getDB();
  if (!db) return;
  // Use index cursor to delete all records matching modelId
  return new Promise((res) => {
    try {
      const tx  = db.transaction('docs', 'readwrite');
      const idx = tx.objectStore('docs').index('modelId');
      idx.openKeyCursor(IDBKeyRange.only(modelId)).onsuccess = function(e) {
        const cursor = e.target.result;
        if (!cursor) return;
        cursor.source.objectStore ? cursor.source.delete(cursor.primaryKey) : cursor.delete();
        cursor.continue();
      };
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// TF-FILES STORE — Terraform / HCL files (inline content, always small)
// Key format: `tf_${modelId}_${simpleHash(path)}`
// ─────────────────────────────────────────────────────────────────────────────

/** Replace all TF files for a model in a single transaction. */
export async function tfFilesPutAll(modelId, files) {
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('tf-files', 'readwrite');
      const store = tx.objectStore('tf-files');

      // Clear existing records for this model first via index cursor
      const idx = store.index('modelId');
      idx.openKeyCursor(IDBKeyRange.only(modelId)).onsuccess = function(e) {
        const cursor = e.target.result;
        if (!cursor) {
          // Now write new records
          (files || []).forEach(f => {
            const key = `tf_${modelId}_${simpleHash(f.path || f.name)}`;
            store.put({ key, modelId, path: f.path, name: f.name, content: f.content, size: f.size, savedAt: Date.now() });
          });
          return;
        }
        cursor.delete();
        cursor.continue();
      };

      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

/** Get all TF files for a model. */
export async function tfFilesGetAll(modelId) {
  const db = await getDB();
  if (!db) return [];
  return new Promise((res) => {
    try {
      const tx  = db.transaction('tf-files');
      const idx = tx.objectStore('tf-files').index('modelId');
      const req = idx.getAll(modelId);
      req.onsuccess = () => res((req.result || []).map(r => ({
        path: r.path, name: r.name, content: r.content, size: r.size,
      })));
      req.onerror   = () => res([]);
    } catch { res([]); }
  });
}

/** Delete all TF files for a model. */
export async function tfFilesDeleteAll(modelId) {
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx  = db.transaction('tf-files', 'readwrite');
      const idx = tx.objectStore('tf-files').index('modelId');
      idx.openKeyCursor(IDBKeyRange.only(modelId)).onsuccess = function(e) {
        const cursor = e.target.result;
        if (!cursor) return;
        cursor.delete();
        cursor.continue();
      };
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MODEL-META STORE — per-model metadata (details, arch-analysis, diagram-image)
// Key format: `meta_${modelId}_${subkey}`
// ─────────────────────────────────────────────────────────────────────────────

export async function modelMetaPut(modelId, subkey, value) {
  const db = await getDB();
  if (!db) return;
  const key = `meta_${modelId}_${subkey}`;
  return new Promise((res) => {
    try {
      const tx = db.transaction('model-meta', 'readwrite');
      tx.objectStore('model-meta').put({ key, modelId, subkey, value, updatedAt: Date.now() });
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

export async function modelMetaGet(modelId, subkey) {
  const db = await getDB();
  if (!db) return null;
  const key = `meta_${modelId}_${subkey}`;
  return new Promise((res) => {
    try {
      const r = db.transaction('model-meta').objectStore('model-meta').get(key);
      r.onsuccess = () => res(r.result?.value ?? null);
      r.onerror   = () => res(null);
    } catch { res(null); }
  });
}

export async function modelMetaDelete(modelId, subkey) {
  const db = await getDB();
  if (!db) return;
  const key = `meta_${modelId}_${subkey}`;
  return new Promise((res) => {
    try {
      const tx = db.transaction('model-meta', 'readwrite');
      tx.objectStore('model-meta').delete(key);
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

/** Delete all model-meta records for a model. */
export async function modelMetaDeleteAll(modelId) {
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx  = db.transaction('model-meta', 'readwrite');
      const idx = tx.objectStore('model-meta').index('modelId');
      idx.openKeyCursor(IDBKeyRange.only(modelId)).onsuccess = function(e) {
        const cursor = e.target.result;
        if (!cursor) return;
        cursor.delete();
        cursor.continue();
      };
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// OPFS — Origin Private File System for large extracted-text caching
// Path: threataform/${modelId}/${pathHash}.txt
// Falls back to null when OPFS is unavailable (Firefox with strict settings).
// ─────────────────────────────────────────────────────────────────────────────

async function _opfsDir(modelId, create = false) {
  try {
    const root = await navigator.storage.getDirectory();
    const base = await root.getDirectoryHandle('threataform', { create });
    return await base.getDirectoryHandle(modelId, { create });
  } catch { return null; }
}

export async function opfsWriteText(modelId, pathHash, text) {
  try {
    const dir = await _opfsDir(modelId, true);
    if (!dir) return false;
    const fh = await dir.getFileHandle(`${pathHash}.txt`, { create: true });
    const w  = await fh.createWritable();
    await w.write(text);
    await w.close();
    return true;
  } catch { return false; }
}

export async function opfsReadText(modelId, pathHash) {
  try {
    const dir = await _opfsDir(modelId, false);
    if (!dir) return null;
    const fh   = await dir.getFileHandle(`${pathHash}.txt`, { create: false });
    const file = await fh.getFile();
    return file.text();
  } catch { return null; }
}

export async function opfsDeleteText(modelId, pathHash) {
  try {
    const dir = await _opfsDir(modelId, false);
    if (!dir) return;
    await dir.removeEntry(`${pathHash}.txt`);
  } catch {}
}

export async function opfsDeleteDir(modelId) {
  try {
    const root = await navigator.storage.getDirectory();
    const base = await root.getDirectoryHandle('threataform', { create: false });
    await base.removeEntry(modelId, { recursive: true });
  } catch {}
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR STORE HELPERS — replaces vdbGet/vdbPut/vdbGetMany/vdbDeleteKeys in main app
// ─────────────────────────────────────────────────────────────────────────────

export async function vecGet(key) {
  const db = await getDB();
  if (!db) return null;
  return new Promise((res) => {
    try {
      const r = db.transaction('vectors').objectStore('vectors').get(key);
      r.onsuccess = () => res(r.result ?? null);
      r.onerror   = () => res(null);
    } catch { res(null); }
  });
}

export async function vecPut(key, value) {
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      tx.objectStore('vectors').put(value, key);
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

export async function vecPutMany(pairs) {
  if (!pairs?.length) return;
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      const store = tx.objectStore('vectors');
      pairs.forEach(({ key, value }) => store.put(value, key));
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

export async function vecGetMany(keys) {
  const db = await getDB();
  if (!db) return {};
  return new Promise((res) => {
    const results = {};
    const tx = db.transaction('vectors');
    const store = tx.objectStore('vectors');
    let pending = keys.length;
    if (!pending) { res(results); return; }
    keys.forEach(k => {
      const r = store.get(k);
      r.onsuccess = () => { results[k] = r.result ?? null; if (--pending === 0) res(results); };
      r.onerror   = () => { results[k] = null;             if (--pending === 0) res(results); };
    });
  });
}

export async function vecDeleteKeys(keys) {
  if (!keys?.length) return;
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      const store = tx.objectStore('vectors');
      keys.forEach(k => store.delete(k));
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SESSION HELPERS (moved here from main app for consolidation)
// ─────────────────────────────────────────────────────────────────────────────

export async function sessionDbPut(record) {
  const db = await getDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('sessions', 'readwrite');
      tx.objectStore('sessions').put(record);
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    } catch { res(); }
  });
}

export async function sessionDbGetRecent(limit = 10) {
  const db = await getDB();
  if (!db) return [];
  return new Promise((res) => {
    try {
      const tx  = db.transaction('sessions');
      const req = tx.objectStore('sessions').index('createdAt').getAll();
      req.onsuccess = () => {
        const all = req.result || [];
        res(all.sort((a, b) => b.createdAt - a.createdAt).slice(0, limit));
      };
      req.onerror = () => res([]);
    } catch { res([]); }
  });
}
