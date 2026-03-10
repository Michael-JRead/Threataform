// src/lib/observability.js
// Privacy-first, zero-telemetry observability utilities for Threataform.
// All output is local-only (DevTools console). Nothing is sent anywhere.

// ── DEV-guarded logger ─────────────────────────────────────────────────────
// In production builds (import.meta.env.PROD), all LOG calls are no-ops.
// Use LOG.group/groupEnd for structured output in DevTools.
export const LOG = import.meta.env.DEV
  ? {
      log:      (...a) => console.log('[Threataform]', ...a),
      warn:     (...a) => console.warn('[Threataform]', ...a),
      error:    (...a) => console.error('[Threataform]', ...a),
      group:    (...a) => console.group('[Threataform]', ...a),
      groupEnd: ()    => console.groupEnd(),
      time:     (l)   => console.time(`[Threataform] ${l}`),
      timeEnd:  (l)   => console.timeEnd(`[Threataform] ${l}`),
      table:    (...a) => console.table(...a),
    }
  : {
      log:      () => {},
      warn:     () => {},
      error:    () => {},
      group:    () => {},
      groupEnd: () => {},
      time:     () => {},
      timeEnd:  () => {},
      table:    () => {},
    };

// ── Structured error class ─────────────────────────────────────────────────
// Wraps any error with component + operation context for clean debugging.
export class ThreataformError extends Error {
  /**
   * @param {string} component  e.g. "ThrataformRAG", "WllamaManager"
   * @param {string} operation  e.g. "hybridSearch", "loadFromFile"
   * @param {Error|string} cause
   */
  constructor(component, operation, cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    super(`[${component}] ${operation}: ${msg}`);
    this.name      = 'ThreataformError';
    this.component = component;
    this.operation = operation;
    this.cause     = cause instanceof Error ? cause : new Error(msg);
    this.timestamp = new Date().toISOString();
  }

  toString() {
    return `${this.name}(${this.component}.${this.operation}): ${this.message}`;
  }
}

// ── LLM inference performance tracker ─────────────────────────────────────
// Returns an object with start() / end(tokenCount) methods.
// Logs tok/sec to console and returns the metric for callers.
export function createInferenceTracker(modelName = 'unknown') {
  let _t0 = null;
  return {
    start() {
      _t0 = performance.now();
    },
    end(tokenCount) {
      if (_t0 === null) return null;
      const durationMs   = performance.now() - _t0;
      const durationSec  = durationMs / 1000;
      const tokSec       = durationSec > 0 ? (tokenCount / durationSec).toFixed(1) : '—';
      const metric       = { model: modelName, tokens: tokenCount, durationMs: Math.round(durationMs), tokSec: parseFloat(tokSec) || 0 };
      LOG.log(`[LLM] ${tokenCount} tokens in ${durationSec.toFixed(1)}s → ${tokSec} tok/sec (${modelName})`);
      _t0 = null;
      return metric;
    },
  };
}

// ── RAG retrieval logger ───────────────────────────────────────────────────
// Log hybrid-search results in a structured DevTools group.
export function logHybridSearch(query, bm25Count, denseCount, rrfTop3) {
  if (!import.meta.env.DEV) return;
  LOG.group(`[RAG] hybridSearch("${String(query).slice(0, 40)}${query?.length > 40 ? '…' : ''}")`);
  LOG.log(`BM25 hits: ${bm25Count}  |  Dense hits: ${denseCount}`);
  if (rrfTop3?.length) LOG.log('RRF top-3:', rrfTop3.map(r => r.source || r.docId || 'doc').join(', '));
  LOG.groupEnd();
}

// ── Error log store ────────────────────────────────────────────────────────
// Collects ThreataformErrors in-memory so the UI error panel can display them.
// Max 50 entries — ring buffer.
const _MAX_ERRORS = 50;
const _errorLog   = [];

export function pushErrorLog(err) {
  _errorLog.push({
    id:        Date.now(),
    message:   err?.message || String(err),
    component: err?.component || 'unknown',
    operation: err?.operation || '',
    timestamp: err?.timestamp || new Date().toISOString(),
  });
  if (_errorLog.length > _MAX_ERRORS) _errorLog.shift();
}

/** Returns a shallow copy of the error log array (most recent last). */
export function getErrorLog() {
  return [..._errorLog];
}

/** Clear the in-memory error log. */
export function clearErrorLog() {
  _errorLog.length = 0;
}
