/**
 * src/lib/rag/Chunker.js
 * Hierarchical + Semantic document chunking pipeline.
 *
 * Two strategies, composable:
 *
 *   RecursiveTextSplitter — Hierarchical, deterministic, zero dependencies.
 *     Splits by: markdown headings → paragraphs → sentences → characters.
 *     Each pass only splits chunks that exceed maxChunk.
 *     Produces uniform-ish chunks ideal as a first pass.
 *
 *   SemanticChunker (re-exported from NLP.js) — Embedding-based boundary detection.
 *     Finds cosine-similarity dips between adjacent sentence windows.
 *     Produces semantically coherent variable-size chunks.
 *
 *   HierarchicalChunker — Two-pass composition:
 *     1. RecursiveTextSplitter (fast, coarse)
 *     2. SemanticChunker refines any chunk still above maxChunk
 *     Best of both: speed of recursive + precision of semantic.
 *
 * Usage:
 *   import { RecursiveTextSplitter, HierarchicalChunker } from './rag/Chunker.js';
 *   import { SemanticChunker } from './rag/Chunker.js'; // re-exported
 *
 *   const rts = new RecursiveTextSplitter({ minChunk: 100, maxChunk: 800, overlap: 50 });
 *   const chunks = rts.split(text);
 *
 *   const hc = new HierarchicalChunker({ minChunk: 80, maxChunk: 900, overlap: 40 });
 *   const chunks = await hc.chunk(text, embedFn); // embedFn optional
 */

export { SemanticChunker } from '../llm/NLP.js';

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Split text on the first separator that produces at least two parts.
 * Returns null if none match.
 */
function _splitOn(text, separators) {
  for (const sep of separators) {
    const re = sep instanceof RegExp ? sep : new RegExp(sep, 'u');
    const parts = text.split(re).map(s => s.trim()).filter(Boolean);
    if (parts.length > 1) return { parts, sep };
  }
  return null;
}

/**
 * Merge short parts into larger chunks respecting [minChunk, maxChunk].
 * Adds `overlap` characters of the previous chunk's tail to the next chunk.
 */
function _mergeWithOverlap(parts, minChunk, maxChunk, overlap) {
  const out = [];
  let current = '';

  for (const part of parts) {
    const candidate = current ? `${current}\n\n${part}` : part;
    if (candidate.length <= maxChunk) {
      current = candidate;
    } else {
      if (current && current.length >= minChunk) {
        out.push(current);
        // Carry overlap from the tail of current into the next chunk
        const tail = overlap > 0 ? current.slice(-overlap) : '';
        current = tail ? `${tail}\n\n${part}` : part;
      } else {
        // current is too short — keep merging
        current = candidate;
      }
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  RecursiveTextSplitter
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hierarchy of separators tried in order (most structural → least structural):
 *   1. Markdown H1/H2 headings
 *   2. Blank line (paragraph boundary)
 *   3. Newline
 *   4. Sentence boundary (. ! ?)
 *   5. Clause boundary (, ; :)
 *   6. Word boundary (space)
 *   7. Character (last resort)
 */
const DEFAULT_SEPARATORS = [
  /\n#{1,2}\s/,          // markdown headings
  /\n{2,}/,              // paragraph breaks
  /\n/,                  // single newline
  /(?<=[.!?])\s+/,       // sentence end
  /(?<=[,;:])\s+/,       // clause end
  /\s+/,                 // word boundary
  '',                    // character-level (empty string → split every char)
];

export class RecursiveTextSplitter {
  /**
   * @param {object} opts
   * @param {number} opts.minChunk   - minimum chunk length in characters (default 100)
   * @param {number} opts.maxChunk   - maximum chunk length in characters (default 800)
   * @param {number} opts.overlap    - character overlap between adjacent chunks (default 50)
   * @param {RegExp[]|string[]} opts.separators - custom separator hierarchy
   */
  constructor({ minChunk = 100, maxChunk = 800, overlap = 50, separators = DEFAULT_SEPARATORS } = {}) {
    this.minChunk   = minChunk;
    this.maxChunk   = maxChunk;
    this.overlap    = overlap;
    this.separators = separators;
  }

  /**
   * Split `text` into chunks.
   * @param {string} text
   * @returns {string[]}
   */
  split(text) {
    if (!text || text.length === 0) return [];
    text = text.trim();
    if (text.length <= this.maxChunk) return text.length >= this.minChunk ? [text] : [];
    return this._splitRecursive(text, 0);
  }

  /** @private */
  _splitRecursive(text, sepIdx) {
    if (text.length <= this.maxChunk) {
      return text.length >= this.minChunk ? [text] : [];
    }

    // Try each separator level starting at sepIdx
    for (let i = sepIdx; i < this.separators.length; i++) {
      const sep = this.separators[i];

      // Character-level fallback
      if (sep === '') {
        const chunks = [];
        for (let start = 0; start < text.length; start += this.maxChunk - this.overlap) {
          const chunk = text.slice(start, start + this.maxChunk);
          if (chunk.length >= this.minChunk) chunks.push(chunk);
        }
        return chunks;
      }

      const result = _splitOn(text, [sep]);
      if (!result) continue;

      const merged = _mergeWithOverlap(result.parts, this.minChunk, this.maxChunk, this.overlap);

      // Recurse into any chunk that is still too large
      const out = [];
      for (const chunk of merged) {
        if (chunk.length > this.maxChunk) {
          out.push(...this._splitRecursive(chunk, i + 1));
        } else if (chunk.length >= this.minChunk) {
          out.push(chunk);
        }
      }
      return out;
    }

    // Absolute fallback: hard-chop
    const chunks = [];
    for (let s = 0; s < text.length; s += this.maxChunk - this.overlap) {
      const c = text.slice(s, s + this.maxChunk);
      if (c.length >= this.minChunk) chunks.push(c);
    }
    return chunks;
  }

  /**
   * Split and annotate with metadata.
   * @param {string} text
   * @param {object} meta - extra metadata fields merged into each chunk object
   * @returns {{ text: string, index: number, charStart: number, charEnd: number }[]}
   */
  splitWithMeta(text, meta = {}) {
    const chunks = this.split(text);
    let offset = 0;
    return chunks.map((c, i) => {
      const start = text.indexOf(c, offset);
      const end   = start >= 0 ? start + c.length : offset + c.length;
      offset      = start >= 0 ? end : offset + c.length;
      return { text: c, index: i, charStart: Math.max(start, 0), charEnd: end, ...meta };
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  HierarchicalChunker
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Two-pass chunker:
 *   Pass 1: RecursiveTextSplitter — fast, structural
 *   Pass 2: SemanticChunker — refines oversized or semantically incoherent chunks
 *
 * When `embedFn` is not provided, falls back to RecursiveTextSplitter alone.
 */
export class HierarchicalChunker {
  /**
   * @param {object} opts
   * @param {number} opts.minChunk
   * @param {number} opts.maxChunk
   * @param {number} opts.overlap
   * @param {number} opts.semanticThreshold - cosine similarity dip threshold (0–1, default 0.65)
   */
  constructor({ minChunk = 80, maxChunk = 900, overlap = 40, semanticThreshold = 0.65 } = {}) {
    this.minChunk          = minChunk;
    this.maxChunk          = maxChunk;
    this.overlap           = overlap;
    this.semanticThreshold = semanticThreshold;
    this._rts = new RecursiveTextSplitter({ minChunk, maxChunk, overlap });
  }

  /**
   * Chunk text with optional semantic refinement.
   *
   * @param {string}   text
   * @param {Function} [embedFn] - async (text: string) => Float32Array  (from model.embed)
   * @returns {Promise<string[]>}
   */
  async chunk(text, embedFn = null) {
    if (!text || text.length === 0) return [];

    // Pass 1: recursive structural splitting
    const coarse = this._rts.split(text);
    if (!embedFn || coarse.length === 0) return coarse;

    // Pass 2: semantic refinement for large chunks
    const { SemanticChunker } = await import('../llm/NLP.js');
    const sc = new SemanticChunker({
      minChunk:  this.minChunk,
      maxChunk:  this.maxChunk,
      threshold: this.semanticThreshold,
    });

    const refined = [];
    for (const coarseChunk of coarse) {
      if (coarseChunk.length <= this.maxChunk) {
        refined.push(coarseChunk);
      } else {
        // Large chunk: apply semantic chunking
        try {
          const sub = await sc.chunk(coarseChunk, embedFn);
          refined.push(...(sub.length > 0 ? sub : [coarseChunk]));
        } catch {
          refined.push(coarseChunk);
        }
      }
    }
    return refined;
  }

  /**
   * Synchronous version — RecursiveTextSplitter only (no semantic refinement).
   * @param {string} text
   * @returns {string[]}
   */
  chunkSync(text) {
    return this._rts.split(text);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Convenience factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a pre-configured HierarchicalChunker with sensible defaults for
 * typical threat-modeling document ingestion.
 *
 * @param {'fast'|'balanced'|'precise'} preset
 * @returns {HierarchicalChunker}
 */
export function makeChunker(preset = 'balanced') {
  const presets = {
    fast:     { minChunk:  80, maxChunk:  600, overlap: 30, semanticThreshold: 0.70 },
    balanced: { minChunk: 100, maxChunk:  900, overlap: 50, semanticThreshold: 0.65 },
    precise:  { minChunk: 120, maxChunk: 1200, overlap: 80, semanticThreshold: 0.58 },
  };
  return new HierarchicalChunker(presets[preset] ?? presets.balanced);
}
