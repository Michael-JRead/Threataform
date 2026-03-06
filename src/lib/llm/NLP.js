/**
 * src/lib/llm/NLP.js
 * ThreataformLM — NLP Pipeline (pure JavaScript, zero dependencies)
 *
 * Provides:
 *   SecurityNER         — Named Entity Recognition for security/cloud domain
 *   SemanticChunker     — Embedding-based chunking at semantic boundaries
 *   LanguageDetector    — Trigram-based language identification (~50 languages)
 *   CoreferenceResolver — Pronoun → antecedent substitution (simplified)
 *   RelationExtractor   — Subject → predicate → object triples
 *   segmentSentences()  — Sentence boundary detection
 *
 * All modules work offline with no external API calls or downloads.
 */

// ─────────────────────────────────────────────────────────────────────────────
//  SecurityNER — Named Entity Recognition
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Entity type definitions for the security / cloud domain.
 * Each entry: { type, pattern (regex), confidence }
 */
const NER_RULES = [
  // CVE identifiers
  { type: 'CVE',          re: /\bCVE-\d{4}-\d{4,7}\b/g,        conf: 0.99 },
  // MITRE ATT&CK technique IDs
  { type: 'MITRE_TECHNIQUE', re: /\bT\d{4}(?:\.\d{3})?\b/g,    conf: 0.97 },
  // CIS controls
  { type: 'CIS_CONTROL',  re: /\bCIS\s+(?:Control\s+)?\d+(?:\.\d+)?\b/gi, conf: 0.95 },
  // NIST controls (SP 800-53 format)
  { type: 'NIST_CONTROL', re: /\b[A-Z]{2}-\d+(?:\(\d+\))?\b/g, conf: 0.88 },
  // AWS resource ARNs
  { type: 'AWS_ARN',      re: /\barn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:[^\s"',]+/gi, conf: 0.99 },
  // AWS account IDs (12-digit)
  { type: 'AWS_ACCOUNT',  re: /\b\d{12}\b/g,                    conf: 0.75 },
  // Terraform resource references (resource.type.name)
  { type: 'TF_RESOURCE',  re: /\b(?:aws|azurerm|google|kubernetes)_[a-z_]+\.[a-zA-Z0-9_]+\b/g, conf: 0.96 },
  // IP addresses (IPv4)
  { type: 'IP_ADDRESS',   re: /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g, conf: 0.92 },
  // IP addresses (IPv6)
  { type: 'IP_ADDRESS',   re: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, conf: 0.92 },
  // Port numbers (with context)
  { type: 'PORT',         re: /\bport(?:s)?\s+(\d{1,5})\b/gi,   conf: 0.85 },
  // Hostnames / FQDNs
  { type: 'HOSTNAME',     re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|mil|edu|cloud|aws|azure|gcp)\b/g, conf: 0.80 },
  // S3 bucket names
  { type: 'S3_BUCKET',    re: /\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:\.amazonaws\.com)?\b/g, conf: 0.92 },
  // Compliance frameworks
  { type: 'COMPLIANCE',   re: /\b(?:HIPAA|PCI[\s-]DSS|FedRAMP|SOC\s*[12]|GDPR|CMMC|ISO\s*27001|NIST\s*CSF|CIS|FISMA)\b/g, conf: 0.97 },
  // Severity levels
  { type: 'SEVERITY',     re: /\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b/g, conf: 0.90 },
  // STRIDE threats
  { type: 'STRIDE',       re: /\b(?:Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege)\b/gi, conf: 0.95 },
  // Common AWS services
  { type: 'AWS_SERVICE',  re: /\b(?:EC2|S3|RDS|IAM|VPC|EKS|ECS|Lambda|CloudTrail|CloudWatch|KMS|Secrets Manager|WAF|Shield|GuardDuty|SecurityHub|Config|Macie|Inspector)\b/g, conf: 0.90 },
  // Risk levels
  { type: 'RISK_LEVEL',   re: /\b(?:critical|high|medium|low)\s+risk\b/gi, conf: 0.88 },
];

export class SecurityNER {
  /**
   * Extract named entities from text.
   * @param {string} text
   * @returns {{ entities: Array<{type, value, start, end, confidence}> }}
   */
  extract(text) {
    const entities = [];
    const seen     = new Set(); // deduplicate by position

    for (const rule of NER_RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(text)) !== null) {
        const key = `${m.index}-${m.index + m[0].length}`;
        if (!seen.has(key)) {
          seen.add(key);
          entities.push({
            type:       rule.type,
            value:      m[0].trim(),
            start:      m.index,
            end:        m.index + m[0].length,
            confidence: rule.conf,
          });
        }
      }
    }

    // Sort by position
    entities.sort((a, b) => a.start - b.start);
    return { entities };
  }

  /**
   * Annotate text by wrapping detected entities with type markers.
   * @param {string} text
   * @returns {string}
   */
  annotate(text) {
    const { entities } = this.extract(text);
    let result = '';
    let last   = 0;
    for (const ent of entities) {
      result += text.slice(last, ent.start);
      result += `[${ent.type}: ${ent.value}]`;
      last    = ent.end;
    }
    result += text.slice(last);
    return result;
  }

  /**
   * Check if text contains a specific entity type.
   * @param {string} text
   * @param {string} type  e.g. 'CVE', 'COMPLIANCE'
   * @returns {boolean}
   */
  has(text, type) {
    return this.extract(text).entities.some(e => e.type === type);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SemanticChunker — split text at semantic boundaries using cosine similarity
// ─────────────────────────────────────────────────────────────────────────────

export class SemanticChunker {
  /**
   * @param {object} [opts]
   * @param {number} [opts.minChunk=100]     Minimum chunk character length
   * @param {number} [opts.maxChunk=1200]    Maximum chunk character length
   * @param {number} [opts.threshold=0.6]    Cosine dip threshold for boundary detection
   * @param {number} [opts.windowSize=3]     Sentences to average for embedding window
   */
  constructor({ minChunk = 100, maxChunk = 1200, threshold = 0.6, windowSize = 3 } = {}) {
    this.minChunk   = minChunk;
    this.maxChunk   = maxChunk;
    this.threshold  = threshold;
    this.windowSize = windowSize;
  }

  /**
   * Chunk text semantically using a provided embedding function.
   * Falls back to simple sentence-boundary chunking if embedder is unavailable.
   *
   * @param {string}   text
   * @param {Function} [embedFn]  async (text: string) => Float32Array
   * @returns {Promise<string[]>}
   */
  async chunk(text, embedFn = null) {
    const sentences = segmentSentences(text);
    if (sentences.length <= 1) return [text];

    if (!embedFn) {
      return this._simpleChunk(sentences);
    }

    return this._semanticChunk(sentences, embedFn);
  }

  async _semanticChunk(sentences, embedFn) {
    // Embed each sentence (or window of sentences)
    const vecs = [];
    for (let i = 0; i < sentences.length; i++) {
      const windowText = sentences
        .slice(Math.max(0, i - 1), i + this.windowSize)
        .join(' ');
      try {
        vecs.push(await embedFn(windowText));
      } catch {
        vecs.push(null);
      }
    }

    // Compute cosine similarity between adjacent windows
    const sims = [];
    for (let i = 0; i < vecs.length - 1; i++) {
      if (vecs[i] && vecs[i + 1]) {
        sims.push(_cosineSim(vecs[i], vecs[i + 1]));
      } else {
        sims.push(0.9); // default: no boundary
      }
    }

    // Detect boundaries: positions where similarity drops below threshold
    const boundaries = new Set([0]);
    for (let i = 0; i < sims.length; i++) {
      if (sims[i] < this.threshold) {
        boundaries.add(i + 1);
      }
    }
    boundaries.add(sentences.length);

    // Build chunks from boundary positions
    const bArr  = Array.from(boundaries).sort((a, b) => a - b);
    const chunks = [];
    for (let i = 0; i < bArr.length - 1; i++) {
      const chunk = sentences.slice(bArr[i], bArr[i + 1]).join(' ');
      chunks.push(...this._splitByLength(chunk));
    }

    return chunks.filter(c => c.trim().length >= 20);
  }

  _simpleChunk(sentences) {
    const chunks = [];
    let   buf    = '';

    for (const sent of sentences) {
      if (buf.length + sent.length > this.maxChunk && buf.length >= this.minChunk) {
        chunks.push(buf.trim());
        buf = '';
      }
      buf += (buf ? ' ' : '') + sent;
    }
    if (buf.trim()) chunks.push(buf.trim());
    return chunks.filter(c => c.length >= 20);
  }

  _splitByLength(text) {
    if (text.length <= this.maxChunk) return [text];
    const parts = [];
    let   i     = 0;
    while (i < text.length) {
      let end = Math.min(i + this.maxChunk, text.length);
      // Try to split at a sentence boundary
      const lastPeriod = text.lastIndexOf('. ', end);
      if (lastPeriod > i + this.minChunk) end = lastPeriod + 2;
      parts.push(text.slice(i, end));
      i = end;
    }
    return parts;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  LanguageDetector — trigram frequency model
// ─────────────────────────────────────────────────────────────────────────────

// Compact trigram profiles for 10 key languages + a default fallback.
// Full 50-language support: replace LANG_PROFILES with the output of
// `python scripts/build_lang_profiles.py`.
const LANG_PROFILES = {
  en: ['the', 'ing', 'ion', ' th', 'he ', 'and', 'tion', 'er ', ' to', ' of'],
  es: ['de ', 'que', ' la', 'ión', ' de', 'los', ' el', 'es ', ' en', 'con'],
  fr: ['les', ' de', ' la', 'de ', 'ent', 'ion', ' le', 'que', 'ons', ' en'],
  de: ['en ', 'die', 'der', 'und', 'ich', ' di', 'ein', 'ung', 'den', 'er '],
  it: ['che', ' di', ' de', 'ion', ' e ', ' la', 'per', 'del', 'ell', 'one'],
  pt: ['de ', ' de', ' a ', 'que', 'ão ', 'ões', ' do', ' co', ' em', ' pa'],
  nl: ['de ', 'en ', ' de', 'van', ' va', 'het', 'ing', 'er ', ' he', 'een'],
  ru: ['ого', 'ния', 'ть ', 'ого', 'то ', 'его', 'ые ', 'ной', 'ние', 'ом '],
  zh: ['的 ', '了 ', '是 ', '在 ', '个 ', '不 ', '我 ', '们 ', '说 ', '他 '],
  ja: ['の ', 'は ', 'に ', 'を ', 'た ', 'が ', 'で ', 'い ', 'て ', 'と '],
};

export class LanguageDetector {
  /** @returns {{ lang: string, confidence: number }} */
  detect(text) {
    if (!text || text.length < 20) return { lang: 'en', confidence: 0.5 };

    const sample   = text.slice(0, 2000).toLowerCase();
    const trigrams = _extractTrigrams(sample);

    let bestLang  = 'en';
    let bestScore = -Infinity;

    for (const [lang, profile] of Object.entries(LANG_PROFILES)) {
      let score = 0;
      for (let i = 0; i < profile.length; i++) {
        const count = trigrams.get(profile[i]) ?? 0;
        score += count * (profile.length - i); // weight by rank
      }
      if (score > bestScore) { bestScore = score; bestLang = lang; }
    }

    // Rough confidence: ratio of best to worst
    const confidence = Math.min(0.99, 0.5 + bestScore / (sample.length * 0.3));
    return { lang: bestLang, confidence };
  }
}

function _extractTrigrams(text) {
  const map = new Map();
  for (let i = 0; i + 3 <= text.length; i++) {
    const tri = text.slice(i, i + 3);
    map.set(tri, (map.get(tri) ?? 0) + 1);
  }
  return map;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CoreferenceResolver — pronoun → antecedent substitution
// ─────────────────────────────────────────────────────────────────────────────

const PRONOUNS = /\b(it|they|them|their|its|the system|the service|this resource|the bucket|the instance)\b/gi;

export class CoreferenceResolver {
  /**
   * Replace pronouns with their most recent named antecedent.
   * Simplified: looks back up to 3 sentences for a noun phrase.
   * @param {string} text
   * @returns {string}
   */
  resolve(text) {
    const sentences = segmentSentences(text);
    const resolved  = [];
    let   lastNoun  = '';

    for (const sent of sentences) {
      // Extract noun phrases (simple: sequences of capitalised words or known resource names)
      const nounsInSent = sent.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g) ?? [];
      // Filter to likely entity names (skip common words)
      const skip = new Set(['The', 'This', 'That', 'These', 'Those', 'A', 'An', 'In', 'On', 'For']);
      const nouns = nounsInSent.filter(n => !skip.has(n));
      if (nouns.length > 0) lastNoun = nouns[nouns.length - 1];

      if (lastNoun) {
        resolved.push(sent.replace(PRONOUNS, (match, p1) => {
          // Only replace if the pronoun plausibly refers to the last noun
          const lower = p1.toLowerCase();
          if (['it', 'its', 'the system', 'the service', 'this resource'].includes(lower)) {
            return lastNoun;
          }
          return match;
        }));
      } else {
        resolved.push(sent);
      }
    }

    return resolved.join(' ');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  RelationExtractor — subject → predicate → object triples
// ─────────────────────────────────────────────────────────────────────────────

const RELATION_PATTERNS = [
  // "X exposes Y to Z"
  { re: /([A-Z][a-zA-Z0-9\s_]+?)\s+(exposes?|allows?|permits?|grants?)\s+(.+?)\s+(?:to|from|via)\s+(.+?)(?:\.|,|$)/gi,
    build: m => ({ subject: m[1].trim(), predicate: m[2].trim(), object: `${m[3].trim()} → ${m[4].trim()}` }) },
  // "X is vulnerable to Y"
  { re: /([A-Z][a-zA-Z0-9\s_]+?)\s+is\s+(vulnerable|exposed|susceptible)\s+to\s+(.+?)(?:\.|,|$)/gi,
    build: m => ({ subject: m[1].trim(), predicate: `is ${m[2].trim()} to`, object: m[3].trim() }) },
  // "X accesses Y"
  { re: /([A-Z][a-zA-Z0-9\s_]+?)\s+(accesses?|reads?|writes?|modifies?|deletes?|authenticates?|connects? to)\s+([A-Z][a-zA-Z0-9\s_]+?)(?:\.|,|;|$)/gi,
    build: m => ({ subject: m[1].trim(), predicate: m[2].trim(), object: m[3].trim() }) },
  // "X lacks / does not have Y"
  { re: /([A-Z][a-zA-Z0-9\s_]+?)\s+(?:lacks?|does not have|missing)\s+(.+?)(?:\.|,|$)/gi,
    build: m => ({ subject: m[1].trim(), predicate: 'lacks', object: m[2].trim() }) },
  // "X → Y (trust boundary / data flow)"
  { re: /([A-Z][a-zA-Z0-9\s_]+?)\s*→\s*([A-Z][a-zA-Z0-9\s_]+)/g,
    build: m => ({ subject: m[1].trim(), predicate: 'flows to', object: m[2].trim() }) },
];

export class RelationExtractor {
  /**
   * Extract (subject, predicate, object) triples from text.
   * @param {string} text
   * @returns {{ triples: Array<{subject, predicate, object}> }}
   */
  extract(text) {
    const triples = [];
    const seen    = new Set();

    for (const { re, build } of RELATION_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const triple = build(m);
        const key    = `${triple.subject}|${triple.predicate}|${triple.object}`;
        if (!seen.has(key) && triple.subject && triple.object) {
          seen.add(key);
          triples.push(triple);
        }
      }
    }

    return { triples };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sentence boundary detection
// ─────────────────────────────────────────────────────────────────────────────

// Abbreviations that should NOT trigger a sentence boundary
const ABBREVS = new Set([
  'mr', 'mrs', 'ms', 'dr', 'prof', 'sr', 'jr', 'vs', 'etc', 'e.g', 'i.e',
  'no', 'vol', 'fig', 'ref', 'sec', 'dept', 'est', 'approx',
  // AWS / tech abbreviations
  'ec2', 's3', 'rds', 'vpc', 'iam', 'eks', 'ecs', 'api', 'sdk', 'cli',
  'http', 'https', 'ftp', 'ssh', 'ssl', 'tls',
]);

/**
 * Split text into sentences, handling abbreviations, code blocks, and URLs.
 * @param {string} text
 * @returns {string[]}
 */
export function segmentSentences(text) {
  if (!text) return [];

  // Remove code blocks temporarily (they confuse the boundary detector)
  const codeBlocks = [];
  let   cleaned    = text.replace(/```[\s\S]*?```/g, match => {
    codeBlocks.push(match);
    return `__CODE${codeBlocks.length - 1}__`;
  });

  // Split on sentence-ending punctuation followed by whitespace + capital or EOL
  const raw = cleaned.split(/(?<=[.!?])(?:\s+)(?=[A-Z"'\u00C0-\u017E]|\d)/);

  const sentences = [];
  let   pending   = '';

  for (const part of raw) {
    // Check if the last "sentence" ends with an abbreviation
    const wordAtEnd = part.trimEnd().split(/\s+/).pop()?.replace(/[^a-zA-Z.]/g, '').toLowerCase().replace(/\.$/, '');
    if (wordAtEnd && ABBREVS.has(wordAtEnd)) {
      pending += (pending ? ' ' : '') + part;
    } else {
      const full = pending ? pending + ' ' + part : part;
      pending = '';
      if (full.trim()) sentences.push(full.trim());
    }
  }
  if (pending.trim()) sentences.push(pending.trim());

  // Restore code blocks
  const restored = sentences.map(s =>
    s.replace(/__CODE(\d+)__/g, (_, i) => codeBlocks[parseInt(i, 10)])
  );

  return restored.filter(s => s.length > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Text preprocessing utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Clean and normalise raw text for NLP processing.
 * @param {string} raw
 * @returns {string}
 */
export function normalizeText(raw) {
  return raw
    .normalize('NFC')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/[ ]{2,}/g, ' ')    // collapse multiple spaces
    .replace(/\n{3,}/g, '\n\n')  // collapse blank lines
    .trim();
}

/**
 * Extract the most informative keywords from text using TF-IDF-lite scoring.
 * Useful for BM25 query expansion.
 * @param {string} text
 * @param {number} topK
 * @returns {string[]}
 */
export function extractKeywords(text, topK = 20) {
  const STOP = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on',
    'at', 'to', 'for', 'of', 'with', 'by', 'from', 'is', 'are', 'was',
    'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does',
    'did', 'will', 'would', 'should', 'could', 'may', 'might', 'it',
    'its', 'this', 'that', 'these', 'those', 'not', 'no', 'so', 'as']);

  const words = text.toLowerCase().match(/\b[a-z][a-z0-9_-]{2,}\b/g) ?? [];
  const freq  = new Map();
  for (const w of words) {
    if (!STOP.has(w)) freq.set(w, (freq.get(w) ?? 0) + 1);
  }

  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, topK)
    .map(([w]) => w);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal math
// ─────────────────────────────────────────────────────────────────────────────

function _cosineSim(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na  += a[i] * a[i];
    nb  += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom < 1e-10 ? 0 : dot / denom;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Singletons
// ─────────────────────────────────────────────────────────────────────────────

export const ner           = new SecurityNER();
export const chunker       = new SemanticChunker();
export const langDetector  = new LanguageDetector();
export const corefResolver = new CoreferenceResolver();
export const relationExt   = new RelationExtractor();
