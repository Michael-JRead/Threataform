/**
 * src/lib/llm/Tokenizer.js
 * ThreataformLM — BPE Tokenizer (pure JavaScript, zero dependencies)
 *
 * Implements Byte-Pair Encoding (Sennrich et al. 2016) from scratch.
 *
 * Vocabulary layout (32 000 tokens after full training):
 *   IDs   0 –  17   Special / control tokens
 *   IDs  18 – 273   256 UTF-8 byte tokens  (guarantees complete Unicode coverage)
 *   IDs 274 – …     Learned BPE merge tokens
 *
 * The file ships with ~160 placeholder merges so the engine is functional
 * immediately.  Run  `python scripts/export_vocab.py`  after training and call
 * `tokenizer.loadVocab(data)` to replace the placeholder with the full 32K vocab.
 *
 * Usage:
 *   import { tokenizer, SPECIAL_IDS } from './Tokenizer.js';
 *   const ids  = tokenizer.encode('Analyse S3 bucket ACL');    // Int32Array
 *   const text = tokenizer.decode(ids);                         // string
 *   const ids2 = tokenizer.encodeChat([
 *     { role: 'system',    content: 'You are a threat model expert.' },
 *     { role: 'user',      content: 'List STRIDE threats for this config.' },
 *   ]);
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Byte ↔ token-string helpers
//
//  Convention used throughout this file:
//    Printable ASCII 0x20–0x7E  →  the character itself  (e.g. 0x74 → 't')
//    All other bytes 0x00–0x1F, 0x7F–0xFF → two-hex-digit notation  <XX>
//
//  This lets BPE merge tables be written in readable form ('th', ' the', etc.)
//  while still covering the full byte range via the <XX> fallback.
// ─────────────────────────────────────────────────────────────────────────────

/** Byte (0–255) → token string */
function b2s(b) {
  return (b >= 0x20 && b <= 0x7E)
    ? String.fromCharCode(b)
    : `<${b.toString(16).padStart(2, '0').toUpperCase()}>`;
}

/** Pre-built byte → token string table (avoid repeated string allocations) */
const BYTE_STRS = Array.from({ length: 256 }, (_, i) => b2s(i));

// ─────────────────────────────────────────────────────────────────────────────
//  Special tokens
// ─────────────────────────────────────────────────────────────────────────────

export const SPECIAL_TOKENS = Object.freeze({
  PAD:         '<|pad|>',             //  0 — padding (silently skipped during decode)
  BOS:         '<|begin_of_text|>',   //  1 — beginning of sequence
  EOS:         '<|end_of_text|>',     //  2 — end of sequence / stop token
  UNK:         '<|unk|>',             //  3 — unknown (should never appear with byte fallback)
  HDR_START:   '<|start_header_id|>', //  4 — LLaMA-3 instruct role tag open
  HDR_END:     '<|end_header_id|>',   //  5 — LLaMA-3 instruct role tag close
  EOT:         '<|eot_id|>',          //  6 — end of turn
  // SELF-RAG decision tokens (predicted during generation, not in user input)
  RETRIEVE:    '<|retrieve|>',        //  7 — model decides to retrieve context
  NO_RETRIEVE: '<|no_retrieve|>',     //  8 — model decides NOT to retrieve
  ISREL:       '<|isrel|>',           //  9 — retrieved passage IS relevant
  ISIRREL:     '<|isirrel|>',         // 10 — retrieved passage is NOT relevant
  ISSUP:       '<|issup|>',           // 11 — generation IS supported by evidence
  ISNOSUP:     '<|isnosup|>',         // 12 — generation is NOT supported
  ISUSE:       '<|isuse|>',           // 13 — response usefulness score (1–5 follows)
  // Security domain markers
  THREAT:      '<|threat|>',          // 14 — STRIDE / ATT&CK threat entry
  CONTROL:     '<|control|>',         // 15 — security control / mitigation
  RESOURCE:    '<|resource|>',        // 16 — cloud / infra resource block
  MITRE:       '<|mitre|>',           // 17 — MITRE ATT&CK technique reference
});

/** Internal ordered list — array index IS the token ID */
const SPECIAL_LIST = [
  SPECIAL_TOKENS.PAD,        //  0
  SPECIAL_TOKENS.BOS,        //  1
  SPECIAL_TOKENS.EOS,        //  2
  SPECIAL_TOKENS.UNK,        //  3
  SPECIAL_TOKENS.HDR_START,  //  4
  SPECIAL_TOKENS.HDR_END,    //  5
  SPECIAL_TOKENS.EOT,        //  6
  SPECIAL_TOKENS.RETRIEVE,   //  7
  SPECIAL_TOKENS.NO_RETRIEVE,//  8
  SPECIAL_TOKENS.ISREL,      //  9
  SPECIAL_TOKENS.ISIRREL,    // 10
  SPECIAL_TOKENS.ISSUP,      // 11
  SPECIAL_TOKENS.ISNOSUP,    // 12
  SPECIAL_TOKENS.ISUSE,      // 13
  SPECIAL_TOKENS.THREAT,     // 14
  SPECIAL_TOKENS.CONTROL,    // 15
  SPECIAL_TOKENS.RESOURCE,   // 16
  SPECIAL_TOKENS.MITRE,      // 17
];

const N_SPECIAL    = SPECIAL_LIST.length;   // 18
const BYTE_OFFSET  = N_SPECIAL;             // byte token IDs: 18–273
const MERGE_OFFSET = BYTE_OFFSET + 256;     // merge result IDs: 274+

/** Numeric ID constants for every special token. */
export const SPECIAL_IDS = Object.freeze({
  PAD: 0, BOS: 1, EOS: 2, UNK: 3,
  HDR_START: 4, HDR_END: 5, EOT: 6,
  RETRIEVE: 7, NO_RETRIEVE: 8,
  ISREL: 9, ISIRREL: 10,
  ISSUP: 11, ISNOSUP: 12, ISUSE: 13,
  THREAT: 14, CONTROL: 15, RESOURCE: 16, MITRE: 17,
});

// ─────────────────────────────────────────────────────────────────────────────
//  Placeholder BPE merge rules  (~160 common English + security merges)
//
//  Format: [leftTokenString, rightTokenString]
//  Priority: lower array index = higher priority (merged first).
//
//  The tokenizer works with these rules immediately (byte fallback ensures all
//  text is encodable).  After `python scripts/export_vocab.py`, replace by
//  calling  tokenizer.loadVocab({ merges: [...], extra: {...} }).
// ─────────────────────────────────────────────────────────────────────────────
const PLACEHOLDER_MERGES = [
  // ── Tier 1: space + single letter (very high frequency) ────────────────────
  [' ', 't'], [' ', 'a'], [' ', 'o'], [' ', 'i'], [' ', 's'],
  [' ', 'w'], [' ', 'b'], [' ', 'h'], [' ', 'f'], [' ', 'c'],
  [' ', 'd'], [' ', 'r'], [' ', 'p'], [' ', 'm'], [' ', 'e'],
  [' ', 'n'], [' ', 'l'], [' ', 'g'], [' ', 'u'], [' ', 'v'],

  // ── Tier 2: common letter bigrams ──────────────────────────────────────────
  ['t', 'h'], ['h', 'e'], ['i', 'n'], ['e', 'r'], ['a', 'n'],
  ['r', 'e'], ['o', 'n'], ['e', 'n'], ['a', 't'], ['e', 'd'],
  ['i', 's'], ['o', 'r'], ['i', 't'], ['e', 's'], ['a', 'r'],
  ['a', 'l'], ['l', 'e'], ['n', 't'], ['o', 'u'], ['s', 't'],
  ['a', 's'], ['u', 'r'], ['i', 'c'], ['l', 'l'], ['o', 'w'],
  ['p', 'r'], ['e', 'c'], ['e', 'a'], ['i', 'o'], ['l', 'y'],

  // ── Tier 3: common English words ───────────────────────────────────────────
  [' t', 'h'], [' th', 'e'],           // ' the'
  [' a', 'n'], [' an', 'd'],           // ' and'
  [' o', 'f'],                          // ' of'
  [' o', 'r'],                          // ' or'
  [' i', 'n'],                          // ' in'
  [' t', 'o'],                          // ' to'
  [' i', 's'],                          // ' is'
  [' w', 'it'], [' wi', 'th'],          // ' with'
  [' f', 'or'],                         // ' for'
  [' n', 'ot'],                         // ' not'
  [' b', 'e'],                          // ' be'
  [' a', 'r'], [' ar', 'e'],            // ' are'
  [' h', 'as'],                         // ' has'
  [' w', 'as'],                         // ' was'
  [' b', 'ut'],                         // ' but'
  [' th', 'at'],                        // ' that'
  [' th', 'is'],                        // ' this'
  [' ha', 've'],                        // ' have'
  [' fr', 'om'],                        // ' from'
  [' th', 'ey'],                        // ' they'
  [' al', 'l'],                         // ' all'
  [' ca', 'n'],                         // ' can'

  // ── Tier 4: common English suffixes ────────────────────────────────────────
  ['i', 'ng'], ['in', 'g'],
  ['t', 'ion'], ['ti', 'on'], ['tio', 'n'],
  ['a', 'tion'],
  ['e', 'tion'],
  ['a', 'ted'],
  ['i', 'zed'],
  ['e', 'ment'],
  ['i', 'cal'], ['ic', 'al'],
  ['i', 'ty'],
  ['al', 'ly'],
  ['i', 've'],
  ['e', 'rs'],
  ['i', 'ze'],
  ['i', 'ble'],

  // ── Tier 5: security domain tokens ─────────────────────────────────────────
  ['C', 'V'], ['CV', 'E'],               // CVE
  ['A', 'W'], ['AW', 'S'],               // AWS
  ['I', 'A'], ['IA', 'M'],               // IAM
  ['V', 'P'], ['VP', 'C'],               // VPC
  ['S', '3'],                             // S3
  ['E', 'C'], ['EC', '2'],               // EC2
  ['R', 'D'], ['RD', 'S'],               // RDS
  ['E', 'K'], ['EK', 'S'],               // EKS
  ['L', 'am'], ['Lam', 'bda'],           // Lambda
  ['T', 'er'], ['Ter', 'ra'], ['Terra', 'form'],  // Terraform
  ['M', 'IT'], ['MIT', 'RE'],            // MITRE
  ['S', 'TR'], ['STR', 'ID'], ['STRID', 'E'],     // STRIDE
  ['H', 'IP'], ['HIP', 'AA'],            // HIPAA
  ['G', 'DP'], ['GDP', 'R'],             // GDPR
  ['F', 'ed'], ['Fed', 'RA'], ['FedRA', 'MP'],    // FedRAMP
  ['C', 'IS'],                            // CIS
  ['N', 'IS'], ['NIS', 'T'],             // NIST
  ['S', 'OC'],                            // SOC
  ['P', 'CI'],                            // PCI
  ['CM', 'MC'],                           // CMMC
  [' s', 'ec'], [' se', 'cur'], [' secu', 'rity'],        // ' security'
  [' r', 'es'], [' re', 'sou'], [' resou', 'rce'],        // ' resource'
  [' c', 'on'], [' co', 'nf'], [' con', 'fig'],           // ' config'
  [' p', 'ol'], [' po', 'lic'], [' poli', 'cy'],          // ' policy'
  [' t', 'hr'], [' th', 'reat'],                           // ' threat'
  [' a', 'cc'], [' ac', 'ces'], [' acce', 'ss'],          // ' access'
  [' n', 'et'], [' ne', 'tw'], [' netw', 'ork'],          // ' network'
  [' e', 'nc'], [' en', 'cr'], [' encr', 'ypt'],          // ' encrypt'
  [' a', 'ut'], [' au', 'th'], [' auth', 'or'],           // ' author'
  [' l', 'og'], [' lo', 'gg'], [' logg', 'ing'],          // ' logging'
  [' d', 'at'], [' da', 'ta'],                             // ' data'
  [' v', 'ul'], [' vu', 'ln'], [' vuln', 'er'],           // ' vulner'
  [' f', 'ir'], [' fi', 'rew'], [' firew', 'all'],        // ' firewall'
  [' m', 'on'], [' mo', 'nit'], [' moni', 'tor'],         // ' monitor'
  [' c', 'om'], [' co', 'mpl'], [' compl', 'ian'],        // ' complian'
  [' tr', 'ust'],                                           // ' trust'
  [' ro', 'le'],                                            // ' role'
  [' bu', 'cket'],                                          // ' bucket'
  [' sub', 'net'],                                          // ' subnet'
  [' key', 's'],                                            // ' keys'
  [' cr', 'ed'], [' cred', 'ential'],                      // ' credential'

  // ── Tier 6: numbers and punctuation ────────────────────────────────────────
  ['1', '0'], ['2', '0'], ['1', '2'], ['1', '9'], ['2', '4'],
  ['0', '.'], ['1', '.'], ['2', '.'],
  ['_', '_'],
  ['-', '-'],
  ['.', '.'], ['..', '.'],
  ['/', '/'],
  [':', ':'],
  ['=', '='],
  ['!', '='],
];

// ─────────────────────────────────────────────────────────────────────────────
//  BPETokenizer
// ─────────────────────────────────────────────────────────────────────────────

export class BPETokenizer {
  /**
   * @param {object} [opts]
   * @param {Array<[string,string]>} [opts.merges]  BPE merge rules in priority order
   */
  constructor({ merges = PLACEHOLDER_MERGES } = {}) {
    // ── Lookup tables ─────────────────────────────────────────────────────────
    /** @type {(string|null)[]} id → token string */
    this._id2str = [];
    /** @type {Map<string,number>} token string → id */
    this._str2id = new Map();

    // Merge pair (id_left, id_right) → {rank, resultId}
    // Packed key: idLeft * PACK + idRight   (PACK > max vocab size)
    const PACK = 40003; // prime > 40000, vocab stays < 40K
    this._PACK = PACK;
    /** @type {Map<number,number>} packed pair → merge rank */
    this._mRank   = new Map();
    /** @type {Map<number,number>} packed pair → merged token ID */
    this._mResult = new Map();

    // ── 1. Special tokens (IDs 0 – N_SPECIAL-1) ──────────────────────────────
    for (let i = 0; i < SPECIAL_LIST.length; i++) {
      this._reg(SPECIAL_LIST[i], i);
    }

    // ── 2. Byte tokens (IDs BYTE_OFFSET … BYTE_OFFSET+255) ───────────────────
    for (let b = 0; b < 256; b++) {
      this._reg(BYTE_STRS[b], BYTE_OFFSET + b);
    }

    // ── 3. Build merge table ──────────────────────────────────────────────────
    // Process merges in priority order.  Each merge may create a new token
    // (merged string) that subsequent merges can reference.
    let nextId = MERGE_OFFSET;
    for (let rank = 0; rank < merges.length; rank++) {
      const pair = merges[rank];
      if (!pair || pair.length < 2) continue;
      const [lStr, rStr] = pair;
      const lId = this._str2id.get(lStr);
      const rId = this._str2id.get(rStr);
      if (lId === undefined || rId === undefined) continue; // unknown piece; skip

      const merged   = lStr + rStr;
      let mergedId   = this._str2id.get(merged);
      if (mergedId === undefined) {
        mergedId = nextId++;
        this._reg(merged, mergedId);
      }

      const key = lId * PACK + rId;
      if (!this._mRank.has(key)) { // first (highest-priority) merge wins
        this._mRank.set(key, rank);
        this._mResult.set(key, mergedId);
      }
    }

    this.vocabSize = nextId;

    // ── Regexes ───────────────────────────────────────────────────────────────

    // Pre-tokenisation: Unicode-aware split into "words"
    // Handles: English contractions | Unicode letter runs | digit runs |
    //          punctuation sequences | whitespace
    this._preTokRE = new RegExp(
      "(?:'s|'t|'re|'ve|'m|'ll|'d)" +
      '|[^\\r\\n\\p{L}\\p{N}]?\\p{L}+' +
      '|\\p{N}{1,4}' +
      '| ?[^\\s\\p{L}\\p{N}]+[\\r\\n]*' +
      '|\\s*[\\r\\n]+' +
      '|\\s+',
      'gu'
    );

    // Special-token isolation regex (longest token first to avoid prefix matches)
    const esc = SPECIAL_LIST
      .slice()
      .sort((a, b) => b.length - a.length)
      .map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    this._specialRE = new RegExp(esc.join('|'), 'g');

    // Shared TextEncoder (UTF-8 byte extraction)
    this._enc = new TextEncoder();
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  /** Register a token string ↔ id mapping. */
  _reg(str, id) {
    this._str2id.set(str, id);
    while (this._id2str.length <= id) this._id2str.push(null);
    this._id2str[id] = str;
  }

  /** Convert a pre-token string to an array of byte token IDs. */
  _toByte(word) {
    const bytes = this._enc.encode(word);
    const ids   = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) ids[i] = BYTE_OFFSET + bytes[i];
    return ids;
  }

  /**
   * Apply BPE merges to an array of token IDs.
   * Greedily finds and applies the highest-priority (lowest rank) adjacent pair
   * until no more merges are possible.
   * @param {number[]} ids
   * @returns {number[]}
   */
  _bpe(ids) {
    if (ids.length <= 1) return ids;
    const arr = ids.slice();
    for (;;) {
      let bestRank = Infinity;
      let bestIdx  = -1;
      for (let i = 0; i < arr.length - 1; i++) {
        const rank = this._mRank.get(arr[i] * this._PACK + arr[i + 1]);
        if (rank !== undefined && rank < bestRank) {
          bestRank = rank;
          bestIdx  = i;
        }
      }
      if (bestIdx === -1) break;
      const mid = this._mResult.get(arr[bestIdx] * this._PACK + arr[bestIdx + 1]);
      arr.splice(bestIdx, 1, mid);
      arr.splice(bestIdx + 1, 1);
    }
    return arr;
  }

  /**
   * Split text into segments, isolating special tokens from plain text.
   * @param {string} text
   * @returns {{ text: string, special: boolean }[]}
   */
  _segs(text) {
    const out = [];
    let last = 0;
    this._specialRE.lastIndex = 0;
    let m;
    while ((m = this._specialRE.exec(text)) !== null) {
      if (m.index > last) out.push({ text: text.slice(last, m.index), special: false });
      out.push({ text: m[0], special: true });
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push({ text: text.slice(last), special: false });
    return out;
  }

  /**
   * Decompose a merge-result token string back into raw byte values.
   *
   * Token strings are concatenations of BYTE_STRS entries:
   *   - Printable ASCII (0x20–0x7E): single character  →  charCodeAt(i) IS the byte
   *   - Non-printable: <XX> two-hex notation  →  parse hex
   *
   * After loading a full trained vocab via loadVocab(), merge tokens may
   * alternatively be proper UTF-8 strings (not byte sequences) — handled by
   * the isUtf8 flag set in that code path.
   *
   * @param {string} tok
   * @returns {number[]}  raw byte values
   */
  _tok2bytes(tok) {
    const bytes = [];
    let i = 0;
    while (i < tok.length) {
      if (tok[i] === '<' && i + 3 < tok.length && tok[i + 3] === '>') {
        // <XX> non-printable byte
        bytes.push(parseInt(tok.slice(i + 1, i + 3), 16));
        i += 4;
      } else {
        // Printable ASCII: charCode equals the byte value (0x20–0x7E range)
        bytes.push(tok.charCodeAt(i));
        i++;
      }
    }
    return bytes;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Encode a string to token IDs.
   *
   * @param {string}  text
   * @param {object}  [opts]
   * @param {boolean} [opts.addBos=false]  prepend BOS token
   * @param {boolean} [opts.addEos=false]  append  EOS token
   * @returns {Int32Array}
   */
  encode(text, { addBos = false, addEos = false } = {}) {
    if (typeof text !== 'string') throw new TypeError('encode: expected a string');

    // Normalise: NFC, strip BOM, unify line endings
    text = text.normalize('NFC')
               .replace(/^\uFEFF/, '')
               .replace(/\r\n/g, '\n')
               .replace(/\r/g, '\n');

    const out = [];
    if (addBos) out.push(SPECIAL_IDS.BOS);

    for (const seg of this._segs(text)) {
      if (seg.special) {
        const id = this._str2id.get(seg.text);
        if (id !== undefined) out.push(id);
        continue;
      }
      // Pre-tokenise the plain-text chunk, then BPE-encode each piece
      for (const [piece] of seg.text.matchAll(this._preTokRE)) {
        const merged = this._bpe(this._toByte(piece));
        for (const id of merged) out.push(id);
      }
    }

    if (addEos) out.push(SPECIAL_IDS.EOS);
    return new Int32Array(out);
  }

  /**
   * Decode token IDs → UTF-8 string.
   *
   * Byte tokens are accumulated before decoding so that multi-byte sequences
   * (e.g. UTF-8 for non-ASCII characters) are reconstructed correctly.
   *
   * @param {Int32Array|number[]} ids
   * @returns {string}
   */
  decode(ids) {
    const byteAcc = [];
    let result = '';

    const flush = () => {
      if (!byteAcc.length) return;
      result += new TextDecoder('utf-8', { fatal: false })
        .decode(new Uint8Array(byteAcc));
      byteAcc.length = 0;
    };

    for (const id of ids) {
      if (id < 0 || id >= this._id2str.length) continue;
      const tok = this._id2str[id];
      if (tok === null) continue;

      // Special tokens: output the raw string (skip padding)
      if (id < N_SPECIAL) {
        flush();
        if (id !== SPECIAL_IDS.PAD) result += tok;
        continue;
      }

      // Byte tokens (18–273): single raw byte
      if (id >= BYTE_OFFSET && id < MERGE_OFFSET) {
        byteAcc.push(id - BYTE_OFFSET);
        continue;
      }

      // Merge result token: decompose to constituent bytes, then flush as UTF-8
      // (handles both placeholder byte-sequence tokens and trained UTF-8 tokens)
      if (this._isUtf8Token(tok)) {
        // Trained vocab: token string IS the decoded text
        flush();
        result += tok;
      } else {
        // Placeholder: token is a concatenation of BYTE_STRS
        const bs = this._tok2bytes(tok);
        for (const b of bs) byteAcc.push(b);
      }
    }

    flush();
    return result;
  }

  /**
   * Determine if a merge token string can be output directly as UTF-8 text
   * (i.e., it does not contain any raw byte-level <XX> or non-printable chars).
   * Used in decode to distinguish trained-vocab tokens from placeholder tokens.
   * @param {string} tok
   * @returns {boolean}
   */
  _isUtf8Token(tok) {
    // A token is a "utf8 token" if it contains no <XX> escape sequences
    // and no raw non-printable ASCII (i.e., it's a proper Unicode string)
    return !/^(?:[^\x80-\xFF])*$/.test(tok) === false
      ? false
      : !/<[0-9A-Fa-f]{2}>/.test(tok);
  }

  // ── Chat template (LLaMA-3 instruct format) ───────────────────────────────

  /**
   * Format a message array as a LLaMA-3 instruct prompt string.
   *
   * @param {Array<{ role: 'system'|'user'|'assistant', content: string }>} messages
   * @param {boolean} [addGenStart=true]
   *   When true, appends "<|start_header_id|>assistant<|end_header_id|>\n\n"
   *   so the model continues from the assistant turn (used during generation).
   *   Set false to score a complete conversation (e.g. for LoRA training loss).
   * @returns {string}
   */
  applyTemplate(messages, addGenStart = true) {
    const { BOS, HDR_START, HDR_END, EOT } = SPECIAL_TOKENS;
    let s = BOS;
    for (const { role, content } of messages) {
      s += `${HDR_START}${role}${HDR_END}\n\n${content}${EOT}`;
    }
    if (addGenStart) s += `${HDR_START}assistant${HDR_END}\n\n`;
    return s;
  }

  /**
   * Encode a chat conversation directly (template + encode in one call).
   * @param {Array<{ role, content }>} messages
   * @param {boolean} [addGenStart=true]
   * @returns {Int32Array}
   */
  encodeChat(messages, addGenStart = true) {
    return this.encode(this.applyTemplate(messages, addGenStart));
  }

  /** Count tokens without retaining the full ID array. */
  countTokens(text) {
    return this.encode(text).length;
  }

  /** Encode multiple texts. */
  encodeBatch(texts) {
    return texts.map(t => this.encode(t));
  }

  /**
   * Load a full trained vocabulary (output of `python scripts/export_vocab.py`).
   *
   * Expected format:
   * {
   *   merges: [ [leftStr, rightStr], … ],   // merge rules in priority order
   *   extra:  { tokenString: id, … }         // additional pre-trained tokens
   * }
   *
   * Tokens in `extra` are stored directly — their strings ARE the decoded text
   * (e.g. { " the": 274, " and": 275, … }).  This enables fast, clean decoding
   * of the trained vocab without the byte-decomposition path.
   *
   * @param {{ merges: string[][], extra?: Record<string,number> }} vocabData
   */
  loadVocab(vocabData) {
    // Build a fresh tokenizer with the new merge table
    const fresh = new BPETokenizer({ merges: vocabData.merges ?? [] });

    // Register extra (direct-string) tokens
    if (vocabData.extra) {
      for (const [tok, id] of Object.entries(vocabData.extra)) {
        if (!fresh._str2id.has(tok)) {
          fresh._reg(tok, id);
          if (fresh.vocabSize <= id) fresh.vocabSize = id + 1;
        }
      }
    }

    // Swap all state onto this instance (so existing references to tokenizer still work)
    this._id2str   = fresh._id2str;
    this._str2id   = fresh._str2id;
    this._mRank    = fresh._mRank;
    this._mResult  = fresh._mResult;
    this._PACK     = fresh._PACK;
    this.vocabSize = fresh.vocabSize;
    this._specialRE = fresh._specialRE;
    // _preTokRE and _enc are identical across instances
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Singleton
//  Import `tokenizer` everywhere; call loadVocab() once after training.
// ─────────────────────────────────────────────────────────────────────────────

export const tokenizer = new BPETokenizer();
export default tokenizer;

// ─────────────────────────────────────────────────────────────────────────────
//  LRU encode cache
//  Caches the most recent 1000 encode() results so repeated prompts
//  (system prompt, common prefixes) don't re-run the BPE loop.
// ─────────────────────────────────────────────────────────────────────────────
const _ENC_CACHE_MAX = 1000;
const _encCache = new Map(); // key: text+addBos+addEos → Int32Array

/**
 * Cached encode — same API as tokenizer.encode() but caches results.
 * @param {string} text
 * @param {{ addBos?: boolean, addEos?: boolean }} [opts]
 * @returns {Int32Array}
 */
export function encodeCached(text, opts = {}) {
  const key = `${opts.addBos ? '1' : '0'}${opts.addEos ? '1' : '0'}|${text}`;
  if (_encCache.has(key)) return _encCache.get(key);
  const result = tokenizer.encode(text, opts);
  // Evict oldest entry when at capacity
  if (_encCache.size >= _ENC_CACHE_MAX) {
    _encCache.delete(_encCache.keys().next().value);
  }
  _encCache.set(key, result);
  return result;
}

/** Clear the encode cache (call after loadVocab if merge rules changed). */
export function clearEncodeCache() {
  _encCache.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Lazy full-vocab loader
//  Ships with ~160 placeholder merges.  Call `ensureVocab()` once at startup
//  to replace them with the full 32K trained vocabulary from IndexedDB or the
//  bundled vocab_merges.json (generated by scripts/export_vocab.py).
// ─────────────────────────────────────────────────────────────────────────────

let _vocabLoaded = false;
let _vocabLoading = null;

/**
 * Lightweight IndexedDB helpers — standalone so Tokenizer.js has no external deps.
 * Uses the same DB name/version as the rest of the app.
 */
function _idbOpen() {
  return new Promise((res, rej) => {
    const req = indexedDB.open('threataform-vectors', 2);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
    };
    req.onsuccess = e => res(e.target.result);
    req.onerror   = () => rej(req.error);
  });
}

async function _idbGet(key) {
  try {
    const db = await _idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', 'readonly');
      const req = tx.objectStore('kv').get(key);
      req.onsuccess = () => { db.close(); res(req.result); };
      req.onerror   = () => { db.close(); rej(req.error); };
    });
  } catch { return undefined; }
}

async function _idbPut(key, value) {
  try {
    const db = await _idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', 'readwrite');
      const req = tx.objectStore('kv').put(value, key);
      req.onsuccess = () => { db.close(); res(); };
      req.onerror   = () => { db.close(); rej(req.error); };
    });
  } catch { /* silently ignore IDB write failures */ }
}

/**
 * Ensure the tokenizer has a full trained vocabulary loaded.
 *
 * Priority:
 *   1. Already loaded (no-op)
 *   2. IndexedDB cache (key: 'tf-vocab-v1')
 *   3. Bundled vocab_merges.json (next to this file, generated by export_vocab.py)
 *
 * If neither the cache nor the JSON file is available the tokenizer continues
 * with the placeholder 160-merge rules — everything still works, just with more
 * tokens per piece of text.
 *
 * @returns {Promise<boolean>} true if full vocab was loaded, false if placeholder kept
 */
export async function ensureVocab() {
  if (_vocabLoaded) return true;
  if (_vocabLoading) return _vocabLoading;

  _vocabLoading = (async () => {
    // Already has a substantial vocab? (e.g. previously loaded via loadVocab())
    if (tokenizer._mRank.size > 500) { _vocabLoaded = true; return true; }

    // Try IndexedDB cache first (fast, avoids network fetch on repeat loads)
    try {
      const cached = await _idbGet('tf-vocab-v1');
      if (cached && Array.isArray(cached.merges) && cached.merges.length > 500) {
        tokenizer.loadVocab(cached);
        clearEncodeCache();
        _vocabLoaded = true;
        return true;
      }
    } catch { /* fall through to fetch */ }

    // Try fetching the bundled JSON produced by scripts/export_vocab.py
    // Tries vocab.json first (sentencepiece export), then vocab_merges.json (tiktoken export)
    try {
      const candidates = ['./vocab.json', './vocab_merges.json'];
      let resp = null;
      for (const name of candidates) {
        try {
          const r = await fetch(new URL(name, import.meta.url), { priority: 'low' });
          if (r.ok) { resp = r; break; }
        } catch { /* try next */ }
      }
      if (!resp) throw new Error('no vocab file found');
      const data = await resp.json();
      // Support both {merges, extra} object (sentencepiece export) and
      // bare [[l,r],...] array (tiktoken export).
      const vocabData = (data && !Array.isArray(data) && data.merges) ? data : { merges: data };
      if (Array.isArray(vocabData.merges) && vocabData.merges.length > 500) {
        tokenizer.loadVocab(vocabData);
        clearEncodeCache();
        // Cache in IDB for next load (avoids fetch on subsequent page loads)
        await _idbPut('tf-vocab-v1', vocabData);
        _vocabLoaded = true;
        return true;
      }
    } catch { /* vocab file not found or parse error — stay with placeholders */ }

    return false;
  })();

  return _vocabLoading;
}
