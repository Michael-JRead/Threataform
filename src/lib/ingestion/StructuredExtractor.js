/**
 * src/lib/ingestion/StructuredExtractor.js
 * Converts structured data (JSON, YAML, HCL, XML, TOML, CSV) to annotated text.
 * Pure JS — no external dependencies for JSON/CSV/XML; TOML/YAML use simple parsers.
 */

/** JSON → annotated flat text. */
export function extractJSON(text) {
  try {
    const obj = JSON.parse(text);
    const lines = [];
    _flattenObj(obj, '', lines);
    return { text: lines.join('\n'), metadata: { type: 'json' }, codeBlocks: [] };
  } catch {
    return { text: text, metadata: { type: 'json', parseError: true }, codeBlocks: [] };
  }
}

function _flattenObj(val, prefix, lines, depth = 0) {
  if (depth > 12) return;
  if (Array.isArray(val)) {
    val.forEach((v, i) => _flattenObj(v, prefix ? `${prefix}[${i}]` : `[${i}]`, lines, depth + 1));
  } else if (val !== null && typeof val === 'object') {
    for (const [k, v] of Object.entries(val)) {
      _flattenObj(v, prefix ? `${prefix}.${k}` : k, lines, depth + 1);
    }
  } else {
    if (prefix) lines.push(`${prefix}: ${val}`);
  }
}

/** YAML → annotated text (simplified parser — handles common cases). */
export function extractYAML(text) {
  // Parse key: value pairs (non-nested), nested via indentation
  const lines = text.split('\n');
  const result = [];
  const stack  = [{ indent: -1, key: '' }];

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const match  = line.trim().match(/^(-\s+)?([^:]+?):\s*(.*)$/);
    if (!match) {
      // Plain value (list item without key)
      result.push(`${stack.map(s => s.key).filter(Boolean).join('.')}: ${line.trim().replace(/^-\s*/, '')}`);
      continue;
    }
    const [, , key, val] = match;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    stack.push({ indent, key: key.trim() });
    const fullKey = stack.map(s => s.key).filter(Boolean).join('.');
    if (val.trim()) result.push(`${fullKey}: ${val.trim()}`);
  }

  return { text: result.join('\n'), metadata: { type: 'yaml' }, codeBlocks: [] };
}

/** HCL / Terraform → annotated text. */
export function extractHCL(text) {
  const result = [];
  const resourceRe = /^\s*(resource|data|variable|output|module|locals?)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{/gm;
  const attrRe     = /^\s{1,8}([a-z_]+)\s*=\s*(.+)$/gm;

  let ctx = '';
  let m;
  resourceRe.lastIndex = 0;
  while ((m = resourceRe.exec(text)) !== null) {
    const [, blockType, type, name] = m;
    ctx = name ? `${blockType}.${type}.${name}` : `${blockType}.${type}`;
    result.push(`\n[Resource: ${ctx}]`);
  }

  // Reset and extract all attributes with context
  const lines = text.split('\n');
  let   currentCtx = '';
  for (const line of lines) {
    const resM = line.match(/^\s*(resource|data|variable|output|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{/);
    if (resM) {
      currentCtx = resM[3] ? `${resM[1]}.${resM[2]}.${resM[3]}` : `${resM[1]}.${resM[2]}`;
      result.push(`\n[${currentCtx}]`);
      continue;
    }
    const attrM = line.match(/^\s{1,8}([a-z_]+)\s*=\s*(.+)$/);
    if (attrM && currentCtx) {
      result.push(`  ${currentCtx}.${attrM[1]}: ${attrM[2].replace(/"/g, '').trim()}`);
    }
  }

  // Also extract code blocks
  const codeBlocks = [{ lang: 'hcl', code: text }];

  return {
    text: result.join('\n').trim() || text,
    metadata: { type: 'hcl' },
    codeBlocks,
  };
}

/** XML → plain text (attribute + text content extraction). */
export function extractXML(text) {
  if (typeof DOMParser !== 'undefined') {
    try {
      const doc    = new DOMParser().parseFromString(text, 'application/xml');
      const lines  = [];
      _walkXML(doc.documentElement, '', lines);
      return { text: lines.join('\n'), metadata: { type: 'xml' }, codeBlocks: [] };
    } catch { /* fall through */ }
  }
  // Fallback: strip tags
  const plain = text.replace(/<[^>]+>/g, ' ').replace(/\s{2,}/g, ' ').trim();
  return { text: plain, metadata: { type: 'xml' }, codeBlocks: [] };
}

function _walkXML(node, prefix, lines, depth = 0) {
  if (depth > 10 || !node) return;
  const tag   = node.tagName ?? node.nodeName;
  const attrs = Array.from(node.attributes ?? []).map(a => `${a.name}="${a.value}"`).join(', ');
  const text  = Array.from(node.childNodes)
    .filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(' ').trim();
  const key   = prefix ? `${prefix}.${tag}` : tag;
  if (attrs) lines.push(`${key} [${attrs}]`);
  if (text)  lines.push(`${key}: ${text}`);
  for (const child of node.children ?? []) _walkXML(child, key, lines, depth + 1);
}

/** CSV → sentence-per-row text. */
export function extractCSV(text) {
  const rows    = text.trim().split(/\r?\n/);
  if (rows.length === 0) return { text: '', metadata: { type: 'csv' } };
  const headers = _parseCSVRow(rows[0]);
  const lines   = [];
  for (let i = 1; i < rows.length && i < 5000; i++) {
    if (!rows[i].trim()) continue;
    const vals = _parseCSVRow(rows[i]);
    const parts = headers.map((h, j) => `${h}: ${vals[j] ?? ''}`)
                          .filter(p => !p.endsWith(': '));
    if (parts.length) lines.push(parts.join(', ') + '.');
  }
  const tables = [{ headers, rows: rows.slice(1, 1001).map(_parseCSVRow) }];
  return { text: lines.join('\n'), metadata: { type: 'csv' }, tables };
}

function _parseCSVRow(row) {
  const cells = [];
  let cur = '', inQ = false;
  for (let i = 0; i < row.length; i++) {
    const c = row[i];
    if (c === '"' && !inQ) { inQ = true; continue; }
    if (c === '"' && inQ) { inQ = false; continue; }
    if (c === ',' && !inQ) { cells.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  cells.push(cur.trim());
  return cells;
}
