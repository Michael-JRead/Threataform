/**
 * src/lib/ingestion/MarkupExtractor.js
 * Extracts clean text from HTML, Markdown, and RST files.
 * Pure JS — no external dependencies.
 */

/** Convert Markdown to plain text. */
export function extractMarkdown(text) {
  let out = text
    // Remove code fences (keep content)
    .replace(/```[\w]*\n?([\s\S]*?)```/g, '\n[code]\n$1\n[/code]\n')
    // Remove inline code
    .replace(/`([^`]+)`/g, '$1')
    // Remove ATX headings markup (keep text)
    .replace(/^#{1,6}\s+(.+)$/gm, '$1')
    // Remove setext heading underlines
    .replace(/^[=-]{2,}$/gm, '')
    // Bold / italic
    .replace(/\*{1,3}([^*]+)\*{1,3}/g, '$1')
    .replace(/_{1,3}([^_]+)_{1,3}/g, '$1')
    // Links: [text](url) → text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Images: ![alt](url) → alt
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, '$1')
    // Blockquotes
    .replace(/^>\s*/gm, '')
    // Unordered list items
    .replace(/^[ \t]*[-*+]\s+/gm, '• ')
    // Ordered list items
    .replace(/^[ \t]*\d+\.\s+/gm, '• ')
    // Horizontal rules
    .replace(/^[-*_]{3,}$/gm, '')
    // HTML entities
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    // Collapse excess blank lines
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return { text: out, metadata: { type: 'markdown' } };
}

/** Strip HTML tags and extract plain text. */
export function extractHTML(html) {
  // Use DOMParser if available (browser context)
  if (typeof DOMParser !== 'undefined') {
    const doc    = new DOMParser().parseFromString(html, 'text/html');
    // Remove scripts and styles
    doc.querySelectorAll('script, style, noscript, iframe').forEach(el => el.remove());
    const text = _walkDOM(doc.body ?? doc.documentElement);
    return { text: text.trim(), metadata: { type: 'html', title: doc.title ?? '' } };
  }
  // Fallback: regex strip
  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ')
    .replace(/\s{2,}/g, ' ').trim();
  return { text, metadata: { type: 'html' } };
}

function _walkDOM(node) {
  if (!node) return '';
  if (node.nodeType === 3) return node.textContent + ' '; // text node
  const tag  = node.tagName?.toLowerCase() ?? '';
  const BLOCK = new Set(['p', 'div', 'section', 'article', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                          'li', 'tr', 'td', 'th', 'blockquote', 'pre', 'br', 'hr']);
  let   out  = '';
  for (const child of node.childNodes) out += _walkDOM(child);
  return BLOCK.has(tag) ? '\n' + out + '\n' : out;
}

/** Convert RST (reStructuredText) to plain text. */
export function extractRST(text) {
  let out = text
    .replace(/^={3,}$/gm, '').replace(/^-{3,}$/gm, '').replace(/^~{3,}$/gm, '')
    .replace(/^\.\.\s+\w+::.*/gm, '')   // directives
    .replace(/^:[\w]+:/gm, '')           // field lists
    .replace(/\*\*([^*]+)\*\*/g, '$1')   // bold
    .replace(/\*([^*]+)\*/g, '$1')       // italic
    .replace(/``([^`]+)``/g, '$1')       // inline code
    .replace(/`([^`]+)`_/g, '$1')        // links
    .replace(/\n{3,}/g, '\n\n').trim();
  return { text: out, metadata: { type: 'rst' } };
}
