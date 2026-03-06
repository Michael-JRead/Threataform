/**
 * src/lib/ingestion/DocxExtractor.js
 * Extracts text from DOCX files using mammoth.js (lazy-loaded).
 */

let mammothMod = null;

async function getMammoth() {
  if (!mammothMod) {
    try {
      mammothMod = await import('mammoth');
    } catch {
      throw new Error('mammoth.js not installed. Run: npm install mammoth');
    }
  }
  return mammothMod;
}

/**
 * Extract text from a DOCX file.
 * @param {ArrayBuffer|File} input
 * @returns {Promise<{ text, metadata, tables, codeBlocks }>}
 */
export async function extractDOCX(input) {
  const mammoth = await getMammoth();
  const arrayBuffer = input instanceof ArrayBuffer ? input : await input.arrayBuffer();

  const { value: html, messages } = await mammoth.convertToHtml({ arrayBuffer });

  // Parse HTML to extract text + tables
  const parser = new DOMParser();
  const doc    = parser.parseFromString(html, 'text/html');

  const tables = [];
  doc.querySelectorAll('table').forEach(table => {
    const headers = Array.from(table.querySelectorAll('tr:first-child th, tr:first-child td'))
                         .map(td => td.textContent.trim());
    const rows    = Array.from(table.querySelectorAll('tr')).slice(1).map(tr =>
      Array.from(tr.querySelectorAll('td, th')).map(td => td.textContent.trim())
    );
    tables.push({ headers, rows });
    // Replace table with annotated text in DOM
    const annot = document.createElement('p');
    annot.textContent = [headers.join(' | '), ...rows.map(r => r.join(' | '))].join('\n');
    table.replaceWith(annot);
  });

  const text = doc.body.textContent.replace(/\s{2,}/g, ' ').trim();

  return {
    text,
    metadata: { type: 'docx', warnings: messages.map(m => m.message) },
    tables,
    codeBlocks: [],
  };
}
