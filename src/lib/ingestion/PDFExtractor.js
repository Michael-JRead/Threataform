/**
 * src/lib/ingestion/PDFExtractor.js
 * Extracts text from PDF files using pdfjs-dist (lazy-loaded).
 */

let pdfjsLib = null;

async function getPDFJS() {
  if (!pdfjsLib) {
    try {
      pdfjsLib = await import('pdfjs-dist');
      // Required worker setup for pdfjs in browser
      if (typeof window !== 'undefined' && !pdfjsLib.GlobalWorkerOptions?.workerSrc) {
        pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;
      }
    } catch {
      throw new Error('pdfjs-dist not installed. Run: npm install pdfjs-dist');
    }
  }
  return pdfjsLib;
}

/**
 * Extract text from a PDF file.
 * @param {ArrayBuffer|File} input
 * @param {object}           [opts]
 * @param {number}           [opts.maxPages=200]
 * @returns {Promise<{ text, metadata, tables, codeBlocks }>}
 */
export async function extractPDF(input, { maxPages = 200 } = {}) {
  const pdfjs       = await getPDFJS();
  const arrayBuffer = input instanceof ArrayBuffer ? input : await input.arrayBuffer();
  const pdf         = await pdfjs.getDocument({ data: arrayBuffer }).promise;
  const numPages    = Math.min(pdf.numPages, maxPages);

  const pageTexts = [];
  const tables    = [];

  for (let p = 1; p <= numPages; p++) {
    const page = await pdf.getPage(p);
    const content = await page.getTextContent();

    // Group items by approximate Y position (rows)
    const byY = new Map();
    for (const item of content.items) {
      const y   = Math.round(item.transform[5] / 10) * 10; // bucket to 10px rows
      const row = byY.get(y) ?? [];
      row.push({ x: item.transform[4], text: item.str });
      byY.set(y, row);
    }

    // Sort rows top-to-bottom, items left-to-right
    const rows = Array.from(byY.entries())
      .sort(([ya], [yb]) => yb - ya)
      .map(([, items]) => items.sort((a, b) => a.x - b.x).map(i => i.text).join(' '));

    // Detect table-like rows (multiple tab-separated columns)
    let tableBuffer = [];
    for (const row of rows) {
      if (_isTableRow(row)) {
        tableBuffer.push(row.split(/\s{3,}/).filter(Boolean));
      } else {
        if (tableBuffer.length >= 2) {
          tables.push({ headers: tableBuffer[0], rows: tableBuffer.slice(1) });
          tableBuffer = [];
        }
        pageTexts.push(row);
      }
    }
    if (tableBuffer.length >= 2) {
      tables.push({ headers: tableBuffer[0], rows: tableBuffer.slice(1) });
    }
  }

  const metadata = { type: 'pdf', pages: pdf.numPages };
  try {
    const info = await pdf.getMetadata();
    Object.assign(metadata, {
      title:   info.info?.Title ?? '',
      author:  info.info?.Author ?? '',
      subject: info.info?.Subject ?? '',
    });
  } catch { /* metadata optional */ }

  return {
    text:       pageTexts.join('\n').replace(/\n{3,}/g, '\n\n').trim(),
    metadata,
    tables,
    codeBlocks: [],
  };
}

function _isTableRow(row) {
  return /\s{3,}/.test(row) && row.trim().length > 10;
}
