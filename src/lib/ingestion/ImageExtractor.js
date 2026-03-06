/**
 * src/lib/ingestion/ImageExtractor.js
 * OCR for images using Tesseract.js (lazy-loaded).
 * Only loaded when the user uploads an image file.
 */

let tesseractWorker = null;

async function getTesseract() {
  if (!tesseractWorker) {
    try {
      const { createWorker } = await import('tesseract.js');
      tesseractWorker = await createWorker('eng');
    } catch {
      throw new Error('tesseract.js not installed. Run: npm install tesseract.js');
    }
  }
  return tesseractWorker;
}

/**
 * Extract text from an image file via OCR.
 * @param {File|Blob|string} input  File object, Blob, or data URL
 * @returns {Promise<{ text, metadata, tables, codeBlocks }>}
 */
export async function extractImage(input) {
  try {
    const worker = await getTesseract();
    const { data: { text, confidence, blocks } } = await worker.recognize(input);

    // Try to detect table-like structures from bounding box data
    const tables = [];
    if (blocks) {
      const rows = _detectTableRows(blocks);
      if (rows.length >= 2) {
        tables.push({ headers: rows[0], rows: rows.slice(1) });
      }
    }

    return {
      text:       text.trim(),
      metadata:   { type: 'image', ocrConfidence: confidence },
      tables,
      codeBlocks: [],
    };
  } catch (err) {
    return {
      text:       `[OCR failed: ${err.message}]`,
      metadata:   { type: 'image', error: err.message },
      tables:     [],
      codeBlocks: [],
    };
  }
}

function _detectTableRows(blocks) {
  // Simplified: group words by approximate y-coordinate
  const byY = new Map();
  for (const block of blocks) {
    for (const par of block.paragraphs ?? []) {
      for (const line of par.lines ?? []) {
        const y   = Math.round(line.bbox.y0 / 20) * 20;
        const row = byY.get(y) ?? [];
        const words = (line.words ?? []).map(w => w.text).join(' ');
        row.push(words);
        byY.set(y, row);
      }
    }
  }
  return Array.from(byY.values()).filter(r => r.length >= 2);
}
