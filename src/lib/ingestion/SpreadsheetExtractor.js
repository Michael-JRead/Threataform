/**
 * src/lib/ingestion/SpreadsheetExtractor.js
 * Extracts text from XLSX/XLS/CSV files using SheetJS (lazy-loaded).
 */

let XLSX = null;

async function getXLSX() {
  if (!XLSX) {
    try {
      XLSX = await import('xlsx');
    } catch {
      throw new Error('SheetJS not installed. Run: npm install xlsx');
    }
  }
  return XLSX;
}

/**
 * Extract text from a spreadsheet file.
 * @param {ArrayBuffer|File} input
 * @param {string}           [filename]
 * @returns {Promise<{ text, metadata, tables }>}
 */
export async function extractSpreadsheet(input, filename = '') {
  const ext = filename.split('.').pop()?.toLowerCase();

  // CSV: no external dependency
  if (ext === 'csv') {
    const text = input instanceof ArrayBuffer
      ? new TextDecoder().decode(input)
      : await input.text();
    const { extractCSV } = await import('./StructuredExtractor.js');
    return extractCSV(text);
  }

  const xlsx        = await getXLSX();
  const arrayBuffer = input instanceof ArrayBuffer ? input : await input.arrayBuffer();
  const workbook    = xlsx.read(arrayBuffer, { type: 'array' });

  const allText  = [];
  const tables   = [];

  for (const sheetName of workbook.SheetNames) {
    const sheet = workbook.Sheets[sheetName];
    const rows  = xlsx.utils.sheet_to_json(sheet, { header: 1, defval: '' });

    if (rows.length === 0) continue;

    const headers = (rows[0] ?? []).map(String);
    const dataRows = rows.slice(1).map(r => r.map(String));
    tables.push({ sheet: sheetName, headers, rows: dataRows.slice(0, 500) });

    // Convert to annotated sentences
    allText.push(`[Sheet: ${sheetName}]`);
    for (const row of dataRows.slice(0, 2000)) {
      const parts = headers
        .map((h, i) => `${h}: ${row[i] ?? ''}`)
        .filter(p => !p.endsWith(': ') && !p.endsWith(': undefined'));
      if (parts.length) allText.push(parts.join(', ') + '.');
    }
  }

  return {
    text: allText.join('\n'),
    metadata: { type: ext ?? 'xlsx', sheets: workbook.SheetNames },
    tables,
    codeBlocks: [],
  };
}
