/**
 * src/lib/ingestion/PresentationExtractor.js
 * Extracts text from PPTX files by parsing the ZIP/XML structure directly.
 * No external dependency for basic text extraction.
 */

/**
 * Extract text from a PPTX file.
 * @param {ArrayBuffer|File} input
 * @returns {Promise<{ text, metadata, tables, codeBlocks }>}
 */
export async function extractPPTX(input) {
  const arrayBuffer = input instanceof ArrayBuffer ? input : await input.arrayBuffer();

  // Try JSZip if available
  let zip;
  try {
    const JSZip = (await import('jszip')).default;
    zip = await JSZip.loadAsync(arrayBuffer);
  } catch {
    return { text: '[PPTX extraction requires: npm install jszip]', metadata: { type: 'pptx' }, tables: [], codeBlocks: [] };
  }

  // Find slide XML files (ppt/slides/slide*.xml)
  const slideFiles = Object.keys(zip.files)
    .filter(f => /^ppt\/slides\/slide\d+\.xml$/.test(f))
    .sort((a, b) => {
      const na = parseInt(a.match(/\d+/)[0], 10);
      const nb = parseInt(b.match(/\d+/)[0], 10);
      return na - nb;
    });

  const slides = [];

  for (let i = 0; i < slideFiles.length; i++) {
    const xml    = await zip.files[slideFiles[i]].async('text');
    const texts  = _extractXMLText(xml);
    const title  = texts[0] ?? `Slide ${i + 1}`;
    const body   = texts.slice(1).join(' ');
    slides.push(`[Slide ${i + 1}: ${title}]\n${body}`);
  }

  // Try to get speaker notes
  const notesFiles = Object.keys(zip.files)
    .filter(f => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(f))
    .sort();

  for (let i = 0; i < notesFiles.length; i++) {
    const xml   = await zip.files[notesFiles[i]].async('text');
    const texts = _extractXMLText(xml);
    if (texts.length && slides[i]) {
      slides[i] += `\n[Notes: ${texts.join(' ')}]`;
    }
  }

  return {
    text:       slides.join('\n\n'),
    metadata:   { type: 'pptx', slides: slideFiles.length },
    tables:     [],
    codeBlocks: [],
  };
}

function _extractXMLText(xml) {
  const texts = [];
  const re    = /<a:t>([^<]*)<\/a:t>/g;
  let   m;
  while ((m = re.exec(xml)) !== null) {
    const t = m[1].trim();
    if (t) texts.push(t);
  }
  return texts;
}
