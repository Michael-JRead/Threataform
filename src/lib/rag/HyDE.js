/**
 * src/lib/rag/HyDE.js
 * Hypothetical Document Embeddings (Gao et al. 2022)
 *
 * Instead of embedding the raw query, we:
 *   1. Generate a short hypothetical answer to the query (no retrieval yet)
 *   2. Embed that hypothetical document
 *   3. Average hypothetical + original query embeddings
 *   4. Use the averaged embedding for retrieval
 *
 * This produces a much richer retrieval signal for complex questions.
 *
 * Usage:
 *   const { hydeVec, hydeText } = await hydeExpand(query, model, tokenizer);
 *   const results = vectorStore.search(hydeVec, topK);
 */

/**
 * HyDE query expansion.
 *
 * @param {string}          query
 * @param {ThreataformLM}   model
 * @param {BPETokenizer}    tokenizer
 * @param {object}          [opts]
 * @param {number}          [opts.maxNew=150]    Max tokens for hypothetical doc
 * @param {number}          [opts.temp=0.3]      Low temp → more factual hypothesis
 * @param {string}          [opts.systemPrompt]  Override system prompt
 * @returns {Promise<{ hydeVec: Float32Array, hydeText: string, queryVec: Float32Array }>}
 */
export async function hydeExpand(query, model, tokenizer, {
  maxNew = 150,
  temp   = 0.3,
  systemPrompt = 'You are a cybersecurity expert. Write a concise, factual answer to the following question about threat modeling, cloud security, or infrastructure risks.',
} = {}) {
  // 1. Build hypothesis generation prompt
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user',   content: `Question: ${query}\n\nProvide a direct, factual answer:` },
  ];
  const promptIds = tokenizer.encodeChat(messages);

  // 2. Generate hypothetical document
  let hydeText = '';
  for await (const tokId of model.generate(promptIds, { maxNew, temp, topP: 0.85 })) {
    hydeText += tokenizer.decode([tokId]);
  }
  hydeText = hydeText.trim();

  // 3. Embed hypothetical document
  const hydeIds = tokenizer.encode(hydeText);
  const hydeVec = model.embed(hydeIds);

  // 4. Embed original query
  const queryIds = tokenizer.encode(query);
  const queryVec = model.embed(queryIds);

  // 5. Average the two vectors (equal weight)
  const dim      = model.cfg.dim;
  const avgVec   = new Float32Array(dim);
  let   norm     = 0;
  for (let i = 0; i < dim; i++) {
    avgVec[i] = (hydeVec[i] + queryVec[i]) * 0.5;
    norm += avgVec[i] * avgVec[i];
  }
  norm = Math.sqrt(norm);
  if (norm > 1e-10) for (let i = 0; i < dim; i++) avgVec[i] /= norm;

  return { hydeVec: avgVec, hydeText, queryVec };
}

/**
 * Lightweight HyDE without generation (uses a template-based hypothetical doc).
 * Useful when the model isn't loaded yet (fallback mode).
 *
 * @param {string}       query
 * @param {BPETokenizer} tokenizer
 * @param {Function}     embedFn   (text: string) => Float32Array
 * @returns {Promise<Float32Array>}
 */
export async function hydeTemplate(query, tokenizer, embedFn) {
  // Expand with security-domain templates
  const templates = [
    `This document discusses: ${query}`,
    `Security analysis of ${query}: The primary risks include unauthorized access, data exposure, and compliance violations.`,
    `Threat model for ${query}: STRIDE threats — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.`,
  ];

  const vecs = await Promise.all(templates.map(t => embedFn(t)));

  // Average all template embeddings + original query
  const queryVec = await embedFn(query);
  vecs.push(queryVec);

  const dim = queryVec.length;
  const avg = new Float32Array(dim);
  for (const v of vecs) {
    for (let i = 0; i < dim; i++) avg[i] += v[i] / vecs.length;
  }

  // L2 normalize
  let n = 0;
  for (let i = 0; i < dim; i++) n += avg[i] * avg[i];
  n = Math.sqrt(n);
  if (n > 1e-10) for (let i = 0; i < dim; i++) avg[i] /= n;

  return avg;
}
