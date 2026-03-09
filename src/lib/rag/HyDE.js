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
 * Multi-hypothesis HyDE query expansion.
 *
 * Generates N hypothetical answers from different expert perspectives, embeds
 * each, and produces a weighted average embedding that better covers the
 * semantic space around the query.
 *
 * Weights: query=0.5, each hypothesis=0.5/N  (query anchors the result)
 *
 * @param {string}          query
 * @param {ThreataformLM}   model
 * @param {BPETokenizer}    tokenizer
 * @param {object}          [opts]
 * @param {number}          [opts.maxNew=80]     Max tokens per hypothesis
 * @param {number}          [opts.temp=0.4]      Temperature for hypothesis generation
 * @param {number}          [opts.numHyps=3]     Number of hypotheses to generate
 * @returns {Promise<{ hydeVec: Float32Array, hydeTexts: string[], queryVec: Float32Array }>}
 */
export async function hydeExpand(query, model, tokenizer, {
  maxNew  = 80,
  temp    = 0.4,
  numHyps = 3,
} = {}) {
  // Domain-specific system prompts for each hypothesis angle
  const HYPOTHESIS_PROMPTS = [
    'You are a threat modeler. Give a direct expert answer about the security risk or control.',
    'You are a cloud security architect. Describe the AWS infrastructure configuration relevant to the question.',
    'You are a compliance auditor. Identify which security controls or compliance requirements apply.',
  ];

  // 1. Embed original query
  const queryIds = tokenizer.encode(query);
  const queryVec = model.embed(queryIds);

  // 2. Generate and embed N hypotheses in parallel (sequential due to JS single-thread,
  //    but structured for worker-based parallelism)
  const hydeTexts = [];
  const hydeVecs  = [];

  for (let h = 0; h < Math.min(numHyps, HYPOTHESIS_PROMPTS.length); h++) {
    try {
      const messages = [
        { role: 'system', content: HYPOTHESIS_PROMPTS[h] },
        { role: 'user',   content: `Question: ${query}\n\nBrief answer:` },
      ];
      const promptIds = tokenizer.encodeChat(messages);

      let hydeText = '';
      for await (const tokId of model.generate(promptIds, { maxNew, temp, topP: 0.9 })) {
        hydeText += tokenizer.decode([tokId]);
      }
      hydeText = hydeText.trim();
      if (hydeText) {
        hydeTexts.push(hydeText);
        const hydeIds = tokenizer.encode(hydeText);
        hydeVecs.push(model.embed(hydeIds));
      }
    } catch { /* skip failed hypothesis */ }
  }

  // 3. Weighted average: query gets weight 0.5, each hypothesis gets (0.5/N)
  const N    = hydeVecs.length;
  const dim  = queryVec.length;
  const hyWeight = N > 0 ? 0.5 / N : 0;
  const avgVec   = new Float32Array(dim);

  for (let i = 0; i < dim; i++) {
    avgVec[i] = queryVec[i] * 0.5;
    for (const hv of hydeVecs) avgVec[i] += hv[i] * hyWeight;
  }

  // 4. L2 normalize
  let norm = 0;
  for (let i = 0; i < dim; i++) norm += avgVec[i] * avgVec[i];
  norm = Math.sqrt(norm);
  if (norm > 1e-10) for (let i = 0; i < dim; i++) avgVec[i] /= norm;

  return { hydeVec: avgVec, hydeTexts, queryVec };
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
