/**
 * src/lib/rag/SelfRAG.js
 * Self-Reflective Retrieval-Augmented Generation (Asai et al. 2023)
 *
 * Uses special tokens predicted by the model to decide:
 *   [Retrieve]  — should the model retrieve evidence for this query?
 *   [IsRel]     — is this retrieved passage relevant?
 *   [IsSup]     — does the generated text actually use this passage?
 *   [IsUse]     — is this final response useful? (score 1–5)
 *
 * Usage:
 *   const gen = selfRAGGenerate(query, retriever, model, tokenizer);
 *   for await (const token of gen) {
 *     text += tokenizer.decode([token]);
 *   }
 */

import { SPECIAL_IDS, SPECIAL_TOKENS } from '../llm/Tokenizer.js';
import { packContext } from './VectorStore.js';

// SELF-RAG decision thresholds
const RETRIEVE_THRESHOLD  = 0.4; // P([Retrieve]) > threshold → do retrieval
const ISREL_THRESHOLD     = 0.5; // P([IsRel])    > threshold → keep passage
const ISSUP_THRESHOLD     = 0.4; // P([IsSup])    > threshold → response is supported
const ISUSE_MIN_SCORE     = 3;   // minimum usefulness score (1–5)

/**
 * SELF-RAG generation loop.
 *
 * @param {string}            query
 * @param {HybridRetriever}   retriever
 * @param {ThreataformLM}     model
 * @param {BPETokenizer}      tokenizer
 * @param {object}            [opts]
 * @param {number}            [opts.maxNew=512]
 * @param {number}            [opts.temp=0.7]
 * @param {number}            [opts.topP=0.9]
 * @param {string}            [opts.systemPrompt]
 * @param {number}            [opts.retrievalK=5]
 * @param {Function}          [opts.onToken]
 * @yields {number}  Token IDs
 */
export async function* selfRAGGenerate(query, retriever, model, tokenizer, {
  maxNew        = 512,
  temp          = 0.7,
  topP          = 0.9,
  systemPrompt  = 'You are a threat modeling expert. Analyse security risks for the given infrastructure.',
  retrievalK    = 5,
  onToken       = null,
} = {}) {
  // ── Step 1: Should we retrieve? ──────────────────────────────────────────
  const checkPrompt = tokenizer.encodeChat([
    { role: 'system', content: systemPrompt },
    { role: 'user',   content: query },
  ]);

  const retrieveProb = model.predictTokenProb(checkPrompt, SPECIAL_IDS.RETRIEVE);
  const shouldRetrieve = retrieveProb > RETRIEVE_THRESHOLD;

  // ── Step 2: Retrieve passages ─────────────────────────────────────────────
  let passages = [];
  if (shouldRetrieve) {
    passages = await retriever.retrieve(query, retrievalK);
  }

  // ── Step 3: Filter by [IsRel] ─────────────────────────────────────────────
  const relevantPassages = [];
  for (const passage of passages) {
    const relPrompt = tokenizer.encode(
      `Query: ${query}\nPassage: ${passage.text.slice(0, 300)}\n${SPECIAL_TOKENS.ISREL}`
    );
    const relProb = model.predictTokenProb(relPrompt, SPECIAL_IDS.ISREL);
    if (relProb > ISREL_THRESHOLD) {
      relevantPassages.push({ ...passage, relevanceScore: relProb });
    }
  }

  // Sort by relevance
  relevantPassages.sort((a, b) => b.relevanceScore - a.relevanceScore);

  // ── Step 4: Generate response with relevant passages ──────────────────────
  const contextStr = relevantPassages.length
    ? packContext(relevantPassages, 1200, 'Retrieved Evidence')
    : '';

  const genMessages = [
    { role: 'system',    content: systemPrompt },
    ...(contextStr ? [{ role: 'system', content: contextStr }] : []),
    { role: 'user',      content: query },
  ];
  const genPromptIds = tokenizer.encodeChat(genMessages);

  // Stream generation, collecting output
  const outputTokens = [];
  for await (const tokId of model.generate(genPromptIds, { maxNew, temp, topP, onToken })) {
    outputTokens.push(tokId);
    yield tokId;
  }

  // ── Step 5: Post-hoc scoring ([IsSup] and [IsUse]) ───────────────────────
  // These scores can be used by the caller for response selection / filtering.
  // We compute them but don't use them to alter the already-yielded tokens.
  if (outputTokens.length > 0 && relevantPassages.length > 0) {
    const outputText = tokenizer.decode(outputTokens);
    const supPrompt  = tokenizer.encode(
      `Passage: ${relevantPassages[0]?.text.slice(0, 200)}\nClaim: ${outputText.slice(0, 200)}\n${SPECIAL_TOKENS.ISSUP}`
    );
    // Scores are logged for debugging; integrate into multi-candidate selection if needed
    const supScore = model.predictTokenProb(supPrompt, SPECIAL_IDS.ISSUP);
    console.debug(`[SELF-RAG] IsSup: ${supScore.toFixed(3)}, passages used: ${relevantPassages.length}`);
  }
}

/**
 * Non-streaming SELF-RAG: collect full output, pick best among multiple candidates.
 *
 * Generates `nCandidates` responses (with different passages) and returns the
 * one with the best combined [IsSup] + [IsUse] score.
 *
 * @param {string}          query
 * @param {HybridRetriever} retriever
 * @param {ThreataformLM}   model
 * @param {BPETokenizer}    tokenizer
 * @param {object}          [opts]
 * @param {number}          [opts.nCandidates=3]
 * @returns {Promise<{ text: string, score: number, passages: object[] }>}
 */
export async function selfRAGBest(query, retriever, model, tokenizer, {
  nCandidates   = 3,
  maxNew        = 400,
  temp          = 0.8,
  topP          = 0.9,
  systemPrompt  = 'You are a threat modeling expert.',
  retrievalK    = 6,
} = {}) {
  // Retrieve a broad set of passages
  const allPassages = await retriever.retrieve(query, retrievalK + 3);

  // Split into subsets for each candidate
  const candidates = [];
  for (let c = 0; c < nCandidates; c++) {
    const subset = allPassages.slice(
      c * Math.ceil(allPassages.length / nCandidates),
      (c + 1) * Math.ceil(allPassages.length / nCandidates)
    );

    const context  = packContext(subset, 800);
    const messages = [
      { role: 'system', content: systemPrompt },
      ...(context ? [{ role: 'system', content: context }] : []),
      { role: 'user',   content: query },
    ];
    const promptIds = tokenizer.encodeChat(messages);

    let text = '';
    for await (const tok of model.generate(promptIds, { maxNew, temp, topP })) {
      text += tokenizer.decode([tok]);
    }

    // Score with [IsSup] and [IsUse]
    const supPrompt  = tokenizer.encode(`${text.slice(0, 300)}\n${SPECIAL_TOKENS.ISSUP}`);
    const usePrompt  = tokenizer.encode(`${text.slice(0, 300)}\n${SPECIAL_TOKENS.ISUSE}`);
    const supScore   = model.predictTokenProb(supPrompt, SPECIAL_IDS.ISSUP);
    const useScore   = model.predictTokenProb(usePrompt, SPECIAL_IDS.ISUSE);

    candidates.push({ text, score: supScore + useScore, passages: subset });
  }

  // Return the highest-scoring candidate
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0];
}
