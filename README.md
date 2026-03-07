# Threataform

**Enterprise Terraform Threat Intelligence Platform**

A browser-based, fully client-side security analysis platform for enterprise infrastructure-as-code. Upload Terraform, enrich with supporting documents, run automated threat modeling, generate exportable Data Flow Diagrams, and query a custom-built LLM + RAG stack — zero data leaves your browser.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Workflow Overview](#workflow-overview)
- [Features](#features)
- [LLM Engine — ThreataformLM](#llm-engine--therataformlm)
- [RAG Pipeline](#rag-pipeline)
- [NLP Pipeline](#nlp-pipeline)
- [File Ingestion](#file-ingestion)
- [Training Pipeline](#training-pipeline)
- [.tnlm Format Reference](#tnlm-format-reference)
- [Intelligence Engine (BM25 Legacy)](#intelligence-engine-bm25-legacy)
- [DFD Output](#dfd-output)
- [TFE-Pave Pattern Support](#tfe-pave-pattern-support)
- [Security & Privacy](#security--privacy)
- [Project Structure](#project-structure)

---

## Quick Start

```bash
npm install

# Browser only
npm run dev:web          # http://127.0.0.1:5173

# Desktop app (Electron + Vite)
npm run dev

# Production build
npm run build
```

**Generate smoke-test model before first use:**

```bash
python scripts/create_dummy_model.py
# Writes public/model.tnlm (~300KB, random weights)
# Replace with real trained weights after running the training pipeline
```

---

## Workflow Overview

```
Step 1 — Create Model
  Name your threat model (e.g. "Kinesis Data Analytics", "EKS Platform")
  ↓
Step 2 — Supporting Documents
  Upload categorized enterprise context documents
  Select industry & threat modeling frameworks in scope
  Describe key product features
  ↓
Step 3 — Workspace
  Upload & parse Terraform files
  Run Architecture Analysis (auto-populated from TF + docs)
  Query the Intelligence engine / AI Assistant
  Run Threataform security analysis
  Export DFD to Lucidchart
```

All state persists per-model in browser `localStorage`. Switch between models without losing context.

---

## Features

### Supporting Documents

**Document Categories**
| Category | Purpose |
|---|---|
| Enterprise Architecture | Platform type, AWS Org/OU/SCP docs, ADRs, SDLC processes |
| Application / Product Details | HLDD, engineer docs, vendor documentation |
| Enterprise Security Controls | Security control matrix, control baseline, known risks |
| CSPM / Cloud Configuration | Wiz reports, cloud configuration rules, posture findings |
| Customer Compliance Guide | CSP compliance guides cross-referenced with control matrix |
| Trust on Cloud Documentation | Enterprise cloud trust framework documentation |

**Framework Selection**
- *Industry & Compliance:* NIST 800-53 r5, NIST CSF 2.0, CIS Controls v8, PCI DSS v4, HIPAA, FedRAMP Moderate, FedRAMP High, GDPR, ISO 27001, CMMC Level 2, SOC 2 Type II, NIST SP 800-207 (Zero Trust)
- *Threat Modeling:* STRIDE, PASTA, VAST, LINDDUN, OCTAVE, RTMP, OWASP Top 10, OWASP Top 10 Cloud, MITRE ATT&CK, DREAD, TRIKE

### Intelligence Tab

| Sub-tab | Description |
|---|---|
| AI Assistant | BM25 + LLM hybrid chat — context-aware threat analysis |
| Query Docs | Free-text BM25 search across all indexed documents |
| Security Posture | NIST CSF 2.0 (40%) + Defense-in-Depth (35%) + Zero Trust (25%) composite score, A–F grade |
| Control Inventory | Present/absent controls per defense-in-depth layer |
| Misconfig Checks | 30+ automated checks (Checkov/tfsec-style) across all resources |
| ATT&CK Mapping | MITRE ATT&CK v18.1 technique coverage from parsed resource types |
| Threat Findings | STRIDE threat signals extracted from uploaded documents |
| Scope Analysis | In-scope / out-of-scope declarations found across all indexed content |
| Resource Intel | Per-resource BM25 query against all indexed documents |

### Threataform Analysis Tab

- Executive summary with risk score and severity breakdown
- Per-finding: resource ID, severity (CRITICAL/HIGH/MEDIUM/LOW), remediation guidance, CWE mapping, ATT&CK technique
- STRIDE-LM threat mapping per architectural tier
- Trust boundary identification (network, compute, storage, IAM, org)
- Full ATT&CK coverage heatmap

---

## LLM Engine — ThreataformLM

### Architecture (ThreataformLM-200M)

Custom causal transformer built from scratch in pure JavaScript. No WASM, no WebGPU, no external inference libraries.

| Hyperparameter | Value |
|---|---|
| Parameters | ~200M |
| vocab_size | 32,000 (full BPE, security-domain weighted) |
| context_len | 4,096 (extendable to ~32K via YaRN) |
| dim | 1,024 |
| n_layers | 24 |
| n_heads | 16 (head_dim = 64) |
| n_kv_heads | 4 (GQA: each KV head serves 4 Q-heads) |
| ffn_hidden | 4,096 (SwiGLU: gate × up → down) |
| norm | RMSNorm (eps=1e-5), pre-norm |
| pos_enc | RoPE (theta=10000) + YaRN context scaling |
| init | muP (Maximal Update Parametrization) |
| tie_embeddings | true (lm_head shares tok_embedding weights, saves ~128MB F32) |
| quantization | Mixed Q4/Q8 → ~50MB at full scale |

**Inference speed target:** 2–5 tok/s (200M Q4, pure JS Web Worker)

**Current model state:** `public/model.tnlm` is a 300KB smoke-test model with random weights. Produces garbage output by design. Replace with trained weights from `scripts/quantize.py` for real inference.

---

### `src/lib/llm/Ops.js` — Math Primitives

Every operation implemented from scratch over `Float32Array` / `Uint8Array`. No external math library.

| Function | Description |
|---|---|
| `matmul(out, W, x, rows, cols)` | Dense matrix-vector multiply (the hot path — called every layer) |
| `matmulAccum(out, W, x, rows, cols)` | Accumulate mv-mul into existing buffer (LoRA delta application) |
| `matmulQ4(out, W_raw, x, rows, cols)` | Q4 row-dequant during multiply — avoids 4× memory expansion |
| `matmulQ8(out, W_raw, x, rows, cols)` | Q8 row-dequant during multiply |
| `rmsnorm(out, x, w, n, eps)` | LLaMA-style RMSNorm — no mean subtraction, just scale by 1/RMS(x) |
| `softmax(arr, offset, n)` | Numerically stable — subtract max before exp |
| `silu(x)` | SwiGLU gate activation: x × sigmoid(x) |
| `buildRoPETable(headDim, maxSeq, theta, yarnScale)` | Pre-compute RoPE sin/cos frequency tables (called once on model load) |
| `applyRoPE(q_or_k, vecOffset, headDim, pos, freqReal, freqImag)` | In-place rotary position encoding |
| `vecAdd(a, b, n)` | In-place residual addition |
| `cosineSim(a, b)` | Cosine similarity (for retrieval scoring) |
| `dotProduct(a, b, n)` | Late-interaction dot product (ColBERT MaxSim) |
| `l2Normalize(v, n)` | L2-normalize embedding vector |
| `greedySample(logits)` | Argmax decoding (temp=0) |
| `sampleTopP(logits, temp, topP)` | Nucleus (top-p) sampling |
| `sampleTopK(logits, temp, topK)` | Top-K sampling |
| `f16ToF32(h)` | IEEE 754 half→float (pure bit manipulation, no ArrayBuffer tricks) |
| `f32ToF16(f)` | IEEE 754 float→half |
| `dequantQ4Block(raw, blockIdx)` | 18-byte Q4 block → 32 floats |
| `dequantQ8Block(raw, blockIdx)` | 34-byte Q8 block → 32 floats |

---

### `src/lib/llm/Tokenizer.js` — BPE Tokenizer

Full byte-pair encoding (Sennrich et al. 2016) in pure JavaScript.

- Unicode-aware pre-tokenization: splits on whitespace + punctuation boundaries preserving word integrity
- Byte fallback: every Unicode character maps to UTF-8 byte tokens — guaranteed full coverage, no UNK tokens
- 32K merge rules embedded as compressed JS object (train offline via `scripts/build_vocab.py` → `scripts/export_vocab.py`)
- NFC normalization, BOM stripping, Windows line-ending normalization
- LLaMA-3-compatible instruct chat template via `encodeChat(messages)`

**Special tokens:**

| Token | ID | Purpose |
|---|---|---|
| `<\|pad\|>` | 0 | Padding |
| `<\|bos\|>` | 1 | Beginning of sequence |
| `<\|eos\|>` | 2 | End of sequence |
| `<\|retrieve\|>` | 3 | SELF-RAG: trigger retrieval |
| `<\|isrel\|>` | 4 | SELF-RAG: passage relevance judgment |
| `<\|issup\|>` | 5 | SELF-RAG: response supported by evidence |
| `<\|isuse\|>` | 6 | SELF-RAG: response usefulness score (1–5) |

**Current state:** Tokenizer fully implemented. Running with a placeholder 1K-token vocabulary. To activate the full 32K vocab: run `scripts/build_vocab.py` → `scripts/export_vocab.py`, then copy the output constants into `Tokenizer.js`.

---

### `src/lib/llm/Model.js` — Forward Pass

```
ThreataformLM(config, weights)
  ├── forward(tokenId, pos, kvCache)     → Float32Array[vocab_size] — raw logits
  ├── generate(promptTokens, opts)       → async generator of token IDs (streaming)
  ├── embed(tokenIds)                    → Float32Array[dim] — single pooled vector
  ├── embedMulti(tokenIds)               → Float32Array[][dim] — per-token ColBERT vectors
  ├── predictTokenProb(prompt, tokenId)  → float — used by SELF-RAG for [Retrieve]/[IsRel] etc.
  ├── allocateKVCache(maxSeqLen)         → KVCache — pre-allocated Float32Arrays per layer
  └── clearKVCache()
```

**Per-token forward pass (per layer):**
1. `attention_norm` — RMSNorm(x, w_norm)
2. Q/K/V projections (matmulQ4) → apply RoPE to Q and K
3. GQA attention: causal mask, softmax, KV-cache read/write, O projection (matmulQ8)
4. Residual add
5. `ffn_norm` — RMSNorm
6. SwiGLU FFN: `silu(W_gate @ x) * (W_up @ x)` → `W_down`
7. Residual add

**Current state:** Full forward pass implemented and wired to `engineWorker.js`. Requires trained weights for meaningful output.

---

### `src/lib/llm/WeightsLoader.js` — Model Loading

- Parses `.tnlm` binary format (see [.tnlm Format Reference](#tnlm-format-reference))
- IndexedDB cache (`threataform-model-v1`): stores raw `ArrayBuffer`, second load is always from IDB (<2s)
- Streaming load with per-tensor progress callbacks
- `autoLoad()` — lazy-fetches `/model.tnlm` on first `generate()` or `embed()` call; no upfront cost

---

### `src/lib/llm/LoRA.js` — In-Browser Fine-Tuning

Low-Rank Adaptation on all 7 projections per layer (Q, K, V, O, gate, up, down) × 24 layers = **168 adapter pairs**.

| Config | Default | Notes |
|---|---|---|
| rank r | 8 | r=8 → ~50MB adapter; r=16 → ~100MB |
| alpha | 16 | delta = (alpha/r) × B @ (A @ x) |
| Optimizer | AdamW | lr=3e-4, β1=0.9, β2=0.999, wd=0.01 |
| Loss | cross-entropy | Next-token prediction on document chunks |
| Batch | 4 sequences | Micro-batching in Web Worker |

- A matrices: Kaiming normal init; B matrices: zero init (delta = 0 at start, no disruption to base model)
- Manual backprop: `dL/dA = Bᵀ @ grad_out @ xᵀ`, `dL/dB = grad_out @ (A @ x)ᵀ`
- Runs non-blocking in `engineWorker.js` with progress callbacks
- Adapter serialized to `ArrayBuffer`, cached in IndexedDB, reloaded automatically

---

### `src/workers/engineWorker.js` — Inference Worker

Runs `ThreataformLM` in a dedicated Web Worker (no UI blocking).

**Handled message types:**
- `load` — fetch + parse `model.tnlm`, report progress
- `generate` — streaming token generation, emits `{type:'token', token}` per step
- `embed` — single-vector embedding for a text string
- `embedMulti` — per-token ColBERT embeddings
- `train` — LoRA training loop with progress updates
- `ready` — sent back on successful model load

---

## RAG Pipeline

### Chunking — `src/lib/rag/Chunker.js`

**RecursiveTextSplitter** — deterministic, zero dependencies
- Separator hierarchy (most structural → least): markdown headings → paragraph breaks → newlines → sentence ends (`[.!?]`) → clause ends (`[,;:]`) → word boundaries → character-level
- `split(text)` → `string[]`
- `splitWithMeta(text, meta)` → `{text, index, charStart, charEnd}[]`
- Default: minChunk=100, maxChunk=800, overlap=50

**SemanticChunker** (in `NLP.js`, re-exported from `Chunker.js`)
- Embeds sequential sentence windows, detects cosine-similarity dips as semantic boundaries
- Produces variable-size chunks preserving semantic coherence
- Requires async `embedFn: string → Float32Array`

**HierarchicalChunker** — two-pass (recommended for production)
- Pass 1: RecursiveTextSplitter (fast, structural coarse split)
- Pass 2: SemanticChunker refines any chunk still above `maxChunk`
- Falls back to RecursiveTextSplitter only if no `embedFn` provided

```js
import { makeChunker } from './rag/Chunker.js';
const chunker = makeChunker('balanced'); // 'fast' | 'balanced' | 'precise'
const chunks = await chunker.chunk(text, embedFn);
```

| Preset | minChunk | maxChunk | overlap | semanticThreshold |
|---|---|---|---|---|
| fast | 80 | 600 | 30 | 0.70 |
| balanced | 100 | 900 | 50 | 0.65 |
| precise | 120 | 1200 | 80 | 0.58 |

---

### BM25 — `src/lib/rag/BM25Index.js`

Classic Okapi BM25: k1=1.5, b=0.75. Stop-word filtered. Used as the primary retrieval stage and as the fallback when the neural model is not loaded.

---

### Vector Store — `src/lib/rag/VectorStore.js`

**SingleVectorStore** — one embedding per chunk
- Cosine similarity ranking
- Backed by HNSW for O(log N) ANN search at scale

**ColBERTVectorStore** — one embedding per token (late interaction)
- Stores `Float32Array[]` (T × dim) per document
- MaxSim scoring: `score(Q, D) = Σᵢ max_j (qᵢ · dⱼ)` — far more accurate than single-vector for multi-aspect queries

**HNSW** — Hierarchical Navigable Small World
- Parameters: M=16 connections/node, efC=200 (construction), efS=50 (search)
- Level assignment: `floor(-ln(rand) / ln(M))` → logarithmic layer distribution
- O(log N) approximate nearest-neighbour; brute-force fallback below 50 vectors

---

### Hybrid Retrieval — `src/lib/rag/HybridRetriever.js`

4-stage pipeline with RRF fusion:

**Stage 1 — Broad recall (top-40 pool)**

| Source | Method |
|---|---|
| BM25 | Keyword TF-IDF recall |
| Dense | Single-vector cosine similarity via HNSW |
| ColBERT | Multi-vector MaxSim late interaction |

**Stage 2 — Reciprocal Rank Fusion**

Merges all three ranked lists: `score(d) = Σᵣ 1/(60 + rankᵣ(d))`  (Cormack et al. 2009, k=60). Produces unified top-40.

**Stage 3 — Cross-encoder reranking**

Uses `ThreataformLM` as a binary relevance classifier on concatenated `[query, passage]` pairs. Sorted by cross-encoder logit, top-K returned (default 8). Skipped if model not loaded.

**Stage 4 — SELF-RAG filtering**

Per-passage `[IsRel]` probability filters irrelevant passages before generation.

---

### HyDE — `src/lib/rag/HyDE.js`

Hypothetical Document Embeddings (Gao et al. 2022).

```
query
  → generate short hypothetical answer (maxNew=200, temp=0.3, no retrieval)
  → embed hypothetical answer
  → embed original query
  → average both embeddings
  → retrieve with combined signal
```

Why: embedding a hypothetical answer is a much richer retrieval signal than embedding a short question. Especially effective for threat modeling queries like "what STRIDE threats apply to this S3 bucket?" where the hypothetical answer contains threat vocabulary not present in the raw question.

Falls back to direct query embedding when model not loaded.

---

### SELF-RAG — `src/lib/rag/SelfRAG.js`

Self-Reflective RAG (Asai et al. 2023).

| Special token | Threshold | Decision |
|---|---|---|
| `[Retrieve]` | P > 0.40 | Should we even retrieve? (skip for simple factual answers) |
| `[IsRel]` | P > 0.50 | Is this retrieved passage relevant? |
| `[IsSup]` | P > 0.40 | Does the response use this passage as evidence? |
| `[IsUse]` | score ≥ 3 | Is the final response useful on a 1–5 scale? |

**Generation loop:**
1. Predict `[Retrieve]` — skip retrieval if query is self-contained
2. Retrieve candidates via `HybridRetriever`
3. Filter by `[IsRel]` per passage — discard irrelevant before generation
4. Generate with each surviving passage independently
5. Score each output by `[IsSup]` + `[IsUse]`
6. Return the highest-scoring response (or beam over top-N passages)

**Current state:** SELF-RAG fully implemented. Special token IDs wired through `Tokenizer.js`. Requires a model trained with SELF-RAG tokens in the vocabulary to predict these probabilities meaningfully. With the smoke-test model, `[Retrieve]` will fire randomly and the loop falls through to BM25 context packing.

---

### Active Chat Flow (current state with smoke-test model)

The AI Assistant currently uses the **legacy BM25 fallback path** (`ThrataformRAG.js`):

```
User query
  → BM25 search over indexed documents
  → ContextPacker (top-K chunks ranked by BM25 score)
  → Format as markdown: "**Relevant content from your documents:** ..."
  → Display verbatim chunk text
```

No neural generation is active. Responses are retrieved context chunks, not generated prose. When real trained weights are placed at `public/model.tnlm`, the full pipeline activates automatically:

```
User query
  → HyDE query expansion (ThreataformLM.generate)
  → HybridRetriever (BM25 + dense + ColBERT + RRF)
  → Cross-encoder reranking
  → SELF-RAG generate loop
  → Streaming tokens to UI
```

---

### `src/workers/ingestWorker.js` — Ingestion Worker

Handles file processing off the main thread:
1. `FileRouter` extracts text from any file type
2. `HierarchicalChunker` splits text into chunks
3. `ThreataformEngine.embed()` generates vectors (or skips if model not loaded)
4. Vectors stored in `ColBERTVectorStore` + `SingleVectorStore`
5. `BM25Index` updated with new chunks
6. Progress callbacks to UI

---

## NLP Pipeline

`src/lib/llm/NLP.js`

| Class / Function | Description |
|---|---|
| `SecurityNER` | Recognizes: CVE IDs, MITRE T-numbers, AWS resource types, CIS control refs, IPs, ports, hostnames, Terraform resource names, compliance frameworks (HIPAA, FedRAMP, SOC2, PCI, GDPR, CMMC) |
| `SemanticChunker` | Embedding-based sentence-boundary detection — cosine dip = chunk boundary |
| `CoreferenceResolver` | Pronoun → antecedent linking ("it", "they", "the system" → actual entity) |
| `RelationExtractor` | Subject-predicate-object triples, e.g. `{S3 bucket, exposes, public internet}` |
| `detectLanguage(text)` | Trigram frequency model, 50 languages, ~50KB embedded data |
| `segmentSentences(text)` | Handles code blocks, URLs, abbreviations correctly |

---

## File Ingestion

All extractors lazy-loaded via `src/lib/ingestion/FileRouter.js` (routes by MIME type + extension).

| Format | Library | Output |
|---|---|---|
| PDF | pdfjs-dist | Text + table detection (column analysis) + figure alt-text |
| DOCX/DOC | mammoth | Heading hierarchy, tables, metadata preserved |
| XLSX/XLS | SheetJS | "ColHeader: CellValue" row format per cell |
| CSV | built-in | First row as headers, each subsequent row as labelled sentences |
| PPTX | custom XML parser | Slide titles + body + speaker notes |
| PNG/JPG/TIFF | Tesseract.js | OCR + layout analysis (lazy-loaded) |
| MP3/WAV/MP4 | Whisper.js | Audio transcription (lazy-loaded) |
| JSON/YAML | built-in | Flattened `key.subkey.leaf: value` |
| HCL/Terraform | custom parser | Resource blocks with all attributes annotated |
| HTML | DOMParser | Text nodes + tag context |
| Markdown | built-in | Stripped syntax + code blocks extracted separately |
| XML | DOMParser | Text nodes |
| TOML | built-in | Parsed + flattened like JSON |

All extractors return:
```js
{
  text: string,
  metadata: { filename, type, pages?, sheets?, slides? },
  tables: [{ headers, rows }],
  codeBlocks: [{ lang, code }],
  entities: []   // populated by SecurityNER post-extraction
}
```

---

## Training Pipeline

### Corpus Sources

| Source | Content | Approx. Size |
|---|---|---|
| MITRE ATT&CK STIX | Technique descriptions + examples | ~50MB |
| NVD CVE database (2010–present) | Structured vulnerability descriptions | ~2GB |
| AWS security documentation | Service security sections | ~500MB |
| Terraform provider docs | Resource attribute descriptions | ~200MB |
| CIS Controls v7/v8 | Control text | ~10MB |
| NIST SP 800-53 r5 | Security control catalog | ~20MB |
| OWASP Top 10 + ASVS | Vulnerability descriptions | ~5MB |
| Synthetic Q&A (GPT-4o, one-time) | 100K threat modeling pairs | ~200MB |
| General web text (OpenWebText) | Language quality | 1B tokens |

### Scripts

```bash
# 1. Build vocabulary (CPU, ~1 hour)
python scripts/build_vocab.py
#    → vocab.json + merges.txt (32K BPE, security-weighted 60% / general 40%)

# 2. Download + preprocess corpus (CPU, multi-hour, ~50GB disk)
python scripts/build_corpus.py
#    → tokenized + packed HDF5 dataset

# 3. Generate synthetic Q&A (requires OPENAI_API_KEY, run once)
python scripts/generate_synth_data.py
#    → 100K (prompt, response) JSONL pairs

# 4. Pre-training (1× A100 ~3 days, 4× RTX 4090 ~5 days)
#    AdamW lr=3e-4, cosine decay, 2000 warmup steps
#    32 seqs × 4096 tokens = 131K tokens/batch, 200K steps (~26B tokens)
python scripts/train_base.py

# 5. Supervised fine-tuning (few hours)
#    LLaMA-3 instruct template, loss on assistant turns only, lr=1e-5
python scripts/train_instruct.py

# 6. DPO alignment (few hours)
#    beta=0.1 KL penalty, 10K (chosen, rejected) pairs, 2000 steps
python scripts/train_dpo.py

# 7. Quantize + export
python scripts/quantize.py --input checkpoints/final.pt --out public/model.tnlm

# 8. Export updated vocab to JS
python scripts/export_vocab.py

# 9. Evaluate
python scripts/eval.py --model public/model.tnlm --all --save-report report.json
```

### Evaluation Benchmarks (`scripts/eval.py`)

| Benchmark | Metric | What it tests |
|---|---|---|
| STRIDE classification | Accuracy | Terraform resource → correct threat categories |
| MITRE ATT&CK recall | Recall@10 | Attack scenario → correct T-numbers |
| CIS control recommendation | Precision@5 | Misconfiguration → correct CIS controls |
| Perplexity | PPL | Held-out security text perplexity |
| RAG retrieval | MRR, NDCG, Hit@5 | BM25 retrieval quality |
| Threat Q&A | BLEU-4, ROUGE-L | Full answer quality vs reference answers |

---

## .tnlm Format Reference

```
Header:
  [4B]  magic = "TNLM"
  [4B]  version = 2  (little-endian uint32)
  [4B]  config_json_length
  [N B] config JSON (utf-8)

Tensors (repeated until EOF):
  [4B]       name_length
  [N B]      name (utf-8)
  [4B]       dtype  (0=F32, 1=Q4, 2=Q8)
  [4B]       ndim
  [4B × ndim] shape dimensions (little-endian uint32)
  [data]     see dtype encoding below

F32: 4 bytes per element (IEEE 754 LE float)

Q4: ceil(n/32) × 18 bytes
  Per 32-weight block:
    [2B]  f16 scale (IEEE 754 LE half) = max_abs / 7
    [16B] nibbles
      byte[i]: low  nibble = weight[i]       → dequant: ((byte & 0x0F) - 8) × scale
               high nibble = weight[i + 16]  → dequant: ((byte >> 4)   - 8) × scale

Q8: ceil(n/32) × 34 bytes
  Per 32-weight block:
    [2B]  f16 scale = max_abs / 127
    [32B] int8 values → dequant: int8 × scale
```

**Weight naming convention** (must match exactly for `Model.js`):

```
tok_embeddings                    [vocab_size, dim]          F32
norm                              [dim]                      F32
layers.{l}.attention_norm         [dim]                      F32
layers.{l}.attention.wq           [n_heads×head_dim, dim]    Q4
layers.{l}.attention.wk           [n_kv_heads×head_dim, dim] Q4
layers.{l}.attention.wv           [n_kv_heads×head_dim, dim] Q4
layers.{l}.attention.wo           [dim, dim]                 Q8  ← higher precision
layers.{l}.ffn_norm               [dim]                      F32
layers.{l}.feed_forward.w1        [ffn_hidden, dim]          Q4
layers.{l}.feed_forward.w3        [ffn_hidden, dim]          Q4
layers.{l}.feed_forward.w2        [dim, ffn_hidden]          Q8  ← higher precision
```

Q8 used for output projections (`attention.wo`, `feed_forward.w2`) where precision loss has the most impact on output quality.

---

## Intelligence Engine (BM25 Legacy)

`ThreatModelIntelligence` in `terraform-enterprise-intelligence.jsx` — the original BM25-lite engine, active as the fallback when the neural model is not loaded.

### Index Sources

| Source | Content |
|---|---|
| Terraform resources | Resource type, name, ATT&CK techniques, misconfig check descriptions |
| User documents | Full extracted text chunked at ~400 tokens with 50-token overlap |
| Model context doc | Synthetic doc: product name, environment, frameworks, key features |

### Entity Patterns Extracted

STRIDE threats, MITRE ATT&CK T-numbers, compliance framework names, 100+ AWS service patterns, security control keywords, scope declarations (in-scope / out-of-scope language).

---

## DFD Output

Generated XML conforms to `mxGraphModel` (draw.io / Lucidchart standard).

- **Layout:** Left-to-right, tiers as columns, max 5 nodes per sub-column
- **Edge styles:** grey (implicit TF reference), red dashed (explicit `depends_on`), green (module I/O)
- **Threat annotations:** Resources with STRIDE findings get a `⚠ stride1,stride2` label
- **Import:** Lucidchart → File → Import → Diagram → select `.xml`

---

## TFE-Pave Pattern Support

Understands enterprise hierarchical IAM layers:

| Layer | Name | Description |
|---|---|---|
| L0 | Org / Management | SCPs, OU structure, Control Tower |
| L1 | Account Vending | AFT, account bootstrapping |
| L2 | Account Pave | CloudTrail, GuardDuty, Config, permission boundaries |
| L3 | Product Pave | Platform VPC, TGW, shared SGs, ProductTeamDeployer role |
| L4 | Service | Application workloads, service-specific roles |

Context-aware wildcard IAM analysis: `kinesis:*` scoped to `team-prefix-*` with permission boundary present = LOW severity (standard pave pattern), not HIGH.

---

## Security & Privacy

- 100% client-side — Terraform code and documents never leave your browser
- All parsing, OCR, intelligence indexing, and inference runs in the browser's JS engine / Web Workers
- No telemetry, no analytics, no external API calls
- `localStorage` keys: `tf-threat-models`, `tf-model-{id}-docs`, `tf-model-{id}-details`, `tf-model-{id}-files`, `tf-model-{id}-arch-analysis`
- IndexedDB: `threataform-vectors` (BM25+vector data), `threataform-model-v1` (model weights cache)

---

## Project Structure

```
src/
  lib/
    llm/
      Ops.js                All math primitives — matmul, RMSNorm, RoPE, SwiGLU, Q4/Q8 dequant
      Tokenizer.js          BPE tokenizer, 32K vocab, SELF-RAG special tokens, instruct template
      Model.js              ThreataformLM-200M forward pass + generate + embed + LoRA hooks
      WeightsLoader.js      .tnlm binary parser + IndexedDB cache + autoLoad
      LoRA.js               168 adapter pairs, AdamW optimizer, manual backprop
      NLP.js                SecurityNER, SemanticChunker, CoreferenceResolver, RelationExtractor
    rag/
      Chunker.js            RecursiveTextSplitter + HierarchicalChunker + makeChunker factory
      BM25Index.js          BM25 (k1=1.5, b=0.75) keyword retrieval
      VectorStore.js        SingleVectorStore + ColBERTVectorStore + HNSW
      HybridRetriever.js    BM25 + dense + ColBERT + RRF + cross-encoder (4-stage)
      HyDE.js               Hypothetical Document Embeddings query expansion
      SelfRAG.js            SELF-RAG loop with [Retrieve]/[IsRel]/[IsSup]/[IsUse] tokens
    ingestion/
      FileRouter.js         MIME/extension routing
      PDFExtractor.js       pdfjs-dist — text + tables + figures
      DocxExtractor.js      mammoth — headings, tables, metadata
      SpreadsheetExtractor.js  SheetJS — cell context format
      PresentationExtractor.js PPTX XML — slides + speaker notes
      ImageExtractor.js     Tesseract.js OCR (lazy)
      AudioExtractor.js     Whisper.js transcription (lazy)
      StructuredExtractor.js   JSON/YAML/HCL/XML/TOML → annotated text
      MarkupExtractor.js    HTML/Markdown/RST → clean text + code blocks
    ThreataformEngine.js    Public singleton API — loadModel, generate, embed, ingest
    WllamaManager.js        Legacy shim re-exporting ThreataformEngine
    ThrataformRAG.js        Legacy BM25 fallback (active with smoke-test model)
  workers/
    engineWorker.js         Inference + embedding + LoRA training Web Worker
    ingestWorker.js         File chunking + embedding Web Worker
    llmWorker.js            Legacy wllama worker
    embedWorker.js          Legacy embed worker
  terraform-enterprise-intelligence.jsx   Main application (~9200 lines)

scripts/
  create_dummy_model.py     Smoke-test .tnlm generator (Python stdlib, no GPU, ~300KB output)
  build_vocab.py            Train 32K BPE vocabulary from security corpus
  build_corpus.py           Download + preprocess training data
  generate_synth_data.py    100K synthetic threat Q&A pairs via GPT-4o (one-time)
  train_base.py             Pre-train ThreataformLM-200M from scratch
  train_instruct.py         SFT on threat modeling instruction data
  train_dpo.py              DPO alignment
  quantize.py               F32 → mixed Q4/Q8 + .tnlm export
  export_vocab.py           Trained vocab → Tokenizer.js constants
  eval.py                   6-benchmark evaluation suite

public/
  model.tnlm                Model weights (smoke-test: 300KB random; production: ~50MB trained)

electron/
  main.cjs                  Electron main process
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI | React 18, Lucide icons, inline CSS |
| Build | Vite 6, Electron 40 |
| LLM inference | Pure JS Web Workers — engineWorker.js (no WASM) |
| Legacy LLM | @wllama/wllama 2.3.7 (llama.cpp WASM, still bundled) |
| PDF extraction | pdfjs-dist 5.x |
| DOCX extraction | mammoth 1.x |
| XLSX extraction | SheetJS 0.18 |
| OCR | Tesseract.js 7.x |
| Diagrams | draw.io / Lucidchart mxGraph XML |
| Persistence | localStorage (model state) + IndexedDB (vectors + model cache) |

---

## Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org/) Enterprise v18.1
- [HashiCorp Terraform](https://developer.hashicorp.com/terraform)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) (Microsoft)
- [SELF-RAG](https://arxiv.org/abs/2310.11511) — Asai et al. 2023
- [HyDE](https://arxiv.org/abs/2212.10496) — Gao et al. 2022
- [ColBERT](https://arxiv.org/abs/2004.12832) — Khattab & Zaharia 2020
- [RRF](https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf) — Cormack et al. 2009
