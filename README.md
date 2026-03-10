# Threataform

**Enterprise Terraform Threat Intelligence Platform**

A browser-based, fully client-side security analysis platform for enterprise infrastructure-as-code. Upload Terraform, enrich with supporting documents, run automated threat modeling, generate exportable Data Flow Diagrams, and query a custom-built LLM + RAG stack — zero data leaves your browser.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Workflow Overview](#workflow-overview)
- [Features](#features)
- [AI Assistant & LLM Stack](#ai-assistant--llm-stack)
- [LLM Engine — ThreataformLM](#llm-engine--threataformlm)
- [RAG Pipeline](#rag-pipeline)
- [NLP Pipeline](#nlp-pipeline)
- [File Ingestion](#file-ingestion)
- [Training Pipeline](#training-pipeline)
- [.tnlm Format Reference](#tnlm-format-reference)
- [Intelligence Engine (BM25)](#intelligence-engine-bm25)
- [IaC Parsing](#iac-parsing)
- [DFD Output](#dfd-output)
- [MCP Tool Server](#mcp-tool-server)
- [TFE-Pave Pattern Support](#tfe-pave-pattern-support)
- [State Management](#state-management)
- [Project Structure](#project-structure)
- [Security & Privacy](#security--privacy)
- [Tech Stack](#tech-stack)

---

## Quick Start

```bash
npm install
npm run dev          # http://127.0.0.1:5173
npm run build        # production build → dist/
```

> **COOP/COEP headers are required.** The dev server sets these automatically. For production, configure your static file server to send:
> ```
> Cross-Origin-Opener-Policy: same-origin
> Cross-Origin-Embedder-Policy: require-corp
> ```
> These are required for `SharedArrayBuffer` (multi-threaded llama.cpp WASM).

**Generate smoke-test model before using the custom engine:**

```bash
python scripts/create_dummy_model.py
# Writes public/model.tnlm (~300KB, random weights)
# Replace with real trained weights after running the training pipeline
```

### Enterprise / Restricted npm Registry (e.g. corporate JFrog Artifactory)

If `npm install` fails or Vite is not found after install (common with corporate Artifactory proxies that intercept `devDependencies`), use this sequence:

```bash
rm -rf node_modules package-lock.json
npm install
npm install vite --save-dev
npm run dev
```

The `rm -rf` ensures a clean state; reinstalling `vite` separately works around Artifactory virtual repos that may not resolve dev dependencies in a single pass. The `npm audit` 404 errors logged by Artifactory (`Virtual repository npm does not have any npm audit providers`) are harmless warnings — the install itself succeeds.

If your environment blocks the public npm registry entirely:

```bash
npm install --omit=optional   # skip native binary optionals
npm run dev
```

All document extractors (PDF, DOCX, XLSX, PPTX, images) automatically fall back to
**esm.sh CDN** if their npm packages are unavailable — as long as the machine has internet access.

| Format | npm package | CDN fallback |
|---|---|---|
| PDF | pdfjs-dist | esm.sh/pdfjs-dist@3.11.174 |
| DOCX | mammoth | esm.sh/mammoth@1.6.0 |
| XLSX/XLS | xlsx (SheetJS) | esm.sh/xlsx@0.18.5 |
| PPTX | jszip | esm.sh/jszip@3.10.1 |
| PNG/JPG | tesseract.js | esm.sh/tesseract.js@5.0.4 |
| CSV | pure JS | — |

---

## Workflow Overview

```
Step 1 — Know Your Domain
  Browse the built-in Knowledge Base (AWS services, STRIDE, ATT&CK, compliance)
  ↓
Step 2 — Build Model
  Name your threat model (e.g. "Kinesis Data Analytics", "EKS Platform")
  Upload Terraform + supporting docs
  Set application details (environment, team, data classification)
  ↓
Step 3 — Analyze Threats
  STRIDE breakdown · IaC misconfig checks · ATT&CK mapping · surface analysis
  ↓
Step 4 — Review Intelligence
  AI Assistant · Posture · Controls · Misconfigs · ATT&CK · Threat Intel · Scope
  ↓
Step 5 — Export
  DFD .xml (draw.io/Lucidchart) · .lucid bundle · Report .txt / .md
```

All state persists per-model in browser `localStorage`. Switch between models without losing context.

---

## Features

### Intelligence Panel Sub-tabs

| Sub-tab | Description |
|---|---|
| **AI Assistant** | BM25 + LLM hybrid chat — context-aware threat analysis. Offline LLM optional; BM25 fallback always active. |
| **Security Posture** | Aggregated security score, STRIDE breakdown, control coverage heatmap |
| **Control Inventory** | Present/absent controls per defense-in-depth layer, with evidence passages |
| **Cross-Doc Analysis** | Finds contradictions, gaps, and duplicates across uploaded documents |
| **Misconfigs** | 30+ automated IaC checks (Checkov/tfsec-style) across all resources |
| **ATT&CK Map** | MITRE ATT&CK v18.1 technique coverage grid by tactic |
| **Threat Intel** | Per-resource threat details with CVSS estimates and remediation guidance |
| **Scope** | In-scope / out-of-scope declarations extracted from uploaded documents |

### Threat Analysis Tab

- Executive summary with risk score and severity breakdown
- Per-finding: resource ID, severity (CRITICAL/HIGH/MEDIUM/LOW), remediation, CWE mapping, ATT&CK technique
- STRIDE-LM threat mapping per architectural tier
- Trust boundary identification (network, compute, storage, IAM, org)
- Full ATT&CK coverage heatmap
- Security surface summary (S3, EKS, Lambda, WAF exposure)

### Supported Frameworks

**Compliance / Industry:** HIPAA, FedRAMP Moderate/High, PCI DSS v4, GDPR, SOC 2 Type II, CMMC Level 2, NIST 800-53 r5, NIST CSF 2.0, CIS Controls v8, ISO 27001, NIST SP 800-207 (Zero Trust)

**Threat Modeling:** STRIDE, PASTA, VAST, LINDDUN, OCTAVE, RTMP, OWASP Top 10, OWASP Top 10 Cloud, MITRE ATT&CK, DREAD, TRIKE

---

## AI Assistant & LLM Stack

Two engines exist. The **active engine** is `WllamaManager` (llama.cpp WASM, user picks a `.gguf` from disk). The **next-gen engine** is `ThreataformEngine` (auto-loads `public/model.tnlm`, uses Web Workers) — fully built but not yet wired as the default.

### Active Engine — WllamaManager

`src/lib/WllamaManager.js` wraps `@wllama/wllama` v2.3.7:

- User selects any `.gguf` file from disk in the AI Assistant → **Load Local LLM** section
- File is read locally via the File API — never uploaded
- Multi-threaded WASM inference when `SharedArrayBuffer` is available; single-thread fallback is automatic
- API: `loadFromFile(file)`, `generate(messages)` (async generator), `embed(texts[])`, `embedQuery(text)`

### Next-Gen Engine — ThreataformEngine

`src/lib/ThreataformEngine.js` (482 lines) — same public API as WllamaManager, drop-in replacement:

- Auto-loads `public/model.tnlm` via `autoLoad()` — no user file picker
- Runs `ThreataformLM-200M` (custom causal transformer, pure JS)
- Uses `engineWorker.js` + `ingestWorker.js` Web Workers
- Supports ColBERT multi-vector embeddings, HyDE query expansion, SelfRAG

**To wire ThreataformEngine:** change `import { wllamaManager } from './src/lib/WllamaManager.js'` to `import { threataformEngine as wllamaManager } from './src/lib/ThreataformEngine.js'` in the main app file.

### Current Chat Flow (WllamaManager + BM25 path)

```
User query
  → BM25 search over indexed documents    [always active]
  + Dense vector search via wllama embed  [when model loaded]
        ↓
  Reciprocal Rank Fusion (k=60)
        ↓
  Context Packer (fills token budget, deduplicates)
        ↓
  LLM generation (streamed tokens)  OR  BM25 top-k summary fallback
```

### Full RAG Flow (ThreataformEngine path — future default)

```
User query
  → HyDE query expansion (generate hypothetical answer, embed it)
  → HybridRetriever: BM25 + dense + ColBERT + RRF
  → Cross-encoder reranking
  → SELF-RAG generate loop ([Retrieve]/[IsRel]/[IsSup]/[IsUse])
  → Streaming tokens to UI
```

---

## LLM Engine — ThreataformLM

Custom causal transformer built from scratch in pure JavaScript for `ThreataformEngine`. No WASM, no WebGPU, no external inference libraries.

### Architecture (ThreataformLM-200M)

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
| `f16ToF32(h)` | IEEE 754 half→float (pure bit manipulation) |
| `f32ToF16(f)` | IEEE 754 float→half |
| `dequantQ4Block(raw, blockIdx)` | 18-byte Q4 block → 32 floats |
| `dequantQ8Block(raw, blockIdx)` | 34-byte Q8 block → 32 floats |

---

### `src/lib/llm/Tokenizer.js` — BPE Tokenizer

Full byte-pair encoding (Sennrich et al. 2016) in pure JavaScript.

- Unicode-aware pre-tokenization: splits on whitespace + punctuation boundaries preserving word integrity
- Byte fallback: every Unicode character maps to UTF-8 byte tokens — guaranteed full coverage, no UNK tokens
- 32K merge rules embedded as compressed JS object
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

---

### `src/lib/llm/Model.js` — Forward Pass

```
ThreataformLM(config, weights)
  ├── forward(tokenId, pos, kvCache)     → Float32Array[vocab_size] — raw logits
  ├── generate(promptTokens, opts)       → async generator of token IDs (streaming)
  ├── embed(tokenIds)                    → Float32Array[dim] — single pooled vector
  ├── embedMulti(tokenIds)               → Float32Array[][dim] — per-token ColBERT vectors
  ├── predictTokenProb(prompt, tokenId)  → float — used by SELF-RAG for special tokens
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

---

### `src/lib/llm/WeightsLoader.js` — Model Loading

- Parses `.tnlm` binary format (see [.tnlm Format Reference](#tnlm-format-reference))
- IndexedDB cache (`threataform-model-v1`): stores raw `ArrayBuffer`, second load is always from IDB (<2s)
- Streaming load with per-tensor progress callbacks
- `autoLoad()` — lazy-fetches `/model.tnlm` on first `generate()` or `embed()` call

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

- A matrices: Kaiming normal init; B matrices: zero init (delta = 0 at start)
- Manual backprop: `dL/dA = Bᵀ @ grad_out @ xᵀ`, `dL/dB = grad_out @ (A @ x)ᵀ`
- Adapter serialized to `ArrayBuffer`, cached in IndexedDB, reloaded automatically

---

### `src/workers/engineWorker.js` — Inference Worker

Runs `ThreataformLM` in a dedicated Web Worker (no UI blocking).

**Message types:**
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
- Default: minChunk=100, maxChunk=800, overlap=50

**SemanticChunker** (in `NLP.js`, re-exported from `Chunker.js`)
- Embeds sequential sentence windows, detects cosine-similarity dips as semantic boundaries
- Requires async `embedFn: string → Float32Array`

**HierarchicalChunker** — two-pass (recommended for production)
- Pass 1: RecursiveTextSplitter (fast structural split)
- Pass 2: SemanticChunker refines chunks still above `maxChunk`

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

Classic Okapi BM25: k1=1.5, b=0.75. Stop-word filtered. Primary retrieval stage and fallback when no LLM is loaded.

---

### Vector Store — `src/lib/rag/VectorStore.js`

**SingleVectorStore** — one embedding per chunk
- Cosine similarity ranking
- HNSW for O(log N) ANN search at scale

**ColBERTVectorStore** — one embedding per token (late interaction)
- Stores `Float32Array[]` (T × dim) per document
- MaxSim scoring: `score(Q, D) = Σᵢ max_j (qᵢ · dⱼ)`

**HNSW** — Hierarchical Navigable Small World
- Parameters: M=16 connections/node, efC=200 (construction), efS=50 (search)
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

`score(d) = Σᵣ 1/(60 + rankᵣ(d))` (Cormack et al. 2009, k=60)

**Stage 3 — Cross-encoder reranking**

Uses `ThreataformLM` as a binary relevance classifier. Skipped when model not loaded.

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

Falls back to direct query embedding when model not loaded.

---

### SELF-RAG — `src/lib/rag/SelfRAG.js`

Self-Reflective RAG (Asai et al. 2023).

| Special token | Threshold | Decision |
|---|---|---|
| `[Retrieve]` | P > 0.40 | Should we even retrieve? |
| `[IsRel]` | P > 0.50 | Is this retrieved passage relevant? |
| `[IsSup]` | P > 0.40 | Does the response use this passage as evidence? |
| `[IsUse]` | score ≥ 3 | Is the final response useful (1–5 scale)? |

**Generation loop:**
1. Predict `[Retrieve]` — skip retrieval if query is self-contained
2. Retrieve candidates via `HybridRetriever`
3. Filter by `[IsRel]` per passage — discard irrelevant
4. Generate with each surviving passage independently
5. Score each output by `[IsSup]` + `[IsUse]`
6. Return the highest-scoring response

---

## NLP Pipeline

`src/lib/llm/NLP.js`

| Class / Function | Description |
|---|---|
| `SecurityNER` | Recognizes: CVE IDs, MITRE T-numbers, AWS resource types, CIS control refs, IPs/ports, Terraform resource names, compliance framework names |
| `SemanticChunker` | Embedding-based sentence-boundary detection |
| `CoreferenceResolver` | Pronoun → antecedent linking ("it", "the system" → actual entity) |
| `RelationExtractor` | Subject-predicate-object triples, e.g. `{S3 bucket, exposes, public internet}` |
| `detectLanguage(text)` | Trigram frequency model, 50 languages |
| `segmentSentences(text)` | Handles code blocks, URLs, abbreviations |

---

## File Ingestion

`src/lib/ingestion/FileRouter.js` routes by MIME type + extension.

| Format | Primary Library | CDN Fallback | Output |
|---|---|---|---|
| PDF | pdfjs-dist | esm.sh/pdfjs-dist@3.11.174 | Text + table detection |
| DOCX/DOC | mammoth | esm.sh/mammoth@1.6.0 | Heading hierarchy, tables, metadata |
| XLSX/XLS | SheetJS (xlsx) | esm.sh/xlsx@0.18.5 | "ColHeader: CellValue" row format |
| CSV | pure JS | — | First row as headers, labelled sentences |
| PPTX | jszip | esm.sh/jszip@3.10.1 | Slide titles + body + speaker notes |
| PNG/JPG/TIFF | Tesseract.js | esm.sh/tesseract.js@5.0.4 | OCR text + layout analysis |
| MP3/WAV/MP4 | Whisper.js | — | Audio transcription (lazy-loaded) |
| JSON/YAML | built-in | — | Flattened `key.subkey.leaf: value` |
| HCL/Terraform | custom parser | — | Resource blocks with all attributes |
| HTML | DOMParser | — | Text nodes + tag context |
| Markdown | built-in | — | Stripped syntax + code blocks |
| TOML | built-in | — | Parsed + flattened |

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

# 3. Generate synthetic Q&A (requires OPENAI_API_KEY, run once)
python scripts/generate_synth_data.py

# 4. Pre-training (1× A100 ~3 days, 4× RTX 4090 ~5 days)
python scripts/train_base.py

# 5. Supervised fine-tuning (few hours)
python scripts/train_instruct.py

# 6. DPO alignment (few hours)
python scripts/train_dpo.py

# 7. Quantize + export
python scripts/quantize.py --input checkpoints/final.pt --out public/model.tnlm

# 8. Export updated vocab to JS
python scripts/export_vocab.py

# 9. Evaluate
python scripts/eval.py --model public/model.tnlm --all --save-report report.json
```

### Evaluation Benchmarks

| Benchmark | Metric | What it tests |
|---|---|---|
| STRIDE classification | Accuracy | Terraform resource → correct threat categories |
| MITRE ATT&CK recall | Recall@10 | Attack scenario → correct T-numbers |
| CIS control recommendation | Precision@5 | Misconfiguration → correct CIS controls |
| Perplexity | PPL | Held-out security text perplexity |
| RAG retrieval | MRR, NDCG, Hit@5 | Retrieval quality |
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
    [2B]  f16 scale = max_abs / 7
    [16B] nibbles
      byte[i]: low  nibble = weight[i]       → ((byte & 0x0F) - 8) × scale
               high nibble = weight[i + 16]  → ((byte >> 4)   - 8) × scale

Q8: ceil(n/32) × 34 bytes
  Per 32-weight block:
    [2B]  f16 scale = max_abs / 127
    [32B] int8 values → int8 × scale
```

**Weight naming convention:**

```
tok_embeddings                    [vocab_size, dim]          F32
norm                              [dim]                      F32
layers.{l}.attention_norm         [dim]                      F32
layers.{l}.attention.wq           [n_heads×head_dim, dim]    Q4
layers.{l}.attention.wk           [n_kv_heads×head_dim, dim] Q4
layers.{l}.attention.wv           [n_kv_heads×head_dim, dim] Q4
layers.{l}.attention.wo           [dim, dim]                 Q8
layers.{l}.ffn_norm               [dim]                      F32
layers.{l}.feed_forward.w1        [ffn_hidden, dim]          Q4
layers.{l}.feed_forward.w3        [ffn_hidden, dim]          Q4
layers.{l}.feed_forward.w2        [dim, ffn_hidden]          Q8
```

Q8 used for output projections (`attention.wo`, `feed_forward.w2`) where precision loss has most impact.

---

## Intelligence Engine (BM25)

`src/lib/intelligence/ThreatModelIntelligence.js` — pure-JavaScript BM25-based engine. Active with or without an LLM loaded.

### Index Sources

| Source | Content |
|---|---|
| Terraform resources | Resource type, name, ATT&CK techniques, misconfiguration check descriptions |
| User documents | Full extracted text chunked at ~400 tokens with 50-token overlap |
| Arch context doc | Synthetic doc: product name, environment, frameworks, key features |
| Model details doc | Architecture description, data classifications, team fields |

### Entity Patterns Extracted

STRIDE threats, MITRE ATT&CK T-numbers, compliance framework names, 100+ AWS service patterns, security control keywords, scope declarations (in-scope / out-of-scope language).

### Key Methods

| Method | Description |
|---|---|
| `build(userDocs, resources, modules)` | Index all sources, extract features |
| `query(text, topK)` | BM25 search, returns verbatim chunks with scores |
| `analyzeResource(type, name)` | Relevant doc passages for a specific resource |
| `getArchitectureSummary(resources)` | Auto-fills the architecture description field |
| `_docHasControl(ctrlName)` | Cross-references control against uploaded docs |

The engine rebuilds automatically on every file upload, document change, or architecture override.

---

## IaC Parsing

### Terraform / HCL — `src/lib/iac/TerraformParser.js`

- Resource blocks: `aws_*`, `azurerm_*`, `google_*`, and custom providers
- Module calls with Terraform Registry source inference
- Output and variable dependencies
- Cross-file connections: security groups → EC2, IAM roles → Lambda, VPC → subnets
- Sentinel policy files, `.tfvars` value injection

### CloudFormation — `src/lib/iac/CFNParser.js`

Parses CloudFormation JSON/YAML stacks (Resources, Parameters, Outputs).

### Security Analysis — `src/lib/iac/SecurityAnalyzer.js`

| Category | Examples |
|---|---|
| Network exposure | Security groups with `0.0.0.0/0` ingress on sensitive ports |
| Encryption | S3 without SSE, RDS without `storage_encrypted`, EBS without `encrypted` |
| Access control | IAM policies with `*` actions/resources, missing MFA |
| Logging/audit | CloudTrail disabled, S3 access logging off, VPC flow logs absent |
| Public access | Public S3 ACLs, unrestricted Lambda URLs, public EKS API endpoints |
| Versioning | S3 versioning disabled, DynamoDB PITR off |

---

## DFD Output

`src/lib/diagram/DFDGenerator.js` produces mxGraphModel XML for draw.io / Lucidchart.

**Layout:** Left-to-right tiers. Resources grouped by service type into tier columns, max 5 nodes per sub-column. Legend top-left.

**XML format (immutable — Lucidchart import depends on this):**
- All nodes: `html=1;whiteSpace=wrap;`
- Edges: `edgeStyle=orthogonalEdgeStyle;...endArrow=blockThin;`
- Newlines in cell values: `&#xa;`
- Wrapper: `<mxfile host="app.diagrams.net" version="21.0.0" type="device">`

**Edge types:**
- Grey — implicit Terraform reference
- Red dashed — explicit `depends_on`
- Green — module I/O

Resources with STRIDE findings get a `⚠ stride1,stride2` label appended.

**Import:** Lucidchart → File → Import → Diagram → select `.xml`; or draw.io → Extras → Edit Diagram.

---

## MCP Tool Server

`src/lib/mcp/MCPToolRegistry.js` implements a Model Context Protocol tool registry. The AI Assistant can invoke these as part of its reasoning.

| Tool | Description |
|---|---|
| `score_cvss` | CVSS v3.1 base score from vector string |
| `lookup_mitre` | ATT&CK technique details by technique ID |
| `check_compliance` | Evaluates a control against HIPAA/FedRAMP/SOC2/PCI-DSS/GDPR/CMMC |

External MCP tools can be connected via WebSocket through `MCPClient.js`.

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

Context-aware IAM analysis: `kinesis:*` scoped to `team-prefix-*` with permission boundary = LOW severity (standard pave pattern), not HIGH.

---

## State Management

React hooks only — no external state library.

| State | Hook | Description |
|---|---|---|
| `files` | `useParseResult` | Parsed TF/HCL file objects |
| `parseResult` | `useParseResult` | Output of `parseTFMultiFile()` — resources, modules, connections |
| `xml` | `useParseResult` | Current DFD mxGraphModel XML string |
| `userDocs` | `useUserDocs` | Non-TF context documents (persisted per model) |
| `currentModel` | `useModelManager` | Active threat model (name, id, metadata) |
| `llmStatus` | `useLLM` | `idle` / `loading` / `ready` / `error` |
| `wllamaModelName` | `useLLM` | Filename of loaded GGUF |
| `llmProgress` | `useLLM` | Loading progress 0–100 |
| `intelligenceRef` | `useRef` | `ThreatModelIntelligence` singleton |
| `intelligenceVersion` | `useState` | Incremented after each index rebuild to trigger re-renders |
| `vectorStoreRef` | `useVectorStore` | Dense vector store for RAG embeddings |

**Persistence:**
- Models list: `localStorage` → `tf-models`
- Documents per model: `localStorage` → `tf-model-{id}-docs`
- Chat history per model: `localStorage` → `tf-model-{id}-chat`
- Last-used LLM model name: `localStorage` → `tf-last-llm-model`
- Dense embedding vectors: IndexedDB → `threataform-vectors` (v2)
- Model weights cache: IndexedDB → `threataform-model-v1`

### Known Bug Pattern: TDZ in `useCallback` Deps

If callback A (declared earlier in the component body) lists callback B (declared later) in its dep array, JavaScript throws a Temporal Dead Zone error:

```
Cannot access 'B' before initialization
```

**Fix:** Declare `const bRef = useRef(null)` before A, assign `bRef.current = B` after B is defined, call `bRef.current?.()` inside A.

---

## Project Structure

```
threataform/
├── terraform-enterprise-intelligence.jsx   # Main App component (~2848 lines)
├── src/
│   ├── hooks/
│   │   ├── useLLM.js              # LLM/embed state (llmStatus, progress, model name/size)
│   │   ├── useModelManager.js     # Threat model CRUD (localStorage persistence)
│   │   ├── useUserDocs.js         # Document management + IDB cache purge on remove
│   │   ├── useParseResult.js      # files / parseResult / xml state
│   │   └── useVectorStore.js      # VectorStore + ColBERTVectorStore refs
│   ├── components/
│   │   ├── KBPanel.jsx            # Knowledge base accordion viewer
│   │   ├── UserDocsPanel.jsx      # Document upload + management panel
│   │   └── ScopeSelector.jsx      # In-scope / out-of-scope tag selector
│   ├── features/
│   │   ├── intelligence/
│   │   │   ├── IntelligencePanel.jsx        # Intelligence hub (8 sub-tabs)
│   │   │   ├── panelHelpers.jsx             # SEV_COLOR, renderMarkdown, chunkCard, etc.
│   │   │   └── tabs/
│   │   │       ├── AIAssistantTab.jsx
│   │   │       ├── PostureControlsTab.jsx
│   │   │       ├── CrossDocTab.jsx
│   │   │       ├── MisconfigsTab.jsx
│   │   │       ├── ThreatIntelTab.jsx
│   │   │       ├── ScopeTab.jsx
│   │   │       ├── ResourceIntelTab.jsx
│   │   │       └── ArchLayersTab.jsx
│   │   ├── analysis/
│   │   │   ├── AnalysisPanel.jsx            # STRIDE / threat analysis tab
│   │   │   └── AnalysisErrorBoundary.jsx
│   │   └── pages/
│   │       ├── LandingPage.jsx              # Model creation / selection screen
│   │       └── DocumentsPage.jsx            # Build Model tab (upload + app details)
│   ├── constants/
│   │   ├── layout.js              # NW=84, NH=60, HGAP=18, VGAP=12, LEGEND_W=252, etc.
│   │   └── styles.js              # C (color palette), MONO, SANS, SEV_COLOR, card(), sectionBar()
│   ├── data/
│   │   └── kb-domains.js          # Built-in knowledge base content (KB object by domain)
│   └── lib/
│       ├── WllamaManager.js       # Active LLM engine — llama.cpp WASM via @wllama/wllama
│       ├── ThreataformEngine.js   # Next-gen engine (auto-loads model.tnlm) — not yet wired
│       ├── ThrataformRAG.js       # RAG: RecursiveTextSplitter, BM25Index, VectorStore, hybridSearch
│       ├── observability.js       # LOG, ThreataformError, createInferenceTracker, logHybridSearch
│       ├── diagram/
│       │   ├── DFDGenerator.js    # mxGraphModel XML generation
│       │   ├── LegendBuilder.js   # DFD legend cell builder
│       │   └── ExportUtils.js     # .lucid bundle + text/markdown report generation
│       ├── iac/
│       │   ├── TerraformParser.js
│       │   ├── CFNParser.js
│       │   ├── SecurityAnalyzer.js
│       │   ├── PolicyEvaluator.js
│       │   └── OrgTreeBuilder.js
│       ├── intelligence/
│       │   ├── ThreatModelIntelligence.js   # BM25 intelligence engine
│       │   └── ArchitectureAnalyzer.js
│       ├── rag/
│       │   ├── BM25Index.js
│       │   ├── VectorStore.js       # SingleVectorStore + ColBERTVectorStore + HNSW
│       │   ├── HybridRetriever.js   # 4-stage: BM25 + dense + ColBERT + RRF
│       │   ├── Chunker.js           # RecursiveTextSplitter, SemanticChunker, makeChunker
│       │   ├── HyDE.js              # Hypothetical Document Embeddings
│       │   └── SelfRAG.js           # Self-reflective retrieval loop
│       ├── ingestion/
│       │   ├── FileRouter.js
│       │   ├── PDFExtractor.js
│       │   ├── DocxExtractor.js
│       │   ├── SpreadsheetExtractor.js
│       │   ├── PresentationExtractor.js
│       │   ├── ImageExtractor.js
│       │   ├── AudioExtractor.js
│       │   ├── MarkupExtractor.js
│       │   └── StructuredExtractor.js
│       ├── llm/
│       │   ├── Model.js             # ThreataformLM-200M forward pass, generate, embed
│       │   ├── Tokenizer.js         # BPE tokenizer, 32K vocab, SELF-RAG tokens
│       │   ├── WeightsLoader.js     # .tnlm parser + IDB cache + autoLoad
│       │   ├── Ops.js               # All math primitives (matmul, RMSNorm, RoPE, etc.)
│       │   ├── NLP.js               # SecurityNER, SemanticChunker, CoreferenceResolver
│       │   └── LoRA.js              # In-browser fine-tuning, 168 adapter pairs
│       └── mcp/
│           ├── MCPToolRegistry.js   # Built-in MCP tools
│           ├── MCPClient.js         # WebSocket MCP client for external tools
│           └── tools/
│               ├── CVSSScorer.js
│               ├── ThreatDBTool.js
│               └── ComplianceChecker.js
├── src/workers/
│   ├── engineWorker.js            # ThreataformLM inference + LoRA training Web Worker
│   ├── ingestWorker.js            # File chunking + embedding Web Worker
│   ├── llmWorker.js               # wllama generation worker (active)
│   └── embedWorker.js             # wllama embedding worker (active)
├── public/
│   ├── model.tnlm                 # ThreataformLM weights (smoke-test: 300KB; prod: ~50MB)
│   └── manifest.webmanifest       # PWA manifest
├── scripts/                       # Python training pipeline (see Training Pipeline section)
├── vite.config.js                 # Vite + vite-plugin-pwa configuration
└── package.json
```

---

## Security & Privacy

- **100% client-side.** Terraform code and documents never leave your browser.
- **No telemetry.** No analytics, no crash reporting, no external API calls from the app.
- **Files never uploaded.** Processed locally via the File API and Web Workers.
- **Air-gap compatible.** PWA service worker caches the app shell for offline-first loading. GGUF models loaded from disk work without any network connection.
- **IndexedDB only.** Embedding vectors and model weights cached in the browser's local IndexedDB.

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI | React 18, Lucide icons, inline CSS |
| Build | Vite 5.4, vite-plugin-pwa |
| Active LLM | @wllama/wllama 2.3.7 (llama.cpp WASM, user-loaded .gguf) |
| Custom LLM | ThreataformLM-200M (pure JS, engineWorker.js, loads model.tnlm) |
| PDF extraction | pdfjs-dist 4.10 |
| DOCX extraction | mammoth 1.8 |
| XLSX extraction | SheetJS 0.18 |
| OCR | Tesseract.js |
| ZIP / PPTX | jszip 3.10 |
| Diagrams | draw.io / Lucidchart mxGraph XML |
| Persistence | localStorage (model state) + IndexedDB (vectors + model cache) |
| PWA | vite-plugin-pwa — offline-first service worker |

---

## Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org/) Enterprise v18.1
- [HashiCorp Terraform](https://developer.hashicorp.com/terraform)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) — Microsoft
- [SELF-RAG](https://arxiv.org/abs/2310.11511) — Asai et al. 2023
- [HyDE](https://arxiv.org/abs/2212.10496) — Gao et al. 2022
- [ColBERT](https://arxiv.org/abs/2004.12832) — Khattab & Zaharia 2020
- [RRF](https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf) — Cormack et al. 2009
