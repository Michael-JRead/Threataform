import React, { useState, useCallback, useRef, useMemo, useEffect, Component } from "react";
import { useModelManager } from './src/hooks/useModelManager.js';
import { useLLM } from './src/hooks/useLLM.js';
import { useUserDocs } from './src/hooks/useUserDocs.js';
import { useParseResult } from './src/hooks/useParseResult.js';
import { useVectorStore } from './src/hooks/useVectorStore.js';
// ── Local AI inference — wllama (llama.cpp WASM) + custom RAG engine ──────────
// Runs 100% offline. No internet. No API. No installation required.
// User loads a GGUF model file from their local disk.
import { wllamaManager } from './src/lib/WllamaManager.js';
import { VectorStore, hybridSearch as ragHybridSearch, rerank as crossEncoderRerank, prewarmCrossEncoder } from './src/lib/ThrataformRAG.js';
import { hydeTemplate } from './src/lib/rag/HyDE.js';
import { mcpRegistry } from './src/lib/mcp/MCPToolRegistry.js';
import {
  BookOpen, Upload, Brain, Microscope, MapIcon, Building2, Search, ShieldCheck,
  ListChecks, GitCompare, ShieldAlert, Zap, TriangleAlert, ScanLine, Layers,
  ImageIcon, BarChart2, Code2, BookMarked, LayoutList, ChevronLeft,
  ArrowRight, Trash2, FolderOpen, Loader2, AppWindow, Sparkles, Shield, Cloud,
  ClipboardList, Lock, SquareStack, DoorOpen, ArrowLeftRight, Globe, RefreshCw,
  KeyRound, LinkIcon, Database, FileText, ChevronDown, ChevronRight,
  CheckCircle2, AlertCircle, Plus, X, Home, Settings, Info, Eye, EyeOff,
  BarChart, TrendingUp, Target, Activity, ArrowUpRight, CheckSquare, Square,
  PenLine, RotateCcw, Cpu, Server, Network, HardDrive, Users, Plug,
  Download, XCircle, CheckCircle, Package,
  Bot, MessageSquare, Send, StopCircle, ChevronUp,
  KB_DOMAIN_ICONS,
} from "./src/icons.jsx";
import { NW, NH, LH, VGAP, HGAP, TPAD, TVPAD, HDRH, TGAP, CPAD, MAXCOLS, LEGEND_W } from './src/constants/layout.js';
import { MONO, SANS, C, SEV_COLOR, SEV_BG, card, sectionBar, hlXml } from './src/constants/styles.js';
import { TIERS, detectPaveLayer } from './src/constants/tiers.js';
import { RT } from './src/data/resource-types.js';
import { KB } from './src/data/kb-domains.js';
import { _STOP, _ENTITY_PATTERNS } from './src/data/entity-patterns.js';
import { ATTACK_TECHNIQUES, TF_ATTACK_MAP, CWE_DETAILS, STRIDE_PER_ELEMENT, getElementType as _getElementType } from './src/data/attack-data.js';
import { TF_MISCONFIG_CHECKS } from './src/data/misconfig-checks.js';
import { CONFIDENCE_BY_METHOD, mkEvidence, CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS, NIST_CSF_CHECKS } from './src/data/control-detection.js';
import { parseTFMultiFile, parseCFNFiles, inferArchitectureHierarchy, parseHCLBody } from './src/lib/iac/TerraformParser.js';
import ThreatModelIntelligence from './src/lib/intelligence/ThreatModelIntelligence.js';
import { buildLegendCells } from './src/lib/diagram/LegendBuilder.js';
import { generateDFDXml } from './src/lib/diagram/DFDGenerator.js';
import { makeZipOneFile, generateLucidJson, generateTXTReport, generateMarkdownReport } from './src/lib/diagram/ExportUtils.js';
import { tfAttr, tfBool, tfBlock, runSecurityChecks, identifyTrustBoundaries, buildArchitectureNarrative, buildStrideLMByTier, classifyDoc, buildContextFromDocs, generateAnalysis } from './src/lib/iac/SecurityAnalyzer.js';
import { architectureAnalyzer } from './src/lib/intelligence/ArchitectureAnalyzer.js';
import AnalysisErrorBoundary from './src/features/analysis/AnalysisErrorBoundary.jsx';
import ArchitectureImageViewer from './src/components/ArchitectureImageViewer.jsx';
import KBPanel from './src/components/KBPanel.jsx';
import LandingPage from './src/features/pages/LandingPage.jsx';
import UserDocsPanel from './src/components/UserDocsPanel.jsx';
import DocumentsPage from './src/features/pages/DocumentsPage.jsx';
import AnalysisPanel from './src/features/analysis/AnalysisPanel.jsx';
import IntelligencePanel from './src/features/intelligence/IntelligencePanel.jsx';

// ═══════════════════════════════════════════════════════════════════════════════
// ENTERPRISE TERRAFORM ARCHITECTURE INTELLIGENCE PLATFORM  v1.0
// ─────────────────────────────────────────────────────────────────────────────
//  Deep knowledge areas:
//  1. xSphere Private Cloud ↔ AWS Hybrid Integration
//  2. Spinnaker.io CD Platform & Terraform Orchestration
//  3. AWS IAM · Organizations · OUs · SCPs (Zero-Trust / Defense-in-Depth)
//  4. Jenkins / Jules → Terraform → xSphere/AWS Bootstrap Pipelines
//  5. Enterprise Multi-Repo TF DFD — Upload files → parse → draw.io XML
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// FILE EXTRACTION UTILITIES — PDF.js + Tesseract.js (CDN lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════════════

function _loadScript(src) {
  return new Promise((res, rej) => {
    if (document.querySelector(`script[src="${src}"]`)) { res(); return; }
    const s = document.createElement("script");
    s.src = src; s.onload = res; s.onerror = rej;
    document.head.appendChild(s);
  });
}

async function _loadPdfJs() {
  if (window.pdfjsLib) return;
  await _loadScript("https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js");
  window.pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
}

async function _loadTesseract() {
  if (window.Tesseract) return;
  await _loadScript("https://cdn.jsdelivr.net/npm/tesseract.js@4/dist/tesseract.min.js");
}

async function _ocrImageSource(imageSource) {
  await _loadTesseract();
  const worker = await window.Tesseract.createWorker("eng");
  try {
    const { data: { text } } = await worker.recognize(imageSource);
    return text.trim();
  } finally {
    await worker.terminate();
  }
}

async function _extractPdfPage(page) {
  const tc = await page.getTextContent();
  const text = tc.items.map(it => it.str).join(" ").trim();
  if (text.length > 40) return text; // text-based page

  // Image-based / scanned page — render to canvas then OCR
  const viewport = page.getViewport({ scale: 1.5 });
  const canvas = document.createElement("canvas");
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  await page.render({ canvasContext: canvas.getContext("2d"), viewport }).promise;
  const ocr = await _ocrImageSource(canvas);
  return ocr || "";
}

/**
 * extractTextFromFile(file) → Promise<string>
 * Extracts rich text context from any uploaded file:
 *  - PDF  → PDF.js text layer; image pages → Tesseract.js OCR
 *  - Image files → Tesseract.js OCR with structural wrapper
 *  - Everything else → FileReader.readAsText()
 */
async function extractTextFromFile(file) {
  const ext = (file.name.split(".").pop() || "").toLowerCase();

  if (ext === "pdf") {
    try {
      await _loadPdfJs();
      const arrayBuf = await file.arrayBuffer();
      const doc = await window.pdfjsLib.getDocument({ data: arrayBuf }).promise;
      const pages = await Promise.all(
        Array.from({ length: doc.numPages }, (_, i) =>
          doc.getPage(i + 1).then(_extractPdfPage)
        )
      );
      return pages.filter(Boolean).join("\n\n");
    } catch (err) {
      console.warn("[extractTextFromFile] PDF extraction failed:", err);
      return `[PDF: ${file.name} — extraction failed]`;
    }
  }

  if (/^image\//i.test(file.type) || /\.(png|jpg|jpeg|webp|bmp|tiff?)$/i.test(file.name)) {
    try {
      const dataUrl = await new Promise((res, rej) => {
        const r = new FileReader();
        r.onload = e => res(e.target.result);
        r.onerror = () => rej(new Error("FileReader error"));
        r.readAsDataURL(file);
      });
      const ocr = await _ocrImageSource(dataUrl);
      return `[Image: ${file.name}]\n${ocr || "[No extractable text — visual/diagram content]"}`;
    } catch (err) {
      console.warn("[extractTextFromFile] Image OCR failed:", err);
      return `[Image: ${file.name} — OCR failed]`;
    }
  }

  // All other text-readable files (tf, hcl, txt, md, json, yaml, csv, xml, sentinel…)
  return new Promise(res => {
    const r = new FileReader();
    r.onload = e => res(e.target.result || "");
    r.onerror = () => res("");
    r.readAsText(file);
  });
}


// ─────────────────────────────────────────────────────────────────────────────
// INTELLIGENCE PANEL
// Enterprise Threat Model Intelligence — zero hallucination, verbatim retrieval
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR DB — IndexedDB persistence for embeddings (no re-embed on reload)
// ─────────────────────────────────────────────────────────────────────────────
let _vdbConn = null;
function _getVectorDB() {
  if (!_vdbConn) {
    _vdbConn = new Promise((resolve) => {
      // v3: adds 'sessions' object store for H2 session history
      const req = indexedDB.open('threataform-vectors', 3);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('vectors')) db.createObjectStore('vectors');
        if (!db.objectStoreNames.contains('sessions')) {
          const s = db.createObjectStore('sessions', { keyPath: 'id' });
          s.createIndex('createdAt', 'createdAt');
        }
      };
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = () => { _vdbConn = null; resolve(null); };
    });
  }
  return _vdbConn;
}

// H2: Write a session record to IDB (fire-and-forget)
async function sessionDbPut(record) {
  const db = await _getVectorDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('sessions', 'readwrite');
      tx.objectStore('sessions').put(record);
      tx.oncomplete = () => res();
      tx.onerror = () => res();
    } catch { res(); }
  });
}

// H2: Get recent sessions (up to N, newest first)
async function sessionDbGetRecent(limit = 10) {
  const db = await _getVectorDB();
  if (!db) return [];
  return new Promise((res) => {
    try {
      const tx = db.transaction('sessions');
      const req = tx.objectStore('sessions').index('createdAt').getAll();
      req.onsuccess = () => {
        const all = req.result || [];
        res(all.sort((a, b) => b.createdAt - a.createdAt).slice(0, limit));
      };
      req.onerror = () => res([]);
    } catch { res([]); }
  });
}
async function vdbGet(key) {
  const db = await _getVectorDB();
  if (!db) return null;
  return new Promise((res) => {
    try {
      const r = db.transaction('vectors').objectStore('vectors').get(key);
      r.onsuccess = () => res(r.result ?? null);
      r.onerror = () => res(null);
    } catch { res(null); }
  });
}
async function vdbPut(key, value) {
  const db = await _getVectorDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      tx.objectStore('vectors').put(value, key);
      tx.oncomplete = () => res();
      tx.onerror = () => res();
    } catch { res(); }
  });
}
async function vdbGetMany(keys) {
  const db = await _getVectorDB();
  if (!db) return {};
  return new Promise((res) => {
    const results = {};
    const tx = db.transaction('vectors');
    const store = tx.objectStore('vectors');
    let pending = keys.length;
    if (!pending) { res(results); return; }
    keys.forEach(k => {
      const r = store.get(k);
      r.onsuccess = () => { results[k] = r.result ?? null; if (--pending === 0) res(results); };
      r.onerror   = () => { results[k] = null;             if (--pending === 0) res(results); };
    });
  });
}
// Stable chunk hash: first 50 chars + length (no crypto needed)
function chunkHash(text) { return (text.substring(0, 50) + '|' + text.length).replace(/[^\w|]/g, '_'); }

// H1: Delete cached vectors for specific IDB keys (computed from chunks of the removed doc)
async function vdbDeleteKeys(keys) {
  if (!keys?.length) return;
  const db = await _getVectorDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      const store = tx.objectStore('vectors');
      keys.forEach(k => store.delete(k));
      tx.oncomplete = () => res();
      tx.onerror = () => res();
    } catch { res(); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [mainTab, setMainTab] = useState("knowledge");
  const [kbDomain, setKbDomain] = useState("xsphere");
  // ── Parse Result State — useParseResult ─────────────────────────────────────
  const { files, setFiles, parseResult, setParseResult, xml, setXml } = useParseResult();
  const [dfdTab, setDfdTab] = useState("stats");
  const [copied, setCopied] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [scopeFiles, setScopeFiles] = useState(null); // null = all in scope
  const [ingestState, setIngestState] = useState(null); // null=idle | {total,done,current}

  // ── Threat Model Management — useModelManager ───────────────────────────────
  const [appMode, setAppMode] = useState("landing");
  const [diagramImage, setDiagramImage] = useState(null);
  const [archAnalysis, setArchAnalysis] = useState(null);
  const [archOverrides, setArchOverrides] = useState({});
  const [archAnalyzing, setArchAnalyzing] = useState(false);
  const [archEditingField, setArchEditingField] = useState(null);

  const {
    threatModels, currentModel, setCurrentModel, modelDetails, setModelDetails,
    deleteModel, updateModelMeta, saveModelDetails,
    createModel: _createModel, openModel: _openModel,
  } = useModelManager();

  // reparseRef avoids TDZ: openModel wrapper is declared before reparse
  const reparseRef = useRef(null);

  // Intelligence engine ref (declared early — needed by useUserDocs below)
  const intelligenceRef = useRef(new ThreatModelIntelligence());
  const [intelligenceVersion, setIntelligenceVersion] = useState(0);

  // ── User Documents — useUserDocs ────────────────────────────────────────────
  const {
    userDocs, setUserDocsState, saveUserDocs, removeUserDoc, vdbModelIdRef,
  } = useUserDocs({
    currentModel, updateModelMeta, intelligenceRef,
    chunkHashFn: chunkHash, vdbDeleteKeysFn: vdbDeleteKeys,
  });
  const setUserDocs = saveUserDocs; // alias for existing call sites

  // ── App-level model lifecycle — orchestrates cross-subsystem state resets ───
  const createModel = useCallback((name) => {
    const model = _createModel(name);
    setDiagramImage(null); setArchAnalysis(null); setArchOverrides({});
    setAppMode("documents"); setMainTab("build");
    setFiles([]); setParseResult(null); setXml(""); setScopeFiles(null); setError("");
    try {
      setUserDocsState(JSON.parse(localStorage.getItem(`tf-model-${model.id}-docs`) || "[]"));
    } catch { setUserDocsState([]); }
  }, [_createModel, setUserDocsState]); // eslint-disable-line

  const openModel = useCallback((model) => {
    _openModel(model);
    setAppMode("documents"); setMainTab("build");
    setFiles([]); setParseResult(null); setXml(""); setScopeFiles(null); setError("");
    let savedTF = [];
    try {
      savedTF = JSON.parse(localStorage.getItem(`tf-model-${model.id}-files`) || "[]");
      if (savedTF.length) setFiles(savedTF);
    } catch {}
    try {
      setUserDocsState(JSON.parse(localStorage.getItem(`tf-model-${model.id}-docs`) || "[]"));
    } catch { setUserDocsState([]); }
    try {
      setDiagramImage(localStorage.getItem(`tf-model-${model.id}-diagram-image`) || null);
    } catch { setDiagramImage(null); }
    try {
      const saved = JSON.parse(localStorage.getItem(`tf-model-${model.id}-arch-analysis`) || "{}");
      setArchAnalysis(saved.base || null); setArchOverrides(saved.overrides || {});
    } catch { setArchAnalysis(null); setArchOverrides({}); }
    if (savedTF.length) setTimeout(() => reparseRef.current?.(savedTF), 0);
  }, [_openModel, setUserDocsState]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Enterprise Architecture Layer Analysis (7-layer model) ───────────────────
  const [archLayerAnalysis, setArchLayerAnalysis] = useState(null);
  const archLayerAnalysisRef = useRef(null);
  const [archLayerVersion, setArchLayerVersion] = useState(0);

  // ── Threataform Assistant — wllama (local GGUF) + Custom RAG Engine ──────────
  // useLLM manages all LLM/embed state declarations; loadWllama stays in App
  const {
    llmStatus,      setLlmStatus,
    llmProgress,    setLlmProgress,
    llmStatusText,  setLlmStatusText,
    embedStatus,    setEmbedStatus,
    embedProgress,  setEmbedProgress,
    selectedLlmModel, setSelectedLlmModel,
    wllamaModelName,  setWllamaModelName,
    wllamaModelSize,  setWllamaModelSize,
  } = useLLM();

  // ── Vector Store — useVectorStore ───────────────────────────────────────────
  const { vectorStoreRef, colbertStoreRef } = useVectorStore();
  const pendingLlmRef   = useRef({});  // retained for compatibility
  // IaC-IR: computed org tree + SCP ceilings
  const [computedIR, setComputedIR] = useState({ organizationTree: null, scpCeilings: {}, gaps: [] });
  const computedIRRef = useRef(computedIR);

  // Keep a ref so reparse (stable callback) can always access latest userDocs
  const userDocsRef = useRef(userDocs);
  const parseResultRef = useRef(parseResult);
  const filesRef = useRef([]);
  const archOverridesRef = useRef({});
  useEffect(() => { userDocsRef.current = userDocs; }, [userDocs]);
  useEffect(() => { parseResultRef.current = parseResult; }, [parseResult]);
  useEffect(() => { filesRef.current = files; }, [files]);

  // ── IaC-IR: Build org tree + SCP ceilings whenever parse result changes ──────
  useEffect(() => {
    if (!parseResult?.resources?.length) return;
    let cancelled = false;
    (async () => {
      try {
        const [{ buildOrgTree }, { computeSCPCeilings }] = await Promise.all([
          import('./src/lib/iac/OrgTreeBuilder.js'),
          import('./src/lib/iac/PolicyEvaluator.js'),
        ]);
        if (cancelled) return;
        const tree = buildOrgTree(parseResult.resources);
        const ceilings = computeSCPCeilings(parseResult.resources, tree);
        const gaps = [
          ...tree.gaps,
          ...Object.entries(ceilings)
            .filter(([, v]) => v.includes('UNKNOWN'))
            .map(([k]) => `Account ${k}: SCP ceiling partially unknown (intrinsic references)`),
        ];
        const irData = { organizationTree: tree, scpCeilings: ceilings, gaps };
        computedIRRef.current = irData;
        setComputedIR(irData);
      } catch (err) {
        console.warn('[IaC-IR] Failed to compute org tree:', err);
      }
    })();
    return () => { cancelled = true; };
  }, [parseResult]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { archOverridesRef.current = archOverrides; }, [archOverrides]);
  useEffect(() => { archLayerAnalysisRef.current = archLayerAnalysis; }, [archLayerAnalysis]);

  // Run 7-layer enterprise architecture analysis whenever TF files change
  useEffect(() => {
    if (!files.length) { setArchLayerAnalysis(null); setArchLayerVersion(0); return; }
    try {
      const analysis = architectureAnalyzer.analyzeArchitecture(files);
      setArchLayerAnalysis(analysis);
      setArchLayerVersion(v => v + 1);
    } catch (err) {
      console.warn('[ArchLayer] Analysis failed:', err);
    }
  }, [files]); // eslint-disable-line react-hooks/exhaustive-deps

  // Stable refs so reparse ([] deps) and grade effect can always read current values
  const currentModelRef    = useRef(currentModel);
  const modelDetailsRef    = useRef(modelDetails);
  const updateModelMetaRef = useRef(updateModelMeta);
  useEffect(() => { currentModelRef.current    = currentModel;    }, [currentModel]);
  useEffect(() => { modelDetailsRef.current    = modelDetails;    }, [modelDetails]);
  useEffect(() => { updateModelMetaRef.current = updateModelMeta; }, [updateModelMeta]);
  // vdbModelIdRef is managed internally by useUserDocs hook (synced with currentModel)

  // Synthetic "model context" doc injected as the first document in every .build() call.
  // Seeds retrieval with product name, environment, data classification, and compliance scope
  // so queries like "what frameworks are in scope?" return model-level metadata.
  const buildModelContextDoc = useCallback(() => {
    const m = currentModelRef.current;
    const d = modelDetailsRef.current;
    if (!m?.name) return null;
    const lines = [
      `Threat Model Product: ${m.name}`,
      d.environment                  ? `Environment: ${d.environment}` : null,
      d.dataClassification?.length   ? `Data Classification: ${d.dataClassification.join(', ')}` : null,
      d.frameworks?.length           ? `Industry Compliance Scope: ${d.frameworks.join(', ')}` : null,
      d.threatFrameworks?.length     ? `Threat Modeling Frameworks: ${d.threatFrameworks.join(', ')}` : null,
      d.keyFeatures                  ? `Key Features: ${d.keyFeatures}` : null,
      d.owner                        ? `Team / Owner: ${d.owner}` : null,
      d.description                  ? `Architecture Notes: ${d.description}` : null,
    ].filter(Boolean);
    return { name:'__model_context__', path:'__model_context__', ext:'txt',
             content: lines.join('\n'), size:0, _synthetic:true };
  }, []);

  // Synthetic doc from architecture narrative overrides — feeds arch edits back into intelligence index
  const buildArchContextDoc = useCallback(() => {
    const ovNarrative = archOverridesRef.current?.narrative || {};
    const lines = Object.entries(ovNarrative)
      .filter(([,v]) => v?.trim())
      .map(([k,v]) => `${k}: ${v}`);
    if (!lines.length) return null;
    return { name:'__arch_context__', path:'__arch_context__', ext:'txt',
             content: lines.join('\n'), size:0, _synthetic:true };
  }, []);

  // After every intelligence rebuild, compute posture grade and persist it to the model card
  useEffect(() => {
    if (!parseResultRef.current || !currentModelRef.current) return;
    try {
      const posture = intelligenceRef.current.getSecurityPosture(parseResultRef.current.resources||[]);
      if (posture?.grade) {
        updateModelMetaRef.current({
          grade:       posture.grade,
          gradeColor:  posture.gradeColor,
          tfFileCount: parseResultRef.current.resources?.length || 0,
        });
      }
    } catch(_) {}
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // Rebuild intelligence whenever userDocs or modelDetails (Application Details form) changes.
  // modelDetails is in deps so filling in env / compliance scope / description immediately
  // re-indexes the synthetic model-context doc — no file upload required.
  useEffect(() => {
    const pr = parseResultRef.current;
    const ctxDoc = buildModelContextDoc();
    const archDoc = buildArchContextDoc();
    const syntheticDocs = [ctxDoc, archDoc].filter(Boolean);
    const docsWithCtx = [...syntheticDocs, ...userDocs];
    intelligenceRef.current = new ThreatModelIntelligence();
    intelligenceRef.current.build(docsWithCtx, pr?.resources||[], pr?.modules||[], archLayerAnalysisRef.current);
    setIntelligenceVersion(v => v+1);
    // Regenerate XML with enriched intelligence if we have parsed data
    if (pr && (pr.resources.length > 0 || pr.modules.length > 0)) {
      const x = generateDFDXml(pr.resources, pr.modules, pr.connections, intelligenceRef.current, archLayerAnalysisRef.current);
      setXml(x);
    }
  }, [userDocs, modelDetails, archOverrides]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-populate Architecture Description when intelligence rebuilds and field is empty
  useEffect(() => {
    if (!intelligenceRef.current?._built) return;
    const md = modelDetailsRef.current;
    if (md?.description?.trim()) return; // never overwrite user-written content
    const pr = parseResultRef.current;
    const summary = intelligenceRef.current.getArchSummaryText(pr?.resources || []);
    if (summary.trim()) {
      const updated = { ...md, description: summary };
      setModelDetails(updated);
      const cm = currentModelRef.current;
      if (cm) {
        try { localStorage.setItem(`tf-model-${cm.id}-details`, JSON.stringify(updated)); } catch {}
      }
    }
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── loadWllama: load a GGUF model from a File object OR a URL string ─────────
  // File object → user file picker
  // URL string  → Electron bundled model (served from /models via local HTTP)
  // null        → unload current model
  const loadWllama = useCallback(async (fileOrUrl) => {
    if (!fileOrUrl) {
      // Unload current model
      await wllamaManager.unload();
      setLlmStatus("idle"); setLlmProgress(0); setLlmStatusText("");
      setSelectedLlmModel(""); setWllamaModelName(""); setWllamaModelSize(0);
      setEmbedStatus("idle"); vectorStoreRef.current.clear(); setEmbedProgress(null);
      return;
    }
    setLlmStatus("loading"); setLlmProgress(0); setLlmStatusText("");
    try {
      const opts = {
        contextSize: 4096,
        onProgress: ({ pct, loaded, total }) => {
          setLlmProgress(pct);
          const mb = Math.round(loaded / 1024 / 1024);
          const totalMb = Math.round(total / 1024 / 1024);
          setLlmStatusText(totalMb > 0 ? `${mb}MB / ${totalMb}MB` : `${mb}MB`);
        },
      };
      // URL string → Electron local model server; File object → user file picker
      const result = typeof fileOrUrl === 'string'
        ? await wllamaManager.loadFromUrl(fileOrUrl, { ...opts, useCache: true })
        : await wllamaManager.loadFromFile(fileOrUrl, opts);
      setLlmStatus("ready"); setLlmProgress(100); setLlmStatusText("");
      setSelectedLlmModel(result.modelName);
      setWllamaModelName(result.modelName);
      setWllamaModelSize(result.sizeMB);
      // H3: Persist last-used model name for display on next session
      try { localStorage.setItem('tf-last-model-name', result.modelName); } catch {}
      // Trigger vector index rebuild now that embeddings are available
      rebuildVectorStore();
      // G1: Pre-warm cross-encoder reranker in the background (22MB, one-time download)
      prewarmCrossEncoder();
    } catch (err) {
      setLlmStatus("error");
      setLlmStatusText(err.message || "Failed to load model. Is the file a valid GGUF?");
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Electron: auto-load bundled model from /models on startup ────────────────
  // Runs once on mount. If running inside Electron and /models has a .gguf file,
  // the model server URL is fetched from the main process and wllama loads it
  // automatically — no file picker needed, no internet required.
  useEffect(() => {
    if (!window?.electronAPI?.isElectron) return;
    window.electronAPI.getModelInfo().then(({ port, models }) => {
      if (models.length > 0 && !wllamaManager.isLoaded) {
        const modelUrl = `http://127.0.0.1:${port}/${encodeURIComponent(models[0])}`;
        console.log('[Threataform] Electron: auto-loading bundled model →', modelUrl);
        loadWllama(modelUrl);
      }
    }).catch(() => {}); // Silently ignore if IPC fails
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── rebuildVectorStore: embed all doc chunks using wllama ────────────────────
  const rebuildVectorStore = useCallback(async () => {
    if (!wllamaManager.isLoaded) return;
    const chunks = intelligenceRef.current.chunks;
    if (!chunks?.length) return;

    const modelId = currentModelRef.current?.id || "global";
    const keys = chunks.map(c => `vec_${modelId}_${chunkHash(c.text)}`);
    const cached = await vdbGetMany(keys);

    const needEmbed = [];
    const result = chunks.map((c, i) => {
      if (cached[keys[i]]) return { ...c, vector: cached[keys[i]] };
      needEmbed.push({ chunkIdx: i, chunk: c, key: keys[i] });
      return { ...c, vector: null };
    });

    // Populate vector store with cached vectors immediately
    vectorStoreRef.current.clear();
    colbertStoreRef.current.clear(); // ColBERT cleared; populated below if embedMulti available
    result.forEach((c, i) => {
      if (c.vector) vectorStoreRef.current.add(`chunk_${i}`, c.vector, c);
    });

    if (!needEmbed.length) { setEmbedProgress(null); return; }

    // Embed uncached chunks in small batches (wllama is sequential, so keep batches small)
    const BATCH = 8;
    setEmbedProgress({ done: 0, total: needEmbed.length });
    for (let i = 0; i < needEmbed.length; i += BATCH) {
      if (!wllamaManager.isLoaded) break; // user unloaded model mid-run
      const batch = needEmbed.slice(i, i + BATCH);
      try {
        const vectors = await wllamaManager.embed(batch.map(b => b.chunk.text));
        batch.forEach((b, j) => {
          const vec = vectors[j];
          if (!vec?.length) return;
          result[b.chunkIdx] = { ...b.chunk, vector: vec };
          vectorStoreRef.current.add(`chunk_${b.chunkIdx}`, vec, b.chunk);
          vdbPut(b.key, vec);
          // ColBERT multi-vector embeddings (late-interaction) — populate if model supports it
          try {
            const multiVecs = wllamaManager.embedMulti?.(b.chunk.text);
            if (multiVecs instanceof Promise) {
              multiVecs.then(mv => { if (mv?.length) colbertStoreRef.current.add(`chunk_${b.chunkIdx}`, mv, b.chunk); }).catch(() => {});
            } else if (multiVecs?.length) {
              colbertStoreRef.current.add(`chunk_${b.chunkIdx}`, multiVecs, b.chunk);
            }
          } catch { /* ColBERT skipped — single-vector still active */ }
        });
      } catch { /* skip failed batch */ }
      setEmbedProgress({ done: Math.min(i + BATCH, needEmbed.length), total: needEmbed.length });
    }
    setEmbedProgress(null);
    setEmbedStatus("ready");
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Rebuild vector store whenever intelligence rebuilds and wllama is loaded
  useEffect(() => {
    if (wllamaManager.isLoaded) rebuildVectorStore();
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── hybridSearch: BM25 + dense (wllama embeddings) via RRF ───────────────────
  const hybridSearch = useCallback(async (query, topK = 8, categoryFilter = null) => {
    const intel = intelligenceRef.current;
    const bm25Results = intel?._built ? intel.query(query, topK * 2) : [];

    const store = vectorStoreRef.current;
    // Offline BM25-only path (no model or no dense store)
    if (!wllamaManager.isLoaded || store.size === 0) {
      const results = bm25Results.slice(0, topK).map(r => ({ ...r, searchType: 'bm25' }));
      if (categoryFilter) {
        const filtered = results.filter(r => r.category && categoryFilter.includes(r.category));
        return filtered.length > 0 ? filtered : results;
      }
      return results;
    }

    try {
      // HyDE: expand query into hypothetical doc embedding for richer retrieval signal
      let queryVec;
      try {
        queryVec = await hydeTemplate(query, null, (text) => wllamaManager.embedQuery(text));
      } catch {
        // Fall back to plain query embedding if HyDE fails
        queryVec = await wllamaManager.embedQuery(query);
      }

      // Fused BM25 + dense retrieval with HyDE-expanded query vector + G3 category filter
      const fused = ragHybridSearch({ bm25Chunks: bm25Results, vectorStore: store, queryVec, topK: topK * 2, categoryFilter });
      // G1: Cross-encoder rerank the top-2*topK candidates, return topK
      return crossEncoderRerank(query, fused, topK);
    } catch {
      return bm25Results.slice(0, topK).map(r => ({ ...r, searchType: 'bm25' }));
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── generateLLMResponse: stream tokens via wllama (local WASM inference) ─────
  const generateLLMResponse = useCallback((messages, onToken) => {
    if (!wllamaManager.isLoaded) return Promise.reject(new Error("Model not loaded"));
    return wllamaManager.generate(messages, {
      onToken,
      maxTokens: 2048,
      temperature: 0.2,
    });
  }, []);

  // Auto-populate Architecture Analysis after each intelligence rebuild
  useEffect(() => {
    if (!parseResult && !userDocs.length) return;
    setArchAnalyzing(true);
    const timeout = setTimeout(() => {
      try {
        const result = intelligenceRef.current.analyzeArchitecture(
          parseResult?.resources || [], userDocs, modelDetails
        );
        setArchAnalysis(result);
        if (currentModel) {
          try {
            localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: result, overrides: archOverrides }));
          } catch {}
        }
      } finally { setArchAnalyzing(false); }
    }, 0);
    return () => clearTimeout(timeout);
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  const addUserDocs = useCallback((fileList, docCategory = "general", onProgress) => {
    // Accept PDFs, images, and text files; skip compiled binaries, archives, web assets
    const SKIP_EXT = /\.(ico|woff|woff2|ttf|eot|zip|tar|gz|7z|exe|dll|so|dylib|class|jar|war|pyc|lock)$/i;
    const candidates = Array.from(fileList)
      .filter(f => !SKIP_EXT.test(f.name) && f.size < 50 * 1024 * 1024); // skip >50MB
    if (!candidates.length) return Promise.resolve([]);
    return Promise.all(candidates.map(async f => {
      const path = f.webkitRelativePath || f.name;
      const name = f.name;
      const ext  = name.includes(".") ? name.split(".").pop().toLowerCase() : "txt";
      if (onProgress) onProgress(name, "processing");
      try {
        const content = await extractTextFromFile(f);
        if (onProgress) onProgress(name, "done");
        return { path, name, ext, content, binary: false, size: f.size, docCategory };
      } catch {
        if (onProgress) onProgress(name, "error");
        return { path, name, ext, content: `[Extraction failed: ${name}]`, binary: false, size: f.size, docCategory };
      }
    })).then(loaded => {
      const valid = loaded.filter(Boolean);
      if (!valid.length) return valid;
      let newDocs = [];
      saveUserDocs(prev => {
        const existingPaths = new Set(prev.map(d => d.path || d.name));
        newDocs = valid.filter(d => !existingPaths.has(d.path || d.name));
        return newDocs.length ? [...prev, ...newDocs] : prev;
      });
      return newDocs;
    });
  }, [saveUserDocs]);

  // Re-run parse + DFD whenever the TF files list changes
  // Uses userDocsRef so this callback stays stable without needing userDocs in deps.
  const reparse = useCallback(async (tfFiles) => {
    const ctxDoc = buildModelContextDoc();
    const archDoc = buildArchContextDoc();
    if (!tfFiles.length) {
      setParseResult(null); setXml("");
      const seedDocs = [ctxDoc, archDoc].filter(Boolean);
      intelligenceRef.current = new ThreatModelIntelligence();
      intelligenceRef.current.build(seedDocs, [], []);
      setIntelligenceVersion(v=>v+1);
      return;
    }

    // ── Separate HCL/TF files from JSON/CFN files ─────────────────────────────
    const CFN_SIG = /"AWSTemplateFormatVersion"|"Resources"\s*:\s*\{[\s\S]{1,500}"AWS::/;
    const hclFiles = tfFiles.filter(f => !/\.json$/i.test(f.name));
    const jsonFiles = tfFiles.filter(f => /\.json$/i.test(f.name));
    const cfnFiles  = jsonFiles.filter(f =>
      /\.cfn\.json$/i.test(f.name) || CFN_SIG.test(f.content || '')
    );

    const result = parseTFMultiFile(hclFiles);

    // ── Parse CFN files and merge resources ───────────────────────────────────
    if (cfnFiles.length > 0) {
      try {
        const cfnResult = await parseCFNFiles(cfnFiles);
        result.resources.push(...cfnResult.resources);
        result.gaps = [...(result.gaps || []), ...cfnResult.gaps];
      } catch (err) {
        console.warn('[reparse] CFN parsing failed:', err);
      }
    }

    setParseResult(result);
    // Rebuild intelligence: model context + arch context + uploaded docs + parsed resources
    const syntheticDocs = [ctxDoc, archDoc].filter(Boolean);
    const docsWithCtx = [...syntheticDocs, ...userDocsRef.current];
    intelligenceRef.current = new ThreatModelIntelligence();
    intelligenceRef.current.build(docsWithCtx, result.resources, result.modules, archLayerAnalysisRef.current);
    setIntelligenceVersion(v => v+1);

    // H2: Persist session snapshot for "Recent Scans" history
    // Also persist posture trend for sparkline (max 90 entries, ring buffer)
    try {
      const posture = intelligenceRef.current.getSecurityPosture?.(result.resources || []);
      const summary = intelligenceRef.current.getArchitectureSummary?.(result.resources || [], userDocsRef.current);
      if (posture?.grade && posture?.score != null) {
        try {
          const trendKey = 'tf-posture-trend';
          const existing = JSON.parse(localStorage.getItem(trendKey) || '[]');
          const entry = { date: new Date().toISOString().slice(0, 10), grade: posture.grade, score: posture.score };
          const updated = [...existing.slice(-89), entry]; // max 90 entries
          localStorage.setItem(trendKey, JSON.stringify(updated));
        } catch { /* trend write non-critical */ }
      }
      sessionDbPut({
        id: `session_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        createdAt: Date.now(),
        modelId: currentModelRef.current?.id || "global",
        modelName: currentModelRef.current?.name || modelDetailsRef.current?.name || "Unknown",
        fileCount: (filesRef.current || []).length,
        resourceCount: result.resources?.length || 0,
        postureGrade: posture?.grade || archLayerAnalysisRef.current?.grade || null,
        postureScore: posture?.score ?? null,
        findingCounts: {
          critical: summary?.misconfigs?.filter(m => m.severity === 'CRITICAL')?.length || 0,
          high:     summary?.misconfigs?.filter(m => m.severity === 'HIGH')?.length || 0,
          medium:   summary?.misconfigs?.filter(m => m.severity === 'MEDIUM')?.length || 0,
        },
        archLayerCount: archLayerAnalysisRef.current?.layerStatus?.filter(l => l.status === 'present')?.length ?? null,
      });
    } catch { /* session history write failure is non-critical */ }
    if (result.resources.length > 0 || result.modules.length > 0) {
      const x = generateDFDXml(result.resources, result.modules, result.connections, intelligenceRef.current, archLayerAnalysisRef.current);
      setXml(x);
    } else {
      setXml("");
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  reparseRef.current = reparse; // Keep ref current (avoids TDZ in openModel)

  // Accept ALL file types. TF/HCL/sentinel/tfvars → files state (parsed).
  // Everything else → userDocs (context). append=true merges instead of replacing.
  const readFiles = useCallback((fileList, append = false, docCategory = "general") => {
    const SKIP_BINARY = /\.(ico|woff|woff2|ttf|eot|zip|tar|gz|7z|exe|dll|so|dylib|class|jar|war|pyc)$/i;
    const isTF = f => /\.(tf|hcl|sentinel|tfvars)$/i.test(f.name) || /\.cfn\.json$/i.test(f.name);
    const all = Array.from(fileList).filter(f => !SKIP_BINARY.test(f.name) && f.size < 50*1024*1024);
    if (!all.length) return;
    setError("");

    const tfCandidates = all.filter(isTF);
    const ctxCandidates = all.filter(f => !isTF(f));
    const total = all.length;
    let done = 0;
    setIngestState({ total, done: 0, current: all[0]?.name || "" });
    const onFileDone = (name) => { done++; setIngestState({ total, done, current: name }); };

    const readAsText = f => new Promise(res => {
      const r = new FileReader();
      r.onload = ev => { onFileDone(f.name); res({ path: f.webkitRelativePath || f.name, name: f.name, content: ev.target.result || "", size: f.size }); };
      r.onerror = () => { onFileDone(f.name); res(null); };
      r.readAsText(f);
    });

    Promise.all([
      Promise.all(tfCandidates.map(readAsText)),
      Promise.all(ctxCandidates.map(f =>
        extractTextFromFile(f).then(content => {
          onFileDone(f.name);
          return { path: f.webkitRelativePath || f.name, name: f.name, content, size: f.size, docCategory };
        }).catch(() => { onFileDone(f.name); return null; })
      )),
    ]).then(([tfLoaded, ctxLoaded]) => {
      setIngestState(null);
      const validTF = tfLoaded.filter(Boolean);
      const validCtx = ctxLoaded.filter(Boolean);

      // Compute merged array OUTSIDE setFiles to avoid side-effects in state updater
      const existing = append ? filesRef.current : [];
      const existPaths = new Set(existing.map(f => f.path));
      const newTF = validTF.filter(f => !existPaths.has(f.path));
      const merged = [...existing, ...newTF].sort((a,b) => a.path.localeCompare(b.path));

      // Pure state update — no side effects inside
      setScopeFiles(null);
      setFiles(merged);

      // Side effects separately, after state update, using stable refs
      const cm = currentModelRef.current;
      if (cm) {
        try { localStorage.setItem(`tf-model-${cm.id}-files`, JSON.stringify(merged)); } catch {}
        updateModelMetaRef.current({ tfFileCount: merged.length });
      }
      reparse(merged); // reads fresh userDocsRef.current

      // Auto-route non-TF files to userDocs
      if (validCtx.length) {
        saveUserDocs(prev => {
          const existCtxPaths = new Set(prev.map(d => d.path || d.name));
          const newDocs = validCtx
            .filter(d => !existCtxPaths.has(d.path))
            .map(d => ({ ...d, ext: (d.name.split('.').pop() || "txt").toLowerCase() }));
          return newDocs.length ? [...prev, ...newDocs] : prev;
        });
      }
    }).catch(e => { setIngestState(null); setError(e.message); });
  }, [reparse, saveUserDocs]);

  // Delete a single TF file and re-parse the rest
  const removeFile = useCallback((path) => {
    const next = filesRef.current.filter(f => f.path !== path);
    setScopeFiles(null);
    setFiles(next);
    if (!next.length) { setParseResult(null); setXml(""); }
    else reparse(next);
    // Update persistence
    const cm = currentModelRef.current;
    if (cm) {
      try { localStorage.setItem(`tf-model-${cm.id}-files`, JSON.stringify(next)); } catch {}
      updateModelMetaRef.current({ tfFileCount: next.length });
    }
  }, [reparse]);

  // Clear all TF files
  const clearFiles = useCallback(() => {
    setFiles([]);
    setParseResult(null);
    setXml("");
    setScopeFiles(null);
    setError("");
  }, []);

  const handleDrop = useCallback(e=>{ e.preventDefault(); setDragging(false); readFiles(e.dataTransfer.files, true); }, [readFiles]);
  // Full <mxfile> wrapper with correct document-level indentation matching the working reference XML:
  //   <mxfile>            ← 0 spaces
  //     <diagram>         ← 2 spaces
  //       <mxGraphModel>  ← 4 spaces
  //         <root>        ← 6 spaces
  //           <mxCell>    ← 8 spaces
  //             <mxGeometry/> ← 10 spaces
  //           </mxCell>   ← 8 spaces
  // The inner xml (from generateDFDXml) starts at 0 — each line is indented +4 spaces
  // so that <mxGraphModel> sits at 4 spaces inside <diagram>.
  const drawioXml = xml
    ? `<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="app.diagrams.net" modified="${new Date().toISOString()}" agent="Threataform" version="21.0.0" type="device">\n  <diagram name="Enterprise Terraform DFD" id="enterprise-tf-dfd">\n${xml.split('\n').map(l=>'    '+l).join('\n')}\n  </diagram>\n</mxfile>`
    : "";
  // Download as .xml — Lucidchart enterprise lists "Draw.io (.xml, .drawio)" and .xml
  // extension passes more corporate DLP/firewall policies than .drawio.
  const download = () => {
    const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([drawioXml],{type:"application/xml"}));
    a.download="enterprise-tf-dfd.xml"; a.click();
  };
  const copy = () => {
    // Copy the full mxfile XML (including <mxfile> wrapper) so users can save as .drawio and upload to Lucidchart
    const done = () => { setCopied(true); setTimeout(()=>setCopied(false),2000); };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(drawioXml).then(done).catch(()=>{
        const ta=document.createElement("textarea"); ta.value=drawioXml;
        document.body.appendChild(ta); ta.select(); document.execCommand("copy");
        document.body.removeChild(ta); done();
      });
    } else {
      const ta=document.createElement("textarea"); ta.value=drawioXml;
      document.body.appendChild(ta); ta.select(); document.execCommand("copy");
      document.body.removeChild(ta); done();
    }
  };

  // ── Download .lucid (Lucid Standard Import — native Lucidchart format) ───────
  const downloadLucid = useCallback(() => {
    if (!parseResult) return;
    const json = generateLucidJson(parseResult.resources, parseResult.modules, parseResult.connections);
    const zipBytes = makeZipOneFile("document.json", json);
    const blob = new Blob([zipBytes], {type:"application/octet-stream"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "enterprise-tf-dfd.lucid";
    a.click();
    URL.revokeObjectURL(a.href);
  }, [parseResult]);

  const KB_DOMAINS = [
    {id:"xsphere",  label:"xSphere Cloud",         color:"#0277BD", Icon: Cloud},
    {id:"spinnaker",label:"Spinnaker.io",           color:"#00838F", Icon: Settings},
    {id:"iam",      label:"IAM · Org · OUs · SCPs", color:"#B71C1C", Icon: KeyRound},
    {id:"jenkins",  label:"Jenkins / Jules",        color:"#BF360C", Icon: Server},
    {id:"dfd",      label:"Enterprise DFD",         color:"#4527A0", Icon: MapIcon},
    {id:"wiz",      label:"Wiz CSPM",               color:"#1A73E8", Icon: ShieldAlert},
    {id:"attack",   label:"MITRE ATT&CK®",          color:"#B71C1C", Icon: Zap},
    {id:"cwe",      label:"MITRE CWE",              color:"#E65100", Icon: TriangleAlert},
    {id:"stride",   label:"STRIDE-LM",              color:"#4527A0", Icon: Target},
    {id:"tfePave",  label:"TFE-Pave / Hier. IAM",  color:"#2E7D32", Icon: Layers},
    {id:"userdocs", label:"My Documents",           color:"#78909C", Icon: FileText},
  ];

  // Landing page render
  if (appMode === "landing") {
    return (
      <>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
        <LandingPage
          threatModels={threatModels}
          onCreateModel={createModel}
          onOpenModel={openModel}
          onDeleteModel={deleteModel}
        />
      </>
    );
  }

  if (appMode === "documents") {
    return (
      <>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
        <DocumentsPage
          model={currentModel}
          modelDetails={modelDetails}
          userDocs={userDocs}
          onSaveDetails={saveModelDetails}
          onAddDocs={addUserDocs}
          onRemoveDoc={removeUserDoc}
          onContinue={() => { setAppMode("workspace"); setMainTab("build"); }}
          onBack={() => setAppMode("landing")}
          ingestState={ingestState}
          intelligence={intelligenceRef.current}
          intelligenceVersion={intelligenceVersion}
        />
      </>
    );
  }

  return (
    <div style={{...SANS, background:C.bg, minHeight:"100vh", color:C.text}}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>

      {/* ── HEADER ── */}
      <div style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 16px", display:"flex", alignItems:"center", height:58,
        position:"sticky", top:0, zIndex:100,
      }}>
        {/* Back to landing + brand */}
        <div style={{display:"flex", alignItems:"center", gap:10, marginRight:20, flexShrink:0}}>
          <button onClick={()=>setAppMode("landing")} title="All threat models" style={{
            background:"transparent", border:`1px solid ${C.border}`, borderRadius:6,
            padding:"5px 10px", color:C.textMuted, cursor:"pointer", fontSize:11, ...SANS,
            display:"flex", alignItems:"center", gap:4,
          }}><ChevronLeft size={13}/> Home</button>
          <div style={{
            width:30, height:30, borderRadius:7, flexShrink:0,
            background:"linear-gradient(135deg,#FF6B35,#FF9900)",
            display:"flex", alignItems:"center", justifyContent:"center",
            boxShadow:"0 2px 8px #FF990040"
          }}><Shield size={16} color="#fff"/></div>
          <div>
            <div style={{fontSize:13, fontWeight:700, color:C.text, letterSpacing:"-.01em", lineHeight:1.1}}>
              Threataform
            </div>
            {currentModel && (
              <div style={{fontSize:10, color:C.accent, marginTop:1, fontWeight:600,
                maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                {currentModel.name}
              </div>
            )}
          </div>
        </div>

        {/* Stepper nav */}
        {(()=>{
          const stepDone = (num) => {
            if (num === 1) return true;
            if (num === 2) return files.length > 0 && parseResult !== null;
            if (num === 3) return (parseResult?.resources?.length || 0) > 0;
            if (num === 4) return intelligenceRef.current?._built === true;
            if (num === 5) return xml && xml.length > 100;
            return false;
          };
          const steps = [
            { num:1, label:"Know Your Domain", tab:"knowledge" },
            { num:2, label:"Build Model",       tab:"build" },
            { num:3, label:"Analyze Threats",   tab:"analysis" },
            { num:4, label:"Review Intelligence", tab:"intelligence" },
            { num:5, label:"Export",            tab:"dfd" },
          ];
          return (
            <div style={{ display:"flex", alignItems:"center", gap:0, padding:"0 24px" }}>
              {steps.map((step, i, arr) => {
                const isActive = mainTab === step.tab || (step.tab === "build" && mainTab === "arch-analysis");
                const isDone = stepDone(step.num);
                return (
                  <React.Fragment key={step.tab}>
                    <button
                      onClick={() => setMainTab(step.tab)}
                      style={{
                        display:"flex", alignItems:"center", gap:6,
                        background:"none", border:"none", cursor:"pointer",
                        padding:"8px 12px", borderRadius:8,
                        color: isActive ? C.accent : isDone ? "#10B981" : C.textSub,
                        fontWeight: isActive ? 700 : 400, fontSize:13, ...SANS,
                      }}
                    >
                      <span style={{
                        width:22, height:22, borderRadius:"50%",
                        display:"flex", alignItems:"center", justifyContent:"center",
                        fontSize:11, fontWeight:700,
                        background: isActive ? C.accent : isDone ? "#10B981" : C.surface,
                        color: (isActive || isDone) ? "#fff" : C.textSub,
                        border: `2px solid ${isActive ? C.accent : isDone ? "#10B981" : C.border}`,
                        flexShrink:0,
                      }}>{isDone && !isActive ? "✓" : step.num}</span>
                      {step.label}
                    </button>
                    {i < arr.length - 1 && (
                      <span style={{ color:C.border, fontSize:16, userSelect:"none" }}>›</span>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          );
        })()}

        {/* Action buttons */}
        {xml && (
          <div style={{marginLeft:"auto", display:"flex", gap:8, alignItems:"center"}}>
            {/* PRIMARY: draw.io / Lucidchart — confirmed supported format in enterprise Lucidchart */}
            <button onClick={download} style={{
              background:"linear-gradient(135deg,#FF6B3520,#FF990020)",
              border:`1px solid ${C.accent}55`,
              borderRadius:7, padding:"7px 18px",
              color:C.accent, fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:6,
              fontWeight:700,
            }}>
              <Download size={13}/> Export .xml
            </button>
            {/* SECONDARY: Copy XML */}
            <button onClick={copy} style={{
              background: copied ? "#0D2010" : C.surface2,
              border:`1px solid ${copied ? C.green+"66" : C.border2}`,
              borderRadius:7, padding:"7px 13px",
              color: copied ? C.green : C.textMuted,
              fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:5,
              transition:"all .15s",
            }}>
              {copied ? <CheckCircle2 size={13}/> : <CheckSquare size={13} style={{opacity:0.6}}/>} {copied ? "Copied!" : "Copy XML"}
            </button>
            {/* TERTIARY: .lucid — for Lucidchart versions that support Lucid Standard Import */}
            <button onClick={downloadLucid} title="Lucid Standard Import format (.lucid) — supported in some Lucidchart versions" style={{
              background:C.surface2,
              border:`1px solid ${C.border2}`,
              borderRadius:7, padding:"7px 13px",
              color:C.textMuted, fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:5,
            }}>
              <Download size={13}/> .lucid
            </button>
            {/* Architecture TXT report */}
            {archLayerAnalysis && (
              <>
                <button onClick={() => {
                  try {
                    const txt = generateTXTReport(archLayerAnalysis, { grade: intelligenceRef.current?.getSecurityPosture?.(parseResult?.resources||[])?.grade });
                    const blob = new Blob([txt], {type:"text/plain"});
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "architecture-report.txt";
                    a.click();
                    URL.revokeObjectURL(a.href);
                  } catch(e) { console.error("[ExportTXT]", e); }
                }} title="Export Architecture Analysis as TXT" style={{
                  background:C.surface2, border:`1px solid ${C.border2}`,
                  borderRadius:7, padding:"7px 13px",
                  color:C.textMuted, fontSize:12, cursor:"pointer", ...SANS,
                  display:"flex", alignItems:"center", gap:5,
                }}>
                  <FileText size={13}/> Report .txt
                </button>
                <button onClick={() => {
                  try {
                    const md = generateMarkdownReport(archLayerAnalysis, { grade: intelligenceRef.current?.getSecurityPosture?.(parseResult?.resources||[])?.grade });
                    const blob = new Blob([md], {type:"text/markdown"});
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "architecture-report.md";
                    a.click();
                    URL.revokeObjectURL(a.href);
                  } catch(e) { console.error("[ExportMD]", e); }
                }} title="Export Architecture Analysis as Markdown" style={{
                  background:C.surface2, border:`1px solid ${C.border2}`,
                  borderRadius:7, padding:"7px 13px",
                  color:C.textMuted, fontSize:12, cursor:"pointer", ...SANS,
                  display:"flex", alignItems:"center", gap:5,
                }}>
                  <Download size={13}/> Report .md
                </button>
              </>
            )}
          </div>
        )}
      </div>

      {/* ── KNOWLEDGE BASE TAB ── */}
      {mainTab==="knowledge" && (
        <div style={{display:"grid", gridTemplateColumns:"256px 1fr", height:"calc(100vh - 58px)"}}>
          {/* Sidebar */}
          <div style={{
            background:C.surface, borderRight:`1px solid ${C.border}`,
            display:"flex", flexDirection:"column", overflowY:"auto"
          }}>
            <div style={{padding:"18px 16px 10px", fontSize:10, color:C.textMuted, textTransform:"uppercase", letterSpacing:".12em", fontWeight:600}}>
              Knowledge Domains
            </div>
            <div style={{flex:1, padding:"0 8px"}}>
              {KB_DOMAINS.map(d => {
                const active = kbDomain === d.id;
                const DomainIcon = d.Icon || BookOpen;
                const badge = d.id === "userdocs" && userDocs.length > 0 ? userDocs.length : null;
                return (
                  <div key={d.id}>
                    {d.id === "userdocs" && (
                      <div style={{borderTop:`1px solid ${C.border}`, margin:"10px 4px 8px"}}/>
                    )}
                    <button onClick={()=>setKbDomain(d.id)} style={{
                      display:"flex", alignItems:"center", gap:10,
                      width:"100%", textAlign:"left",
                      padding:"10px 12px",
                      background: active ? `${d.color}15` : "transparent",
                      border:"none",
                      borderRadius:8,
                      color: active ? d.color : C.textSub,
                      cursor:"pointer",
                      ...SANS, fontSize:13, fontWeight: active ? 600 : 400,
                      transition:"all .15s",
                      marginBottom:2,
                    }}>
                      <span style={{
                        width:28, height:28, borderRadius:7, flexShrink:0,
                        background: active ? `${d.color}20` : C.surface2,
                        border:`1px solid ${active ? d.color+"44" : C.border}`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        color: active ? d.color : C.textMuted,
                      }}><DomainIcon size={14}/></span>
                      <span style={{flex:1, lineHeight:1.3}}>{d.label}</span>
                      {badge && (
                        <span style={{
                          background:`${d.color}22`, color:d.color,
                          border:`1px solid ${d.color}44`,
                          borderRadius:10, padding:"1px 7px", fontSize:10, fontWeight:600
                        }}>{badge}</span>
                      )}
                    </button>
                  </div>
                );
              })}
            </div>

            {/* Tips */}
            <div style={{padding:"14px 16px 18px", borderTop:`1px solid ${C.border}`}}>
              <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".07em"}}>
                Quick Tips
              </div>
              {[
                "Upload .tf files to auto-generate DFD",
                "Cross-file references detected",
                "Module trees visualized",
                "Sentinel policy gates shown",
                "Export to draw.io / Lucidchart",
              ].map((tip, i) => (
                <div key={i} style={{display:"flex", gap:8, alignItems:"flex-start", marginBottom:5}}>
                  <span style={{color:C.accent, fontSize:10, marginTop:1}}>›</span>
                  <span style={{fontSize:12, color:C.textMuted, lineHeight:1.5}}>{tip}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Content */}
          <div style={{overflowY:"auto", padding:"24px 28px", background:C.bg}}>
            {kbDomain === "userdocs"
              ? <UserDocsPanel docs={userDocs} onAdd={addUserDocs}
                  onDelete={(i) => saveUserDocs(userDocs.filter((_,idx)=>idx!==i))}
                  onClear={() => saveUserDocs([])} />
              : <KBPanel domain={kbDomain} />
            }
          </div>
        </div>
      )}


      {/* ── ARCHITECTURE ANALYSIS TAB ── */}
      {mainTab==="arch-analysis" && (() => {
        const NARRATIVE_FIELDS = [
          { key:"entryPoints",           label:"Entry Points",               Icon:DoorOpen },
          { key:"dataFlow",              label:"Data Flow",                  Icon:ArrowLeftRight },
          { key:"securityBoundaries",    label:"Security Boundaries",        Icon:Lock },
          { key:"publicPrivateResources",label:"Public & Private Resources", Icon:Globe },
          { key:"securityControls",      label:"Security Controls",          Icon:Shield },
          { key:"faultTolerance",        label:"Fault Tolerance",            Icon:RefreshCw },
          { key:"authAndAuthz",          label:"Authentication & AuthZ",     Icon:KeyRound },
          { key:"externalDependencies",  label:"External Dependencies",      Icon:LinkIcon },
          { key:"storageAndDataSecurity",label:"Storage & Data Security",    Icon:Database },
        ];

        const ATTR_CHIPS = {
          applicationType:   ["Web App","REST API","Serverless","Microservices","Container-Based","VM-Based","Static Site","Data Pipeline","Streaming","ML/AI"],
          entryPointTypes:   ["HTTPS","REST API","GraphQL","gRPC","CLI","SDK","Webhook","Event Stream","File Transfer","Web UI"],
          developedBy:       ["Vendor (AWS)","Vendor (Azure)","Vendor (GCP)","Vendor (3rd Party)","Internal","Hybrid"],
          users:             ["Internal Employees","Internal Apps/Services","External End Users","3rd Party Systems","Business Partners"],
          inboundDataSource: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","IoT/Edge"],
          inboundDataFlow:   ["API Request","Event/Message","Network Traffic","User Input","Data Streaming","File Upload","DB Replication"],
          outboundDataFlow:  ["API Response","Event/Message","Network Traffic","Data Streaming","File Export","DB Write"],
          outboundDataDestination: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","Data Warehouse"],
          integrations:      ["REST API","GraphQL","SDK","Webhook","File Transfer","Message Queue (SQS/SNS)","Event Stream (Kinesis/Kafka)","Middleware","DB Replication"],
          exposure:          ["Public Internet","Intranet Only","VPN Required","Trusted Partner Network","Air-Gapped"],
          facilityType:      ["AWS Cloud","Azure Cloud","GCP Cloud","Enterprise Data Center","3rd Party DC","Mobile","Desktop"],
          computeType:       ["Cloud Managed Service","Serverless","Container (ECS/EKS)","VM (EC2)","On-Premises","Hybrid"],
          authMethods:       ["OAuth 2.0","SSO/SAML","PKI/mTLS","ADFS/LDAP","API Key","MFA","AWS IAM","Certificate","Passwordless"],
          dataSensitivity:   ["PII","PHI","PCI Data","Confidential","Internal","Public","Export Controlled","Trade Secret"],
          complianceFramework:["HIPAA","PCI-DSS","SOC 2","GDPR","FedRAMP","ISO 27001","NIST 800-53","CIS AWS","CCPA","CMMC"],
          environment:       ["Production","Staging","Development","DR / Backup","Lab / Sandbox","Multi-Tenant","Single-Tenant"],
        };

        const ATTR_GROUPS = [
          { label:"Application Profile",        keys:["applicationType","entryPointTypes","developedBy","users"] },
          { label:"Data & Integration",          keys:["inboundDataSource","inboundDataFlow","outboundDataFlow","outboundDataDestination","integrations"] },
          { label:"Deployment & Infrastructure", keys:["exposure","facilityType","computeType"] },
          { label:"Security & Compliance",       keys:["authMethods","dataSensitivity","complianceFramework"] },
          { label:"Context",                     keys:["environment"] },
        ];

        const ATTR_LABELS = {
          applicationType:"Application / Solution Type", entryPointTypes:"Entry Points",
          developedBy:"Developed By", users:"Users / Consumers",
          inboundDataSource:"Inbound Data Source", inboundDataFlow:"Inbound Data Flow",
          outboundDataFlow:"Outbound Data Flow", outboundDataDestination:"Outbound Destination",
          integrations:"Integrations", exposure:"Exposure", facilityType:"Facility Type",
          computeType:"Compute Type", authMethods:"Authentication Methods",
          dataSensitivity:"Data Sensitivity", complianceFramework:"Compliance Frameworks",
          environment:"Environment / Deployment Stage",
        };

        const SINGLE_SELECT = ["developedBy","environment"];

        // Merge base + overrides
        const baseNarrative = archAnalysis?.narrative || {};
        const baseAttrs     = archAnalysis?.attributes || {};
        const ovNarrative   = archOverrides?.narrative || {};
        const ovAttrs       = archOverrides?.attributes || {};
        const narrative     = { ...baseNarrative, ...ovNarrative };
        const attrs         = { ...baseAttrs, ...ovAttrs };

        const saveNarrativeField = (key, value) => {
          const updated = { ...archOverrides, narrative: { ...ovNarrative, [key]: value } };
          setArchOverrides(updated);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: updated })); } catch {}
          }
        };

        const toggleAttrChip = (attrKey, chip) => {
          const single = SINGLE_SELECT.includes(attrKey);
          const current = attrs[attrKey];
          let updated;
          if (single) {
            updated = current === chip ? "" : chip;
          } else {
            const arr = Array.isArray(current) ? current : [];
            updated = arr.includes(chip) ? arr.filter(c => c !== chip) : [...arr, chip];
          }
          const newAttrs = { ...ovAttrs, [attrKey]: updated };
          const newOverrides = { ...archOverrides, attributes: newAttrs };
          setArchOverrides(newOverrides);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: newOverrides })); } catch {}
          }
        };

        const reanalyze = () => {
          setArchAnalyzing(true);
          setTimeout(() => {
            try {
              const result = intelligenceRef.current.analyzeArchitecture(parseResult?.resources||[], userDocs, modelDetails);
              setArchAnalysis(result);
              if (currentModel) {
                try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
                  JSON.stringify({ base: result, overrides: archOverrides })); } catch {}
              }
            } finally { setArchAnalyzing(false); }
          }, 0);
        };

        const resetOverrides = () => {
          setArchOverrides({});
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: {} })); } catch {}
          }
        };

        return (
          <div style={{ height:"calc(100vh - 58px)", overflow:"hidden", display:"flex", flexDirection:"column" }}>
            {/* Header bar */}
            <div style={{ padding:"16px 28px", borderBottom:`1px solid ${C.border}`, background:C.surface,
              display:"flex", alignItems:"center", gap:16, flexShrink:0 }}>
              <div style={{ flex:1 }}>
                <div style={{...SANS, fontSize:16, fontWeight:700, color:C.text}}>Architecture Analysis</div>
                <div style={{ fontSize:11, color:C.textMuted, marginTop:2 }}>
                  Auto-populated from Terraform resources and uploaded documents · editable per-model
                  {archAnalysis && <span style={{marginLeft:10, color:C.accent, fontWeight:600}}>· Confidence: {archAnalysis.confidence}%</span>}
                </div>
              </div>
              {archAnalyzing && <Loader2 size={16} style={{color:C.accent, animation:"spin 1s linear infinite"}}/>}
              <button onClick={reanalyze} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:C.surface2, border:`1px solid ${C.border2}`, borderRadius:7,
                color:C.textSub, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RotateCcw size={12}/> Re-analyze</button>
              <button onClick={resetOverrides} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:"transparent", border:`1px solid ${C.border}`, borderRadius:7,
                color:C.textMuted, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RefreshCw size={12}/> Reset edits</button>
            </div>

            {/* Body — 2-column */}
            {!archAnalysis && !archAnalyzing ? (
              <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center", flexDirection:"column", gap:12 }}>
                <Building2 size={40} style={{color:C.textMuted, opacity:.4}}/>
                <div style={{...SANS, fontSize:14, color:C.textMuted}}>Upload Terraform files or documents to generate architecture analysis</div>
                <button onClick={()=>setMainTab("build")} style={{
                  ...SANS, fontSize:12, padding:"7px 16px", borderRadius:7,
                  background:`${C.accent}18`, border:`1px solid ${C.accent}44`, color:C.accent, cursor:"pointer",
                }}>Go to Upload & Analyze</button>
              </div>
            ) : (() => {
              // ── Inline markdown renderer for narrative preview ──
              const renderLine = (line, i) => {
                const parts = line.split(/(\*\*[^*]+\*\*)/g);
                return parts.map((p,j) =>
                  (p.startsWith('**') && p.endsWith('**'))
                    ? <strong key={j}>{p.slice(2,-2)}</strong>
                    : <span key={j}>{p}</span>
                );
              };
              const decodeEntities = (s) => (s||'')
                .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>')
                .replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&nbsp;/g,' ');
              const renderNarrative = (text) => {
                if (!text?.trim()) return null;
                const lines = decodeEntities(text).split('\n');
                const els = [];
                let i = 0;
                while (i < lines.length) {
                  const line = lines[i];
                  const trimmed = line.trim();
                  if (trimmed.startsWith('• ') || trimmed.startsWith('- ')) {
                    const bullets = [];
                    while (i < lines.length && (lines[i].trim().startsWith('• ') || lines[i].trim().startsWith('- '))) {
                      bullets.push(lines[i].trim().slice(2));
                      i++;
                    }
                    els.push(
                      <div key={`b${i}`} style={{marginBottom:4}}>
                        {bullets.map((b,bi) => (
                          <div key={bi} style={{display:'flex', gap:7, marginBottom:3, alignItems:'flex-start'}}>
                            <span style={{color:C.accent, flexShrink:0, marginTop:1, fontSize:13, lineHeight:'16px'}}>•</span>
                            <span style={{lineHeight:'18px'}}>{renderLine(b, bi)}</span>
                          </div>
                        ))}
                      </div>
                    );
                  } else if (trimmed.startsWith('Context:')) {
                    els.push(
                      <div key={`c${i}`} style={{
                        marginTop:8, padding:'7px 10px',
                        background:`${C.accent}0a`, border:`1px solid ${C.accent}22`,
                        borderRadius:6, fontSize:11, color:C.textSub, lineHeight:1.6,
                        fontStyle:'italic',
                      }}>
                        <span style={{fontWeight:700, fontStyle:'normal', color:C.accent, fontSize:10, marginRight:5}}>FROM DOCS</span>
                        {renderLine(trimmed.slice(9).trim(), i)}
                      </div>
                    );
                    i++;
                  } else if (trimmed === '') {
                    els.push(<div key={`sp${i}`} style={{height:5}}/>);
                    i++;
                  } else {
                    els.push(<div key={`t${i}`} style={{marginBottom:3, lineHeight:'18px'}}>{renderLine(trimmed, i)}</div>);
                    i++;
                  }
                }
                return els;
              };

              return (
                <div style={{ flex:1, display:"grid", gridTemplateColumns:"1fr 1fr", overflow:"hidden" }}>
                  {/* LEFT — Narrative Fields */}
                  <div style={{ overflowY:"auto", padding:"16px 20px", borderRight:`1px solid ${C.border}` }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Narrative Findings
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        {Object.values(narrative).filter(Boolean).length} / {NARRATIVE_FIELDS.length} fields populated
                      </div>
                    </div>
                    {NARRATIVE_FIELDS.map(({ key, label, Icon: FieldIcon }) => {
                      const value = narrative[key] || "";
                      const isOverridden = !!ovNarrative[key];
                      const isEditing = archEditingField === key;
                      const bulletCount = (value.match(/^•/gm) || []).length;
                      return (
                        <div key={key} style={{
                          marginBottom:10,
                          border:`1px solid ${isEditing ? C.accent+'55' : C.border}`,
                          borderRadius:10,
                          overflow:'hidden',
                          transition:'border-color .15s',
                          background: C.surface,
                        }}>
                          {/* Section header */}
                          <div style={{
                            display:'flex', alignItems:'center', gap:7, padding:'8px 12px',
                            borderBottom:`1px solid ${isEditing ? C.accent+'22' : C.border}`,
                            background: isEditing ? `${C.accent}08` : C.surface2,
                          }}>
                            <FieldIcon size={13} style={{color: C.accent, flexShrink:0}}/>
                            <span style={{...SANS, fontSize:12, fontWeight:700, color:C.text, flex:1}}>{label}</span>
                            {bulletCount > 0 && !isEditing && (
                              <span style={{fontSize:10, color:C.textMuted}}>{bulletCount} items</span>
                            )}
                            {!isOverridden && value && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:"#FF980018", color:"#FF9800",
                                border:"1px solid #FF980044", borderRadius:8, padding:"1px 6px"}}>AI</span>
                            )}
                            {isOverridden && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:`${C.accent}18`, color:C.accent,
                                border:`1px solid ${C.accent}44`, borderRadius:8, padding:"1px 6px"}}>edited</span>
                            )}
                            <button
                              onClick={() => setArchEditingField(isEditing ? null : key)}
                              style={{
                                ...SANS, fontSize:10, padding:'2px 8px', borderRadius:6, cursor:'pointer',
                                display:'flex', alignItems:'center', gap:4,
                                background: isEditing ? C.accent : 'transparent',
                                border:`1px solid ${isEditing ? C.accent : C.border2}`,
                                color: isEditing ? '#fff' : C.textMuted,
                                transition:'all .12s',
                              }}
                            >
                              {isEditing
                                ? <><CheckCircle2 size={9}/> Done</>
                                : <><PenLine size={9}/> Edit</>
                              }
                            </button>
                          </div>
                          {/* Content: preview or textarea */}
                          {isEditing ? (
                            <textarea
                              value={value}
                              onChange={e => saveNarrativeField(key, e.target.value)}
                              placeholder={`Describe ${label.toLowerCase()}...\n\nUse • for bullets, e.g.:\n• Item one\n• Item two\nContext: optional doc note`}
                              ref={el => { if (el) { el.style.height='auto'; el.style.height=Math.max(80, el.scrollHeight)+'px'; }}}
                              onInput={e => { e.target.style.height='auto'; e.target.style.height=Math.max(80, e.target.scrollHeight)+'px'; }}
                              style={{
                                width:'100%', boxSizing:'border-box', resize:'none',
                                background:C.bg, border:'none', borderRadius:0,
                                color:C.text, fontSize:12, padding:'10px 12px',
                                lineHeight:1.7, outline:'none', ...SANS,
                                minHeight:80, display:'block', fontFamily:'inherit',
                              }}
                            />
                          ) : (
                            <div
                              onClick={() => setArchEditingField(key)}
                              style={{
                                padding:'10px 12px', fontSize:12, lineHeight:1.6,
                                color: value ? C.text : C.textMuted,
                                ...SANS, cursor:'text', minHeight:38,
                                fontStyle: value ? 'normal' : 'italic',
                              }}
                            >
                              {value
                                ? renderNarrative(value)
                                : `Click to add ${label.toLowerCase()}…`
                              }
                            </div>
                          )}
                          {isEditing && (
                            <div style={{
                              display:'flex', justifyContent:'flex-end',
                              padding:'4px 10px', borderTop:`1px solid ${C.border}`,
                              background:C.surface2,
                            }}>
                              <span style={{fontSize:10, color:C.textMuted}}>{value.length} chars</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* RIGHT — Structured Attributes */}
                  <div style={{ overflowY:"auto", padding:"16px 20px" }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Structured Attributes
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        ✦ = AI-detected
                      </div>
                    </div>
                    {ATTR_GROUPS.map((group, gi) => {
                      // Count selected across this group
                      const selCount = group.keys.reduce((n, k) => {
                        const v = attrs[k];
                        return n + (SINGLE_SELECT.includes(k) ? (v ? 1 : 0) : (Array.isArray(v) ? v.length : 0));
                      }, 0);
                      return (
                        <div key={gi} style={{ marginBottom:18 }}>
                          <div style={{
                            display:'flex', alignItems:'center', justifyContent:'space-between',
                            marginBottom:10, paddingBottom:7,
                            borderBottom:`1px solid ${C.border}`,
                          }}>
                            <div style={{fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".08em"}}>
                              {group.label}
                            </div>
                            {selCount > 0 && (
                              <span style={{
                                fontSize:10, color:C.accent, fontWeight:600,
                                background:`${C.accent}15`, border:`1px solid ${C.accent}33`,
                                borderRadius:8, padding:'1px 7px',
                              }}>{selCount} selected</span>
                            )}
                          </div>
                          {group.keys.map(attrKey => {
                            const options = ATTR_CHIPS[attrKey] || [];
                            const single = SINGLE_SELECT.includes(attrKey);
                            const selected = attrs[attrKey];
                            const isSelected = (opt) => single
                              ? selected === opt
                              : Array.isArray(selected) && selected.includes(opt);
                            const isAI = (opt) => {
                              const base = baseAttrs[attrKey];
                              return single ? base === opt : Array.isArray(base) && base.includes(opt);
                            };
                            const anySelected = single ? !!selected : (Array.isArray(selected) && selected.length > 0);
                            return (
                              <div key={attrKey} style={{ marginBottom:11 }}>
                                <div style={{...SANS, fontSize:11, fontWeight:600, color: anySelected ? C.textSub : C.textMuted, marginBottom:5, display:'flex', alignItems:'center', gap:5}}>
                                  {ATTR_LABELS[attrKey]}
                                  {single && <span style={{fontSize:9, color:C.textMuted, fontWeight:400, background:C.surface2, padding:'1px 5px', borderRadius:4}}>single</span>}
                                </div>
                                <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                                  {options.map(opt => {
                                    const active = isSelected(opt);
                                    const ai = isAI(opt);
                                    return (
                                      <button key={opt} onClick={() => toggleAttrChip(attrKey, opt)} style={{
                                        ...SANS, fontSize:11, fontWeight: active ? 600 : 400,
                                        padding:"3px 9px", borderRadius:12, cursor:"pointer",
                                        background: active ? `${C.accent}20` : C.surface2,
                                        border: `1px solid ${active ? C.accent+'88' : C.border2}`,
                                        color: active ? C.accent : C.textMuted,
                                        transition:"all .12s", position:"relative",
                                        lineHeight:'16px',
                                      }}>
                                        {opt}
                                        {ai && active && (
                                          <span title="AI-detected" style={{
                                            fontSize:8, color:"#FF9800",
                                            position:"absolute", top:-4, right:-4,
                                            background:C.surface, borderRadius:"50%",
                                            padding:"0 2px", lineHeight:'12px',
                                            border:'1px solid #FF980044',
                                          }}>✦</span>
                                        )}
                                      </button>
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
          </div>
        );
      })()}


      {/* ── BUILD MODEL TAB (merged: Upload + Architecture) ── */}
      {mainTab==="build" && (
        <div style={{padding:"32px 40px", maxWidth:980, height:"calc(100vh - 58px)", overflowY:"auto"}}>
          {/* Page heading */}
          <div style={{marginBottom:22}}>
            <div style={{...SANS, fontSize:22, fontWeight:700, color:C.text, marginBottom:6, letterSpacing:"-.02em"}}>
              {currentModel ? currentModel.name : "Upload & Analyze"}
            </div>
            <div style={{fontSize:13, color:C.textSub, lineHeight:1.6, maxWidth:680}}>
              Drop any Terraform, HCL, Sentinel, JSON, YAML, docs, or any other file. TF/HCL files are parsed for resources and connections; all other files become context documents that inform the analysis.
            </div>
          </div>

          {/* Ingestion Progress Bar */}
          {ingestState && (
            <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
              padding:"10px 16px", marginBottom:20 }}>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:5 }}>
                <span style={{ fontSize:12, color:C.textSub, fontWeight:500 }}>
                  Analyzing {ingestState.done} / {ingestState.total} files
                  {ingestState.current ? ` · ${ingestState.current}` : ""}
                </span>
                <span style={{ fontSize:12, fontWeight:700, color:C.accent }}>
                  {Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%
                </span>
              </div>
              <div style={{ height:4, background:C.border, borderRadius:2, overflow:"hidden" }}>
                <div style={{
                  height:"100%", borderRadius:2, background:`linear-gradient(90deg,${C.accent},${C.accent}aa)`,
                  width:`${Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%`,
                  transition:"width .3s ease",
                }} />
              </div>
            </div>
          )}

          {/* ── APPLICATION DETAILS ── */}
          {currentModel && (()=>{
            const envOptions = ["Production","Staging","Development","DR / Disaster Recovery","Sandbox"];
            const dataCls   = ["PII (Personal Data)","PHI (Health Data)","PCI (Payment Data)","Financial Data","Internal","Public"];
            const md = modelDetails;
            const toggleArr = (arr, val) => arr.includes(val) ? arr.filter(x=>x!==val) : [...arr, val];
            return (
              <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                padding:"20px 24px", marginBottom:24}}>
                <div style={{fontSize:14, fontWeight:700, color:C.text, marginBottom:16, display:"flex", alignItems:"center", gap:8}}>
                  <span>Application Details</span>
                  <span style={{fontSize:10, color:C.textMuted, fontWeight:400}}>— enriches intelligence context</span>
                </div>
                <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:14}}>
                  {/* Environment */}
                  <div>
                    <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6}}>Environment</div>
                    <select value={md.environment||""} onChange={e=>saveModelDetails({...md,environment:e.target.value})} style={{
                      width:"100%", background:C.bg, border:`1px solid ${C.border2}`, borderRadius:8,
                      padding:"8px 12px", color:md.environment?C.text:C.textMuted, fontSize:13, ...SANS, outline:"none",
                    }}>
                      <option value="">Select environment...</option>
                      {envOptions.map(o=><option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                  {/* Owner */}
                  <div>
                    <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6}}>Team / Owner</div>
                    <input value={md.owner||""} onChange={e=>saveModelDetails({...md,owner:e.target.value})}
                      placeholder="e.g. Platform Security Team" style={{
                        width:"100%", boxSizing:"border-box", background:C.bg, border:`1px solid ${C.border2}`,
                        borderRadius:8, padding:"8px 12px", color:C.text, fontSize:13, ...SANS, outline:"none",
                      }} />
                  </div>
                </div>
                {/* Data classification */}
                <div style={{marginBottom:14}}>
                  <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8}}>Data Classification</div>
                  <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
                    {dataCls.map(cls=>{
                      const on = (md.dataClassification||[]).includes(cls);
                      return (
                        <button key={cls} onClick={()=>saveModelDetails({...md,dataClassification:toggleArr(md.dataClassification||[],cls)})} style={{
                          background:on?"#0277BD20":"transparent", border:`1px solid ${on?"#0277BD":"#33333A"}`,
                          borderRadius:20, padding:"4px 12px", fontSize:11,
                          color:on?"#4FC3F7":C.textMuted, cursor:"pointer", ...SANS,
                        }}>{cls}</button>
                      );
                    })}
                  </div>
                </div>
                {/* Description — auto-populated from intelligence */}
                <div>
                  <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6, display:"flex", alignItems:"center", gap:8}}>
                    Architecture Description
                    {!md.description && intelligenceRef.current?._built && (
                      <span style={{ fontSize:10, color:C.accent, fontWeight:400 }}>auto-populated from docs</span>
                    )}
                  </div>
                  <textarea value={md.description||""} onChange={e=>saveModelDetails({...md,description:e.target.value})}
                    placeholder="Auto-populated from uploaded documents and Terraform analysis. Edit freely."
                    rows={3} style={{
                      width:"100%", boxSizing:"border-box", background:C.bg, border:`1px solid ${C.border2}`,
                      borderRadius:8, padding:"8px 12px", color:C.text, fontSize:12, ...SANS, outline:"none",
                      resize:"vertical", lineHeight:1.6, ...MONO,
                    }} />
                </div>
              </div>
            );
          })()}

          {/* Drop zone — always visible for adding more */}
          <div
            onDrop={handleDrop}
            onDragOver={e=>{e.preventDefault();setDragging(true);}}
            onDragLeave={()=>setDragging(false)}
            style={{
              border:`2px dashed ${dragging ? C.accent : C.border2}`,
              borderRadius:12, padding: files.length ? "24px 32px" : "48px 32px", textAlign:"center",
              background: dragging ? `${C.accent}08` : C.surface,
              transition:"all .2s", marginBottom:16,
              boxShadow: dragging ? `0 0 24px ${C.accent}20` : "none",
            }}
          >
            <div style={{marginBottom:8, opacity:dragging?1:0.6, display:"flex", justifyContent:"center"}}>
              {dragging ? <Download size={files.length?28:40}/> : <FolderOpen size={files.length?28:40}/>}
            </div>
            <div style={{...SANS, color:C.textSub, fontSize:14, marginBottom:4, fontWeight:500}}>
              {dragging ? "Drop to add files" : files.length ? "Drop more files to add them" : "Drag & drop files or a folder here"}
            </div>
            <div style={{fontSize:12, color:C.textMuted, marginBottom:18}}>
              All file types accepted · .tf .hcl .sentinel .tfvars → parsed · everything else → context docs
            </div>
            <div style={{display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap"}}>
              <label style={{
                background:C.surface2, border:`1px solid ${C.border2}`,
                borderRadius:8, padding:"9px 20px",
                color:C.textSub, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:7, fontWeight:500,
              }}>
                <FileText size={14}/> {files.length ? "Add Files" : "Select Files"}
                <input type="file" multiple
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files, files.length>0);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
              <label style={{
                background:`linear-gradient(135deg,${C.accent}18,${C.accent}08)`,
                border:`1px solid ${C.accent}55`,
                borderRadius:8, padding:"9px 20px",
                color:C.accent, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:7, fontWeight:600,
              }}>
                <span>📂</span> {files.length ? "Add Folder" : "Select Folder"}
                <input type="file" webkitdirectory=""
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files, files.length>0);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
            </div>
          </div>

          {error && (
            <div style={{
              padding:"12px 16px", background:"#200808",
              border:`1px solid ${C.red}44`, borderRadius:8,
              color:"#FF8A80", fontSize:13, marginBottom:16,
              display:"flex", gap:10, alignItems:"flex-start"
            }}>
              <TriangleAlert size={16} style={{flexShrink:0}}/>
              <span>{error}</span>
            </div>
          )}

          {files.length > 0 && (() => {
            // Group by folder prefix
            const grouped = {};
            files.forEach(f => {
              const parts = f.path.split("/");
              const folder = parts.length > 1 ? parts.slice(0,-1).join("/") : "";
              if (!grouped[folder]) grouped[folder] = [];
              grouped[folder].push(f);
            });
            const ext = f => f.path.split(".").pop().toLowerCase();
            const extColor = e => ({tf:"#FF6B35",hcl:"#FF9900",sentinel:"#E91E63",tfvars:"#9C27B0"}[e]||C.textMuted);
            return (
              <div style={{...card(C.green+"33"), marginBottom:16}}>
                <div style={{...sectionBar(C.green), justifyContent:"space-between"}}>
                  <div style={{display:"flex", alignItems:"center", gap:8}}>
                    <CheckCircle2 size={14}/>
                    <span>{files.length} Terraform file{files.length!==1?"s":""} loaded</span>
                    {parseResult && <span style={{fontSize:11, color:C.textMuted}}>· {parseResult.resources.length} resources · {parseResult.connections.length} connections</span>}
                  </div>
                  <button onClick={clearFiles} style={{
                    background:"transparent", border:`1px solid ${C.red}44`,
                    borderRadius:6, padding:"3px 10px", color:C.red,
                    fontSize:11, cursor:"pointer", ...SANS
                  }}>Clear All</button>
                </div>
                <div style={{padding:"10px 14px", maxHeight:320, overflowY:"auto"}}>
                  {Object.entries(grouped).map(([folder, fls]) => (
                    <div key={folder} style={{marginBottom: folder ? 10 : 0}}>
                      {folder && (
                        <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:4, paddingLeft:2, textTransform:"uppercase", letterSpacing:".06em", display:"flex", alignItems:"center", gap:5}}>
                          <FolderOpen size={11}/> {folder}
                        </div>
                      )}
                      {fls.map(f => (
                        <div key={f.path} style={{
                          display:"flex", gap:8, alignItems:"center", padding:"4px 6px",
                          borderRadius:5, marginBottom:2,
                          background:"transparent",
                        }}
                          onMouseEnter={e=>e.currentTarget.style.background=C.surface2}
                          onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                        >
                          <span style={{
                            fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3,
                            background:`${extColor(ext(f))}20`, color:extColor(ext(f)),
                            border:`1px solid ${extColor(ext(f))}44`, flexShrink:0, minWidth:28, textAlign:"center"
                          }}>{ext(f).toUpperCase().slice(0,6)}</span>
                          <span style={{...MONO, fontSize:12, color:C.textSub, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                            {folder ? f.path.split("/").pop() : f.path}
                          </span>
                          {f.size && <span style={{fontSize:11, color:C.textMuted, flexShrink:0}}>{f.size < 1024 ? f.size+"B" : Math.round(f.size/1024)+"K"}</span>}
                          <button onClick={()=>removeFile(f.path)} style={{
                            background:"transparent", border:"none", color:C.textMuted,
                            cursor:"pointer", fontSize:14, padding:"0 4px", lineHeight:1,
                            borderRadius:4, flexShrink:0,
                          }}
                            onMouseEnter={e=>{ e.currentTarget.style.color=C.red; e.currentTarget.style.background=C.red+"15"; }}
                            onMouseLeave={e=>{ e.currentTarget.style.color=C.textMuted; e.currentTarget.style.background="transparent"; }}
                            title="Remove file"
                          ><X size={12}/></button>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          {parseResult && (
            <div style={{...card(), marginBottom:20}}>
              <div style={{...sectionBar(C.accent)}}>
                <BarChart2 size={14}/>
                <span>Parse Results</span>
              </div>
              <div style={{padding:"20px 18px"}}>
                {/* Stats grid */}
                <div style={{display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:20}}>
                  {[
                    {label:"Resources",     val:parseResult.resources.length,          c:C.green},
                    {label:"Modules",       val:parseResult.modules.length,            c:C.accent},
                    {label:"Connections",   val:parseResult.connections.length,        c:C.blue},
                    {label:"Outputs",       val:parseResult.outputs.length,            c:"#9C27B0"},
                    {label:"Variables",     val:parseResult.variables.length,          c:"#00BCD4"},
                    {label:"Remote States", val:parseResult.remoteStates?.length||0,   c:"#E91E63"},
                  ].map(s => (
                    <div key={s.label} style={{
                      background:C.bg, borderRadius:8, padding:"14px 16px",
                      border:`1px solid ${s.c}30`,
                    }}>
                      <div style={{fontSize:26, fontWeight:700, color:s.c, lineHeight:1}}>{s.val}</div>
                      <div style={{fontSize:12, color:C.textMuted, marginTop:5}}>{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Tier breakdown */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:12, color:C.textMuted, marginBottom:10, fontWeight:600, textTransform:"uppercase", letterSpacing:".07em"}}>
                    Resource Tier Breakdown
                  </div>
                  <div style={{display:"flex", flexWrap:"wrap", gap:8}}>
                    {Object.entries(
                      parseResult.resources.reduce((acc,r)=>{
                        const t=(RT[r.type]||RT._default).t;
                        acc[t]=(acc[t]||0)+1; return acc;
                      },{})
                    ).sort((a,b)=>b[1]-a[1]).map(([t,n])=>(
                      <div key={t} style={{
                        fontSize:12, padding:"6px 12px", borderRadius:6,
                        background:`${TIERS[t]?.border||"#555"}15`,
                        color:TIERS[t]?.border||"#888",
                        border:`1px solid ${TIERS[t]?.border||"#555"}33`,
                        fontWeight:600,
                      }}>
                        {TIERS[t]?.label||t}
                        <span style={{marginLeft:8, opacity:0.7, fontWeight:400}}>{n}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{display:"flex", gap:10}}>
                  <button onClick={()=>setMainTab("analysis")} style={{
                    background:"linear-gradient(135deg,#FF6B35,#FF9900)",
                    border:"none", borderRadius:8, padding:"10px 24px",
                    color:"#000", fontWeight:700, fontSize:13, cursor:"pointer", ...SANS,
                    display:"flex", alignItems:"center", gap:8,
                  }}>🔬 View Analysis →</button>
                  <button onClick={()=>setMainTab("dfd")} style={{
                    background:C.surface2, border:`1px solid ${C.accent}44`,
                    borderRadius:8, padding:"10px 24px",
                    color:C.accent, fontWeight:600, fontSize:13, cursor:"pointer", ...SANS,
                    display:"flex", alignItems:"center", gap:8,
                  }}>🗺 View DFD →</button>
                </div>
              </div>
            </div>
          )}

          {/* Architecture Context accordion */}
          <details open style={{marginTop:24}}>
            <summary style={{
              fontSize:14, fontWeight:700, color:C.text, cursor:"pointer",
              padding:"12px 0", borderTop:`1px solid ${C.border}`,
              listStyle:"none", display:"flex", alignItems:"center", gap:8,
              userSelect:"none",
            }}>Architecture Context (optional)</summary>
            {(()=>{
        const NARRATIVE_FIELDS = [
          { key:"entryPoints",           label:"Entry Points",               Icon:DoorOpen },
          { key:"dataFlow",              label:"Data Flow",                  Icon:ArrowLeftRight },
          { key:"securityBoundaries",    label:"Security Boundaries",        Icon:Lock },
          { key:"publicPrivateResources",label:"Public & Private Resources", Icon:Globe },
          { key:"securityControls",      label:"Security Controls",          Icon:Shield },
          { key:"faultTolerance",        label:"Fault Tolerance",            Icon:RefreshCw },
          { key:"authAndAuthz",          label:"Authentication & AuthZ",     Icon:KeyRound },
          { key:"externalDependencies",  label:"External Dependencies",      Icon:LinkIcon },
          { key:"storageAndDataSecurity",label:"Storage & Data Security",    Icon:Database },
        ];

        const ATTR_CHIPS = {
          applicationType:   ["Web App","REST API","Serverless","Microservices","Container-Based","VM-Based","Static Site","Data Pipeline","Streaming","ML/AI"],
          entryPointTypes:   ["HTTPS","REST API","GraphQL","gRPC","CLI","SDK","Webhook","Event Stream","File Transfer","Web UI"],
          developedBy:       ["Vendor (AWS)","Vendor (Azure)","Vendor (GCP)","Vendor (3rd Party)","Internal","Hybrid"],
          users:             ["Internal Employees","Internal Apps/Services","External End Users","3rd Party Systems","Business Partners"],
          inboundDataSource: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","IoT/Edge"],
          inboundDataFlow:   ["API Request","Event/Message","Network Traffic","User Input","Data Streaming","File Upload","DB Replication"],
          outboundDataFlow:  ["API Response","Event/Message","Network Traffic","Data Streaming","File Export","DB Write"],
          outboundDataDestination: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","Data Warehouse"],
          integrations:      ["REST API","GraphQL","SDK","Webhook","File Transfer","Message Queue (SQS/SNS)","Event Stream (Kinesis/Kafka)","Middleware","DB Replication"],
          exposure:          ["Public Internet","Intranet Only","VPN Required","Trusted Partner Network","Air-Gapped"],
          facilityType:      ["AWS Cloud","Azure Cloud","GCP Cloud","Enterprise Data Center","3rd Party DC","Mobile","Desktop"],
          computeType:       ["Cloud Managed Service","Serverless","Container (ECS/EKS)","VM (EC2)","On-Premises","Hybrid"],
          authMethods:       ["OAuth 2.0","SSO/SAML","PKI/mTLS","ADFS/LDAP","API Key","MFA","AWS IAM","Certificate","Passwordless"],
          dataSensitivity:   ["PII","PHI","PCI Data","Confidential","Internal","Public","Export Controlled","Trade Secret"],
          complianceFramework:["HIPAA","PCI-DSS","SOC 2","GDPR","FedRAMP","ISO 27001","NIST 800-53","CIS AWS","CCPA","CMMC"],
          environment:       ["Production","Staging","Development","DR / Backup","Lab / Sandbox","Multi-Tenant","Single-Tenant"],
        };

        const ATTR_GROUPS = [
          { label:"Application Profile",        keys:["applicationType","entryPointTypes","developedBy","users"] },
          { label:"Data & Integration",          keys:["inboundDataSource","inboundDataFlow","outboundDataFlow","outboundDataDestination","integrations"] },
          { label:"Deployment & Infrastructure", keys:["exposure","facilityType","computeType"] },
          { label:"Security & Compliance",       keys:["authMethods","dataSensitivity","complianceFramework"] },
          { label:"Context",                     keys:["environment"] },
        ];

        const ATTR_LABELS = {
          applicationType:"Application / Solution Type", entryPointTypes:"Entry Points",
          developedBy:"Developed By", users:"Users / Consumers",
          inboundDataSource:"Inbound Data Source", inboundDataFlow:"Inbound Data Flow",
          outboundDataFlow:"Outbound Data Flow", outboundDataDestination:"Outbound Destination",
          integrations:"Integrations", exposure:"Exposure", facilityType:"Facility Type",
          computeType:"Compute Type", authMethods:"Authentication Methods",
          dataSensitivity:"Data Sensitivity", complianceFramework:"Compliance Frameworks",
          environment:"Environment / Deployment Stage",
        };

        const SINGLE_SELECT = ["developedBy","environment"];

        // Merge base + overrides
        const baseNarrative = archAnalysis?.narrative || {};
        const baseAttrs     = archAnalysis?.attributes || {};
        const ovNarrative   = archOverrides?.narrative || {};
        const ovAttrs       = archOverrides?.attributes || {};
        const narrative     = { ...baseNarrative, ...ovNarrative };
        const attrs         = { ...baseAttrs, ...ovAttrs };

        const saveNarrativeField = (key, value) => {
          const updated = { ...archOverrides, narrative: { ...ovNarrative, [key]: value } };
          setArchOverrides(updated);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: updated })); } catch {}
          }
        };

        const toggleAttrChip = (attrKey, chip) => {
          const single = SINGLE_SELECT.includes(attrKey);
          const current = attrs[attrKey];
          let updated;
          if (single) {
            updated = current === chip ? "" : chip;
          } else {
            const arr = Array.isArray(current) ? current : [];
            updated = arr.includes(chip) ? arr.filter(c => c !== chip) : [...arr, chip];
          }
          const newAttrs = { ...ovAttrs, [attrKey]: updated };
          const newOverrides = { ...archOverrides, attributes: newAttrs };
          setArchOverrides(newOverrides);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: newOverrides })); } catch {}
          }
        };

        const reanalyze = () => {
          setArchAnalyzing(true);
          setTimeout(() => {
            try {
              const result = intelligenceRef.current.analyzeArchitecture(parseResult?.resources||[], userDocs, modelDetails);
              setArchAnalysis(result);
              if (currentModel) {
                try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
                  JSON.stringify({ base: result, overrides: archOverrides })); } catch {}
              }
            } finally { setArchAnalyzing(false); }
          }, 0);
        };

        const resetOverrides = () => {
          setArchOverrides({});
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: {} })); } catch {}
          }
        };

        return (
          <div style={{ height:"calc(100vh - 58px)", overflow:"hidden", display:"flex", flexDirection:"column" }}>
            {/* Header bar */}
            <div style={{ padding:"16px 28px", borderBottom:`1px solid ${C.border}`, background:C.surface,
              display:"flex", alignItems:"center", gap:16, flexShrink:0 }}>
              <div style={{ flex:1 }}>
                <div style={{...SANS, fontSize:16, fontWeight:700, color:C.text}}>Architecture Analysis</div>
                <div style={{ fontSize:11, color:C.textMuted, marginTop:2 }}>
                  Auto-populated from Terraform resources and uploaded documents · editable per-model
                  {archAnalysis && <span style={{marginLeft:10, color:C.accent, fontWeight:600}}>· Confidence: {archAnalysis.confidence}%</span>}
                </div>
              </div>
              {archAnalyzing && <Loader2 size={16} style={{color:C.accent, animation:"spin 1s linear infinite"}}/>}
              <button onClick={reanalyze} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:C.surface2, border:`1px solid ${C.border2}`, borderRadius:7,
                color:C.textSub, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RotateCcw size={12}/> Re-analyze</button>
              <button onClick={resetOverrides} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:"transparent", border:`1px solid ${C.border}`, borderRadius:7,
                color:C.textMuted, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RefreshCw size={12}/> Reset edits</button>
            </div>

            {/* Body — 2-column */}
            {!archAnalysis && !archAnalyzing ? (
              <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center", flexDirection:"column", gap:12 }}>
                <Building2 size={40} style={{color:C.textMuted, opacity:.4}}/>
                <div style={{...SANS, fontSize:14, color:C.textMuted}}>Upload Terraform files or documents to generate architecture analysis</div>
                <button onClick={()=>setMainTab("build")} style={{
                  ...SANS, fontSize:12, padding:"7px 16px", borderRadius:7,
                  background:`${C.accent}18`, border:`1px solid ${C.accent}44`, color:C.accent, cursor:"pointer",
                }}>Go to Upload & Analyze</button>
              </div>
            ) : (() => {
              // ── Inline markdown renderer for narrative preview ──
              const renderLine = (line, i) => {
                const parts = line.split(/(\*\*[^*]+\*\*)/g);
                return parts.map((p,j) =>
                  (p.startsWith('**') && p.endsWith('**'))
                    ? <strong key={j}>{p.slice(2,-2)}</strong>
                    : <span key={j}>{p}</span>
                );
              };
              const decodeEntities = (s) => (s||'')
                .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>')
                .replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&nbsp;/g,' ');
              const renderNarrative = (text) => {
                if (!text?.trim()) return null;
                const lines = decodeEntities(text).split('\n');
                const els = [];
                let i = 0;
                while (i < lines.length) {
                  const line = lines[i];
                  const trimmed = line.trim();
                  if (trimmed.startsWith('• ') || trimmed.startsWith('- ')) {
                    const bullets = [];
                    while (i < lines.length && (lines[i].trim().startsWith('• ') || lines[i].trim().startsWith('- '))) {
                      bullets.push(lines[i].trim().slice(2));
                      i++;
                    }
                    els.push(
                      <div key={`b${i}`} style={{marginBottom:4}}>
                        {bullets.map((b,bi) => (
                          <div key={bi} style={{display:'flex', gap:7, marginBottom:3, alignItems:'flex-start'}}>
                            <span style={{color:C.accent, flexShrink:0, marginTop:1, fontSize:13, lineHeight:'16px'}}>•</span>
                            <span style={{lineHeight:'18px'}}>{renderLine(b, bi)}</span>
                          </div>
                        ))}
                      </div>
                    );
                  } else if (trimmed.startsWith('Context:')) {
                    els.push(
                      <div key={`c${i}`} style={{
                        marginTop:8, padding:'7px 10px',
                        background:`${C.accent}0a`, border:`1px solid ${C.accent}22`,
                        borderRadius:6, fontSize:11, color:C.textSub, lineHeight:1.6,
                        fontStyle:'italic',
                      }}>
                        <span style={{fontWeight:700, fontStyle:'normal', color:C.accent, fontSize:10, marginRight:5}}>FROM DOCS</span>
                        {renderLine(trimmed.slice(9).trim(), i)}
                      </div>
                    );
                    i++;
                  } else if (trimmed === '') {
                    els.push(<div key={`sp${i}`} style={{height:5}}/>);
                    i++;
                  } else {
                    els.push(<div key={`t${i}`} style={{marginBottom:3, lineHeight:'18px'}}>{renderLine(trimmed, i)}</div>);
                    i++;
                  }
                }
                return els;
              };

              return (
                <div style={{ flex:1, display:"grid", gridTemplateColumns:"1fr 1fr", overflow:"hidden" }}>
                  {/* LEFT — Narrative Fields */}
                  <div style={{ overflowY:"auto", padding:"16px 20px", borderRight:`1px solid ${C.border}` }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Narrative Findings
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        {Object.values(narrative).filter(Boolean).length} / {NARRATIVE_FIELDS.length} fields populated
                      </div>
                    </div>
                    {NARRATIVE_FIELDS.map(({ key, label, Icon: FieldIcon }) => {
                      const value = narrative[key] || "";
                      const isOverridden = !!ovNarrative[key];
                      const isEditing = archEditingField === key;
                      const bulletCount = (value.match(/^•/gm) || []).length;
                      return (
                        <div key={key} style={{
                          marginBottom:10,
                          border:`1px solid ${isEditing ? C.accent+'55' : C.border}`,
                          borderRadius:10,
                          overflow:'hidden',
                          transition:'border-color .15s',
                          background: C.surface,
                        }}>
                          {/* Section header */}
                          <div style={{
                            display:'flex', alignItems:'center', gap:7, padding:'8px 12px',
                            borderBottom:`1px solid ${isEditing ? C.accent+'22' : C.border}`,
                            background: isEditing ? `${C.accent}08` : C.surface2,
                          }}>
                            <FieldIcon size={13} style={{color: C.accent, flexShrink:0}}/>
                            <span style={{...SANS, fontSize:12, fontWeight:700, color:C.text, flex:1}}>{label}</span>
                            {bulletCount > 0 && !isEditing && (
                              <span style={{fontSize:10, color:C.textMuted}}>{bulletCount} items</span>
                            )}
                            {!isOverridden && value && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:"#FF980018", color:"#FF9800",
                                border:"1px solid #FF980044", borderRadius:8, padding:"1px 6px"}}>AI</span>
                            )}
                            {isOverridden && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:`${C.accent}18`, color:C.accent,
                                border:`1px solid ${C.accent}44`, borderRadius:8, padding:"1px 6px"}}>edited</span>
                            )}
                            <button
                              onClick={() => setArchEditingField(isEditing ? null : key)}
                              style={{
                                ...SANS, fontSize:10, padding:'2px 8px', borderRadius:6, cursor:'pointer',
                                display:'flex', alignItems:'center', gap:4,
                                background: isEditing ? C.accent : 'transparent',
                                border:`1px solid ${isEditing ? C.accent : C.border2}`,
                                color: isEditing ? '#fff' : C.textMuted,
                                transition:'all .12s',
                              }}
                            >
                              {isEditing
                                ? <><CheckCircle2 size={9}/> Done</>
                                : <><PenLine size={9}/> Edit</>
                              }
                            </button>
                          </div>
                          {/* Content: preview or textarea */}
                          {isEditing ? (
                            <textarea
                              value={value}
                              onChange={e => saveNarrativeField(key, e.target.value)}
                              placeholder={`Describe ${label.toLowerCase()}...\n\nUse • for bullets, e.g.:\n• Item one\n• Item two\nContext: optional doc note`}
                              ref={el => { if (el) { el.style.height='auto'; el.style.height=Math.max(80, el.scrollHeight)+'px'; }}}
                              onInput={e => { e.target.style.height='auto'; e.target.style.height=Math.max(80, e.target.scrollHeight)+'px'; }}
                              style={{
                                width:'100%', boxSizing:'border-box', resize:'none',
                                background:C.bg, border:'none', borderRadius:0,
                                color:C.text, fontSize:12, padding:'10px 12px',
                                lineHeight:1.7, outline:'none', ...SANS,
                                minHeight:80, display:'block', fontFamily:'inherit',
                              }}
                            />
                          ) : (
                            <div
                              onClick={() => setArchEditingField(key)}
                              style={{
                                padding:'10px 12px', fontSize:12, lineHeight:1.6,
                                color: value ? C.text : C.textMuted,
                                ...SANS, cursor:'text', minHeight:38,
                                fontStyle: value ? 'normal' : 'italic',
                              }}
                            >
                              {value
                                ? renderNarrative(value)
                                : `Click to add ${label.toLowerCase()}…`
                              }
                            </div>
                          )}
                          {isEditing && (
                            <div style={{
                              display:'flex', justifyContent:'flex-end',
                              padding:'4px 10px', borderTop:`1px solid ${C.border}`,
                              background:C.surface2,
                            }}>
                              <span style={{fontSize:10, color:C.textMuted}}>{value.length} chars</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* RIGHT — Structured Attributes */}
                  <div style={{ overflowY:"auto", padding:"16px 20px" }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Structured Attributes
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        ✦ = AI-detected
                      </div>
                    </div>
                    {ATTR_GROUPS.map((group, gi) => {
                      // Count selected across this group
                      const selCount = group.keys.reduce((n, k) => {
                        const v = attrs[k];
                        return n + (SINGLE_SELECT.includes(k) ? (v ? 1 : 0) : (Array.isArray(v) ? v.length : 0));
                      }, 0);
                      return (
                        <div key={gi} style={{ marginBottom:18 }}>
                          <div style={{
                            display:'flex', alignItems:'center', justifyContent:'space-between',
                            marginBottom:10, paddingBottom:7,
                            borderBottom:`1px solid ${C.border}`,
                          }}>
                            <div style={{fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".08em"}}>
                              {group.label}
                            </div>
                            {selCount > 0 && (
                              <span style={{
                                fontSize:10, color:C.accent, fontWeight:600,
                                background:`${C.accent}15`, border:`1px solid ${C.accent}33`,
                                borderRadius:8, padding:'1px 7px',
                              }}>{selCount} selected</span>
                            )}
                          </div>
                          {group.keys.map(attrKey => {
                            const options = ATTR_CHIPS[attrKey] || [];
                            const single = SINGLE_SELECT.includes(attrKey);
                            const selected = attrs[attrKey];
                            const isSelected = (opt) => single
                              ? selected === opt
                              : Array.isArray(selected) && selected.includes(opt);
                            const isAI = (opt) => {
                              const base = baseAttrs[attrKey];
                              return single ? base === opt : Array.isArray(base) && base.includes(opt);
                            };
                            const anySelected = single ? !!selected : (Array.isArray(selected) && selected.length > 0);
                            return (
                              <div key={attrKey} style={{ marginBottom:11 }}>
                                <div style={{...SANS, fontSize:11, fontWeight:600, color: anySelected ? C.textSub : C.textMuted, marginBottom:5, display:'flex', alignItems:'center', gap:5}}>
                                  {ATTR_LABELS[attrKey]}
                                  {single && <span style={{fontSize:9, color:C.textMuted, fontWeight:400, background:C.surface2, padding:'1px 5px', borderRadius:4}}>single</span>}
                                </div>
                                <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                                  {options.map(opt => {
                                    const active = isSelected(opt);
                                    const ai = isAI(opt);
                                    return (
                                      <button key={opt} onClick={() => toggleAttrChip(attrKey, opt)} style={{
                                        ...SANS, fontSize:11, fontWeight: active ? 600 : 400,
                                        padding:"3px 9px", borderRadius:12, cursor:"pointer",
                                        background: active ? `${C.accent}20` : C.surface2,
                                        border: `1px solid ${active ? C.accent+'88' : C.border2}`,
                                        color: active ? C.accent : C.textMuted,
                                        transition:"all .12s", position:"relative",
                                        lineHeight:'16px',
                                      }}>
                                        {opt}
                                        {ai && active && (
                                          <span title="AI-detected" style={{
                                            fontSize:8, color:"#FF9800",
                                            position:"absolute", top:-4, right:-4,
                                            background:C.surface, borderRadius:"50%",
                                            padding:"0 2px", lineHeight:'12px',
                                            border:'1px solid #FF980044',
                                          }}>✦</span>
                                        )}
                                      </button>
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
          </div>
        );
            })()}
          </details>
        </div>
      )}

      {/* ── INTELLIGENCE TAB ── */}
      {mainTab==="intelligence" && (
        <IntelligencePanel
          intelligence={intelligenceRef.current}
          intelligenceVersion={intelligenceVersion}
          userDocs={userDocs}
          parseResult={parseResult}
          modelDetails={modelDetails}
          archAnalysis={archAnalysis}
          archOverrides={archOverrides}
          currentModelId={currentModel?.id}
          llmStatus={llmStatus}
          llmProgress={llmProgress}
          llmStatusText={llmStatusText}
          embedStatus={embedStatus}
          embedProgress={embedProgress}
          selectedLlmModel={selectedLlmModel}
          wllamaModelName={wllamaModelName}
          wllamaModelSize={wllamaModelSize}
          onLoadModel={loadWllama}
          onHybridSearch={hybridSearch}
          onGenerateLLM={generateLLMResponse}
          vectorStore={vectorStoreRef.current}
          computedIR={computedIR}
          archLayerAnalysis={archLayerAnalysis}
          archLayerVersion={archLayerVersion}
        />
      )}

      {/* ── THREATAFORM ANALYSIS TAB ── */}
      {mainTab==="analysis" && (
        <div style={{flex:1, overflow:"auto", background:C.bg, height:"calc(100vh - 58px)"}}>
          {parseResult ? (
            <AnalysisErrorBoundary>
              <AnalysisPanel parseResult={parseResult} files={files} userDocs={userDocs} scopeFiles={scopeFiles} onScopeChange={setScopeFiles}/>
            </AnalysisErrorBoundary>
          ) : (
            <div style={{
              height:"100%", display:"flex", flexDirection:"column",
              alignItems:"center", justifyContent:"center",
              gap:20, padding:40,
            }}>
              <div style={{
                width:80, height:80, borderRadius:20,
                background:`linear-gradient(135deg,${C.accent}20,${C.accent}08)`,
                border:`1px solid ${C.accent}30`,
                display:"flex", alignItems:"center", justifyContent:"center",
                fontSize:36,
              }}>🔬</div>
              <div>
                <div style={{fontSize:20, fontWeight:700, color:C.text, textAlign:"center", marginBottom:10}}>
                  Threataform Analysis
                </div>
                <div style={{fontSize:14, color:C.textSub, textAlign:"center", maxWidth:480, lineHeight:1.75}}>
                  Upload Terraform files to generate a full architectural analysis — STRIDE-LM threat modeling, MITRE ATT&CK® mapping, security findings, trust boundaries, and architecture narrative.
                </div>
              </div>
              <button onClick={()=>setMainTab("build")} style={{
                background:"linear-gradient(135deg,#FF6B35,#FF9900)",
                border:"none", borderRadius:8, padding:"12px 28px",
                color:"#000", fontWeight:700, fontSize:14, cursor:"pointer", ...SANS,
              }}>Upload .tf Files →</button>
            </div>
          )}
        </div>
      )}

      {/* ── DFD OUTPUT TAB ── */}
      {mainTab==="dfd" && (
        <div style={{display:"flex", flexDirection:"column", height:"calc(100vh - 58px)"}}>
          {/* Sub-tab bar */}
          <div style={{
            background:C.surface, borderBottom:`1px solid ${C.border}`,
            padding:"0 24px", display:"flex", gap:4, alignItems:"center", height:48,
          }}>
            {[
              {id:"arch",     label:"Architecture",       Icon: ImageIcon},
              {id:"stats",    label:"Stats",              Icon: BarChart2},
              {id:"xml",      label:"XML Output",         Icon: Code2},
              {id:"guide",    label:"Import Guide",       Icon: BookMarked},
              {id:"legend",   label:"Legend",             Icon: LayoutList},
            ].map(t => {
              const active = dfdTab === t.id;
              return (
                <button key={t.id} onClick={()=>setDfdTab(t.id)} style={{
                  display:"flex", alignItems:"center", gap:6,
                  background: active ? `${C.accent}12` : "transparent",
                  border: active ? `1px solid ${C.accent}40` : "1px solid transparent",
                  borderRadius:6, padding:"6px 14px",
                  color: active ? C.accent : C.textMuted,
                  fontSize:13, cursor:"pointer", ...SANS,
                  fontWeight: active ? 600 : 400,
                  transition:"all .15s",
                }}>
                  <t.Icon size={14} />
                  <span>{t.label}</span>
                </button>
              );
            })}
            {!xml && !parseResult && (
              <span style={{fontSize:12, color:C.textMuted, marginLeft:16}}>
                ← Upload files in the "Upload & Analyze" tab first
              </span>
            )}
          </div>

          <div style={{flex:1, overflow:"auto", background:"#080810"}}>

            {/* ── ARCHITECTURE IMAGE (uploaded from Lucidchart export) ── */}
            {dfdTab==="arch" && (
              <ArchitectureImageViewer
                image={diagramImage}
                onUpload={(dataUrl, _name) => {
                  setDiagramImage(dataUrl);
                  if (currentModel) {
                    try { localStorage.setItem(`tf-model-${currentModel.id}-diagram-image`, dataUrl); } catch {}
                  }
                }}
              />
            )}

            {/* STATS */}
            {dfdTab==="stats" && parseResult && (
              <div style={{padding:"20px 28px", maxWidth:800}}>
                <div style={{fontSize:15, fontWeight:700, color:"#FFF", marginBottom:16}}>Terraform Architecture Analysis</div>

                {/* Files */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><FolderOpen size={11}/> Analyzed Files ({files.length})</div>
                  <div style={{display:"flex", flexDirection:"column", gap:3}}>
                    {files.map((f,i)=>(
                      <div key={i} style={{fontSize:10, color:"#3A5A3A", ...MONO, display:"flex", justifyContent:"space-between"}}>
                        <span><span style={{color:"#2E7D32",marginRight:6}}>▸</span>{f.path}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Resource table */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#4CAF50", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><Layers size={11}/> Resources ({parseResult.resources.length})</div>
                  <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                    <div style={{display:"grid", gridTemplateColumns:"1fr 1fr auto", background:"#111120", padding:"6px 12px", fontSize:9, color:"#444", textTransform:"uppercase", letterSpacing:".1em"}}>
                      <span>Resource ID</span><span>Label</span><span>Tier</span>
                    </div>
                    {parseResult.resources.slice(0,50).map((r,i)=>{
                      const meta=RT[r.type]||RT._default;
                      return (
                        <div key={i} style={{display:"grid", gridTemplateColumns:"1fr 1fr auto", padding:"5px 12px", borderTop:"1px solid #111120", background:i%2===0?"#0A0A14":"#0C0C18"}}>
                          <span style={{...MONO, fontSize:10, color:"#4a8a8a"}}>{r.id.substring(0,40)}</span>
                          <span style={{fontSize:10, color:"#999"}}>{r.label}</span>
                          <span style={{fontSize:9, padding:"1px 6px", borderRadius:2, background:meta.c+"22", color:meta.c}}>{meta.t}</span>
                        </div>
                      );
                    })}
                    {parseResult.resources.length > 50 && (
                      <div style={{padding:"6px 12px", fontSize:10, color:"#444"}}>...and {parseResult.resources.length-50} more</div>
                    )}
                  </div>
                </div>

                {/* Modules */}
                {parseResult.modules.length > 0 && (
                  <div style={{marginBottom:20}}>
                    <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><Package size={11}/> Modules & Remote State ({parseResult.modules.length})</div>
                    <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                      {parseResult.modules.map((m,i)=>(
                        <div key={i} style={{padding:"6px 12px", borderTop:i>0?"1px solid #111120":"none", background:i%2===0?"#0A0A14":"#0C0C18", display:"flex", justifyContent:"space-between", alignItems:"center"}}>
                          <span style={{...MONO, fontSize:10, color:"#4a8a8a"}}>{m.id.substring(0,40)}</span>
                          <span style={{fontSize:10, color:"#666"}}>{m.shortSrc}</span>
                          <span style={{fontSize:9, padding:"1px 6px", borderRadius:2,
                            background: m.srcType==="sentinel"?"#E65100"+"22":m.srcType==="local"?"#2E7D32"+"22":m.srcType==="git"?"#1565C0"+"22":"#9C27B0"+"22",
                            color: m.srcType==="sentinel"?"#E65100":m.srcType==="local"?"#4CAF50":m.srcType==="git"?"#2196F3":"#CE93D8"
                          }}>{m.srcType}{m.version?` v${m.version}`:""}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Connections */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#2196F3", fontWeight:600, marginBottom:8}}>→ Connections ({parseResult.connections.length})</div>
                  <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                    {parseResult.connections.slice(0,30).map((c,i)=>(
                      <div key={i} style={{padding:"5px 12px", borderTop:i>0?"1px solid #111120":"none", background:i%2===0?"#0A0A14":"#0C0C18", display:"flex", gap:8, alignItems:"center", fontSize:10}}>
                        <span style={{...MONO, color:"#4a8a8a", flex:1}}>{c.from.substring(0,30)}</span>
                        <span style={{color:c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#4CAF50":"#546E7A", fontSize:10}}>→</span>
                        <span style={{...MONO, color:"#6a8a6a", flex:1}}>{c.to.substring(0,30)}</span>
                        <span style={{fontSize:9, padding:"1px 5px", borderRadius:2,
                          background:c.kind==="explicit"?"#E5393522":c.kind==="module-input"?"#4CAF5022":"#54647422",
                          color:c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#4CAF50":"#78909C"
                        }}>{c.kind}</span>
                      </div>
                    ))}
                    {parseResult.connections.length>30&&<div style={{padding:"6px 12px",fontSize:10,color:"#444"}}>...and {parseResult.connections.length-30} more connections</div>}
                  </div>
                </div>
              </div>
            )}

            {/* XML */}
            {dfdTab==="xml" && xml && (
              <pre style={{margin:0, padding:"16px", background:"transparent", fontSize:10, lineHeight:1.7, ...MONO, whiteSpace:"pre-wrap", wordBreak:"break-all"}}>
                <code dangerouslySetInnerHTML={{__html:hlXml(xml)}}/>
              </pre>
            )}
            {dfdTab==="xml" && !xml && (
              <div style={{padding:"40px", textAlign:"center", color:"#333", fontSize:12}}>
                Upload .tf files first to generate XML
              </div>
            )}

            {/* GUIDE */}
            {dfdTab==="guide" && (
              <div style={{padding:"24px 28px", maxWidth:780}}>
                <div style={{fontSize:16, fontWeight:700, color:C.text, marginBottom:4}}>Import Guide</div>
                <div style={{fontSize:13, color:C.textSub, marginBottom:24}}>Step-by-step instructions for importing your generated DFD into diagramming tools</div>

                {/* Tool cards */}
                <div style={{display:"flex", flexDirection:"column", gap:14, marginBottom:28}}>
                  {[
                    {
                      name:"Lucidchart (Enterprise)", color:"#FF7043", badge:"✦ Primary — Draw.io Import",
                      steps:[
                        "Click Export .xml in the top-right — saves enterprise-tf-dfd.xml to your machine",
                        "In Lucidchart: click File → Import Documents",
                        "In the Import dialog select Draw.io (.xml, .drawio) and upload your enterprise-tf-dfd.xml file",
                        "All tier boundaries, resource nodes, and connection arrows will import correctly",
                        "Press Ctrl+Shift+H (Fit Page) after import to center the diagram in the canvas",
                      ]
                    },
                    {
                      name:"draw.io / diagrams.net", color:"#1E88E5", badge:"Secondary",
                      steps:[
                        "Click Export .xml to save the file",
                        "Open app.diagrams.net in any browser (free, no account needed)",
                        "Drag and drop the .drawio file onto the canvas — or use File → Import From → Device",
                        "All tier blocks, nodes, and connection arrows are preserved automatically",
                        "Press Ctrl+Shift+H (Cmd+Shift+H on Mac) to fit the diagram to the window",
                      ]
                    },
                    {
                      name:"Microsoft Visio", color:"#2E7D32", badge:null,
                      steps:[
                        "Download the .xml file via the Export .xml button",
                        "In draw.io, use File → Export As → Visio (.vsdx) to convert",
                        "Or install the Diagrams.net add-in for Visio from the Microsoft AppSource store",
                      ]
                    },
                  ].map((tool,ti)=>(
                    <div key={ti} style={{background:C.surface2, border:`1px solid ${tool.color}30`, borderLeft:`3px solid ${tool.color}`, borderRadius:8, overflow:"hidden"}}>
                      <div style={{padding:"12px 18px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:10}}>
                        <span style={{fontSize:14, fontWeight:700, color:tool.color}}>{tool.name}</span>
                        {tool.badge && (
                          <span style={{fontSize:10, fontWeight:700, background:`${tool.color}20`, color:tool.color, border:`1px solid ${tool.color}44`, borderRadius:4, padding:"2px 8px"}}>{tool.badge}</span>
                        )}
                      </div>
                      <div style={{padding:"14px 18px", display:"flex", flexDirection:"column", gap:9}}>
                        {tool.steps.map((step,si)=>(
                          <div key={si} style={{display:"flex", gap:12, alignItems:"flex-start"}}>
                            <div style={{minWidth:22, height:22, borderRadius:"50%", background:`${tool.color}20`, border:`1px solid ${tool.color}44`, color:tool.color, fontSize:11, fontWeight:700, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0}}>{si+1}</div>
                            <span style={{fontSize:13, color:C.textSub, lineHeight:1.55, paddingTop:2}}>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Tier swim lane reference */}
                <div style={{marginBottom:24}}>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Tier Swim Lane Reference</div>
                  <div style={{display:"flex", flexDirection:"column", gap:6}}>
                    {[
                      {k:"xsphere",  desc:"Private cloud VMs, clusters, datastores, and virtual networks"},
                      {k:"org",      desc:"AWS Organizations, organizational units, accounts, and SCPs"},
                      {k:"security", desc:"IAM roles/policies, KMS keys, Secrets Manager, WAF, GuardDuty"},
                      {k:"cicd",     desc:"CodePipeline, CodeBuild, Terraform modules, Sentinel policy gates"},
                      {k:"network",  desc:"VPC, subnets, security groups, gateways, Transit GW, Direct Connect"},
                      {k:"compute",  desc:"EC2, Lambda, EKS, ECS, ALB, API Gateway, CloudFront, SQS, SNS"},
                      {k:"storage",  desc:"S3, RDS, DynamoDB, ElastiCache, EFS, EBS, Backup Vault"},
                    ].map(({k,desc})=>{
                      const t=TIERS[k]; if(!t)return null;
                      return (
                        <div key={k} style={{display:"flex", alignItems:"center", gap:14, padding:"9px 16px", background:C.surface2, border:`1px solid ${t.border}30`, borderLeft:`3px solid ${t.border}`, borderRadius:6}}>
                          <div style={{width:16, height:16, borderRadius:3, background:t.hdr, border:`1px solid ${t.border}60`, flexShrink:0}}/>
                          <span style={{color:t.border, fontWeight:700, fontSize:13, minWidth:200}}>{t.label}</span>
                          <span style={{color:C.textSub, fontSize:12}}>{desc}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Edge type reference */}
                <div>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Connection Type Reference</div>
                  <div style={{display:"flex", flexDirection:"column", gap:8}}>
                    {[
                      {c:"#78909C", dash:false, l:"Implicit reference",    d:"Resource attribute cross-reference (auto-detected from Terraform HCL body)"},
                      {c:"#E53935", dash:true,  l:"Explicit depends_on",   d:"Manually declared dependency via depends_on = [...]"},
                      {c:"#4CAF50", dash:false, l:"Module input / output", d:"Module input directly references a resource attribute or output"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:16, padding:"10px 16px", background:C.surface2, border:`1px solid ${C.border}`, borderRadius:6}}>
                        <svg width="50" height="14" style={{flexShrink:0}}>
                          <line x1="2" y1="7" x2="38" y2="7" stroke={e.c} strokeWidth="2" strokeDasharray={e.dash?"6 3":"none"}/>
                          <polygon points="36,4 50,7 36,10" fill={e.c}/>
                        </svg>
                        <span style={{fontSize:13, fontWeight:600, color:e.c, minWidth:160}}>{e.l}</span>
                        <span style={{fontSize:12, color:C.textMuted}}>{e.d}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* LEGEND */}
            {dfdTab==="legend" && (
              <div style={{padding:"24px 28px", maxWidth:960}}>
                <div style={{fontSize:16, fontWeight:700, color:C.text, marginBottom:4}}>DFD Resource Type Legend</div>
                <div style={{fontSize:13, color:C.textSub, marginBottom:20}}>All resource types mapped to infrastructure tiers — no emoji, color-coded by tier</div>

                {/* Tier color key */}
                <div style={{marginBottom:22}}>
                  <div style={{fontSize:11, fontWeight:700, color:C.accent, textTransform:"uppercase", letterSpacing:".1em", marginBottom:10}}>Tier Color Key</div>
                  <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
                    {Object.entries(TIERS).map(([k,t])=>(
                      <div key={k} style={{display:"flex", alignItems:"center", gap:8, padding:"7px 14px", background:C.surface2, border:`1px solid ${t.border}40`, borderLeft:`3px solid ${t.border}`, borderRadius:6}}>
                        <div style={{width:12, height:12, borderRadius:2, background:t.hdr, border:`1px solid ${t.border}60`, flexShrink:0}}/>
                        <span style={{color:t.border, fontWeight:600, fontSize:12}}>{t.label}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Resource types per tier */}
                <div style={{display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:24}}>
                  {Object.entries(TIERS).map(([tid, tmeta])=>{
                    const resInTier = Object.entries(RT).filter(([k,v])=>v.t===tid&&k!=="_default");
                    return (
                      <div key={tid} style={{background:C.surface2, border:`1px solid ${tmeta.border}30`, borderRadius:8, overflow:"hidden"}}>
                        <div style={{background:tmeta.hdr, padding:"8px 14px", fontSize:11, fontWeight:700, color:"#FFF", letterSpacing:".04em"}}>
                          {tmeta.label} <span style={{opacity:0.65, fontWeight:400}}>({resInTier.length})</span>
                        </div>
                        <div style={{padding:"10px 14px", display:"flex", flexDirection:"column", gap:5}}>
                          {resInTier.slice(0,14).map(([k,v])=>(
                            <div key={k} style={{display:"flex", gap:8, alignItems:"center"}}>
                              <div style={{width:10, height:10, borderRadius:2, background:v.c, border:`1px solid ${v.c}88`, flexShrink:0}}/>
                              <span style={{fontSize:12, color:C.text}}>{v.l}</span>
                              <span style={{fontSize:10, color:C.textMuted, ...MONO, marginLeft:"auto"}}>{k.replace(/^aws_|^xsphere_/,"").replace(/_/g,"_").substring(0,22)}</span>
                            </div>
                          ))}
                          {resInTier.length>14&&<div style={{fontSize:10,color:C.textMuted,marginTop:4}}>+{resInTier.length-14} more types</div>}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Connection types */}
                <div style={{marginBottom:16}}>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Connection Types</div>
                  <div style={{display:"flex", gap:10, flexWrap:"wrap"}}>
                    {[
                      {c:"#78909C", dash:false, l:"Implicit Reference",    d:"Auto-detected attribute cross-reference"},
                      {c:"#E53935", dash:true,  l:"Explicit depends_on",   d:"Manual depends_on = [...] declaration"},
                      {c:"#4CAF50", dash:false, l:"Module Input / Output", d:"Module input references resource attribute"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:14, padding:"12px 16px", background:C.surface2, border:`1px solid ${C.border}`, borderLeft:`3px solid ${e.c}`, borderRadius:8, flex:1, minWidth:220}}>
                        <svg width="44" height="14" style={{flexShrink:0}}>
                          <line x1="2" y1="7" x2="32" y2="7" stroke={e.c} strokeWidth="2" strokeDasharray={e.dash?"6 3":"none"}/>
                          <polygon points="30,4 44,7 30,10" fill={e.c}/>
                        </svg>
                        <div>
                          <div style={{fontSize:12, fontWeight:600, color:e.c}}>{e.l}</div>
                          <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{e.d}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Node types */}
                <div>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Node Border Styles</div>
                  <div style={{display:"flex", gap:10, flexWrap:"wrap"}}>
                    {[
                      {fill:"#FFFFFF", stroke:"#546E7A", dash:false,  l:"AWS / xSphere Resource", d:"Standard managed resource"},
                      {fill:"#FAFFF5", stroke:"#558B2F", dash:true,   l:"Terraform Module",       d:"local / git / registry module"},
                      {fill:"#E3F2FD", stroke:"#1565C0", dash:true,   l:"Remote State Reference", d:"terraform_remote_state data source"},
                      {fill:"#FFF8E1", stroke:"#E65100", dash:false,  l:"Sentinel Policy Gate",   d:"Policy-as-code enforcement point"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:12, padding:"10px 14px", background:C.surface2, border:`1px solid ${C.border}`, borderRadius:8, flex:1, minWidth:200}}>
                        <div style={{width:28, height:20, borderRadius:4, background:e.fill, border:`1.5px ${e.dash?"dashed":"solid"} ${e.stroke}`, flexShrink:0}}/>
                        <div>
                          <div style={{fontSize:12, fontWeight:600, color:C.text}}>{e.l}</div>
                          <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{e.d}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}


            {/* Empty state */}
            {dfdTab==="stats" && !parseResult && (
              <div style={{height:"100%", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:14, opacity:0.3, padding:40}}>
                <div style={{fontSize:48}}>🗺</div>
                <div style={{fontSize:14, letterSpacing:".1em", textAlign:"center"}}>Upload .tf files to generate<br/>your enterprise DFD</div>
                <button onClick={()=>setMainTab("build")} style={{background:"none",border:"1px solid #333",borderRadius:4,padding:"6px 16px",color:"#555",fontSize:11,cursor:"pointer"}}>Go to Upload →</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
