// src/features/intelligence/IntelligencePanel.jsx
import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Upload, Building2, Search, ShieldCheck, GitCompare, ShieldAlert, Zap, TriangleAlert, ScanLine, Layers, Loader2, Shield, Cloud, FileText, CheckCircle2, AlertCircle, X, Info, Target, RotateCcw, Cpu, Server, Network, Users, Download, CheckCircle, Package, Bot, Send } from '../../icons.jsx';
import { MONO, SANS, C, SEV_COLOR, SEV_BG, card, sectionBar } from '../../constants/styles.js';
import { ATTACK_TECHNIQUES, CWE_DETAILS } from '../../data/attack-data.js';
import { CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS } from '../../data/control-detection.js';
import { generateTXTReport, generateMarkdownReport } from '../../lib/diagram/ExportUtils.js';
import { mcpRegistry } from '../../lib/mcp/MCPToolRegistry.js';
import { ARCH_QUICK_PROMPTS } from '../../lib/ThrataformRAG.js';
import { wllamaManager } from '../../lib/WllamaManager.js';


import { AIAssistantTab }     from './tabs/AIAssistantTab.jsx';
import { ThreatIntelTab }     from './tabs/ThreatIntelTab.jsx';
import { ScopeTab }           from './tabs/ScopeTab.jsx';
import { MisconfigsTab }      from './tabs/MisconfigsTab.jsx';
import { PostureControlsTab } from './tabs/PostureControlsTab.jsx';
import { CrossDocTab }        from './tabs/CrossDocTab.jsx';
import { ResourceIntelTab }   from './tabs/ResourceIntelTab.jsx';
import { ArchLayersTab }      from './tabs/ArchLayersTab.jsx';
function IntelligencePanel({ intelligence, intelligenceVersion, userDocs, parseResult,
  modelDetails, archAnalysis, archOverrides, currentModelId,
  llmStatus, llmProgress, llmStatusText, embedStatus, embedProgress,
  selectedLlmModel, wllamaModelName, wllamaModelSize,
  onLoadModel, onHybridSearch, onGenerateLLM, vectorStore, computedIR,
  archLayerAnalysis, archLayerVersion }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null); // null = not searched yet
  const [iTab, setITab] = useState("assistant");
  const chatKey = currentModelId ? `tf-model-${currentModelId}-chat` : null;
  const [chatMessages, setChatMessages] = useState(() => {
    if (!chatKey) return [];
    try { return JSON.parse(localStorage.getItem(chatKey) || "[]"); } catch { return []; }
  });
  const [chatInput, setChatInput] = useState("");
  const [chatGenerating, setChatGenerating] = useState(false);
  const [isTraining, setIsTraining]   = useState(false);  // LoRA fine-tuning state
  const [ftProgress, setFtProgress]   = useState(0);       // LoRA training progress %
  const [loraReady, setLoraReady]     = useState(false);   // LoRA adapter trained + ready to export
  // MCP tool server state
  const [mcpUrl, setMcpUrl]         = useState('ws://localhost:3747');
  const [mcpStatus, setMcpStatus]   = useState(''); // '' | 'connected' | 'failed' | 'connecting'
  const [mcpError, setMcpError]     = useState(null);
  const [showMcpHelp, setShowMcpHelp] = useState(false);
  const chatBottomRef = useRef(null);

  // ── Cross-tab navigation state ──
  const [attackFilter, setAttackFilter] = useState(null);
  const [resourceSearch, setResourceSearch] = useState('');
  const [resourceTypeFilter, setResourceTypeFilter] = useState('');
  const [resourcePage, setResourcePage] = useState(0);
  const [expandedControl, setExpandedControl] = useState(null);
  const [expandedCwe, setExpandedCwe] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  // ── Per-tab async/LLM output state ──
  const [synthesisingQuery, setSynthesisingQuery] = useState(false);
  const [synthesisText, setSynthesisText] = useState('');
  const [postureNarrative, setPostureNarrative] = useState('');
  const [postureNarrLoading, setPostureNarrLoading] = useState(false);
  const [gapAnalysis, setGapAnalysis] = useState('');
  const [gapAnalysisLoading, setGapAnalysisLoading] = useState(false);
  const [remediationPlan, setRemediationPlan] = useState('');
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [threatScenarios, setThreatScenarios] = useState('');
  const [threatScenariosLoading, setThreatScenariosLoading] = useState(false);
  const [inferredScope, setInferredScope] = useState('');
  const [inferredScopeLoading, setInferredScopeLoading] = useState(false);
  const [resourceSummaries, setResourceSummaries] = useState({});
  const [hybridHits, setHybridHits] = useState({});
  const [techPassages, setTechPassages] = useState({});
  const [findingGuidance, setFindingGuidance] = useState({});
  const [attackNarrative, setAttackNarrative] = useState('');
  const [attackNarrLoading, setAttackNarrLoading] = useState(false);
  const [contradictionNarrative, setContradictionNarrative] = useState('');
  const [contraNarrLoading, setContraNarrLoading] = useState(false);
  const [queryLoading, setQueryLoading] = useState(false);
  const [controlSearch, setControlSearch] = useState('');
  // ── AI Assistant search mode (replaces Query Docs tab) ──
  const [searchMode, setSearchMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);

  // Persist chat history per model
  useEffect(() => {
    if (!chatKey) return;
    try { localStorage.setItem(chatKey, JSON.stringify(chatMessages.filter(m => !m.streaming).slice(-60))); } catch {}
  }, [chatMessages, chatKey]);

  // Auto-scroll chat
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior:"smooth" });
  }, [chatMessages]);

  const summary = useMemo(() => {
    if (!intelligence?._built) return null;
    return intelligence.getArchitectureSummary(parseResult?.resources || [], userDocs || []);
  }, [intelligence, intelligenceVersion, parseResult, userDocs]);

  const handleQuery = async () => {
    if (!query.trim() || !intelligence) return;
    setSynthesisText('');
    setQueryLoading(true);
    try {
      const results = onHybridSearch
        ? await onHybridSearch(query.trim(), 8)
        : intelligence.query(query.trim(), 8);
      setResults(results);
    } finally {
      setQueryLoading(false);
    }
  };

  const STRIDE_COLORS = {
    spoofing:"#E91E63", tampering:"#FF5722", repudiation:"#9C27B0",
    infoDisclose:"#F44336", dos:"#FF9800", elevPriv:"#B71C1C",
  };
  const STRIDE_LABELS = {
    spoofing:"Spoofing", tampering:"Tampering", repudiation:"Repudiation",
    infoDisclose:"Info Disclosure", dos:"Denial of Service", elevPriv:"Elevation of Privilege",
  };
  const COMPLIANCE_LABELS = {
    hipaa:"HIPAA", fedramp:"FedRAMP", soc2:"SOC 2", pci:"PCI DSS",
    gdpr:"GDPR", cmmc:"CMMC", iso27001:"ISO 27001",
  };

  const noData = !intelligence?._built || (summary?.chunkCount || 0) === 0;
  const hasUserDocs = (userDocs?.length || 0) > 0;

  const catPill = (label, color) => (
    <span style={{
      background:`${color}22`, color, border:`1px solid ${color}44`,
      borderRadius:10, padding:"1px 8px", fontSize:10, fontWeight:600,
    }}>{label}</span>
  );

  const catColor = (cat) => ({
    "threat-model":"#E53935","compliance":"#0277BD","architecture":"#4527A0",
    "runbook":"#6A1B9A","terraform":"#5C4033"
  }[cat]||"#78909C");

  const chunkCard = (chunk, i) => (
    <div key={i} style={{
      background:C.surface, border:`1px solid ${C.border}`,
      borderRadius:8, padding:"12px 14px", marginBottom:8,
    }}>
      <div style={{display:"flex", gap:8, alignItems:"center", marginBottom:6, flexWrap:"wrap"}}>
        <span style={{background:`${C.accent}22`, color:C.accent, border:`1px solid ${C.accent}44`,
          borderRadius:10, padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
        {catPill(chunk.category, catColor(chunk.category))}
        {/* Confidence meter */}
        {chunk.confidence != null && (
          <span style={{marginLeft:"auto", display:"flex", alignItems:"center", gap:5}}>
            <span style={{fontSize:9,color:C.textMuted}}>match</span>
            <span style={{fontSize:11, fontWeight:700,
              color:chunk.confidence>=80?"#2E7D32":chunk.confidence>=50?"#F57C00":"#E53935"}}>
              {chunk.confidence}%
            </span>
            <div style={{width:40,height:4,background:C.border,borderRadius:2,overflow:"hidden"}}>
              <div style={{width:`${chunk.confidence}%`,height:"100%",borderRadius:2,
                background:chunk.confidence>=80?"#2E7D32":chunk.confidence>=50?"#F57C00":"#E53935"}}/>
            </div>
          </span>
        )}
      </div>
      {/* Compressed context highlight */}
      {chunk.compressed && chunk.compressed !== chunk.text && (
        <div style={{...MONO, fontSize:11, color:C.accent, lineHeight:1.6,
          background:`${C.accent}08`, padding:"5px 8px", borderRadius:5,
          border:`1px solid ${C.accent}22`, marginBottom:4, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
          ✦ {chunk.compressed}
        </div>
      )}
      <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
        background:C.bg, padding:"8px 10px", borderRadius:6,
        border:`1px solid ${C.border}`, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
        &ldquo;{chunk.text}&rdquo;
      </div>
      {/* Entity + ATT&CK tags */}
      {Object.entries(chunk.entities||{}).some(([,s])=>Object.keys(s).length>0) && (
        <div style={{display:"flex", gap:4, flexWrap:"wrap", marginTop:6}}>
          {Object.entries(chunk.entities.stride||{}).map(([k])=>(
            <span key={k} style={{background:`${STRIDE_COLORS[k]||"#999"}18`,color:STRIDE_COLORS[k]||"#999",
              border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
              STRIDE·{STRIDE_LABELS[k]||k}
            </span>
          ))}
          {Object.entries(chunk.entities.attack||{}).slice(0,3).map(([k])=>(
            <span key={k} style={{background:"#E5393514",color:"#E53935",border:"1px solid #E5393530",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{k}</span>
          ))}
          {Object.entries(chunk.entities.compliance||{}).map(([k])=>(
            <span key={k} style={{background:"#0277BD18",color:"#0277BD",border:"1px solid #0277BD44",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{COMPLIANCE_LABELS[k]||k}</span>
          ))}
          {Object.entries(chunk.entities.security||{}).slice(0,2).map(([k])=>(
            <span key={k} style={{background:"#2E7D3218",color:"#2E7D32",border:"1px solid #2E7D3244",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{k}</span>
          ))}
        </div>
      )}
    </div>
  );

  if (noData && !hasUserDocs) {
    return (
      <div style={{padding:"48px 40px", maxWidth:720, textAlign:"center"}}>
        <div style={{fontSize:48, marginBottom:16, opacity:0.4}}>🧠</div>
        <div style={{fontSize:18, fontWeight:600, color:C.text, marginBottom:8}}>Intelligence Engine</div>
        <div style={{fontSize:13, color:C.textSub, lineHeight:1.7, maxWidth:480, margin:"0 auto"}}>
          Upload architecture documents, runbooks, threat models, or compliance docs.
          The intelligence engine will index them and let you query your architecture knowledge
          base with zero hallucination — every answer is a verbatim passage from your documents.
        </div>
        <div style={{marginTop:24, padding:"16px 20px", background:C.surface,
          border:`1px solid ${C.border}`, borderRadius:10, maxWidth:480, margin:"24px auto 0",
          textAlign:"left"}}>
          <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em"}}>Supported document types</div>
          {["Architecture diagrams (.txt, .md, .json, .yaml)","Threat model documents (STRIDE, MITRE templates)",
            "Compliance policies (HIPAA, FedRAMP, SOC 2, PCI)","Runbooks and incident response procedures",
            "Network topology descriptions","Security control inventories"].map((s,i)=>(
            <div key={i} style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
              <span style={{color:C.accent,fontSize:10}}>›</span>
              <span style={{fontSize:12,color:C.textSub}}>{s}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const SEV_COLOR = { Critical:"#B71C1C", High:"#E53935", Medium:"#F57C00", Low:"#43A047" };

  const ITAB_GROUPS = [
    { label: "Assistant", tabs: [
      {id:"assistant",        label:"AI Assistant",                 Icon: Bot,          accent:"#7C3AED"},
    ]},
    { label: "Analysis", tabs: [
      {id:"posture-controls", label:"Security Posture & Controls",  Icon: ShieldCheck},
      {id:"misconfigs",       label:"Misconfig Checks",             Icon: ShieldAlert},
    ]},
    { label: "Threat Intel", tabs: [
      {id:"threat-intel",     label:"Threat Intelligence",          Icon: Zap},
      {id:"crossdoc",         label:"Cross-Doc Links",              Icon: GitCompare},
    ]},
    { label: "Architecture", tabs: [
      {id:"scope",            label:"Scope Analysis",               Icon: ScanLine},
      {id:"resources",        label:"Resource Intel",               Icon: Layers},
      {id:"arclayers",        label:"Architecture Layers",          Icon: Building2,    accent:"#0277BD"},
    ]},
  ];
  const ITABS = ITAB_GROUPS.flatMap(g => g.tabs);

  const llmStatusDot = llmStatus === "ready" ? "#43A047"
    : llmStatus === "loading" ? "#F57C00"
    : llmStatus === "error" ? "#E53935" : "#555";

  // ── Shared markdown renderer (used by all tabs) ──────────────────────────
  const inlineFormat = (text, key = 0) => {
    const parts = [];
    const rx = /(\*\*[^*]+\*\*|`[^`]+`|\[DOC-\d+\])/g;
    let last = 0, m;
    while ((m = rx.exec(text)) !== null) {
      if (m.index > last) parts.push(<span key={`t${last}`}>{text.slice(last, m.index)}</span>);
      const tok = m[0];
      if (tok.startsWith('**'))
        parts.push(<strong key={`b${m.index}`} style={{ color: C.text, fontWeight: 700 }}>{tok.slice(2, -2)}</strong>);
      else if (tok.startsWith('`'))
        parts.push(<code key={`c${m.index}`} style={{ ...MONO, fontSize: 11, background: C.bg, padding: '1px 5px', borderRadius: 3, color: C.accent }}>{tok.slice(1, -1)}</code>);
      else
        parts.push(<span key={`d${m.index}`} style={{ color: C.accent, fontWeight: 600 }}>{tok}</span>);
      last = m.index + tok.length;
    }
    if (last < text.length) parts.push(<span key={`e${last}`}>{text.slice(last)}</span>);
    return parts.length ? parts : [text];
  };

  const renderMarkdown = (text) => {
    if (!text?.trim()) return null;
    const blocks = text.split(/\n\n+/);
    return blocks.map((block, bi) => {
      const trim = block.trim();
      // ATX headings
      const headM = trim.match(/^(#{1,3})\s+(.+)/);
      if (headM) {
        const sz = { 1: 15, 2: 13, 3: 12 }[headM[1].length] || 12;
        return <div key={bi} style={{ fontSize: sz, fontWeight: 700, color: C.text, marginTop: 10, marginBottom: 4 }}>{headM[2]}</div>;
      }
      // Bullet list block
      if (/^[-*•]\s/.test(trim)) {
        const items = trim.split('\n').filter(l => /^[-*•]\s/.test(l.trim())).map(l => l.trim().replace(/^[-*•]\s/, ''));
        return (
          <div key={bi} style={{ marginBottom: 6 }}>
            {items.map((item, ii) => (
              <div key={ii} style={{ display: 'flex', gap: 7, marginBottom: 3, alignItems: 'flex-start' }}>
                <span style={{ color: C.accent, flexShrink: 0, lineHeight: '18px' }}>•</span>
                <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
              </div>
            ))}
          </div>
        );
      }
      // Numbered list
      if (/^\d+\.\s/.test(trim)) {
        const items = trim.split('\n').filter(l => /^\d+\.\s/.test(l.trim())).map(l => l.trim().replace(/^\d+\.\s/, ''));
        return (
          <div key={bi} style={{ marginBottom: 6 }}>
            {items.map((item, ii) => (
              <div key={ii} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
                <span style={{ color: C.accent, flexShrink: 0, fontWeight: 700, lineHeight: '18px', minWidth: 16 }}>{ii + 1}.</span>
                <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
              </div>
            ))}
          </div>
        );
      }
      // Horizontal rule
      if (/^---+$/.test(trim)) return <div key={bi} style={{ borderTop: `1px solid ${C.border}`, margin: '8px 0' }} />;
      // Regular paragraph
      return <p key={bi} style={{ fontSize: 12, color: C.textSub, lineHeight: 1.7, margin: '4px 0' }}>{inlineFormat(trim, bi)}</p>;
    });
  };

  // ── Evidence UI helpers ──────────────────────────────────────────────────
  const ConfidenceBadge = ({ ev }) => {
    if (!ev) return null;
    const c = ev.confidence ?? 50;
    const color = c>=80?'#2E7D32':c>=55?'#F57C00':'#B71C1C';
    const label = ev.source==='hcl'?'HCL':ev.source==='doc'?'DOC':'INFER';
    const tip = `Method: ${ev.method}\nConfidence: ${c}%\n${ev.snippet?'Evidence: '+ev.snippet.slice(0,100):''}`;
    return (
      <span title={tip} style={{
        display:'inline-flex',alignItems:'center',gap:2,
        background:`${color}18`,border:`1px solid ${color}40`,
        borderRadius:4,padding:'1px 5px',fontSize:9,
        color,cursor:'help',fontWeight:700,flexShrink:0
      }}>
        {label} {c}%
      </span>
    );
  };

  const EvidenceDrawer = ({ ev, label='evidence' }) => {
    const [evOpen, setEvOpen] = useState(false);
    if (!ev?.snippet) return null;
    return (
      <div>
        <span onClick={()=>setEvOpen(o=>!o)}
          style={{cursor:'pointer',fontSize:9,color:C.textMuted,userSelect:'none'}}>
          {evOpen?'▲ hide':'▼'} {label}
        </span>
        {evOpen&&(
          <div style={{marginTop:5,padding:'5px 8px',background:C.bg,borderRadius:4,
            fontSize:10,fontFamily:'monospace',lineHeight:1.5,maxHeight:100,overflow:'auto',
            border:`1px solid ${C.border}`,whiteSpace:'pre-wrap',wordBreak:'break-word'}}>
            {ev.snippet}
            {ev.location&&<div style={{fontSize:9,color:C.textMuted,marginTop:2}}>↳ {ev.location}</div>}
          </div>
        )}
      </div>
    );
  };

  const getConf = (item) =>
    item?.evidence?.confidence ?? item?.confidence ??
    (item?.source==='doc'?55:item?.source==='scm'?65:50);

  return (
    <div style={{display:"flex", height:"calc(100vh - 58px)"}}>
      {/* Sub-nav — grouped */}
      <div style={{width:214, background:C.surface, borderRight:`1px solid ${C.border}`,
        padding:"10px 6px", display:"flex", flexDirection:"column", gap:0, flexShrink:0, overflowY:"auto"}}>
        {ITAB_GROUPS.map(group => (
          <div key={group.label} style={{marginBottom:8}}>
            <div style={{fontSize:9, color:C.textMuted, fontWeight:700, textTransform:"uppercase",
              letterSpacing:".12em", padding:"4px 10px 4px", opacity:0.7}}>{group.label}</div>
            {group.tabs.map(tab => {
              const isAssistant = tab.id === "assistant";
              const accentColor = tab.accent || C.accent;
              const isActive = iTab === tab.id;
              return (
                <button key={tab.id} onClick={()=>setITab(tab.id)} style={{
                  display:"flex", alignItems:"center", gap:8, width:"100%", textAlign:"left",
                  padding:"7px 10px",
                  background: isActive ? `${accentColor}20` : isAssistant ? `${accentColor}06` : "transparent",
                  border: isAssistant ? `1px solid ${accentColor}${isActive?"55":"22"}` : "none",
                  borderRadius:7, color: isActive ? accentColor : C.textSub,
                  fontSize:12, cursor:"pointer", ...SANS, fontWeight: isActive ? 600 : 400,
                  marginBottom:1,
                }}>
                  <tab.Icon size={13} />
                  <span style={{flex:1}}>{tab.label}</span>
                  {isAssistant && <span style={{width:6, height:6, borderRadius:"50%", background:llmStatusDot, flexShrink:0}} />}
                </button>
              );
            })}
          </div>
        ))}

        {/* Stats */}
        {summary && (
          <div style={{marginTop:"auto", padding:"12px 8px", borderTop:`1px solid ${C.border}`}}>
            {/* Posture grade badge */}
            {summary.posture && (
              <div style={{marginBottom:10, textAlign:"center"}}>
                <div style={{fontSize:9, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
                  letterSpacing:".08em", marginBottom:4}}>Security Posture</div>
                <div style={{display:"inline-flex", alignItems:"center", gap:6, background:`${summary.posture.gradeColor}18`,
                  border:`1px solid ${summary.posture.gradeColor}44`, borderRadius:8, padding:"4px 12px"}}>
                  <span style={{fontSize:22, fontWeight:800, color:summary.posture.gradeColor, lineHeight:1}}>
                    {summary.posture.grade}
                  </span>
                  <div style={{textAlign:"left"}}>
                    <div style={{fontSize:13, fontWeight:700, color:summary.posture.gradeColor}}>{summary.posture.score}/100</div>
                    <div style={{fontSize:9, color:C.textMuted}}>{summary.posture.maturity}</div>
                  </div>
                </div>
              </div>
            )}
            <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
              letterSpacing:".08em", marginBottom:8}}>Index Stats</div>
            {[
              {label:"Docs indexed",         val:summary.docCount},
              {label:"Text chunks",          val:summary.chunkCount},
              {label:"ATT&CK techniques",    val:summary.attackTechniqueCount||0, color:"#E53935"},
              {label:"Misconfigurations",    val:summary.misconfigCount||0,       color:"#F57C00"},
              {label:"Controls present",     val:summary.controlInventory?.present?.length||0, color:"#43A047"},
              {label:"Control gaps",         val:summary.controlInventory?.absent?.length||0,  color:"#E53935"},
              {label:"Doc threat findings",  val:summary.threatChunks?.length||0},
              {label:"Scope references",     val:summary.scopeChunks?.length||0},
            ].map(({label,val,color},i)=>(
              <div key={i} style={{display:"flex", justifyContent:"space-between", marginBottom:4, fontSize:11}}>
                <span style={{color:C.textMuted}}>{label}</span>
                <span style={{color:color||C.accent, fontWeight:600}}>{val}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Content */}
      <div style={{flex:1, overflowY:"auto", padding:"24px 28px"}}>

        {/* ── AI ASSISTANT TAB ── */}

        {/* Tab routing - each tab is a separate component */}
        {(() => {
          const ctx = {
            summary, parseResult, userDocs, llmStatus, onGenerateLLM, onHybridSearch,
            intelligence, computedIR, archLayerAnalysis,
            modelDetails, archAnalysis, archOverrides, selectedLlmModel,
            embedStatus, embedProgress,
            attackFilter, setAttackFilter, expandedCwe, setExpandedCwe,
            expandedFinding, setExpandedFinding, expandedControl, setExpandedControl,
            techPassages, setTechPassages, findingGuidance, setFindingGuidance,
            attackNarrative, setAttackNarrative, attackNarrLoading, setAttackNarrLoading,
            contradictionNarrative, setContradictionNarrative, contraNarrLoading, setContraNarrLoading,
            postureNarrative, setPostureNarrative, postureNarrLoading, setPostureNarrLoading,
            gapAnalysis, setGapAnalysis, gapAnalysisLoading, setGapAnalysisLoading,
            remediationPlan, setRemediationPlan, remediationLoading, setRemediationLoading,
            inferredScope, setInferredScope, inferredScopeLoading, setInferredScopeLoading,
            resourceSummaries, setResourceSummaries, hybridHits, setHybridHits,
            resourceSearch, setResourceSearch, resourceTypeFilter, setResourceTypeFilter,
            resourcePage, setResourcePage, controlSearch, setControlSearch,
            chatMessages, setChatMessages, chatInput, setChatInput,
            chatGenerating, setChatGenerating, chatBottomRef,
            isTraining, setIsTraining, ftProgress, setFtProgress, loraReady, setLoraReady,
            mcpUrl, setMcpUrl, mcpStatus, setMcpStatus, mcpError, setMcpError,
            showMcpHelp, setShowMcpHelp,
            llmProgress, llmStatusText, wllamaModelName, wllamaModelSize,
            onLoadModel, vectorStore,
            searchMode, setSearchMode, searchQuery, setSearchQuery,
            searchResults, setSearchResults, searchLoading, setSearchLoading,
            synthesisingQuery, setSynthesisingQuery, synthesisText, setSynthesisText,
            threatScenarios, setThreatScenarios, threatScenariosLoading, setThreatScenariosLoading,
            query, setQuery, results, setResults, queryLoading, setQueryLoading,
            noData, hasUserDocs,
          };
          const tabNode = iTab==="assistant" ? <AIAssistantTab {...ctx} />
            : iTab==="threat-intel"     ? <ThreatIntelTab {...ctx} />
            : iTab==="scope"            ? <ScopeTab {...ctx} />
            : iTab==="misconfigs"       ? <MisconfigsTab {...ctx} />
            : iTab==="posture-controls" ? <PostureControlsTab {...ctx} />
            : iTab==="crossdoc"         ? <CrossDocTab {...ctx} />
            : iTab==="resources"        ? <ResourceIntelTab {...ctx} />
            : iTab==="arclayers"        ? <ArchLayersTab {...ctx} />
            : null;
          return tabNode;
        })()}
      </div>
    </div>
  );
}

export default IntelligencePanel;
