import { useState, useMemo, useEffect, useRef } from "react";
import {
  Upload, Shield, Building2, AppWindow, Cloud, ClipboardList, Lock, SquareStack,
  ChevronLeft, ChevronRight, ChevronDown, ArrowRight, X, CheckCircle2, Sparkles,
  Loader2, RefreshCw, Zap,
} from '../../icons.jsx';
import { C, SANS } from '../../constants/styles.js';

// Recursively collect all File objects from a DataTransfer, including nested folders.
async function collectDroppedFiles(dataTransfer) {
  const files = [];
  const processEntry = (entry, prefix) => new Promise(resolve => {
    if (entry.isFile) {
      entry.file(file => {
        if (prefix) {
          try { Object.defineProperty(file, 'webkitRelativePath', { configurable: true, get: () => `${prefix}/${file.name}` }); } catch {}
        }
        files.push(file); resolve();
      }, () => resolve());
    } else if (entry.isDirectory) {
      const fp = prefix ? `${prefix}/${entry.name}` : entry.name;
      const reader = entry.createReader();
      const readAll = () => new Promise(r => {
        reader.readEntries(async entries => {
          if (!entries.length) { r(); return; }
          await Promise.all(entries.map(e => processEntry(e, fp)));
          readAll().then(r);
        }, () => r());
      });
      readAll().then(resolve);
    } else { resolve(); }
  });
  const items = Array.from(dataTransfer.items || []);
  if (items.length && typeof items[0].webkitGetAsEntry === 'function') {
    await Promise.all(items.map(item => {
      const entry = item.webkitGetAsEntry?.();
      if (entry) return processEntry(entry, '');
      const f = item.getAsFile?.(); if (f) files.push(f);
      return Promise.resolve();
    }));
  } else { Array.from(dataTransfer.files || []).forEach(f => files.push(f)); }
  return files;
}

// ─────────────────────────────────────────────────────────────────────────────
// DOCUMENTS PAGE — Step 2: categorized supporting document upload
// ─────────────────────────────────────────────────────────────────────────────
const DOC_CATEGORIES = [
  // Group A — Enterprise Context (expanded by default)
  { id:"enterprise-arch",   group:"A", label:"Enterprise Architecture",      Icon:Building2,      desc:"Platform type, AWS Org/OU/SCP docs, Sentinel policies, ADRs, SDLC processes",   tip:"e.g. AWS Organization policy JSON, Architecture Decision Records, SCPs" },
  { id:"app-details",       group:"A", label:"Application / Product Details", Icon:AppWindow,      desc:"HLDD, engineer docs, vendor documentation (AWS, Azure, GCP, 3rd party)",        tip:"e.g. High-Level Design Document, vendor integration guide" },
  // Group B — Security & Compliance (collapsed by default)
  { id:"security-controls", group:"B", label:"Enterprise Security Controls",  Icon:Shield,         desc:"Security control matrix, control baseline, known risks, security objectives",    tip:"e.g. Security Control Baseline.xlsx, risk register" },
  { id:"cspm",              group:"B", label:"CSPM / Cloud Configuration",    Icon:Cloud,          desc:"Wiz reports, cloud configuration rules, cloud posture findings",                  tip:"e.g. Wiz export CSV, AWS Config rules JSON" },
  { id:"compliance-guide",  group:"B", label:"Customer Compliance Guide",     Icon:ClipboardList,  desc:"CSP compliance guides cross-referenced with enterprise control matrix",           tip:"e.g. AWS HIPAA compliance guide PDF" },
  { id:"trust-cloud",       group:"B", label:"Trust on Cloud Documentation",  Icon:Lock,           desc:"Cloud trust documentation for your enterprise (if available)",                   tip:"e.g. enterprise cloud trust framework PDF" },
];

const INDUSTRY_FRAMEWORKS = [
  "NIST 800-53 r5","NIST CSF 2.0","CIS Controls v8","PCI DSS v4","HIPAA",
  "FedRAMP Moderate","FedRAMP High","GDPR","ISO 27001","CMMC Level 2","SOC 2 Type II","NIST SP 800-207 (Zero Trust)",
];

const THREAT_FRAMEWORKS = [
  "STRIDE","PASTA","VAST","LINDDUN","OCTAVE","RTMP",
  "OWASP Top 10","OWASP Top 10 Cloud","MITRE ATT&CK","DREAD","TRIKE",
];

function DocumentsPage({ model, modelDetails, userDocs, onSaveDetails, onAddDocs, onRemoveDoc, onContinue, onBack, ingestState, intelligence, intelligenceVersion, onPickDirectory }) {
  const [collapsed, setCollapsed] = useState({ "security-controls":true, "cspm":true, "compliance-guide":true, "trust-cloud":true });
  const [processing, setProcessing] = useState({});   // { filename: 'processing'|'done'|'error' }
  const [keyFeaturesText, setKeyFeaturesText] = useState(modelDetails.keyFeatures || "");
  const [kfGenerating, setKfGenerating] = useState(false);
  const kfRef = useRef(null);

  // Auto-resize key features textarea
  useEffect(() => {
    if (kfRef.current) {
      kfRef.current.style.height = "auto";
      kfRef.current.style.height = kfRef.current.scrollHeight + "px";
    }
  }, [keyFeaturesText]);

  // Auto-populate key features when intelligence rebuilds and enterprise docs are present
  useEffect(() => {
    if (!intelligence?._built) return;
    const enterpriseDocCount = userDocs.filter(d => d.docCategory === 'enterprise-arch' || d.docCategory === 'app-details').length;
    if (!enterpriseDocCount) return;
    // Only auto-overwrite if empty or previously auto-generated (starts with "- ")
    if (keyFeaturesText && !keyFeaturesText.startsWith("- ")) return;
    setKfGenerating(true);
    // Run async so UI updates before extraction
    setTimeout(() => {
      const bullets = intelligence.extractKeyFeatures();
      if (bullets.length) {
        const text = bullets.join("\n");
        setKeyFeaturesText(text);
        onSaveDetails({ ...modelDetails, keyFeatures: text });
      }
      setKfGenerating(false);
    }, 0);
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  const docsByCategory = useMemo(() => {
    const map = {};
    DOC_CATEGORIES.forEach(c => { map[c.id] = []; });
    map["general"] = [];
    userDocs.forEach(d => { const cat = d.docCategory || "general"; if (!map[cat]) map[cat] = []; map[cat].push(d); });
    return map;
  }, [userDocs]);

  const totalDocs = userDocs.length;

  const handleDrop = async (e, catId) => {
    e.preventDefault(); e.stopPropagation();
    const collected = await collectDroppedFiles(e.dataTransfer);
    if (collected.length) handleFiles(collected, catId);
  };

  const handleFiles = (fileList, catId) => {
    const filesArr = Array.from(fileList);
    const initial = {};
    filesArr.forEach(f => { initial[f.name] = "processing"; });
    setProcessing(prev => ({ ...prev, ...initial }));
    // Auto-expand the card so the user sees files as they arrive
    setCollapsed(prev => ({ ...prev, [catId]: false }));

    onAddDocs(fileList, catId, (name, status) => {
      setProcessing(prev => ({ ...prev, [name]: status }));
    });
  };

  const handleDirectoryPicker = async () => {
    try {
      const dirHandle = await window.showDirectoryPicker({ mode: 'read' });
      if (onPickDirectory) onPickDirectory(dirHandle);
    } catch (err) {
      if (err?.name !== 'AbortError') console.warn('[DocumentsPage] showDirectoryPicker failed:', err);
    }
  };

  const toggleFramework = (fw, isIndustry) => {
    const key = isIndustry ? "frameworks" : "threatFrameworks";
    const current = modelDetails[key] || [];
    const updated = current.includes(fw) ? current.filter(f => f !== fw) : [...current, fw];
    onSaveDetails({ ...modelDetails, [key]: updated });
  };

  const saveKeyFeatures = () => {
    onSaveDetails({ ...modelDetails, keyFeatures: keyFeaturesText });
  };

  const extColor = ext => ({ pdf:"#E53935", png:"#0288D1", jpg:"#0288D1", jpeg:"#0288D1",
    docx:"#1565C0", xlsx:"#2E7D32", csv:"#2E7D32", json:"#F57C00", yaml:"#7B1FA2",
    txt:"#546E7A", md:"#546E7A" })[ext] || C.textMuted;

  const extLabel = name => (name.split(".").pop() || "file").toUpperCase().slice(0,5);

  const fileSize = bytes => bytes < 1024 ? bytes+"B" : bytes < 1048576 ? Math.round(bytes/1024)+"KB" : (bytes/1048576).toFixed(1)+"MB";

  const renderFileList = (catDocs, catId) => {
    // Files already saved in userDocs
    const savedNames = new Set(catDocs.map(d => d.name));
    // Files being processed but not yet saved
    const pendingEntries = Object.entries(processing)
      .filter(([name, status]) => status === "processing" && !savedNames.has(name));
    const hasSomething = catDocs.length > 0 || pendingEntries.length > 0;
    return (
      <div style={{ marginTop: hasSomething ? 10 : 0, display:"flex", flexDirection:"column", gap:4, maxHeight:220, overflowY:"auto" }}>
        {/* Saved docs */}
        {catDocs.map((doc, i) => {
          const status = processing[doc.name];
          return (
            <div key={i} style={{
              display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
              background:C.bg, borderRadius:6, border:`1px solid ${C.border}`,
            }}>
              <span style={{
                fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3, flexShrink:0, minWidth:32, textAlign:"center",
                background:`${extColor(doc.ext)}20`, color:extColor(doc.ext), border:`1px solid ${extColor(doc.ext)}44`,
              }}>{extLabel(doc.name)}</span>
              <span style={{...SANS, fontSize:12, color:C.textSub, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                {doc.name}
              </span>
              <span style={{fontSize:10, color:C.textMuted, flexShrink:0}}>{fileSize(doc.size||0)}</span>
              {status === "processing" && (
                <span style={{fontSize:10, color:C.accent, flexShrink:0, display:"flex", alignItems:"center", gap:3}}>
                  <Loader2 size={11} style={{animation:"spin 1s linear infinite"}}/> extracting
                </span>
              )}
              {status === "done" && <span style={{fontSize:10, color:"#43A047", flexShrink:0}}>extracted</span>}
              {status === "error" && <span style={{fontSize:10, color:C.red, flexShrink:0}}>error</span>}
              <button onClick={() => onRemoveDoc(doc.path || doc.name)} style={{
                background:"transparent", border:"none", color:C.textMuted, cursor:"pointer",
                padding:"0 2px", borderRadius:3, display:"flex", alignItems:"center", flexShrink:0,
              }}
                onMouseEnter={e=>{ e.currentTarget.style.color=C.red; }}
                onMouseLeave={e=>{ e.currentTarget.style.color=C.textMuted; }}
              ><X size={12}/></button>
            </div>
          );
        })}
        {/* Pending rows — files being extracted but not yet in userDocs */}
        {pendingEntries.map(([name]) => (
          <div key={`pending-${name}`} style={{
            display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
            background:C.bg, borderRadius:6, border:`1px solid ${C.border}`, opacity:0.7,
          }}>
            <span style={{
              fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3, flexShrink:0, minWidth:32, textAlign:"center",
              background:`${C.border}`, color:C.textMuted, border:`1px solid ${C.border}`,
            }}>{extLabel(name)}</span>
            <span style={{...SANS, fontSize:12, color:C.textMuted, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
              {name}
            </span>
            <span style={{fontSize:10, color:C.accent, flexShrink:0, display:"flex", alignItems:"center", gap:3}}>
              <Loader2 size={11} style={{animation:"spin 1s linear infinite"}}/> extracting
            </span>
          </div>
        ))}
      </div>
    );
  };

  const renderUploadCard = (cat) => {
    const catDocs = docsByCategory[cat.id] || [];
    const isCollapsed = collapsed[cat.id];
    return (
      <div key={cat.id} style={{
        background:C.surface, border:`1px solid ${catDocs.length ? C.accent+"66" : C.border}`,
        borderRadius:12, overflow:"hidden", transition:"border-color .2s",
      }}>
        {/* Card header */}
        <div onClick={() => setCollapsed(s => ({ ...s, [cat.id]: !isCollapsed }))} style={{
          display:"flex", alignItems:"center", gap:12, padding:"14px 18px",
          cursor:"pointer", background: catDocs.length ? `${C.accent}08` : "transparent",
          userSelect:"none",
        }}>
          <cat.Icon size={18} style={{ color: catDocs.length ? C.accent : C.textMuted, flexShrink:0 }}/>
          <div style={{ flex:1 }}>
            <div style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>{cat.label}</div>
            <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{cat.desc}</div>
          </div>
          {catDocs.length > 0 && (
            <span style={{ fontSize:11, fontWeight:700, color:C.accent, background:`${C.accent}18`,
              border:`1px solid ${C.accent}44`, borderRadius:10, padding:"2px 8px", flexShrink:0 }}>
              {catDocs.length}
            </span>
          )}
          {isCollapsed ? <ChevronRight size={14} style={{color:C.textMuted, flexShrink:0}}/> : <ChevronDown size={14} style={{color:C.textMuted, flexShrink:0}}/>}
        </div>

        {/* Card body */}
        {!isCollapsed && (
          <div style={{ padding:"0 18px 16px", borderTop:`1px solid ${C.border}` }}>
            <div style={{fontSize:11, color:C.textMuted, marginBottom:10, marginTop:12, fontStyle:"italic"}}>{cat.tip}</div>
            {/* Drop zone */}
            <div
              onDrop={e => handleDrop(e, cat.id)}
              onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = C.accent; }}
              onDragLeave={e => { e.currentTarget.style.borderColor = C.border2; }}
              style={{
                border:`2px dashed ${C.border2}`, borderRadius:8, padding:"20px 16px",
                textAlign:"center", cursor:"pointer", transition:"border-color .15s",
              }}
              onClick={() => {
                const inp = document.createElement("input");
                inp.type = "file"; inp.multiple = true;
                inp.onchange = e => { if (e.target.files?.length) handleFiles(e.target.files, cat.id); };
                inp.click();
              }}
            >
              <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:8, color:C.textMuted }}>
                <Upload size={16}/>
                <span style={{...SANS, fontSize:12}}>Drop files here or <span style={{color:C.accent, fontWeight:600}}>click to browse</span></span>
              </div>
              <div style={{fontSize:11, color:C.textMuted, marginTop:4}}>PDF · DOCX · XLSX · CSV · JSON · YAML · TXT · Images — up to 512MB each</div>
            </div>
            {renderFileList(catDocs, cat.id)}
          </div>
        )}
      </div>
    );
  };

  const renderChips = (items, selected, onToggle, accentColor = C.accent) => (
    <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
      {items.map(item => {
        const active = selected.includes(item);
        return (
          <button key={item} onClick={() => onToggle(item)} style={{
            ...SANS, fontSize:11, fontWeight: active ? 700 : 500,
            padding:"5px 12px", borderRadius:20, cursor:"pointer",
            background: active ? `${accentColor}22` : C.surface2,
            border: `1px solid ${active ? accentColor : C.border2}`,
            color: active ? accentColor : C.textSub,
            transition:"all .15s",
          }}>
            {item}
          </button>
        );
      })}
    </div>
  );

  return (
    <div style={{ minHeight:"100vh", background:C.bg, display:"flex", flexDirection:"column" }}>
      {/* ── Header ── */}
      <div style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 28px", height:58, display:"flex", alignItems:"center", gap:16, flexShrink:0, position:"sticky", top:0, zIndex:100,
      }}>
        <button onClick={onBack} style={{
          display:"flex", alignItems:"center", gap:5, background:"transparent",
          border:"none", color:C.textMuted, cursor:"pointer", fontSize:12, ...SANS, padding:"4px 8px", borderRadius:6,
        }}
          onMouseEnter={e=>e.currentTarget.style.color=C.text}
          onMouseLeave={e=>e.currentTarget.style.color=C.textMuted}
        >
          <ChevronLeft size={14}/> Models
        </button>

        {/* Brand */}
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:28, height:28, borderRadius:6, background:`linear-gradient(135deg,${C.accent},${C.accent}88)`,
            display:"flex", alignItems:"center", justifyContent:"center" }}>
            <Shield size={14} color="#fff"/>
          </div>
          <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>{model?.name || "Threat Model"}</span>
        </div>

        {/* Progress steps */}
        <div style={{ flex:1, display:"flex", justifyContent:"center" }}>
          {[{n:1,label:"Create Model"},{n:2,label:"Documents"},{n:3,label:"Workspace"}].map((step,i) => (
            <div key={step.n} style={{ display:"flex", alignItems:"center" }}>
              {i > 0 && <div style={{ width:40, height:2, background: step.n <= 2 ? C.accent : C.border, margin:"0 4px" }}/>}
              <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                <div style={{
                  width:22, height:22, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center",
                  background: step.n < 2 ? C.accent : step.n === 2 ? C.accent : C.surface2,
                  border: `2px solid ${step.n <= 2 ? C.accent : C.border}`,
                  fontSize:11, fontWeight:700,
                  color: step.n <= 2 ? "#fff" : C.textMuted,
                }}>
                  {step.n < 2 ? <CheckCircle2 size={12}/> : step.n}
                </div>
                <span style={{...SANS, fontSize:11, fontWeight: step.n === 2 ? 700 : 400,
                  color: step.n === 2 ? C.text : step.n < 2 ? C.accent : C.textMuted}}>
                  {step.label}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* FSAPI folder picker — Chrome/Edge only */}
        {'showDirectoryPicker' in window && (
          <button onClick={handleDirectoryPicker} style={{
            display:"flex", alignItems:"center", gap:6, background:`${C.blue}18`,
            border:`1px solid ${C.blue}55`, borderRadius:8, padding:"8px 14px", color:C.blue,
            fontSize:12, cursor:"pointer", ...SANS, flexShrink:0,
          }}>
            🗂 Open Folder (1GB+)
          </button>
        )}

        {/* Continue */}
        <button onClick={onContinue} style={{
          display:"flex", alignItems:"center", gap:7, background:`linear-gradient(135deg,${C.accent},${C.accent}cc)`,
          border:"none", borderRadius:8, padding:"8px 18px", color:"#fff",
          fontSize:13, fontWeight:700, cursor:"pointer", ...SANS,
        }}>
          Continue <ArrowRight size={14}/>
          {totalDocs > 0 && (
            <span style={{ background:"rgba(255,255,255,.2)", borderRadius:10, padding:"1px 7px", fontSize:11 }}>
              {totalDocs}
            </span>
          )}
        </button>
      </div>

      {/* ── Ingestion Progress Bar ── */}
      {ingestState && (
        <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"8px 24px" }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:4 }}>
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

      {/* ── Body ── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>
        {/* ── Left Sidebar ── */}
        <div style={{
          width:200, flexShrink:0, background:C.surface, borderRight:`1px solid ${C.border}`,
          padding:"20px 12px", overflowY:"auto", position:"sticky", top:58, height:"calc(100vh - 58px)",
        }}>
          <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase", letterSpacing:".12em", marginBottom:12, paddingLeft:4}}>
            Sections
          </div>
          {[
            { id:"group-a",   label:"Enterprise Context",   items:["enterprise-arch","app-details"] },
            { id:"key-feat",  label:"Key Features",         items:[] },
            { id:"group-b",   label:"Security & Compliance",items:["security-controls","cspm","compliance-guide","trust-cloud"] },
            { id:"frameworks",label:"Analysis Frameworks",  items:[] },
          ].map(section => {
            const count = section.items.reduce((s,id) => s + (docsByCategory[id]?.length||0), 0);
            const hasExtra = section.id === "frameworks"
              ? ((modelDetails.frameworks?.length||0) + (modelDetails.threatFrameworks?.length||0)) > 0
              : false;
            return (
              <a key={section.id} href={`#${section.id}`} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"8px 10px", borderRadius:6, marginBottom:2,
                color: count || hasExtra ? C.accent : C.textSub, fontSize:12, textDecoration:"none", ...SANS,
                background: count || hasExtra ? `${C.accent}10` : "transparent",
              }}>
                <span style={{fontWeight: count || hasExtra ? 600 : 400}}>{section.label}</span>
                {(count > 0) && (
                  <span style={{ fontSize:10, fontWeight:700, background:`${C.accent}22`, color:C.accent,
                    border:`1px solid ${C.accent}44`, borderRadius:9, padding:"1px 6px" }}>
                    {count}
                  </span>
                )}
              </a>
            );
          })}

          <div style={{ marginTop:20, paddingTop:16, borderTop:`1px solid ${C.border}` }}>
            <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase", letterSpacing:".12em", marginBottom:8, paddingLeft:4}}>Summary</div>
            <div style={{fontSize:12, color:C.textSub, padding:"0 4px", ...SANS}}>
              <div style={{marginBottom:4}}><span style={{fontWeight:700, color:C.accent}}>{totalDocs}</span> docs uploaded</div>
              <div style={{marginBottom:4}}><span style={{fontWeight:700, color:"#7B1FA2"}}>{modelDetails.frameworks?.length||0}</span> industry frameworks</div>
              <div><span style={{fontWeight:700, color:"#E65100"}}>{modelDetails.threatFrameworks?.length||0}</span> threat frameworks</div>
            </div>
          </div>
        </div>

        {/* ── Main Content ── */}
        <div style={{ flex:1, overflowY:"auto", padding:"28px 32px", maxWidth:860 }}>

          {/* GROUP A */}
          <div id="group-a" style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <Building2 size={18} style={{ color:C.accent }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Enterprise Context</div>
                <div style={{fontSize:12, color:C.textMuted}}>Architecture and product documentation that defines scope and platform context</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {DOC_CATEGORIES.filter(c => c.group === "A").map(renderUploadCard)}
            </div>
          </div>

          {/* KEY FEATURES */}
          <div id="key-feat" style={{ marginBottom:32 }}>
            <div style={{
              background:C.surface, border:`1px solid ${keyFeaturesText ? C.accent+"66" : C.border}`,
              borderRadius:12, padding:"18px 20px",
            }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
                <Sparkles size={18} style={{ color: keyFeaturesText ? C.accent : C.textMuted }}/>
                <div style={{ flex:1 }}>
                  <div style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Key Features</div>
                  <div style={{fontSize:11, color:C.textMuted}}>Auto-extracted from Enterprise Context docs — edit freely</div>
                </div>
                {kfGenerating && (
                  <span style={{ display:"flex", alignItems:"center", gap:5, fontSize:11, color:C.accent }}>
                    <Loader2 size={12} style={{ animation:"spin 1s linear infinite" }}/> Extracting...
                  </span>
                )}
                {intelligence?._built && !kfGenerating && (
                  <button onClick={() => {
                    setKfGenerating(true);
                    setTimeout(() => {
                      const bullets = intelligence.extractKeyFeatures();
                      if (bullets.length) {
                        const text = bullets.join("\n");
                        setKeyFeaturesText(text);
                        onSaveDetails({ ...modelDetails, keyFeatures: text });
                      }
                      setKfGenerating(false);
                    }, 0);
                  }} style={{
                    display:"flex", alignItems:"center", gap:5, fontSize:11, fontWeight:600,
                    background:`${C.accent}15`, border:`1px solid ${C.accent}44`, borderRadius:6,
                    padding:"4px 10px", color:C.accent, cursor:"pointer", ...SANS,
                  }}>
                    <RefreshCw size={11}/> Regenerate
                  </button>
                )}
              </div>
              <textarea
                ref={kfRef}
                value={keyFeaturesText}
                onChange={e => setKeyFeaturesText(e.target.value)}
                onBlur={saveKeyFeatures}
                placeholder="Upload Enterprise Context docs above — key features will be auto-extracted. Or type manually here."
                style={{
                  width:"100%", boxSizing:"border-box", minHeight:90, resize:"none", overflow:"hidden",
                  background:C.bg, border:`1px solid ${C.border}`, borderRadius:8,
                  color:C.text, fontSize:12, padding:"10px 12px", lineHeight:1.6,
                  outline:"none", ...SANS, transition:"border-color .15s",
                }}
                onFocus={e=>e.target.style.borderColor=C.accent}
                onBlurCapture={e=>e.target.style.borderColor=C.border}
              />
            </div>
          </div>

          {/* GROUP B */}
          <div id="group-b" style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <Shield size={18} style={{ color:"#E53935" }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Security & Compliance</div>
                <div style={{fontSize:12, color:C.textMuted}}>Security controls, CSPM posture findings, compliance guides, and trust documentation</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {DOC_CATEGORIES.filter(c => c.group === "B").map(renderUploadCard)}
            </div>
          </div>

          {/* GROUP C — Frameworks */}
          <div id="frameworks" style={{ marginBottom:40 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <SquareStack size={18} style={{ color:"#7B1FA2" }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Analysis Frameworks</div>
                <div style={{fontSize:12, color:C.textMuted}}>Select the frameworks in scope — they will inform intelligence queries and threat model generation</div>
              </div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
              {/* Industry */}
              <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:12, padding:"18px 20px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                  <ClipboardList size={16} style={{ color:"#7B1FA2" }}/>
                  <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Industry & Compliance Frameworks</span>
                  {(modelDetails.frameworks?.length > 0) && (
                    <span style={{ fontSize:11, color:"#7B1FA2", background:"#7B1FA210", border:"1px solid #7B1FA244", borderRadius:9, padding:"1px 7px", marginLeft:"auto" }}>
                      {modelDetails.frameworks.length} selected
                    </span>
                  )}
                </div>
                {renderChips(INDUSTRY_FRAMEWORKS, modelDetails.frameworks || [], fw => toggleFramework(fw, true), "#7B1FA2")}
              </div>

              {/* Threat */}
              <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:12, padding:"18px 20px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                  <Zap size={16} style={{ color:"#E65100" }}/>
                  <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Threat Modeling Frameworks</span>
                  {(modelDetails.threatFrameworks?.length > 0) && (
                    <span style={{ fontSize:11, color:"#E65100", background:"#E6510010", border:"1px solid #E6510044", borderRadius:9, padding:"1px 7px", marginLeft:"auto" }}>
                      {modelDetails.threatFrameworks.length} selected
                    </span>
                  )}
                </div>
                {renderChips(THREAT_FRAMEWORKS, modelDetails.threatFrameworks || [], fw => toggleFramework(fw, false), "#E65100")}
              </div>
            </div>
          </div>

          {/* Spacer */}
          <div style={{height:48}}/>
        </div>
      </div>

      {/* Spinner keyframe */}
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

export default DocumentsPage;
