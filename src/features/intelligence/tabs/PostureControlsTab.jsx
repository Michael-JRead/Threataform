// src/features/intelligence/tabs/PostureControlsTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown, ConfidenceBadge, EvidenceDrawer } from '../panelHelpers.jsx';
import { CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS } from '../../../data/control-detection.js';
import { ShieldCheck, Shield, ChevronDown, ChevronRight, Search, CheckCircle2, AlertCircle, Loader2, Target } from '../../../icons.jsx';

export const PostureControlsTab = React.memo(function PostureControlsTab(ctx) {
  const { summary, parseResult, userDocs, llmStatus, onGenerateLLM, onHybridSearch,
    intelligence, computedIR, archLayerAnalysis,
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
    onLoadModel, onHybridSearch: _onHybridSearch, vectorStore,
    searchMode, setSearchMode, searchQuery, setSearchQuery,
    searchResults, setSearchResults, searchLoading, setSearchLoading,
    synthesisingQuery, setSynthesisingQuery, synthesisText, setSynthesisText,
    threatScenarios, setThreatScenarios, threatScenariosLoading, setThreatScenariosLoading,
    query, setQuery, results, setResults, queryLoading, setQueryLoading,
    noData, hasUserDocs,
  } = ctx;

  return (

<div style={{maxWidth:860}}>
  {/* ── Section: Security Posture ── */}
  <>
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>Security Posture</div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    Weighted composite score across NIST CSF 2.0 (40%), Defense-in-Depth (35%), and Zero Trust (25%).
    Grades reflect actual Terraform resource configuration — zero hallucination.
  </div>
  {!summary?.posture ? (
    <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to generate posture assessment.</div>
  ) : (()=>{
    const p = summary.posture;
    const GC = p.gradeColor;
    // Derive topRisks from did/zt if not already present in posture
    if (!p.topRisks) {
      const tr = [];
      Object.entries(p.did?.layers||{}).forEach(([layer,data]) => {
        if ((data.score??100) < 50 && data.missing?.length)
          tr.push(`${layer.charAt(0).toUpperCase()+layer.slice(1)} layer: missing ${data.missing.slice(0,2).join(', ')}`);
      });
      Object.entries(p.zt?.pillars||{}).forEach(([pillar,data]) => {
        if ((data.score??100) < 40 && data.absent?.length) {
          const names = data.absent.slice(0,2).map(a => typeof a==='string'?a:(a?.name||a?.id||JSON.stringify(a)));
          tr.push(`Zero Trust ${pillar}: ${names.join(', ')} not detected`);
        }
      });
      if ((p.nist?.score??100) < 50) tr.push(`NIST CSF at ${Math.round(p.nist?.score||0)}% — review Identify/Protect functions`);
      p.topRisks = tr.slice(0,6);
    }
    return (
      <div>
        {/* Grade hero */}
        <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
          padding:"24px 28px", marginBottom:20, display:"flex", alignItems:"center", gap:28}}>
          <div style={{textAlign:"center"}}>
            <div style={{fontSize:64, fontWeight:900, color:GC, lineHeight:1}}>{p.grade}</div>
            <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>Grade</div>
          </div>
          <div style={{flex:1}}>
            <div style={{display:"flex", alignItems:"baseline", gap:8, marginBottom:6}}>
              <span style={{fontSize:32, fontWeight:700, color:GC}}>{p.score}</span>
              <span style={{fontSize:14, color:C.textMuted}}>/100</span>
              <span style={{fontSize:12, color:C.textMuted, marginLeft:4}}>· {p.maturity}</span>
            </div>
            {(()=>{
              const docBoost = (summary?.controlInventory?.present||[]).filter(c=>c.source==='doc').length;
              return docBoost > 0 ? (
                <div style={{ fontSize:10, color:C.textMuted, marginTop:3, marginBottom:8 }}>+{docBoost} controls detected in uploaded documents</div>
              ) : null;
            })()}
            {/* Score bar */}
            <div style={{height:8, background:C.border, borderRadius:4, marginBottom:16, overflow:"hidden"}}>
              <div style={{height:"100%", width:`${p.score}%`, background:`linear-gradient(90deg,${GC},${GC}88)`,
                borderRadius:4, transition:"width .6s"}} />
            </div>
            <div style={{display:"flex", gap:16, flexWrap:"wrap"}}>
              {[
                {label:"NIST CSF 2.0",      val:`${p.nist?.score??'—'}%`,  color:"#0277BD"},
                {label:"Defense-in-Depth",  val:`${p.did?.overallScore??'—'}%`,color:"#6A1B9A"},
                {label:"Zero Trust",        val:`${p.zt?.overallScore??'—'}%`, color:"#00695C"},
              ].map(({label,val,color},i)=>(
                <div key={i} style={{background:C.bg, border:`1px solid ${C.border}`,
                  borderRadius:8, padding:"8px 14px", minWidth:110}}>
                  <div style={{fontSize:10, color:C.textMuted, marginBottom:2}}>{label}</div>
                  <div style={{fontSize:18, fontWeight:700, color}}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Posture Trend Sparkline */}
        {(()=>{
          let trend = [];
          try { trend = JSON.parse(localStorage.getItem('tf-posture-trend') || '[]'); } catch {}
          if (trend.length < 2) return null;
          const scores = trend.map(t => t.score);
          const minS = Math.min(...scores);
          const maxS = Math.max(...scores);
          const range = Math.max(maxS - minS, 10); // at least 10-pt visual range
          const W = 220, H = 38, PAD = 4;
          const iW = W - PAD*2, iH = H - PAD*2;
          const pts = scores.map((s, i) => {
            const x = PAD + (i / (scores.length - 1)) * iW;
            const y = PAD + iH - ((s - minS) / range) * iH;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
          }).join(' ');
          const last = trend[trend.length - 1];
          const first = trend[0];
          const delta = last.score - first.score;
          const deltaColor = delta >= 0 ? '#43A047' : '#E53935';
          return (
            <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, padding:"10px 14px", marginBottom:14, display:"flex", alignItems:"center", gap:16}}>
              <div>
                <div style={{fontSize:10, color:C.textMuted, marginBottom:4}}>Posture Trend ({trend.length} scans)</div>
                <svg width={W} height={H} style={{display:"block"}}>
                  <polyline points={pts} fill="none" stroke={`${deltaColor}88`} strokeWidth="1.5" />
                  <polyline points={pts} fill="none" stroke={deltaColor} strokeWidth="1.5" strokeDasharray="none" />
                  {/* Last point dot */}
                  {(()=>{const [lx,ly]=pts.split(' ').pop().split(','); return <circle cx={lx} cy={ly} r="3" fill={deltaColor} />;})()}
                </svg>
              </div>
              <div>
                <div style={{fontSize:22, fontWeight:700, color:deltaColor}}>{delta >= 0 ? '+' : ''}{delta}</div>
                <div style={{fontSize:10, color:C.textMuted}}>pts since first scan</div>
                <div style={{fontSize:10, color:C.textMuted}}>{first.date} → {last.date}</div>
              </div>
            </div>
          );
        })()}
        {/* Scoring methodology footnote */}
        <div style={{fontSize:10,color:C.textMuted,background:C.surface,border:`1px solid ${C.border}`,
          borderRadius:8,padding:"8px 12px",marginBottom:16,lineHeight:1.7}}>
          <strong style={{color:C.textSub}}>Scoring methodology:</strong>{' '}
          NIST CSF 40% · Defense-in-Depth 35% · Zero Trust 25%{' · '}
          HCL-verified controls: full weight · Doc-referenced controls: partial weight ·
          Partial controls (configured but incomplete): 50% weight ·
          Variable-referenced attributes excluded from checks (shown as unresolved).
        </div>

        {/* Priority Remediation Actions */}
        {p?.topRisks?.length > 0 && (
          <div style={{ background:'#E5393510', border:'1px solid #E5393540', borderRadius:10, padding:'14px 18px', marginBottom:16 }}>
            <div style={{ fontSize:12, fontWeight:700, color:'#E53935', marginBottom:8 }}>Priority Remediation Actions ({p.topRisks.length})</div>
            {p.topRisks.map((risk,i) => (
              <div key={i} style={{ display:'flex', gap:10, alignItems:'flex-start', marginBottom:6 }}>
                <span style={{ background:'#E53935', color:'#fff', borderRadius:'50%', width:18, height:18, display:'flex', alignItems:'center', justifyContent:'center', fontSize:10, fontWeight:700, flexShrink:0 }}>{i+1}</span>
                <span style={{ fontSize:12, color:C.text, lineHeight:1.6 }}>{risk}</span>
              </div>
            ))}
          </div>
        )}

        {/* LLM posture explanation */}
        {llmStatus === 'ready' && (
          <div style={{ marginBottom:16 }}>
            {postureNarrative ? (
              <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'12px 14px' }}>
                <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:6 }}>AI POSTURE ANALYSIS</div>
                <div style={{ fontSize:12 }}>{renderMarkdown(postureNarrative)}</div>
                <button onClick={()=>setPostureNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:6 }}>Clear</button>
              </div>
            ) : (
              <button
                disabled={postureNarrLoading}
                onClick={async () => {
                  setPostureNarrLoading(true);
                  setPostureNarrative('');
                  const ctx = `Score: ${p?.score}/100, grade ${p?.grade}, maturity: ${p?.maturity}. NIST: ${p?.nist?.score}%, DiD: ${p?.did?.overallScore}%, ZT: ${p?.zt?.overallScore}%. Top risks: ${(p?.topRisks||[]).join('; ')}. Missing controls: ${(summary?.controlInventory?.absent||[]).slice(0,8).map(c=>c.name).join(', ')}.`;
                  await onGenerateLLM(
                    [{ role:'system', content:'You are a cloud security advisor. Explain this AWS security posture score in 3-4 sentences, then suggest the top 3 concrete improvements. Reference specific AWS services and controls.' },
                     { role:'user', content:ctx }],
                    tok => setPostureNarrative(prev => prev + tok)
                  );
                  setPostureNarrLoading(false);
                }}
                style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'6px 14px', fontSize:11, cursor:'pointer', fontWeight:600 }}
              >
                {postureNarrLoading ? 'Analyzing…' : '✦ Explain this score'}
              </button>
            )}
          </div>
        )}

        {/* Defense-in-Depth layers */}
        {p.did?.layers && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
            padding:"18px 20px", marginBottom:16}}>
            <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
              Defense-in-Depth Coverage
            </div>
            {Object.entries(p.did.layers).map(([name,layer])=>(
              <div key={name} style={{marginBottom:10}}>
                <div style={{display:"flex", justifyContent:"space-between", marginBottom:3}}>
                  <div style={{display:"flex", alignItems:"center", gap:6}}>
                    {(()=>{const dl=Object.values(DID_LAYERS).find(l=>l.name===name); return dl ? <dl.Icon size={14} style={{color:dl.color}}/> : <Shield size={14}/>;})()}
                    <span style={{fontSize:12, fontWeight:600, color:C.text}}>{name}</span>
                  </div>
                  <span style={{fontSize:11, fontWeight:600, color:layer.score>=60?"#43A047":"#E53935"}}>
                    {layer.score}%
                  </span>
                </div>
                <div style={{height:5, background:C.border, borderRadius:3, overflow:"hidden"}}>
                  <div style={{height:"100%", width:`${layer.score}%`,
                    background:layer.score>=60?"#43A047":layer.score>=30?"#F57C00":"#E53935",
                    borderRadius:3}} />
                </div>
                {layer.absent?.length>0 && (
                  <div style={{fontSize:10, color:C.textMuted, marginTop:3}}>
                    Missing: {layer.absent.map(c=>c.name).join(", ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Zero Trust pillars */}
        {p.zt?.pillars && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
            padding:"18px 20px", marginBottom:16}}>
            <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
              Zero Trust Pillar Assessment (NIST SP 800-207)
            </div>
            <div style={{display:"flex", flexWrap:"wrap", gap:10}}>
              {Object.entries(p.zt.pillars).map(([name,pillar])=>{
                const ztp = ZT_PILLARS[name];
                const ZtpIcon = ztp?.Icon || Target;
                return (
                  <div key={name} style={{flex:"1 1 140px", background:C.bg,
                    border:`1px solid ${C.border}`, borderRadius:8, padding:"12px 14px"}}>
                    <div style={{marginBottom:6}}><ZtpIcon size={18} style={{color:ztp?.color||C.accent}}/></div>
                    <div style={{fontSize:11, fontWeight:700, color:C.text, marginBottom:6}}>{name}</div>
                    <div style={{height:4, background:C.border, borderRadius:2, marginBottom:6, overflow:"hidden"}}>
                      <div style={{height:"100%", width:`${pillar.score}%`,
                        background:pillar.score>=60?"#43A047":pillar.score>=30?"#F57C00":"#E53935",
                        borderRadius:2}} />
                    </div>
                    <div style={{fontSize:13, fontWeight:700,
                      color:pillar.score>=60?"#43A047":pillar.score>=30?"#F57C00":"#E53935"}}>
                      {pillar.score}%
                    </div>
                    {pillar.controls?.filter(c=>c.present).slice(0,2).map((c,j)=>(
                      <div key={j} style={{fontSize:9, color:"#43A047", marginTop:2}}>✓ {c.name}</div>
                    ))}
                    {pillar.controls?.filter(c=>!c.present).slice(0,2).map((c,j)=>(
                      <div key={j} style={{fontSize:9, color:"#E53935", marginTop:2}}>✗ {c.name}</div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* NIST CSF breakdown */}
        {p.nist?.byFn && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
            padding:"18px 20px"}}>
            <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
              NIST CSF 2.0 by Function
            </div>
            <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
              {Object.entries(p.nist.byFn).map(([fn,data])=>(
                <div key={fn} style={{flex:"1 1 90px", background:C.bg,
                  border:`1px solid ${C.border}`, borderRadius:8, padding:"10px 12px", textAlign:"center"}}>
                  <div style={{fontSize:10, fontWeight:700, color:C.textMuted, marginBottom:4}}>{fn}</div>
                  <div style={{fontSize:18, fontWeight:700,
                    color:data.pct>=70?"#43A047":data.pct>=40?"#F57C00":"#E53935"}}>
                    {data.pct}%
                  </div>
                  <div style={{fontSize:9, color:C.textMuted}}>{data.pass}/{data.total}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  })()}
  </>

  {/* ── Divider ── */}
  <div style={{borderTop:`1px solid ${C.border}`, margin:"32px 0"}} />

  {/* ── Section: Control Inventory ── */}
  <>
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>Control Inventory</div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    Security controls detected (or missing) from your Terraform configuration and uploaded security documents,
    organized by defense-in-depth layer. <strong>&lt;/&gt;</strong> = detected in Terraform · <strong>📄</strong> = found in uploaded docs.
  </div>
  {/* Docs scanned for control evidence */}
  {(() => {
    const scannedDocs = userDocs.filter(d => ['security-controls','cspm','compliance-guide','trust-cloud'].includes(d.category || d.docCategory));
    return scannedDocs.length > 0 ? (
      <div style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 12px", background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, marginBottom:12, fontSize:12 }}>
        <span style={{ color:C.accent }}>📄</span>
        <span style={{ color:C.textSub }}>Scanned {scannedDocs.length} security document{scannedDocs.length>1?'s':''} for control evidence:</span>
        <span style={{ color:C.text, fontWeight:500 }}>{scannedDocs.map(d=>d.name).join(', ')}</span>
      </div>
    ) : null;
  })()}
  {!summary?.controlInventory ? (
    <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to generate control inventory.</div>
  ) : (()=>{
    const ci = summary.controlInventory;
    const byLayer = {};
    const presentIds  = new Set((ci.present||[]).map(c=>c.id));
    const partialIds  = new Set((ci.partial||[]).map(c=>c.id));
    [...(ci.present||[]), ...(ci.partial||[]), ...(ci.absent||[])].forEach(c=>{
      const lk = c.layer || 'monitoring';
      if(!byLayer[lk]) byLayer[lk]={present:[],partial:[],absent:[]};
      if(presentIds.has(c.id))      byLayer[lk].present.push(c);
      else if(partialIds.has(c.id)) byLayer[lk].partial.push(c);
      else                          byLayer[lk].absent.push(c);
    });
    const presentCount = ci.present?.length||0;
    const partialCount = ci.partial?.length||0;
    const absentCount  = ci.absent?.length||0;
    const totalCount   = presentCount + partialCount + absentCount;
    // Weighted: present=1.0, partial=0.5
    const coveragePct  = totalCount ? Math.round(((presentCount + partialCount * 0.5)/totalCount)*100) : 0;
    return (
      <div>
        {/* Coverage bar */}
        <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
          padding:"16px 20px", marginBottom:12, display:"flex", alignItems:"center", gap:20}}>
          <div style={{flex:1}}>
            <div style={{display:"flex", justifyContent:"space-between", marginBottom:6}}>
              <span style={{fontSize:12, fontWeight:600, color:C.text}}>Overall Control Coverage</span>
              <span style={{fontSize:12, fontWeight:700, color:coveragePct>=70?"#43A047":coveragePct>=40?"#F57C00":"#E53935"}}>
                {presentCount} present · {partialCount} partial · {absentCount} absent ({coveragePct}%)
              </span>
            </div>
            <div style={{height:8, background:C.border, borderRadius:4, overflow:"hidden"}}>
              <div style={{height:"100%", width:`${coveragePct}%`,
                background:coveragePct>=70?"#43A047":coveragePct>=40?"#F57C00":"#E53935",
                borderRadius:4}} />
            </div>
          </div>
        </div>

        {/* LLM gap prioritization */}
        {llmStatus === 'ready' && (
          <div style={{ padding:'8px 0', marginBottom:12 }}>
            {gapAnalysis ? (
              <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', margin:'4px 0 8px' }}>
                <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI GAP PRIORITIZATION</div>
                <div style={{ fontSize:12 }}>{renderMarkdown(gapAnalysis)}</div>
                <button onClick={()=>setGapAnalysis('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
              </div>
            ) : (
              <button
                disabled={gapAnalysisLoading}
                onClick={async () => {
                  setGapAnalysisLoading(true);
                  setGapAnalysis('');
                  const absentNames = (summary?.controlInventory?.absent||[]).map(c=>c.name).slice(0,12);
                  const resources = parseResult?.resources||[];
                  const resTypes = [...new Set(resources.map(r=>r.type))].slice(0,10);
                  await onGenerateLLM(
                    [{ role:'system', content:'You are a cloud security engineer. Be concise and actionable.' },
                     { role:'user', content:`AWS infrastructure resource types: ${resTypes.join(', ')}. Missing security controls: ${absentNames.join(', ')}. Rank the top 5 missing controls by remediation priority. For each: why it is critical, and which Terraform resource type to add. Format as a numbered list.` }],
                    tok => setGapAnalysis(prev => prev + tok)
                  );
                  setGapAnalysisLoading(false);
                }}
                style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
              >
                {gapAnalysisLoading ? 'Analyzing gaps…' : '✦ Prioritize gaps with AI'}
              </button>
            )}
          </div>
        )}

        {/* Control search/filter */}
        <div style={{ marginBottom:16 }}>
          <input
            value={controlSearch}
            onChange={e=>setControlSearch(e.target.value)}
            placeholder="Filter controls…"
            style={{ width:'100%', background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'5px 10px', fontSize:11, color:C.text, outline:'none', boxSizing:'border-box' }}
          />
        </div>

        {/* By layer — three-state */}
        {Object.entries(DID_LAYERS).sort(([,a],[,b])=>a.order-b.order).map(([didLayerKey, didLayer])=>{
          const layerData = byLayer[didLayerKey] || {present:[],partial:[],absent:[]};
          const flt = s => controlSearch ? s.filter(c=>c.name.toLowerCase().includes(controlSearch.toLowerCase())) : s;
          const fp = flt(layerData.present), fpa = flt(layerData.partial), fa = flt(layerData.absent);
          if(!fp.length && !fpa.length && !fa.length) return null;
          return (
            <div key={didLayerKey} style={{background:C.surface, border:`1px solid ${C.border}`,
              borderRadius:12, padding:"16px 20px", marginBottom:12}}>
              <div style={{display:"flex", alignItems:"center", gap:8, marginBottom:12}}>
                <didLayer.Icon size={16} style={{color:didLayer.color}} />
                <span style={{fontSize:13, fontWeight:700, color:C.text}}>{didLayer.name}</span>
                <span style={{fontSize:11, color:C.textMuted, marginLeft:"auto"}}>
                  {fp.length} present{fpa.length?` · ${fpa.length} partial`:''} · {fa.length} missing
                </span>
              </div>
              <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
                {/* ✓ PRESENT */}
                {fp.map((c,i)=>(
                  <div key={`p${i}`} style={{background:"#43A04710", border:"1px solid #43A04740",
                    borderRadius:6, padding:"4px 10px", fontSize:11, color:"#43A047", display:"flex", flexDirection:"column", gap:3}}>
                    <div style={{display:"flex", alignItems:"center", gap:4, flexWrap:"wrap"}}>
                      <span style={{fontWeight:700}}>✓</span>
                      <span style={{fontWeight:600}}>{c.name}</span>
                      {c.source==='doc' ? <span style={{fontSize:9,opacity:0.8}}>📄</span>
                        : c.source==='hcl'||!c.source ? <span style={{fontSize:9,background:"#43A04720",borderRadius:3,padding:"1px 4px",opacity:0.7}}>&lt;/&gt;</span> : null}
                      <ConfidenceBadge ev={c.evidence} />
                    </div>
                    <EvidenceDrawer ev={c.evidence} label="evidence" />
                  </div>
                ))}
                {/* ~ PARTIAL */}
                {fpa.map((c,i)=>(
                  <div key={`pa${i}`} style={{background:"#F57C0010", border:"1px solid #F57C0040",
                    borderRadius:6, padding:"4px 10px", fontSize:11, color:"#F57C00", display:"flex", flexDirection:"column", gap:3}}>
                    <div style={{display:"flex", alignItems:"center", gap:4, flexWrap:"wrap"}}>
                      <span style={{fontWeight:700}}>~</span>
                      <span style={{fontWeight:600}}>{c.name}</span>
                      <span style={{fontSize:9,background:"#F57C0020",borderRadius:3,padding:"1px 4px",fontWeight:700}}>PARTIAL</span>
                      <ConfidenceBadge ev={c.evidence} />
                    </div>
                    {c.partialNote && <div style={{fontSize:9,color:"#F57C00",opacity:0.85}}>{c.partialNote}</div>}
                    <EvidenceDrawer ev={c.evidence} label="evidence" />
                  </div>
                ))}
                {/* ✗ ABSENT */}
                {fa.map((c,i)=>(
                  <div key={`a${i}`} style={{background:"#E5393510", border:"1px solid #E5393540",
                    borderRadius:6, padding:"4px 10px", fontSize:11, color:"#E53935", display:"flex", alignItems:"center", gap:4}}>
                    <span style={{fontWeight:700}}>✗</span><span style={{fontWeight:600}}>{c.name}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  })()}
  </>
</div>

  );
});
