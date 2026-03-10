// src/features/intelligence/tabs/ThreatIntelTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown } from '../panelHelpers.jsx';
import { ATTACK_TECHNIQUES, TF_ATTACK_MAP, CWE_DETAILS } from '../../../data/attack-data.js';
import { Zap, ChevronDown, ChevronRight, Target, Shield } from '../../../icons.jsx';

export const ThreatIntelTab = React.memo(function ThreatIntelTab(ctx) {
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

<div style={{maxWidth:900}}>
  {/* ── Section: MITRE ATT&CK Mapping ── */}
  <div>
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
    MITRE ATT&CK Mapping
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    Techniques from MITRE ATT&CK Cloud mapped to your Terraform resources.
    Hover over technique IDs for full descriptions.
  </div>

  {(!parseResult?.resources?.length) ? (
    <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to see ATT&CK mapping.</div>
  ) : (() => {
    // Build: technique → resources that trigger it
    const techMap = {};
    const tactic_order = ['Initial Access/Persistence','Persistence','Credential Access','Privilege Escalation',
      'Defense Evasion','Discovery','Lateral Movement','Collection','Execution','Exfiltration','Impact'];
    parseResult.resources.forEach(r => {
      (TF_ATTACK_MAP[r.type]||[]).forEach(tid => {
        if (!techMap[tid]) techMap[tid]={resources:[]};
        techMap[tid].resources.push(`${r.type}/${r.name||r.id}`);
      });
    });
    // 7A: Merge doc-sourced ATT&CK techniques from entity extraction
    Object.entries(summary?.entitySummary?.attack||{}).forEach(([tid,terms])=>{
      if(!techMap[tid]) techMap[tid]={resources:[],docMentioned:true,docTerms:terms};
      else techMap[tid].docMentioned=true;
    });

    const entries = Object.entries(techMap);
    if (entries.length===0) return (
      <div style={{color:C.textMuted,fontSize:13}}>No ATT&CK techniques mapped to current resource types.</div>
    );
    // 7B: Build visible entries respecting attackFilter
    const visibleEntries = attackFilter
      ? entries.filter(([tid]) => tid === attackFilter)
      : entries;

    // Group by tactic (using visibleEntries for filtered display)
    const byTactic = {};
    visibleEntries.forEach(([tid,data]) => {
      const tech = ATTACK_TECHNIQUES[tid];
      const tactic = tech?.tactic||'Other';
      if (!byTactic[tactic]) byTactic[tactic]=[];
      byTactic[tactic].push({tid,tech,resources:data.resources,docMentioned:data.docMentioned});
    });
    const sevColor = { Critical:"#B71C1C", High:"#E53935", Medium:"#F57C00", Low:"#43A047" };

    return (
      <div>
        {/* 7C: LLM attack narrative */}
        {llmStatus === 'ready' && (
          <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
            {attackNarrative ? (
              <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
                <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI ATTACK NARRATIVE</div>
                <div style={{ fontSize:12 }}>{renderMarkdown(attackNarrative)}</div>
                <button onClick={()=>setAttackNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
              </div>
            ) : (
              <button
                disabled={attackNarrLoading}
                onClick={async () => {
                  setAttackNarrLoading(true);
                  setAttackNarrative('');
                  const techList = entries.slice(0,12).map(([tid,data])=>`${tid} (${ATTACK_TECHNIQUES?.[tid]?.name||tid}) via ${(data.resources||[]).slice(0,2).join(', ')}`).join('\n');
                  await onGenerateLLM(
                    [{ role:'system', content:'You are a threat modeler. Write a concise 4-6 sentence attacker kill-chain narrative describing how an adversary could chain these AWS ATT&CK techniques. Be specific about cloud exploitation paths.' },
                     { role:'user', content:`MITRE ATT&CK techniques mapped to infrastructure:\n${techList}` }],
                    tok => setAttackNarrative(prev=>prev+tok)
                  );
                  setAttackNarrLoading(false);
                }}
                style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
              >
                {attackNarrLoading ? 'Generating…' : '✦ Generate attack narrative with AI'}
              </button>
            )}
          </div>
        )}

        {/* 7B: Attack filter banner */}
        {attackFilter && (
          <div style={{ padding:'6px 0', background:`${C.accent}10`, borderRadius:6, marginBottom:12, display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ fontSize:11, color:C.accent, fontWeight:600 }}>Filtered to: {attackFilter}</span>
            <button onClick={()=>setAttackFilter(null)} style={{ fontSize:10, color:C.textMuted, background:'none', border:'none', cursor:'pointer' }}>✕ Clear filter</button>
          </div>
        )}

        {/* Coverage summary */}
        <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap"}}>
          {['Critical','High','Medium','Low'].map(s=>{
            const cnt=entries.filter(([t])=>ATTACK_TECHNIQUES[t]?.severity===s).length;
            return cnt>0 ? (
              <div key={s} style={{background:`${sevColor[s]}18`,border:`1px solid ${sevColor[s]}44`,
                borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
                <span style={{fontSize:20,fontWeight:700,color:sevColor[s]}}>{cnt}</span>
                <span style={{fontSize:10,fontWeight:600,color:sevColor[s],textTransform:"uppercase",letterSpacing:".06em"}}>{s}</span>
              </div>
            ) : null;
          })}
          <div style={{background:`${C.accent}18`,border:`1px solid ${C.accent}44`,
            borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
            <span style={{fontSize:20,fontWeight:700,color:C.accent}}>{entries.length}</span>
            <span style={{fontSize:10,fontWeight:600,color:C.accent,textTransform:"uppercase",letterSpacing:".06em"}}>Total</span>
          </div>
        </div>
        {/* Per-tactic sections */}
        {tactic_order.filter(t=>byTactic[t]?.length).map(tactic=>(
          <div key={tactic} style={{marginBottom:18}}>
            <div style={{fontSize:11,fontWeight:700,color:C.textMuted,textTransform:"uppercase",
              letterSpacing:".08em",marginBottom:8}}>{tactic}</div>
            <div style={{display:"flex",flexDirection:"column",gap:6}}>
              {byTactic[tactic].map(({tid,tech,resources,docMentioned})=>(
                <div key={tid} style={{background:C.surface,border:`1px solid ${C.border}`,
                  borderLeft:`3px solid ${sevColor[tech?.severity||'Low']}`,
                  borderRadius:8,padding:"10px 14px"}}>
                  <div style={{display:"flex",gap:10,alignItems:"flex-start",flexWrap:"wrap"}}>
                    <a href={`https://attack.mitre.org/techniques/${tid.replace('.','/').replace('.','/')}`}
                      target="_blank" rel="noopener noreferrer" style={{
                        ...MONO,fontSize:11,color:"#E53935",fontWeight:700,flexShrink:0,textDecoration:"none",
                        background:"#E5393518",border:"1px solid #E5393544",borderRadius:6,padding:"1px 8px",
                      }}>{tid}</a>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12,color:C.text,fontWeight:600,marginBottom:3}}>
                        {tech?.name||tid}
                        <span style={{marginLeft:8,fontSize:10,color:sevColor[tech?.severity||'Low'],
                          fontWeight:600,background:`${sevColor[tech?.severity||'Low']}18`,
                          border:`1px solid ${sevColor[tech?.severity||'Low']}44`,
                          borderRadius:6,padding:"0 6px"}}>{tech?.severity||'?'}</span>
                        {docMentioned && (
                          <span style={{ fontSize:9, fontWeight:700, background:`${C.accent}18`, color:C.accent, borderRadius:4, padding:'1px 5px', marginLeft:4 }}>
                            IN DOCS
                          </span>
                        )}
                      </div>
                      <div style={{fontSize:11,color:C.textSub,lineHeight:1.5,marginBottom:6}}>{tech?.desc}</div>
                      <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
                        {[...new Set(resources)].slice(0,6).map((r,ri)=>(
                          <span key={ri} style={{...MONO,fontSize:9,color:C.textMuted,
                            background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,padding:"1px 6px"}}>
                            {r}
                          </span>
                        ))}
                        {resources.length>6 && <span style={{fontSize:9,color:C.textMuted}}>+{resources.length-6} more</span>}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {/* Any unclassified tactic */}
        {Object.entries(byTactic).filter(([t])=>!tactic_order.includes(t)).map(([tactic,items])=>(
          <div key={tactic} style={{marginBottom:18}}>
            <div style={{fontSize:11,fontWeight:700,color:C.textMuted,textTransform:"uppercase",letterSpacing:".08em",marginBottom:8}}>{tactic}</div>
            {items.map(({tid,tech,resources})=>(
              <div key={tid} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 14px",marginBottom:6}}>
                <span style={{...MONO,fontSize:11,color:"#E53935",fontWeight:700}}>{tid}</span>
                <span style={{fontSize:12,color:C.text,marginLeft:10}}>{tech?.name||tid}</span>
              </div>
            ))}
          </div>
        ))}
      </div>
    );
  })()}
  {/* end */}
  </div>

  {/* ── Divider ── */}
  <div style={{borderTop:`1px solid ${C.border}`, margin:"32px 0"}} />

  {/* ── Section: Threat Findings ── */}
  <div>
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
    Threat Findings from Documents
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
    STRIDE threats identified in uploaded architecture documents. Each finding is a verbatim excerpt.
  </div>

  {/* 8A: LLM threat scenarios */}
  {llmStatus === 'ready' && (
    <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
      {threatScenarios ? (
        <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
          <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI THREAT SCENARIOS</div>
          <div style={{ fontSize:12 }}>{renderMarkdown(threatScenarios)}</div>
          <button onClick={()=>setThreatScenarios('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
        </div>
      ) : (
        <button
          disabled={threatScenariosLoading}
          onClick={async () => {
            setThreatScenariosLoading(true);
            setThreatScenarios('');
            const resources = parseResult?.resources||[];
            const topRiskRes = resources.filter(r=>(TF_ATTACK_MAP?.[r.type]||[]).length>0).slice(0,5);
            const strideCtx = Object.entries(summary?.entitySummary?.stride||{}).map(([k,terms])=>`${k}: ${(terms||[]).join(', ')}`).join('\n');
            const docCtx = (summary?.threatChunks||[]).slice(0,3).map((c,i)=>`[${i+1}] ${(c.excerpt||c.text||'').slice(0,150)}`).join('\n');
            await onGenerateLLM(
              [{ role:'system', content:'You are a threat modeler using STRIDE. Generate 3 threat scenarios. For each use bold headers: **Threat**, **STRIDE**, **ATT&CK**, **Impact**, **Countermeasure**.' },
               { role:'user', content:`High-risk resources: ${topRiskRes.map(r=>r.type+'/'+(r.name||r.id)).join(', ')}\nSTRIDE findings: ${strideCtx}\nDoc excerpts: ${docCtx}\n\nGenerate 3 structured threat scenarios.` }],
              tok => setThreatScenarios(prev=>prev+tok)
            );
            setThreatScenariosLoading(false);
          }}
          style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
        >
          {threatScenariosLoading ? 'Generating…' : '✦ Generate threat scenarios with AI'}
        </button>
      )}
    </div>
  )}

  {/* 8B: STRIDE summary grid — always show all 6 categories */}
  <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",
    gap:10, marginBottom:20}}>
    {Object.entries(STRIDE_LABELS).map(([k, label])=>{
      const terms = summary?.entitySummary?.stride?.[k] || [];
      const hasFindings = terms.length > 0;
      return (
        <div key={k} style={{
          background:C.surface, border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,
          borderRadius:8, padding:"10px 12px",
          borderLeft:`3px solid ${STRIDE_COLORS[k]||"#999"}${hasFindings?'':'44'}`,
          opacity: hasFindings ? 1 : 0.5,
        }}>
          <div style={{fontSize:11, fontWeight:700, color:STRIDE_COLORS[k]||"#999",
            textTransform:"uppercase", letterSpacing:".06em", marginBottom:6,
            opacity: hasFindings ? 1 : 0.6}}>
            {label}
          </div>
          {hasFindings
            ? <div style={{fontSize:11, color:C.textSub, lineHeight:1.5}}>
                {terms.slice(0,6).join(", ")}
              </div>
            : <div style={{fontSize:10, color:C.textMuted, fontStyle:"italic"}}>
                No findings in uploaded documents
              </div>
          }
        </div>
      );
    })}
  </div>

  {/* Threat chunks */}
  {(summary?.threatChunks||[]).length === 0 ? (
    <div style={{color:C.textMuted, fontSize:13}}>
      No explicit threat indicators found in uploaded documents.
      Upload threat model docs, STRIDE assessments, or security reviews.
    </div>
  ) : (
    summary.threatChunks.map((chunk,i)=>(
      <div key={i} style={{
        background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
        padding:"12px 14px", marginBottom:8,
      }}>
        <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:6}}>
          <span style={{background:`${C.accent}22`, color:C.accent,
            border:`1px solid ${C.accent}44`, borderRadius:10,
            padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
          {chunk.threats.map(t=>(
            <span key={t} style={{background:`${STRIDE_COLORS[t]||"#999"}18`,
              color:STRIDE_COLORS[t]||"#999",border:`1px solid ${STRIDE_COLORS[t]||"#999"}44`,
              borderRadius:8,padding:"1px 6px",fontSize:9,fontWeight:600}}>
              {STRIDE_LABELS[t]||t}
            </span>
          ))}
        </div>
        <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
          background:C.bg, padding:"8px 10px", borderRadius:6, border:`1px solid ${C.border}`,
          whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
          &ldquo;{chunk.excerpt}&rdquo;
        </div>
      </div>
    ))
  )}
  </div>
</div>

  );
});
