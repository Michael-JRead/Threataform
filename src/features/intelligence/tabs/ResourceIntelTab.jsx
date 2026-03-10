// src/features/intelligence/tabs/ResourceIntelTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown } from '../panelHelpers.jsx';
import { RT } from '../../../data/resource-types.js';
import { Layers, Search, ChevronDown, Server, Database, Network, Loader2 } from '../../../icons.jsx';

export const ResourceIntelTab = React.memo(function ResourceIntelTab(ctx) {
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
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
    Resource Intelligence
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
    For each Terraform resource, the engine finds relevant passages in your uploaded documents.
    Shows compliance requirements, threat relevance, and architectural context.
  </div>

  {(!parseResult?.resources?.length) ? (
    <div style={{color:C.textMuted, fontSize:13}}>
      Upload Terraform files to see resource intelligence.
    </div>
  ) : (() => {
    // 10A: Search + pagination
    const allResources = parseResult.resources;
    const PAGE_SIZE = 20;
    const filtered = allResources.filter(r => {
      if(!resourceSearch && !resourceTypeFilter) return true;
      const label = (r.type+' '+(r.name||r.id)).toLowerCase();
      if(resourceSearch && !label.includes(resourceSearch.toLowerCase())) return false;
      if(resourceTypeFilter && r.type !== resourceTypeFilter) return false;
      return true;
    });
    const paged = filtered.slice(resourcePage*PAGE_SIZE, (resourcePage+1)*PAGE_SIZE);
    const totalPages = Math.ceil(filtered.length/PAGE_SIZE);

    return (
      <div style={{display:"flex", flexDirection:"column", gap:0}}>
        {/* Search + filter bar */}
        <div style={{ display:'flex', gap:8, marginBottom:10, flexShrink:0 }}>
          <input
            value={resourceSearch}
            onChange={e=>{setResourceSearch(e.target.value);setResourcePage(0);}}
            placeholder={`Search ${allResources.length} resources…`}
            style={{ flex:1, background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'5px 10px', fontSize:11, color:C.text, outline:'none' }}
          />
          <select
            value={resourceTypeFilter}
            onChange={e=>{setResourceTypeFilter(e.target.value);setResourcePage(0);}}
            style={{ background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'4px 8px', fontSize:11, color:C.text, maxWidth:160 }}
          >
            <option value="">All types</option>
            {[...new Set(allResources.map(r=>r.type))].sort().map(t=>(
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {/* Resource count indicator */}
        {filtered.length !== allResources.length && (
          <div style={{ fontSize:10, color:C.textMuted, marginBottom:8 }}>
            Showing {filtered.length} of {allResources.length} resources
          </div>
        )}

        {/* Resource cards */}
        <div style={{display:"flex", flexDirection:"column", gap:10}}>
          {paged.map((r,i)=>{
            const meta = RT[r.type]||RT._default;
            const hits = intelligence?._built ? intelligence.analyzeResource(r.type, r.name||r.id) : [];
            const strideHits = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.stride||{})))];
            const compHits  = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.compliance||{})))];
            const threats   = intelligence?._built ? intelligence.getThreats(r) : null;
            const misconfigs = intelligence?._built ? intelligence.getMisconfigurations(r) : [];
            const resourceKey = r.id||r.name||`${r.type}-${i}`;
            return (
              <div key={resourcePage*PAGE_SIZE+i} style={{background:C.surface, border:`1px solid ${C.border}`,
                borderRadius:8, padding:"12px 14px"}}>
                <div style={{display:"flex", gap:8, alignItems:"center", marginBottom:6, flexWrap:"wrap"}}>
                  <div style={{width:10,height:10,borderRadius:2,background:meta.c,flexShrink:0}}/>
                  <span style={{...MONO, fontSize:12, color:C.text, fontWeight:600}}>
                    {r.type}/{r.name||r.id}
                  </span>
                  {/* STRIDE badges */}
                  {(threats?.stride||[]).map(k=>(
                    <span key={k} style={{background:`${STRIDE_COLORS[k]||"#999"}18`,
                      color:STRIDE_COLORS[k]||"#999",border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,
                      borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                      {STRIDE_LABELS[k]||k}
                    </span>
                  ))}
                  {/* ATT&CK badges */}
                  {(threats?.attackTechniques||[]).slice(0,3).map(t=>(
                    <span key={t.techniqueId} style={{background:"#E5393514",color:"#E53935",
                      border:"1px solid #E5393530",borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                      {t.techniqueId}
                    </span>
                  ))}
                  {/* 10B: Misconfig severity breakdown badges */}
                  {misconfigs.length>0 && (()=>{
                    const sev = {};
                    misconfigs.forEach(m => { sev[m.severity] = (sev[m.severity]||0)+1; });
                    const colors = { Critical:'#B71C1C', High:'#E53935', Medium:'#F57C00', Low:'#F9A825' };
                    return (
                      <span style={{ display:'inline-flex', gap:3, alignItems:'center' }}>
                        {['Critical','High','Medium','Low'].filter(s=>sev[s]).map(s=>(
                          <span key={s} style={{ background:`${colors[s]}18`, color:colors[s], border:`1px solid ${colors[s]}35`, borderRadius:4, padding:'0 5px', fontSize:9, fontWeight:700 }}>
                            {sev[s]}{s[0]}
                          </span>
                        ))}
                      </span>
                    );
                  })()}
                  {compHits.map(k=>(
                    <span key={k} style={{background:"#0277BD18",color:"#0277BD",
                      border:"1px solid #0277BD44",borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                      {COMPLIANCE_LABELS[k]||k}
                    </span>
                  ))}
                </div>
                {/* Doc hits */}
                {hits.length>0 && (
                  <div style={{display:"flex", flexDirection:"column", gap:5, marginBottom:misconfigs.length?6:0}}>
                    {hits.slice(0,2).map((chunk,j)=>(
                      <div key={j} style={{...MONO, fontSize:10, color:C.textSub,
                        background:C.bg, padding:"5px 8px", borderRadius:5,
                        border:`1px solid ${C.border}`, lineHeight:1.6, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
                        <span style={{color:C.textMuted,fontSize:9}}>[{chunk.source}] </span>
                        {chunk.compressed||chunk.text.substring(0,200)}{(chunk.compressed||chunk.text).length>200?"…":""}
                        {chunk.confidence && (
                          <span style={{marginLeft:6,fontSize:9,color:C.textMuted}}>({chunk.confidence}% match)</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {/* Misconfig inline */}
                {misconfigs.length>0 && (
                  <div style={{marginTop:6,display:"flex",flexDirection:"column",gap:4}}>
                    {misconfigs.slice(0,2).map((f,j)=>(
                      <div key={j} style={{fontSize:10,color:SEV_COLOR[f.severity],background:`${SEV_COLOR[f.severity]}10`,
                        border:`1px solid ${SEV_COLOR[f.severity]}30`,borderRadius:5,padding:"4px 8px"}}>
                        <span style={{fontWeight:700}}>{f.id} </span>{f.title}
                      </div>
                    ))}
                    {misconfigs.length>2 && (
                      <div style={{fontSize:10,color:C.textMuted}}>+{misconfigs.length-2} more — see Misconfig Checks tab</div>
                    )}
                  </div>
                )}
                {/* HCL-derived input dependencies (factual from parseHCLBody) */}
                {r.inputRefs?.length > 0 && (
                  <div style={{marginTop:6,fontSize:10,color:C.textMuted,lineHeight:1.7}}>
                    <span style={{fontWeight:600,color:C.textSub}}>→ Inputs: </span>
                    {[...new Map(r.inputRefs.map(ref=>[ref.resourceId,ref])).values()].slice(0,6).map((ref,j)=>(
                      <span key={j} style={{...MONO,background:C.bg,border:`1px solid ${C.border}`,borderRadius:3,padding:"0 4px",marginRight:4,fontSize:9}}>
                        {ref.resourceId} [{ref.attr}]
                      </span>
                    ))}
                    {r.inputRefs.length > 6 && <span style={{fontSize:9,color:C.textMuted}}>+{r.inputRefs.length-6} more</span>}
                  </div>
                )}
                {hits.length===0 && misconfigs.length===0 && (
                  <div style={{fontSize:10,color:C.textMuted,fontStyle:"italic"}}>No document matches or config checks for this resource type.</div>
                )}
                {/* 10C: LLM per-resource risk summary */}
                {llmStatus === 'ready' && (
                  <div style={{ marginTop:6 }}>
                    {resourceSummaries[resourceKey] ? (
                      <div style={{ background:`${C.accent}08`, borderRadius:6, padding:'6px 10px', fontSize:11, lineHeight:1.6 }}>
                        {renderMarkdown(resourceSummaries[resourceKey])}
                      </div>
                    ) : (
                      <button
                        onClick={async () => {
                          const miscs = intelligence?.getMisconfigurations(r)||[];
                          const thr = intelligence?.getThreats(r)||{};
                          const ctx = `Resource: ${r.type}/${r.name||r.id}\nSTRIDE: ${(thr.stride||[]).join(', ')}\nATT&CK: ${(thr.attackTechniques||[]).map(t=>t.techniqueId||t).join(', ')}\nMisconfigs (${miscs.length}): ${miscs.slice(0,3).map(m=>m.title).join('; ')}`;
                          const key = resourceKey;
                          setResourceSummaries(prev=>({...prev,[key]:'…'}));
                          let text='';
                          await onGenerateLLM(
                            [{ role:'system', content:'In 2-3 sentences, summarize the security risk of this AWS resource and the single most important remediation action.' },
                             { role:'user', content:ctx }],
                            tok=>{ text+=tok; setResourceSummaries(prev=>({...prev,[key]:text})); }
                          );
                        }}
                        style={{ fontSize:10, background:`${C.accent}12`, color:C.accent, border:`1px solid ${C.accent}30`, borderRadius:5, padding:'3px 9px', cursor:'pointer', marginTop:2 }}
                      >
                        ✦ Risk summary
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display:'flex', gap:6, padding:'10px 0', justifyContent:'center' }}>
            <button disabled={resourcePage===0} onClick={()=>setResourcePage(p=>p-1)} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:5, padding:'4px 10px', fontSize:11, color:resourcePage===0?C.textMuted:C.text, cursor:resourcePage===0?'default':'pointer' }}>‹ Prev</button>
            <span style={{ fontSize:11, color:C.textMuted, lineHeight:'24px' }}>{resourcePage+1} / {totalPages}</span>
            <button disabled={resourcePage===totalPages-1} onClick={()=>setResourcePage(p=>p+1)} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:5, padding:'4px 10px', fontSize:11, color:resourcePage===totalPages-1?C.textMuted:C.text, cursor:resourcePage===totalPages-1?'default':'pointer' }}>Next ›</button>
          </div>
        )}
      </div>
    );
  })()}
</div>

  );
});
