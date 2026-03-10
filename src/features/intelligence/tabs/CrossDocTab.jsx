// src/features/intelligence/tabs/CrossDocTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown } from '../panelHelpers.jsx';
import { GitCompare, Loader2 } from '../../../icons.jsx';

export const CrossDocTab = React.memo(function CrossDocTab(ctx) {
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
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
    Cross-Document Correlation
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    Links your uploaded documents (threat models, runbooks, compliance docs) to actual Terraform resources.
    Contradictions are flagged where docs describe controls that are absent in configuration.
  </div>
  {!summary?.crossDocCorrelations || !summary.crossDocCorrelations.length ? (
    <div style={{color:C.textMuted, fontSize:13}}>
      {!parseResult?.resources?.length
        ? "Upload Terraform files to enable cross-doc correlation."
        : "Upload context documents (threat models, runbooks, compliance docs) to correlate against your Terraform."}
    </div>
  ) : (
    <div>
      {/* 5B: LLM contradiction narrative */}
      {llmStatus === 'ready' && (
        <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
          {contradictionNarrative ? (
            <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:6 }}>
              <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI RISK SUMMARY</div>
              <div style={{ fontSize:12 }}>{renderMarkdown(contradictionNarrative)}</div>
              <button onClick={()=>setContradictionNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
            </div>
          ) : (summary?.crossDocCorrelations?.some(c=>c.contradictions?.length>0)) && (
            <button
              disabled={contraNarrLoading}
              onClick={async () => {
                setContraNarrLoading(true);
                setContradictionNarrative('');
                const all = (summary.crossDocCorrelations||[]).flatMap(c=>c.contradictions||[]);
                const ctx = all.slice(0,10).map(c=>`- ${c.type||'GAP'}: ${c.msg||c.title||''}`).join('\n');
                await onGenerateLLM(
                  [{ role:'system', content:'You are a security analyst. Summarize the overall risk these contradictions represent and suggest the top 3 remediation priorities in 4-5 sentences.' },
                   { role:'user', content:`Contradictions between architecture documents and Terraform:\n${ctx}` }],
                  tok => setContradictionNarrative(prev=>prev+tok)
                );
                setContraNarrLoading(false);
              }}
              style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
            >
              {contraNarrLoading ? 'Analyzing…' : '✦ Summarize contradiction risk with AI'}
            </button>
          )}
        </div>
      )}

      {/* Contradiction summary */}
      {(()=>{
        const allContradictions = (summary.crossDocCorrelations||[])
          .flatMap(c=>c.contradictions||[]);
        return allContradictions.length > 0 ? (
          <div style={{background:"#E5393510", border:"1px solid #E5393540",
            borderRadius:12, padding:"14px 18px", marginBottom:18}}>
            <div style={{fontSize:13, fontWeight:700, color:"#E53935", marginBottom:8}}>
              {allContradictions.length} Contradiction{allContradictions.length!==1?"s":""} Detected
            </div>
            <div style={{fontSize:11, color:C.textSub, marginBottom:8, lineHeight:1.5}}>
              Documents describe controls that are absent or misconfigured in your Terraform.
            </div>
            {allContradictions.slice(0,5).map((c,i)=>(
              <div key={i} style={{marginBottom:6, padding:"6px 10px",
                background:"#E5393508", borderRadius:6, fontSize:11}}>
                <span style={{fontWeight:700, color: c.type==='SCOPE-VIOLATION'?'#B71C1C':c.type==='CONTRADICTION'?'#E53935':'#F57C00'}}>{c.type}: </span>
                <span style={{color:C.text}}>{c.msg||c.title}</span>
                {(c.docRef||c.doc) && <span style={{color:C.textMuted}}> [source: {c.docRef||c.doc}]</span>}
              </div>
            ))}
            {allContradictions.length>5 && (
              <div style={{fontSize:11, color:C.textMuted}}>
                +{allContradictions.length-5} more contradictions — expand individual resources below.
              </div>
            )}
          </div>
        ) : null;
      })()}

      {/* Per-resource correlations */}
      {summary.crossDocCorrelations.filter(c=>c.docHits?.length>0||c.contradictions?.length>0).map((corr,i)=>(
        <div key={i} style={{background:C.surface, border:`1px solid ${
          corr.contradictions?.length ? "#E5393544" : C.border}`,
          borderRadius:10, padding:"14px 18px", marginBottom:10}}>
          <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:8}}>
            <div>
              <span style={{fontSize:12, fontWeight:700, color:C.text}}>
                {corr.resource?.name || corr.resource?.id}
              </span>
              <span style={{fontSize:10, color:C.textMuted, marginLeft:8}}>
                {corr.resource?.type}
              </span>
            </div>
            {corr.contradictions?.length > 0 && (
              <span style={{fontSize:10, fontWeight:700, color:"#E53935",
                background:"#E5393515", border:"1px solid #E5393544",
                borderRadius:6, padding:"2px 8px"}}>
                {corr.contradictions.length} contradiction{corr.contradictions.length!==1?"s":""}
              </span>
            )}
          </div>
          {/* Doc hits */}
          {corr.docHits?.slice(0,2).map((hit,j)=>(
            <div key={j} style={{...MONO, fontSize:10, color:C.textSub,
              background:C.bg, padding:"5px 8px", borderRadius:5,
              border:`1px solid ${C.border}`, lineHeight:1.6, marginBottom:6,
              whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
              <span style={{color:C.textMuted, fontSize:9}}>[{hit.source}] </span>
              {hit.compressed||hit.text?.substring(0,220)}{((hit.compressed||hit.text||"").length>220?"…":"")}
            </div>
          ))}
          {/* Contradictions */}
          {corr.contradictions?.map((ct,j)=>{
            const ctColor = ct.type==='SCOPE-VIOLATION'?'#B71C1C':ct.type==='CONTRADICTION'?'#E53935':'#F57C00';
            return (
              <div key={j} style={{fontSize:10, color:ctColor,
                background:`${ctColor}08`, border:`1px solid ${ctColor}30`,
                borderRadius:5, padding:"4px 8px", marginBottom:4}}>
                <span style={{fontWeight:700, color:ctColor, borderColor:`${ctColor}44`}}>{ct.type}: </span>{ct.msg||ct.title}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  )}
</div>

  );
});
