// src/features/intelligence/tabs/ScopeTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown } from '../panelHelpers.jsx';
import { ScanLine, Loader2 } from '../../../icons.jsx';

export const ScopeTab = React.memo(function ScopeTab(ctx) {
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

<div style={{maxWidth:800}}>
  <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
    Scope Analysis
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
    In-scope and out-of-scope declarations detected in uploaded documents.
    These define the threat model boundary for this assessment.
  </div>

  {(summary?.scopeChunks||[]).length === 0 ? (
    <div>
      <div style={{color:C.textMuted, fontSize:13, marginBottom:16}}>
        No explicit scope declarations found in uploaded documents.
        Include phrases like &ldquo;in scope&rdquo; / &ldquo;out of scope&rdquo; in your architecture docs.
      </div>
      {/* 9B: LLM scope inference when no scope docs */}
      {llmStatus === 'ready' && (
        <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
          {inferredScope ? (
            <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
              <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI SCOPE INFERENCE</div>
              <div style={{ fontSize:12 }}>{renderMarkdown(inferredScope)}</div>
              <button onClick={()=>setInferredScope('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
            </div>
          ) : (
            <button
              disabled={inferredScopeLoading}
              onClick={async () => {
                setInferredScopeLoading(true);
                setInferredScope('');
                const types = [...new Set((parseResult?.resources||[]).map(r=>r.type))].slice(0,15);
                await onGenerateLLM(
                  [{ role:'system', content:'You are a threat model scoping expert. Base your assessment only on the resource types provided.' },
                   { role:'user', content:`AWS infrastructure resource types: ${types.join(', ')}. Identify what is likely IN scope and OUT of scope for a threat model. Format as:\n**IN SCOPE:** (bulleted list)\n**OUT OF SCOPE:** (bulleted list)\n**ASSUMPTIONS:** (key assumptions)` }],
                  tok => setInferredScope(prev=>prev+tok)
                );
                setInferredScopeLoading(false);
              }}
              style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
            >
              {inferredScopeLoading ? 'Inferring…' : '✦ Infer scope with AI'}
            </button>
          )}
        </div>
      )}
      {/* Show all resources as assumed in scope */}
      {parseResult?.resources?.length > 0 && (
        <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, padding:"14px 16px"}}>
          <div style={{fontSize:12, fontWeight:600, color:C.text, marginBottom:10}}>
            All Terraform resources (assumed in scope — no scope docs uploaded)
          </div>
          <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
            {parseResult.resources.map((r,i)=>(
              <span key={i} style={{background:"#2E7D3218", color:"#2E7D32",
                border:"1px solid #2E7D3244", borderRadius:8,
                padding:"2px 8px", fontSize:10, fontWeight:500}}>
                {r.type}/{r.name||r.id}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  ) : (
    <div>
      {/* 9A: Resource-scope matching */}
      {(()=>{
        const resources = parseResult?.resources||[];
        // Extract actual scope items from raw chunk text (entity arrays only have labels)
        const extractScopeTerms = (chunks, marker) => {
          const terms = [];
          chunks.forEach(c => {
            const txt = (c.text||c.excerpt||'');
            // Find sections after the marker header
            const rx = new RegExp(marker+'[:\\s]*([\\s\\S]{0,600}?)(?:(?:out of scope|in scope|\\*\\*out|\\*\\*in|##|$))', 'i');
            const m = txt.match(rx);
            if (m) {
              // Extract dash/bullet items
              (m[1]||'').split(/[-\n*,]/).map(s=>s.replace(/\*\*/g,'').trim().toLowerCase())
                .filter(s=>s.length>2&&s.length<40&&!/^(and|the|or|of|for|with)$/.test(s))
                .forEach(s=>terms.push(s));
            }
          });
          return [...new Set(terms)];
        };
        const chunks = summary?.scopeChunks||[];
        // Also pull from entity arrays as fallback (for explicitly tagged terms)
        const inScopeTerms = [
          ...extractScopeTerms(chunks, 'in scope'),
          ...(chunks.flatMap(c=>(c.inScope||[])).map(s=>s.toLowerCase()).filter(s=>s!=='in scope')),
        ].filter(Boolean);
        const outScopeTerms = [
          ...extractScopeTerms(chunks, 'out of scope'),
          ...(chunks.flatMap(c=>(c.outOfScope||[])).map(s=>s.toLowerCase()).filter(s=>s!=='out of scope')),
        ].filter(Boolean);

        if(!inScopeTerms.length && !outScopeTerms.length) return null;

        const inScope=[], outScope=[];
        resources.forEach(r => {
          const label = (r.type+' '+(r.name||r.id)).toLowerCase().replace(/_/g,' ');
          if(outScopeTerms.some(t=>label.includes(t))) outScope.push(r);
          else if(inScopeTerms.some(t=>label.includes(t))) inScope.push(r);
        });

        return (
          <div style={{ marginBottom:14 }}>
            {outScope.length > 0 && (
              <div style={{ background:'#B71C1C14', border:'1px solid #B71C1C40', borderRadius:8, padding:'12px 14px', marginBottom:10 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'#B71C1C', marginBottom:5 }}>
                  {outScope.length} resources match out-of-scope declarations
                </div>
                <div style={{ fontSize:11, color:C.textSub, marginBottom:8 }}>These Terraform resources exist but are declared out-of-scope in your documents. Review whether they should be included in the threat model.</div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
                  {outScope.map((r,i) => (
                    <span key={i} style={{ ...MONO, fontSize:10, background:'#B71C1C10', color:'#B71C1C', border:'1px solid #B71C1C30', borderRadius:4, padding:'2px 7px' }}>
                      {r.type}/{r.name||r.id}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {inScope.length > 0 && (
              <div style={{ fontSize:11, color:C.textMuted, marginBottom:8 }}>
                <span style={{ color:'#2E7D32', fontWeight:600 }}>✓ {inScope.length}</span> resources matched to in-scope declarations
              </div>
            )}
          </div>
        );
      })()}

      {/* Scope chunk cards */}
      {summary.scopeChunks.map((chunk,i)=>(
        <div key={i} style={{
          background:C.surface, border:`1px solid ${C.border}`,
          borderRadius:8, padding:"12px 14px", marginBottom:8,
        }}>
          <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:6}}>
            <span style={{background:`${C.accent}22`, color:C.accent,
              border:`1px solid ${C.accent}44`, borderRadius:10,
              padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
            {chunk.inScope.length>0 && (
              <span style={{background:"#2E7D3218", color:"#2E7D32",
                border:"1px solid #2E7D3244", borderRadius:8,
                padding:"1px 6px", fontSize:9, fontWeight:600}}>
                IN SCOPE: {chunk.inScope.join(", ")}
              </span>
            )}
            {chunk.outOfScope.length>0 && (
              <span style={{background:"#F4433618", color:"#F44336",
                border:"1px solid #F4433644", borderRadius:8,
                padding:"1px 6px", fontSize:9, fontWeight:600}}>
                OUT OF SCOPE: {chunk.outOfScope.join(", ")}
              </span>
            )}
          </div>
          <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
            background:C.bg, padding:"8px 10px", borderRadius:6, border:`1px solid ${C.border}`,
            whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
            &ldquo;{chunk.excerpt}&rdquo;
          </div>
        </div>
      ))}
    </div>
  )}
</div>

  );
});
