// src/features/intelligence/tabs/MisconfigsTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown, ConfidenceBadge, EvidenceDrawer } from '../panelHelpers.jsx';
import { ATTACK_TECHNIQUES, CWE_DETAILS } from '../../../data/attack-data.js';
import { ShieldAlert, ChevronDown, ChevronRight, AlertCircle, CheckCircle2 } from '../../../icons.jsx';

export const MisconfigsTab = React.memo(function MisconfigsTab(ctx) {
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
    Misconfiguration Checks
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    Automated security configuration analysis of your Terraform resources — modeled after
    Checkov/tfsec rules. Each finding includes CWE weakness ID, ATT&CK technique, and remediation.
  </div>

  {/* 6A: LLM remediation plan */}
  {llmStatus === 'ready' && (
    <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
      {remediationPlan ? (
        <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
          <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI REMEDIATION PLAN</div>
          <div style={{ fontSize:12 }}>{renderMarkdown(remediationPlan)}</div>
          <button onClick={()=>setRemediationPlan('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
        </div>
      ) : (
        <button
          disabled={remediationLoading}
          onClick={async () => {
            setRemediationLoading(true);
            setRemediationPlan('');
            const allF = summary?.topMisconfigs||[];
            const critical = allF.filter(f=>f.severity==='Critical'||f.severity==='High').slice(0,10);
            const ctx = critical.map(f=>`- ${f.id} (${f.severity}): ${f.title} on ${f.resourceType||f.type}/${f.resourceName||f.name}. Fix: ${f.remediation||''}`).join('\n');
            await onGenerateLLM(
              [{ role:'system', content:'You are a Terraform security engineer. For each finding provide the specific HCL attribute to add/change and an example value. Format as a numbered list.' },
               { role:'user', content:`Generate a prioritized Terraform remediation plan for these ${critical.length} findings:\n${ctx}` }],
              tok => setRemediationPlan(prev=>prev+tok)
            );
            setRemediationLoading(false);
          }}
          style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
        >
          {remediationLoading ? 'Generating plan…' : '✦ Generate remediation plan with AI'}
        </button>
      )}
    </div>
  )}

  {(!parseResult?.resources?.length) ? (
    <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to run misconfiguration checks.</div>
  ) : !intelligence?._built ? (
    <div style={{color:C.textMuted, fontSize:13}}>Intelligence engine not ready.</div>
  ) : (() => {
    const sev=['Critical','High','Medium','Low'];
    const allFindings = (summary?.topMisconfigs||[]);
    if (allFindings.length===0) return (
      <div style={{background:C.surface,border:`1px solid #2E7D3244`,borderRadius:10,padding:"20px 22px"}}>
        <div style={{color:"#2E7D32",fontWeight:600,fontSize:14,marginBottom:6}}>No Misconfigurations Detected</div>
        <div style={{color:C.textSub,fontSize:12}}>All checked resources pass security configuration checks. Ensure resource attributes are fully defined in your Terraform files for complete analysis.</div>
      </div>
    );
    // Group by severity
    const bySev = {};
    allFindings.forEach(f=>{ if(!bySev[f.severity]) bySev[f.severity]=[]; bySev[f.severity].push(f); });
    return (
      <div>
        {/* Severity summary bar */}
        <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap"}}>
          {sev.map(s=>bySev[s]?.length ? (
            <div key={s} style={{background:`${SEV_COLOR[s]}18`,border:`1px solid ${SEV_COLOR[s]}44`,
              borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
              <span style={{fontSize:20,fontWeight:700,color:SEV_COLOR[s]}}>{bySev[s].length}</span>
              <span style={{fontSize:10,fontWeight:600,color:SEV_COLOR[s],textTransform:"uppercase",letterSpacing:".06em"}}>{s}</span>
            </div>
          ) : null)}
        </div>
        {/* Findings list grouped by severity */}
        {sev.filter(s=>bySev[s]?.length).map(s=>(
          <div key={s} style={{marginBottom:20}}>
            <div style={{fontSize:11,fontWeight:700,color:SEV_COLOR[s],textTransform:"uppercase",
              letterSpacing:".08em",marginBottom:10,display:"flex",alignItems:"center",gap:8}}>
              <span style={{width:8,height:8,borderRadius:"50%",background:SEV_COLOR[s],display:"inline-block"}}/>
              {s} ({bySev[s].length})
            </div>
            {bySev[s].map((f,i)=>{
              // SCP-mitigation check: is any attack vector blocked by an SCP?
              const SCP_TECH_ACTIONS = {
                'T1548':     ['iam:CreateRole','iam:AttachRolePolicy','iam:PutRolePolicy'],
                'T1078.004': ['iam:CreateUser','sts:AssumeRole'],
                'T1098.003': ['iam:CreateRole','iam:AttachRolePolicy'],
                'T1530':     ['s3:GetObject','s3:PutBucketAcl','s3:PutBucketPolicy'],
                'T1537':     ['s3:DeleteBucket'],
                'T1485':     ['s3:DeleteBucket','rds:DeleteDBInstance'],
                'T1562.008': ['cloudtrail:DeleteTrail','cloudtrail:StopLogging'],
                'T1600':     ['kms:DisableKey','kms:ScheduleKeyDeletion'],
                'T1190':     ['ec2:AuthorizeSecurityGroupIngress'],
              };
              const scpAccounts = computedIR?.scpCeilings ? Object.values(computedIR.scpCeilings) : [];
              const isScpMitigated = scpAccounts.length > 0 && (f.attack||[]).some(tech => {
                const actions = SCP_TECH_ACTIONS[tech] || [];
                return actions.length > 0 && scpAccounts.some(denied =>
                  actions.some(a => denied.some(p =>
                    p === a || p === '*' ||
                    (p.endsWith(':*') && a.startsWith(p.slice(0, -1)))
                  ))
                );
              });
              return (
              <div key={i} style={{background:C.surface,
                border:`1px solid ${isScpMitigated ? '#2E7D3244' : SEV_COLOR[f.severity]+'33'}`,
                borderLeft:`3px solid ${isScpMitigated ? '#2E7D32' : SEV_COLOR[f.severity]}`,
                borderRadius:8,padding:"12px 14px",marginBottom:8,
                opacity: isScpMitigated ? 0.75 : 1}}>
                <div style={{display:"flex",gap:8,alignItems:"flex-start",marginBottom:6,flexWrap:"wrap"}}>
                  <span style={{...MONO,fontSize:10,color:isScpMitigated ? '#2E7D32' : SEV_COLOR[f.severity],fontWeight:700,flexShrink:0}}>{f.id}</span>
                  <span style={{fontSize:12,color:C.text,fontWeight:600,flex:1}}>{f.title}</span>
                </div>
                <div style={{...MONO,fontSize:10,color:C.textMuted,marginBottom:8}}>
                  Resource: {f.resourceType}/{f.resourceName}
                  {f.paveLayer ? ` [${f.paveLayer}]` : ''}
                </div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
                  {(f.cwe||[]).map(c=>(
                    <span key={c} style={{position:'relative'}}>
                      <span
                        onClick={e=>{e.stopPropagation();setExpandedCwe(expandedCwe===c?null:c);}}
                        style={{background:"#0277BD18",color:"#0277BD",
                          border:"1px solid #0277BD44",borderRadius:6,padding:"1px 7px",fontSize:9,fontWeight:600,cursor:"pointer",display:"inline-block"}}
                        title="Click for details"
                      >{c}: {CWE_DETAILS[c]?.name||c}</span>
                      {expandedCwe===c && (
                        <div style={{ position:'absolute', zIndex:100, background:C.surface2, border:`1px solid ${C.border}`, borderRadius:6, padding:'8px 10px', maxWidth:280, fontSize:10, color:C.textSub, lineHeight:1.6, marginTop:2, boxShadow:'0 4px 16px #0006', top:'100%', left:0 }}>
                          <div style={{ fontWeight:700, color:C.text, marginBottom:3 }}>{c}: {CWE_DETAILS?.[c]?.name||c}</div>
                          <div>{CWE_DETAILS?.[c]?.desc||'Common Weakness Enumeration entry.'}</div>
                          <a href={`https://cwe.mitre.org/data/definitions/${c.replace('CWE-','')}.html`} target="_blank" rel="noopener noreferrer" style={{ fontSize:9, color:C.accent, marginTop:4, display:'block' }}>View on MITRE CWE ↗</a>
                        </div>
                      )}
                    </span>
                  ))}
                  {(f.attack||[]).map(t=>(
                    <span key={t}
                      onClick={()=>{ setITab('attacks'); setAttackFilter(t); }}
                      style={{background:"#E5393518",color:"#E53935",
                        border:"1px solid #E5393544",borderRadius:6,padding:"1px 7px",fontSize:9,fontWeight:600,cursor:"pointer"}}
                      title={`View ${t} in ATT&CK tab`}
                    >
                      {t} {ATTACK_TECHNIQUES[t]?.name||''}
                    </span>
                  ))}
                  {isScpMitigated && (
                    <span title="An SCP blocks the primary attack vector for this finding"
                      style={{background:"#1B5E2018",color:"#2E7D32",
                        border:"1px solid #2E7D3244",borderRadius:6,
                        padding:"1px 7px",fontSize:9,fontWeight:700}}>
                      SCP-Mitigated
                    </span>
                  )}
                </div>
                <div style={{fontSize:11,color:C.textSub,lineHeight:1.6,
                  background:C.bg,padding:"6px 10px",borderRadius:6,border:`1px solid ${C.border}`}}>
                  <span style={{color:C.textMuted,fontWeight:600}}>Remediation: </span>{f.remediation}
                </div>
                {/* ── Evidence row ── */}
                <div style={{display:'flex',gap:6,alignItems:'center',marginTop:6,flexWrap:'wrap'}}>
                  <ConfidenceBadge ev={f.evidence} />
                  {f.evidence?.method==='var_ref'&&(
                    <span style={{fontSize:9,color:'#F57C00',background:'#F57C0015',borderRadius:3,padding:'1px 4px',border:'1px solid #F57C0030',fontWeight:700}}>VAR UNRESOLVED</span>
                  )}
                  {isScpMitigated&&(
                    <span style={{fontSize:9,color:'#2E7D32',background:'#2E7D3215',borderRadius:3,padding:'1px 4px',border:'1px solid #2E7D3230',fontWeight:700}}>SCP MITIGATED</span>
                  )}
                  <EvidenceDrawer ev={f.evidence} label="attribute" />
                </div>
              </div>
              );
            })}
          </div>
        ))}
      </div>
    );
  })()}
</div>

  );
});
