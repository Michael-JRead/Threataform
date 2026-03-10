// src/features/intelligence/tabs/ArchLayersTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill } from '../panelHelpers.jsx';
import { generateTXTReport, generateMarkdownReport } from '../../../lib/diagram/ExportUtils.js';
import { Building2, Download, ChevronDown, ChevronRight, Shield, Layers, Cpu, ShieldCheck, Package, TriangleAlert, AlertCircle, CheckCircle2 } from '../../../icons.jsx';

export const ArchLayersTab = React.memo(function ArchLayersTab(ctx) {
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

<div style={{maxWidth:960}}>
  <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:4, gap:12}}>
    <div style={{fontSize:18, fontWeight:700, color:C.text}}>Architecture Layers</div>
    {archLayerAnalysis && (
      <div style={{display:"flex", gap:8, flexShrink:0}}>
        <button onClick={() => {
          try {
            const postureGrade = summary?.posture?.grade || summary?.grade;
            const tc = {
              grade: postureGrade,
              postureScore: summary?.posture?.score ?? summary?.postureScore,
              misconfigCount: summary?.misconfigCount || 0,
              topMisconfigs: (summary?.misconfigs || []).slice(0,3).map(m => m.check || m.title || m.id),
              attackTechniqueCount: summary?.attackTechniqueCount || 0,
              controlGapCount: summary?.controlInventory?.absent?.length || 0,
            };
            const txt = generateTXTReport(archLayerAnalysis, tc);
            const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([txt], {type:"text/plain"}));
            a.download = "architecture-report.txt"; a.click();
          } catch(err) { console.error('[Export TXT]', err); }
        }} style={{
          display:"flex", alignItems:"center", gap:5,
          background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
          padding:"5px 10px", color:C.textSub, fontSize:11, cursor:"pointer", ...SANS,
        }}>
          <Download size={12}/> .txt
        </button>
        <button onClick={() => {
          try {
            const postureGrade = summary?.posture?.grade || summary?.grade;
            const tc = {
              grade: postureGrade,
              postureScore: summary?.posture?.score ?? summary?.postureScore,
              misconfigCount: summary?.misconfigCount || 0,
              topMisconfigs: (summary?.misconfigs || []).slice(0,3).map(m => m.check || m.title || m.id),
              attackTechniqueCount: summary?.attackTechniqueCount || 0,
              controlGapCount: summary?.controlInventory?.absent?.length || 0,
            };
            const md = generateMarkdownReport(archLayerAnalysis, tc);
            const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([md], {type:"text/markdown"}));
            a.download = "architecture-report.md"; a.click();
          } catch(err) { console.error('[Export MD]', err); }
        }} style={{
          display:"flex", alignItems:"center", gap:5,
          background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
          padding:"5px 10px", color:C.textSub, fontSize:11, cursor:"pointer", ...SANS,
        }}>
          <Download size={12}/> .md
        </button>
      </div>
    )}
  </div>
  <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
    7-layer enterprise Terraform architecture model. Detects layer completeness, factory components,
    Sentinel policies, IAM modules, and compliance alignment across your uploaded files.
  </div>
  {!archLayerAnalysis ? (
    <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to generate architecture layer analysis.</div>
  ) : (() => {
    const a = archLayerAnalysis;
    const layers = a.layers || {};
    const factories = a.factories || {};
    const sentinel = a.sentinelPolicies || {};
    const compliance = a.compliance || {};
    const productModules = (a.productModules?.allModules || a.productModules?.detected || []);
    const recommendations = a.recommendations || [];
    const security = a.security || {};
    const archGrade = a.architectureGrade || 'N/A';

    const LAYER_NAMES = {1:"Foundation",2:"Platform Factory",3:"IAM Management",4:"Network Boundary",5:"Security Controls",6:"Product Module",7:"Application"};
    const LAYER_COLORS = {1:"#546E7A",2:"#1565C0",3:"#AD1457",4:"#2E7D32",5:"#E65100",6:"#6A1B9A",7:"#00838F"};

    return (
      <div style={{display:"flex", flexDirection:"column", gap:18}}>

        {/* Architecture grade hero */}
        <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, padding:"16px 20px", display:"flex", alignItems:"center", gap:20}}>
          <div style={{textAlign:"center"}}>
            <div style={{fontSize:52, fontWeight:900, color: archGrade==='A'?"#43A047":archGrade==='B'?"#8BC34A":archGrade==='C'?"#F57C00":archGrade==='D'?"#E53935":"#B71C1C", lineHeight:1}}>{archGrade}</div>
            <div style={{fontSize:10, color:C.textMuted, marginTop:2}}>Arch Grade</div>
          </div>
          <div style={{flex:1}}>
            <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:6}}>Enterprise Architecture Assessment</div>
            <div style={{display:"flex", gap:12, flexWrap:"wrap"}}>
              {[
                {label:"Layers Present", value:`${Object.values(layers).filter(l=>(l.completeness||0)>0).length}/7`},
                {label:"Factories", value:`${Object.values(factories).filter(f=>f.status!=='missing').length}/${Object.keys(factories).length}`},
                {label:"Sentinel Files", value:String(sentinel.totalCount||0)},
                {label:"Compliance Avg", value:`${Math.round(((compliance.sox||0)+(compliance.pci||0)+(compliance.gdpr||0)+(compliance.hipaa||0))/4)}%`},
              ].map(({label,value})=>(
                <div key={label} style={{background:C.surface2, border:`1px solid ${C.border}`, borderRadius:6, padding:"6px 12px"}}>
                  <div style={{fontSize:18, fontWeight:700, color:C.accent}}>{value}</div>
                  <div style={{fontSize:10, color:C.textMuted}}>{label}</div>
                </div>
              ))}
            </div>
          </div>
          {security.overall !== undefined && (
            <div style={{textAlign:"center", minWidth:60}}>
              <div style={{fontSize:28, fontWeight:800, color: security.overall>=80?"#43A047":security.overall>=50?"#F57C00":"#E53935"}}>{security.overall}</div>
              <div style={{fontSize:10, color:C.textMuted}}>Security Score</div>
            </div>
          )}
        </div>

        {/* Layer completeness table */}
        <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
          <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
            <Layers size={14} style={{color:C.accent}}/>
            <span style={{fontSize:13, fontWeight:700, color:C.text}}>Layer Completeness</span>
            <span style={{fontSize:11, color:C.textMuted, marginLeft:"auto"}}>
              {Object.values(layers).filter(l=>(l.completeness||0)>=80).length} complete · {Object.values(layers).filter(l=>(l.completeness||0)>0&&(l.completeness||0)<80).length} partial · {Object.values(layers).filter(l=>(l.completeness||0)===0).length} missing
            </span>
          </div>
          <div>
            {[1,2,3,4,5,6,7].map(num => {
              const layer = layers[num] || {};
              const pct = Math.min(100, Math.round(layer.completeness || 0));
              const color = LAYER_COLORS[num];
              const statusColor = pct>=80?"#43A047":pct>=40?"#F57C00":"#B71C1C";
              const statusLabel = pct>=80?"COMPLETE":pct>=40?"PARTIAL":"MISSING";
              return (
                <div key={num} style={{padding:"10px 16px", borderBottom:`1px solid ${C.border}22`, display:"flex", alignItems:"center", gap:12, background:`${color}05`}}>
                  <div style={{width:26,height:26,borderRadius:6,background:`${color}20`,border:`1px solid ${color}50`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                    <span style={{fontSize:11,fontWeight:700,color}}>{num}</span>
                  </div>
                  <div style={{flex:1, minWidth:0}}>
                    <div style={{display:"flex", alignItems:"center", gap:6, marginBottom:4}}>
                      <span style={{fontSize:12, fontWeight:600, color:C.text}}>L{num} — {LAYER_NAMES[num]}</span>
                      <span style={{fontSize:9,fontWeight:700,background:`${statusColor}15`,color:statusColor,border:`1px solid ${statusColor}40`,borderRadius:4,padding:"1px 6px"}}>{statusLabel}</span>
                      {layer.presentModules?.length > 0 && (
                        <span style={{fontSize:9,color:C.textMuted}}>· {layer.presentModules.slice(0,3).join(', ')}{layer.presentModules.length>3?` +${layer.presentModules.length-3}`:''}</span>
                      )}
                    </div>
                    <div style={{height:4,background:C.surface2,borderRadius:2,overflow:"hidden"}}>
                      <div style={{height:"100%",width:`${pct}%`,background:statusColor,borderRadius:2,transition:"width .3s"}}/>
                    </div>
                  </div>
                  <span style={{fontSize:13,fontWeight:700,color:statusColor,minWidth:38,textAlign:"right"}}>{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Factory + Sentinel row */}
        <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:14}}>
          {/* Factory Components */}
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
            <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
              <Cpu size={14} style={{color:"#1565C0"}}/>
              <span style={{fontSize:13,fontWeight:700,color:C.text}}>Factory Components</span>
              <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>{Object.values(factories).filter(f=>f.status!=='missing').length}/{Object.keys(factories).length} detected</span>
            </div>
            <div style={{padding:"8px 0"}}>
              {Object.keys(factories).length === 0 ? (
                <div style={{padding:"8px 16px",fontSize:12,color:C.textMuted}}>No factory components analyzed</div>
              ) : Object.entries(factories).map(([fname, fdata]) => (
                <div key={fname} style={{padding:"8px 16px",borderBottom:`1px solid ${C.border}22`,display:"flex",alignItems:"flex-start",gap:8}}>
                  <div style={{width:8,height:8,borderRadius:"50%",flexShrink:0,marginTop:4,background:fdata.status==='present'?"#43A047":fdata.status==='partial'?"#F57C00":"#B71C1C"}}/>
                  <div style={{flex:1,minWidth:0}}>
                    <span style={{fontSize:11,color:C.text,fontWeight:500}}>{fname.replace(/-factory$/,'')}</span>
                    {fdata.status==='partial' && fdata.securityFindings?.length > 0 && (
                      <div style={{fontSize:9,color:"#F57C00",marginTop:2,lineHeight:1.4}}>{fdata.securityFindings[0].replace('WARNING: ','')}</div>
                    )}
                  </div>
                  <span style={{fontSize:9,fontWeight:700,color:fdata.status==='present'?"#43A047":fdata.status==='partial'?"#F57C00":"#B71C1C",background:`${fdata.status==='present'?"#43A047":fdata.status==='partial'?"#F57C00":"#B71C1C"}15`,border:`1px solid ${fdata.status==='present'?"#43A04740":fdata.status==='partial'?"#F57C0040":"#B71C1C40"}`,borderRadius:4,padding:"1px 6px",flexShrink:0}}>{fdata.status?.toUpperCase()||"ABSENT"}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Sentinel + Compliance */}
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {/* Sentinel */}
            <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
              <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
                <Shield size={14} style={{color:"#E65100"}}/>
                <span style={{fontSize:13,fontWeight:700,color:C.text}}>Sentinel Policies</span>
                <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>{sentinel.totalCount||0} files</span>
              </div>
              <div style={{padding:"10px 16px"}}>
                {(sentinel.totalCount||0) > 0 ? (
                  <div style={{display:"flex",flexDirection:"column",gap:6}}>
                    <div style={{fontSize:11,color:C.textSub}}>
                      <span style={{color:"#43A047",fontWeight:600}}>{sentinel.totalCount}</span> policy file{sentinel.totalCount!==1?"s":""} · {Math.round((sentinel.coverage||0)*100)}% type coverage
                    </div>
                    {sentinel.policyTypes && (
                      <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
                        {Object.entries(sentinel.policyTypes).filter(([,arr])=>arr.length>0).map(([t])=>(
                          <span key={t} style={{fontSize:9,background:"#E6510015",color:"#E65100",border:"1px solid #E6510040",borderRadius:4,padding:"2px 6px"}}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{fontSize:11,color:C.textMuted}}>No Sentinel .sentinel files detected — policy-as-code absent</div>
                )}
              </div>
            </div>

            {/* Compliance */}
            <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden", flex:1}}>
              <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
                <CheckCircle2 size={14} style={{color:"#43A047"}}/>
                <span style={{fontSize:13,fontWeight:700,color:C.text}}>Compliance</span>
                {compliance.overall !== undefined && <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>Overall {compliance.overall}%</span>}
              </div>
              <div style={{padding:"6px 0"}}>
                {[["SOX", compliance.sox],["PCI DSS", compliance.pci],["GDPR", compliance.gdpr],["HIPAA", compliance.hipaa]].map(([framework, score]) => {
                  if (score === undefined) return null;
                  const color = score>=80?"#43A047":score>=50?"#F57C00":"#B71C1C";
                  return (
                    <div key={framework} style={{padding:"6px 16px",display:"flex",alignItems:"center",gap:8,borderBottom:`1px solid ${C.border}22`}}>
                      <span style={{fontSize:11,fontWeight:600,color:C.text,minWidth:60}}>{framework}</span>
                      <div style={{flex:1,height:4,background:C.surface2,borderRadius:2,overflow:"hidden"}}>
                        <div style={{height:"100%",width:`${score}%`,background:color,borderRadius:2}}/>
                      </div>
                      <span style={{fontSize:11,color,fontWeight:700,minWidth:38,textAlign:"right"}}>{score}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Security domain scores */}
        {security.overall !== undefined && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
            <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
              <ShieldCheck size={14} style={{color:C.accent}}/>
              <span style={{fontSize:13,fontWeight:700,color:C.text}}>Security Domain Scores</span>
            </div>
            <div style={{padding:"12px 16px", display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10}}>
              {[
                ["SCP / Org Policy", security.scpInheritance],
                ["Network Security", security.networkSecurity],
                ["IAM Governance", security.iamGovernance],
                ["Data Protection", security.dataProtection],
                ["Sentinel Coverage", security.sentinelCoverage],
                ["Audit Logging", security.auditLogging],
              ].map(([label,score]) => {
                if (score===undefined) return null;
                const color = score>=70?"#43A047":score>=40?"#F57C00":"#E53935";
                return (
                  <div key={label} style={{background:C.surface2,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 12px"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:5}}>
                      <span style={{fontSize:11,color:C.textSub,fontWeight:500}}>{label}</span>
                      <span style={{fontSize:15,fontWeight:800,color}}>{score}</span>
                    </div>
                    <div style={{height:3,background:C.bg,borderRadius:2,overflow:"hidden"}}>
                      <div style={{height:"100%",width:`${score}%`,background:color,borderRadius:2}}/>
                    </div>
                  </div>
                );
              })}
            </div>
            {security.criticalIssues?.length > 0 && (
              <div style={{borderTop:`1px solid ${C.border}`, padding:"10px 16px"}}>
                <div style={{fontSize:11,fontWeight:700,color:"#B71C1C",marginBottom:6}}>Critical Security Issues</div>
                {security.criticalIssues.map((issue,i)=>(
                  <div key={i} style={{fontSize:11,color:C.textSub,padding:"3px 0",borderBottom:i<security.criticalIssues.length-1?`1px solid ${C.border}22`:"none"}}>
                    <span style={{color:"#E53935",marginRight:6}}>✕</span>{issue}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Product modules */}
        {productModules.length > 0 && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
            <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
              <Package size={14} style={{color:"#6A1B9A"}}/>
              <span style={{fontSize:13,fontWeight:700,color:C.text}}>Detected Product Modules</span>
              <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>{productModules.length} candidates</span>
            </div>
            <div style={{padding:"12px 16px", display:"flex", flexDirection:"column", gap:8}}>
              {productModules.map((pm,pi)=>(
                <div key={pi} style={{background:C.surface2,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 14px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:pm.awsServices?.length>0?4:0}}>
                    <span style={{fontSize:12,fontWeight:700,color:C.text}}>{pm.name}</span>
                    {pm.serviceType && <span style={{fontSize:9,background:"#6A1B9A15",color:"#6A1B9A",border:"1px solid #6A1B9A40",borderRadius:4,padding:"2px 6px"}}>{pm.serviceType}</span>}
                    <span style={{fontSize:9,color:C.textMuted,marginLeft:"auto"}}>{pm.fileCount||0} files · {Math.round((pm.confidence||0)*100)}% conf</span>
                  </div>
                  {pm.awsServices?.length > 0 && <div style={{fontSize:10,color:C.textMuted}}>Services: {pm.awsServices.slice(0,5).join(', ')}</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {recommendations.length > 0 && (
          <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:10, overflow:"hidden"}}>
            <div style={{background:C.surface2, padding:"10px 16px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:8}}>
              <TriangleAlert size={14} style={{color:"#F57C00"}}/>
              <span style={{fontSize:13,fontWeight:700,color:C.text}}>Architecture Recommendations</span>
              <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>{recommendations.length} items</span>
            </div>
            <div style={{padding:"0", display:"flex", flexDirection:"column", gap:0}}>
              {recommendations.slice(0,15).map((rec,ri)=>{
                const sev = (rec.priority||rec.severity||"MEDIUM").toUpperCase();
                const sevColor = {CRITICAL:"#B71C1C",HIGH:"#E53935",MEDIUM:"#F57C00",LOW:"#43A047"}[sev]||"#F57C00";
                return (
                  <div key={ri} style={{padding:"10px 16px",borderBottom:`1px solid ${C.border}22`,display:"flex",gap:10,alignItems:"flex-start"}}>
                    <span style={{fontSize:9,fontWeight:700,background:`${sevColor}15`,color:sevColor,border:`1px solid ${sevColor}40`,borderRadius:4,padding:"2px 6px",flexShrink:0,marginTop:1}}>{sev}</span>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12,color:C.text,fontWeight:600,marginBottom:2}}>{rec.title||rec.message}</div>
                      {rec.action && <div style={{fontSize:11,color:C.textMuted,lineHeight:1.5}}>{rec.action}</div>}
                      {rec.attackTechniques?.length > 0 && (
                        <div style={{marginTop:4,display:"flex",gap:4,flexWrap:"wrap"}}>
                          {rec.attackTechniques.map(t=>(
                            <span key={t} style={{fontSize:9,background:"#E5393514",color:"#E53935",border:"1px solid #E5393530",borderRadius:4,padding:"1px 5px"}}>{t}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              {recommendations.length > 15 && (
                <div style={{padding:"8px 16px",fontSize:11,color:C.textMuted}}>+{recommendations.length-15} more recommendations</div>
              )}
            </div>
          </div>
        )}

        {/* Compliance violations */}
        {compliance.violations?.length > 0 && (
          <div style={{background:C.surface, border:`1px solid #B71C1C30`, borderRadius:10, overflow:"hidden"}}>
            <div style={{background:"#B71C1C10", padding:"10px 16px", borderBottom:`1px solid #B71C1C30`, display:"flex", alignItems:"center", gap:8}}>
              <AlertCircle size={14} style={{color:"#B71C1C"}}/>
              <span style={{fontSize:13,fontWeight:700,color:"#B71C1C"}}>Compliance Violations</span>
              <span style={{fontSize:11,color:C.textMuted,marginLeft:"auto"}}>{compliance.violations.length} critical failures</span>
            </div>
            <div style={{padding:"0"}}>
              {compliance.violations.slice(0,8).map((v,vi)=>(
                <div key={vi} style={{padding:"8px 16px",borderBottom:`1px solid ${C.border}22`,display:"flex",gap:8,alignItems:"flex-start"}}>
                  <span style={{fontSize:9,fontWeight:700,background:"#B71C1C15",color:"#B71C1C",border:"1px solid #B71C1C40",borderRadius:4,padding:"1px 6px",flexShrink:0}}>{v.framework}</span>
                  <div>
                    <span style={{fontSize:10,color:C.accent,...MONO,marginRight:6}}>{v.id}</span>
                    <span style={{fontSize:11,color:C.textSub}}>{v.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  })()}
</div>

  );
});
