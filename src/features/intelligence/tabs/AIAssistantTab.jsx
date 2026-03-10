// src/features/intelligence/tabs/AIAssistantTab.jsx
import React from 'react';
import { C, MONO, SANS } from '../../../constants/styles.js';
import { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill, renderMarkdown, chunkCard } from '../panelHelpers.jsx';
import { wllamaManager } from '../../../lib/WllamaManager.js';
import { mcpRegistry } from '../../../lib/mcp/MCPToolRegistry.js';
import { ARCH_QUICK_PROMPTS } from '../../../lib/ThrataformRAG.js';
import { KB } from '../../../data/kb-domains.js';
import { createInferenceTracker, LOG } from '../../../lib/observability.js';
import { Bot, Send, Loader2, X, RefreshCw, Upload, Search, Plug, Info, CheckCircle, XCircle, ChevronDown, ChevronUp, Download, Users, FileText, RotateCcw } from '../../../icons.jsx';

export const AIAssistantTab = React.memo(function AIAssistantTab(ctx) {
  const { summary, parseResult, userDocs, llmStatus, onGenerateLLM, onHybridSearch,
    intelligence, computedIR, archLayerAnalysis,
    modelDetails, archAnalysis, archOverrides, selectedLlmModel, embedStatus, embedProgress,
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


const QUICK_PROMPTS = [
  "What are the top STRIDE threats in this architecture?",
  "Identify security gaps and missing controls",
  "Map findings to MITRE ATT&CK techniques",
  "Summarize trust boundary violations",
  "Generate an executive security summary",
  "What compliance gaps exist for our frameworks?",
  "List the highest-risk Terraform misconfigurations",
  "What data flows cross trust boundaries?",
  ...(archLayerAnalysis ? (ARCH_QUICK_PROMPTS || []) : []),
];

// ── Build full intelligence context for LLM (PrivateGPT approach) ──────
const buildFullContext = async (userText) => {
  // 1. Hybrid semantic + keyword search
  const contextChunks = onHybridSearch ? await onHybridSearch(userText, 20) : [];
  const retrievedCtx = contextChunks.length
    ? contextChunks.map((c,i) =>
        `[DOC-${i+1}] File: ${c.source||c.docId||'doc'} | Category: ${c.category||'general'}\n${c.text}`
      ).join("\n\n")
    : "No indexed documents available yet.";

  // 2. Model metadata
  const md = modelDetails || {};
  const metaLines = [
    md.productName || summary?.productName ? `Product: ${md.productName || summary?.productName}` : null,
    md.environment || summary?.environment   ? `Environment: ${md.environment || summary?.environment}` : null,
    md.dataClassification?.length ? `Data Classification: ${md.dataClassification.join(', ')}` : null,
    md.frameworks?.length         ? `Compliance Frameworks: ${md.frameworks.join(', ')}` : null,
    md.owner                      ? `Owner: ${md.owner}` : null,
    md.description                ? `Architecture: ${md.description.substring(0, 300)}` : null,
  ].filter(Boolean);

  // 3. Security posture
  const posture = summary?.posture;
  const postureCtx = posture
    ? `Security Posture: ${posture.grade} (${posture.score}/100) — ${posture.maturity}\nTop risks: ${(posture.topRisks||[]).slice(0,3).join('; ')}`
    : null;

  // 4. Control inventory gaps
  const inv = summary?.controlInventory;
  const invCtx = inv ? [
    inv.present?.length ? `Present controls (${inv.present.length}): ${inv.present.slice(0,8).map(c=>c.name||c).join(', ')}` : null,
    inv.absent?.length  ? `Control GAPS (${inv.absent.length}): ${inv.absent.slice(0,8).map(c=>c.name||c).join(', ')}` : null,
  ].filter(Boolean).join('\n') : null;

  // 5. Misconfigurations
  const misconfigCtx = summary?.misconfigCount
    ? `Misconfigurations detected: ${summary.misconfigCount} (check Misconfig Checks tab for details)`
    : null;

  // 6. ATT&CK techniques
  const attackCtx = summary?.attackTechniqueCount
    ? `MITRE ATT&CK techniques detected: ${summary.attackTechniqueCount}`
    : null;

  // 7. Scope
  const scopeChunks = summary?.scopeChunks || [];
  const scopeCtx = scopeChunks.length
    ? `Scope references found:\n${scopeChunks.slice(0,4).map(c=>c.text?.substring(0,120)).join('\n')}`
    : null;

  // 8. Architecture analysis overrides
  const archCtx = archAnalysis?.summary || archOverrides?.narrative?.description
    ? `Architecture analysis: ${(archAnalysis?.summary || archOverrides?.narrative?.description||'').substring(0,400)}`
    : null;

  // 9. Terraform resources summary
  const resources = parseResult?.resources || [];
  const resCtx = resources.length
    ? `IaC resources (${resources.length}): ${[...new Set(resources.map(r=>r.type))].slice(0,12).join(', ')}`
    : null;

  // 10. IaC-IR: Organization Hierarchy
  const orgCtx = computedIR?.organizationTree ? (() => {
    const t = computedIR.organizationTree;
    const lines = [`Root${t.root?.scps?.length ? ` (SCPs: ${t.root.scps.join(', ')})` : ''}`];
    (t.ous || []).slice(0, 10).forEach(ou =>
      lines.push(`  OU: ${ou.name || ou.id} [${ou.paveLayer || '?'}] — SCPs: ${(ou.scps||[]).join(', ')||'none'}`)
    );
    (t.accounts || []).slice(0, 15).forEach(acc =>
      lines.push(`    Account: ${acc.name || acc.id} [${acc.paveLayer || '?'}]`)
    );
    if (t.gaps?.length) lines.push(`Gaps: ${t.gaps.slice(0, 3).join('; ')}`);
    return lines.join('\n');
  })() : null;

  // 11. IaC-IR: SCP Ceiling (denied actions)
  const scpCtx = computedIR?.scpCeilings && Object.keys(computedIR.scpCeilings).length ? (() => {
    const entries = Object.entries(computedIR.scpCeilings).slice(0, 5);
    return entries.map(([acct, actions]) =>
      `Account ${acct}: ${actions.slice(0, 6).join(', ')}`
    ).join('\n');
  })() : null;

  // 12. IaC-IR: Effective IAM Analysis
  const iamCtx = (() => {
    const roles = resources.filter(r => r.type === 'aws_iam_role' || r.type === 'AWS::IAM::Role');
    if (!roles.length) return null;
    const wildcardRoles = roles.filter(r => {
      const body = r.body || '';
      return body.includes('"Action":"*"') || body.includes('"Action":["*"]') ||
        (r.cfnProps?.Policies||[]).some(p => JSON.stringify(p).includes('"*"'));
    });
    const noBoundary = roles.filter(r =>
      r.isCFN ? !r.cfnProps?.PermissionsBoundary : !(r.body||'').includes('permissions_boundary')
    );
    return [
      `${roles.length} IAM roles detected across ${new Set(roles.map(r=>r.paveLayer).filter(Boolean)).size} pave layers`,
      wildcardRoles.length ? `${wildcardRoles.length} roles with wildcard actions (*) — FLAGGED` : null,
      noBoundary.length   ? `${noBoundary.length} roles missing permission boundary — FLAGGED` : null,
      computedIR?.gaps?.length ? `${computedIR.gaps.length} IAM/org analysis gaps (intrinsic references)` : null,
    ].filter(Boolean).join('\n');
  })();

  const sections = [
    metaLines.length ? `=== MODEL CONTEXT ===\n${metaLines.join('\n')}` : null,
    postureCtx ? `=== SECURITY POSTURE ===\n${postureCtx}` : null,
    invCtx     ? `=== CONTROL INVENTORY ===\n${invCtx}` : null,
    misconfigCtx ? `=== MISCONFIGURATIONS ===\n${misconfigCtx}` : null,
    attackCtx  ? `=== ATT&CK COVERAGE ===\n${attackCtx}` : null,
    scopeCtx   ? `=== SCOPE ===\n${scopeCtx}` : null,
    archCtx    ? `=== ARCHITECTURE ===\n${archCtx}` : null,
    orgCtx     ? `=== ORG HIERARCHY ===\n${orgCtx}` : null,
    scpCtx     ? `=== POLICY CEILING (INFEASIBLE ACTIONS) ===\nActions blocked by SCP:\n${scpCtx}` : null,
    iamCtx     ? `=== EFFECTIVE IAM ANALYSIS ===\n${iamCtx}` : null,
    resCtx     ? `=== IaC RESOURCES ===\n${resCtx}` : null,
    archLayerAnalysis ? (
      Object.entries(archLayerAnalysis.layers || {}).length > 0 ? (
        '=== ARCH LAYER ANALYSIS ==='+'\n' +
        'Grade: ' + (archLayerAnalysis.architectureGrade || 'N/A') + '\n' +
        Object.entries(archLayerAnalysis.layers || {}).map(([n, l]) =>
          n + ': ' + Math.round((l.completeness||0)*100) + '% complete').join('\n') +
        (archLayerAnalysis.recommendations && archLayerAnalysis.recommendations.length ?
          '\nRecommendations:\n' + archLayerAnalysis.recommendations.map(r => '  - ' + r).join('\n') : '')
      ) : null
    ) : null,
    summary && summary.topMisconfigs && summary.topMisconfigs.length ? (
      '=== ALL MISCONFIGS: ' + summary.topMisconfigs.length + '\n' +
      summary.topMisconfigs.map((m, i) => '[' + (i+1) + '] ' + (m.resource || m.type || 'resource') + ' -- ' + (m.issue || m.title || m.description || '') + (m.remediation ? ' | Fix: ' + m.remediation : '')).join('\n')
    ) : null,
    summary && summary.controlInventory && summary.controlInventory.absent && summary.controlInventory.absent.length ? (
      '=== CONTROL GAPS: ' + summary.controlInventory.absent.length + '\n' +
      summary.controlInventory.absent.map(c => '- ' + (c.name || c) + (c.description ? ': ' + c.description : '')).join('\n')
    ) : null,
    `=== RETRIEVED DOCUMENT CONTEXT (semantic+keyword) ===\n${retrievedCtx}`,
  ].filter(Boolean).join('\n\n');

  return { sections, contextChunks };
};

// ── Pure offline intelligence response (no LLM, no internet) ─────────────
const generateSmartResponse = async (userText) => {
  const intel = intelligence;
  const resources = parseResult?.resources || [];
  const q = userText.toLowerCase();
  const out = [];

  // B5: invoke built-in MCP tools directly (no LLM or external server needed)
  const cvssVec = userText.match(/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/i);
  if (cvssVec) {
    try {
      const r = await mcpRegistry.invoke("score_cvss", { vector: cvssVec[0] });
      out.push(`**CVSS Score:**\n${typeof r === 'string' ? r : JSON.stringify(r, null, 2)}`);
    } catch(_) {}
  }
  const attckId = userText.match(/\bT\d{4}(?:\.\d{3})?\b/i);
  if (attckId || /att.?ck.*technique|mitre.*lookup/i.test(q)) {
    try {
      const r = await mcpRegistry.invoke("lookup_mitre", { query: attckId?.[0] || userText.slice(0, 80) });
      out.push(`**MITRE ATT&CK:**\n${typeof r === 'string' ? r : JSON.stringify(r, null, 2)}`);
    } catch(_) {}
  }
  const fwMatch = /\b(hipaa|pci(?:-?dss)?|soc\s?2|fedramp|gdpr|cmmc|sox)\b/i.exec(q);
  if (fwMatch && /compli|check|gap|require|certif/i.test(q)) {
    try {
      const fw = fwMatch[1].toLowerCase().replace(/[^a-z0-9]/g, '').replace('pcidss','pci').replace('soc2','soc2');
      const r = await mcpRegistry.invoke("check_compliance", { framework: fw, resource_type: resources[0]?.type || 'aws_s3_bucket' });
      out.push(`**Compliance Check (${fwMatch[1].toUpperCase()}):**\n${typeof r === 'string' ? r : JSON.stringify(r, null, 2)}`);
    } catch(_) {}
  }

  const isThreats    = /\b(threat|attack|stride|risk|vulnerabilit|exploit|mitre|att.?ck|adversar|malware|breach)\b/.test(q);
  const isControls   = /\b(control|compliance|policy|framework|nist|pci|hipaa|soc|fedramp|gdpr|cmmc|requirement|standard|audit)\b/.test(q);
  const isMisconfig  = /\b(misconfig|finding|issue|problem|fix|remediat|harden|insecure|weak|misconfigur)\b/.test(q);
  const isPosture    = /\b(posture|score|grade|maturity|gap|weakness|overall|summary|overview|status)\b/.test(q);
  const isArch       = /\b(architect|infrastructure|component|service|resource|terraform|vpc|network|topology|deploy)\b/.test(q);
  const isScope      = /\b(scope|boundar|in.scope|out.of.scope|asset|perimeter)\b/.test(q);
  const isCompliance = /\b(complian|regulator|certif|audit|soc2|hipaa|pci|fedramp|gdpr)\b/.test(q);
  const isArchLayers   = /\b(layer|foundation|factory|sentinel|platform|pave|hierarchy)\b/.test(q);
  const isExport       = /\b(export|report|download|drawio|lucid|pdf|markdown)\b/.test(q);
  const isRemediation  = /\b(fix|remediat|resolve|mitigat|patch|harden)\b/.test(q);
  const isResources    = /\b(ec2|s3|rds|lambda|list resource|all resource|resource count)\b/.test(q);
  const isTrustBdry    = /trust boundary|network zone|segmentation|dmz/.test(q);
  const isDataFlow     = /data flow|connection path|traffic flow|ingress|egress/.test(q);

  // Always run BM25 retrieval
  const retrieved = intel._built ? intel.query(userText, 8) : [];

  // Security Posture
  if (isPosture || (!isThreats && !isControls && !isMisconfig && !isScope && !isArch)) {
    try {
      const sum = intel.getSummary(resources);
      if (sum?.posture) {
        const p = sum.posture;
        out.push(`**Security Posture: ${p.grade} — ${p.score}/100 (${p.maturity})**`);
        if (p.topRisks?.length) out.push(`Top risks:\n${p.topRisks.slice(0,5).map(r=>`• ${r}`).join('\n')}`);
        if (sum.misconfigCount) out.push(`⚠ ${sum.misconfigCount} Terraform misconfiguration${sum.misconfigCount>1?'s':''} detected.`);
        if (sum.controlInventory) {
          out.push(`Controls: ${sum.controlInventory.present?.length||0} present, ${sum.controlInventory.absent?.length||0} gaps identified.`);
        }
      }
    } catch(_) {}
  }

  // Threats & STRIDE
  if (isThreats) {
    try {
      const sum = intel.getSummary(resources);
      if (sum?.threatChunks?.length) {
        out.push(`**Threat findings from uploaded documents (${sum.threatChunks.length} total):**`);
        sum.threatChunks.slice(0,5).forEach((c,i) => {
          const snippet = c.text.substring(0,130).trim();
          out.push(`**[${i+1}]** ${snippet}…\n_Source: ${c.source||c.category||'doc'}_`);
        });
      }
      if (sum?.attackTechniqueCount) {
        out.push(`**MITRE ATT&CK:** ${sum.attackTechniqueCount} technique(s) detected across uploaded documents.`);
      }
    } catch(_) {}
    // STRIDE from retrieved chunks
    const strideChunks = retrieved.filter(c => Object.keys(c.entities?.stride||{}).length > 0);
    if (strideChunks.length) {
      const techniqueSet = new Set();
      strideChunks.forEach(c => Object.keys(c.entities.stride||{}).forEach(k => techniqueSet.add(k)));
      out.push(`**STRIDE categories present:** ${[...techniqueSet].map(k=>({ S:'Spoofing', T:'Tampering', R:'Repudiation', I:'Info Disclosure', D:'Denial of Service', E:'Elevation of Privilege' }[k]||k)).join(', ')}`);
    }
  }

  // Controls & Compliance
  if (isControls || isCompliance) {
    try {
      const inv = intel.getControlInventory(resources);
      if (inv) {
        out.push(`**Control Inventory: ${inv.present.length} present / ${inv.absent.length} gaps**`);
        if (inv.absent.length) {
          out.push(`**Critical control gaps:**\n${inv.absent.slice(0,8).map(c=>`• ${c.name}`).join('\n')}`);
        }
        const docControls = inv.present.filter(c=>c.source==='doc'||c.source==='scm');
        if (docControls.length) {
          out.push(`**From uploaded security docs (${docControls.length}):**\n${docControls.slice(0,6).map(c=>`• ${c.name}`).join('\n')}`);
        }
      }
    } catch(_) {}
  }

  // Misconfigurations
  if (isMisconfig) {
    try {
      const misconfigs = intel.getMisconfigurations?.(resources) || [];
      if (misconfigs.length) {
        out.push(`**${misconfigs.length} Terraform misconfigurations:**`);
        misconfigs.slice(0,8).forEach(m => out.push(`• **${m.resource||m.type}** — ${m.issue||m.description}`));
      } else {
        out.push('No Terraform misconfigurations detected. Upload .tf files for analysis.');
      }
    } catch(_) {}
  }

  // Architecture & Resources
  if (isArch) {
    if (resources.length) {
      const typeCounts = {};
      resources.forEach(r => { const t = r.type; typeCounts[t]=(typeCounts[t]||0)+1; });
      const topTypes = Object.entries(typeCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);
      out.push(`**Terraform resources (${resources.length} total):**\n${topTypes.map(([t,n])=>`• ${t}${n>1?` ×${n}`:''}`).join('\n')}`);
    }
  }

  // Scope
  if (isScope) {
    try {
      const sum = intel.getSummary(resources);
      if (sum?.scopeChunks?.length) {
        out.push(`**Scope references (${sum.scopeChunks.length}):**`);
        sum.scopeChunks.slice(0,5).forEach(c => out.push(`• ${c.text.substring(0,120).trim()}\n  _${c.source||c.category||'doc'}_`));
      }
    } catch(_) {}
  }


  // B3: Architecture Layers intent
  if (isArchLayers && archLayerAnalysis) {
    try {
      const grade = archLayerAnalysis.architectureGrade || 'N/A';
      const allLayers = Object.entries(archLayerAnalysis.layers || {});
      const presentL = allLayers.filter(([,l]) => l.completeness > 0);
      const missingL = allLayers.filter(([,l]) => l.completeness === 0);
      const fpCount = Object.values(archLayerAnalysis.factories || {}).filter(f => f.status !== 'missing').length;
      const ftCount = Object.keys(archLayerAnalysis.factories || {}).length;
      out.push('**Architecture Layer Analysis**');
      out.push('Grade: ' + grade + ' | Factories: ' + fpCount + '/' + ftCount + ' | Sentinel: ' + (archLayerAnalysis.sentinelPolicies?.totalCount || 0) + ' policies');
      if (presentL.length) out.push('Present layers (' + presentL.length + '):\n' + presentL.map(([n,l]) => '  - ' + n + ': ' + Math.round((l.completeness||0)*100) + '% complete (' + (l.resources||[]).length + ' resources)').join('\n'));
      if (missingL.length) out.push('Missing layers (' + missingL.length + '):\n' + missingL.map(([n]) => '  - ' + n).join('\n'));
      if (archLayerAnalysis.recommendations?.length) out.push('Recommendations:\n' + archLayerAnalysis.recommendations.map(r => '  - ' + r).join('\n'));
    } catch(_) {}
  }
  // B3: Export options intent
  if (isExport) {
    out.push('**Available export formats:**');
    out.push('  - DrawIO XML: click Download DrawIO in the toolbar — imports directly into Diagrams.net / Lucidchart');
    out.push('  - Lucid JSON: click Download Lucid for Lucidchart native format');
    out.push('  - Text Report (.txt): full findings summary with misconfigs, controls, posture score');
    out.push('  - Markdown Report (.md): formatted threat model document suitable for GitHub / Confluence');
    out.push('All exports are generated client-side — no data leaves your browser.');
  }
  // B3: Remediation/Fix intent
  if (isRemediation) {
    try {
      const misconfigs = intel.getMisconfigurations ? intel.getMisconfigurations(resources) : (summary?.topMisconfigs || []);
      if (misconfigs.length) {
        out.push('**Remediation steps for top misconfigurations (' + misconfigs.length + ' total):**');
        misconfigs.slice(0,10).forEach((m,i) => {
          const title = m.resource || m.type || 'resource';
          const issue = m.issue || m.title || m.description || '';
          const fix = m.remediation || m.fix || m.recommendation || 'See documentation';
          out.push('[' + (i+1) + '] **' + title + '**\n  Issue: ' + issue + '\n  Fix: ' + fix);
        });
      }
    } catch(_) {}
  }
  // B3: Resources list intent
  if (isResources) {
    if (resources.length) {
      const typeCounts = {};
      resources.forEach(r => { const t = r.type || 'unknown'; typeCounts[t] = (typeCounts[t] || 0) + 1; });
      const sorted = Object.entries(typeCounts).sort((a,b) => b[1] - a[1]);
      out.push('**Infrastructure resources (' + resources.length + ' total, ' + sorted.length + ' types):**');
      out.push(sorted.map(([t,n]) => '  - ' + t + ': ' + n).join('\n'));
    } else {
      out.push('No Terraform resources loaded yet. Upload .tf or CloudFormation files in the Upload tab.');
    }
  }
  // B3: Trust boundary intent
  if (isTrustBdry) {
    try {
      const boundaries = parseResult?.trustBoundaries || parseResult?.trustBounds || [];
      const modules = parseResult?.modules || [];
      if (boundaries.length) {
        out.push('**Trust boundaries identified (' + boundaries.length + '):**');
        boundaries.slice(0,10).forEach(b => out.push('  - ' + (b.name || b.id || b)));
      } else if (modules.length) {
        out.push('**Module boundaries detected (' + modules.length + '):**');
        modules.slice(0,10).forEach(m => out.push('  - ' + (m.name || m.source || m.id)));
      } else {
        out.push('No explicit trust boundaries detected in the loaded IaC files. Consider defining network segmentation using VPCs, security groups, or network ACLs.');
      }
    } catch(_) {}
  }
  // B3: Data flow intent
  if (isDataFlow) {
    try {
      const connections = parseResult?.connections || [];
      if (connections.length) {
        out.push('**Data flows / connections (' + connections.length + '):**');
        connections.slice(0,15).forEach(conn => {
          const from = conn.from || conn.source || conn.src || 'unknown';
          const to = conn.to || conn.target || conn.dst || 'unknown';
          const label = conn.label || conn.type || '';
          out.push('  - ' + from + ' -> ' + to + (label ? ' [' + label + ']' : ''));
        });
      } else {
        out.push('No explicit connections detected. Upload Terraform files that include resource references to auto-detect data flows.');
      }
    } catch(_) {}
  }

  // Always append BM25 retrieved context
  if (retrieved.length) {
    out.push(`**Relevant content from your documents:**`);
    retrieved.slice(0,5).forEach((c,i) => {
      const src = c.source || c.category || 'doc';
      out.push(`**[${i+1}] ${src}**\n${c.text.substring(0,180).trim()}…`);
    });
  }

  if (!out.length) {
    // B3: General fallback - run BM25 and format with citations
    if (!intel._built) {
      out.push('Upload Terraform files or documents in the Upload tab to enable intelligence analysis.');
    } else {
      const fallbackResults = intel.query(userText, 8);
      if (fallbackResults.length) {
        out.push('**Relevant content from your documents:**');
        fallbackResults.slice(0,5).forEach((r,i) => {
          const src = r.source || r.docId || r.category || 'doc';
          out.push('[DOC-' + (i+1) + '] **' + src + '**\n' + r.text.substring(0,300).trim() + '...');
        });
      } else {
        out.push('No relevant content found for this query. Try uploading more context documents or rephrasing your question.');
      }
    }
  }

  return out.join('\n\n');
};

// ── Dynamic context-aware system prompt ──────────────────────────────
const buildSystemPrompt = (sections) => {
  const resources = parseResult?.resources || [];
  const resCtx = resources.length
    ? `\nInfrastructure: ${resources.length} resources (${[...new Set(resources.map(r => r.type?.split('_')[1]).filter(Boolean))].slice(0, 8).join(', ')}).`
    : '';
  const scoreCtx = summary?.postureScore !== undefined
    ? `\nPosture: ${summary.postureScore}/100 — Grade ${summary.grade}. ${summary.topMisconfigs?.length || 0} open findings.`
    : '';
  // Architecture layer context
  const archLayerCtx = archLayerAnalysis ? (() => {
    const layersPresent = Object.entries(archLayerAnalysis.layers || {}).filter(([,l]) => l.completeness > 0).length;
    const grade = archLayerAnalysis.architectureGrade || 'N/A';
    const factoriesPresent = Object.values(archLayerAnalysis.factories || {}).filter(f => f.status !== 'missing').length;
    const factoriesTotal = Object.keys(archLayerAnalysis.factories || {}).length;
    return `\nArchitecture: ${layersPresent}/7 layers present, Grade ${grade}. Factories: ${factoriesPresent}/${factoriesTotal}. Sentinel: ${archLayerAnalysis.sentinelPolicies?.totalCount || 0} policies.`;
  })() : '';
  const toolDefs = mcpRegistry.getToolsForPrompt();
  const toolCtx = toolDefs.length
    ? `\nTools available — call with <tool_call>{"name":"...","args":{...}}</tool_call>:\n` +
      toolDefs.map(t => `  • ${t.name}: ${t.description.slice(0, 120)}`).join('\n')
    : '';
  const example = '\nExample Q: "Is my S3 safe?" → "3 issues: (1) S3-001 public access block missing — anyone can list contents. (2) S3-002 versioning disabled. Fix: add aws_s3_bucket_public_access_block."';
  return `You are Threataform, expert threat modeler and cloud security architect.${resCtx}${scoreCtx}${archLayerCtx}
You have full access to the user's architecture: uploaded documents, Terraform resources, security posture, control inventory, misconfigurations, ATT&CK coverage, and scope.
Provide exhaustive, complete responses. Never truncate analysis. Cover all relevant aspects. Use headers, bullets, and code blocks for clarity. Aim for completeness over brevity. Cite specific resource IDs and finding codes (e.g. S3-001, EC2-001, T1078).
Never hallucinate resource names or CVE IDs. If uncertain, say so.${toolCtx}${example}

Context:
${sections}`;
};

// ── Conversation memory compression ──────────────────────────────────
// When history exceeds 80 messages, compress oldest 60 into a summary.
const compressHistory = async (history) => {
  if (history.length <= 80) return history;
  const toCompress = history.slice(0, 60).filter(m => !m._compressed);
  if (!toCompress.length) return history;
  const summaryText = toCompress
    .map(m => `${m.role}: ${m.content.slice(0, 200)}`)
    .join('\n');
  return [
    {
      role: 'assistant',
      content: `[Earlier conversation summary]\n${summaryText.slice(0, 1500)}`,
      _compressed: true,
    },
    ...history.slice(60),
  ];
};

const sendChat = async (userText) => {
  if (!userText?.trim() || chatGenerating) return;
  setChatInput("");
  setChatGenerating(true);

  // Compress history if needed (Phase 4-B)
  const compressedHistory = await compressHistory(chatMessages);
  if (compressedHistory !== chatMessages) setChatMessages(compressedHistory);

  // Add user message immediately
  setChatMessages(prev => [...prev, { role:"user", content: userText }]);
  setChatMessages(prev => [...prev, { role:"assistant", content:"", streaming: true, sources:[] }]);

  try {
    const { sections, contextChunks } = await buildFullContext(userText);

    // ── Tier 1: LLM (Ollama or wllama WASM) ───────────────────────────
    if (onGenerateLLM && llmStatus === "ready") {
      const systemPrompt = buildSystemPrompt(sections);

      // Build message history — use compressed if available
      const historyMsgs = chatMessages
        .filter(m => !m.streaming)
        .slice(-12)
        .map(m => ({ role: m.role, content: m.content.slice(0, 800) }));

      const messages = [
        { role: "system", content: systemPrompt },
        ...historyMsgs,
        { role: "user", content: userText },
      ];

      // Attach retrieval stats + sources to streaming bubble
      const retrieval = contextChunks.length ? {
        count:    contextChunks.length,
        bm25:     contextChunks.filter(c => c.searchType === 'bm25').length,
        dense:    contextChunks.filter(c => c.searchType === 'dense').length,
        colbert:  contextChunks.filter(c => c.searchType === 'hybrid' || c.searchType === 'colbert').length,
        avgScore: Math.round((contextChunks.reduce((s, c) => s + (c.score ?? 0.5), 0) / contextChunks.length) * 100),
      } : null;

      setChatMessages(prev => {
        const last = prev[prev.length-1];
        if (last?.streaming) return [...prev.slice(0,-1), { ...last,
          sources:   contextChunks.slice(0, 5).map(c => ({ file:c.source||c.docId||'doc', cat:c.category||'', type:c.searchType||'bm25' })),
          retrieval,
        }];
        return prev;
      });

      // Stream response with performance tracking
      let fullResponse = '';
      const _tracker = createInferenceTracker(wllamaModelName || 'wllama');
      _tracker.start();
      await onGenerateLLM(messages, (token) => {
        fullResponse += token;
        setChatMessages(prev => {
          const last = prev[prev.length - 1];
          if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: last.content + token }];
          return prev;
        });
      });
      // Log tok/sec (DevTools only)
      const _tokenCount = fullResponse.split(/\s+/).length;
      _tracker.end(_tokenCount);

      // Phase 3-D: Execute any <tool_call> blocks embedded in the response
      if (fullResponse.includes('<tool_call>')) {
        const withResults = await mcpRegistry.executeToolCalls(fullResponse);
        if (withResults !== fullResponse) {
          setChatMessages(prev => {
            const last = prev[prev.length - 1];
            if (!last?.streaming) return [...prev.slice(0,-1), { ...last, content: withResults }];
            return prev;
          });
          fullResponse = withResults;
        }
      }

      // ReAct loop: parse ACTION: tool(args) patterns (max 3 iterations)
      const ACTION_RE = /ACTION:\s*(\w+)\((\{[^}]+\})\)/g;
      let reactMatch, reactIter = 0;
      let enriched = fullResponse;
      ACTION_RE.lastIndex = 0;
      while ((reactMatch = ACTION_RE.exec(enriched)) !== null && reactIter < 3) {
        reactIter++;
        const toolName = reactMatch[1];
        let toolArgs = {};
        try { toolArgs = JSON.parse(reactMatch[2]); } catch { break; }
        LOG.log(`[ReAct] iter=${reactIter} tool=${toolName} args=`, toolArgs);
        try {
          const obs = await mcpRegistry.invoke(toolName, toolArgs);
          const obsText = typeof obs === 'string' ? obs : JSON.stringify(obs, null, 2);
          enriched += `\n\nOBSERVATION (${toolName}):\n${obsText}`;
          ACTION_RE.lastIndex = 0; // rescan for more ACTIONs in enriched
        } catch (toolErr) {
          enriched += `\n\nOBSERVATION (${toolName} ERROR): ${toolErr.message}`;
          break;
        }
      }
      if (enriched !== fullResponse) {
        setChatMessages(prev => {
          const last = prev[prev.length - 1];
          return [...prev.slice(0, -1), { ...last, content: enriched }];
        });
      }

    } else {
      // ── Tier 2 / 3: Offline smart response (always available) ──────
      const response = await generateSmartResponse(userText);
      setChatMessages(prev => {
        const last = prev[prev.length-1];
        if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: response }];
        return prev;
      });
    }
  } catch (err) {
    setChatMessages(prev => {
      const last = prev[prev.length - 1];
      if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: `Error: ${err.message}`, streaming: false }];
      return prev;
    });
  }
  setChatMessages(prev => prev.map((m,i) => i===prev.length-1 ? {...m, streaming:false} : m));
  setChatGenerating(false);
};

// ── LoRA fine-tuning handler ───────────────────────────────────────────
const handleFineTune = async () => {
  if (isTraining || !userDocs?.length) return;
  const texts = userDocs.map(d => d.content).filter(Boolean);
  if (!texts.length) return;
  setIsTraining(true);
  setFtProgress(0);
  setLoraReady(false);
  let trainOk = false;
  try {
    if (typeof wllamaManager.fineTune === 'function') {
      await wllamaManager.fineTune(texts, {
        steps: 300,
        onProgress: (step, total) => setFtProgress(Math.round(step / total * 100)),
      });
      setFtProgress(100);
      trainOk = true;
    } else {
      // Fallback: just show progress animation without actual training
      for (let i = 1; i <= 10; i++) {
        await new Promise(r => setTimeout(r, 100));
        setFtProgress(i * 10);
      }
    }
  } catch (err) {
    console.warn('[LoRA] Fine-tuning failed:', err);
  }
  setIsTraining(false);
  setFtProgress(0);
  if (trainOk) setLoraReady(true);
};

// ── LoRA adapter export handler (Phase 5-D) ───────────────────────────
const handleExportLora = async () => {
  if (!loraReady || isTraining) return;
  try {
    let buf;
    if (typeof wllamaManager.saveLoRA === 'function') {
      buf = await wllamaManager.saveLoRA();
    }
    if (!buf) { console.warn('[LoRA] saveLoRA returned nothing'); return; }
    const blob     = new Blob([buf], { type: 'application/octet-stream' });
    const ts       = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `threataform-lora-adapter-${ts}.tnlm`;
    const url = URL.createObjectURL(blob);
    const a   = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    console.info(`[LoRA] Exported adapter: ${filename} (${(buf.byteLength / 1024).toFixed(1)} KB)`);
  } catch (err) {
    console.warn('[LoRA] Export failed:', err);
  }
};

return (
  <div style={{ maxWidth:760, display:"flex", flexDirection:"column", height:"100%", maxHeight:"calc(100vh - 100px)" }}>
    {/* Header */}
    <div style={{ marginBottom:16 }}>
      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
        <Bot size={20} style={{ color:"#7C3AED" }} />
        <span style={{ fontSize:18, fontWeight:700, color:C.text }}>Threataform Assistant</span>
        <span style={{ fontSize:10, background:"#43A04718", border:"1px solid #43A04744",
          borderRadius:9, padding:"2px 8px", fontWeight:600, color:"#43A047" }}>
          {intelligence?._built ? "Ready" : "Upload files to start"}
        </span>
        {llmStatus === "ready" && (
          <span style={{ fontSize:10, color:"#7C3AED", background:"#7C3AED15", border:"1px solid #7C3AED33",
            borderRadius:9, padding:"2px 8px", fontWeight:600, marginLeft:4 }}>
            + Local AI
          </span>
        )}
        <button onClick={() => { setSearchMode(m => !m); setSearchResults(null); setSearchQuery(''); }}
          title="Toggle document search mode — retrieve verbatim passages from uploaded docs"
          style={{
            marginLeft:"auto", display:"flex", alignItems:"center", gap:5,
            background: searchMode ? `${C.accent}20` : C.surface,
            border:`1px solid ${searchMode ? C.accent+"44" : C.border}`,
            borderRadius:7, padding:"5px 10px", fontSize:11, cursor:"pointer",
            color: searchMode ? C.accent : C.textSub, ...SANS,
          }}>
          <Search size={12}/> {searchMode ? 'Chat Mode' : 'Search Docs'}
        </button>
      </div>
      <div style={{ fontSize:11, color:C.textMuted }}>
        Powered by Threataform Intelligence · Fully Offline · No internet required
        {llmStatus === "ready" && wllamaModelName && (
          <span style={{ color:"#7C3AED", marginLeft:6 }}>· {wllamaModelName}</span>
        )}
      </div>
    </div>


    {/* ── Loading model ── */}
    {llmStatus === "loading" && (
      <div style={{ background:C.surface, border:`1px solid #7C3AED33`, borderRadius:12,
        padding:"16px 20px", marginBottom:16 }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
          <div style={{ width:10, height:10, borderRadius:"50%", background:"#7C3AED",
            animation:"pulse 1.2s ease-in-out infinite" }} />
          <span style={{ fontSize:13, color:C.text, fontWeight:600 }}>
            Loading model into browser…
          </span>
        </div>
        <div style={{ height:5, background:C.border, borderRadius:3, overflow:"hidden", marginBottom:6 }}>
          <div style={{ height:"100%", borderRadius:3, width:`${llmProgress}%`,
            background:"linear-gradient(90deg,#7C3AED,#9F67FA)", transition:"width .3s ease" }} />
        </div>
        <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:C.textMuted }}>
          <span>{selectedLlmModel || "model.gguf"}</span>
          <span>{llmProgress}%{llmStatusText ? ` · ${llmStatusText}` : ""}</span>
        </div>
        <div style={{ fontSize:10, color:C.textMuted, marginTop:6 }}>
          Loading via WebAssembly — runs entirely in your browser, no internet needed
        </div>
      </div>
    )}

    {/* ── Model loaded indicator ── */}
    {llmStatus === "ready" && wllamaModelName && (
      <div style={{ background:"#7C3AED08", border:"1px solid #7C3AED22", borderRadius:8,
        padding:"10px 14px", marginBottom:12, display:"flex", alignItems:"center", gap:10 }}>
        <div style={{ width:8, height:8, borderRadius:"50%", background:"#7C3AED", flexShrink:0 }} />
        <div>
          <span style={{ fontSize:12, fontWeight:600, color:"#7C3AED" }}>{wllamaModelName}</span>
          {wllamaModelSize > 0 && <span style={{ fontSize:11, color:C.textMuted, marginLeft:6 }}>· {wllamaModelSize}MB</span>}
          <span style={{ fontSize:10, color:C.textMuted, marginLeft:8 }}>· In-browser WASM · Zero internet</span>
        </div>
        <div style={{ marginLeft:"auto", display:"flex", gap:6, alignItems:"center" }}>
          {userDocs?.length > 0 && (
            <button onClick={handleFineTune} disabled={isTraining}
              title="Fine-tune the model on your uploaded documents (LoRA adaptation)"
              style={{ background: isTraining ? "#7C3AED22" : "transparent",
                border:`1px solid #7C3AED44`, borderRadius:5, padding:"3px 10px", fontSize:10,
                color:"#7C3AED", cursor: isTraining ? "default" : "pointer",
                display:"flex", alignItems:"center", gap:4, ...SANS }}>
              {isTraining ? `Training ${ftProgress}%` : 'Fine-tune on Docs'}
            </button>
          )}
          {loraReady && !isTraining && (
            <button onClick={handleExportLora}
              title="Download trained LoRA adapter as a .tnlm patch file"
              style={{ background:"transparent",
                border:`1px solid #2E7D3244`, borderRadius:5, padding:"3px 10px", fontSize:10,
                color:"#2E7D32", cursor:"pointer",
                display:"flex", alignItems:"center", gap:4, ...SANS }}>
              Export .tnlm
            </button>
          )}
          <button onClick={() => onLoadModel(null)} style={{ background:"transparent",
            border:`1px solid ${C.border}`, borderRadius:5, padding:"3px 10px", fontSize:10,
            color:C.textMuted, cursor:"pointer", ...SANS }}>Change</button>
        </div>
      </div>
    )}

    {/* ── Dense embedding progress ── */}
    {embedProgress && (
      <div style={{ background:C.surface, border:`1px solid #FB8C0033`, borderRadius:8,
        padding:"10px 14px", marginBottom:12 }}>
        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
          <span style={{ fontSize:11, color:"#FB8C00", fontWeight:600 }}>Building Vector Index</span>
          <span style={{ fontSize:11, color:C.textMuted }}>{embedProgress.done} / {embedProgress.total} chunks</span>
        </div>
        <div style={{ height:4, background:C.border, borderRadius:2, overflow:"hidden" }}>
          <div style={{ height:"100%", borderRadius:2,
            width:`${Math.round((embedProgress.done/embedProgress.total)*100)}%`,
            background:"linear-gradient(90deg,#FB8C00,#FFB74D)", transition:"width .25s ease" }} />
        </div>
        <div style={{ fontSize:10, color:C.textMuted, marginTop:4 }}>
          Semantic search improves as index builds · {embedProgress.total - embedProgress.done} remaining
        </div>
      </div>
    )}

    {/* ── MCP Tool Server ── */}
    <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, padding:"10px 14px", marginBottom:12 }}>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:6 }}>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ fontSize:11, fontWeight:600, color:C.text }}>MCP Tool Server</span>
          <button
            onClick={() => setShowMcpHelp(h => !h)}
            title="Setup instructions"
            style={{ fontSize:10, width:16, height:16, borderRadius:"50%", border:`1px solid ${C.border}`,
              background:C.bg, color:C.textMuted, cursor:"pointer", lineHeight:"14px", padding:0, flexShrink:0 }}>
            ?
          </button>
        </div>
        <span style={{ fontSize:9, color:C.textMuted }}>
          Built-in: score_cvss · lookup_mitre · check_compliance
        </span>
      </div>
      {showMcpHelp && (
        <div style={{ fontSize:10, color:C.textMuted, background:C.bg, border:`1px solid ${C.border}`, borderRadius:6, padding:"8px 10px", marginBottom:8, lineHeight:1.6 }}>
          <div style={{ fontWeight:600, color:C.text, marginBottom:4 }}>MCP extends the AI Assistant with external tools.</div>
          <div>1. Install a server: <code style={{ background:C.surface, padding:"1px 4px", borderRadius:3, fontSize:10 }}>npm install -g @modelcontextprotocol/server-filesystem</code></div>
          <div style={{ marginTop:4 }}>2. Run it: <code style={{ background:C.surface, padding:"1px 4px", borderRadius:3, fontSize:10 }}>mcp-server-filesystem ws://localhost:3747</code></div>
          <div style={{ marginTop:4 }}>3. Enter the URL below and click Connect.</div>
        </div>
      )}
      <div style={{ display:"flex", gap:6, alignItems:"center" }}>
        <input
          value={mcpUrl}
          onChange={e => setMcpUrl(e.target.value)}
          placeholder="ws://localhost:3747"
          style={{ flex:1, fontSize:10, padding:"3px 7px", background:C.bg, border:`1px solid ${C.border}`, borderRadius:4, color:C.text, outline:"none" }}
        />
        <button
          onClick={async () => {
            setMcpStatus('connecting');
            setMcpError(null);
            const ok = await mcpRegistry.tryConnectExternal(mcpUrl);
            setMcpStatus(ok ? 'connected' : 'failed');
            if (!ok) {
              setMcpError(mcpRegistry.lastConnectError || 'Connection failed');
            }
          }}
          style={{ fontSize:10, padding:"3px 10px", borderRadius:4, cursor:"pointer",
            background: mcpStatus === 'connected' ? '#2E7D3215' : C.surface,
            border:`1px solid ${mcpStatus === 'connected' ? '#2E7D3244' : C.border}`,
            color: mcpStatus === 'connected' ? '#2E7D32' : C.text }}
        >
          {mcpStatus === 'connecting' ? '…' : 'Connect'}
        </button>
        {mcpStatus && (
          <span style={{ fontSize:9, fontWeight:700,
            color: mcpStatus === 'connected' ? '#2E7D32' : mcpStatus === 'failed' ? '#B71C1C' : C.textMuted }}>
            {mcpStatus === 'connected' ? `✓ ${mcpRegistry.toolCount} tools` : mcpStatus === 'failed' ? '✗ failed' : '…'}
          </span>
        )}
      </div>
      {mcpStatus === 'failed' && mcpError && (
        <div style={{ fontSize:11, color:"#EF4444", marginTop:4, padding:"4px 8px", background:"#EF444410", borderRadius:4, border:"1px solid #EF444433" }}>
          {mcpError}
        </div>
      )}
      {mcpStatus === 'connected' && (
        <div style={{ fontSize:9, color:C.textMuted, marginTop:4 }}>
          LLM can call tools via &lt;tool_call&gt; in responses. Ask: "score CVSS AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        </div>
      )}
      <div style={{ marginTop:8 }}>
        <button onClick={async () => {
          try {
            const result = await mcpRegistry.callTool("score_cvss", {
              vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            });
            setMcpError(null);
            alert('Built-in tools working: CVSS score = ' + (result?.score || result?.baseScore || JSON.stringify(result)));
          } catch(e) {
            setMcpError('Built-in tool test failed: ' + String(e?.message || e));
          }
        }} style={{ fontSize:11, color:C.textSub, background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"4px 10px", cursor:"pointer", ...SANS }}>
          Test Built-in Tools
        </button>
      </div>
    </div>

    {/* ── Search mode (replaces Query Docs tab) ── */}
    {searchMode && (
      <div style={{ marginBottom:16 }}>
        <div style={{ display:"flex", gap:8, marginBottom:12 }}>
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={async e => {
              if (e.key !== 'Enter' || !searchQuery.trim()) return;
              setSearchLoading(true); setSearchResults(null);
              const r = onHybridSearch ? await onHybridSearch(searchQuery.trim(), 12) : (intelligence?.query(searchQuery.trim(), 12) || []);
              setSearchResults(r); setSearchLoading(false);
            }}
            placeholder="Search uploaded documents for verbatim passages…"
            style={{ flex:1, background:C.surface, border:`1px solid ${C.border2}`,
              borderRadius:8, padding:"9px 13px", color:C.text, fontSize:12, outline:"none", ...SANS }}
          />
          <button onClick={async () => {
            if (!searchQuery.trim()) return;
            setSearchLoading(true); setSearchResults(null);
            const r = onHybridSearch ? await onHybridSearch(searchQuery.trim(), 12) : (intelligence?.query(searchQuery.trim(), 12) || []);
            setSearchResults(r); setSearchLoading(false);
          }} disabled={searchLoading || !searchQuery.trim()} style={{
            background:`${C.accent}20`, color:C.accent, border:`1px solid ${C.accent}44`,
            borderRadius:8, padding:"9px 16px", fontSize:12, cursor:"pointer", fontWeight:600, ...SANS,
            opacity: searchLoading ? 0.6 : 1, flexShrink:0,
          }}>{searchLoading ? '…' : 'Search'}</button>
        </div>
        {searchResults !== null && (
          <div>
            <div style={{ fontSize:11, color:C.textMuted, marginBottom:10 }}>
              {searchResults.length} passage{searchResults.length !== 1 ? 's' : ''} found
              <span style={{ marginLeft:8, fontSize:10 }}>
                {onHybridSearch && llmStatus === 'ready' ? '⚡ BM25 + Dense Hybrid' : '○ BM25 keyword'}
              </span>
              {searchResults.length > 0 && (
                <button onClick={() => sendChat(`Based on these search results for "${searchQuery}":\n\n${searchResults.slice(0,5).map((c,i)=>`[${i+1}] ${c.text?.slice(0,200)}`).join('\n\n')}\n\nProvide a comprehensive analysis.`)}
                  style={{ marginLeft:12, fontSize:10, background:`${C.accent}15`, color:C.accent,
                    border:`1px solid ${C.accent}30`, borderRadius:5, padding:"2px 8px", cursor:"pointer" }}>
                  Send to AI →
                </button>
              )}
            </div>
            {searchResults.map((chunk, i) => chunkCard(chunk, i))}
          </div>
        )}
        {!searchResults && !searchLoading && (
          <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
            {["What services are in scope?","What encryption controls exist?","Which resources handle PHI?",
              "What STRIDE threats apply?","IAM privilege escalation risks","Compliance frameworks in scope",
              "Network trust boundaries","CloudTrail logging status"].map((s,i) => (
              <button key={i} onClick={() => { setSearchQuery(s); }}
                style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                  padding:"4px 10px", color:C.textSub, fontSize:11, cursor:"pointer", ...SANS }}>{s}</button>
            ))}
          </div>
        )}
      </div>
    )}

    {/* Quick prompts — always show when intelligence is ready and no chat */}
    {!searchMode && chatMessages.length === 0 && intelligence?._built && (
      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:11, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
          letterSpacing:".08em", marginBottom:8 }}>Quick Prompts</div>
        <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
          {QUICK_PROMPTS.map((p,i) => (
            <button key={i} onClick={() => sendChat(p)} style={{
              background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
              padding:"5px 12px", color:C.textSub, fontSize:11, cursor:"pointer", ...SANS,
            }}>{p}</button>
          ))}
        </div>
      </div>
    )}

    {/* Chat history — hidden in search mode */}
    {!searchMode && (
    <div style={{ flex:1, overflowY:"auto", display:"flex", flexDirection:"column", gap:12, marginBottom:12 }}>
      {chatMessages.map((msg, i) => (
        <div key={i} style={{
          display:"flex", flexDirection: msg.role==="user" ? "row-reverse" : "row",
          gap:8, alignItems:"flex-start",
        }}>
          <div style={{
            width:28, height:28, borderRadius:"50%", flexShrink:0,
            background: msg.role==="user" ? C.accent : "#7C3AED",
            display:"flex", alignItems:"center", justifyContent:"center",
          }}>
            {msg.role==="user"
              ? <Users size={13} style={{color:"#fff"}} />
              : <Bot size={13} style={{color:"#fff"}} />}
          </div>
          <div style={{
            maxWidth:"80%", background: msg.role==="user" ? `${C.accent}15` : C.surface,
            border:`1px solid ${msg.role==="user" ? C.accent+"33" : C.border}`,
            borderRadius:10, padding:"10px 14px",
          }}>
            <div style={{ fontSize:12, color:C.text, lineHeight:1.7, whiteSpace: msg.role === 'assistant' ? undefined : "pre-wrap" }}>
              {msg.role === 'assistant' ? renderMarkdown(msg.content) : msg.content}
              {msg.streaming && <span style={{ display:"inline-block", width:8, height:14,
                background:C.accent, marginLeft:2, animation:"pulse 1s ease-in-out infinite",
                verticalAlign:"text-bottom", borderRadius:2 }} />}
            </div>
            {/* Source citation chips */}
            {msg.role === "assistant" && msg.sources?.length > 0 && !msg.streaming && (
              <div style={{ display:"flex", flexWrap:"wrap", gap:4, marginTop:8, paddingTop:8,
                borderTop:`1px solid ${C.border}` }}>
                {msg.sources.map((s, si) => (
                  <span key={si} title={s.file} style={{
                    display:"inline-flex", alignItems:"center", gap:4,
                    background: s.type === "dense" ? "#7C3AED12" : s.type === "hybrid" ? "#1565C012" : C.bg,
                    border:`1px solid ${s.type === "dense" ? "#7C3AED33" : s.type === "hybrid" ? "#1565C033" : C.border}`,
                    borderRadius:10, padding:"2px 8px", fontSize:10, color:C.textSub,
                  }}>
                    <FileText size={9} style={{ flexShrink:0, opacity:.7 }} />
                    <span style={{ maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {s.file.split('/').pop().split('\\').pop()}
                    </span>
                    {s.cat && <span style={{ opacity:.6 }}>· {s.cat}</span>}
                    <span style={{ opacity:.5, fontSize:9 }}>{s.type === "dense" ? "⚡" : s.type === "hybrid" ? "◈" : "∷"}</span>
                  </span>
                ))}
              </div>
            )}
            {/* Retrieval quality stats (Phase 4-E) */}
            {msg.role === 'assistant' && msg.retrieval && !msg.streaming && (
              <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginTop:4, fontSize:9, color:C.textMuted, paddingTop:4 }}>
                <span>{msg.retrieval.count} chunks retrieved</span>
                {msg.retrieval.bm25 > 0 && <span>BM25: {msg.retrieval.bm25}</span>}
                {msg.retrieval.dense > 0 && <span>dense: {msg.retrieval.dense}</span>}
                {msg.retrieval.colbert > 0 && <span>colbert: {msg.retrieval.colbert}</span>}
                <span>avg: {msg.retrieval.avgScore}%</span>
              </div>
            )}
            {msg.role === 'assistant' && !msg.streaming && (
              <button
                onClick={() => navigator.clipboard.writeText(msg.content).catch(()=>{})}
                title="Copy response"
                style={{ background:'none', border:'none', cursor:'pointer', color:C.textMuted, fontSize:10, padding:'2px 5px', marginTop:4, opacity:.7, display:'flex', alignItems:'center', gap:3 }}
              >
                ⎘ Copy
              </button>
            )}
          </div>
        </div>
      ))}
      <div ref={chatBottomRef} />
    </div>
    )}

    {/* Input area — shown in chat mode only */}
    {!searchMode && intelligence?._built && (
      <div style={{ display:"flex", gap:8, marginTop:"auto" }}>
        {chatMessages.length > 0 && (
          <button onClick={() => { setChatMessages([]); setChatInput(""); }} style={{
            background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
            padding:"10px 12px", color:C.textMuted, cursor:"pointer", fontSize:11, ...SANS,
            display:"flex", alignItems:"center", gap:4,
          }}>
            <RotateCcw size={12}/> Clear
          </button>
        )}
        <input
          value={chatInput}
          onChange={e => setChatInput(e.target.value)}
          onKeyDown={e => { if(e.key==="Enter" && !e.shiftKey) { e.preventDefault(); sendChat(chatInput); }}}
          placeholder={chatGenerating ? "Generating..." : "Ask about your architecture..."}
          disabled={chatGenerating}
          style={{
            flex:1, background:C.surface, border:`1px solid ${chatGenerating ? C.border : "#7C3AED44"}`,
            borderRadius:8, padding:"10px 14px", color:C.text, fontSize:13,
            outline:"none", ...SANS, opacity: chatGenerating ? 0.6 : 1,
          }}
        />
        <button onClick={() => sendChat(chatInput)} disabled={chatGenerating || !chatInput.trim()} style={{
          background:"linear-gradient(135deg,#7C3AED,#6D28D9)", border:"none", borderRadius:8,
          padding:"10px 16px", color:"#fff", fontSize:13, cursor:"pointer", fontWeight:600, ...SANS,
          opacity: chatGenerating || !chatInput.trim() ? 0.5 : 1,
          display:"flex", alignItems:"center", gap:6,
        }}>
          {chatGenerating ? <Loader2 size={14} style={{animation:"spin 1s linear infinite"}}/> : <Send size={14}/>}
        </button>
      </div>
    )}
  </div>
);

});
