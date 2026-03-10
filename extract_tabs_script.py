import os

ROOT     = "C:/Users/mjrma/Downloads/threataform"
IP       = ROOT + "/src/features/intelligence/IntelligencePanel.jsx"
TABS_DIR = ROOT + "/src/features/intelligence/tabs"
os.makedirs(TABS_DIR, exist_ok=True)

with open(IP, "r", encoding="utf-8") as fh:
    raw = fh.read()
source_lines = raw.splitlines(keepends=True)
total = len(source_lines)
print("File: " + str(total) + " lines")

helpers_path = ROOT + '/src/features/intelligence/panelHelpers.jsx'
helpers_content = "// src/features/intelligence/panelHelpers.jsx\n// Shared helpers for IntelligencePanel tab components.\nimport { C, MONO, SANS } from '../../constants/styles.js';\n\nexport const SEV_COLOR = { Critical: '#B71C1C', High: '#E53935', Medium: '#F57C00', Low: '#43A047' };\nexport const STRIDE_COLORS = { spoofing: '#E91E63', tampering: '#FF5722', repudiation: '#9C27B0', infoDisclose: '#F44336', dos: '#FF9800', elevPriv: '#B71C1C' };\nexport const STRIDE_LABELS = { spoofing: 'Spoofing', tampering: 'Tampering', repudiation: 'Repudiation', infoDisclose: 'Info Disclosure', dos: 'Denial of Service', elevPriv: 'Elevation of Privilege' };\nexport const COMPLIANCE_LABELS = { hipaa: 'HIPAA', fedramp: 'FedRAMP', soc2: 'SOC 2', pci: 'PCI DSS', gdpr: 'GDPR', cmmc: 'CMMC', iso27001: 'ISO 27001' };\n\nexport const catColor = (cat) => ({ 'threat-model': '#E53935', 'compliance': '#0277BD', 'architecture': '#4527A0', 'runbook': '#6A1B9A', 'terraform': '#5C4033' }[cat] || '#78909C');\n\nexport function catPill(label, color) {\n  return <span style={{ background: color + '22', color, border: '1px solid ' + color + '44', borderRadius: 10, padding: '1px 8px', fontSize: 10, fontWeight: 600 }}>{label}</span>;\n}\n"
with open(helpers_path, 'w', encoding='utf-8') as fh:
    fh.write(helpers_content)
print("Written: panelHelpers.jsx (" + str(len(helpers_content.splitlines())) + " lines)")

def find_block_end_idx(lines_list, start_0idx):
    depth_brace = 0
    depth_paren = 0
    in_ss = False
    in_sd = False
    in_tpl = False
    in_cb = False
    SQ = chr(39)
    DQ = chr(34)
    BT = chr(96)
    for i in range(start_0idx, len(lines_list)):
        line = lines_list[i]
        j = 0
        while j < len(line):
            c = line[j]
            if not in_ss and not in_sd and not in_tpl and not in_cb:
                if c == "/" and j+1 < len(line) and line[j+1] == "/":
                    break
                if c == "/" and j+1 < len(line) and line[j+1] == "*":
                    in_cb = True; j += 2; continue
            if in_cb:
                if c == "*" and j+1 < len(line) and line[j+1] == "/":
                    in_cb = False; j += 2; continue
                j += 1; continue
            if c == SQ and not in_sd and not in_tpl: in_ss = not in_ss
            elif c == DQ and not in_ss and not in_tpl: in_sd = not in_sd
            elif c == BT and not in_ss and not in_sd: in_tpl = not in_tpl
            elif not in_ss and not in_sd and not in_tpl:
                if c == "{": depth_brace += 1
                elif c == "}": depth_brace -= 1
                elif c == "(": depth_paren += 1
                elif c == ")": depth_paren -= 1
            j += 1
        if i > start_0idx and depth_brace == 0 and depth_paren == 0:
            return i
    return len(lines_list) - 1

TABS_DEF = [
    ("assistant",        436,  True,  "AIAssistantTab",     "AIAssistantTab.jsx",
     ["import { wllamaManager } from '../../../lib/WllamaManager.js';",
      "import { mcpRegistry } from '../../../lib/mcp/MCPToolRegistry.js';",
      "import { ARCH_QUICK_PROMPTS } from '../../../lib/ThrataformRAG.js';",
      "import { Bot, Send, Loader2, X, RefreshCw, Upload, Search, Plug, Info, CheckCircle, XCircle, ChevronDown, ChevronUp, Download } from '../../../icons.jsx';"
     ]),
    ("threat-intel",     1411, False, "ThreatIntelTab",     "ThreatIntelTab.jsx",
     ["import { ATTACK_TECHNIQUES, CWE_DETAILS } from '../../../data/attack-data.js';",
      "import { Zap, ChevronDown, ChevronRight, Target, Shield } from '../../../icons.jsx';"
     ]),
    ("scope",            1698, False, "ScopeTab",           "ScopeTab.jsx",
     ["import { ScanLine, Loader2 } from '../../../icons.jsx';"
     ]),
    ("misconfigs",       1868, False, "MisconfigsTab",      "MisconfigsTab.jsx",
     ["import { ATTACK_TECHNIQUES, CWE_DETAILS } from '../../../data/attack-data.js';",
      "import { ShieldAlert, ChevronDown, ChevronRight, AlertCircle, CheckCircle2 } from '../../../icons.jsx';"
     ]),
    ("posture-controls", 2048, False, "PostureControlsTab", "PostureControlsTab.jsx",
     ["import { CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS } from '../../../data/control-detection.js';",
      "import { ShieldCheck, Shield, ChevronDown, ChevronRight, Search, CheckCircle2, AlertCircle, Loader2 } from '../../../icons.jsx';"
     ]),
    ("crossdoc",         2440, False, "CrossDocTab",        "CrossDocTab.jsx",
     ["import { GitCompare, Loader2 } from '../../../icons.jsx';"
     ]),
    ("resources",        2570, False, "ResourceIntelTab",   "ResourceIntelTab.jsx",
     ["import { Layers, Search, ChevronDown, Server, Database, Network, Loader2 } from '../../../icons.jsx';"
     ]),
    ("arclayers",        2776, False, "ArchLayersTab",      "ArchLayersTab.jsx",
     ["import { generateTXTReport, generateMarkdownReport } from '../../../lib/diagram/ExportUtils.js';",
      "import { Building2, Download, ChevronDown, ChevronRight, Shield } from '../../../icons.jsx';"
     ]),
]

COMMON_IMPORTS = "import React from 'react';\nimport { C, MONO, SANS } from '../../../constants/styles.js';\nimport { SEV_COLOR, STRIDE_COLORS, STRIDE_LABELS, COMPLIANCE_LABELS, catColor, catPill } from '../panelHelpers.jsx';\n"

CTX_DESTRUCTURE = '  const { summary, parseResult, userDocs, llmStatus, onGenerateLLM, onHybridSearch,\n    intelligence, computedIR, archLayerAnalysis,\n    attackFilter, setAttackFilter, expandedCwe, setExpandedCwe,\n    expandedFinding, setExpandedFinding, expandedControl, setExpandedControl,\n    techPassages, setTechPassages, findingGuidance, setFindingGuidance,\n    attackNarrative, setAttackNarrative, attackNarrLoading, setAttackNarrLoading,\n    contradictionNarrative, setContradictionNarrative, contraNarrLoading, setContraNarrLoading,\n    postureNarrative, setPostureNarrative, postureNarrLoading, setPostureNarrLoading,\n    gapAnalysis, setGapAnalysis, gapAnalysisLoading, setGapAnalysisLoading,\n    remediationPlan, setRemediationPlan, remediationLoading, setRemediationLoading,\n    inferredScope, setInferredScope, inferredScopeLoading, setInferredScopeLoading,\n    resourceSummaries, setResourceSummaries, hybridHits, setHybridHits,\n    resourceSearch, setResourceSearch, resourceTypeFilter, setResourceTypeFilter,\n    resourcePage, setResourcePage, controlSearch, setControlSearch,\n    chatMessages, setChatMessages, chatInput, setChatInput,\n    chatGenerating, setChatGenerating, chatBottomRef,\n    isTraining, setIsTraining, ftProgress, setFtProgress, loraReady, setLoraReady,\n    mcpUrl, setMcpUrl, mcpStatus, setMcpStatus, mcpError, setMcpError,\n    showMcpHelp, setShowMcpHelp,\n    llmProgress, llmStatusText, wllamaModelName, wllamaModelSize,\n    onLoadModel, onHybridSearch: _onHybridSearch, vectorStore,\n    searchMode, setSearchMode, searchQuery, setSearchQuery,\n    searchResults, setSearchResults, searchLoading, setSearchLoading,\n    synthesisingQuery, setSynthesisingQuery, synthesisText, setSynthesisText,\n    threatScenarios, setThreatScenarios, threatScenariosLoading, setThreatScenariosLoading,\n    query, setQuery, results, setResults, queryLoading, setQueryLoading,\n    noData, hasUserDocs,\n  } = ctx;\n'

extracted_blocks = {}

for (tab_id, start_1idx, is_iife, comp_name, filename, extra_imports) in TABS_DEF:
    start_0 = start_1idx - 1
    end_0 = find_block_end_idx(source_lines, start_0)
    block_text = "".join(source_lines[start_0:end_0+1])
    print(chr(10) + tab_id + ": lines " + str(start_1idx) + "--" + str(end_0+1) + " (" + str(end_0-start_0+1) + " lines)")
    extracted_blocks[tab_id] = (start_0, end_0, block_text, is_iife)
    if is_iife:
        iife_start = block_text.index("(()=>{")
        iife_end   = block_text.rindex("})()}")
        inner_raw  = block_text[iife_start + len("(()=>{") : iife_end]
        inner_ll   = inner_raw.split(chr(10))
        de = [ln[10:] if ln.startswith("          ") else (ln[8:] if ln.startswith("        ") else ln) for ln in inner_ll]
        component_body = chr(10).join(de)
    else:
        stripped    = block_text.strip()
        open_paren  = stripped.index("(", stripped.index("&&"))
        close_paren = stripped.rindex(")}")
        inner_raw   = stripped[open_paren+1:close_paren]
        inner_ll    = inner_raw.split(chr(10))
        de = [ln[10:] if ln.startswith("          ") else (ln[8:] if ln.startswith("        ") else ln) for ln in inner_ll]
        inner_content = chr(10).join(de)
        component_body = "  return (" + chr(10) + inner_content + chr(10) + "  );"
    file_content  = "// src/features/intelligence/tabs/" + filename + chr(10)
    file_content += COMMON_IMPORTS
    for imp in extra_imports:
        file_content += imp + chr(10)
    file_content += chr(10) + "export function " + comp_name + "(ctx) {" + chr(10)
    file_content += CTX_DESTRUCTURE
    file_content += chr(10)
    file_content += component_body
    file_content += chr(10) + "}" + chr(10)
    tab_path = TABS_DIR + "/" + filename
    with open(tab_path, "w", encoding="utf-8") as fh:
        fh.write(file_content)
    print("  -> Written: tabs/" + filename + " (" + str(len(file_content.splitlines())) + " lines)")

print(chr(10) + chr(10) + "All tab files written.")

# Rewrite IntelligencePanel.jsx as shell
first_tab_start_0 = 436 - 1
arclayers_end_0   = extracted_blocks["arclayers"][1]
after_tabs        = source_lines[arclayers_end_0+1:]

content_start_comment = "      {/* Content */}"
content_area_line = None
for i, line in enumerate(source_lines):
    if content_start_comment in line:
        content_area_line = i
        break
print("Content area at line " + str(content_area_line+1 if content_area_line else -1))
print("Last tab block ends at line " + str(arclayers_end_0+1))
print("Lines after last tab: " + str(len(after_tabs)))
print("First 5 after-tab lines:")
for l in after_tabs[:5]: print("  " + repr(l))

shell_imports = "".join(source_lines[:11])
tab_imports = "\nimport { AIAssistantTab }     from './tabs/AIAssistantTab.jsx';\nimport { ThreatIntelTab }     from './tabs/ThreatIntelTab.jsx';\nimport { ScopeTab }           from './tabs/ScopeTab.jsx';\nimport { MisconfigsTab }      from './tabs/MisconfigsTab.jsx';\nimport { PostureControlsTab } from './tabs/PostureControlsTab.jsx';\nimport { CrossDocTab }        from './tabs/CrossDocTab.jsx';\nimport { ResourceIntelTab }   from './tabs/ResourceIntelTab.jsx';\nimport { ArchLayersTab }      from './tabs/ArchLayersTab.jsx';\n"

shell_body_before_tabs = "".join(source_lines[11:first_tab_start_0])

ctx_and_routing = '\n        {/* Tab routing - each tab is a separate component */}\n        {(() => {\n          const ctx = {\n            summary, parseResult, userDocs, llmStatus, onGenerateLLM, onHybridSearch,\n            intelligence, computedIR, archLayerAnalysis,\n            attackFilter, setAttackFilter, expandedCwe, setExpandedCwe,\n            expandedFinding, setExpandedFinding, expandedControl, setExpandedControl,\n            techPassages, setTechPassages, findingGuidance, setFindingGuidance,\n            attackNarrative, setAttackNarrative, attackNarrLoading, setAttackNarrLoading,\n            contradictionNarrative, setContradictionNarrative, contraNarrLoading, setContraNarrLoading,\n            postureNarrative, setPostureNarrative, postureNarrLoading, setPostureNarrLoading,\n            gapAnalysis, setGapAnalysis, gapAnalysisLoading, setGapAnalysisLoading,\n            remediationPlan, setRemediationPlan, remediationLoading, setRemediationLoading,\n            inferredScope, setInferredScope, inferredScopeLoading, setInferredScopeLoading,\n            resourceSummaries, setResourceSummaries, hybridHits, setHybridHits,\n            resourceSearch, setResourceSearch, resourceTypeFilter, setResourceTypeFilter,\n            resourcePage, setResourcePage, controlSearch, setControlSearch,\n            chatMessages, setChatMessages, chatInput, setChatInput,\n            chatGenerating, setChatGenerating, chatBottomRef,\n            isTraining, setIsTraining, ftProgress, setFtProgress, loraReady, setLoraReady,\n            mcpUrl, setMcpUrl, mcpStatus, setMcpStatus, mcpError, setMcpError,\n            showMcpHelp, setShowMcpHelp,\n            llmProgress, llmStatusText, wllamaModelName, wllamaModelSize,\n            onLoadModel, vectorStore,\n            searchMode, setSearchMode, searchQuery, setSearchQuery,\n            searchResults, setSearchResults, searchLoading, setSearchLoading,\n            synthesisingQuery, setSynthesisingQuery, synthesisText, setSynthesisText,\n            threatScenarios, setThreatScenarios, threatScenariosLoading, setThreatScenariosLoading,\n            query, setQuery, results, setResults, queryLoading, setQueryLoading,\n            noData, hasUserDocs,\n          };\n          if (iTab === "assistant")        return <AIAssistantTab {...ctx} />;\n          if (iTab === "threat-intel")     return <ThreatIntelTab {...ctx} />;\n          if (iTab === "scope")            return <ScopeTab {...ctx} />;\n          if (iTab === "misconfigs")       return <MisconfigsTab {...ctx} />;\n          if (iTab === "posture-controls") return <PostureControlsTab {...ctx} />;\n          if (iTab === "crossdoc")         return <CrossDocTab {...ctx} />;\n          if (iTab === "resources")        return <ResourceIntelTab {...ctx} />;\n          if (iTab === "arclayers")        return <ArchLayersTab {...ctx} />;\n          return null;\n        })()}\n'

shell_after_tabs = "".join(after_tabs)
new_ip = shell_imports + tab_imports + shell_body_before_tabs + ctx_and_routing + shell_after_tabs
with open(IP, "w", encoding="utf-8") as fh:
    fh.write(new_ip)
new_lines = len(new_ip.splitlines())
print(chr(10) + "New IntelligencePanel.jsx: " + str(new_lines) + " lines")
print("Done!")
