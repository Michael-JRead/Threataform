import { useState, useMemo } from "react";
import { C, SANS, MONO } from '../../constants/styles.js';
import { TIERS } from '../../constants/tiers.js';
import { RT } from '../../data/resource-types.js';
import { ATTACK_TECHNIQUES } from '../../data/attack-data.js';
import { generateAnalysis } from '../../lib/iac/SecurityAnalyzer.js';
import ScopeSelector from '../../components/ScopeSelector.jsx';

// DOC_TYPE_META is needed locally for document display in AnalysisPanel
const DOC_TYPE_META = {
  // Terraform / IaC
  tf:       { label:"TF",      color:"#7C4DFF" },
  hcl:      { label:"HCL",     color:"#9C27B0" },
  tfvars:   { label:"TFVARS",  color:"#AB47BC" },
  sentinel: { label:"SENTINEL",color:"#CE93D8" },
  // Config / data
  json:     { label:"JSON",    color:"#F9A825" },
  yaml:     { label:"YAML",    color:"#FFA726" },
  yml:      { label:"YAML",    color:"#FFA726" },
  toml:     { label:"TOML",    color:"#FF8F00" },
  xml:      { label:"XML",     color:"#FB8C00" },
  csv:      { label:"CSV",     color:"#66BB6A" },
  // Docs
  md:       { label:"MD",      color:"#42A5F5" },
  txt:      { label:"TXT",     color:"#78909C" },
  pdf:      { label:"PDF",     color:"#EF5350" },
  // Code
  py:       { label:"PY",      color:"#26A69A" },
  sh:       { label:"SH",      color:"#4CAF50" },
  bash:     { label:"SH",      color:"#4CAF50" },
  ts:       { label:"TS",      color:"#29B6F6" },
  js:       { label:"JS",      color:"#FFEE58" },
  go:       { label:"GO",      color:"#00BCD4" },
  rb:       { label:"RB",      color:"#EF5350" },
  // CI/CD & infra
  groovy:   { label:"GROOVY",  color:"#BF360C" },
  jenkinsfile:{label:"JENKINS",color:"#D84315" },
  dockerfile:{label:"DOCKER",  color:"#0288D1" },
  env:      { label:"ENV",     color:"#78909C" },
  // Catch-all
  log:      { label:"LOG",     color:"#607D8B" },
};

function AnalysisPanel({ parseResult, files, userDocs, scopeFiles, onScopeChange }) {
  const A = useMemo(
    () => generateAnalysis(parseResult, files, userDocs, scopeFiles),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [parseResult, files, userDocs, scopeFiles]
  );
  const [strideOpen, setStrideOpen] = useState(null);
  const [activeSection, setActiveSection] = useState(null);
  const SEV_C = { CRITICAL:"#FF1744", HIGH:"#EF5350", MEDIUM:"#FFA726", LOW:"#66BB6A" };
  const SEV_B = { CRITICAL:"#1C0006", HIGH:"#1C0404", MEDIUM:"#191000", LOW:"#071407" };

  const Section = ({ id, title, color=C.accent, count, children }) => {
    const isOpen = activeSection !== id; // sections open by default; click to collapse
    return (
      <div style={{ marginBottom:16, background:C.surface2, border:`1px solid ${C.border}`, borderLeft:`3px solid ${color}`, borderRadius:8, overflow:"hidden" }}>
        <button
          onClick={()=>setActiveSection(activeSection===id ? null : id)}
          style={{ width:"100%", display:"flex", alignItems:"center", gap:10, background:C.surface, padding:"11px 20px", border:"none", cursor:"pointer", ...SANS }}
        >
          <span style={{ flex:1, fontSize:12, fontWeight:700, color, letterSpacing:".07em", textTransform:"uppercase", textAlign:"left" }}>{title}</span>
          {count !== undefined && (
            <span style={{ fontSize:11, fontWeight:700, background:`${color}20`, color, border:`1px solid ${color}44`, borderRadius:4, padding:"1px 8px" }}>{count}</span>
          )}
          <span style={{ fontSize:11, color:C.textMuted, marginLeft:4 }}>{isOpen?"▲":"▼"}</span>
        </button>
        {isOpen && <div style={{ padding:"16px 20px" }}>{children}</div>}
      </div>
    );
  };

  const Badge = ({ sev }) => (
    <span style={{ background:SEV_B[sev], color:SEV_C[sev], border:`1px solid ${SEV_C[sev]}55`, borderRadius:4, padding:"2px 8px", fontSize:10, fontWeight:700, letterSpacing:".06em", marginRight:6 }}>{sev}</span>
  );

  const Pill = ({ label, val, color=C.accent }) => (
    <div style={{ background:C.surface2, border:`1px solid ${C.border}`, borderRadius:8, padding:"12px 16px", textAlign:"center" }}>
      <div style={{ fontSize:26, fontWeight:700, color, fontFamily:"monospace" }}>{val}</div>
      <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>{label}</div>
    </div>
  );

  const total = A.connCounts.implicit + A.connCounts.explicit + A.connCounts["module-input"] + A.connCounts.other;
  const critFindings = A.secFindings.filter(f=>f.sev==="CRITICAL");
  const highFindings = A.secFindings.filter(f=>f.sev==="HIGH");

  const STRIDE_COLORS = { S:"#EF5350", T:"#FF7043", R:"#FFCA28", I:"#AB47BC", D:"#42A5F5", E:"#FF9800", LM:"#E040FB" };
  const STRIDE_LABELS = { S:"Spoofing", T:"Tampering", R:"Repudiation", I:"Info Disclosure", D:"Denial of Service", E:"Elevation of Privilege", LM:"Lateral Movement" };

  return (
    <div style={{ padding:"24px 32px", maxWidth:1120, ...SANS }}>

      {/* Scope Selector */}
      {files.length > 0 && onScopeChange && (
        <ScopeSelector files={files} scopeFiles={scopeFiles} onScopeChange={onScopeChange}/>
      )}

      {/* Scope Summary Banner */}
      {A.scopeInfo.active && (
        <div style={{
          marginBottom:16, padding:"16px 20px", borderRadius:8,
          background:C.surface2,
          border:`1px solid #1565C044`, borderLeft:"3px solid #1E88E5"
        }}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:14}}>
            <div>
              <div style={{fontSize:13, fontWeight:700, color:"#42A5F5", letterSpacing:".05em", marginBottom:6}}>
                SCOPE ACTIVE — Focused Threat Model
              </div>
              <div style={{fontSize:13, color:C.textSub, lineHeight:1.7, maxWidth:560}}>
                Security findings, STRIDE-LM, and ATT&CK mapping apply only to{" "}
                <span style={{color:C.text, fontWeight:600}}>{A.scopeInfo.inScopeFileCount} in-scope file(s)</span>.{" "}
                {A.scopeInfo.outScopeResourceCount} resource(s) from{" "}
                {A.scopeInfo.totalFileCount - A.scopeInfo.inScopeFileCount} context file(s) provide dependency context.
                {A.scopeInfo.crossScopeConnCount > 0 && ` ${A.scopeInfo.crossScopeConnCount} cross-boundary connection(s) detected.`}
              </div>
            </div>
            <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
              {[
                {label:"In-Scope",       val:A.scopeInfo.inScopeResourceCount,          c:"#42A5F5"},
                {label:"Context",        val:A.scopeInfo.outScopeResourceCount,          c:"#546E7A"},
                {label:"Cross-Boundary", val:A.scopeInfo.crossScopeConnCount,            c:"#FF7043"},
                {label:"Upstream Deps",  val:A.scopeInfo.dependencyResources.length,     c:"#AB47BC"},
                {label:"Downstream",     val:A.scopeInfo.inboundResources.length,        c:"#FFCA28"},
              ].map(p=>(
                <div key={p.label} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"8px 14px", textAlign:"center", minWidth:80}}>
                  <div style={{fontSize:22, fontWeight:700, color:p.c, fontFamily:"monospace"}}>{p.val}</div>
                  <div style={{fontSize:11, color:C.textMuted, marginTop:3}}>{p.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:20, flexWrap:"wrap", gap:14 }}>
        <div>
          <div style={{ fontSize:20, fontWeight:700, color:C.text, letterSpacing:".04em" }}>Threataform Analysis</div>
          <div style={{ fontSize:12, color:C.textMuted, marginTop:5 }}>
            {new Date(A.timestamp).toLocaleString()} · {A.scale.files} file(s) · ATT&CK Enterprise v18.1 · CWE v4.16
            {A.scopeInfo.active ? ` · ${A.scopeInfo.inScopeResourceCount} in-scope resources` : ""}
          </div>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10 }}>
          <Pill label={A.scopeInfo.active ? "In-Scope" : "Resources"} val={A.scale.resources} color={C.green}/>
          <Pill label="Modules"     val={A.scale.modules}          color={C.blue}/>
          <Pill label="Connections" val={A.scale.connections}      color={C.accent}/>
          <Pill label="CRITICAL"    val={critFindings.length}      color={C.critRed}/>
          <Pill label="Findings"    val={A.secFindings.length}     color={C.red}/>
        </div>
      </div>

      {/* Executive Summary */}
      <Section id="exec" title="Executive Summary" color={C.accent}>
        <p style={{ fontSize:13, color:C.textSub, lineHeight:1.8, margin:0 }}>{A.execSummary}</p>
      </Section>

      {/* Architecture Narrative */}
      {A.narrative.length > 0 && (
        <Section id="narrative" title="Architecture Narrative" color="#26C6DA" count={A.narrative.length}>
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            {A.narrative.map((line,i) => (
              <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
                <span style={{ color:"#26C6DA", fontSize:13, marginTop:1, flexShrink:0 }}>▸</span>
                <div style={{ fontSize:13, color:C.textSub, lineHeight:1.7 }}>{line}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Trust Boundaries */}
      {A.trustBoundaries.length > 0 && (
        <Section id="trust" title="Trust Boundaries" color="#7C4DFF" count={A.trustBoundaries.length}>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {A.trustBoundaries.map((b,i) => (
              <div key={i} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"12px 16px" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
                  <span style={{ fontSize:13, fontWeight:700, color:"#B39DDB" }}>{b.zone}</span>
                  <div style={{ display:"flex", gap:6 }}>
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:4, background:C.surface2, color:C.textMuted }}>{b.type}</span>
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:4,
                      background: b.risk==="HIGH"?SEV_B.HIGH:SEV_B.MEDIUM,
                      color: b.risk==="HIGH"?SEV_C.HIGH:SEV_C.MEDIUM }}>{b.risk} RISK</span>
                  </div>
                </div>
                <div style={{ fontSize:13, color:C.textSub, lineHeight:1.6, marginBottom:6 }}>{b.desc}</div>
                <div style={{ fontSize:11, color:C.textMuted }}>Controls: {b.control}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Security Findings (Checkov-style) */}
      <Section id="findings" title={`Security Findings`} color={C.critRed} count={`${A.secFindings.length} (${critFindings.length} CRITICAL · ${highFindings.length} HIGH)`}>
        {A.secFindings.length === 0 && (
          <div style={{ fontSize:13, color:C.textMuted }}>No security findings detected based on parsed resource attributes.</div>
        )}
        {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
          const grp = A.secFindings.filter(f=>f.sev===sev);
          if (!grp.length) return null;
          return (
            <div key={sev} style={{ marginBottom:14 }}>
              <div style={{ fontSize:11, color:SEV_C[sev], fontWeight:700, marginBottom:8, letterSpacing:".1em", textTransform:"uppercase" }}>── {sev} ({grp.length})</div>
              {grp.map((f,i) => (
                <div key={i} style={{ marginBottom:8, padding:"12px 16px", background:SEV_B[sev], border:`1px solid ${SEV_C[sev]}22`, borderRadius:6 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, flexWrap:"wrap" }}>
                    <Badge sev={sev}/>
                    <span style={{ fontSize:11, color:C.textMuted, ...MONO }}>{f.code}</span>
                    <span style={{ fontSize:13, fontWeight:600, color:SEV_C[sev], flex:1 }}>{f.msg}</span>
                  </div>
                  <div style={{ fontSize:12, color:C.textSub, lineHeight:1.6, marginBottom:8 }}>{f.detail}</div>
                  <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                    {f.technique && ATTACK_TECHNIQUES[f.technique] && (
                      <span style={{ fontSize:11, color:"#EF9A9A", background:"#1A0008", border:"1px solid #B71C1C33", borderRadius:4, padding:"2px 8px" }}>
                        ATT&CK {f.technique} · {ATTACK_TECHNIQUES[f.technique].tactic}
                      </span>
                    )}
                    {f.cwe && (
                      <span style={{ fontSize:11, color:"#FFAB91", background:"#1A0800", border:"1px solid #E6510033", borderRadius:4, padding:"2px 8px" }}>
                        {f.cwe}
                      </span>
                    )}
                    <span style={{ fontSize:10, color:C.textMuted, ...MONO }}>{f.id}</span>
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </Section>

      {/* STRIDE-LM Threat Analysis by Tier */}
      {A.strideLM.length > 0 && (
        <Section id="stride" title="STRIDE-LM Threat Analysis by Infrastructure Tier" color="#E040FB" count={A.strideLM.length + " tiers"}>
          <div style={{ fontSize:12, color:C.textMuted, marginBottom:14, lineHeight:1.7 }}>
            Per-tier threats based on STRIDE-LM: S=Spoofing · T=Tampering · R=Repudiation · I=Info Disclosure · D=Denial of Service · E=Elevation of Privilege · LM=Lateral Movement. Click a tier to expand.
          </div>
          {A.strideLM.map((tierData, ti) => (
            <div key={ti} style={{ marginBottom:8, border:`1px solid ${tierData.color}33`, borderRadius:6, overflow:"hidden" }}>
              <button
                onClick={() => setStrideOpen(strideOpen===ti ? null : ti)}
                style={{ width:"100%", background: strideOpen===ti ? tierData.color+"18" : C.surface,
                  border:"none", cursor:"pointer", padding:"11px 16px", display:"flex", alignItems:"center",
                  justifyContent:"space-between", ...SANS }}
              >
                <span style={{ fontSize:13, fontWeight:700, color:tierData.color }}>{tierData.tier}</span>
                <div style={{ display:"flex", gap:4, alignItems:"center" }}>
                  {Object.keys(STRIDE_COLORS).map(cat => (
                    <span key={cat} style={{ fontSize:10, fontWeight:700, color:STRIDE_COLORS[cat],
                      background:STRIDE_COLORS[cat]+"22", borderRadius:3, padding:"2px 6px" }}>{cat}</span>
                  ))}
                  <span style={{ fontSize:11, color:C.textMuted, marginLeft:8 }}>{strideOpen===ti?"▲":"▼"}</span>
                </div>
              </button>
              {strideOpen===ti && (
                <div style={{ background:C.surface2, padding:"14px 16px", borderTop:`1px solid ${C.border}` }}>
                  {tierData.cats.map((c,ci) => (
                    <div key={ci} style={{ marginBottom:12, paddingBottom:12, borderBottom:`1px solid ${C.border}` }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
                        <span style={{ fontSize:12, fontWeight:800, color:STRIDE_COLORS[c.cat],
                          background:STRIDE_COLORS[c.cat]+"22", borderRadius:4, padding:"3px 8px",
                          minWidth:32, textAlign:"center" }}>{c.cat}</span>
                        <span style={{ fontSize:13, fontWeight:600, color:STRIDE_COLORS[c.cat] }}>{STRIDE_LABELS[c.cat]}</span>
                      </div>
                      {c.threats.map((t,ti2) => (
                        <div key={ti2} style={{ display:"flex", gap:10, alignItems:"flex-start", marginBottom:5 }}>
                          <span style={{ color:STRIDE_COLORS[c.cat], fontSize:12, marginTop:1, flexShrink:0 }}>›</span>
                          <span style={{ fontSize:12, color:C.textSub, lineHeight:1.6 }}>{t}</span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* MITRE ATT&CK Technique Mapping */}
      {Object.keys(A.attackMap).length > 0 && (
        <Section id="attack" title="MITRE ATT&CK® Technique Mapping" color="#B71C1C" count={Object.keys(A.attackMap).length}>
          <div style={{ fontSize:12, color:C.textMuted, marginBottom:12 }}>Techniques mapped from security findings — attack.mitre.org · Enterprise v18.1 Cloud/IaaS matrix</div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:10 }}>
            {Object.entries(A.attackMap).map(([tid, data]) => (
              <div key={tid} style={{ background:C.surface, border:"1px solid #B71C1C33", borderRadius:6, padding:"12px 14px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                  <span style={{ fontSize:11, fontWeight:700, color:"#FF1744", ...MONO,
                    background:"#1A0008", border:"1px solid #FF174433", borderRadius:4, padding:"2px 8px" }}>{tid}</span>
                  <span style={{ fontSize:13, fontWeight:600, color:"#EF9A9A" }}>{data.name}</span>
                </div>
                <div style={{ fontSize:12, color:C.textMuted, marginBottom:6 }}>{data.tactic}</div>
                <div style={{ fontSize:11, color:C.textMuted }}>{data.findings.length} finding(s): {data.findings.slice(0,3).map(f=>f.code).join(", ")}{data.findings.length>3?"…":""}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Architecture Inventory */}
      <Section id="inventory" title="Architecture Inventory by Tier" color={C.green} count={A.scale.resources}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:10 }}>
          {Object.entries(A.tierGroups).map(([tid, res]) => {
            const tm = TIERS[tid] || { label:tid, border:"#555", hdr:"#111" };
            return (
              <div key={tid} style={{ background:C.surface, border:`1px solid ${tm.border}33`, borderLeft:`3px solid ${tm.border}`, borderRadius:6, padding:"12px 14px" }}>
                <div style={{ fontSize:12, fontWeight:700, color:tm.border, marginBottom:8 }}>
                  {tm.label} <span style={{ color:C.textMuted, fontWeight:400 }}>({res.length})</span>
                </div>
                {res.slice(0,8).map((r,i) => (
                  <div key={i} style={{ fontSize:11, color:C.textSub, ...MONO, padding:"2px 0", display:"flex", gap:6 }}>
                    <span style={{ color:RT[r.type]?.c||C.textMuted, fontSize:10, flexShrink:0 }}>▸</span>
                    <span style={{ color:C.textSub, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.id}</span>
                  </div>
                ))}
                {res.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{res.length-8} more</div>}
              </div>
            );
          })}
        </div>
      </Section>

      {/* Architecture Signals (existing) */}
      {A.signals.length > 0 && (
        <Section id="signals" title="Architecture Signals" color={C.accent} count={A.signals.length}>
          {["HIGH","MEDIUM","LOW"].map(sev => {
            const grp = A.signals.filter(s=>s.sev===sev);
            if (!grp.length) return null;
            return (
              <div key={sev} style={{ marginBottom:10 }}>
                {grp.map((s,i) => (
                  <div key={i} style={{ marginBottom:8, padding:"12px 16px", background:SEV_B[sev]||C.surface, border:`1px solid ${SEV_C[sev]||C.border}22`, borderRadius:6 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                      <Badge sev={sev}/>
                      <span style={{ fontSize:13, fontWeight:600, color:SEV_C[sev]||C.text }}>{s.msg}</span>
                    </div>
                    <div style={{ fontSize:12, color:C.textSub, lineHeight:1.6 }}>{s.detail}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </Section>
      )}

      {/* Data Flow Analysis */}
      <Section id="dataflow" title="Data Flow Analysis" color={C.blue} count={total}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:16 }}>
          <Pill label="Total Connections"   val={total}                          color={C.blue}/>
          <Pill label="Implicit Refs"       val={A.connCounts.implicit}          color="#78909C"/>
          <Pill label="Explicit depends_on" val={A.connCounts.explicit}          color={C.red}/>
          <Pill label="Module I/O"          val={A.connCounts["module-input"]}   color={C.green}/>
        </div>
        {A.topR.length > 0 && (
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Top Connected Resources — Highest Dependency Degree</div>
            {A.topR.map((r,i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:10, padding:"6px 0", borderBottom:`1px solid ${C.border}` }}>
                <span style={{ fontSize:11, color:C.textMuted, minWidth:24, textAlign:"right" }}>#{i+1}</span>
                <span style={{ fontSize:12, color:RT[r.type]?.c||C.textSub, ...MONO, flex:1 }}>{r.id}</span>
                <span style={{ fontSize:11, color:C.textMuted }}>{r.type}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Security Surface */}
      <Section id="surface" title="Security Surface Inventory" color={C.purple}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10 }}>
          {[
            { label:"IAM Principals & Policies", items:A.surf.iam,                     color:"#E040FB" },
            { label:"Security Groups",            items:A.surf.sg,                      color:"#FF7043" },
            { label:"KMS Keys",                   items:A.surf.kms,                     color:"#26C6DA" },
            { label:"Load Balancers / API GW",    items:[...A.surf.lb,...A.surf.apigw], color:"#EF5350" },
            { label:"RDS / Aurora",               items:A.surf.rds,                     color:"#42A5F5" },
            { label:"S3 Buckets",                 items:A.surf.s3,                      color:"#FFCA28" },
            { label:"EKS / Kubernetes",           items:A.surf.eks,                     color:"#66BB6A" },
            { label:"Lambda Functions",           items:A.surf.lambda,                  color:"#FF9800" },
            { label:"WAF",                        items:A.surf.waf,                     color:"#26C6DA" },
          ].map(({ label, items, color }) => (
            <div key={label} style={{ background:C.surface, borderRadius:6, padding:"10px 12px", borderLeft:`1px solid ${C.border}`, borderRight:`1px solid ${C.border}`, borderBottom:`1px solid ${C.border}`, borderTop:`2px solid ${color}` }}>
              <div style={{ fontSize:12, color, fontWeight:700, marginBottom:6 }}>{label} <span style={{ color:C.textMuted, fontWeight:400 }}>({items.length})</span></div>
              {items.slice(0,4).map((r,i) => (
                <div key={i} style={{ fontSize:11, color:C.textMuted, ...MONO, overflow:"hidden", whiteSpace:"nowrap", textOverflow:"ellipsis", padding:"1px 0" }}>{r.id}</div>
              ))}
              {items.length>4 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{items.length-4} more</div>}
            </div>
          ))}
        </div>
      </Section>

      {/* Terraform Patterns */}
      <Section id="patterns" title="Terraform Patterns" color="#26C6DA">
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:14 }}>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Modules ({A.modules.length})</div>
            {A.modules.slice(0,8).map((m,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#CE93D8" }}>module.</span>{m.name}
                {m.source && <span style={{ color:C.textMuted }}> ← {m.source.substring(0,38)}{m.source.length>38?"…":""}</span>}
              </div>
            ))}
            {A.modules.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.modules.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Remote States ({A.remoteStates.length})</div>
            {A.remoteStates.slice(0,8).map((rs,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#42A5F5" }}>{rs.address||rs.id||`remote_${i}`}</span>
              </div>
            ))}
            {A.remoteStates.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.remoteStates.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Variables ({A.variables.length})</div>
            {A.variables.slice(0,8).map((v,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#FFD54F" }}>var.</span>{v.name}
                {v.sensitive && <span style={{ color:C.red, marginLeft:8, fontSize:10 }}>[sensitive]</span>}
              </div>
            ))}
            {A.variables.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.variables.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Outputs ({A.outputs.length})</div>
            {A.outputs.slice(0,8).map((o,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#4DD0E1" }}>output.</span>{o.name}
                {o.sensitive && <span style={{ color:C.red, marginLeft:8, fontSize:10 }}>[sensitive]</span>}
              </div>
            ))}
            {A.outputs.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.outputs.length-8} more</div>}
          </div>
        </div>
      </Section>

      {/* Supporting Documents — with architecture classification */}
      {A.userDocs.length > 0 && (
        <Section id="docs" title="Context Documents & Architecture Intelligence" color="#78909C" count={A.userDocs.length}>
          {/* Doc context summary */}
          {A.docContext && (A.docContext.compliance.length > 0 || Object.keys(A.docContext.mentions).length > 0) && (
            <div style={{background:C.bg, border:`1px solid ${"#78909C"}30`, borderRadius:8, padding:"12px 16px", marginBottom:14}}>
              {A.docContext.compliance.length > 0 && (
                <div style={{display:"flex", gap:6, alignItems:"center", flexWrap:"wrap", marginBottom:6}}>
                  <span style={{fontSize:11, color:C.textMuted, fontWeight:600}}>Compliance:</span>
                  {A.docContext.compliance.map(c => (
                    <span key={c} style={{fontSize:10, padding:"2px 8px", borderRadius:4, background:"#E65100"+"20", color:"#FF8A65", border:"1px solid #E6510030", fontWeight:600}}>{c}</span>
                  ))}
                </div>
              )}
              {Object.keys(A.docContext.mentions).length > 0 && (
                <div style={{display:"flex", gap:6, alignItems:"center", flexWrap:"wrap"}}>
                  <span style={{fontSize:11, color:C.textMuted, fontWeight:600}}>Platforms:</span>
                  {Object.keys(A.docContext.mentions).slice(0,10).map(m => (
                    <span key={m} style={{fontSize:10, padding:"2px 8px", borderRadius:4, background:"#0277BD"+"20", color:"#4FC3F7", border:"1px solid #0277BD30", fontWeight:600}}>{m}</span>
                  ))}
                </div>
              )}
            </div>
          )}
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {A.userDocs.map((d,i) => {
              const ext = (d.name||"").split(".").pop().toLowerCase();
              const typeMeta = DOC_TYPE_META[ext] || { label: ext.toUpperCase().slice(0,6)||"FILE", color:"#78909C" };
              const inv = A.docContext?.docInventory?.find(di => di.name === d.name);
              const roleLabel = inv?.roles?.[0]?.replace(/-/g," ") || "";
              const tierLabel = inv?.archTier && inv.archTier !== "Unknown" ? inv.archTier : null;
              return (
                <div key={i} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"9px 13px", display:"flex", gap:10, alignItems:"flex-start" }}>
                  <span style={{
                    fontSize:9, fontWeight:700, color:typeMeta.color,
                    background:`${typeMeta.color}15`, border:`1px solid ${typeMeta.color}33`,
                    borderRadius:4, padding:"2px 6px", flexShrink:0, marginTop:1
                  }}>{typeMeta.label}</span>
                  <div style={{minWidth:0, flex:1}}>
                    <div style={{display:"flex", alignItems:"center", gap:7, marginBottom:3, flexWrap:"wrap"}}>
                      <span style={{ fontSize:12, color:"#90A4AE", fontWeight:600,
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {d.path || d.name}
                      </span>
                      {tierLabel && (
                        <span style={{fontSize:9, padding:"1px 6px", borderRadius:3, fontWeight:700, flexShrink:0,
                          background:"#2E7D32"+"25", color:"#81C784", border:"1px solid #2E7D3240"}}>
                          {tierLabel}
                        </span>
                      )}
                      {roleLabel && (
                        <span style={{fontSize:9, padding:"1px 6px", borderRadius:3, fontWeight:600, flexShrink:0,
                          background:"#78909C"+"20", color:C.textMuted, border:`1px solid ${"#78909C"}30`}}>
                          {roleLabel}
                        </span>
                      )}
                    </div>
                    {!d.binary && d.content && (
                      <div style={{ fontSize:10, color:C.textMuted, ...MONO, whiteSpace:"pre-wrap",
                        maxHeight:52, overflow:"hidden", lineHeight:1.5 }}>
                        {d.content.substring(0,280)}{d.content.length>280?"…":""}
                      </div>
                    )}
                    {d.binary && <div style={{fontSize:10, color:C.textMuted, fontStyle:"italic"}}>binary file — content not analyzed</div>}
                  </div>
                  {d.size && <span style={{fontSize:10, color:C.textMuted, flexShrink:0, paddingTop:1}}>{d.size < 1024 ? d.size+"B" : Math.round(d.size/1024)+"K"}</span>}
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Upstream Infrastructure Dependencies (scope context) */}
      {A.scopeInfo.active && A.scopeInfo.dependencyResources.length > 0 && (
        <Section id="upstream" title="Upstream Infrastructure Dependencies — Context (Out of Scope)" color="#AB47BC" count={A.scopeInfo.dependencyResources.length}>
          <div style={{fontSize:13, color:C.textSub, marginBottom:12, lineHeight:1.7}}>
            These resources are defined <strong style={{color:"#CE93D8"}}>outside the threat model scope</strong> but are directly referenced by in-scope resources.
            Their security posture directly impacts the in-scope system's risk profile — review their configurations as part of the broader risk assessment.
          </div>
          <div style={{display:"flex", flexDirection:"column", gap:4}}>
            {A.scopeInfo.dependencyResources.map((r,i) => {
              const meta = RT[r.type] || RT._default;
              return (
                <div key={i} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
                  padding:"8px 14px", display:"flex", alignItems:"center", gap:10}}>
                  <div style={{width:10, height:10, borderRadius:2, background:meta.c, flexShrink:0}}/>
                  <span style={{...MONO, fontSize:12, color:"#CE93D8", flex:1}}>{r.id}</span>
                  <span style={{fontSize:11, color:C.textMuted}}>{r.type}</span>
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background:"#AB47BC22", color:"#CE93D8", border:"1px solid #AB47BC33", flexShrink:0}}>upstream context</span>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Downstream Callers (scope context) */}
      {A.scopeInfo.active && A.scopeInfo.inboundResources.length > 0 && (
        <Section id="downstream" title="Downstream Callers — Context (Out of Scope)" color="#FFCA28" count={A.scopeInfo.inboundResources.length}>
          <div style={{fontSize:13, color:C.textSub, marginBottom:12, lineHeight:1.7}}>
            These resources are defined <strong style={{color:"#FFE082"}}>outside the threat model scope</strong> but depend on in-scope resources.
            Each caller is a potential entry vector if improperly authenticated or authorized at the scope boundary.
          </div>
          <div style={{display:"flex", flexDirection:"column", gap:4}}>
            {A.scopeInfo.inboundResources.map((r,i) => {
              const meta = RT[r.type] || RT._default;
              return (
                <div key={i} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
                  padding:"8px 14px", display:"flex", alignItems:"center", gap:10}}>
                  <div style={{width:10, height:10, borderRadius:2, background:meta.c, flexShrink:0}}/>
                  <span style={{...MONO, fontSize:12, color:"#FFE082", flex:1}}>{r.id}</span>
                  <span style={{fontSize:11, color:C.textMuted}}>{r.type}</span>
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background:"#FFCA2822", color:"#FFE082", border:"1px solid #FFCA2833", flexShrink:0}}>downstream caller</span>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Analyzed Files */}
      <Section id="files" title={A.scopeInfo.active ? "File Scope Map" : "Analyzed Files"} color="#546E7A" count={A.fileNames.length}>
        <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
          {A.fileNames.map((f,i) => {
            const isInScope = !A.scopeInfo.active || (scopeFiles && scopeFiles.has(f));
            return (
              <div key={i} style={{ fontSize:12, ...MONO, display:"flex", alignItems:"center", gap:8, padding:"3px 0" }}>
                <span style={{ color: isInScope ? C.green : C.textMuted }}>▸</span>
                <span style={{color: isInScope ? "#66BB6A" : C.textMuted, flex:1}}>{f}</span>
                {A.scopeInfo.active && (
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background: isInScope ? "#2E7D3222" : "#33333322",
                    color: isInScope ? C.green : C.textMuted,
                    border:`1px solid ${isInScope?"#2E7D3233":"#33333333"}`}}>
                    {isInScope ? "in scope" : "context"}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </Section>

    </div>
  );
}

export default AnalysisPanel;
