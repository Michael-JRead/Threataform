import { useState } from "react";
import { Shield, Brain, Target, X } from '../../icons.jsx';
import { C, SANS } from '../../constants/styles.js';

// ─────────────────────────────────────────────────────────────────────────────
// LANDING PAGE — Threat model selection / creation
// ─────────────────────────────────────────────────────────────────────────────
function LandingPage({ onCreateModel, onOpenModel, onDeleteModel, threatModels }) {
  const [newName, setNewName] = useState("");
  const EXAMPLES = ["Kinesis Data Analytics","Amazon EKS Platform","API Gateway + Lambda","RDS Multi-Region","S3 Data Lake","MSK Kafka Cluster"];

  const handleCreate = () => {
    const n = newName.trim();
    if (!n) return;
    onCreateModel(n);
  };

  const GRADE_COLORS = { A:"#43A047", B:"#7CB342", C:"#F57C00", D:"#E64A19", F:"#B71C1C" };

  return (
    <div style={{...SANS, minHeight:"100vh", background:C.bg, display:"flex", flexDirection:"column", alignItems:"center", padding:"72px 24px 60px"}}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>

      {/* Hero */}
      <div style={{textAlign:"center", maxWidth:640, marginBottom:56}}>
        <div style={{
          width:72, height:72, borderRadius:20, margin:"0 auto 22px",
          background:"linear-gradient(135deg,#FF6B35,#FF9900)",
          display:"flex", alignItems:"center", justifyContent:"center",
          boxShadow:"0 8px 32px #FF990050",
        }}><Shield size={36} color="#fff"/></div>
        <div style={{fontSize:40, fontWeight:800, color:C.text, letterSpacing:"-.03em", lineHeight:1.1, marginBottom:14}}>
          Threataform
        </div>
        <div style={{fontSize:15, color:C.textSub, lineHeight:1.75, maxWidth:520, margin:"0 auto"}}>
          Enterprise Terraform Threat Intelligence. Upload your infrastructure-as-code,
          auto-generate DFD diagrams, discover threats, and assess zero-trust posture.
        </div>
      </div>

      {/* New model card */}
      <div style={{
        width:"100%", maxWidth:660, background:C.surface,
        border:`1px solid ${C.border}`, borderRadius:18,
        padding:"32px 36px", marginBottom:48,
        boxShadow:"0 8px 48px #00000060",
      }}>
        <div style={{fontSize:20, fontWeight:700, color:C.text, marginBottom:6}}>
          Start New Threat Model
        </div>
        <div style={{fontSize:12, color:C.textSub, lineHeight:1.7, marginBottom:22}}>
          The <strong style={{color:C.text}}>product name</strong> (e.g., "Kinesis Data Analytics") is used to infer
          what services are in scope, enrich threat analysis, and seed the intelligence engine.
        </div>
        <div style={{display:"flex", gap:10, marginBottom:14}}>
          <input
            value={newName}
            onChange={e=>setNewName(e.target.value)}
            onKeyDown={e=>{if(e.key==="Enter"&&newName.trim())handleCreate();}}
            placeholder='e.g. "Kinesis Data Analytics", "EKS Multi-Tenant Platform"'
            autoFocus
            style={{
              flex:1, background:C.bg, border:`1px solid ${C.border2}`,
              borderRadius:10, padding:"13px 16px", color:C.text, fontSize:14,
              outline:"none", ...SANS,
            }}
          />
          <button onClick={handleCreate} disabled={!newName.trim()} style={{
            background:newName.trim()?"linear-gradient(135deg,#FF6B35,#FF9900)":C.surface2,
            border:"none", borderRadius:10, padding:"13px 26px",
            color:newName.trim()?"#fff":C.textMuted,
            fontSize:14, cursor:newName.trim()?"pointer":"not-allowed",
            fontWeight:700, ...SANS, flexShrink:0, transition:"all .15s",
          }}>
            Create →
          </button>
        </div>
        {/* Quick examples */}
        <div style={{display:"flex", flexWrap:"wrap", gap:7}}>
          <span style={{fontSize:11, color:C.textMuted, alignSelf:"center", marginRight:2}}>Quick:</span>
          {EXAMPLES.map(ex=>(
            <button key={ex} onClick={()=>setNewName(ex)} style={{
              background:"transparent", border:`1px solid ${C.border}`,
              borderRadius:20, padding:"4px 12px", fontSize:11, color:C.textMuted,
              cursor:"pointer", ...SANS, transition:"all .15s",
            }}
            onMouseEnter={e=>e.currentTarget.style.borderColor=C.accent}
            onMouseLeave={e=>e.currentTarget.style.borderColor=C.border}
            >{ex}</button>
          ))}
        </div>
      </div>

      {/* Existing models */}
      {threatModels.length > 0 && (
        <div style={{width:"100%", maxWidth:880}}>
          <div style={{fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase",
            letterSpacing:".12em", marginBottom:18}}>
            Existing Threat Models
          </div>
          <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(260px, 1fr))", gap:12}}>
            {threatModels.map(model=>(
              <div key={model.id}
                onClick={()=>onOpenModel(model)}
                style={{
                  background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                  padding:"20px 22px", cursor:"pointer", position:"relative",
                  transition:"all .2s",
                }}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent; e.currentTarget.style.transform="translateY(-2px)"; e.currentTarget.style.boxShadow=`0 8px 24px ${C.accent}20`;}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border; e.currentTarget.style.transform="translateY(0)"; e.currentTarget.style.boxShadow="none";}}
              >
                {/* Grade badge */}
                {model.grade && (
                  <div style={{
                    position:"absolute", top:14, right:40,
                    fontSize:13, fontWeight:800, color:GRADE_COLORS[model.grade]||C.accent,
                    background:`${GRADE_COLORS[model.grade]||C.accent}18`,
                    border:`1px solid ${GRADE_COLORS[model.grade]||C.accent}40`,
                    borderRadius:6, padding:"2px 8px",
                  }}>{model.grade}</div>
                )}
                {/* Delete */}
                <button onClick={e=>{e.stopPropagation();onDeleteModel(model.id);}} style={{
                  position:"absolute", top:10, right:10, background:"transparent", border:"none",
                  color:C.textMuted, cursor:"pointer", fontSize:14, padding:"4px 6px",
                  borderRadius:4, lineHeight:1,
                }} title="Delete model"><X size={13}/></button>

                <div style={{fontSize:15, fontWeight:700, color:C.text, marginBottom:6, paddingRight:56,
                  lineHeight:1.3, wordBreak:"break-word"}}>{model.name}</div>
                <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:8}}>
                  {model.environment && (
                    <span style={{fontSize:10, color:C.textMuted, background:C.surface2,
                      border:`1px solid ${C.border}`, borderRadius:4, padding:"1px 6px"}}>
                      {model.environment}
                    </span>
                  )}
                  <span style={{fontSize:10, color:C.textMuted}}>
                    {model.tfFileCount ? `${model.tfFileCount} TF files` : "No TF files"}
                  </span>
                  {model.docCount > 0 && (
                    <span style={{fontSize:10, color:C.textMuted}}>{model.docCount} docs</span>
                  )}
                </div>
                <div style={{fontSize:10, color:C.textMuted}}>
                  {model.updatedAt
                    ? `Updated ${new Date(model.updatedAt).toLocaleDateString()}`
                    : `Created ${new Date(model.createdAt).toLocaleDateString()}`}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default LandingPage;
