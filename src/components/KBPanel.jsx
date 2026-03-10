import { useState } from "react";
import { BookOpen, KB_DOMAIN_ICONS } from '../icons.jsx';
import { C, MONO, SANS } from '../constants/styles.js';
import { KB } from '../data/kb-domains.js';

// ─────────────────────────────────────────────────────────────────────────────
// KNOWLEDGE PANEL
// ─────────────────────────────────────────────────────────────────────────────
function KBPanel({domain}) {
  const d = KB[domain];
  if (!d) return null;
  const [openSec, setOpenSec] = useState(0);
  const DomainIcon = KB_DOMAIN_ICONS[domain] || BookOpen;

  return (
    <div style={{display:"flex", flexDirection:"column", gap:0}}>
      {/* Domain header */}
      <div style={{
        padding:"24px 28px 20px",
        background:`linear-gradient(135deg, ${d.color}18, ${C.surface})`,
        borderBottom:`2px solid ${d.color}44`,
        borderRadius:"10px 10px 0 0",
      }}>
        <div style={{
          display:"flex", alignItems:"center", gap:14, marginBottom:10
        }}>
          <div style={{
            width:42, height:42, borderRadius:10,
            background:`linear-gradient(135deg,${d.color}33,${d.color}11)`,
            border:`1px solid ${d.color}44`,
            display:"flex", alignItems:"center", justifyContent:"center",
            flexShrink:0, color:d.color,
          }}><DomainIcon size={20}/></div>
          <div>
            <div style={{...SANS, fontSize:18, fontWeight:700, color:C.text, letterSpacing:"-.01em"}}>{d.title}</div>
            <div style={{fontSize:11, color:d.color, marginTop:2, fontWeight:500}}>
              {d.sections.length} section{d.sections.length !== 1 ? "s" : ""}
            </div>
          </div>
        </div>
        {d.sections[0]?.body && (
          <div style={{...SANS, fontSize:13, color:C.textSub, lineHeight:1.75, maxWidth:720, marginTop:4}}>
            {d.sections[0].body.length > 320 ? d.sections[0].body.substring(0, 320) + "…" : d.sections[0].body}
          </div>
        )}
      </div>

      {/* Accordion sections */}
      <div style={{
        background:C.surface,
        borderLeft:`1px solid ${d.color}22`,
        borderRight:`1px solid ${d.color}22`,
        borderBottom:`1px solid ${d.color}22`,
        borderRadius:"0 0 10px 10px", overflow:"hidden"
      }}>
        {d.sections.map((sec, si) => {
          const isOpen = openSec === si;
          return (
            <div key={si} style={{borderBottom:`1px solid ${C.border}`}}>
              <button
                onClick={()=>setOpenSec(isOpen ? null : si)}
                style={{
                  width:"100%", textAlign:"left",
                  padding:"14px 20px",
                  background: isOpen ? `${d.color}10` : "transparent",
                  border:"none", cursor:"pointer",
                  display:"flex", alignItems:"center", justifyContent:"space-between",
                  ...SANS, fontSize:13, fontWeight:600,
                  color: isOpen ? d.color : C.text,
                  transition:"background .15s, color .15s",
                }}
              >
                <div style={{display:"flex", alignItems:"center", gap:10}}>
                  <span style={{
                    width:22, height:22, borderRadius:5,
                    background: isOpen ? `${d.color}22` : `${C.border}`,
                    display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:9, color: isOpen ? d.color : C.textMuted,
                    fontWeight:700, flexShrink:0
                  }}>{si+1}</span>
                  <span>{sec.heading}</span>
                </div>
                <span style={{
                  fontSize:11, color: isOpen ? d.color : C.textMuted,
                  transform: isOpen ? "rotate(180deg)" : "none",
                  transition:"transform .2s", lineHeight:1
                }}>▼</span>
              </button>

              {isOpen && (
                <div style={{padding:"4px 20px 18px", background:C.bg}}>
                  {sec.body && !sec.items && (
                    <div style={{
                      ...MONO, fontSize:12, background:"#0D1117",
                      color:"#C9D1D9", padding:"16px 18px", borderRadius:8,
                      marginBottom:12, lineHeight:1.85, whiteSpace:"pre-wrap",
                      overflowX:"auto", border:`1px solid ${C.border}`
                    }}>
                      {sec.body}
                    </div>
                  )}
                  {sec.body && sec.items && (
                    <div style={{
                      ...SANS, fontSize:13, color:C.textSub,
                      lineHeight:1.75, marginBottom:14, padding:"10px 0 4px"
                    }}>
                      {sec.body}
                    </div>
                  )}
                  {sec.items && (
                    <div style={{display:"flex", flexDirection:"column", gap:0}}>
                      {sec.items.map((item, ii) => (
                        <div key={ii} style={{
                          display:"flex", gap:12, alignItems:"flex-start",
                          padding:"9px 0",
                          borderBottom:`1px solid ${C.border}`,
                        }}>
                          <span style={{
                            color:d.color, fontSize:12, marginTop:1,
                            flexShrink:0, fontWeight:700
                          }}>›</span>
                          <span style={{
                            ...SANS, fontSize:13, color:C.textSub, lineHeight:1.7
                          }}>{item}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default KBPanel;
