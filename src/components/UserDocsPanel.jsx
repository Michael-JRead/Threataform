import { useState, useMemo } from "react";
import { FileText, X, FolderOpen } from '../icons.jsx';
import { C, SANS, MONO } from '../constants/styles.js';

// ─────────────────────────────────────────────────────────────────────────────
// USER DOCUMENTS PANEL
// ─────────────────────────────────────────────────────────────────────────────
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

function UserDocsPanel({docs, onAdd, onDelete, onClear}) {
  const [openDoc, setOpenDoc]       = useState(null);
  const [docDragging, setDocDragging] = useState(false);
  const [folderOpen, setFolderOpen] = useState({});

  const handleDrop = e => {
    e.preventDefault(); setDocDragging(false);
    if (e.dataTransfer.files?.length) onAdd(e.dataTransfer.files);
  };

  // Group docs by top-level folder (from webkitRelativePath)
  const grouped = useMemo(() => {
    const g = {}; // { folderLabel: [{doc, idx}] }
    docs.forEach((doc, idx) => {
      const parts = (doc.path || doc.name).split(/[/\\]/);
      const folder = parts.length > 1 ? parts.slice(0, -1).join("/") : "__root__";
      if (!g[folder]) g[folder] = [];
      g[folder].push({ doc, idx });
    });
    return g;
  }, [docs]);

  const totalKB = docs.reduce((s, d) => s + (d.content?.length || 0), 0) / 1024;
  const folderCount = Object.keys(grouped).filter(k => k !== "__root__").length;

  const renderDocRow = ({ doc, idx }) => {
    const ext = (doc.name || "").split(".").pop().toLowerCase();
    const typeMeta = DOC_TYPE_META[ext] || { label: ext.toUpperCase().slice(0,8) || "FILE", color:"#78909C" };
    const isOpen = openDoc === idx;
    return (
      <div key={idx} style={{borderTop:`1px solid ${C.border}`}}>
        <div
          style={{
            display:"flex", alignItems:"center", justifyContent:"space-between",
            padding:"10px 18px",
            background: isOpen ? `${C.blue}08` : "transparent",
            cursor:"pointer", transition:"background .15s",
          }}
          onClick={()=>setOpenDoc(isOpen ? null : idx)}
        >
          <div style={{display:"flex", alignItems:"center", gap:10, minWidth:0}}>
            <span style={{
              fontSize:9, fontWeight:700, color:typeMeta.color,
              background:`${typeMeta.color}15`, border:`1px solid ${typeMeta.color}33`,
              borderRadius:4, padding:"2px 6px", flexShrink:0, textAlign:"center"
            }}>{typeMeta.label}</span>
            <div style={{minWidth:0}}>
              <div style={{...SANS, fontSize:12, fontWeight:600, color:C.text,
                overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:320}}>
                {doc.name}
              </div>
              <div style={{fontSize:10, color:C.textMuted, marginTop:1}}>
                {doc.binary ? "binary / not shown" : `${(doc.content.length/1024).toFixed(1)} KB`}
              </div>
            </div>
          </div>
          <div style={{display:"flex", alignItems:"center", gap:8, flexShrink:0}}>
            <span style={{fontSize:11, color:C.textMuted, transform:isOpen?"rotate(180deg)":"none", transition:"transform .2s"}}>▼</span>
            <button onClick={e=>{e.stopPropagation();onDelete(idx);}}
              style={{ background:"transparent", border:`1px solid ${C.red}44`,
                borderRadius:5, padding:"3px 8px", color:C.red, fontSize:11, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center" }}>
              <X size={12}/>
            </button>
          </div>
        </div>
        {isOpen && !doc.binary && (
          <div style={{padding:"0 18px 14px", background:C.bg}}>
            <pre style={{
              ...MONO, fontSize:11, background:"#0D1117", color:"#C9D1D9",
              padding:"14px 16px", borderRadius:8, lineHeight:1.75,
              whiteSpace:"pre-wrap", overflowX:"auto",
              maxHeight:380, overflowY:"auto", margin:0, border:`1px solid ${C.border}`
            }}>
              {doc.content.slice(0, 40000)}{doc.content.length > 40000 ? "\n\n… (truncated for display — full content used in analysis)" : ""}
            </pre>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{display:"flex", flexDirection:"column", gap:0}}>
      {/* Header */}
      <div style={{
        padding:"22px 26px 18px",
        background:`linear-gradient(135deg, #78909C18, ${C.surface})`,
        borderBottom:`2px solid #78909C44`,
        borderRadius:"10px 10px 0 0",
      }}>
        <div style={{display:"flex", alignItems:"center", gap:14, marginBottom:10}}>
          <div style={{
            width:42, height:42, borderRadius:10,
            background:"#78909C22", border:"1px solid #78909C44",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:20, flexShrink:0
          }}>📂</div>
          <div style={{flex:1}}>
            <div style={{...SANS, fontSize:17, fontWeight:700, color:C.text}}>My Documents & Folders</div>
            <div style={{fontSize:11, color:"#78909C", marginTop:2}}>
              {docs.length} file{docs.length !== 1 ? "s" : ""}
              {folderCount > 0 && ` across ${folderCount} folder${folderCount !== 1?"s":""}`}
              {" · "}{totalKB.toFixed(1)} KB stored
            </div>
          </div>
          {docs.length > 0 && (
            <button onClick={onClear}
              style={{background:"transparent", border:`1px solid ${C.red}55`, borderRadius:6,
                padding:"6px 14px", color:C.red, fontSize:11, cursor:"pointer", ...SANS}}>
              Clear All
            </button>
          )}
        </div>
        <div style={{...SANS, fontSize:12, color:C.textSub, lineHeight:1.7}}>
          Upload entire Terraform repo folders or individual files of any type. All text-readable files are ingested for analysis — .tf, .hcl, .tfvars, .json, .yaml, .md, .sh, .py, Dockerfiles, Jenkinsfiles, and more.
        </div>
      </div>

      <div style={{background:C.surface, borderLeft:"1px solid #78909C22", borderRight:"1px solid #78909C22", borderBottom:"1px solid #78909C22", borderRadius:"0 0 10px 10px", overflow:"hidden"}}>
        {/* Drop zone + buttons */}
        <div style={{padding:"14px 16px"}}>
          <div
            onDrop={handleDrop}
            onDragOver={e=>{e.preventDefault();setDocDragging(true);}}
            onDragLeave={()=>setDocDragging(false)}
            style={{
              border:`2px dashed ${docDragging ? C.blue : C.border2}`,
              borderRadius:10, padding:"22px 20px", textAlign:"center",
              background: docDragging ? `${C.blue}10` : C.bg,
              transition:"all .2s",
            }}
          >
            <div style={{fontSize:26, marginBottom:6, opacity:docDragging?1:0.5}}>📂</div>
            <div style={{...SANS, color:C.textMuted, fontSize:12, marginBottom:14}}>
              Drop any files or folders here — all file types accepted
            </div>
            <div style={{display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap"}}>
              {/* Browse folder */}
              <label style={{
                background:`${C.accent}18`, border:`1px solid ${C.accent}55`,
                borderRadius:6, padding:"8px 18px",
                color:C.accent, fontSize:12, cursor:"pointer", ...SANS,
                display:"inline-flex", alignItems:"center", gap:6,
              }}>
                📂 Select Folder
                <input type="file" webkitdirectory="" multiple
                  onChange={e=>{if(e.target.files?.length)onAdd(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
              {/* Browse files */}
              <label style={{
                background:C.surface, border:`1px solid ${C.border2}`,
                borderRadius:6, padding:"8px 18px",
                color:C.textSub, fontSize:12, cursor:"pointer", ...SANS,
                display:"inline-flex", alignItems:"center", gap:6,
              }}>
                <FileText size={13}/> Browse Files
                <input type="file" multiple
                  onChange={e=>{if(e.target.files?.length)onAdd(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
            </div>
          </div>
          <div style={{fontSize:10, color:C.textMuted, textAlign:"center", marginTop:8, ...SANS}}>
            All files read client-side — nothing leaves your browser
          </div>
        </div>

        {docs.length === 0 && (
          <div style={{padding:"20px", textAlign:"center", color:C.textMuted, fontSize:12, ...SANS, borderTop:`1px solid ${C.border}`}}>
            No files uploaded yet. Select a Terraform folder from Bitbucket or upload individual files to enrich your analysis.
          </div>
        )}

        {/* Grouped file list */}
        {Object.entries(grouped).map(([folder, items]) => {
          if (folder === "__root__") {
            return items.map(renderDocRow);
          }
          const isFolderOpen = folderOpen[folder] !== false; // default open
          return (
            <div key={folder} style={{borderTop:`1px solid ${C.border}`}}>
              {/* Folder header */}
              <div
                onClick={()=>setFolderOpen(s=>({...s,[folder]:!isFolderOpen}))}
                style={{
                  display:"flex", alignItems:"center", gap:10,
                  padding:"9px 18px", cursor:"pointer",
                  background:`${C.surface2}`, borderBottom:isFolderOpen?`1px solid ${C.border}`:"none",
                }}
              >
                <FolderOpen size={13} style={{opacity: isFolderOpen ? 1 : 0.6}}/>
                <span style={{...SANS, fontSize:12, fontWeight:700, color:C.textSub,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", flex:1}}>
                  {folder}
                </span>
                <span style={{fontSize:10, color:C.textMuted, background:C.bg,
                  border:`1px solid ${C.border}`, borderRadius:10, padding:"1px 8px", flexShrink:0}}>
                  {items.length} file{items.length !== 1 ? "s" : ""}
                </span>
                <span style={{fontSize:10, color:C.textMuted}}>{isFolderOpen?"▲":"▼"}</span>
              </div>
              {isFolderOpen && items.map(renderDocRow)}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default UserDocsPanel;
