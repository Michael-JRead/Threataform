import { useState, useMemo } from "react";
import { C, SANS, MONO } from '../constants/styles.js';

// ─────────────────────────────────────────────────────────────────────────────
// SCOPE SELECTOR — lets users define which files are "in scope" for threat modeling
// ─────────────────────────────────────────────────────────────────────────────
function ScopeSelector({ files, scopeFiles, onScopeChange }) {
  const [open, setOpen] = useState(false);
  const [folderOpenState, setFolderOpenState] = useState({});

  // Group files by folder prefix
  const folderMap = useMemo(() => {
    const m = {};
    files.forEach(f => {
      const parts = f.path.replace(/\\/g,"/").split("/");
      const folder = parts.length > 1 ? parts.slice(0,-1).join("/") : "(root)";
      if (!m[folder]) m[folder] = [];
      m[folder].push(f);
    });
    return m;
  }, [files]);

  const folders = useMemo(() => Object.keys(folderMap).sort(), [folderMap]);

  // null = all in scope; new Set() = none selected; Set([...]) = subset
  const effectiveScope = (scopeFiles === null || scopeFiles === undefined)
    ? new Set(files.map(f => f.path))
    : scopeFiles;
  const inScopeCount  = effectiveScope.size;
  const allSelected   = scopeFiles === null || inScopeCount === files.length;
  const noneSelected  = scopeFiles !== null && scopeFiles !== undefined && inScopeCount === 0;
  const scopeActive   = scopeFiles !== null && scopeFiles !== undefined && inScopeCount > 0 && inScopeCount < files.length;

  const isFolderFull    = folder => folderMap[folder].every(f => effectiveScope.has(f.path));
  const isFolderPartial = folder => {
    const s = folderMap[folder].filter(f => effectiveScope.has(f.path)).length;
    return s > 0 && s < folderMap[folder].length;
  };

  const toggleFolder = (folder, e) => {
    e.stopPropagation();
    const next = new Set(effectiveScope);
    if (isFolderFull(folder)) folderMap[folder].forEach(f => next.delete(f.path));
    else                       folderMap[folder].forEach(f => next.add(f.path));
    onScopeChange(next);
  };

  const toggleFile = (path, e) => {
    e.stopPropagation();
    const next = new Set(effectiveScope);
    if (next.has(path)) next.delete(path); else next.add(path);
    onScopeChange(next);
  };

  const selectAll   = () => onScopeChange(null);
  const deselectAll = () => onScopeChange(new Set());

  const borderColor = scopeActive ? "#1E88E5" : "#333";

  return (
    <div style={{
      marginBottom:16, background:C.surface2,
      border:`1px solid ${borderColor}44`,
      borderLeft:`3px solid ${borderColor}`,
      borderRadius:8, overflow:"hidden"
    }}>
      {/* Header row */}
      <button onClick={()=>setOpen(o=>!o)} style={{
        width:"100%", textAlign:"left", background:"none", border:"none",
        cursor:"pointer", padding:"12px 18px", display:"flex", alignItems:"center", gap:12, ...SANS
      }}>
        <div style={{flex:1}}>
          <span style={{fontSize:13, fontWeight:700, color: scopeActive?"#42A5F5":C.textSub, letterSpacing:".05em"}}>
            Threat Model Scope
          </span>
          {" "}
          <span style={{fontSize:12, color:C.textMuted}}>
            {noneSelected
              ? `No files selected — analysis disabled`
              : scopeActive
              ? `${inScopeCount} of ${files.length} files in scope · ${files.length - inScopeCount} context-only`
              : `All ${files.length} files in scope (full analysis)`}
          </span>
        </div>
        {scopeActive && (
          <span style={{fontSize:11, padding:"3px 10px", borderRadius:4,
            background:"#1565C033", color:"#42A5F5", border:"1px solid #1565C055", fontWeight:600}}>SCOPE ACTIVE</span>
        )}
        <span style={{fontSize:12, color:C.textMuted}}>{open?"▲":"▼"}</span>
      </button>

      {open && (
        <div style={{borderTop:`1px solid ${C.border}`}}>
          {/* Quick controls */}
          <div style={{padding:"8px 18px", display:"flex", gap:8, alignItems:"center",
            background:C.surface, borderBottom:`1px solid ${C.border}`}}>
            <span style={{fontSize:12, color:C.textMuted, marginRight:4}}>Select:</span>
            <button onClick={selectAll} style={{
              fontSize:11, padding:"4px 12px", borderRadius:4, cursor:"pointer", ...SANS,
              border:"1px solid #4CAF5055", background:"#4CAF5011", color:"#4CAF50"
            }}>All</button>
            <button onClick={deselectAll} style={{
              fontSize:11, padding:"4px 12px", borderRadius:4, cursor:"pointer", ...SANS,
              border:"1px solid #EF535055", background:"#EF535011", color:"#EF5350"
            }}>None</button>
            <span style={{fontSize:11, color:C.textMuted, marginLeft:"auto", maxWidth:420, textAlign:"right"}}>
              Checked files → full threat analysis · Unchecked files → infrastructure context only
            </span>
          </div>

          {/* File tree */}
          <div style={{maxHeight:360, overflowY:"auto"}}>
            {folders.map(folder => {
              const folderFiles = folderMap[folder];
              const full    = isFolderFull(folder);
              const partial = isFolderPartial(folder);
              const isExpanded = folderOpenState[folder] !== false;
              const selCount = folderFiles.filter(f => effectiveScope.has(f.path)).length;

              return (
                <div key={folder}>
                  <div
                    onClick={()=>setFolderOpenState(s=>({...s,[folder]:!isExpanded}))}
                    style={{display:"flex", alignItems:"center", gap:10, padding:"7px 18px",
                      background:C.surface, borderBottom:`1px solid ${C.border}`, cursor:"pointer",
                      userSelect:"none"}}
                  >
                    <input type="checkbox"
                      checked={full}
                      ref={el => { if(el) el.indeterminate = partial && !full; }}
                      onChange={e=>toggleFolder(folder,e)}
                      onClick={e=>e.stopPropagation()}
                      style={{cursor:"pointer", accentColor:"#1E88E5", flexShrink:0}}
                    />
                    <span style={{...MONO, fontSize:12, flex:1,
                      color: full?C.text : partial?"#90CAF9" : C.textMuted}}>
                      {isExpanded?"▾ ":"▸ "}{folder}
                    </span>
                    <span style={{fontSize:11, color:C.textMuted}}>
                      {selCount}/{folderFiles.length}
                    </span>
                  </div>

                  {isExpanded && folderFiles.map((f,fi) => {
                    const isIn = effectiveScope.has(f.path);
                    const fname = f.path.replace(/\\/g,"/").split("/").pop();
                    return (
                      <div key={fi}
                        onClick={e=>toggleFile(f.path,e)}
                        style={{display:"flex", alignItems:"center", gap:10,
                          padding:"5px 18px 5px 40px",
                          background: isIn ? "#050D1A" : "transparent",
                          borderBottom:`1px solid ${C.border}`, cursor:"pointer", userSelect:"none"}}
                      >
                        <input type="checkbox" checked={!!isIn} onChange={e=>toggleFile(f.path,e)}
                          onClick={e=>e.stopPropagation()}
                          style={{cursor:"pointer", accentColor:"#1E88E5", flexShrink:0}}
                        />
                        <span style={{...MONO, fontSize:12, flex:1,
                          color: isIn ? "#90CAF9" : C.textMuted}}>{fname}</span>
                        {isIn && (
                          <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                            background:"#1565C033", color:"#42A5F5", border:"1px solid #1565C044"}}>
                            in scope
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default ScopeSelector;
