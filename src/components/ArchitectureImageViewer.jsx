import { useRef } from "react";
import { ImageIcon } from '../icons.jsx';
import { C, SANS } from '../constants/styles.js';

// ─────────────────────────────────────────────────────────────────────────────
// ARCHITECTURE IMAGE VIEWER
// User exports XML → imports to Lucidchart → exports diagram image → uploads here
// ─────────────────────────────────────────────────────────────────────────────
function ArchitectureImageViewer({ image, onUpload }) {
  const inputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    if (!/^image\//i.test(file.type) && !/\.(png|jpg|jpeg|svg|webp|gif)$/i.test(file.name)) return;
    const reader = new FileReader();
    reader.onload = (e) => onUpload(e.target.result, file.name);
    reader.readAsDataURL(file);
  };

  const onDrop = (e) => {
    e.preventDefault();
    handleFile(e.dataTransfer.files[0]);
  };

  if (!image) {
    return (
      <div
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        style={{
          display:"flex", alignItems:"center", justifyContent:"center",
          height:"calc(100vh - 130px)", flexDirection:"column", gap:20,
        }}
      >
        <div style={{
          border:`2px dashed ${C.border}`, borderRadius:16,
          padding:"56px 64px", textAlign:"center",
          display:"flex", flexDirection:"column", alignItems:"center", gap:16,
          maxWidth:560, cursor:"pointer", transition:"border-color .2s",
        }}
          onClick={() => inputRef.current?.click()}
          onMouseEnter={e => e.currentTarget.style.borderColor = C.accent}
          onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
        >
          <ImageIcon size={48} style={{color:C.textMuted, opacity:0.5}}/>
          <div style={{fontSize:16, fontWeight:700, color:C.text}}>Upload Architecture Diagram</div>
          <div style={{fontSize:13, color:C.textMuted, lineHeight:1.6}}>
            Export the XML from the <strong style={{color:C.accent}}>XML Output</strong> tab,
            import it into <strong style={{color:C.accent}}>Lucidchart</strong>,
            then export your diagram as an image and upload it here.
          </div>
          <div style={{
            marginTop:4, background:`${C.accent}18`, border:`1px solid ${C.accent}30`,
            borderRadius:8, padding:"8px 20px", fontSize:12, color:C.accent, fontWeight:600,
          }}>
            Click to upload or drag & drop
          </div>
          <div style={{fontSize:11, color:C.textMuted}}>PNG · JPG · SVG · WebP</div>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          style={{display:"none"}}
          onChange={e => handleFile(e.target.files[0])}
        />
      </div>
    );
  }

  return (
    <div style={{position:"relative", height:"calc(100vh - 130px)", overflow:"auto", background:"#080810"}}>
      {/* Replace button */}
      <button
        onClick={() => inputRef.current?.click()}
        style={{
          position:"absolute", top:16, right:16, zIndex:10,
          background:`${C.accent}22`, border:`1px solid ${C.accent}50`,
          borderRadius:8, padding:"6px 16px", color:C.accent,
          fontSize:12, fontWeight:600, cursor:"pointer", ...SANS,
        }}
      >
        Replace Image
      </button>
      <input
        ref={inputRef}
        type="file"
        accept="image/*"
        style={{display:"none"}}
        onChange={e => handleFile(e.target.files[0])}
      />
      <img
        src={image}
        alt="Architecture Diagram"
        style={{
          display:"block", maxWidth:"100%", height:"auto",
          margin:"0 auto", padding:24,
        }}
      />
    </div>
  );
}

export default ArchitectureImageViewer;
