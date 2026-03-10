import sys,io
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding="utf-8")
fp="C:/Users/mjrma/Downloads/threataform/terraform-enterprise-intelligence.jsx"
c=open(fp,"r",encoding="utf-8").read()
print("Loaded",len(c),"chars")
NL=chr(10)
Q=chr(39)
DQ=chr(34)
TICK=chr(96)
DOLLAR=chr(36)
DOC=chr(55357)+chr(56356)
SP12=chr(32)*12
MARKER=chr(123)+chr(33)+"summary?.controlInventory ? ("
if "scannedDocs" in c:
    print("C3: already applied")
elif MARKER not in c:
    print("ERROR: marker not found")
else:
    j=[]
    j.append(SP12+'{/* Docs scanned for control evidence */}')
    j.append(SP12+'{(() => {')
    j.append(SP12+"  const scannedDocs = userDocs.filter(d => ['security-controls','cspm','compliance-guide','trust-cloud'].includes(d.category || d.docCategory));")
    j.append(SP12+'  return scannedDocs.length > 0 ? (')
    j.append(SP12+'    <div style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 12px", background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, marginBottom:12, fontSize:12 }}>')
    j.append(SP12+'      <span style={{ color:C.accent }}>📄</span>')
    j.append(SP12+"      <span style={{ color:C.textSub }}>Scanned {scannedDocs.length} security document{scannedDocs.length>1?'s':''} for control evidence:</span>")
    j.append(SP12+"      <span style={{ color:C.text, fontWeight:500 }}>{scannedDocs.map(d=>d.name).join(', ')}</span>")
    j.append(SP12+'    </div>')
    j.append(SP12+'  ) : null;')
    j.append(SP12+'})()}')
    jsx_block = NL.join(j) + NL
    old_str = SP12 + MARKER
    new_str = jsx_block + SP12 + MARKER
    if old_str not in c: print("ERROR: old_str not found in JSX")
    else:
        c2 = c.replace(old_str, new_str, 1)
        open(fp,"w",encoding="utf-8").write(c2)
        print("C3: applied, new size:", len(c2))
