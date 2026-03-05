
// ─── XML / DFD GENERATOR ──────────────────────────────────────────────────────

const xa = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

const NW=80, NH=80, LH=36, VGAP=14, HGAP=22, TIER_PAD=20, TIER_VPAD=26, TIER_GAP=60, HEADER_H=44;
const MAX_COLS = 5, CANVAS_PAD = 28;

function buildDFDXml(resources, modules, connections) {
  const TIER_ORDER = ["xsphere","org","security","cicd","spinnaker","network","compute","storage"];

  // Group resources by tier
  const groups = {};
  TIER_ORDER.forEach(t => { groups[t] = []; });

  resources.forEach(r => {
    const meta = RESOURCE_TIERS[r.type] || RESOURCE_TIERS._default;
    const t = meta.tier;
    if (!groups[t]) groups[t] = [];
    groups[t].push({ ...r, meta });
  });

  // Add modules as special nodes
  modules.forEach(m => {
    const t = m.srcType === "sentinel" ? "cicd" : "cicd";
    if (!groups[t]) groups[t] = [];
    groups[t].push({ ...m, isModule:true, meta:{ label:m.name, tier:t, icon:"📦", color:"#558B2F" } });
  });

  // Active tiers
  const activeTiers = TIER_ORDER.filter(t => groups[t] && groups[t].length > 0);

  // Layout: tiers stacked vertically; nodes in rows within each tier
  const tierLayouts = {};
  let globalY = CANVAS_PAD;
  const validNodes = new Map();

  activeTiers.forEach(t => {
    const nodes = groups[t];
    const cols = Math.min(nodes.length, MAX_COLS);
    const rows = Math.ceil(nodes.length / MAX_COLS);
    const tW = TIER_PAD*2 + cols*(NW+HGAP) - HGAP;
    const tH = HEADER_H + TIER_VPAD + rows*(NH+LH+VGAP) - VGAP + TIER_VPAD;

    tierLayouts[t] = { x:CANVAS_PAD, y:globalY, w:tW, h:tH, nodes:[] };

    nodes.forEach((n, i) => {
      const col = i % MAX_COLS;
      const row = Math.floor(i / MAX_COLS);
      const nx = CANVAS_PAD + TIER_PAD + col*(NW+HGAP);
      const ny = globalY + HEADER_H + TIER_VPAD + row*(NH+LH+VGAP);
      tierLayouts[t].nodes.push({ ...n, x:nx, y:ny, w:NW, h:NH });
      validNodes.set(n.id, { x:nx+NW/2, y:ny+NH/2, cx:nx, cy:ny });
    });

    globalY += tH + TIER_GAP;
  });

  const totalH = globalY;
  const maxTierW = Math.max(...activeTiers.map(t => tierLayouts[t].w));
  const totalW = maxTierW + CANVAS_PAD*2;

  // Build XML cells
  const containers = [], edges = [], vertices = [];
  let cellId = 100;
  const idMap = new Map(); // node.id → cell id

  // Tier swimlanes
  activeTiers.forEach(t => {
    const tl = tierLayouts[t];
    const tm = TIER_META[t] || { label:t, bg:"#F5F5F5", border:"#999", hdr:"#555" };
    const cid = `tier_${t}`;
    containers.push(
      `<mxCell id="${cid}" value="${xa(tm.label)} (${tl.nodes.length})" style="swimlane;startSize=${HEADER_H};fillColor=${tm.hdr};swimlaneFillColor=${tm.bg};strokeColor=${tm.border};strokeWidth=2;fontColor=#FFFFFF;fontSize=12;fontStyle=1;align=left;swimlaneLine=1;rounded=1;arcSize=2;html=1;" vertex="1" parent="1">` +
      `<mxGeometry x="${tl.x}" y="${tl.y}" width="${Math.max(tl.w, totalW-CANVAS_PAD*2)}" height="${tl.h}" as="geometry"/>` +
      `</mxCell>`
    );

    // Node cells
    tl.nodes.forEach(n => {
      const cname = `n_${(++cellId)}`;
      idMap.set(n.id, cname);
      const meta = n.meta || RESOURCE_TIERS[n.type] || RESOURCE_TIERS._default;
      const icon = meta.icon || "◆";
      const color = meta.color || "#546E7A";
      const shortType = n.isModule
        ? `${n.srcType} module`
        : (n.type || "").replace(/^aws_|^xsphere_/,"").replace(/_/g," ").substring(0,22);
      const label = `<b style="font-size:10px">${xa((n.label||n.name||"").substring(0,20))}</b><br/><span style="font-size:8px;color:#888">${xa(shortType)}</span>`;

      const borderStyle = n.isModule ? "dashed=1;" : "";
      const style = n.srcType === "sentinel"
        ? `rounded=1;arcSize=8;fillColor=#FFF8E1;strokeColor=#E65100;strokeWidth=2;fontColor=#333;fontSize=10;html=1;align=center;whiteSpace=wrap;${borderStyle}`
        : `rounded=1;arcSize=8;fillColor=#FFFFFF;strokeColor=${color};strokeWidth=1.5;fontColor=#333;fontSize=10;html=1;align=center;whiteSpace=wrap;${borderStyle}`;

      vertices.push(
        `<mxCell id="${cname}" value="${label}" style="${style}" vertex="1" parent="1">` +
        `<mxGeometry x="${n.x}" y="${n.y}" width="${NW}" height="${NH+LH}" as="geometry"/>` +
        `</mxCell>`
      );
    });
  });

  // Edge cells
  const seenEdge = new Set();
  connections.forEach(c => {
    const srcId = idMap.get(c.from);
    const tgtId = idMap.get(c.to);
    if (!srcId || !tgtId) return;
    const ekey = `${srcId}|${tgtId}`;
    if (seenEdge.has(ekey)) return;
    seenEdge.add(ekey);

    const color = c.type === "explicit" ? "#E74C3C"
                : c.type === "module-input" ? "#2E7D32"
                : "#78909C";
    const dash = c.type === "explicit" ? "dashed=1;dashPattern=5 3;" : "";
    const label = c.type === "explicit" ? "depends_on" : c.type === "module-input" ? "input" : "";
    const eid = `e_${++cellId}`;
    edges.push(
      `<mxCell id="${eid}" value="${label}" style="edgeStyle=orthogonalEdgeStyle;html=1;rounded=1;strokeColor=${color};strokeWidth=1.5;${dash}endArrow=block;endFill=1;fontSize=9;fontColor=${color};" edge="1" source="${srcId}" target="${tgtId}" parent="1">` +
      `<mxGeometry relative="1" as="geometry"/>` +
      `</mxCell>`
    );
  });

  const allCells = containers.concat(edges).concat(vertices);

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<mxfile host="enterprise-tf-dfd" version="21.0.0">`,
    `<diagram id="tf-dfd" name="Enterprise Terraform DFD">`,
    `<mxGraphModel dx="1800" dy="1200" grid="1" gridSize="10" guides="1" page="1" pageScale="1" pageWidth="${Math.max(1654,totalW+200)}" pageHeight="${Math.max(1169,totalH+200)}" math="0" shadow="0">`,
    `<root>`,
    `<mxCell id="0"/>`,
    `<mxCell id="1" parent="0"/>`,
    ...allCells,
    `</root>`,
    `</mxGraphModel>`,
    `</diagram>`,
    `</mxfile>`
  ].join("\n");
}

export { buildDFDXml };
