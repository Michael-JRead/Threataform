// src/lib/diagram/DFDGenerator.js
import { NW, NH, LH, VGAP, HGAP, TPAD, TVPAD, HDRH, TGAP, CPAD, LEGEND_W } from '../../constants/layout.js';
import { C, SEV_COLOR } from '../../constants/styles.js';
import { TIERS } from '../../constants/tiers.js';
import { RT } from '../../data/resource-types.js';
import { getElementType as _getElementType } from '../../data/attack-data.js';
import { buildLegendCells, xe, xeXml } from './LegendBuilder.js';

// Architecture layer prefix map for badge annotation
const _ARCH_LAYER_MAP = {
  'aws_organizations_': 1, 'scp': 1,
  'aws_eks_': 2, 'kubernetes_': 2,
  'aws_iam_': 3,
  'aws_vpc': 4, 'aws_subnet': 4, 'aws_security_group': 4, 'aws_transit_gateway': 4,
  'aws_wafv2_': 5, 'aws_guardduty_': 5,
  'aws_rds': 6, 'aws_msk': 6, 'aws_opensearch': 6, 'aws_elasticache': 6, 'aws_kendra': 6,
  'aws_lambda': 7, 'aws_ecs_service': 7,
};
function _getArchLayer(resourceType) {
  const rt = (resourceType||'').toLowerCase();
  for(const [prefix, layer] of Object.entries(_ARCH_LAYER_MAP)) {
    if(rt.includes(prefix)) return layer;
  }
  return null;
}

export function generateDFDXml(resources, modules, connections, intelligenceCtx, archAnalysis = null) {
  const TORD = ["xsphere","org","security","cicd","network","compute","storage"];
  const groups = {};
  TORD.forEach(t=>{groups[t]=[];});

  resources.forEach(r=>{
    const meta = RT[r.type]||RT._default;
    if(!groups[meta.t])groups[meta.t]=[];
    groups[meta.t].push({...r, _meta:meta, _isModule:false});
  });
  modules.forEach(m=>{
    const t = "cicd";
    if(!groups[t])groups[t]=[];
    const mcolor = m.srcType==="sentinel"?"#E65100":m.srcType==="remote_state"?"#1565C0":"#558B2F";
    groups[t].push({...m, _meta:{l:m.name, t, i:"-", c:mcolor}, _isModule:true});
  });

  const activeTiers = TORD.filter(t=>groups[t]&&groups[t].length>0);
  // idMap stores { cid, tier, tierIdx } for smart edge routing
  const idMap = new Map();
  const containers=[], edges=[], vertices=[];
  let cellN=100;

  // ── HORIZONTAL LEFT-TO-RIGHT LAYOUT ────────────────────────────────────────
  // Legend sits at top-left (CPAD, CPAD). Diagram flows right from legend.
  // Each tier is a vertical column; nodes within a tier flow top-to-bottom.
  // MAXROWS: max nodes per sub-column within a tier before wrapping to next column.
  const MAXROWS = 5;
  const DIAG_X   = CPAD + LEGEND_W + 40; // diagram start X (right of legend)
  const DIAG_Y   = CPAD;                 // diagram start Y (same top as legend)

  // Uniform tier height: based on tallest single sub-column across all tiers
  const maxRowsNeeded = activeTiers.reduce((mx,t)=>Math.max(mx,Math.min(groups[t].length,MAXROWS)),1);
  const tierH = HDRH + TVPAD + maxRowsNeeded*(NH+LH+VGAP) - VGAP + TVPAD;

  let globalX = DIAG_X;

  activeTiers.forEach((t,ti)=>{
    const nodes=groups[t];
    // How many sub-columns does this tier need?
    const subCols = Math.ceil(nodes.length / MAXROWS);
    const tW = TPAD*2 + subCols*(NW+HGAP) - HGAP;

    const tm = TIERS[t]||{label:t, bg:"#F5F5F5", border:"#999", hdr:"#555"};
    const tcid=`tier_${t}`;
    // Single plain rectangle per tier — most compatible with Lucidchart's draw.io importer.
    // Label floats at top-left of the tier background box.
    containers.push(
      `<mxCell id="${tcid}" value="${xeXml(tm.label)}&#xa;(${nodes.length} resources)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=${tm.bg};strokeColor=${tm.border};strokeWidth=2;fontColor=${tm.hdr};fontSize=11;fontStyle=1;align=left;verticalAlign=top;spacingLeft=10;spacingTop=5;" vertex="1" parent="1">\n      <mxGeometry x="${globalX}" y="${DIAG_Y}" width="${tW}" height="${tierH}" as="geometry"/>\n    </mxCell>`
    );

    nodes.forEach((n,i)=>{
      // Within a tier: flow top-to-bottom, wrapping into sub-columns
      const subCol = Math.floor(i / MAXROWS);
      const row    = i % MAXROWS;
      const nx = globalX + TPAD + subCol*(NW+HGAP);
      const ny = DIAG_Y + HDRH + TVPAD + row*(NH+LH+VGAP);
      const cid=`n_${++cellN}`;
      idMap.set(n.id, {cid, tier:t, tierIdx:ti});
      const meta=n._meta;
      const shortType = n._isModule
        ? `${n.srcType||"module"}`
        : (n.type||"").replace(/^aws_|^xsphere_/,"").replace(/_/g," ").substring(0,20);
      const rawMulti = n.multi ? ` [${n.multi}]` : "";
      const rawName = (n.label||n.name||"").substring(0,18) + rawMulti;
      // Use &#xa; for multi-line labels — value is pre-escaped so do NOT apply xe() again.
      // xeXml() encodes user content (XML chars + non-ASCII); &#xa; is then appended literally.
      const escapedName = xeXml(rawName);
      const escapedType = shortType ? xeXml(shortType) : "";
      // Intelligence enrichment: if uploaded docs mention STRIDE threats for this resource,
      // add a third line to the node label (e.g. "⚑ tamper,infoDisclose")
      // This only adds content to the VALUE field — XML format/structure is untouched.
      let threatLine = "";
      if (intelligenceCtx && intelligenceCtx._built) {
        const hits = intelligenceCtx.analyzeResource(n.type||"", n.name||"");
        const strideFound = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.stride||{})))].slice(0,2);
        if (strideFound.length) threatLine = xeXml(`\u26A0 ${strideFound.join(",")}`);
      }
      // Architecture layer badge: append [L{n}] if archAnalysis provided and layer is known.
      // Also append [UNGOVERNED] if resource type has no factory coverage in archAnalysis.
      let archBadge = "";
      if (archAnalysis && !n._isModule) {
        const al = _getArchLayer(n.type||"");
        if (al !== null) {
          archBadge = xeXml(`[L${al}]`);
        }
        // Check if resource type is ungoverned (no factory covers it)
        if (archAnalysis.factories) {
          const rt = (n.type||'').toLowerCase();
          const hasFactory = Object.entries(archAnalysis.factories).some(([, f]) =>
            f.status === 'present' || f.status === 'partial'
          );
          if (!hasFactory && al === null) {
            archBadge = xeXml('[UNGOVERNED]');
          }
        }
      }
      const rawLbl = (() => {
        const parts = [escapedName];
        if (escapedType) parts.push(escapedType);
        if (threatLine) parts.push(threatLine);
        if (archBadge) parts.push(archBadge);
        return parts.join('&#xa;');
      })();
      const bdrDash = n._isModule||n.srcType==="remote_state" ? "dashed=1;" : "";
      const bgColor = n._isModule ? "#FAFFF5" : "#FFFFFF";
      // Matches the working reference XML: html=1 + whiteSpace=wrap are required for Lucidchart.
      const style=`rounded=1;whiteSpace=wrap;html=1;fillColor=${bgColor};strokeColor=${meta.c||"#546E7A"};strokeWidth=1;fontColor=#333333;fontSize=9;align=center;${bdrDash}`;
      vertices.push(
        `<mxCell id="${cid}" value="${rawLbl}" style="${style}" vertex="1" parent="1">\n      <mxGeometry x="${nx}" y="${ny}" width="${NW}" height="${NH+LH}" as="geometry"/>\n    </mxCell>`
      );
    });

    globalX += tW + TGAP;
  });

  const totalW = globalX;
  const totalH = DIAG_Y + tierH + CPAD;

  // Edges with smart exit/entry routing — orthogonalEdgeStyle for L→R flow.
  // Cross-tier edges flow left→right. Same-tier: orthogonal routing.
  const seenE=new Set();
  connections.forEach(c=>{
    const sInfo=idMap.get(c.from), tInfo=idMap.get(c.to);
    if(!sInfo||!tInfo)return;
    const ek=`${sInfo.cid}|${tInfo.cid}`;
    if(seenE.has(ek))return;
    seenE.add(ek);
    const color=c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#2E7D32":"#78909C";
    const dash=c.kind==="explicit"?"dashed=1;" : "";
    const lbl=c.kind==="explicit"?"depends_on":c.kind==="module-input"?"input":"";
    // Edge style matching the working reference XML: orthogonalEdgeStyle + html=1 + blockThin arrow.
    // This is the exact pattern Lucidchart's draw.io importer handles correctly.
    edges.push(
      `<mxCell id="e_${++cellN}" value="${xe(lbl)}" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=${color};strokeWidth=2;${dash}fontColor=${color};fontSize=8;endArrow=blockThin;" edge="1" source="${sInfo.cid}" target="${tInfo.cid}" parent="1">\n      <mxGeometry relative="1" as="geometry"/>\n    </mxCell>`
    );
  });

  // Legend at TOP-LEFT (CPAD, CPAD) — diagram flows right from (DIAG_X, CPAD).
  // Uses only Lucidchart-safe shapes: html=1 + whiteSpace=wrap, no triangle, no opacity.
  const legendCells=buildLegendCells(CPAD, CPAD);
  const allCells=[...containers,...edges,...vertices,...legendCells];
  // Return bare <mxGraphModel> — wrapped in <mxfile> wrapper when downloading/copying.
  const pageW = Math.max(5000, totalW+200);
  const pageH = Math.max(3500, totalH+200);
  return [
    // Full mxGraphModel attributes matching draw.io export format — required for correct Lucidchart import.
    `<mxGraphModel dx="5000" dy="3500" grid="1" gridSize="20" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${pageW}" pageHeight="${pageH}" math="0" shadow="0" background="#FAFAFA">`,
    `  <root>`,
    `    <mxCell id="0"/>`,
    `    <mxCell id="1" parent="0"/>`,
    ...allCells.map(c=>`    ${c}`),
    `  </root>`,
    `</mxGraphModel>`
  ].join("\n");
}
