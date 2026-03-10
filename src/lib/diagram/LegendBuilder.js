// src/lib/diagram/LegendBuilder.js
import { NW, NH, LH, VGAP, HGAP, TPAD, TVPAD, HDRH, TGAP, CPAD, MAXCOLS, LEGEND_W } from '../../constants/layout.js';
import { C, SEV_COLOR } from '../../constants/styles.js';
import { TIERS } from '../../constants/tiers.js';

// ── XML escape helpers ────────────────────────────────────────────────────────
// xe: basic XML entity encoding for ASCII-safe label text
export const xe = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
// xeXml: full XML encoding including non-ASCII chars (for user-supplied content)
export const xeXml = s => String(s)
  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")
  .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, c => `&#${c.charCodeAt(0)};`);

export function buildLegendCells(lx, ly) {
  // All cells use parent="1" with ABSOLUTE coordinates.
  // Every <mxCell> is properly nested: opening tag → child <mxGeometry/> → </mxCell>
  // with consistent 2-space relative indentation (matching draw.io export format).
  // NO 'triangle' shape (draw.io-only). NO 'opacity'. html=1 + whiteSpace=wrap throughout.
  const LW=LEGEND_W, LR=24, TR=20, SH=18;
  const cells=[];
  let lid=9000;
  const nid=()=>`lg_${++lid}`;
  let ry=0;

  // vcell: generates ONE properly-nested vertex mxCell.
  // The outer allCells.map(c=>`    ${c}`) adds 4 spaces to line 1.
  // Interior lines use absolute indentation: 6sp for <mxGeometry>, 4sp for </mxCell>.
  const vcell=(id,value,style,gx,gy,gw,gh)=>
    `<mxCell id="${id}" value="${value}" style="${style}" vertex="1" parent="1">\n      <mxGeometry x="${gx}" y="${gy}" width="${gw}" height="${gh}" as="geometry"/>\n    </mxCell>`;

  // ── Background + header ──────────────────────────────────────────────────
  const TOTAL_H = 540;
  cells.push(
    vcell("legend_bg",      "", "rounded=1;fillColor=#F8F9FA;strokeColor=#283593;strokeWidth=2;html=1;",                                           lx,    ly,    LW, TOTAL_H),
    vcell("legend_hdr_bar", "", "rounded=0;fillColor=#1A237E;strokeColor=none;html=1;",                                                            lx,    ly,    LW, 28),
    vcell("legend_hdr_txt", "Legend", "text;whiteSpace=wrap;html=1;align=center;fontStyle=1;fontSize=12;fontColor=#FFFFFF;strokeColor=none;fillColor=none;", lx, ly, LW, 28)
  );
  ry = 36;

  // Helper: section heading
  const hdr=(t)=>{
    cells.push(vcell(nid(), xe(t),
      "text;whiteSpace=wrap;html=1;align=left;fontStyle=1;fontSize=9;fontColor=#1A237E;strokeColor=none;fillColor=none;",
      lx+10, ly+ry, LW-20, 16));
    ry+=SH;
  };

  // Helper: horizontal divider line
  const div=()=>{
    cells.push(vcell(nid(), "",
      "rounded=0;fillColor=#BBDEFB;strokeColor=none;html=1;",
      lx+8, ly+ry+2, LW-16, 1));
    ry+=10;
  };

  // Helper: node-type swatch + label row
  const nodeRow=(lbl,fill,stroke,extra="")=>{
    cells.push(
      vcell(nid(), "",
        `rounded=1;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;${extra}html=1;`,
        lx+10, ly+ry+3, 28, 17),
      vcell(nid(), xe(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+46, ly+ry+3, LW-56, 17)
    );
    ry+=LR;
  };

  // Helper: edge-type row — colored bar + end-cap rect + label.
  // 'triangle' shape is draw.io-only; replaced with small filled rectangle end-cap.
  const edgeRow=(lbl,color,dashed=false)=>{
    const lineW=62, lineH=3, capW=5, capH=9;
    const ex=lx+10, ey=ly+ry+12;
    const solidStyle=`rounded=0;fillColor=${color};strokeColor=none;html=1;`;
    if(dashed){
      for(let d=0;d<4;d++){
        cells.push(vcell(nid(), "", solidStyle, ex+d*16, ey, 11, lineH));
      }
    } else {
      cells.push(vcell(nid(), "", solidStyle, ex, ey, lineW, lineH));
    }
    // End-cap (arrow indicator — plain rectangle, Lucidchart-safe)
    cells.push(
      vcell(nid(), "", `rounded=0;fillColor=${color};strokeColor=none;html=1;`,
        ex+lineW, ey-3, capW, capH),
      vcell(nid(), xe(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+88, ly+ry+5, LW-98, 16)
    );
    ry+=LR;
  };

  // Helper: tier boundary swatch + label row
  const tierRow=(lbl,fill,stroke)=>{
    cells.push(
      vcell(nid(), "",
        `rounded=1;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;html=1;`,
        lx+10, ly+ry+3, 28, 13),
      vcell(nid(), xeXml(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+46, ly+ry+2, LW-56, 15)
    );
    ry+=TR;
  };

  // ── Section 1: Node Types ─────────────────────────────────────────────────
  hdr("NODE TYPES");
  nodeRow("AWS Resource (managed)",  "#FFFFFF","#546E7A");
  nodeRow("Data Source (read-only)", "#F5F5F5","#0277BD","dashed=1;dashPattern=4 3;");
  nodeRow("Terraform Module",        "#EDE7F6","#4527A0","dashed=1;dashPattern=5 3;");
  nodeRow("Sentinel Policy Gate",    "#FFF8E1","#E65100");
  nodeRow("Remote State Reference",  "#E3F2FD","#1565C0","dashed=1;dashPattern=6 4;");
  div();

  // ── Section 2: Connection Types ───────────────────────────────────────────
  hdr("CONNECTION TYPES");
  edgeRow("Implicit reference",    "#78909C", false);
  edgeRow("Explicit depends_on",   "#E53935", true);
  edgeRow("Module input / output", "#2E7D32", false);
  edgeRow("Remote state read",     "#6A1B9A", true);
  edgeRow("Data source read",      "#0277BD", true);
  div();

  // ── Section 3: Tier Boundaries ────────────────────────────────────────────
  hdr("TIER BOUNDARIES");
  tierRow("xSphere Private Cloud",  "#E8EAF6","#3949AB");
  tierRow("Org / Account",          "#F3E5F5","#6A1B9A");
  tierRow("Security / IAM / KMS",   "#FFEBEE","#C62828");
  tierRow("CI/CD / Jenkins / IaC",  "#FFF3E0","#E65100");
  tierRow("Network / VPC / TGW",    "#E8F5E9","#2E7D32");
  tierRow("Compute / API / Events", "#E3F2FD","#1565C0");
  tierRow("Storage / Database",     "#FFF8E1","#F57F17");

  // Footer
  cells.push(vcell(nid(), "threataform - enterprise terraform dfd",
    "text;whiteSpace=wrap;html=1;align=center;fontSize=7;fontColor=#78909C;strokeColor=none;fillColor=none;",
    lx, ly+ry+6, LW, 12));
  return cells;
}
