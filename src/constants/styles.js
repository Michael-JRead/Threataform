// src/constants/styles.js
// UI design tokens, color palette, typography, and shared style factory functions.
// Import specific exports rather than the whole module to keep bundles lean.

// ── Typography ────────────────────────────────────────────────────────────────
export const MONO = { fontFamily: "'JetBrains Mono','Fira Code','Cascadia Code',monospace" };
export const SANS = { fontFamily: "'Inter','DM Sans','system-ui',sans-serif" };

// ── Color palette (dark theme) ────────────────────────────────────────────────
export const C = {
  bg:        "#09090E",
  surface:   "#111118",
  surface2:  "#16161F",
  border:    "#1E1E2E",
  border2:   "#2A2A40",
  text:      "#E8E8F0",
  textSub:   "#9090A8",
  textMuted: "#5A5A70",
  accent:    "#FF9900",
  accentDim: "#FF990022",
  blue:      "#4A90E2",
  green:     "#4CAF50",
  red:       "#EF5350",
  critRed:   "#FF1744",
  orange:    "#FF7043",
  purple:    "#9C27B0",
};

// ── Severity system ───────────────────────────────────────────────────────────
export const SEV_COLOR = { CRITICAL: "#FF1744", HIGH: "#EF5350", MEDIUM: "#FFA726", LOW: "#66BB6A" };
export const SEV_BG    = { CRITICAL: "#200010", HIGH: "#200808", MEDIUM: "#1A1000", LOW: "#081808" };

// ── Reusable style factories ──────────────────────────────────────────────────

/** Card/box container style */
export const card = (borderColor = C.border) => ({
  background: C.surface,
  border: `1px solid ${borderColor}`,
  borderRadius: 8,
  overflow: "hidden",
});

/** Section header bar style */
export const sectionBar = (color = C.accent) => ({
  background: C.surface2,
  borderBottom: `1px solid ${C.border}`,
  padding: "10px 18px",
  fontSize: 11,
  fontWeight: 700,
  color,
  letterSpacing: ".08em",
  textTransform: "uppercase",
  display: "flex",
  alignItems: "center",
  gap: 8,
});

// ── XML syntax highlighter (used in DFD preview panel) ───────────────────────
export function hlXml(raw) {
  const xe2 = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  let out = "";
  const re = /(<\?xml[\s\S]*?\?>)|(<!--[\s\S]*?-->)|(<\/[\w:]+\s*>)|(<[\w:][\s\S]*?>)|([^<]+)/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    if (m[1]) out += `<span style="color:#f97583">${xe2(m[1])}</span>`;
    else if (m[2]) out += `<span style="color:#6a737d">${xe2(m[2])}</span>`;
    else if (m[3]) { const nm = m[3].match(/^<\/([\w:]+)/); out += nm ? `&lt;<span style="color:#79c0ff">/${xe2(nm[1])}</span>&gt;` : xe2(m[3]); }
    else if (m[4]) {
      const nm = m[4].match(/^<([\w:]+)/); const tn = nm ? nm[1] : ""; const rest = m[4].slice(1 + tn.length).replace(/\/?>$/, ""); const sc = m[4].endsWith("/>");
      const hr = rest.replace(/([\w:]+)(\s*=\s*")((?:[^"\\]|\\.)*)(")/g, (_, a, eq, v, cl) => `<span style="color:#ffa657">${xe2(a)}</span>${xe2(eq)}<span style="color:#a5d6ff">${xe2(v)}</span>${cl}`);
      out += `&lt;<span style="color:#79c0ff">${xe2(tn)}</span>${hr}${sc ? "/" : ""}`.trimEnd() + "&gt;";
    }
    else if (m[5]) out += `<span style="color:#4a7a80">${xe2(m[5])}</span>`;
  }
  return out;
}
