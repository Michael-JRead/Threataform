// src/constants/layout.js
// DFD diagram layout constants. Used by DFDGenerator, LegendBuilder, and the App.
// CRITICAL: Do not change these values without testing Lucidchart import —
// the XML geometry offsets depend on these exact numbers.

export const NW = 84;          // Node width
export const NH = 60;          // Node height
export const LH = 32;          // Lane header height
export const VGAP = 12;        // Vertical gap between nodes
export const HGAP = 18;        // Horizontal gap between nodes
export const TPAD = 18;        // Tier top padding
export const TVPAD = 22;       // Tier vertical padding
export const HDRH = 40;        // Tier header height
export const TGAP = 60;        // Gap between tiers
export const CPAD = 28;        // Canvas padding
export const MAXCOLS = 6;      // Max node columns per sub-column (was MAXROWS in earlier versions)
export const LEGEND_W = 252;   // Legend panel width
