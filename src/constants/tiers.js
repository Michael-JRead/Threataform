// src/constants/tiers.js
// Architectural tier definitions for DFD layout and visual grouping.
// Each tier maps to a column in the left-to-right DFD layout.

export const TIERS = {
  xsphere: { label: "xSphere Private Cloud", bg: "#E3F2FD", border: "#0277BD", hdr: "#01579B", ord: 0 },
  org:     { label: "AWS Org · SCPs · OUs",  bg: "#FCE4EC", border: "#B71C1C", hdr: "#7F0000", ord: 1 },
  security:{ label: "Security · IAM · KMS",  bg: "#FFEBEE", border: "#C62828", hdr: "#B71C1C", ord: 2 },
  cicd:    { label: "CI/CD · Jenkins · IaC", bg: "#FBE9E7", border: "#BF360C", hdr: "#870000", ord: 3 },
  network: { label: "Network · VPC · TGW",   bg: "#F3E5F5", border: "#6A1B9A", hdr: "#4A148C", ord: 4 },
  compute: { label: "Compute · API · Events",bg: "#E8F5E9", border: "#1B5E20", hdr: "#004D40", ord: 5 },
  storage: { label: "Storage · Database",    bg: "#E3F2FD", border: "#0D47A1", hdr: "#01579B", ord: 6 },
};

/**
 * Detect TFE-Pave layer from a Terraform file path.
 * Returns "L0"–"L4" or null if not a pave-layer path.
 *   L0 = org/management, L1 = account vending, L2 = account pave/baseline,
 *   L3 = product/platform, L4 = service/workload/app
 */
export function detectPaveLayer(filePath) {
  const p = filePath.toLowerCase();
  if (/\bl0[_/-]|org[_/-]mgmt|management[_/-]|control[_/-]tower/.test(p)) return "L0";
  if (/\bl1[_/-]|vend|aft[_/-]|account[_/-]vend/.test(p)) return "L1";
  if (/\bl2[_/-]|account[_/-]pave|pave[_/-]account|baseline/.test(p)) return "L2";
  if (/\bl3[_/-]|product[_/-]pave|platform[_/-]|shared[_/-]/.test(p)) return "L3";
  if (/\bl4[_/-]|service[_/-]|workload[_/-]|app[_/-]/.test(p)) return "L4";
  return null;
}
