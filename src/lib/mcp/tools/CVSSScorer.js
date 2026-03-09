/**
 * src/lib/mcp/tools/CVSSScorer.js
 * Pure JavaScript CVSS v3.1 base score calculator.
 * Formula from NVD specification: https://nvd.nist.gov/vuln-metrics/cvss
 * No external dependencies.
 *
 * Usage:
 *   scoreCVSS('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
 *   // → { score: 9.8, severity: 'Critical', vector: 'CVSS:3.1/AV:N/...' }
 */

// CVSS v3.1 metric weights
const AV  = { N: 0.85, A: 0.62, L: 0.55, P: 0.2  };  // Attack Vector
const AC  = { L: 0.77, H: 0.44 };                       // Attack Complexity
const PR_U = { N: 0.85, L: 0.62, H: 0.27 };            // Privileges Required (Scope Unchanged)
const PR_C = { N: 0.85, L: 0.68, H: 0.5  };            // Privileges Required (Scope Changed)
const UI  = { N: 0.85, R: 0.62 };                       // User Interaction
const CI  = { N: 0,    L: 0.22, H: 0.56 };             // Confidentiality / Integrity / Availability Impact

/**
 * Calculate CVSS v3.1 base score from a vector string.
 *
 * @param {string} vector  e.g. 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
 *                         or   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
 * @returns {{ score: number, severity: string, vector: string, metrics: object }|{ error: string }}
 */
export function scoreCVSS(vector) {
  if (typeof vector !== 'string') return { error: 'vector must be a string' };

  // Strip optional prefix
  const v = vector.replace(/^CVSS:\d+\.\d+\//, '');

  // Parse metric=value pairs
  const m = {};
  for (const part of v.split('/')) {
    const [key, val] = part.split(':');
    if (key && val) m[key] = val.toUpperCase();
  }

  // Validate required metrics
  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  for (const r of required) {
    if (!m[r]) return { error: `Missing metric: ${r}` };
  }

  // Look up weights
  const av  = AV[m.AV];
  const ac  = AC[m.AC];
  const pr  = m.S === 'C' ? PR_C[m.PR] : PR_U[m.PR];
  const ui  = UI[m.UI];
  const s   = m.S;
  const c   = CI[m.C];
  const i   = CI[m.I];
  const a   = CI[m.A];

  if ([av, ac, pr, ui, c, i, a].some(x => x === undefined)) {
    return { error: 'Invalid metric value — check AV/AC/PR/UI/S/C/I/A' };
  }

  // ISCBase
  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

  // ISC
  let isc;
  if (s === 'U') {
    isc = 6.42 * iscBase;
  } else {
    // S = C (Scope Changed)
    isc = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  // Exploitability
  const exploitability = 8.22 * av * ac * pr * ui;

  // Base Score
  let baseScore;
  if (isc <= 0) {
    baseScore = 0;
  } else if (s === 'U') {
    baseScore = Math.min(isc + exploitability, 10);
  } else {
    baseScore = Math.min(1.08 * (isc + exploitability), 10);
  }

  // Round up to 1 decimal place (CVSS spec uses "roundup" not standard rounding)
  const rounded = _roundUp(baseScore);

  return {
    score:    rounded,
    severity: _severity(rounded),
    vector:   `CVSS:3.1/${v}`,
    metrics: { AV: m.AV, AC: m.AC, PR: m.PR, UI: m.UI, S: m.S, C: m.C, I: m.I, A: m.A },
    breakdown: {
      iscBase:        Number(iscBase.toFixed(4)),
      isc:            Number(isc.toFixed(4)),
      exploitability: Number(exploitability.toFixed(4)),
    },
  };
}

/** CVSS spec roundup: round up to nearest 0.1 */
function _roundUp(x) {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return Math.floor(i / 10000 + 1) / 10;
}

function _severity(score) {
  if (score === 0)         return 'None';
  if (score < 4)           return 'Low';
  if (score < 7)           return 'Medium';
  if (score < 9)           return 'High';
  return 'Critical';
}
