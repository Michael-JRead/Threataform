#!/usr/bin/env node
/**
 * scripts/build_wasm.js
 * Build the ops.wasm SIMD acceleration module from AssemblyScript source.
 *
 * Prerequisites:
 *   npm install -g assemblyscript   (or: npm install --save-dev assemblyscript)
 *
 * Usage:
 *   node scripts/build_wasm.js
 *
 * Output:
 *   src/lib/llm/ops.wasm  — production module (~3-5 KB gzip)
 *   src/lib/llm/ops.wat   — human-readable text (for inspection)
 *
 * Expected speedup vs pure JS:
 *   matmul (large): 3-5× (SIMD f32x4 + WASM JIT)
 *   rmsnorm:        2-3×
 *   Overall tok/s:  ~50 → 150-400 tok/s depending on model/hardware
 */

const { execSync, spawnSync } = require('child_process');
const path = require('path');
const fs   = require('fs');

const root = path.resolve(__dirname, '..');
const src  = path.join(root, 'src', 'lib', 'llm', 'ops.as.ts');
const out  = path.join(root, 'src', 'lib', 'llm', 'ops.wasm');
const wat  = path.join(root, 'src', 'lib', 'llm', 'ops.wat');

if (!fs.existsSync(src)) {
  console.error(`ERROR: Source not found: ${src}`);
  process.exit(1);
}

// Prefer local asc over global
const ascCandidates = [
  path.join(root, 'node_modules', '.bin', 'asc'),
  path.join(root, 'node_modules', '.bin', 'asc.cmd'),
  'asc',
];

let asc = null;
for (const c of ascCandidates) {
  try {
    const r = spawnSync(c, ['--version'], { encoding: 'utf8' });
    if (r.status === 0) { asc = c; console.log(`Found asc: ${c} (${r.stdout.trim()})`); break; }
  } catch { /* try next */ }
}

if (!asc) {
  console.error([
    'ERROR: AssemblyScript compiler (asc) not found.',
    '',
    'Install it:',
    '  npm install -g assemblyscript',
    '  -- or --',
    '  npm install --save-dev assemblyscript',
    '',
    'Then rerun: node scripts/build_wasm.js',
  ].join('\n'));
  process.exit(1);
}

const args = [
  src,
  '--outFile',    out,
  '--textFile',   wat,
  '--enable',     'simd',
  '--optimize',
  '-O3',
  '--runtime',    'stub',
  '--exportRuntime', 'false',
  '--noAssert',
  '--target',     'release',
];

console.log(`\nCompiling: ${asc} ${args.join(' ')}\n`);
const result = spawnSync(asc, args, { encoding: 'utf8', stdio: 'inherit' });

if (result.status !== 0) {
  console.error(`\nCompilation failed (exit ${result.status})`);
  if (result.stderr) console.error(result.stderr);
  process.exit(result.status);
}

const size = fs.statSync(out).size;
console.log(`\nSuccess! ops.wasm: ${(size / 1024).toFixed(1)} KB`);
console.log(`         ops.wat:  ${(fs.statSync(wat).size / 1024).toFixed(1)} KB`);
console.log('\nRestart the dev server to pick up the new WASM module.');
console.log('Check browser console for: [Ops] WASM acceleration loaded — SIMD matmul active');
