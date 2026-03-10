// src/lib/iac/TerraformParser.js
import { RT } from '../../data/resource-types.js';
import { TIERS, detectPaveLayer } from '../../constants/tiers.js';

function parseTFMultiFile(files) {
  const resources=[], modules=[], connections=[], outputs=[], variables=[], remoteStates=[];
  // Build an output index keyed by "output_name" → value for cross-file resolution
  const outputIndex = {}; // populated on second pass
  // Map variable defaults for resolution
  const varIndex = {};    // "file::varname" → defaultValue

  files.forEach(({path, content}) => {
    const fname = path.split("/").pop();
    const paveLayer = detectPaveLayer(path);

    // ── Variables (first pass — needed for reference resolution) ───────────
    const vRe = /\bvariable\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    let m;
    while ((m = vRe.exec(content)) !== null) {
      const [,vname,body] = m;
      const dM = body.match(/default\s*=\s*"?([^"\n]+)"?/);
      const tM = body.match(/type\s*=\s*(\S+)/);
      const senM = /sensitive\s*=\s*true/.test(body);
      const desc = (body.match(/description\s*=\s*"([^"]+)"/) || [])[1] || "";
      variables.push({name:vname, type:tM?tM[1]:"any", hasDefault:!!dM, defaultVal:dM?dM[1]:null, sensitive:senM, description:desc, file:path, paveLayer});
      varIndex[`${path}::${vname}`] = dM ? dM[1] : null;
    }

    // ── Outputs (first pass) ───────────────────────────────────────────────
    const oRe = /\boutput\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = oRe.exec(content)) !== null) {
      const [,oname,body] = m;
      const vM = body.match(/value\s*=\s*(.+)/);
      const senM = /sensitive\s*=\s*true/.test(body);
      const val = vM ? vM[1].trim() : "";
      outputs.push({name:oname, value:val, sensitive:senM, file:path, paveLayer});
      outputIndex[oname] = val;
    }

    // ── Resources ─────────────────────────────────────────────────────────
    const rRe = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = rRe.exec(content)) !== null) {
      const [,rtype,rname,body] = m;
      const id = `${rtype}.${rname}`;
      const LBLS = ["name","bucket","function_name","cluster_id","cluster_identifier","table_name","queue_name","topic_name","identifier","description","title","role_name","pipeline_name","family"];
      let label = rname;
      for (const a of LBLS) {
        const lm = body.match(new RegExp(`\\b${a}\\s*=\\s*"([^"]{1,40})"`, "m"));
        if (lm) { label = lm[1]; break; }
      }
      const multi = /\bfor_each\s*=/.test(body) ? "for_each" : /\bcount\s*=/.test(body) ? "count" : null;
      // Parse structured attrs and collect HCL-derived input references
      const attrs = parseHCLBody(body);
      const inputRefs = [];
      { const irRe = /\b(aws_[\w]+)\.([\w-]+)\.(\w+)\b/g; let ir;
        while ((ir = irRe.exec(body)) !== null)
          inputRefs.push({resourceId:`${ir[1]}.${ir[2]}`, attr:ir[3]}); }
      resources.push({id, type:rtype, name:rname, label, body, attrs, inputRefs, multi, file:path, paveLayer});

      // Implicit deps: resource type references (aws_*, xsphere_*)
      const depRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = depRe.exec(body)) !== null) {
        const to = `${rm[1]}.${rm[2]}`;
        if (to !== id) connections.push({from:id, to, kind:"implicit", file:path});
      }
      // Explicit depends_on
      const dm = body.match(/depends_on\s*=\s*\[([^\]]+)\]/);
      if (dm) {
        const dr = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let d;
        while ((d = dr.exec(dm[1])) !== null)
          connections.push({from:id, to:`${d[1]}.${d[2]}`, kind:"explicit", file:path});
      }
      // Module output references: module.<name>.<output>
      const modRefRe = /\bmodule\.([\w-]+)\.([\w-]+)\b/g; let mr;
      while ((mr = modRefRe.exec(body)) !== null)
        connections.push({from:id, to:`module.${mr[1]}`, kind:"module-output", file:path});
      // Data source references: data.<type>.<name>
      const dataRefRe = /\bdata\.([\w]+)\.([\w-]+)\b/g; let dr2;
      while ((dr2 = dataRefRe.exec(body)) !== null)
        connections.push({from:id, to:`data.${dr2[1]}.${dr2[2]}`, kind:"data-ref", file:path});
    }

    // ── Modules ───────────────────────────────────────────────────────────
    const mRe = /\bmodule\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = mRe.exec(content)) !== null) {
      const [,mname,body] = m;
      const srcM = body.match(/source\s*=\s*"([^"]+)"/);
      const verM = body.match(/version\s*=\s*"([^"]+)"/);
      const src = srcM ? srcM[1] : "?";
      const ver = verM ? verM[1] : null;
      const srcType = src.startsWith("./") || src.startsWith("../") ? "local"
                    : src.startsWith("git::") || src.includes("github.com") ? "git"
                    : src === "remote_state" ? "remote_state"
                    : "registry";
      const shortSrc = src.split("/").slice(-2).join("/").substring(0,30);
      const pinned = ver ? /^[~>=!]/.test(ver) ? "constrained" : "exact" : "unpinned";
      modules.push({id:`module.${mname}`, name:mname, source:src, shortSrc, version:ver, srcType, pinned, body, file:path, paveLayer});
      // module inputs referencing resources
      const refRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = refRe.exec(body)) !== null)
        connections.push({from:`module.${mname}`, to:`${rm[1]}.${rm[2]}`, kind:"module-input", file:path});
    }

    // ── Data sources (all types, not just remote_state) ───────────────────
    const dRe = /\bdata\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = dRe.exec(content)) !== null) {
      const [,dtype,dname,body] = m;
      const dsId = `data.${dtype}.${dname}`;
      if (dtype === "terraform_remote_state") {
        const keyM = body.match(/key\s*=\s*"([^"]+)"/);
        const buckM = body.match(/bucket\s*=\s*"([^"]+)"/);
        remoteStates.push({name:dname, key:keyM?keyM[1]:null, bucket:buckM?buckM[1]:null, file:path});
        modules.push({id:`remote_state.${dname}`, name:dname, source:"remote_state", shortSrc:"remote state",
                      version:null, srcType:"remote_state", body, file:path, paveLayer});
      } else {
        // All other data sources — add as lightweight module-like node for DFD and connection tracking
        modules.push({id:dsId, name:dname, source:`data:${dtype}`, shortSrc:dtype.replace("aws_",""), version:null, srcType:"data", body, file:path, paveLayer});
      }
    }

    // ── Sentinel ──────────────────────────────────────────────────────────
    if (fname.endsWith(".sentinel")) {
      const pname = fname.replace(".sentinel","");
      modules.push({id:`sentinel.${pname}`, name:pname, source:"sentinel", shortSrc:"policy", version:null, srcType:"sentinel", body:"", file:path, paveLayer});
    }
  });

  // ── Pass 4: Attachment resource connections ────────────────────────────
  // These "glue" resources describe associations between two other resources.
  // Walk each one and emit connections for every aws_*.name reference found.
  const ATTACHMENT_TYPES = new Set([
    'aws_lb_target_group_attachment',
    'aws_lambda_event_source_mapping',
    'aws_wafv2_web_acl_association',
    'aws_cloudwatch_event_target',
    'aws_sns_topic_subscription',
    'aws_iam_role_policy_attachment',
    'aws_iam_instance_profile',
  ]);
  resources.forEach(r => {
    if (!ATTACHMENT_TYPES.has(r.type)) return;
    const refRe = /\b(aws_[\w]+)\.([\w-]+)\b/g; let am;
    while ((am = refRe.exec(r.body || '')) !== null) {
      const to = `${am[1]}.${am[2]}`;
      if (to !== r.id) connections.push({from:r.id, to, kind:'attachment', file:r.file, attachType:r.type});
    }
  });
  // S3 bucket notification → Lambda: emit direct bucket→lambda edge
  resources.filter(r => r.type === 'aws_s3_bucket_notification').forEach(r => {
    [...(r.body || '').matchAll(/lambda_function_arn\s*=\s*([^\s\n]+)/g)].forEach(lr => {
      const lm = (lr[1] || '').match(/\b(aws_lambda_function)\.([\w-]+)\b/);
      if (lm) {
        const bM = (r.body || '').match(/bucket\s*=\s*aws_s3_bucket\.([\w-]+)/);
        const from = bM ? `aws_s3_bucket.${bM[1]}` : r.id;
        connections.push({from, to:`aws_lambda_function.${lm[2]}`, kind:'notification', file:r.file});
      }
    });
  });

  // ── Dedup ─────────────────────────────────────────────────────────────
  const seenR=new Set(), seenM=new Set(), seenC=new Set();
  const uResources = resources.filter(r=>{if(seenR.has(r.id))return false;seenR.add(r.id);return true;});
  const uModules = modules.filter(m=>{if(seenM.has(m.id))return false;seenM.add(m.id);return true;});
  const valid = new Set([...uResources.map(r=>r.id),...uModules.map(m=>m.id)]);
  const uConns = connections.filter(c=>{
    const k=`${c.from}||${c.to}`;
    const isAttach = c.kind==='attachment'||c.kind==='notification';
    if(seenC.has(k)||c.from===c.to||(!valid.has(c.from)&&!isAttach))return false;
    seenC.add(k);return true;
  });

  // ── Pave-layer summary ────────────────────────────────────────────────
  const paveLayers = {};
  [...uResources,...uModules].forEach(r => {
    if (r.paveLayer) { paveLayers[r.paveLayer] = (paveLayers[r.paveLayer]||0)+1; }
  });

  // ── Unpinned registry modules (supply chain signal) ───────────────────
  const unpinnedModules = uModules.filter(m => m.srcType === "registry" && m.pinned === "unpinned");

  return {resources:uResources, modules:uModules, connections:uConns, outputs, variables, remoteStates, paveLayers, unpinnedModules, outputIndex};
}

/**
 * Parse CloudFormation JSON files and return unified resources array.
 * Lazy-loads CFNParser to avoid bundle bloat when CFN is not used.
 * @param {Array<{path: string, content: string}>} files
 * @returns {Promise<{resources: object[], gaps: string[]}>}
 */
async function parseCFNFiles(files) {
  const { extractCFNResources } = await import('./CFNParser.js');
  const allResources = [];
  const allGaps = [];
  for (const { path, content } of files) {
    try {
      const { resources, gaps } = extractCFNResources(content, path);
      allResources.push(...resources);
      allGaps.push(...gaps);
    } catch (err) {
      allGaps.push(`[parseCFNFiles] Error processing ${path}: ${err.message}`);
    }
  }
  return { resources: allResources, gaps: allGaps };
}

// Architecture hierarchy inference from Terraform resources
function inferArchitectureHierarchy(resources, modules, files) {
  const h = { org:null, accounts:[], vpcs:[], subnets:[], paveLayers:{} };
  // Org
  if (resources.some(r=>r.type.startsWith('aws_organizations')))
    h.org = { detected:true, scpCount:resources.filter(r=>r.type==='aws_organizations_policy').length, accountCount:resources.filter(r=>r.type==='aws_organizations_account').length };
  // Accounts from provider blocks + naming
  const providerPattern = /provider\s+"aws"\s*\{([^}]+)\}/g;
  (files||[]).forEach(f => { let m; while((m=providerPattern.exec(f.content||''))!==null) {
    const alias=(m[1].match(/alias\s*=\s*"([^"]+)"/))||[];
    const region=(m[1].match(/region\s*=\s*"([^"]+)"/))||[];
    if(alias[1]) h.accounts.push({ alias:alias[1], region:region[1]||'unknown' });
  }});
  if(!h.accounts.length) h.accounts=[{alias:'default',region:'detected from resources'}];
  // VPCs
  resources.filter(r=>r.type==='aws_vpc').forEach(r=>{
    const cidr=(r.body.match(/cidr_block\s*=\s*"([^"]+)"/))||[];
    const hasIGW=resources.some(x=>x.type==='aws_internet_gateway'&&x.body&&x.body.includes(r.name));
    h.vpcs.push({id:r.id,name:r.name,cidr:cidr[1]||'?',hasInternetGateway:hasIGW,
      subnets:resources.filter(s=>s.type==='aws_subnet'&&s.body&&s.body.includes(r.name)).map(s=>s.id)});
  });
  // Subnets
  resources.filter(r=>r.type==='aws_subnet').forEach(r=>{
    const cidr=(r.body.match(/cidr_block\s*=\s*"([^"]+)"/))||[];
    const isPublic=/map_public_ip_on_launch\s*=\s*true/.test(r.body);
    const az=(r.body.match(/availability_zone\s*=\s*"([^"]+)"/))||[];
    h.subnets.push({id:r.id,name:r.name,cidr:cidr[1]||'?',isPublic,az:az[1]||'?'});
  });
  // Pave layers
  resources.forEach(r=>{ if(r.paveLayer){h.paveLayers[r.paveLayer]=(h.paveLayers[r.paveLayer]||0)+1; }});
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// HCL PARSER — recursive brace-depth block extraction
// Replaces _parseAttrMap flat-regex approach. Handles nested blocks correctly:
//   metadata_options { http_tokens = "required" }  →  attrs.metadata_options.http_tokens = "required"
//   versioning { enabled = true }                  →  attrs.versioning.enabled = true
// ─────────────────────────────────────────────────────────────────────────────

function _findMatchingBrace(text, openPos) {
  let depth = 0;
  for (let i = openPos; i < text.length; i++) {
    // Skip string literals so braces inside strings are ignored
    if (text[i] === '"') {
      i++;
      while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; }
      continue;
    }
    if (text[i] === '{') depth++;
    else if (text[i] === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function _extractBlocks(text, attrs) {
  // Block names that are top-level HCL constructs, not nested attribute blocks
  const SKIP = new Set(['resource','data','module','variable','output','provider','locals',
                        'terraform','lifecycle','for_each','count','dynamic']);
  const re = /\b(\w+)(?:\s+"[^"]*")?\s*\{/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (SKIP.has(m[1])) continue;
    const open = m.index + m[0].length - 1;
    const close = _findMatchingBrace(text, open);
    if (close === -1) continue;
    const sub = parseHCLBody(text.slice(open + 1, close));
    const k = m[1];
    // Support repeated blocks → array
    if (Array.isArray(attrs[k])) attrs[k].push(sub);
    else if (attrs[k] && typeof attrs[k] === 'object' && !Array.isArray(attrs[k])) attrs[k] = [attrs[k], sub];
    else attrs[k] = sub;
    re.lastIndex = close + 1;
  }
}

function parseHCLBody(body) {
  if (!body) return {};
  const attrs = {};
  // Strip comments before parsing
  const clean = body.replace(/\/\/[^\n]*/g, '').replace(/#[^\n]*/g, '');
  // Flat string: key = "value"
  for (const [, k, v] of clean.matchAll(/^\s*(\w+)\s*=\s*"([^"\\]*)"/gm)) {
    attrs[k] = v;
    attrs[`__src_${k}`] = { method: 'flat_string', snippet: `${k} = "${v}"` };
  }
  // Flat bool: key = true|false
  for (const [, k, v] of clean.matchAll(/^\s*(\w+)\s*=\s*(true|false)\b/gm)) {
    if (attrs[k] === undefined) {
      attrs[k] = (v === 'true');
      attrs[`__src_${k}`] = { method: 'flat_bool', snippet: `${k} = ${v}` };
    }
  }
  // Flat number: key = 42
  for (const [, k, v] of clean.matchAll(/^\s*(\w+)\s*=\s*(\d+)\b/gm)) {
    if (attrs[k] === undefined) {
      attrs[k] = parseInt(v, 10);
      attrs[`__src_${k}`] = { method: 'flat_number', snippet: `${k} = ${v}` };
    }
  }
  // String list: key = ["a","b"]
  for (const [, k, v] of clean.matchAll(/^\s*(\w+)\s*=\s*\[([^\]]*)\]/gm)) {
    const items = [...(v || '').matchAll(/"([^"]+)"/g)].map(m2 => m2[1]);
    if (items.length) {
      attrs[k] = items;
      attrs[`__src_${k}`] = { method: 'list', snippet: `${k} = [${v.trim().slice(0, 60)}]` };
    }
  }
  // Variable/local ref → null (unresolved, cannot be checked)
  for (const [, k, ref] of clean.matchAll(/^\s*(\w+)\s*=\s*(var\.\w+|local\.\w+)/gm)) {
    if (attrs[k] === undefined) {
      attrs[k] = null;
      attrs[`__src_${k}`] = { method: 'var_ref', snippet: `${k} = ${ref}`, unresolved: true, ref };
    }
  }
  // Nested blocks (recursive)
  _extractBlocks(clean, attrs);
  return attrs;
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM POLICY ANALYSIS — factual JSON policy document inspection
// Never uses substring matching; parses actual Statement arrays
// ─────────────────────────────────────────────────────────────────────────────

import { mkEvidence } from '../../data/control-detection.js';

function _analyzeIAMDocument(doc, resourceId, findings, policyKind) {
  if (!doc?.Statement) return;
  const stmts = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
  stmts.forEach(stmt => {
    if (stmt.Effect !== 'Allow') return;
    const actions = (Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action]).filter(Boolean);
    const rsrcs   = (Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource]).filter(Boolean);
    if (actions.includes('*') && rsrcs.includes('*'))
      findings.push({
        id:'IAM-ADMIN', severity:'Critical', policyKind, resourceId,
        title:'Policy grants AdministratorAccess (Action:* Resource:*)',
        evidence: mkEvidence('policy_parse','Action:* Resource:*', resourceId),
        remediation:'Replace wildcard with specific actions following least-privilege principle.',
        cwe:['CWE-269'], attack:['T1078.004'],
      });
    if (actions.some(a => a === 'iam:*' || /^iam:.*\*$/.test(a)))
      findings.push({
        id:'IAM-PRIV-ESC', severity:'Critical', policyKind, resourceId,
        title:'Policy allows IAM privilege escalation (iam:*)',
        evidence: mkEvidence('policy_parse','iam:* allows creating roles/policies with any permissions', resourceId),
        remediation:'Restrict to specific IAM read actions; never grant iam:PassRole without conditions.',
        cwe:['CWE-269'], attack:['T1078.004','T1548'],
      });
    // Broad service wildcards (s3:*, ec2:*, etc.)
    const broadSvc = actions.filter(a => /^\w+:\*$/.test(a) && a !== 'iam:*');
    if (broadSvc.length > 0 && rsrcs.includes('*'))
      findings.push({
        id:'IAM-SVC-WILD', severity:'High', policyKind, resourceId,
        title:`Policy uses broad service wildcard: ${broadSvc.slice(0,3).join(', ')}`,
        evidence: mkEvidence('policy_parse', broadSvc.join(', ') + ' on Resource:*', resourceId),
        remediation:'Scope actions to specific resource ARNs; avoid service-level wildcards on Resource:*.',
        cwe:['CWE-269'], attack:['T1078.004'],
      });
  });
}

export { parseTFMultiFile, parseCFNFiles, inferArchitectureHierarchy, parseHCLBody };

// ─────────────────────────────────────────────────────────────────────────────
// FILE CLASSIFICATION — multi-signal confidence scoring for enterprise IaC repos
// ─────────────────────────────────────────────────────────────────────────────

export function classifyFile(file) {
  const fp = (file.path || '').toLowerCase();
  const fn = (file.name || '').toLowerCase();
  const fc = (file.content || '').toLowerCase();
  const ext = fn.includes('.') ? '.' + fn.split('.').pop() : '';
  let score = 0, category = 'unknown', layer = 7, type = 'config', signals = [];

  // Foundation Layer 1 signals
  const foundationNameSignals = ['enterprise-aws-bootstrap','ou-tree','ou-linker','bootstrap'];
  const foundationPathSignals = ['templates/scp','templates/rcp','/foundation/','/bootstrap/'];
  const foundationContentSignals = ['aws_organizations_','organizational_unit','service_control_policy','aws organizations','jules','organizational_units'];
  let foundationScore = 0;
  foundationNameSignals.forEach(s => { if(fn.includes(s)){ foundationScore+=0.3; signals.push({signal:s,type:'name'}); }});
  foundationPathSignals.forEach(s => { if(fp.includes(s)){ foundationScore+=0.2; signals.push({signal:s,type:'path'}); }});
  foundationContentSignals.forEach(s => { if(fc.includes(s)){ foundationScore+=0.4; signals.push({signal:s,type:'content'}); }});
  if(['.py','.groovy','.yaml','.yml'].includes(ext)) foundationScore+=0.1;
  if(foundationScore > score){ score=foundationScore; category='foundation'; layer=1; type='bootstrap'; }

  // Factory Layer 2 signals
  const factoryNames = ['portfolio-boundary-factory','network-boundary-factory','base-account-factory','workload-boundary-factory'];
  const factoryNameShort = ['boundary-factory','account-factory'];
  const factoryContentSignals = ['kind: boundaryr','kind: accountfactory','kind: networkboundary','apiversion: platform','kubernetes_','helm_','crd','serviceaccount'];
  let factoryScore = 0;
  factoryNames.forEach(s => { if(fp.includes(s)||fn.includes(s)){ factoryScore+=0.35; signals.push({signal:s,type:'factory-name'}); }});
  factoryNameShort.forEach(s => { if(fp.includes(s)||fn.includes(s)){ factoryScore+=0.2; }});
  factoryContentSignals.forEach(s => { if(fc.includes(s)){ factoryScore+=0.35; signals.push({signal:s,type:'factory-content'}); }});
  if(factoryScore > score){ score=Math.min(0.95,factoryScore); category='factories'; layer=2; type='factory-operator'; }

  // IAM Module Layer 3 signals
  const iamNames = ['module-role','module-iam','role-distribution','role-policy-updater','iam-policy'];
  const iamContent = ['module-role-policy-updater','role-distribution-factory','aws_iam_role','assume_role_policy','aws_iam_policy','permissions_boundary'];
  let iamScore = 0;
  iamNames.forEach(s => { if(fp.includes(s)||fn.includes(s)){ iamScore+=0.3; signals.push({signal:s,type:'iam-name'}); }});
  iamContent.forEach(s => { if(fc.includes(s)){ iamScore+=0.35; signals.push({signal:s,type:'iam-content'}); }});
  if(['.tf','.tfvars'].includes(ext)) iamScore+=0.1;
  if(iamScore > score){ score=Math.min(0.90,iamScore); category='modules'; layer=3; type='iam-module'; }

  // Sentinel Policy Layer 5 signals
  const sentinelImports = ['import "tfplan"','import "tfconfig"','import "tfstate"','main = rule','main=rule'];
  let sentinelScore = 0;
  if(ext==='.sentinel'){ sentinelScore+=0.5; signals.push({signal:'.sentinel',type:'extension'}); }
  if(fp.includes('sentinel/')||fp.includes('/policies/')){ sentinelScore+=0.2; signals.push({signal:'sentinel-path',type:'path'}); }
  sentinelImports.forEach(s => { if(fc.includes(s)){ sentinelScore+=0.35; signals.push({signal:s,type:'sentinel-content'}); }});
  if(sentinelScore > score){ score=Math.min(0.95,sentinelScore); category='policies'; layer=5; type='sentinel-policy'; }

  // CRD signals
  const crdContent = ['kind: customresourcedefinition','apiversion: apiextensions.k8s.io'];
  let crdScore = 0;
  crdContent.forEach(s => { if(fc.includes(s)){ crdScore+=0.5; signals.push({signal:s,type:'crd-content'}); }});
  if(fp.includes('/crds/')||fn.includes('-crd.')){ crdScore+=0.3; }
  if(crdScore > score){ score=Math.min(0.90,crdScore); category='crds'; layer=2; type='crd-definition'; }

  // Product Module Layer 6 signals
  const productModuleNames = ['module-msk','module-kendra','module-opensearch','module-elasticache','module-rds','module-kafka','module-redis','module-aurora'];
  const productContent = ['aws_msk_','aws_kendra','aws_opensearch','aws_elasticache','aws_rds','aws_kafka','aws_redis'];
  let productScore = 0;
  productModuleNames.forEach(s => { if(fp.includes(s)||fn.includes(s)){ productScore+=0.35; signals.push({signal:s,type:'product-name'}); }});
  productContent.forEach(s => { if(fc.includes(s)){ productScore+=0.3; signals.push({signal:s,type:'product-content'}); }});
  if(fp.includes('/module') && fp.includes('/modules')){ productScore+=0.1; }
  if(productScore > score){ score=Math.min(0.85,productScore); category='modules'; layer=6; type='product-module'; }

  // Terraform config
  const tfContent = ['terraform {','provider "aws"','resource "','module "'];
  let tfScore = 0;
  if(['.tf','.tfvars','.tfstate'].includes(ext)){ tfScore+=0.2; signals.push({signal:ext,type:'extension'}); }
  tfContent.forEach(s => { if(fc.includes(s)){ tfScore+=0.15; }});
  if(tfScore > score && category === 'unknown'){ score=tfScore; category='configs'; layer=determineTerraformLayer(file.content||''); type='terraform-config'; }

  // Multi-signal bonus
  const uniqueTypes = [...new Set(signals.map(s=>s.type))];
  if(uniqueTypes.length >= 3) score = Math.min(1.0, score + 0.2);

  return { category, layer, type, confidence: Math.round(Math.min(1.0, score)*100)/100, signals };
}

export function classifyFiles(files) {
  const result = { foundation:[], factories:[], modules:[], policies:[], crds:[], configs:[], unknown:[] };
  files.forEach(file => {
    const classification = classifyFile(file);
    const cat = classification.category;
    result[cat] = result[cat] || [];
    result[cat].push({ ...file, classification });
  });
  return result;
}

export function determineTerraformLayer(content) {
  const c = (content||'').toLowerCase();
  if(c.includes('aws_organizations_')||c.includes('organizational_unit')||c.includes('service_control_policy')||c.includes('aws organizations')) return 1;
  if(c.includes('kubernetes_')||c.includes('helm_')||c.includes('boundary-factory')||c.includes('operator')||c.includes('kind: boundary')) return 2;
  if(c.includes('module.role')||c.includes('role_distribution')||c.includes('module-role')||(c.includes('aws_iam_role')&&!c.includes('aws_iam_role_policy'))) return 3;
  if(c.includes('aws_vpc')||c.includes('aws_subnet')||c.includes('security_group')||c.includes('aws_transit_gateway')||c.includes('aws_flow_log')) return 4;
  if(c.includes('import "tfplan"')||c.includes('main = rule')||c.includes('sentinel')||c.includes('policy_as_code')) return 5;
  if(c.includes('aws_msk')||c.includes('aws_kendra')||c.includes('aws_opensearch')||c.includes('aws_elasticache')||c.includes('aws_rds')||c.includes('aws_kafka')) return 6;
  return 7;
}

export function findPotentialProductModules(files) {
  const PRODUCT_INDICATORS = {
    'Database Service':   ['rds','dynamodb','aurora','database','db_','postgresql','mysql'],
    'Messaging Service':  ['sqs','sns','msk','kafka','kinesis','eventbridge','messaging','queue'],
    'Search Service':     ['elasticsearch','opensearch','kendra','search'],
    'Storage Service':    ['s3','efs','fsx','storage','backup'],
    'Compute Service':    ['lambda','ecs','eks','ec2','fargate','batch'],
    'Analytics Service':  ['redshift','athena','glue','emr','analytics'],
    'AI/ML Service':      ['sagemaker','bedrock','comprehend','textract','ml'],
    'API Service':        ['api_gateway','apigw','apigateway','appsync'],
    'Cache Service':      ['elasticache','redis','memcached','cache','dax'],
    'CDN Service':        ['cloudfront','cdn','waf','edge'],
    'Container Service':  ['ecr','ecs','eks','container','docker','fargate'],
  };

  // Group files by directory
  const dirMap = {};
  files.forEach(f => {
    const parts = (f.path||f.name||'').split('/');
    const dir = parts.length > 1 ? parts.slice(0,-1).join('/') : '.';
    if(!dirMap[dir]) dirMap[dir] = [];
    dirMap[dir].push(f);
  });

  const candidates = [];
  Object.entries(dirMap).forEach(([dir, dirFiles]) => {
    const fnames = dirFiles.map(f=>(f.name||f.path||'').toLowerCase());
    const hasMain = fnames.some(n=>n.endsWith('main.tf'));
    const hasVars = fnames.some(n=>n.endsWith('variables.tf')||n.endsWith('vars.tf'));
    const hasOutputs = fnames.some(n=>n.endsWith('outputs.tf'));
    if(!hasMain) return; // must have main.tf

    const allContent = dirFiles.map(f=>f.content||'').join('\n').toLowerCase();
    let serviceType = 'Custom Module';
    let awsServices = [];
    let bestScore = 0;

    Object.entries(PRODUCT_INDICATORS).forEach(([svcType, signals]) => {
      const matches = signals.filter(s=>allContent.includes(s));
      if(matches.length > bestScore){ bestScore=matches.length; serviceType=svcType; awsServices=matches; }
    });

    const dirName = dir.split('/').pop();
    candidates.push({
      name: dirName,
      path: dir,
      serviceType,
      fileCount: dirFiles.length,
      awsServices: [...new Set(awsServices)].slice(0,5),
      hasVars,
      hasOutputs,
      confidence: hasVars && hasOutputs ? 0.9 : hasVars ? 0.7 : 0.5,
      contentPreview: allContent.substring(0,200).replace(/\s+/g,' '),
    });
  });

  return candidates.sort((a,b)=>b.confidence-a.confidence||b.fileCount-a.fileCount);
}

export function getAWSServiceFromResource(resourceType) {
  const rt = (resourceType||'').toLowerCase();
  if(rt.includes('rds')||rt.includes('aurora')||rt.includes('db_instance')||rt.includes('dynamodb')) return 'Database Service';
  if(rt.includes('msk')||rt.includes('sqs')||rt.includes('sns')||rt.includes('kinesis')||rt.includes('kafka')||rt.includes('eventbridge')) return 'Messaging Service';
  if(rt.includes('opensearch')||rt.includes('elasticsearch')||rt.includes('kendra')) return 'Search Service';
  if(rt.includes('elasticache')||rt.includes('redis')||rt.includes('memcached')||rt.includes('dax')) return 'Cache Service';
  if(rt.includes('lambda')||rt.includes('ecs_task')||rt.includes('ecs_service')) return 'Compute Service';
  if(rt.includes('s3')||rt.includes('efs')||rt.includes('fsx')) return 'Storage Service';
  if(rt.includes('api_gateway')||rt.includes('apigateway')||rt.includes('appsync')) return 'API Service';
  if(rt.includes('cloudfront')||rt.includes('waf')) return 'CDN Service';
  if(rt.includes('sagemaker')||rt.includes('bedrock')||rt.includes('comprehend')) return 'AI/ML Service';
  if(rt.includes('ecr')||rt.includes('eks')||rt.includes('ecs_cluster')) return 'Container Service';
  if(rt.includes('redshift')||rt.includes('athena')||rt.includes('glue')||rt.includes('emr')) return 'Analytics Service';
  if(rt.includes('secretsmanager')||rt.includes('ssm_parameter')||rt.includes('kms')) return 'Secrets Service';
  if(rt.includes('iam_role')||rt.includes('iam_policy')||rt.includes('iam_user')) return 'IAM';
  if(rt.includes('vpc')||rt.includes('subnet')||rt.includes('security_group')||rt.includes('transit_gateway')) return 'Network';
  if(rt.includes('cloudtrail')||rt.includes('guardduty')||rt.includes('securityhub')||rt.includes('config')) return 'Security & Monitoring';
  return 'Other AWS Service';
}
