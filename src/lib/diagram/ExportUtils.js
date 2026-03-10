// src/lib/diagram/ExportUtils.js
import { NW, NH, LH, VGAP, HGAP, TPAD, TVPAD, HDRH, TGAP, CPAD, MAXCOLS, LEGEND_W } from '../../constants/layout.js';
import { TIERS } from '../../constants/tiers.js';
import { RT } from '../../data/resource-types.js';

// ─────────────────────────────────────────────────────────────────────────────
// LUCID STANDARD IMPORT (.lucid) GENERATOR
// .lucid = ZIP archive containing document.json (Lucid Standard Import schema)
// This is the most reliable Lucidchart import format — no XML parse failures.
// ─────────────────────────────────────────────────────────────────────────────

// Minimal CRC-32 + single-file ZIP creator (no external dependencies)
const _CRC32T=(()=>{const t=new Uint32Array(256);for(let i=0;i<256;i++){let c=i;for(let j=0;j<8;j++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[i]=c;}return t;})();
function _crc32(buf){let c=0xFFFFFFFF;for(let i=0;i<buf.length;i++)c=_CRC32T[(c^buf[i])&0xFF]^(c>>>8);return(c^0xFFFFFFFF)>>>0;}
function _u16(v){return[v&0xFF,(v>>8)&0xFF];}
function _u32(v){return[v&0xFF,(v>>8)&0xFF,(v>>16)&0xFF,(v>>24)&0xFF];}

export function makeZipOneFile(filename, contentStr) {
  const enc=new TextEncoder();
  const name=enc.encode(filename);
  const data=enc.encode(contentStr);
  const crc=_crc32(data);
  const d=new Date();
  const dt=((d.getHours()<<11)|(d.getMinutes()<<5)|(d.getSeconds()>>1))&0xFFFF;
  const dd=(((d.getFullYear()-1980)<<9)|((d.getMonth()+1)<<5)|d.getDate())&0xFFFF;
  // Local file header (signature + version + flags + compression + time + date + crc + sizes + name-len + extra + name)
  const lfh=new Uint8Array([
    0x50,0x4B,0x03,0x04, // local file header sig
    0x14,0x00,           // version needed (2.0)
    0x00,0x00,           // general purpose bit flags
    0x00,0x00,           // compression: stored (0)
    ..._u16(dt),..._u16(dd),
    ..._u32(crc),
    ..._u32(data.length), // compressed size = uncompressed (stored)
    ..._u32(data.length), // uncompressed size
    ..._u16(name.length),
    0x00,0x00,           // extra field length
    ...name
  ]);
  // Central directory entry
  const cde=new Uint8Array([
    0x50,0x4B,0x01,0x02, // central dir sig
    0x14,0x00,           // version made by
    0x14,0x00,           // version needed
    0x00,0x00,           // bit flags
    0x00,0x00,           // compression: stored
    ..._u16(dt),..._u16(dd),
    ..._u32(crc),
    ..._u32(data.length),
    ..._u32(data.length),
    ..._u16(name.length),
    0x00,0x00,           // extra field length
    0x00,0x00,           // file comment length
    0x00,0x00,           // disk number start
    0x00,0x00,           // internal file attrs
    0x00,0x00,0x00,0x00, // external file attrs
    ..._u32(0),          // offset of local header (always 0 — first file)
    ...name
  ]);
  const cdOff=lfh.length+data.length;
  // End of central directory
  const eocd=new Uint8Array([
    0x50,0x4B,0x05,0x06, // EOCD sig
    0x00,0x00,           // disk number
    0x00,0x00,           // disk with central dir
    0x01,0x00,           // entries on this disk
    0x01,0x00,           // total entries
    ..._u32(cde.length), // size of central dir
    ..._u32(cdOff),      // offset of central dir
    0x00,0x00            // comment length
  ]);
  const zip=new Uint8Array(lfh.length+data.length+cde.length+eocd.length);
  let off=0;
  zip.set(lfh,off); off+=lfh.length;
  zip.set(data,off); off+=data.length;
  zip.set(cde,off); off+=cde.length;
  zip.set(eocd,off);
  return zip;
}

// Generates Lucid Standard Import JSON from parsed TF resources/modules/connections.
// Uses identical layout math to generateDFDXml (same tier order, column/row calc, spacing).
export function generateLucidJson(resources, modules, connections) {
  const TORD=["xsphere","org","security","cicd","network","compute","storage"];
  const groups={};
  TORD.forEach(t=>{groups[t]=[];});
  resources.forEach(r=>{
    const meta=RT[r.type]||RT._default;
    if(!groups[meta.t])groups[meta.t]=[];
    groups[meta.t].push({...r,_meta:meta,_isModule:false});
  });
  modules.forEach(m=>{
    const t="cicd";
    if(!groups[t])groups[t]=[];
    const mc=m.srcType==="sentinel"?"#E65100":m.srcType==="remote_state"?"#1565C0":"#558B2F";
    groups[t].push({...m,_meta:{l:m.name,t,i:"-",c:mc},_isModule:true});
  });

  const activeTiers=TORD.filter(t=>groups[t]&&groups[t].length>0);
  const maxNodes=activeTiers.reduce((mx,t)=>Math.max(mx,groups[t].length),1);
  const effectiveCols=Math.min(maxNodes,MAXCOLS);
  const tierW=TPAD*2+effectiveCols*(NW+HGAP)-HGAP;
  let globalY=CPAD;
  const shapes=[], lines=[];
  const idMap=new Map();
  let shapeN=1, lineN=1;

  activeTiers.forEach(t=>{
    const nodes=groups[t];
    const rows=Math.ceil(nodes.length/MAXCOLS);
    const tH=HDRH+TVPAD+rows*(NH+LH+VGAP)-VGAP+TVPAD;
    const tm=TIERS[t]||{label:t,bg:"#F5F5F5",border:"#999",hdr:"#555"};

    // Tier swim-lane container
    shapes.push({
      id:`tier-${t}`,
      type:"rectangle",
      boundingBox:{x:CPAD,y:globalY,w:tierW,h:tH},
      style:{fill:tm.bg,stroke:tm.border,strokeWidth:2},
      text:`${tm.label} (${nodes.length})`,
      textStyle:{color:tm.hdr,bold:true,fontSize:13,verticalAlignment:"top"}
    });

    nodes.forEach((n,i)=>{
      const col=i%MAXCOLS, row=Math.floor(i/MAXCOLS);
      const nx=CPAD+TPAD+col*(NW+HGAP);
      const ny=globalY+HDRH+TVPAD+row*(NH+LH+VGAP);
      const meta=n._meta;
      const shortType=n._isModule
        ?`${n.srcType||"module"}`
        :(n.type||"").replace(/^aws_|^xsphere_/,"").replace(/_/g," ").substring(0,20);
      const rawName=(n.label||n.name||"").substring(0,18)+(n.multi?` [${n.multi}]`:"");
      const shapeId=`node-${shapeN++}`;
      idMap.set(n.id,shapeId);
      shapes.push({
        id:shapeId,
        type:"rectangle",
        boundingBox:{x:nx,y:ny,w:NW,h:NH+LH},
        style:{
          fill:n._isModule?"#FAFFF5":"#FFFFFF",
          stroke:meta.c||"#546E7A",
          strokeWidth:2,
          strokeStyle:(n._isModule||n.srcType==="remote_state")?"dashed":"solid"
        },
        text:`${rawName}\n${shortType}`,
        textStyle:{fontSize:9,color:"#333333"}
      });
    });
    globalY+=tH+TGAP;
  });

  // Connection lines
  const seenE=new Set();
  connections.forEach(c=>{
    const srcId=idMap.get(c.from), tgtId=idMap.get(c.to);
    if(!srcId||!tgtId)return;
    const ek=`${srcId}|${tgtId}`;
    if(seenE.has(ek))return;
    seenE.add(ek);
    const color=c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#2E7D32":"#78909C";
    // Route: downward = exit bottom/enter top; upward = exit top/enter bottom
    lines.push({
      id:`line-${lineN++}`,
      lineType:"elbow",
      stroke:color,
      strokeWidth:2,
      strokeStyle:c.kind==="explicit"?"dashed":"solid",
      text:c.kind==="explicit"?"depends_on":c.kind==="module-input"?"input":"",
      endpoint1:{type:"shapeEndpoint",style:"none",shapeId:srcId,position:{x:0.5,y:1}},
      endpoint2:{type:"shapeEndpoint",style:"arrow",shapeId:tgtId,position:{x:0.5,y:0}}
    });
  });

  return JSON.stringify({
    version:1,
    pages:[{
      id:"page-1",
      title:"Enterprise Terraform DFD",
      shapes,
      lines
    }]
  },null,2);
}

// ─────────────────────────────────────────────────────────────────────────────
// STATIC ENRICHMENT DATA — layer remediation, ATT&CK mapping, compliance gaps
// ─────────────────────────────────────────────────────────────────────────────

// Per-layer remediation guidance: what Terraform resources/modules to add when missing/partial
const LAYER_REMEDIATION = {
  1: {
    label: 'Foundation Layer',
    resources: ['aws_organizations_organization', 'aws_organizations_policy (SCP)', 'aws_organizations_policy_attachment'],
    action: 'Add enterprise-aws-bootstrap module with SCP templates for OU-level governance controls.',
    moduleExample: 'module "bootstrap" {\n  source = "enterprise-aws-bootstrap"\n  ou_tree_file = "ou-tree.yaml"\n}',
  },
  2: {
    label: 'Platform Factory Layer',
    resources: ['kubernetes_manifest (CRDs)', 'kubernetes_service_account', 'aws_iam_role (IRSA)'],
    action: 'Deploy Kubernetes operator factories for automated boundary provisioning. Add CRD manifests and IRSA roles.',
    moduleExample: 'module "portfolio_boundary_factory" {\n  source = "portfolio-boundary-factory"\n  cluster_name = var.eks_cluster_name\n}',
  },
  3: {
    label: 'IAM Management Layer',
    resources: ['aws_iam_role', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_iam_instance_profile'],
    action: 'Add module-role and module-iam-policy for centralized IAM lifecycle. Enforce permission boundaries.',
    moduleExample: 'module "iam_role" {\n  source          = "module-role"\n  service_name    = var.service_name\n  permissions_boundary = aws_iam_policy.boundary.arn\n}',
  },
  4: {
    label: 'Network Boundary Layer',
    resources: ['aws_vpc', 'aws_subnet', 'aws_security_group', 'aws_ec2_transit_gateway', 'aws_vpc_endpoint'],
    action: 'Add network-boundary modules. Define private subnets, TGW attachments, and PrivateLink for AWS services.',
    moduleExample: 'module "network_boundary" {\n  source      = "network-boundary-factory"\n  vpc_cidr    = "10.0.0.0/16"\n  enable_tgw  = true\n}',
  },
  5: {
    label: 'Security Controls Layer',
    resources: ['tfe_sentinel_policy', 'tfe_policy_set', 'tfe_policy_set_parameter'],
    action: 'Add Sentinel policy files for governance enforcement. Cover tagging, naming conventions, and cost controls.',
    moduleExample: '# sentinel.hcl\npolicy "require-tags" {\n  source           = "policies/require-tags.sentinel"\n  enforcement_level = "hard-mandatory"\n}',
  },
  6: {
    label: 'Product Module Layer',
    resources: ['aws_msk_cluster', 'aws_elasticsearch_domain', 'aws_rds_cluster', 'aws_elasticache_cluster', 'aws_kendra_index'],
    action: 'Add product-specific service modules for AWS managed services your platform exposes.',
    moduleExample: 'module "msk" {\n  source           = "module-msk-connect"\n  cluster_name     = var.kafka_cluster_name\n  number_of_broker_nodes = 3\n}',
  },
  7: {
    label: 'Application Layer',
    resources: ['aws_ecs_service', 'aws_lambda_function', 'aws_api_gateway_rest_api', 'aws_codepipeline'],
    action: 'Add workload-specific modules and application-level resources for your product teams.',
    moduleExample: 'module "app_workload" {\n  source       = "workload-boundary-factory"\n  workload_name = var.app_name\n  team_id      = var.team_id\n}',
  },
};

// Factory component remediation: where to find/create each factory module
const FACTORY_REMEDIATION = {
  'portfolio-boundary-factory': {
    path: 'platform/operators/portfolio-boundary-factory/',
    keyFiles: ['crds/portfolio-boundary.yaml', 'serviceaccount.yaml', 'rbac.yaml', 'operator-deployment.yaml'],
    priority: 'CRITICAL',
  },
  'network-boundary-factory': {
    path: 'platform/operators/network-boundary-factory/',
    keyFiles: ['crds/network-boundary.yaml', 'serviceaccount.yaml', 'rbac.yaml', 'operator-deployment.yaml'],
    priority: 'HIGH',
  },
  'base-account-factory': {
    path: 'platform/operators/base-account-factory/',
    keyFiles: ['crds/account-factory.yaml', 'serviceaccount.yaml', 'rbac.yaml', 'operator-deployment.yaml'],
    priority: 'HIGH',
  },
  'workload-boundary-factory': {
    path: 'platform/operators/workload-boundary-factory/',
    keyFiles: ['crds/workload-boundary.yaml', 'serviceaccount.yaml', 'rbac.yaml', 'operator-deployment.yaml'],
    priority: 'MEDIUM',
  },
};

// ATT&CK techniques enabled when each layer is absent
const LAYER_ATTACK_MAP = {
  1: ['T1580 (Cloud Infrastructure Discovery)', 'T1528 (Steal Application Access Token)', 'T1562.001 (Disable Cloud Controls)'],
  2: ['T1610 (Deploy Container)', 'T1609 (Container Administration Command)', 'T1204.003 (Malicious Image Execution)'],
  3: ['T1078.004 (Valid Cloud Accounts)', 'T1098.001 (Additional Cloud Credentials)', 'T1548.005 (Abuse Elevation Control - IAM)'],
  4: ['T1021.007 (Cloud Services Lateral Movement)', 'T1599.001 (NAT Traversal)', 'T1090.004 (Domain Fronting via Proxy)'],
  5: ['T1562.008 (Disable Cloud Logging)', 'T1098.003 (Additional Cloud Roles)', 'T1578 (Modify Cloud Compute Infrastructure)'],
  6: ['T1530 (Data from Cloud Storage)', 'T1537 (Exfil to Cloud Account)', 'T1213.003 (Data from Code Repos)'],
  7: ['T1190 (Exploit Public-Facing Application)', 'T1059.009 (Cloud API Scripting)', 'T1203 (Exploitation for Client Execution)'],
};

// Per-framework top 3 gap areas for compliance narrative
const COMPLIANCE_GAP_AREAS = {
  sox: [
    'Financial data access logging — enable CloudTrail data events on all S3 buckets storing financial records',
    'Change management controls — enforce resource tagging (ChangeRequest, ApprovedBy) via SCP/Sentinel',
    'Segregation of duties — separate IAM roles for deploy, approve, and audit principals (no shared admin)',
  ],
  pci: [
    'Network segmentation — isolate cardholder data environment (CDE) in dedicated VPCs with no-inbound default SGs',
    'Encryption in transit and at rest — enforce TLS 1.2+ via SCP; use aws_kms_key for all data stores',
    'Vulnerability management — add automated scanning (aws_inspector2_enabler) and patch automation (aws_ssm_patch_baseline)',
  ],
  gdpr: [
    'Data residency controls — lock S3 buckets and RDS to EU regions via aws_s3_bucket_policy + SCP deny outside EU',
    'Right to erasure automation — add S3 lifecycle policies and DynamoDB TTL for PII data stores',
    'Processing activity records — enforce DataClassification and ProcessingPurpose tags via Sentinel policy',
  ],
  hipaa: [
    'PHI access controls — use aws_iam_policy with Condition keys (aws:RequestedRegion, aws:PrincipalTag/PHIAuthorized)',
    'Audit controls — enable CloudTrail + Config rules (restricted-common-ports, iam-no-inline-policy) for all PHI accounts',
    'Transmission security — enforce PrivateLink for all API calls; ban public S3 buckets via aws_s3_account_public_access_block',
  ],
};

// Sentinel starter policy template (shown when totalCount === 0)
const SENTINEL_STARTER_POLICY = `# sentinel.hcl — Add to your TFE workspace root
policy "require-mandatory-tags" {
  source           = "./policies/require-tags.sentinel"
  enforcement_level = "hard-mandatory"
}
policy "restrict-aws-regions" {
  source           = "./policies/restrict-regions.sentinel"
  enforcement_level = "hard-mandatory"
}
policy "prohibit-public-s3" {
  source           = "./policies/no-public-s3.sentinel"
  enforcement_level = "hard-mandatory"
}

# policies/require-tags.sentinel
import "tfplan/v2" as tfplan
mandatory_tags = ["Environment", "Owner", "CostCenter", "DataClassification"]
main = rule {
  all tfplan.resource_changes as _, rc {
    rc.mode is "managed" and (rc.change.actions contains "create" or rc.change.actions contains "update") implies
      all mandatory_tags as tag { tag in keys(rc.change.after.tags else {}) }
  }
}`;

// ─────────────────────────────────────────────────────────────────────────────
// REPORT CONTENT HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function _gradeLabel(g) {
  return g === 'A' ? 'Excellent' : g === 'B' ? 'Good' : g === 'C' ? 'Moderate' : g === 'D' ? 'Poor' : g === 'F' ? 'Critical' : 'Unknown';
}

function _buildExecutiveSummaryText(archAnalysis, threatContext) {
  const archGrade = archAnalysis?.architectureGrade || '?';
  const layers = archAnalysis?.layers || {};
  const layerKeys = Object.keys(layers);
  const presentCount = layerKeys.filter(k => (layers[k].completeness || 0) > 0).length;
  const missingCount = layerKeys.filter(k => (layers[k].completeness || 0) === 0).length;

  const postureGrade = threatContext?.grade || archAnalysis?.security?.grade || '?';
  const postureScore = threatContext?.postureScore ?? archAnalysis?.security?.overall ?? null;
  const misconfigCount = threatContext?.misconfigCount ?? 0;
  const attackCount = threatContext?.attackTechniqueCount ?? 0;
  const gapCount = threatContext?.controlGapCount ?? 0;

  const lines = [];
  lines.push(`Architecture Grade ${archGrade} (${_gradeLabel(archGrade)}) — ${presentCount} of ${layerKeys.length || 7} layers present, ${missingCount} missing.`);

  if (postureScore !== null) {
    lines.push(`Security Posture Score: ${postureScore}/100 (Grade ${postureGrade}, ${_gradeLabel(postureGrade)}).`);
  }

  const findings = [];
  if (misconfigCount > 0) findings.push(`${misconfigCount} active misconfiguration${misconfigCount !== 1 ? 's' : ''}`);
  if (attackCount > 0) findings.push(`${attackCount} MITRE ATT&CK technique${attackCount !== 1 ? 's' : ''} mapped`);
  if (gapCount > 0) findings.push(`${gapCount} control gap${gapCount !== 1 ? 's' : ''} requiring remediation`);
  if (findings.length > 0) {
    lines.push(`Analysis identified: ${findings.join('; ')}.`);
  }

  const topMisconfigs = threatContext?.topMisconfigs || [];
  if (topMisconfigs.length > 0) {
    lines.push(`Top misconfigurations: ${topMisconfigs.join(' | ')}.`);
  }

  if (missingCount >= 4) {
    lines.push('PRIORITY: Foundational layers are absent. Remediate Layers 1-3 before addressing higher-level controls.');
  } else if (missingCount >= 2) {
    lines.push('Partial coverage detected. Address missing layers to close attack surface gaps identified in the ATT&CK mapping below.');
  } else if (missingCount === 0) {
    lines.push('All architecture layers detected. Focus remediation on misconfigurations and control gaps.');
  }

  return lines;
}

function _buildLayerRemediationItems(archAnalysis) {
  const layers = archAnalysis?.layers || {};
  const items = [];
  Object.keys(layers).forEach(k => {
    const l = layers[k];
    const completeness = l.completeness || 0;
    if (completeness >= 90) return; // fully present — skip
    const rem = LAYER_REMEDIATION[parseInt(k, 10)];
    if (!rem) return;
    const status = completeness === 0 ? 'MISSING' : 'PARTIAL';
    const missingMods = l.missingModules?.length ? `Missing modules: ${l.missingModules.join(', ')}` : '';
    items.push({ layerNum: k, status, completeness, rem, missingMods, layerName: l.name || rem.label });
  });
  return items;
}

function _buildFactoryRemediationItems(archAnalysis) {
  const factories = archAnalysis?.factories || {};
  const items = [];
  Object.entries(factories).forEach(([name, f]) => {
    if (f.status === 'present') return;
    const rem = FACTORY_REMEDIATION[name];
    if (!rem) return;
    items.push({ name, status: f.status || 'missing', rem });
  });
  return items;
}

function _buildAttackMappingItems(archAnalysis) {
  const layers = archAnalysis?.layers || {};
  const items = [];
  Object.keys(layers).forEach(k => {
    const l = layers[k];
    if ((l.completeness || 0) > 0) return; // only fully missing layers
    const techniques = LAYER_ATTACK_MAP[parseInt(k, 10)];
    if (!techniques) return;
    items.push({ layerNum: k, layerName: l.name || `Layer ${k}`, techniques });
  });
  return items;
}

// ─────────────────────────────────────────────────────────────────────────────
// PLAIN TEXT REPORT GENERATOR
// ─────────────────────────────────────────────────────────────────────────────

export function generateTXTReport(archAnalysis, threatContext = null) {
  const ts = new Date().toISOString();
  const lines = [];
  const hr = (char='=', len=60) => char.repeat(len);
  const section = (title) => { lines.push('', hr('-'), title, hr('-')); };

  lines.push(hr('='));
  lines.push('THREATAFORM — ENTERPRISE INFRASTRUCTURE INTELLIGENCE REPORT');
  lines.push(hr('='));
  lines.push(`Analysis Date:     ${ts}`);
  lines.push(`Platform Version:  Enterprise Cloud Platform 2.0`);
  if (archAnalysis?.summary) {
    lines.push(`Total Files:       ${archAnalysis.summary.totalFiles || 0}`);
  }

  // ── Executive Summary ──────────────────────────────────────────────────────
  section('EXECUTIVE SUMMARY');
  const summaryLines = _buildExecutiveSummaryText(archAnalysis, threatContext);
  summaryLines.forEach(l => lines.push(l));

  if (archAnalysis) {
    // ── Architecture Analysis ────────────────────────────────────────────────
    section('ARCHITECTURE ANALYSIS');
    const grade = archAnalysis.architectureGrade || '?';
    const layers = archAnalysis.layers || {};
    const layerKeys = Object.keys(layers);
    const presentCount = layerKeys.filter(k => layers[k].completeness > 0).length;
    lines.push(`Architecture Grade: ${grade}`);
    lines.push(`Layers Found: ${presentCount}/${layerKeys.length}`);
    lines.push('');
    layerKeys.forEach(k => {
      const l = layers[k];
      const icon = l.completeness >= 90 ? '[OK]' : l.completeness > 0 ? '[PARTIAL]' : '[MISSING]';
      const missing = l.missingModules?.length ? `   Missing: ${l.missingModules.join(', ')}` : '';
      lines.push(`Layer ${k} - ${l.name || ''}: ${icon} ${l.completeness || 0}% — ${l.fileCount || 0} files${missing}`);
    });

    // ── Per-Layer Remediation ────────────────────────────────────────────────
    const remItems = _buildLayerRemediationItems(archAnalysis);
    if (remItems.length > 0) {
      section('PER-LAYER REMEDIATION ACTIONS');
      remItems.forEach(item => {
        lines.push(`Layer ${item.layerNum} — ${item.layerName} [${item.status}, ${item.completeness}%]`);
        if (item.missingMods) lines.push(`  ${item.missingMods}`);
        lines.push(`  Action: ${item.rem.action}`);
        lines.push(`  Terraform resources to add: ${item.rem.resources.join(', ')}`);
        lines.push(`  Example:`);
        item.rem.moduleExample.split('\n').forEach(el => lines.push(`    ${el}`));
        lines.push('');
      });
    }

    // ── Factory Component Status ─────────────────────────────────────────────
    if (archAnalysis.factories) {
      section('FACTORY COMPONENT STATUS');
      Object.entries(archAnalysis.factories).forEach(([name, f]) => {
        const icon = f.status === 'present' ? '[OK]' : f.status === 'partial' ? '[PARTIAL]' : '[MISSING]';
        lines.push(`${name}: ${icon} ${(f.status || 'missing').toUpperCase()}   Files: ${f.fileCount || 0}`);
        (f.securityFindings || []).forEach(sf => lines.push(`  WARNING: ${sf}`));
      });

      // ── Factory Remediation Paths ──────────────────────────────────────────
      const factItems = _buildFactoryRemediationItems(archAnalysis);
      if (factItems.length > 0) {
        lines.push('');
        lines.push('Factory Remediation Paths:');
        factItems.forEach(item => {
          lines.push(`  ${item.name} [${item.status.toUpperCase()}] — Priority: ${item.rem.priority}`);
          lines.push(`    Create directory: ${item.rem.path}`);
          lines.push(`    Required files: ${item.rem.keyFiles.join(', ')}`);
        });
      }
    }

    // ── Sentinel Policy Coverage ─────────────────────────────────────────────
    if (archAnalysis.sentinelPolicies) {
      section('SENTINEL POLICY COVERAGE');
      const totalCount = archAnalysis.sentinelPolicies.totalCount || 0;
      lines.push(`Total Sentinel Policies: ${totalCount}`);
      const types = archAnalysis.sentinelPolicies.policyTypes || {};
      Object.entries(types).forEach(([t, cnt]) => lines.push(`  ${t}: ${cnt > 0 ? '[OK]' : '[MISSING]'} (${cnt} policies)`));

      if (totalCount === 0) {
        lines.push('');
        lines.push('RISK: No Sentinel policies detected. Without policy-as-code enforcement, any Terraform');
        lines.push('configuration can be applied — including public S3 buckets, untagged resources, and');
        lines.push('over-privileged IAM roles. Recommended starter policies:');
        lines.push('');
        SENTINEL_STARTER_POLICY.split('\n').forEach(l => lines.push('  ' + l));
      }
    }

    // ── Security Posture ─────────────────────────────────────────────────────
    if (archAnalysis.security) {
      section('SECURITY POSTURE');
      const s = archAnalysis.security;
      lines.push(`Overall Security Score: ${s.overall || 0}%`);
      lines.push(`  SCP Inheritance:   ${s.scpInheritance || 0}%`);
      lines.push(`  Network Security:  ${s.networkSecurity || 0}%`);
      lines.push(`  IAM Governance:    ${s.iamGovernance || 0}%`);
      lines.push(`  Data Protection:   ${s.dataProtection || 0}%`);
      lines.push(`  Sentinel Coverage: ${s.sentinelCoverage || 0}%`);
      lines.push(`  Audit Logging:     ${s.auditLogging || 0}%`);
      if (s.criticalIssues?.length) {
        lines.push('', 'Critical Issues:');
        s.criticalIssues.forEach((i, n) => lines.push(`  ${n + 1}. ${i}`));
      }
    }

    // ── Compliance Status ────────────────────────────────────────────────────
    if (archAnalysis.compliance) {
      section('COMPLIANCE STATUS');
      const c = archAnalysis.compliance;
      lines.push(`Overall Compliance: ${c.overall || 0}%`);
      lines.push(`  SOX:   ${c.sox || 0}%`);
      lines.push(`  PCI:   ${c.pci || 0}%`);
      lines.push(`  GDPR:  ${c.gdpr || 0}%`);
      lines.push(`  HIPAA: ${c.hipaa || 0}%`);
      if (c.violations?.length) {
        lines.push('', 'Violations:');
        c.violations.slice(0, 10).forEach((v, n) => lines.push(`  ${n + 1}. ${v}`));
      }

      // ── Compliance Gap Narrative ─────────────────────────────────────────
      const frameworkScores = { sox: c.sox || 0, pci: c.pci || 0, gdpr: c.gdpr || 0, hipaa: c.hipaa || 0 };
      const gapFrameworks = Object.entries(frameworkScores).filter(([, score]) => score < 80);
      if (gapFrameworks.length > 0) {
        lines.push('');
        lines.push('Compliance Gap Analysis:');
        gapFrameworks.forEach(([fw, score]) => {
          const fwLabel = { sox: 'SOX', pci: 'PCI DSS', gdpr: 'GDPR', hipaa: 'HIPAA' }[fw] || fw.toUpperCase();
          lines.push(`  ${fwLabel} (${score}%) — Top remediation areas:`);
          (COMPLIANCE_GAP_AREAS[fw] || []).forEach((area, i) => {
            lines.push(`    ${i + 1}. ${area}`);
          });
        });
      }
    }

    // ── Architecture-to-ATT&CK Mapping ──────────────────────────────────────
    const attackItems = _buildAttackMappingItems(archAnalysis);
    if (attackItems.length > 0) {
      section('ARCHITECTURE-TO-ATT&CK MAPPING');
      lines.push('The following ATT&CK techniques are enabled by absent architecture layers:');
      lines.push('');
      attackItems.forEach(item => {
        lines.push(`Layer ${item.layerNum} ABSENT (${item.layerName}):`);
        item.techniques.forEach(t => lines.push(`  - ${t}`));
        lines.push('');
      });
    }

    // ── Threat Intelligence Summary (from threatContext) ─────────────────────
    if (threatContext && (threatContext.misconfigCount || threatContext.attackTechniqueCount)) {
      section('THREAT INTELLIGENCE SUMMARY');
      if (threatContext.misconfigCount) lines.push(`Misconfigurations Detected: ${threatContext.misconfigCount}`);
      if (threatContext.attackTechniqueCount) lines.push(`ATT&CK Techniques Mapped:   ${threatContext.attackTechniqueCount}`);
      if (threatContext.controlGapCount) lines.push(`Control Gaps Identified:    ${threatContext.controlGapCount}`);
      if (threatContext.topMisconfigs?.length) {
        lines.push('');
        lines.push('Top Misconfiguration Findings:');
        threatContext.topMisconfigs.forEach((m, i) => lines.push(`  ${i + 1}. ${m}`));
      }
    }

    // ── Recommendations ──────────────────────────────────────────────────────
    if (archAnalysis.recommendations?.length) {
      section('RECOMMENDATIONS (Priority Ordered)');
      archAnalysis.recommendations.forEach((r, i) => {
        lines.push(`${i + 1}. [${r.priority || 'MEDIUM'}] ${r.title || r.description || 'Recommendation'}`);
        if (r.description && r.title) lines.push(`   ${r.description}`);
        if (r.impact) lines.push(`   Impact: ${r.impact}`);
        if (r.action) lines.push(`   Action: ${r.action}`);
        if (r.attackTechniques?.length) lines.push(`   ATT&CK: ${r.attackTechniques.join(', ')}`);
        lines.push('');
      });
    }
  }

  lines.push(hr('='));
  lines.push('END OF REPORT');
  lines.push(hr('='));
  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// MARKDOWN REPORT GENERATOR
// Produces a GitHub/Confluence-compatible markdown report from archAnalysis output.
// ─────────────────────────────────────────────────────────────────────────────

export function generateMarkdownReport(archAnalysis, threatContext = null) {
  const ts = new Date().toISOString();
  const lines = [];

  lines.push('# Threataform — Enterprise Infrastructure Intelligence Report');
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Analysis Date | ${ts} |`);
  lines.push(`| Platform Version | Enterprise Cloud Platform 2.0 |`);
  if (archAnalysis?.summary) {
    lines.push(`| Total Files Analyzed | ${archAnalysis.summary.totalFiles || 0} |`);
  }

  // ── Executive Summary ──────────────────────────────────────────────────────
  lines.push('');
  lines.push('## Executive Summary');
  lines.push('');
  const summaryLines = _buildExecutiveSummaryText(archAnalysis, threatContext);
  summaryLines.forEach(l => lines.push(l));

  if (archAnalysis) {
    // ── Architecture Analysis ────────────────────────────────────────────────
    lines.push('');
    lines.push('## Architecture Analysis');
    lines.push('');
    const grade = archAnalysis.architectureGrade || '?';
    const layers = archAnalysis.layers || {};
    const layerKeys = Object.keys(layers);
    const presentCount = layerKeys.filter(k => layers[k].completeness > 0).length;
    lines.push(`**Architecture Grade:** \`${grade}\`  `);
    lines.push(`**Layers Found:** ${presentCount}/${layerKeys.length}  `);
    lines.push('');
    lines.push('| Layer | Name | Status | Completeness | Files | Missing Modules |');
    lines.push('|-------|------|--------|-------------|-------|-----------------|');
    layerKeys.forEach(k => {
      const l = layers[k];
      const icon = l.completeness >= 90 ? '✅' : l.completeness > 0 ? '⚠️' : '❌';
      const missing = l.missingModules?.length ? l.missingModules.join(', ') : '—';
      lines.push(`| ${k} | ${l.name || ''} | ${icon} | ${l.completeness || 0}% | ${l.fileCount || 0} | ${missing} |`);
    });

    // ── Per-Layer Remediation ────────────────────────────────────────────────
    const remItems = _buildLayerRemediationItems(archAnalysis);
    if (remItems.length > 0) {
      lines.push('');
      lines.push('## Per-Layer Remediation Actions');
      lines.push('');
      remItems.forEach(item => {
        const badge = item.status === 'MISSING' ? '❌' : '⚠️';
        lines.push(`### Layer ${item.layerNum} — ${badge} ${item.layerName} (${item.completeness}%)`);
        lines.push('');
        if (item.missingMods) lines.push(`**${item.missingMods}**  `);
        lines.push(`**Action:** ${item.rem.action}  `);
        lines.push(`**Terraform resources to add:** \`${item.rem.resources.join('`, `')}\``);
        lines.push('');
        lines.push('```hcl');
        lines.push(item.rem.moduleExample);
        lines.push('```');
        lines.push('');
      });
    }

    // ── Factory Component Status ─────────────────────────────────────────────
    if (archAnalysis.factories) {
      lines.push('');
      lines.push('## Factory Component Status');
      lines.push('');
      lines.push('| Factory | Status | Files | Security Findings |');
      lines.push('|---------|--------|-------|-------------------|');
      Object.entries(archAnalysis.factories).forEach(([name, f]) => {
        const icon = f.status === 'present' ? '✅' : f.status === 'partial' ? '⚠️' : '❌';
        const findings = (f.securityFindings || []).length ? (f.securityFindings || []).join('; ') : '—';
        lines.push(`| \`${name}\` | ${icon} ${(f.status || 'missing').toUpperCase()} | ${f.fileCount || 0} | ${findings} |`);
      });

      // ── Factory Remediation Paths ──────────────────────────────────────────
      const factItems = _buildFactoryRemediationItems(archAnalysis);
      if (factItems.length > 0) {
        lines.push('');
        lines.push('### Factory Remediation Paths');
        lines.push('');
        lines.push('| Factory | Priority | Directory | Required Files |');
        lines.push('|---------|----------|-----------|----------------|');
        factItems.forEach(item => {
          lines.push(`| \`${item.name}\` | **${item.rem.priority}** | \`${item.rem.path}\` | ${item.rem.keyFiles.map(f => `\`${f}\``).join(', ')} |`);
        });
      }
    }

    // ── Sentinel Policy Coverage ─────────────────────────────────────────────
    if (archAnalysis.sentinelPolicies) {
      lines.push('');
      lines.push('## Sentinel Policy Coverage');
      lines.push('');
      const totalCount = archAnalysis.sentinelPolicies.totalCount || 0;
      lines.push(`**Total Sentinel Policies:** ${totalCount}`);
      lines.push('');
      lines.push('| Policy Type | Status | Count |');
      lines.push('|-------------|--------|-------|');
      const types = archAnalysis.sentinelPolicies.policyTypes || {};
      Object.entries(types).forEach(([t, cnt]) => {
        lines.push(`| ${t} | ${cnt > 0 ? '✅ Present' : '❌ Missing'} | ${cnt} |`);
      });

      if (totalCount === 0) {
        lines.push('');
        lines.push('> **RISK:** No Sentinel policies detected. Without policy-as-code enforcement, any');
        lines.push('> Terraform configuration can be applied — public S3 buckets, untagged resources,');
        lines.push('> and over-privileged IAM roles are all permissible. Add the starter policies below.');
        lines.push('');
        lines.push('```hcl');
        lines.push(SENTINEL_STARTER_POLICY);
        lines.push('```');
      }
    }

    // ── Security Posture ─────────────────────────────────────────────────────
    if (archAnalysis.security) {
      lines.push('');
      lines.push('## Security Posture');
      lines.push('');
      const s = archAnalysis.security;
      lines.push(`**Overall Security Score:** \`${s.overall || 0}%\``);
      lines.push('');
      lines.push('| Dimension | Score |');
      lines.push('|-----------|-------|');
      lines.push(`| SCP Inheritance | ${s.scpInheritance || 0}% |`);
      lines.push(`| Network Security | ${s.networkSecurity || 0}% |`);
      lines.push(`| IAM Governance | ${s.iamGovernance || 0}% |`);
      lines.push(`| Data Protection | ${s.dataProtection || 0}% |`);
      lines.push(`| Sentinel Coverage | ${s.sentinelCoverage || 0}% |`);
      lines.push(`| Audit Logging | ${s.auditLogging || 0}% |`);
      if (s.criticalIssues?.length) {
        lines.push('');
        lines.push('### Critical Issues');
        lines.push('');
        s.criticalIssues.forEach(i => lines.push(`- **${i}**`));
      }
    }

    // ── Compliance Status ────────────────────────────────────────────────────
    if (archAnalysis.compliance) {
      lines.push('');
      lines.push('## Compliance Status');
      lines.push('');
      const c = archAnalysis.compliance;
      lines.push(`**Overall Compliance:** \`${c.overall || 0}%\``);
      lines.push('');
      lines.push('| Framework | Score |');
      lines.push('|-----------|-------|');
      lines.push(`| SOX | ${c.sox || 0}% |`);
      lines.push(`| PCI DSS | ${c.pci || 0}% |`);
      lines.push(`| GDPR | ${c.gdpr || 0}% |`);
      lines.push(`| HIPAA | ${c.hipaa || 0}% |`);
      if (c.violations?.length) {
        lines.push('');
        lines.push('### Violations');
        lines.push('');
        c.violations.slice(0, 10).forEach((v, n) => lines.push(`${n + 1}. ${v}`));
      }

      // ── Compliance Gap Narrative ─────────────────────────────────────────
      const frameworkScores = { sox: c.sox || 0, pci: c.pci || 0, gdpr: c.gdpr || 0, hipaa: c.hipaa || 0 };
      const gapFrameworks = Object.entries(frameworkScores).filter(([, score]) => score < 80);
      if (gapFrameworks.length > 0) {
        lines.push('');
        lines.push('### Compliance Gap Analysis');
        lines.push('');
        gapFrameworks.forEach(([fw, score]) => {
          const fwLabel = { sox: 'SOX', pci: 'PCI DSS', gdpr: 'GDPR', hipaa: 'HIPAA' }[fw] || fw.toUpperCase();
          lines.push(`**${fwLabel} (${score}%) — Top remediation areas:**`);
          lines.push('');
          (COMPLIANCE_GAP_AREAS[fw] || []).forEach((area, i) => {
            lines.push(`${i + 1}. ${area}`);
          });
          lines.push('');
        });
      }
    }

    // ── Architecture-to-ATT&CK Mapping ──────────────────────────────────────
    const attackItems = _buildAttackMappingItems(archAnalysis);
    if (attackItems.length > 0) {
      lines.push('');
      lines.push('## Architecture-to-ATT&CK Mapping');
      lines.push('');
      lines.push('The following MITRE ATT&CK techniques are enabled by absent architecture layers:');
      lines.push('');
      lines.push('| Missing Layer | Enabled ATT&CK Techniques |');
      lines.push('|---------------|---------------------------|');
      attackItems.forEach(item => {
        lines.push(`| **Layer ${item.layerNum} — ${item.layerName}** | ${item.techniques.map(t => `\`${t}\``).join(', ')} |`);
      });
    }

    // ── Threat Intelligence Summary ──────────────────────────────────────────
    if (threatContext && (threatContext.misconfigCount || threatContext.attackTechniqueCount)) {
      lines.push('');
      lines.push('## Threat Intelligence Summary');
      lines.push('');
      lines.push('| Finding Category | Count |');
      lines.push('|-----------------|-------|');
      if (threatContext.misconfigCount) lines.push(`| Misconfigurations Detected | **${threatContext.misconfigCount}** |`);
      if (threatContext.attackTechniqueCount) lines.push(`| ATT&CK Techniques Mapped | **${threatContext.attackTechniqueCount}** |`);
      if (threatContext.controlGapCount) lines.push(`| Control Gaps Identified | **${threatContext.controlGapCount}** |`);
      if (threatContext.topMisconfigs?.length) {
        lines.push('');
        lines.push('**Top Misconfiguration Findings:**');
        lines.push('');
        threatContext.topMisconfigs.forEach((m, i) => lines.push(`${i + 1}. ${m}`));
      }
    }

    // ── Recommendations ──────────────────────────────────────────────────────
    if (archAnalysis.recommendations?.length) {
      lines.push('');
      lines.push('## Recommendations (Priority Ordered)');
      lines.push('');
      archAnalysis.recommendations.forEach((r, i) => {
        const badge = r.priority === 'CRITICAL' ? '🔴' : r.priority === 'HIGH' ? '🟠' : r.priority === 'MEDIUM' ? '🟡' : '🟢';
        lines.push(`### ${i + 1}. ${badge} [${r.priority || 'MEDIUM'}] ${r.title || r.description || 'Recommendation'}`);
        lines.push('');
        if (r.description && r.title) lines.push(`${r.description}`);
        if (r.impact) lines.push(`**Impact:** ${r.impact}`);
        if (r.action) lines.push(`**Action:** ${r.action}`);
        if (r.attackTechniques?.length) lines.push(`**ATT&CK Techniques:** \`${r.attackTechniques.join('`, `')}\``);
        lines.push('');
      });
    }
  }

  lines.push('---');
  lines.push('*Generated by Threataform — Enterprise Infrastructure Intelligence*');
  return lines.join('\n');
}
