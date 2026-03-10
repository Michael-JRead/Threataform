// src/data/control-detection.js
// Evidence confidence scores, security control detection map, and
// defense-in-depth / zero-trust / NIST CSF framework definitions.
// Used by ThreatModelIntelligence, runSecurityChecks, and the Control Inventory tab.

import {
  Shield, Network, KeyRound, Cpu, AppWindow, Database, Activity,
  Users, Globe, HardDrive, Zap, Search,
} from '../icons.jsx';

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE FRAMEWORK — confidence scores + source metadata for every finding
// ─────────────────────────────────────────────────────────────────────────────

export const CONFIDENCE_BY_METHOD = {
  attr_parse:     92, // parseHCLBody extracted a concrete value
  flat_string:    90, // flat key = "value" regex match
  flat_bool:      90, // flat key = true/false regex match
  policy_parse:   95, // JSON policy document parsed and evaluated
  type_presence:  50, // resource type found, config not verified
  type_assoc:     75, // resource type + association resource verified
  substring_match:35, // r.body.includes(x) only
  bm25_token:     55, // doc match with BM25 + negation check passed
  bm25_low:       30, // doc match at 60% token threshold only
  var_ref:        20, // attribute present but value is var.x (unresolved)
  attr_absence:   85, // attribute confirmed absent by parseHCLBody
};

export function mkEvidence(method, snippet, location='', extra={}) {
  return {
    source: ['attr_parse','flat_string','flat_bool','policy_parse','var_ref','attr_absence'].includes(method)
      ? 'hcl' : ['bm25_token','bm25_low'].includes(method) ? 'doc' : 'inferred',
    confidence: CONFIDENCE_BY_METHOD[method] ?? 40,
    snippet: (snippet||'').slice(0, 160),
    location,
    method,
    ...extra,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTERPRISE SECURITY KNOWLEDGE GRAPH v2
// Control Detection · Defense-in-Depth Layers · Zero-Trust Pillars
// NIST CSF 2.0 · Cross-Doc Correlation · Blast Radius · Posture Scoring
// ─────────────────────────────────────────────────────────────────────────────

// ── Control detect helpers ─────────────────────────────────────────────────────
const _ctrlPresent = (snippet, loc='') => ({ state:'present', evidence:mkEvidence('type_presence', snippet, loc) });
const _ctrlPartial = (snippet, loc='') => ({ state:'partial',  evidence:mkEvidence('type_presence', snippet, loc) });
const _ctrlAbsent  = (snippet, loc='') => ({ state:'absent',   evidence:mkEvidence('type_presence', snippet, loc) });
const _ctrlAssoc   = (snippet, loc='') => ({ state:'present',  evidence:mkEvidence('type_assoc', snippet, loc) });
const _ctrlAttr    = (snippet, loc='') => ({ state:'present',  evidence:mkEvidence('attr_parse', snippet, loc) });

// Control detection map: TF resource presence → named security control
export const CONTROL_DETECTION_MAP = [
  // ── Perimeter
  { id:'CTRL-WAF', layer:'perimeter', ztPillar:'network', name:'Web Application Firewall (WAF)',
    detect:(rs)=>{
      const waf=rs.find(r=>['aws_wafv2_web_acl','aws_waf_web_acl'].includes(r.type));
      if(!waf) return _ctrlAbsent('No aws_wafv2_web_acl resource found');
      const assoc=rs.find(r=>r.type==='aws_wafv2_web_acl_association');
      if(!assoc) return _ctrlPartial(`aws_wafv2_web_acl.${waf.name} exists but no aws_wafv2_web_acl_association`,waf.id);
      return _ctrlAssoc(`WAF ACL + association verified: ${waf.id}`,waf.id);
    }},
  { id:'CTRL-SHIELD', layer:'perimeter', ztPillar:'network', name:'DDoS Protection (Shield Advanced)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_shield_protection');return r?_ctrlPresent(`aws_shield_protection.${r.name}`,r.id):_ctrlAbsent('No aws_shield_protection resource');} },
  { id:'CTRL-CF', layer:'perimeter', ztPillar:'network', name:'CloudFront CDN / Edge Security',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_cloudfront_distribution');return r?_ctrlPresent(`aws_cloudfront_distribution.${r.name}`,r.id):_ctrlAbsent('No aws_cloudfront_distribution resource');} },
  // ── Network
  { id:'CTRL-VPC', layer:'network', ztPillar:'network', name:'VPC Network Isolation',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_vpc');return r?_ctrlPresent(`aws_vpc.${r.name}`,r.id):_ctrlAbsent('No aws_vpc resource');} },
  { id:'CTRL-NACL', layer:'network', ztPillar:'network', name:'Network ACLs (Layer 4 filter)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_network_acl');return r?_ctrlPresent(`aws_network_acl.${r.name}`,r.id):_ctrlAbsent('No aws_network_acl resource');} },
  { id:'CTRL-VPCE', layer:'network', ztPillar:'network', name:'VPC Endpoints (PrivateLink)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_vpc_endpoint');return r?_ctrlPresent(`aws_vpc_endpoint.${r.name}`,r.id):_ctrlAbsent('No aws_vpc_endpoint resource');} },
  { id:'CTRL-FLOGS', layer:'network', ztPillar:'monitoring', name:'VPC Flow Logs',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_flow_log');return r?_ctrlPresent(`aws_flow_log.${r.name}`,r.id):_ctrlAbsent('No aws_flow_log resource');} },
  { id:'CTRL-TGW', layer:'network', ztPillar:'network', name:'Transit Gateway (Microsegmentation)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_ec2_transit_gateway');return r?_ctrlPresent(`aws_ec2_transit_gateway.${r.name}`,r.id):_ctrlAbsent('No aws_ec2_transit_gateway resource');} },
  { id:'CTRL-DX', layer:'network', ztPillar:'network', name:'Direct Connect / VPN',
    detect:(rs)=>{const r=rs.find(x=>['aws_dx_connection','aws_vpn_connection','aws_customer_gateway'].includes(x.type));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No Direct Connect or VPN resource');} },
  // ── Identity
  { id:'CTRL-SCP', layer:'identity', ztPillar:'identity', name:'Service Control Policies (SCPs)',
    detect:(rs)=>{
      const pol=rs.find(r=>r.type==='aws_organizations_policy'||r.type==='AWS::Organizations::Policy');
      if(!pol) return _ctrlAbsent('No aws_organizations_policy resource');
      const attach=rs.find(r=>r.type==='aws_organizations_policy_attachment');
      if(!attach) return _ctrlPartial(`aws_organizations_policy exists but no aws_organizations_policy_attachment`,pol.id);
      return _ctrlAssoc(`SCP + attachment verified: ${pol.id}`,pol.id);
    }},
  { id:'CTRL-SSO', layer:'identity', ztPillar:'identity', name:'AWS SSO / Identity Center',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_ssoadmin')||x.type.startsWith('aws_identitystore'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No SSO/Identity Center resource');} },
  { id:'CTRL-OIDC', layer:'identity', ztPillar:'identity', name:'OIDC Federation (GitHub/TFE)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_iam_openid_connect_provider');return r?_ctrlPresent(`aws_iam_openid_connect_provider.${r.name}`,r.id):_ctrlAbsent('No aws_iam_openid_connect_provider resource');} },
  { id:'CTRL-PB', layer:'identity', ztPillar:'identity', name:'IAM Permission Boundaries',
    detect:(rs)=>{
      const roles=rs.filter(r=>r.type==='aws_iam_role'||r.type==='AWS::IAM::Role');
      if(!roles.length) return _ctrlAbsent('No IAM role resources');
      const results=roles.map(role=>{
        const attrs=role.isCFN?role.cfnProps||{}:(role.attrs||parseHCLBody(role.body||''));
        const hasPB=role.isCFN?!!attrs.PermissionsBoundary:(attrs.permissions_boundary!==undefined&&attrs.permissions_boundary!==null);
        return {id:role.id,hasPB,msg:hasPB?`permissions_boundary set`:`permissions_boundary absent`};
      });
      const allHave=results.every(r=>r.hasPB), anyHave=results.some(r=>r.hasPB);
      const snippet=results.map(r=>`${r.id}: ${r.msg}`).join('; ').slice(0,160);
      return {state:allHave?'present':anyHave?'partial':'absent', evidence:mkEvidence('attr_parse',snippet)};
    }},
  { id:'CTRL-SAML', layer:'identity', ztPillar:'identity', name:'SAML Federation',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_iam_saml_provider');return r?_ctrlPresent(`aws_iam_saml_provider.${r.name}`,r.id):_ctrlAbsent('No aws_iam_saml_provider resource');} },
  { id:'CTRL-AA', layer:'identity', ztPillar:'identity', name:'IAM Access Analyzer',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_accessanalyzer_analyzer');return r?_ctrlPresent(`aws_accessanalyzer_analyzer.${r.name}`,r.id):_ctrlAbsent('No aws_accessanalyzer_analyzer resource');} },
  // ── Compute
  { id:'CTRL-IMDSv2', layer:'compute', ztPillar:'application', name:'EC2 IMDSv2 Enforced',
    detect:(rs)=>{
      const instances=rs.filter(r=>r.type==='aws_instance');
      if(!instances.length) return _ctrlAbsent('No aws_instance resources');
      const results=instances.map(r=>{
        const a=r.attrs||parseHCLBody(r.body||'');
        const mo=a.metadata_options;
        if(!mo) return {id:r.id,state:'absent',msg:'metadata_options block missing'};
        if(typeof mo==='object'&&mo.http_tokens===null) return {id:r.id,state:'partial',msg:'http_tokens = var (unresolved)'};
        return {id:r.id,state:(typeof mo==='object'&&mo.http_tokens==='required')?'present':'absent',msg:`http_tokens = "${typeof mo==='object'?mo.http_tokens:mo}"`};
      });
      const all=results.every(r=>r.state==='present'), any=results.some(r=>r.state!=='absent');
      return {state:all?'present':any?'partial':'absent', evidence:mkEvidence('attr_parse',results.map(r=>`${r.id}: ${r.msg}`).join('; ').slice(0,160))};
    }},
  { id:'CTRL-SSMSM', layer:'compute', ztPillar:'application', name:'SSM Session Manager',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_ssm_document'||x.type==='aws_ssm_association');return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_ssm_document or aws_ssm_association resource');} },
  { id:'CTRL-EKSP', layer:'compute', ztPillar:'application', name:'EKS Private API Endpoint',
    detect:(rs)=>{
      const cls=rs.find(r=>r.type==='aws_eks_cluster');
      if(!cls) return _ctrlAbsent('No aws_eks_cluster resource');
      const a=cls.attrs||parseHCLBody(cls.body||'');
      const vc=a.vpc_config;
      const pub=typeof vc==='object'?vc.endpoint_public_access:undefined;
      if(pub===false) return _ctrlAttr(`endpoint_public_access = false`,cls.id);
      if(pub===null)  return _ctrlPartial(`endpoint_public_access = var (unresolved)`,cls.id);
      return _ctrlAbsent(`endpoint_public_access not set to false`,cls.id);
    }},
  // ── Application
  { id:'CTRL-APIGW', layer:'application', ztPillar:'application', name:'API Gateway Auth / Throttling',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_api_gateway')||x.type.startsWith('aws_apigatewayv2'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No API Gateway resource');} },
  { id:'CTRL-COGNITO', layer:'application', ztPillar:'application', name:'Cognito User Authentication',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_cognito'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_cognito resource');} },
  { id:'CTRL-WAFASSOC', layer:'application', ztPillar:'application', name:'WAF Associated to ALB/API GW',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_wafv2_web_acl_association');return r?_ctrlAssoc(`aws_wafv2_web_acl_association.${r.name}`,r.id):_ctrlAbsent('No aws_wafv2_web_acl_association resource');} },
  // ── Data
  { id:'CTRL-KMS', layer:'data', ztPillar:'data', name:'KMS Customer-Managed Keys',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_kms_key');return r?_ctrlPresent(`aws_kms_key.${r.name}`,r.id):_ctrlAbsent('No aws_kms_key resource');} },
  { id:'CTRL-SM', layer:'data', ztPillar:'data', name:'Secrets Manager',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_secretsmanager_secret');return r?_ctrlPresent(`aws_secretsmanager_secret.${r.name}`,r.id):_ctrlAbsent('No aws_secretsmanager_secret resource');} },
  { id:'CTRL-SSMPS', layer:'data', ztPillar:'data', name:'SSM Parameter Store (SecureString)',
    detect:(rs)=>{
      const params=rs.filter(r=>r.type==='aws_ssm_parameter');
      if(!params.length) return _ctrlAbsent('No aws_ssm_parameter resources');
      const secures=params.filter(r=>{const a=r.attrs||parseHCLBody(r.body||'');return a.type==='SecureString';});
      if(!secures.length) return _ctrlAbsent(`${params.length} SSM parameter(s) found, none SecureString`);
      if(secures.length<params.length) return _ctrlPartial(`${secures.length}/${params.length} SSM parameters are SecureString`);
      return _ctrlAttr(`All ${params.length} SSM parameter(s) use SecureString`);
    }},
  { id:'CTRL-MACIE', layer:'data', ztPillar:'data', name:'Macie (Sensitive Data Discovery)',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_macie'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_macie resource');} },
  { id:'CTRL-BACKUP', layer:'data', ztPillar:'data', name:'AWS Backup (Recovery Plans)',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_backup'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_backup resource');} },
  { id:'CTRL-S3VER', layer:'data', ztPillar:'data', name:'S3 Versioning (Data Protection)',
    detect:(rs)=>{
      const buckets=rs.filter(r=>r.type==='aws_s3_bucket');
      if(!buckets.length) return _ctrlAbsent('No aws_s3_bucket resources');
      const results=buckets.map(r=>{
        const a=r.attrs||parseHCLBody(r.body||'');
        const v=a.versioning;
        const enabled=typeof v==='object'?v?.enabled===true:false;
        return {id:r.id,state:enabled?'present':'absent',msg:enabled?'versioning.enabled = true':'versioning not enabled'};
      });
      const all=results.every(r=>r.state==='present'), any=results.some(r=>r.state!=='absent');
      return {state:all?'present':any?'partial':'absent', evidence:mkEvidence('attr_parse',results.map(r=>`${r.id}: ${r.msg}`).join('; ').slice(0,160))};
    }},
  // ── Monitoring
  { id:'CTRL-CT', layer:'monitoring', ztPillar:'monitoring', name:'CloudTrail API Audit Logging',
    detect:(rs)=>{
      const ct=rs.find(r=>r.type==='aws_cloudtrail');
      if(!ct) return _ctrlAbsent('No aws_cloudtrail resource');
      const a=ct.attrs||parseHCLBody(ct.body||'');
      if(a.enable_log_file_validation===true) return _ctrlAttr(`enable_log_file_validation = true`,ct.id);
      if(a.enable_log_file_validation===false) return _ctrlPartial(`enable_log_file_validation = false`,ct.id);
      return _ctrlPartial(`aws_cloudtrail.${ct.name} present; enable_log_file_validation not set`,ct.id);
    }},
  { id:'CTRL-CTMR', layer:'monitoring', ztPillar:'monitoring', name:'CloudTrail Multi-Region',
    detect:(rs)=>{
      const ct=rs.find(r=>r.type==='aws_cloudtrail');
      if(!ct) return _ctrlAbsent('No aws_cloudtrail resource');
      const a=ct.attrs||parseHCLBody(ct.body||'');
      if(a.is_multi_region_trail===true) return _ctrlAttr(`is_multi_region_trail = true`,ct.id);
      if(a.is_multi_region_trail===null) return _ctrlPartial(`is_multi_region_trail = var (unresolved)`,ct.id);
      return _ctrlAbsent(`is_multi_region_trail not set to true`,ct.id);
    }},
  { id:'CTRL-GD', layer:'monitoring', ztPillar:'monitoring', name:'GuardDuty Threat Detection',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_guardduty_detector');return r?_ctrlPresent(`aws_guardduty_detector.${r.name}`,r.id):_ctrlAbsent('No aws_guardduty_detector resource');} },
  { id:'CTRL-CONFIG', layer:'monitoring', ztPillar:'monitoring', name:'AWS Config (Compliance Rules)',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_config_configuration_recorder'||x.type==='aws_config_rule');return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_config_configuration_recorder or aws_config_rule resource');} },
  { id:'CTRL-SH', layer:'monitoring', ztPillar:'monitoring', name:'Security Hub (Findings Aggregation)',
    detect:(rs)=>{const r=rs.find(x=>x.type.startsWith('aws_securityhub'));return r?_ctrlPresent(`${r.type}.${r.name}`,r.id):_ctrlAbsent('No aws_securityhub resource');} },
  { id:'CTRL-CW', layer:'monitoring', ztPillar:'monitoring', name:'CloudWatch Metric Alarms',
    detect:(rs)=>{const r=rs.find(x=>x.type==='aws_cloudwatch_metric_alarm');return r?_ctrlPresent(`aws_cloudwatch_metric_alarm.${r.name}`,r.id):_ctrlAbsent('No aws_cloudwatch_metric_alarm resource');} },
];

// Defense-in-Depth layer metadata
export const DID_LAYERS = {
  perimeter:   { name:'Perimeter Defense',    order:1, color:'#B71C1C', Icon:Shield,       desc:'WAF, DDoS protection, CDN edge rules, DNS security' },
  network:     { name:'Network Segmentation', order:2, color:'#E53935', Icon:Network,      desc:'VPC isolation, SGs, NACLs, PrivateLink, flow logs' },
  identity:    { name:'Identity & Access',    order:3, color:'#F57C00', Icon:KeyRound,     desc:'SCPs, permission boundaries, SSO, OIDC, Access Analyzer' },
  compute:     { name:'Compute Security',     order:4, color:'#FBC02D', Icon:Cpu,          desc:'IMDSv2, SSM Session Manager, EKS private endpoints' },
  application: { name:'Application Security', order:5, color:'#388E3C', Icon:AppWindow,    desc:'API Gateway auth, Cognito, WAF associations, rate limiting' },
  data:        { name:'Data Protection',      order:6, color:'#0288D1', Icon:Database,     desc:'KMS CMK, Secrets Manager, Macie DLP, S3 versioning, backup' },
  monitoring:  { name:'Detection & Response', order:7, color:'#7B1FA2', Icon:Activity,     desc:'CloudTrail, GuardDuty, Config rules, Security Hub, CloudWatch' },
};

// Zero-Trust pillar metadata
export const ZT_PILLARS = {
  identity:    { name:'Identity',     color:'#7B1FA2', Icon:Users,        desc:'Verify every user/service identity; never trust implicit context' },
  network:     { name:'Network',      color:'#1565C0', Icon:Globe,        desc:'Micro-segment; deny by default; verify every network flow' },
  data:        { name:'Data',         color:'#00695C', Icon:HardDrive,    desc:'Classify, protect, and monitor all data regardless of location' },
  application: { name:'Application',  color:'#E65100', Icon:Zap,          desc:'Authorize each transaction with least-privilege; verify workloads' },
  monitoring:  { name:'Monitoring',   color:'#4A148C', Icon:Search,       desc:'Log, detect, and respond to all activity continuously' },
};

// NIST CSF 2.0 control checks (resource-presence + attribute based)
export const NIST_CSF_CHECKS = [
  // Govern
  { id:'GV.OC-01', fn:'Govern',   cat:'Org Context',      critical:false, desc:'Org account structure (AWS Organizations)',     check:(rs)=>rs.some(r=>r.type.startsWith('aws_organizations')) },
  { id:'GV.RR-01', fn:'Govern',   cat:'Roles & Resp',     critical:true,  desc:'Permission boundaries on IAM roles',            check:(rs)=>rs.some(r=>r.type==='aws_iam_role'&&r.body&&r.body.includes('permissions_boundary')) },
  // Identify
  { id:'ID.AM-01', fn:'Identify', cat:'Asset Mgmt',       critical:true,  desc:'AWS Config for asset inventory',                check:(rs)=>rs.some(r=>r.type==='aws_config_configuration_recorder') },
  { id:'ID.RA-01', fn:'Identify', cat:'Risk Assessment',  critical:true,  desc:'GuardDuty for continuous risk detection',       check:(rs)=>rs.some(r=>r.type==='aws_guardduty_detector') },
  { id:'ID.RA-02', fn:'Identify', cat:'Risk Assessment',  critical:false, desc:'IAM Access Analyzer for external access',       check:(rs)=>rs.some(r=>r.type==='aws_accessanalyzer_analyzer') },
  // Protect
  { id:'PR.AC-01', fn:'Protect',  cat:'Identity Mgmt',    critical:true,  desc:'Federated identity (OIDC/SAML/SSO)',            check:(rs)=>rs.some(r=>['aws_iam_openid_connect_provider','aws_iam_saml_provider'].includes(r.type)||r.type.startsWith('aws_ssoadmin')) },
  { id:'PR.AC-02', fn:'Protect',  cat:'Identity Mgmt',    critical:true,  desc:'No static IAM users (role-based only)',         check:(rs)=>!rs.some(r=>r.type==='aws_iam_user') },
  { id:'PR.AC-03', fn:'Protect',  cat:'Remote Access',    critical:true,  desc:'EC2 IMDSv2 enforced (prevents SSRF→cred theft)',check:(rs)=>!rs.some(r=>r.type==='aws_instance')||rs.filter(r=>r.type==='aws_instance').every(r=>r.body&&r.body.includes('http_tokens')&&r.body.includes('required')) },
  { id:'PR.AC-04', fn:'Protect',  cat:'Access Perms',     critical:false, desc:'SCPs at org level guardrails',                  check:(rs)=>rs.some(r=>r.type==='aws_organizations_policy') },
  { id:'PR.DS-01', fn:'Protect',  cat:'Data at Rest',     critical:true,  desc:'KMS CMK for data encryption',                   check:(rs)=>rs.some(r=>r.type==='aws_kms_key') },
  { id:'PR.DS-02', fn:'Protect',  cat:'Data in Transit',  critical:true,  desc:'HTTPS/TLS enforced on public endpoints',        check:(rs)=>rs.some(r=>r.type==='aws_lb_listener'&&r.body&&r.body.includes('HTTPS'))||rs.some(r=>r.type==='aws_cloudfront_distribution') },
  { id:'PR.DS-05', fn:'Protect',  cat:'Data Protection',  critical:false, desc:'Secrets Manager for credential storage',        check:(rs)=>rs.some(r=>r.type==='aws_secretsmanager_secret') },
  { id:'PR.IP-01', fn:'Protect',  cat:'Baseline Config',  critical:false, desc:'AWS Config rules enforcing secure baseline',    check:(rs)=>rs.some(r=>r.type==='aws_config_rule') },
  { id:'PR.PT-01', fn:'Protect',  cat:'Protective Tech',  critical:true,  desc:'WAF protecting internet-facing applications',   check:(rs)=>rs.some(r=>['aws_wafv2_web_acl','aws_waf_web_acl'].includes(r.type)) },
  { id:'PR.PT-03', fn:'Protect',  cat:'Network Integrity', critical:false, desc:'VPC Endpoints for private AWS service access',  check:(rs)=>rs.some(r=>r.type==='aws_vpc_endpoint') },
  // Detect
  { id:'DE.AE-01', fn:'Detect',   cat:'Anomaly Detection',critical:false, desc:'CloudWatch alarms for security events',         check:(rs)=>rs.some(r=>r.type==='aws_cloudwatch_metric_alarm') },
  { id:'DE.CM-01', fn:'Detect',   cat:'Monitoring',       critical:true,  desc:'CloudTrail API activity logging',               check:(rs)=>rs.some(r=>r.type==='aws_cloudtrail') },
  { id:'DE.CM-03', fn:'Detect',   cat:'Monitoring',       critical:true,  desc:'CloudTrail multi-region coverage',              check:(rs)=>rs.some(r=>r.type==='aws_cloudtrail'&&r.body&&r.body.includes('is_multi_region_trail')&&r.body.includes('true')) },
  { id:'DE.CM-06', fn:'Detect',   cat:'Threat Detection', critical:true,  desc:'GuardDuty ML-based anomaly detection',          check:(rs)=>rs.some(r=>r.type==='aws_guardduty_detector') },
  { id:'DE.CM-07', fn:'Detect',   cat:'Threat Detection', critical:false, desc:'Security Hub centralizing findings',            check:(rs)=>rs.some(r=>r.type.startsWith('aws_securityhub')) },
  // Respond
  { id:'RS.AN-01', fn:'Respond',  cat:'Incident Analysis',critical:false, desc:'SNS for security alert notification',           check:(rs)=>rs.some(r=>r.type==='aws_sns_topic') },
  { id:'RS.RP-01', fn:'Respond',  cat:'Response Planning',critical:false, desc:'Lambda-based automated response playbooks',     check:(rs)=>rs.some(r=>r.type==='aws_lambda_function'&&r.body&&/guardduty|security|incident|remediat/i.test(r.body)) },
  // Recover
  { id:'RC.RP-01', fn:'Recover',  cat:'Recovery Planning',critical:false, desc:'AWS Backup plan configured',                    check:(rs)=>rs.some(r=>r.type.startsWith('aws_backup')) },
  { id:'RC.RP-02', fn:'Recover',  cat:'Recovery Planning',critical:true,  desc:'RDS automated backup retention configured',     check:(rs)=>!rs.some(r=>(r.type==='aws_rds_instance'||r.type==='aws_rds_cluster')&&r.body&&/backup_retention_period\s*=\s*0/.test(r.body)) },
  { id:'RC.IM-01', fn:'Recover',  cat:'Improvements',     critical:false, desc:'S3 versioning for object-level recovery',       check:(rs)=>rs.some(r=>r.type==='aws_s3_bucket'&&r.body&&/versioning[\s\S]{0,80}enabled\s*=\s*true/.test(r.body)) },
];
