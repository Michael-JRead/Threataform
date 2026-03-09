/**
 * src/lib/mcp/tools/ThreatDBTool.js
 * MITRE ATT&CK cloud/IaaS technique lookup.
 *
 * Searches a bundled dataset of cloud-relevant ATT&CK techniques by:
 *   - Exact technique ID  (T1078, T1078.004)
 *   - Keyword in name     ("credential", "S3", "IAM")
 *   - Keyword in tactics  ("initial-access", "persistence")
 *
 * Usage:
 *   lookupMitre('T1078')
 *   lookupMitre('credential access')
 *   lookupMitre('T1530')
 */

// Inline cloud-relevant ATT&CK techniques (subset focusing on IaaS/SaaS/cloud)
// Source: MITRE ATT&CK v14 Enterprise Matrix — cloud platform techniques
const MITRE_CLOUD_TTPS = [
  // ── Initial Access ─────────────────────────────────────────────────────────
  { id:'T1078',     subtechId:null,       name:'Valid Accounts',                    tactics:['initial-access','persistence','privilege-escalation','defense-evasion'], platforms:['IaaS','SaaS','Azure AD'], description:'Adversaries may obtain and abuse credentials of existing accounts to gain initial access.  In cloud environments this commonly means stolen IAM user credentials, stolen service account keys, or compromised SSO tokens.' },
  { id:'T1078',     subtechId:'T1078.004',name:'Valid Accounts: Cloud Accounts',    tactics:['initial-access','persistence','privilege-escalation','defense-evasion'], platforms:['IaaS','SaaS','Azure AD'], description:'Adversaries may obtain and abuse credentials of cloud accounts — IAM users, service accounts, OAuth tokens — to authenticate as a legitimate user and bypass controls.' },
  { id:'T1190',     subtechId:null,       name:'Exploit Public-Facing Application', tactics:['initial-access'], platforms:['IaaS','Linux','Windows'], description:'Adversaries may attempt to exploit a weakness in an internet-facing host or system to gain a foothold.' },
  { id:'T1566',     subtechId:'T1566.002',name:'Phishing: Spearphishing Link',      tactics:['initial-access'], platforms:['IaaS','SaaS','Office365'], description:'Spearphishing link to capture cloud service credentials.' },
  // ── Execution ──────────────────────────────────────────────────────────────
  { id:'T1651',     subtechId:null,       name:'Cloud Administration Command',      tactics:['execution'], platforms:['IaaS'], description:'Adversaries may abuse cloud management services (SSM Run Command, Azure Run Command) to execute commands on cloud-hosted instances.' },
  { id:'T1059',     subtechId:'T1059.009',name:'Command and Scripting: Cloud API',  tactics:['execution'], platforms:['IaaS','SaaS'], description:'Adversaries may abuse cloud APIs directly via CLIs (aws, az, gcloud) to execute commands and interact with cloud services.' },
  // ── Persistence ────────────────────────────────────────────────────────────
  { id:'T1098',     subtechId:null,       name:'Account Manipulation',              tactics:['persistence'], platforms:['IaaS','SaaS','Azure AD'], description:'Adversaries may manipulate accounts to maintain access. In cloud: adding MFA devices to stolen accounts, creating IAM users or access keys.' },
  { id:'T1098',     subtechId:'T1098.001',name:'Account Manipulation: Additional Cloud Credentials', tactics:['persistence'], platforms:['IaaS'], description:'Adding a new access key pair, service account key, or OAuth credential to maintain persistent access.' },
  { id:'T1136',     subtechId:'T1136.003',name:'Create Account: Cloud Account',     tactics:['persistence'], platforms:['IaaS','SaaS'], description:'Adversaries may create a cloud account to maintain access — new IAM users, service principals, SaaS app accounts.' },
  { id:'T1525',     subtechId:null,       name:'Implant Internal Image',            tactics:['persistence'], platforms:['IaaS'], description:'Adversaries may implant cloud or container images with malicious code to establish a persistent foothold in cloud environments.' },
  { id:'T1546',     subtechId:'T1546.016',name:'Event Triggered Execution: Install Root Certificate', tactics:['persistence'], platforms:['IaaS'], description:'Adversaries may install a root certificate into a cloud-hosted machine to intercept TLS traffic.' },
  // ── Privilege Escalation ───────────────────────────────────────────────────
  { id:'T1548',     subtechId:null,       name:'Abuse Elevation Control Mechanism', tactics:['privilege-escalation','defense-evasion'], platforms:['IaaS','Linux'], description:'Adversaries may bypass permission boundaries by assuming roles, creating policies, or exploiting misconfigurations like iam:PassRole.' },
  { id:'T1078',     subtechId:'T1078.004',name:'Valid Accounts: Cloud Accounts',    tactics:['privilege-escalation'], platforms:['IaaS'], description:'Using stolen cloud credentials with high-privilege access for lateral movement and escalation.' },
  // ── Defense Evasion ────────────────────────────────────────────────────────
  { id:'T1578',     subtechId:null,       name:'Modify Cloud Compute Infrastructure', tactics:['defense-evasion'], platforms:['IaaS'], description:'Adversaries may modify compute infrastructure to evade detection — creating snapshots, modifying AMIs, disabling CloudTrail.' },
  { id:'T1578',     subtechId:'T1578.001',name:'Modify Cloud Compute Infrastructure: Create Snapshot',  tactics:['defense-evasion','collection'], platforms:['IaaS'], description:'Create a snapshot of a cloud storage volume to copy data without triggering data-exfiltration alerts.' },
  { id:'T1562',     subtechId:'T1562.008',name:'Impair Defenses: Disable Cloud Logs', tactics:['defense-evasion'], platforms:['IaaS'], description:'Adversaries may disable CloudTrail, VPC Flow Logs, or S3 access logs to hide activity.' },
  { id:'T1535',     subtechId:null,       name:'Unused/Unsupported Cloud Regions',   tactics:['defense-evasion'], platforms:['IaaS'], description:'Adversaries may create resources in an unused cloud region to evade detection and monitoring.' },
  // ── Credential Access ──────────────────────────────────────────────────────
  { id:'T1552',     subtechId:null,       name:'Unsecured Credentials',              tactics:['credential-access'], platforms:['IaaS','SaaS'], description:'Adversaries may search for unsecured credentials — environment variables, EC2 metadata IMDS, S3 objects, CloudFormation outputs.' },
  { id:'T1552',     subtechId:'T1552.005',name:'Unsecured Credentials: Cloud Instance Metadata API', tactics:['credential-access'], platforms:['IaaS'], description:'IMDS endpoint (169.254.169.254) may return IAM role credentials. Without IMDSv2 enforcement, SSRF attacks can steal these.' },
  { id:'T1528',     subtechId:null,       name:'Steal Application Access Token',     tactics:['credential-access'], platforms:['SaaS','IaaS'], description:'Adversaries may steal application access tokens to acquire the permissions of that application.' },
  // ── Discovery ──────────────────────────────────────────────────────────────
  { id:'T1526',     subtechId:null,       name:'Cloud Service Discovery',            tactics:['discovery'], platforms:['IaaS','SaaS'], description:'Adversaries may use cloud APIs to enumerate services, resources, and configurations.' },
  { id:'T1580',     subtechId:null,       name:'Cloud Infrastructure Discovery',     tactics:['discovery'], platforms:['IaaS'], description:'Adversaries may attempt to discover EC2 instances, S3 buckets, RDS databases, Lambda functions, IAM roles, and other resources.' },
  { id:'T1619',     subtechId:null,       name:'Cloud Storage Object Discovery',     tactics:['discovery'], platforms:['IaaS','SaaS'], description:'Adversaries may enumerate objects in cloud storage (S3 buckets, Azure Blob containers) to identify sensitive data.' },
  // ── Lateral Movement ──────────────────────────────────────────────────────
  { id:'T1550',     subtechId:'T1550.001',name:'Use Alternate Authentication Material: Application Access Token', tactics:['lateral-movement','defense-evasion'], platforms:['SaaS','IaaS'], description:'Adversaries use OAuth tokens, STS temporary credentials, or service account keys to move laterally.' },
  { id:'T1021',     subtechId:'T1021.007',name:'Remote Services: Cloud Services',    tactics:['lateral-movement'], platforms:['IaaS','SaaS'], description:'Log into cloud services using valid credentials obtained elsewhere.' },
  // ── Collection ────────────────────────────────────────────────────────────
  { id:'T1530',     subtechId:null,       name:'Data from Cloud Storage',            tactics:['collection'], platforms:['IaaS','SaaS'], description:'Adversaries may access data in cloud storage (S3, Azure Blob, GCS). Public ACLs or misconfigured bucket policies allow unauthenticated access.' },
  { id:'T1537',     subtechId:null,       name:'Transfer Data to Cloud Account',     tactics:['exfiltration'], platforms:['IaaS'], description:'Adversaries may exfiltrate data by transferring it to another cloud account they control (S3 cross-account copy, EBS snapshot sharing).' },
  { id:'T1602',     subtechId:null,       name:'Data from Configuration Repository', tactics:['collection'], platforms:['IaaS'], description:'Adversaries may collect data stored in configuration repositories — Secrets Manager, Parameter Store, environment variables, user data scripts.' },
  // ── Exfiltration ──────────────────────────────────────────────────────────
  { id:'T1567',     subtechId:'T1567.002',name:'Exfiltration Over Web Service: Exfiltration to Cloud Storage', tactics:['exfiltration'], platforms:['IaaS','Linux','Windows'], description:'Adversaries may exfiltrate data to external cloud storage (attacker-controlled S3 buckets, Dropbox).' },
  // ── Impact ────────────────────────────────────────────────────────────────
  { id:'T1485',     subtechId:null,       name:'Data Destruction',                   tactics:['impact'], platforms:['IaaS','SaaS'], description:'Adversaries may destroy data in cloud storage — delete S3 objects, terminate RDS instances, delete EBS volumes.' },
  { id:'T1496',     subtechId:null,       name:'Resource Hijacking',                 tactics:['impact'], platforms:['IaaS'], description:'Adversaries may leverage cloud resources for crypto-mining or other resource-intensive workloads.' },
  { id:'T1490',     subtechId:null,       name:'Inhibit System Recovery',            tactics:['impact'], platforms:['IaaS'], description:'Adversaries may delete backups, snapshots, or RDS automated backups to prevent recovery.' },
];

// Build lookup indexes
const _byId   = new Map();
const _byName = [];

for (const t of MITRE_CLOUD_TTPS) {
  const key = t.subtechId ?? t.id;
  if (!_byId.has(key)) _byId.set(key, []);
  _byId.get(key).push(t);
  _byName.push({ ...t, _searchText: `${t.id} ${t.subtechId ?? ''} ${t.name} ${t.tactics.join(' ')} ${t.description}`.toLowerCase() });
}

/**
 * Look up MITRE ATT&CK technique(s) by ID or keyword.
 *
 * @param {string} query  Technique ID (T1078, T1078.004) or keyword
 * @returns {object}  { results: TechniqueEntry[], query }
 */
export function lookupMitre(query) {
  if (!query) return { error: 'query is required', results: [] };

  const q = query.trim();

  // Exact ID match (case-insensitive)
  const idMatch = _byId.get(q.toUpperCase());
  if (idMatch?.length) {
    return {
      query: q,
      results: idMatch.map(_format),
      source: 'mitre-attack-v14-cloud',
    };
  }

  // Keyword search
  const ql = q.toLowerCase().split(/\s+/).filter(w => w.length > 2);
  const scored = _byName
    .map(t => ({ t, hits: ql.filter(w => t._searchText.includes(w)).length }))
    .filter(x => x.hits > 0)
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 5);

  if (!scored.length) {
    return { query: q, results: [], message: `No techniques found matching "${q}". Try an ID like T1078 or a keyword like "credential" or "S3".` };
  }

  return {
    query: q,
    results: scored.map(x => _format(x.t)),
    source: 'mitre-attack-v14-cloud',
  };
}

function _format(t) {
  return {
    id:          t.subtechId ?? t.id,
    parentId:    t.subtechId ? t.id : null,
    name:        t.name,
    tactics:     t.tactics,
    platforms:   t.platforms,
    description: t.description,
    url:         `https://attack.mitre.org/techniques/${(t.subtechId ?? t.id).replace('.', '/')}`,
    mitigations: _mitigations(t.subtechId ?? t.id),
  };
}

/** Common mitigations for cloud techniques */
function _mitigations(id) {
  const M = {
    'T1078':     ['Enforce MFA on all IAM users', 'Enable AWS CloudTrail and alert on unusual API calls', 'Apply least-privilege IAM policies', 'Regularly rotate access keys'],
    'T1078.004': ['Enforce MFA on all IAM users', 'Use temporary STS credentials instead of long-term keys', 'Monitor CloudTrail for ConsoleLogin from unusual IPs'],
    'T1190':     ['Apply WAF with OWASP ruleset', 'Patch regularly', 'Restrict public-facing attack surface', 'Enable AWS Shield'],
    'T1552':     ['Enable IMDSv2 (http_tokens = required) on all EC2 instances', 'Do not store credentials in environment variables or user data', 'Rotate secrets regularly via Secrets Manager'],
    'T1552.005': ['Enforce IMDSv2 on all EC2 instances (aws_instance metadata_options.http_tokens = "required")', 'Apply hop-limit = 1 to prevent SSRF from reaching IMDS'],
    'T1530':     ['Enable S3 Block Public Access', 'Apply bucket policies with explicit Deny for unauthorized principals', 'Enable S3 server-side encryption'],
    'T1537':     ['Use S3 bucket policies to deny cross-account PutObject unless explicitly allowed', 'Monitor CloudTrail for unusual S3 cross-account copy operations'],
    'T1562.008': ['Deny cloudtrail:DeleteTrail and cloudtrail:StopLogging via SCP', 'Enable CloudTrail log file validation', 'Use multi-region trails'],
    'T1580':     ['Restrict ec2:DescribeInstances and similar Describe* actions to trusted principals', 'Enable CloudTrail and alert on bulk Describe API calls'],
  };
  return M[id] ?? ['Follow principle of least privilege', 'Enable CloudTrail logging', 'Apply SCPs to restrict sensitive API calls'];
}
