/**
 * src/lib/mcp/tools/ComplianceChecker.js
 * AWS resource configuration compliance checker.
 * Evaluates resource attributes against HIPAA, PCI DSS 3.2.1, SOC 2, and FedRAMP controls.
 *
 * Usage:
 *   checkCompliance('HIPAA', 'aws_s3_bucket', { versioning: { enabled: true }, ... })
 *   checkCompliance('PCI', 'aws_rds_instance', { storage_encrypted: true, ... })
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Control matrices per framework and resource type
//  Each entry: { control, description, check(attrs) → bool, remediation }
// ─────────────────────────────────────────────────────────────────────────────

const CONTROL_MATRICES = {

  HIPAA: {
    'aws_s3_bucket': [
      { control: 'HIPAA §164.312(a)(2)(iv)', description: 'S3 bucket encryption at rest',       check: a => !!a.server_side_encryption_configuration, remediation: 'Add server_side_encryption_configuration with AES256 or aws:kms' },
      { control: 'HIPAA §164.312(e)(2)(ii)', description: 'S3 bucket versioning (integrity)',    check: a => a.versioning?.enabled === true,            remediation: 'Enable versioning: versioning { enabled = true }' },
      { control: 'HIPAA §164.312(a)(1)',      description: 'S3 public access blocked',           check: _s3PublicBlocked,                               remediation: 'Add aws_s3_bucket_public_access_block with all fields true' },
      { control: 'HIPAA §164.312(b)',         description: 'S3 access logging enabled',          check: a => !!a.logging,                               remediation: 'Add logging { target_bucket = "..." }' },
    ],
    'aws_rds_instance': [
      { control: 'HIPAA §164.312(a)(2)(iv)', description: 'RDS storage encrypted',              check: a => a.storage_encrypted === true,              remediation: 'Set storage_encrypted = true' },
      { control: 'HIPAA §164.312(e)(2)(i)',  description: 'RDS automated backups retained ≥7d', check: a => (a.backup_retention_period ?? 0) >= 7,     remediation: 'Set backup_retention_period = 7 (minimum for HIPAA)' },
      { control: 'HIPAA §164.312(b)',         description: 'RDS enhanced monitoring',            check: a => (a.monitoring_interval ?? 0) > 0,          remediation: 'Set monitoring_interval = 60 and monitoring_role_arn' },
      { control: 'HIPAA §164.312(e)(1)',      description: 'RDS not publicly accessible',        check: a => a.publicly_accessible === false,            remediation: 'Set publicly_accessible = false' },
    ],
    'aws_instance': [
      { control: 'HIPAA §164.312(a)(2)(iv)', description: 'EC2 IMDSv2 enforced',               check: a => a.metadata_options?.http_tokens === 'required', remediation: 'Add metadata_options { http_tokens = "required" }' },
      { control: 'HIPAA §164.312(a)(2)(iv)', description: 'EC2 root volume encrypted',         check: a => a.root_block_device?.encrypted === true,        remediation: 'Set root_block_device { encrypted = true }' },
    ],
    'aws_iam_role': [
      { control: 'HIPAA §164.312(a)(1)',     description: 'IAM permission boundary set',       check: a => !!a.permissions_boundary,                  remediation: 'Add permissions_boundary = aws_iam_policy.boundary.arn' },
    ],
    'aws_cloudtrail': [
      { control: 'HIPAA §164.312(b)',        description: 'CloudTrail log file validation',    check: a => a.enable_log_file_validation === true,     remediation: 'Set enable_log_file_validation = true' },
      { control: 'HIPAA §164.312(b)',        description: 'CloudTrail multi-region',           check: a => a.is_multi_region_trail === true,           remediation: 'Set is_multi_region_trail = true' },
    ],
  },

  PCI: {
    'aws_s3_bucket': [
      { control: 'PCI DSS Req 3.4',         description: 'S3 bucket encryption at rest',       check: a => !!a.server_side_encryption_configuration, remediation: 'Add server_side_encryption_configuration with aws:kms' },
      { control: 'PCI DSS Req 2.2',         description: 'S3 public access blocked',           check: _s3PublicBlocked,                               remediation: 'Block all public access via aws_s3_bucket_public_access_block' },
      { control: 'PCI DSS Req 10.5',        description: 'S3 versioning for log integrity',    check: a => a.versioning?.enabled === true,            remediation: 'Enable versioning { enabled = true }' },
    ],
    'aws_rds_instance': [
      { control: 'PCI DSS Req 3.4',         description: 'RDS storage encrypted',              check: a => a.storage_encrypted === true,              remediation: 'Set storage_encrypted = true' },
      { control: 'PCI DSS Req 6.4.1',       description: 'RDS not publicly accessible',        check: a => a.publicly_accessible === false,            remediation: 'Set publicly_accessible = false' },
      { control: 'PCI DSS Req 10.7',        description: 'RDS backup retention ≥1 year',       check: a => (a.backup_retention_period ?? 0) >= 35,    remediation: 'Set backup_retention_period = 35 (PCI requires 1 year, use additional backup solution for full year)' },
    ],
    'aws_instance': [
      { control: 'PCI DSS Req 6.3',         description: 'EC2 IMDSv2 enforced (SSRF protection)', check: a => a.metadata_options?.http_tokens === 'required', remediation: 'Add metadata_options { http_tokens = "required" }' },
      { control: 'PCI DSS Req 3.4',         description: 'EC2 root volume encrypted',          check: a => a.root_block_device?.encrypted === true,   remediation: 'Set root_block_device { encrypted = true }' },
    ],
    'aws_security_group': [
      { control: 'PCI DSS Req 1.2.1',       description: 'No inbound 0.0.0.0/0 on port 22',   check: a => !_sgHasOpenPort(a, 22),                   remediation: 'Restrict SSH (port 22) to specific IP ranges' },
      { control: 'PCI DSS Req 1.2.1',       description: 'No inbound 0.0.0.0/0 on port 3389',  check: a => !_sgHasOpenPort(a, 3389),                  remediation: 'Restrict RDP (port 3389) to specific IP ranges' },
    ],
    'aws_cloudtrail': [
      { control: 'PCI DSS Req 10.5',        description: 'CloudTrail log file validation',     check: a => a.enable_log_file_validation === true,     remediation: 'Set enable_log_file_validation = true' },
      { control: 'PCI DSS Req 10.1',        description: 'CloudTrail multi-region',            check: a => a.is_multi_region_trail === true,           remediation: 'Set is_multi_region_trail = true' },
    ],
  },

  SOC2: {
    'aws_s3_bucket': [
      { control: 'CC6.1',                   description: 'S3 bucket encryption (confidentiality)', check: a => !!a.server_side_encryption_configuration, remediation: 'Add server_side_encryption_configuration' },
      { control: 'CC6.1',                   description: 'S3 public access blocked',           check: _s3PublicBlocked,                               remediation: 'Add aws_s3_bucket_public_access_block' },
      { control: 'CC7.2',                   description: 'S3 access logging (detection)',       check: a => !!a.logging,                               remediation: 'Add logging { target_bucket = "..." }' },
    ],
    'aws_rds_instance': [
      { control: 'CC6.1',                   description: 'RDS encrypted at rest',              check: a => a.storage_encrypted === true,              remediation: 'Set storage_encrypted = true' },
      { control: 'CC6.6',                   description: 'RDS not publicly accessible',         check: a => a.publicly_accessible === false,            remediation: 'Set publicly_accessible = false' },
      { control: 'A1.2',                    description: 'RDS Multi-AZ for availability',       check: a => a.multi_az === true,                       remediation: 'Set multi_az = true' },
    ],
    'aws_cloudtrail': [
      { control: 'CC7.2',                   description: 'CloudTrail enabled for audit',        check: a => a.enable_logging !== false,                remediation: 'Ensure CloudTrail is not explicitly disabled' },
      { control: 'CC7.2',                   description: 'Log file validation',                 check: a => a.enable_log_file_validation === true,     remediation: 'Set enable_log_file_validation = true' },
    ],
    'aws_instance': [
      { control: 'CC6.1',                   description: 'EC2 IMDSv2 enforced',                check: a => a.metadata_options?.http_tokens === 'required', remediation: 'Enforce IMDSv2: metadata_options { http_tokens = "required" }' },
    ],
  },

  FedRAMP: {
    'aws_s3_bucket': [
      { control: 'SC-28',                   description: 'S3 encryption at rest (FIPS)',        check: a => _hasFipsEncryption(a),                    remediation: 'Use aws:kms encryption with a FIPS-approved KMS key' },
      { control: 'AC-3',                    description: 'S3 public access blocked',            check: _s3PublicBlocked,                               remediation: 'Add aws_s3_bucket_public_access_block' },
      { control: 'AU-9',                    description: 'S3 versioning (audit protection)',     check: a => a.versioning?.enabled === true,            remediation: 'Enable versioning { enabled = true }' },
      { control: 'AU-3',                    description: 'S3 access logging',                   check: a => !!a.logging,                               remediation: 'Add logging { target_bucket = "..." }' },
    ],
    'aws_instance': [
      { control: 'SC-8',                    description: 'EC2 IMDSv2 enforced',                check: a => a.metadata_options?.http_tokens === 'required', remediation: 'Set metadata_options { http_tokens = "required" }' },
      { control: 'SC-28',                   description: 'EC2 root volume encrypted (FIPS)',    check: a => a.root_block_device?.encrypted === true,   remediation: 'Set root_block_device { encrypted = true }' },
    ],
    'aws_rds_instance': [
      { control: 'SC-28',                   description: 'RDS FIPS-compliant encryption',       check: a => a.storage_encrypted === true,              remediation: 'Set storage_encrypted = true; use KMS key in GovCloud' },
      { control: 'CP-9',                    description: 'RDS backup retention ≥90d',           check: a => (a.backup_retention_period ?? 0) >= 90,    remediation: 'Set backup_retention_period >= 90 (FedRAMP Moderate/High)' },
    ],
    'aws_cloudtrail': [
      { control: 'AU-2',                    description: 'CloudTrail multi-region logging',     check: a => a.is_multi_region_trail === true,           remediation: 'Set is_multi_region_trail = true' },
      { control: 'AU-9',                    description: 'CloudTrail log integrity validation', check: a => a.enable_log_file_validation === true,     remediation: 'Set enable_log_file_validation = true' },
    ],
  },
};

// ── Helper checks ────────────────────────────────────────────────────────────

function _s3PublicBlocked(attrs) {
  return attrs.block_public_acls === true
    && attrs.block_public_policy === true
    && attrs.ignore_public_acls === true
    && attrs.restrict_public_buckets === true;
}

function _hasFipsEncryption(attrs) {
  const sse = attrs.server_side_encryption_configuration;
  if (!sse) return false;
  // Accept both nested object and boolean (parseHCLBody presence indicator)
  if (sse === true) return true;
  const rule = sse.rule ?? sse;
  return !!(rule?.apply_server_side_encryption_by_default?.sse_algorithm === 'aws:kms'
    || rule?.sse_algorithm === 'aws:kms');
}

function _sgHasOpenPort(attrs, port) {
  const rules = [
    ...(Array.isArray(attrs.ingress) ? attrs.ingress : attrs.ingress ? [attrs.ingress] : []),
  ];
  return rules.some(r => {
    const cidrOpen = (r.cidr_blocks?.includes?.('0.0.0.0/0') || r.cidr_blocks === '0.0.0.0/0')
      || (r.ipv6_cidr_blocks?.includes?.('::/0') || r.ipv6_cidr_blocks === '::/0');
    if (!cidrOpen) return false;
    const from = r.from_port ?? 0;
    const to   = r.to_port   ?? 65535;
    return port >= from && port <= to;
  });
}

// ── Public API ───────────────────────────────────────────────────────────────

const FRAMEWORK_ALIASES = {
  HIPAA: 'HIPAA', HITECH: 'HIPAA',
  PCI: 'PCI', 'PCI-DSS': 'PCI', 'PCI DSS': 'PCI',
  SOC2: 'SOC2', 'SOC 2': 'SOC2', 'SOC-2': 'SOC2',
  FEDRAMP: 'FedRAMP', 'FedRAMP': 'FedRAMP', 'FEDRAMP MODERATE': 'FedRAMP',
};

/**
 * Check AWS resource configuration against a compliance framework.
 *
 * @param {string} framework     'HIPAA' | 'PCI' | 'SOC2' | 'FedRAMP'
 * @param {string} resource_type e.g. 'aws_s3_bucket', 'aws_rds_instance'
 * @param {object} attrs         Parsed HCL attributes (from parseHCLBody or cfnProps)
 * @returns {{ framework, resource_type, score, met, gaps, total }}
 */
export function checkCompliance(framework, resource_type, attrs = {}) {
  const fw = FRAMEWORK_ALIASES[(framework || '').toUpperCase()] ?? framework;
  const matrix = CONTROL_MATRICES[fw];

  if (!matrix) {
    const supported = Object.keys(CONTROL_MATRICES).join(', ');
    return { error: `Unknown framework "${framework}". Supported: ${supported}` };
  }

  const checks = matrix[resource_type];
  if (!checks) {
    const supportedTypes = Object.keys(matrix).join(', ');
    return {
      framework: fw,
      resource_type,
      score: null,
      message: `No ${fw} controls defined for "${resource_type}". Supported resource types: ${supportedTypes}`,
      met: [], gaps: [], total: 0,
    };
  }

  const met  = [];
  const gaps = [];

  for (const ctrl of checks) {
    let passed = false;
    try { passed = !!ctrl.check(attrs); } catch { /* treat as failed */ }
    if (passed) {
      met.push({ control: ctrl.control, description: ctrl.description });
    } else {
      gaps.push({ control: ctrl.control, description: ctrl.description, remediation: ctrl.remediation });
    }
  }

  const total = checks.length;
  const score = total > 0 ? Math.round((met.length / total) * 100) : 100;

  return {
    framework:     fw,
    resource_type,
    score,
    total,
    met_count:     met.length,
    gap_count:     gaps.length,
    met,
    gaps,
    summary:       score === 100
      ? `✓ ${resource_type} meets all ${total} ${fw} controls`
      : `${gaps.length} of ${total} ${fw} controls failing on ${resource_type} (score: ${score}%)`,
  };
}
