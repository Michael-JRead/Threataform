// src/data/architecture-layers.js
// Enterprise Terraform 7-Layer Architecture Model — static data for ArchitectureAnalyzer.
// Layer definitions, factory components, IAM modules, Sentinel policies, product indicators,
// naming conventions, abbreviation maps, and file patterns.

// ── 7-Layer Architecture Model ──────────────────────────────────────────────────────────────────
// Each layer represents a distinct architectural concern in the enterprise AWS platform stack.
// Layers 1-7 progress from foundational governance down to application-level resources.

export const TERRAFORM_LAYERS = {
  1: {
    name: 'Foundation Layer',
    modules: ['enterprise-aws-bootstrap'],
    description: 'AWS Organization, OUs, SCPs, baseline governance automation',
    technologies: ['Python', 'Automation Engine', 'Jinja2', 'Boto3', 'Jenkins', 'CloudFormation Guard'],
    apis: ['AWS Organizations API', 'IAM API', 'CloudFormation API', 'Config API'],
    files: ['enterprise-aws-bootstrap.yaml', 'ou-tree.yaml', 'ou-linker.yaml', 'templates/scp/*.yaml', 'templates/rcp/*.yaml', 'Jenkinsfile'],
    expectedConcerns: ['org bootstrap', 'OU tree', 'OU linkers', 'SCP templates', 'RCP templates', 'baseline governance automation', 'bootstrap scripts', 'CI/CD pipelines for org'],
  },
  2: {
    name: 'Platform Factory Layer',
    modules: ['portfolio-boundary-factory', 'network-boundary-factory', 'base-account-factory', 'workload-boundary-factory'],
    description: 'Kubernetes operators for automated resource provisioning at platform scale',
    technologies: ['Kubernetes', 'CRD', 'IRSA', 'Terraform Enterprise', 'Helm', 'Go Operators'],
    apis: ['Kubernetes API', 'EKS API', 'Organizations API', 'Control Tower API'],
    files: ['*-factory/**', 'crds/*.yaml', '*-operator.yaml', '*-rbac.yaml', 'serviceaccount*.yaml'],
    expectedConcerns: ['operator-driven provisioning', 'CRD definitions', 'service accounts', 'IAM roles for operators (IRSA)', 'boundary creation', 'account vending', 'orchestration control plane'],
  },
  3: {
    name: 'IAM Management Layer',
    modules: ['module-role', 'module-role-policy-updater', 'module-iam-policy', 'role-distribution-factory'],
    description: 'Centralized IAM asset lifecycle management — role creation, policy authoring, distribution',
    technologies: ['Terraform', 'HCL', 'SDLC', 'RBAC', 'AWS IAM'],
    apis: ['IAM API', 'STS API', 'Organizations API'],
    files: ['module-role/**', 'module-iam*/**', 'role-distribution*/**', '*.tf (aws_iam_*)'],
    expectedConcerns: ['role creation', 'policy authoring', 'policy updates', 'trust relationships', 'role distribution', 'cross-account role assumptions', 'least privilege enforcement'],
  },
  4: {
    name: 'Network Boundary Layer',
    modules: ['network-boundary-*', 'vpc-*', 'security-group-*', 'transit-gateway-*'],
    description: 'Network isolation and connectivity management',
    technologies: ['Terraform', 'AWS VPC', 'Transit Gateway', 'RAM', 'Route 53'],
    apis: ['EC2 Network API', 'TGW API', 'RAM API', 'Route 53 API'],
    files: ['vpc*.tf', 'sg*.tf', 'tgw*.tf', 'network-boundary*/**', 'subnets*.tf', 'route-table*.tf'],
    expectedConcerns: ['VPCs', 'subnets', 'route tables', 'security groups', 'transit gateways', 'VPC peering', 'PrivateLink endpoints', 'network isolation', 'micro-segmentation'],
  },
  5: {
    name: 'Security Controls Layer',
    modules: ['sentinel-policies', 'platform-global-*', 'aws-res-iam-role-policy'],
    description: 'Policy-as-code enforcement, governance rules, compliance validation',
    technologies: ['HashiCorp Sentinel', 'Policy-as-Code', 'Terraform Enterprise', 'OPA'],
    apis: ['Terraform Enterprise API', 'Organizations Policy API'],
    files: ['*.sentinel', 'sentinel/**', 'policies/**', 'platform-global*/**'],
    expectedConcerns: ['policy validation', 'governance rules', 'global platform controls', 'tagging enforcement', 'naming rules', 'compliance rules', 'resource lifecycle constraints', 'cost controls'],
  },
  6: {
    name: 'Product Module Layer',
    modules: ['module-msk-connect', 'module-kendra', 'module-opensearch-*', 'module-elasticache', 'module-rds'],
    description: 'Service-specific implementations — AWS managed services, data/messaging/search/cache/database',
    technologies: ['Terraform', 'HCL', 'AWS Services'],
    apis: ['Service-specific AWS APIs'],
    files: ['module-*/**', 'modules/**', 'service-*.tf'],
    expectedConcerns: ['service-specific modules', 'integration modules', 'product/business service modules', 'AWS managed services', 'data platforms', 'messaging platforms', 'search platforms', 'cache layers', 'database tiers'],
  },
  7: {
    name: 'Application Layer',
    modules: ['application-*', 'workload-*', 'custom-modules'],
    description: 'Application-specific resources, workload configurations, custom infra',
    technologies: ['Terraform', 'Application Code', 'CI/CD'],
    apis: ['Application-specific APIs'],
    files: ['application*/**', 'workload*/**', 'app*.tf', 'custom-*.tf'],
    expectedConcerns: ['application resources', 'workload-specific modules', 'custom infra', 'app-level configuration', 'service-specific overrides'],
  },
};

// ── Factory Components (Layer 2) ─────────────────────────────────────────────────────────────────
// Kubernetes operators that provision platform resources via CRDs and IRSA.

export const FACTORY_COMPONENTS = {
  'portfolio-boundary-factory': {
    purpose: 'Manages AWS organizational portfolio boundaries, OUs, and policy scopes',
    crds: ['BoundaryResource', 'BoundaryAccount', 'PortfolioBoundary'],
    serviceAccount: 'portfolio-boundary-sa',
    iamRole: 'controlplane-portfolio-boundary',
    apis: ['Organizations API', 'Control Tower API', 'Platform Services API'],
    dependencies: ['enterprise-aws-bootstrap'],
    security: ['RBAC', 'IRSA', 'SCP enforcement', 'OU-based boundaries'],
    detectionSignals: ['portfolio-boundary', 'portfolio_boundary', 'PortfolioBoundary', 'pbf'],
  },
  'network-boundary-factory': {
    purpose: 'Provisions network boundaries — VPCs, TGW, PrivateLink, micro-segmentation',
    crds: ['NetworkBoundary', 'VPCBoundary', 'NetworkSegment'],
    serviceAccount: 'network-boundary-sa',
    iamRole: 'controlplane-network-boundary',
    apis: ['EC2 Network API', 'TGW API', 'RAM API', 'Route 53 API'],
    dependencies: ['enterprise-aws-bootstrap', 'portfolio-boundary-factory'],
    security: ['RBAC', 'IRSA', 'default-deny SGs', 'VPC isolation', 'private subnets'],
    detectionSignals: ['network-boundary', 'network_boundary', 'NetworkBoundary', 'nbf', 'netboundary'],
  },
  'base-account-factory': {
    purpose: 'Vends new AWS accounts with baseline security config and governance controls',
    crds: ['AccountFactory', 'BaselineAccount', 'AccountVending'],
    serviceAccount: 'base-account-sa',
    iamRole: 'controlplane-base-account',
    apis: ['Organizations API', 'Control Tower API', 'SSO API'],
    dependencies: ['enterprise-aws-bootstrap', 'portfolio-boundary-factory'],
    security: ['RBAC', 'IRSA', 'account-level SCPs', 'baseline IAM', 'CloudTrail by default'],
    detectionSignals: ['base-account', 'base_account', 'BaselineAccount', 'baf', 'account-factory', 'account_factory'],
  },
  'workload-boundary-factory': {
    purpose: 'Provisions workload-specific boundaries and isolation contexts for application teams',
    crds: ['WorkloadBoundary', 'WorkloadContext', 'TeamBoundary'],
    serviceAccount: 'workload-boundary-sa',
    iamRole: 'controlplane-workload-boundary',
    apis: ['Organizations API', 'IAM API', 'EKS API'],
    dependencies: ['enterprise-aws-bootstrap', 'portfolio-boundary-factory', 'network-boundary-factory'],
    security: ['RBAC', 'IRSA', 'workload namespace isolation', 'team-scoped SCPs'],
    detectionSignals: ['workload-boundary', 'workload_boundary', 'WorkloadBoundary', 'wbf', 'workload-context'],
  },
};

// ── IAM Modules (Layer 3) ────────────────────────────────────────────────────────────────────────
// Centralized IAM lifecycle management modules.

export const IAM_MODULES = {
  'module-role': {
    purpose: 'Creates and manages IAM roles for services with configurable trust policies',
    variables: ['service_name', 'app_id', 'roles_to_assume', 'trusted_roles', 'trusted_services', 'permissions_boundary'],
    outputs: ['role_arn', 'role_name', 'instance_profile_arn'],
    crossAccount: true,
    security: ['Least Privilege', 'Trust Policies', 'Cross-Account Access', 'Permission Boundaries'],
    detectionSignals: ['module-role', 'module_role', 'iam-role-module', 'role-module'],
  },
  'module-role-policy-updater': {
    purpose: 'Lifecycle management for IAM role policies — create, update, and retire policy attachments',
    variables: ['role_name', 'policy_arns', 'inline_policies', 'managed_policy_arns'],
    outputs: ['updated_role_arn', 'policy_attachment_ids'],
    crossAccount: false,
    security: ['Policy Hygiene', 'Least Privilege', 'Policy Version Management'],
    detectionSignals: ['role-policy-updater', 'policy-updater', 'role_policy_updater', 'module-role-policy'],
  },
  'module-iam-policy': {
    purpose: 'Centralized IAM policy authoring with SDLC controls and version management',
    variables: ['policy_name', 'policy_document', 'description', 'path', 'tags'],
    outputs: ['policy_arn', 'policy_id', 'policy_name'],
    crossAccount: false,
    security: ['Policy-as-Code', 'Version Control', 'Audit Trail'],
    detectionSignals: ['module-iam-policy', 'iam_policy_module', 'iam-policy-module', 'module_iam_policy'],
  },
  'role-distribution-factory': {
    purpose: 'Distributes IAM roles across accounts and OUs at scale via factory pattern',
    variables: ['role_template', 'target_accounts', 'target_ous', 'distribution_scope'],
    outputs: ['distributed_role_arns', 'distribution_report'],
    crossAccount: true,
    security: ['Centralized RBAC', 'Cross-Account Trust', 'Boundary Enforcement', 'Audit Trail'],
    detectionSignals: ['role-distribution', 'role_distribution', 'roledist', 'rdf', 'iam-factory'],
  },
};

// ── Sentinel Policies (Layer 5) ──────────────────────────────────────────────────────────────────
// HashiCorp Sentinel policy-as-code definitions for enterprise governance.

export const SENTINEL_POLICIES = {
  'global-policies': {
    'mandatory-resource-tag.sentinel': 'Requires enterprise-app-id and environment tags on all resources',
    'provider-validation.sentinel': 'Ensures AWS provider has required region and default tags',
    'resource-retirement.sentinel': 'Prevents usage of deprecated/retired resource types',
    'naming-convention.sentinel': 'Validates resource naming follows enterprise-{type}-{env} pattern',
    'cost-control.sentinel': 'Enforces instance type allowlists and storage size limits',
    'encryption-required.sentinel': 'Mandates encryption-at-rest for all storage resources',
    'public-access-deny.sentinel': 'Prevents public S3 buckets, public RDS, open security groups',
  },
};

// Patterns found in valid Sentinel policy files
export const SENTINEL_IMPORT_PATTERNS = [
  'import "tfplan"',
  'import "tfconfig"',
  'import "tfstate"',
  'import "tfrun"',
  'main = rule',
  'main=rule',
];

// Keyword-based classification of Sentinel policy types by name/content
export const SENTINEL_POLICY_TYPES = {
  tagging:    ['tag', 'label', 'mandatory-tag', 'resource-tag'],
  naming:     ['naming', 'name-convention', 'resource-name'],
  security:   ['security', 'encryption', 'public-access', 'tls', 'ssl'],
  compliance: ['compliance', 'hipaa', 'pci', 'gdpr', 'sox', 'fedramp'],
  governance: ['governance', 'provider-validation', 'region-restriction'],
  lifecycle:  ['retirement', 'deprecated', 'cost-control', 'instance-type'],
};

// ── Product Module Indicators (Layer 6) ──────────────────────────────────────────────────────────
// Keywords that indicate which AWS service category a module belongs to.

export const PRODUCT_INDICATORS = {
  'Database Service':   ['rds', 'dynamodb', 'aurora', 'database', 'db_', 'postgresql', 'mysql', 'mariadb', 'oracle', 'sqlserver'],
  'Messaging Service':  ['sqs', 'sns', 'msk', 'kafka', 'kinesis', 'eventbridge', 'rabbitmq', 'activemq', 'messaging', 'queue', 'topic'],
  'Search Service':     ['elasticsearch', 'opensearch', 'kendra', 'cloudsearch', 'search'],
  'Storage Service':    ['s3', 'efs', 'fsx', 'storage', 'backup', 'glacier', 'ebs'],
  'Compute Service':    ['lambda', 'ecs', 'eks', 'ec2', 'fargate', 'batch', 'lightsail', 'compute'],
  'Analytics Service':  ['redshift', 'athena', 'glue', 'emr', 'quicksight', 'analytics', 'datawarehouse'],
  'AI/ML Service':      ['sagemaker', 'bedrock', 'comprehend', 'textract', 'rekognition', 'forecast', 'ml', 'ai'],
  'API Service':        ['api_gateway', 'apigw', 'apigateway', 'rest_api', 'graphql', 'appsync'],
  'Cache Service':      ['elasticache', 'redis', 'memcached', 'cache', 'dax'],
  'CDN Service':        ['cloudfront', 'cdn', 'waf', 'shield', 'edge'],
  'Container Service':  ['ecr', 'ecs', 'eks', 'container', 'docker', 'kubernetes', 'fargate'],
  'Secrets Service':    ['secretsmanager', 'ssm_parameter', 'secrets', 'vault', 'kms'],
};

// ── Naming Conventions ────────────────────────────────────────────────────────────────────────────
// Enterprise naming patterns for modules, factories, accounts, resources, and tags.

export const NAMING_CONVENTIONS = {
  modules: {
    pattern: 'module-{service}-{function}',
    examples: ['module-msk-connect', 'module-opensearch-private-link', 'module-rds-aurora', 'module-elasticache-redis'],
  },
  factories: {
    pattern: '{boundary-type}-boundary-factory',
    examples: ['portfolio-boundary-factory', 'network-boundary-factory', 'base-account-factory', 'workload-boundary-factory'],
  },
  accounts: {
    pattern: '{Platform}-{BusinessUnit}-{Environment}-{Purpose}-{Sequence}',
    examples: ['Enterprise-CIB-Prod-Workload-001', 'Enterprise-Platform-NonProd-Shared-001'],
  },
  resources: {
    pattern: '{prefix}-{resource-type}-{identifier}',
    examples: ['enterprise-vpc-prod-001', 'platform-sg-trading-app', 'enterprise-kms-data-001'],
  },
  tags: {
    required: ['enterprise-app-id', 'environment', 'managed-by', 'cost-center'],
    optional: ['team', 'project', 'data-classification'],
  },
};

// ── Abbreviation Map ──────────────────────────────────────────────────────────────────────────────
// Maps canonical module/component names to common abbreviations and aliases encountered in the wild.
// Used for fuzzy matching during file classification.

export const ABBREVIATION_MAP = {
  'base-account-factory':          ['baseaccount', 'base_account', 'account_factory', 'acct-factory', 'baf', 'accountfactory'],
  'role-distribution-factory':     ['role-dist', 'role_distribution', 'roledist', 'rdf', 'iam-factory', 'role_dist_factory'],
  'network-boundary-factory':      ['network-boundary', 'netboundary', 'net_boundary', 'nbf', 'networkboundary'],
  'portfolio-boundary-factory':    ['portfolio-boundary', 'portfolio_boundary', 'pbf', 'portfolioboundary'],
  'workload-boundary-factory':     ['workload-boundary', 'workload_boundary', 'wbf', 'workloadboundary'],
  'security-group':                ['securitygroup', 'security_group', 'sg', 'secgroup'],
  'transit-gateway':               ['transitgateway', 'transit_gateway', 'tgw', 'tg'],
  'network-boundary':              ['netboundary', 'net_boundary', 'network_boundary'],
  'module-role':                   ['iam-role', 'iam_role', 'role-module', 'iamrole'],
  'module-role-policy-updater':    ['role-policy-updater', 'policy-updater', 'role_policy_updater', 'rpu'],
  'module-iam-policy':             ['iam-policy', 'iam_policy', 'policy-module', 'iampolicy'],
  'enterprise-aws-bootstrap':      ['bootstrap', 'aws-bootstrap', 'enterprise_bootstrap', 'xsphere-aws-bootstrap', 'xsphere_bootstrap'],
  'sentinel-policies':             ['sentinel', 'policies', 'policy', 'governance', 'sentinel_policy'],
  'platform-global':               ['platform', 'global', 'platform_global', 'atlas_global', 'atlas-global'],
  'aws-res-iam-role-policy':       ['aws-res', 'iam-role-policy', 'res-iam', 'awsres'],
  'module-msk-connect':            ['msk', 'kafka', 'messaging', 'mskconnect', 'msk_connect'],
  'module-opensearch':             ['opensearch', 'elasticsearch', 'search', 'es', 'aoss'],
  'module-elasticache':            ['elasticache', 'redis', 'cache', 'memcached'],
  'module-rds':                    ['rds', 'database', 'db', 'aurora', 'postgresql', 'mysql'],
  'module-kendra':                 ['kendra', 'enterprise-search', 'search-service'],
};

// ── File Patterns ─────────────────────────────────────────────────────────────────────────────────
// Known file extensions and naming patterns per technology category.

export const FILE_PATTERNS = {
  terraform: {
    extensions: ['.tf', '.tfvars', '.tfstate', '.tfstate.backup'],
    patterns: ['main.tf', 'variables.tf', 'outputs.tf', 'versions.tf', 'providers.tf', 'data.tf', 'locals.tf'],
    directories: ['modules/', 'environments/', 'policies/', 'layers/'],
  },
  kubernetes: {
    extensions: ['.yaml', '.yml'],
    patterns: ['*-crd.yaml', '*-rbac.yaml', '*-deployment.yaml', '*-operator.yaml', '*-serviceaccount.yaml'],
    directories: ['crds/', 'operators/', 'manifests/', 'k8s/'],
  },
  policies: {
    extensions: ['.sentinel', '.yaml', '.json'],
    patterns: ['*.sentinel', 'scp-*.yaml', 'rcp-*.yaml', '*-policy.json', '*-policy.yaml'],
    directories: ['policies/', 'sentinel/', 'templates/scp/', 'templates/rcp/', 'governance/'],
  },
  bootstrap: {
    extensions: ['.yaml', '.py', '.groovy', '.sh', '.j2'],
    patterns: ['ou-tree.yaml', 'ou-linker.yaml', 'Jenkinsfile', '*.j2', 'bootstrap*.yaml'],
    directories: ['templates/', 'scripts/', 'pipelines/', 'automation/'],
  },
};

// ── Compliance Checks ─────────────────────────────────────────────────────────────────────────────
// Each check has: id, category, critical flag, description, and a check function.
// The check function accepts a resources array (objects with .type and .body string fields).

export const SOX_CHECKS = [
  {
    id: 'SOX-01',
    category: 'Access Controls',
    critical: true,
    desc: 'Segregation of duties — IAM roles separate for deploy/admin/audit',
    check: (rs) => rs.some(r => r.type === 'aws_iam_role' && r.body && /assume_role|trust/i.test(r.body)),
  },
  {
    id: 'SOX-02',
    category: 'Audit Trail',
    critical: true,
    desc: 'CloudTrail enabled with log file validation',
    check: (rs) => rs.some(r => r.type === 'aws_cloudtrail' && r.body && /enable_log_file_validation\s*=\s*true/.test(r.body)),
  },
  {
    id: 'SOX-03',
    category: 'Change Management',
    critical: true,
    desc: 'Terraform state locking (DynamoDB) prevents concurrent changes',
    check: (rs) => rs.some(r => r.type === 'aws_dynamodb_table' && r.body && /LockID|terraform.*lock/i.test(r.body)),
  },
  {
    id: 'SOX-04',
    category: 'Data Integrity',
    critical: true,
    desc: 'S3 versioning for Terraform state integrity',
    check: (rs) => rs.some(r => r.type === 'aws_s3_bucket' && r.body && /versioning[\s\S]{0,80}enabled\s*=\s*true/.test(r.body)),
  },
  {
    id: 'SOX-05',
    category: 'Financial Controls',
    critical: false,
    desc: 'Cost allocation tags (enterprise-app-id, cost-center) on resources',
    check: (rs) => rs.some(r => r.body && /enterprise.app.id|cost.center/i.test(r.body)),
  },
  {
    id: 'SOX-06',
    category: 'Monitoring',
    critical: true,
    desc: 'CloudWatch alarms for unauthorized access attempts',
    check: (rs) => rs.some(r => r.type === 'aws_cloudwatch_metric_alarm'),
  },
];

export const PCI_CHECKS = [
  {
    id: 'PCI-01',
    category: 'Network Segmentation',
    critical: true,
    desc: 'Cardholder Data Environment (CDE) isolated in dedicated VPC',
    check: (rs) => rs.some(r => r.type === 'aws_vpc'),
  },
  {
    id: 'PCI-02',
    category: 'Encryption',
    critical: true,
    desc: 'All storage encrypted at rest with KMS CMK',
    check: (rs) => rs.some(r => r.type === 'aws_kms_key'),
  },
  {
    id: 'PCI-03',
    category: 'Access Control',
    critical: true,
    desc: 'MFA/SSO enforced — no IAM users with long-term credentials',
    check: (rs) => !rs.some(r => r.type === 'aws_iam_user') || rs.some(r => r.type.startsWith('aws_ssoadmin') || r.type.startsWith('aws_iam_openid')),
  },
  {
    id: 'PCI-04',
    category: 'Logging & Monitoring',
    critical: true,
    desc: 'CloudTrail + VPC flow logs for all CDE traffic',
    check: (rs) => rs.some(r => r.type === 'aws_cloudtrail') && rs.some(r => r.type === 'aws_flow_log'),
  },
  {
    id: 'PCI-05',
    category: 'Vulnerability Mgmt',
    critical: true,
    desc: 'GuardDuty + Security Hub for continuous threat detection',
    check: (rs) => rs.some(r => r.type === 'aws_guardduty_detector') && rs.some(r => r.type.startsWith('aws_securityhub')),
  },
  {
    id: 'PCI-06',
    category: 'Anti-Malware',
    critical: false,
    desc: 'WAF protecting all internet-facing applications',
    check: (rs) => rs.some(r => ['aws_wafv2_web_acl', 'aws_waf_web_acl'].includes(r.type)),
  },
  {
    id: 'PCI-07',
    category: 'Secure Systems',
    critical: true,
    desc: 'IMDSv2 enforced on all EC2 (prevents SSRF to credential theft)',
    check: (rs) => !rs.some(r => r.type === 'aws_instance') || rs.filter(r => r.type === 'aws_instance').every(r => r.body && r.body.includes('required')),
  },
];

export const GDPR_CHECKS = [
  {
    id: 'GDPR-01',
    category: 'Data Protection',
    critical: true,
    desc: 'Encryption at rest for all personal data stores (S3, RDS)',
    check: (rs) => rs.some(r => r.type === 'aws_kms_key'),
  },
  {
    id: 'GDPR-02',
    category: 'Data Residency',
    critical: true,
    desc: 'Region constraints via SCP or provider config',
    check: (rs) => rs.some(r => r.type === 'aws_organizations_policy' || r.type === 'AWS::Organizations::Policy'),
  },
  {
    id: 'GDPR-03',
    category: 'Right to Erasure',
    critical: false,
    desc: 'S3 lifecycle policies for data retention management',
    check: (rs) => rs.some(r => r.type === 'aws_s3_bucket' && r.body && /lifecycle/i.test(r.body)),
  },
  {
    id: 'GDPR-04',
    category: 'Breach Detection',
    critical: true,
    desc: 'GuardDuty + Macie for data breach detection',
    check: (rs) => rs.some(r => r.type === 'aws_guardduty_detector') && rs.some(r => r.type.startsWith('aws_macie')),
  },
  {
    id: 'GDPR-05',
    category: 'Access Logging',
    critical: true,
    desc: 'S3 server access logging + CloudTrail data events',
    check: (rs) => rs.some(r => r.type === 'aws_cloudtrail'),
  },
  {
    id: 'GDPR-06',
    category: 'Data Minimization',
    critical: false,
    desc: 'Macie for sensitive data discovery and classification',
    check: (rs) => rs.some(r => r.type.startsWith('aws_macie')),
  },
];

export const HIPAA_CHECKS = [
  {
    id: 'HIPAA-01',
    category: 'Access Control',
    critical: true,
    desc: 'Unique user identification — SSO/OIDC federation, no shared creds',
    check: (rs) => rs.some(r => r.type.startsWith('aws_ssoadmin') || r.type === 'aws_iam_openid_connect_provider'),
  },
  {
    id: 'HIPAA-02',
    category: 'Audit Controls',
    critical: true,
    desc: 'CloudTrail + CloudWatch for PHI access audit trail',
    check: (rs) => rs.some(r => r.type === 'aws_cloudtrail') && rs.some(r => r.type === 'aws_cloudwatch_metric_alarm'),
  },
  {
    id: 'HIPAA-03',
    category: 'Encryption',
    critical: true,
    desc: 'All PHI encrypted in transit (TLS) and at rest (KMS)',
    check: (rs) => rs.some(r => r.type === 'aws_kms_key') && (
      rs.some(r => r.type === 'aws_lb_listener' && r.body && r.body.includes('HTTPS')) ||
      rs.some(r => r.type === 'aws_cloudfront_distribution')
    ),
  },
  {
    id: 'HIPAA-04',
    category: 'Integrity',
    critical: true,
    desc: 'Backup and recovery — AWS Backup or RDS automated snapshots',
    check: (rs) => rs.some(r => r.type.startsWith('aws_backup')) || rs.some(r =>
      (r.type === 'aws_rds_instance' || r.type === 'aws_rds_cluster') &&
      r.body && !/backup_retention_period\s*=\s*0/.test(r.body)
    ),
  },
  {
    id: 'HIPAA-05',
    category: 'Transmission',
    critical: true,
    desc: 'VPC endpoints for AWS services (no data over public internet)',
    check: (rs) => rs.some(r => r.type === 'aws_vpc_endpoint'),
  },
  {
    id: 'HIPAA-06',
    category: 'Incident Response',
    critical: false,
    desc: 'Security Hub + SNS for HIPAA breach notification workflow',
    check: (rs) => rs.some(r => r.type.startsWith('aws_securityhub')) && rs.some(r => r.type === 'aws_sns_topic'),
  },
];

// ── Aggregated Exports ────────────────────────────────────────────────────────────────────────────

export const ALL_COMPLIANCE_CHECKS = {
  SOX:  SOX_CHECKS,
  PCI:  PCI_CHECKS,
  GDPR: GDPR_CHECKS,
  HIPAA: HIPAA_CHECKS,
};

export const ARCHITECTURE_LAYER_COUNT = 7;
export const ARCHITECTURE_FACTORY_COUNT = Object.keys(FACTORY_COMPONENTS).length;
