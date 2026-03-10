// src/data/misconfig-checks.js
// Terraform + CloudFormation misconfiguration checks (checkov-style).
// Each entry is keyed by resource type and contains an array of check objects:
//   { id, title, severity, cwe[], attack[], check(attrs) => bool, remediation }
// Used by runSecurityChecks() in SecurityAnalyzer and the Misconfigs tab.

export const TF_MISCONFIG_CHECKS = {
  'aws_s3_bucket': [
    { id:'S3-001', attrKey:'block_public_acls',                  title:'S3 Bucket Public Access Not Blocked',   severity:'Critical', cwe:['CWE-284','CWE-732'], attack:['T1530'], check:(a)=>!a.block_public_acls&&!a.block_public_policy,              remediation:'Enable aws_s3_bucket_public_access_block with all four settings = true.' },
    { id:'S3-002', attrKey:'versioning',                         title:'S3 Bucket Versioning Disabled',         severity:'Medium',   cwe:['CWE-400'],           attack:['T1485'], check:(a)=>{ const v=a.versioning; return !v||(typeof v==='object'&&!v.enabled); },  remediation:'Enable versioning { enabled = true } for data protection and DR.' },
    { id:'S3-003', attrKey:'logging',                            title:'S3 Bucket Access Logging Disabled',     severity:'Medium',   cwe:['CWE-778'],           attack:['T1562.008'], check:(a)=>!a.logging,                                            remediation:'Enable server access logging via logging { target_bucket = ... }' },
    { id:'S3-004', attrKey:'server_side_encryption_configuration',title:'S3 Bucket Encryption Not Configured',   severity:'High',     cwe:['CWE-311'],           attack:['T1530'], check:(a)=>!a.server_side_encryption_configuration,                   remediation:'Configure server_side_encryption_configuration with AES256 or aws:kms.' },
  ],
  'aws_security_group': [
    { id:'SG-001', attrKey:'ingress', title:'Unrestricted SSH Access (0.0.0.0/0:22)',   severity:'Critical', cwe:['CWE-732','CWE-284'], attack:['T1190','T1133'], check:(a)=>(a.ingress||[]).some(r=>r.from_port<=22&&r.to_port>=22&&((r.cidr_blocks||[]).includes('0.0.0.0/0')||(r.ipv6_cidr_blocks||[]).includes('::/0'))),   remediation:'Restrict SSH to known IP ranges. Use bastion host or SSM Session Manager.' },
    { id:'SG-002', attrKey:'ingress', title:'Unrestricted RDP Access (0.0.0.0/0:3389)', severity:'Critical', cwe:['CWE-732','CWE-284'], attack:['T1190','T1133'], check:(a)=>(a.ingress||[]).some(r=>r.from_port<=3389&&r.to_port>=3389&&((r.cidr_blocks||[]).includes('0.0.0.0/0')||(r.ipv6_cidr_blocks||[]).includes('::/0'))),remediation:'Restrict RDP to specific IP ranges. Use VPN or Direct Connect.' },
    { id:'SG-003', attrKey:'ingress', title:'All Inbound Traffic Allowed (0.0.0.0/0)', severity:'Critical', cwe:['CWE-732'],           attack:['T1190'],         check:(a)=>(a.ingress||[]).some(r=>r.from_port===0&&r.to_port===0&&((r.cidr_blocks||[]).includes('0.0.0.0/0')||(r.ipv6_cidr_blocks||[]).includes('::/0'))),        remediation:'Apply least privilege. Only allow necessary ports from known CIDRs.' },
  ],
  'aws_rds_instance': [
    { id:'RDS-001', attrKey:'storage_encrypted',     title:'RDS Not Encrypted at Rest',          severity:'High',     cwe:['CWE-311','CWE-326'], attack:['T1530'],        check:(a)=>a.storage_encrypted===false||a.storage_encrypted===undefined,   remediation:'Set storage_encrypted = true and specify a kms_key_id.' },
    { id:'RDS-002', attrKey:'publicly_accessible',   title:'RDS Instance Publicly Accessible',   severity:'Critical', cwe:['CWE-284'],           attack:['T1190'],        check:(a)=>a.publicly_accessible===true,            remediation:'Set publicly_accessible = false. Place RDS in private subnets only.' },
    { id:'RDS-003', attrKey:'deletion_protection',   title:'RDS Deletion Protection Disabled',   severity:'Medium',   cwe:['CWE-400'],           attack:['T1485'],        check:(a)=>!a.deletion_protection,                 remediation:'Set deletion_protection = true in all production environments.' },
    { id:'RDS-004', attrKey:'backup_retention_period',title:'RDS Automated Backups Disabled',    severity:'High',     cwe:['CWE-400'],           attack:['T1485','T1490'], check:(a)=>a.backup_retention_period===0,           remediation:'Set backup_retention_period >= 7 days for production databases.' },
    { id:'RDS-005', attrKey:'multi_az',              title:'RDS Multi-AZ Not Enabled',           severity:'Medium',   cwe:['CWE-400'],           attack:['T1485'],        check:(a)=>!a.multi_az,                            remediation:'Set multi_az = true for high availability in production.' },
  ],
  'aws_db_instance': [
    { id:'RDS-001', attrKey:'storage_encrypted',   title:'DB Not Encrypted at Rest',           severity:'High',     cwe:['CWE-311','CWE-326'], attack:['T1530'],  check:(a)=>a.storage_encrypted===false||a.storage_encrypted===undefined, remediation:'Set storage_encrypted = true and specify kms_key_id.' },
    { id:'RDS-002', attrKey:'publicly_accessible', title:'DB Instance Publicly Accessible',    severity:'Critical', cwe:['CWE-284'],           attack:['T1190'],  check:(a)=>a.publicly_accessible===true, remediation:'Set publicly_accessible = false.' },
  ],
  'aws_instance': [
    { id:'EC2-001', attrKey:'metadata_options', title:'IMDSv1 Enabled (Metadata API Vulnerable)', severity:'High',   cwe:['CWE-284'],    attack:['T1552.005'], check:(a)=>{ const m=a.metadata_options; return !m||(typeof m==='object'?m.http_tokens!=='required':true); }, remediation:'Set metadata_options { http_tokens = "required" } to enforce IMDSv2.' },
    { id:'EC2-002', attrKey:'iam_instance_profile', title:'No IAM Instance Profile Assigned',     severity:'Low',    cwe:['CWE-250'],    attack:['T1552.005'], check:(a)=>!a.iam_instance_profile,                                              remediation:'Assign a least-privilege IAM instance profile; avoid embedded credentials.' },
    { id:'EC2-003', attrKey:'root_block_device',    title:'Root EBS Volume Not Encrypted',        severity:'High',   cwe:['CWE-311'],    attack:['T1530'],     check:(a)=>{ const r=a.root_block_device; return !r||(typeof r==='object'&&!r.encrypted); }, remediation:'Set root_block_device { encrypted = true, kms_key_id = ... }' },
    { id:'EC2-004', attrKey:'ebs_block_device',     title:'EBS Volumes Not Encrypted',            severity:'High',   cwe:['CWE-311'],    attack:['T1530'],     check:(a)=>{ const b=Array.isArray(a.ebs_block_device)?a.ebs_block_device:(a.ebs_block_device?[a.ebs_block_device]:[]); return b.some(v=>!v.encrypted); }, remediation:'Set encrypted = true on all ebs_block_device blocks.' },
  ],
  'aws_cloudtrail': [
    { id:'CT-001', attrKey:'enable_log_file_validation', title:'CloudTrail Log File Validation Disabled', severity:'High',   cwe:['CWE-778'], attack:['T1562.008'], check:(a)=>!a.enable_log_file_validation, remediation:'Set enable_log_file_validation = true to detect log tampering.' },
    { id:'CT-002', attrKey:'kms_key_id',                 title:'CloudTrail Logs Not Encrypted with KMS',  severity:'Medium', cwe:['CWE-311'], attack:['T1530'],     check:(a)=>!a.kms_key_id,                remediation:'Set kms_key_id to a KMS CMK ARN to encrypt CloudTrail logs at rest.' },
    { id:'CT-003', attrKey:'is_multi_region_trail',      title:'CloudTrail Not Multi-Region',             severity:'High',   cwe:['CWE-778'], attack:['T1562.008'], check:(a)=>!a.is_multi_region_trail,      remediation:'Set is_multi_region_trail = true to capture all regional API activity.' },
  ],
  'aws_kms_key': [
    { id:'KMS-001', attrKey:'enable_key_rotation', title:'KMS Key Rotation Disabled', severity:'Medium', cwe:['CWE-326'], attack:['T1600'], check:(a)=>!a.enable_key_rotation, remediation:'Set enable_key_rotation = true for automatic annual key rotation.' },
  ],
  'aws_lambda_function': [
    { id:'LMB-001', title:'Lambda Not Inside VPC',                    severity:'Medium', cwe:['CWE-284'],           attack:['T1648'],     check:(a)=>!a.vpc_config,                                                           remediation:'Configure vpc_config with subnet_ids and security_group_ids.' },
    { id:'LMB-002', title:'Lambda Uses Deprecated/EOL Runtime',       severity:'High',   cwe:['CWE-1104'],          attack:['T1190'],     check:(a)=>['nodejs12.x','nodejs10.x','python2.7','python3.6','ruby2.5'].includes(a.runtime||''), remediation:'Upgrade to a current supported runtime (nodejs20.x, python3.12, etc.).' },
    { id:'LMB-003', title:'Lambda Env Vars May Contain Secrets',      severity:'High',   cwe:['CWE-256','CWE-798'], attack:['T1555.006'], check:(a)=>{ const e=JSON.stringify(a.environment||'').toLowerCase(); return /password|secret|key|token|credential/.test(e); }, remediation:'Use AWS Secrets Manager or SSM SecureString instead of env var secrets.' },
  ],
  'aws_ssm_parameter': [
    { id:'SSM-001', attrKey:'type', title:'SSM Parameter Not SecureString Type', severity:'High', cwe:['CWE-256','CWE-312'], attack:['T1555.006'], check:(a)=>a.type!=='SecureString', remediation:'Use type = "SecureString" with a KMS key for sensitive parameter values.' },
  ],
  'aws_eks_cluster': [
    { id:'EKS-001', title:'EKS API Endpoint Publicly Accessible',  severity:'High',   cwe:['CWE-284'], attack:['T1190','T1613'], check:(a)=>{ const v=a.vpc_config; return !v||v.endpoint_public_access!==false; },  remediation:'Set endpoint_public_access = false; access cluster via private endpoint + VPN.' },
    { id:'EKS-002', title:'EKS Control Plane Logging Incomplete',   severity:'Medium', cwe:['CWE-778'], attack:['T1562.008'],     check:(a)=>{ const l=a.enabled_cluster_log_types||[]; return !['api','audit','authenticator'].every(x=>l.includes(x)); }, remediation:'Enable all log types: api, audit, authenticator, controllerManager, scheduler.' },
  ],
  'aws_iam_role': [
    { id:'IAM-001', title:'IAM Role Allows Wildcard Actions (*)', severity:'Critical', cwe:['CWE-284','CWE-269'], attack:['T1078.004','T1548'], check:(a)=>{ const p=JSON.stringify(a.assume_role_policy||a.inline_policy||''); return p.includes('"Action":"*"')||p.includes('"Action": "*"'); }, remediation:'Apply least-privilege IAM. Enumerate only required actions — never use "*".' },
  ],
  'aws_iam_user': [
    { id:'IAM-002', title:'IAM User Detected — Prefer IAM Roles', severity:'Low', cwe:['CWE-285'], attack:['T1078.004'], check:()=>true, remediation:'Prefer IAM roles for service access and AWS SSO/Identity Center for human access.' },
  ],
  // ── DynamoDB ──────────────────────────────────────────────────────────────
  'aws_dynamodb_table': [
    { id:'DDB-001', attrKey:'server_side_encryption',    title:'DynamoDB Table No Explicit KMS Encryption',  severity:'Medium', cwe:['CWE-311'],       attack:['T1530'],     check:(a)=>{ const s=a.server_side_encryption; return !s||(typeof s==='object'&&!s.enabled); }, remediation:'Add server_side_encryption { enabled = true } with a CMK kms_key_arn for compliance.' },
    { id:'DDB-002', attrKey:'point_in_time_recovery',    title:'DynamoDB PITR (Point-in-Time Recovery) Off',  severity:'High',   cwe:['CWE-400'],       attack:['T1485','T1490'], check:(a)=>{ const p=a.point_in_time_recovery; return !p||(typeof p==='object'&&!p.enabled); }, remediation:'Enable point_in_time_recovery { enabled = true } for ransomware / deletion recovery.' },
    { id:'DDB-003', attrKey:'deletion_protection_enabled',title:'DynamoDB Table Has No Deletion Protection',  severity:'Medium', cwe:['CWE-400'],       attack:['T1485'],     check:(a)=>!a.deletion_protection_enabled, remediation:'Set deletion_protection_enabled = true to prevent accidental or malicious deletion.' },
  ],
  // ── ElastiCache ───────────────────────────────────────────────────────────
  'aws_elasticache_cluster': [
    { id:'ECACHE-001', title:'ElastiCache Cluster Not Encrypted at Rest',    severity:'High',   cwe:['CWE-311','CWE-326'], attack:['T1530'],     check:(a)=>!a.at_rest_encryption_enabled, remediation:'Set at_rest_encryption_enabled = true with kms_key_id for CMK encryption.' },
    { id:'ECACHE-002', title:'ElastiCache Cluster Not Encrypted in Transit', severity:'High',   cwe:['CWE-319'],           attack:['T1040'],     check:(a)=>!a.transit_encryption_enabled,  remediation:'Set transit_encryption_enabled = true (requires Redis engine >= 3.2.6).' },
    { id:'ECACHE-003', title:'ElastiCache No Auth Token (Redis AUTH off)',   severity:'Medium', cwe:['CWE-306'],           attack:['T1078'],     check:(a)=>!a.auth_token,                  remediation:'Set auth_token for Redis clusters with transit_encryption_enabled = true.' },
    { id:'ECACHE-004', title:'ElastiCache No Snapshot Retention',           severity:'Medium', cwe:['CWE-400'],           attack:['T1485'],     check:(a)=>!a.snapshot_retention_limit||a.snapshot_retention_limit===0, remediation:'Set snapshot_retention_limit >= 7 days for backup and recovery capability.' },
  ],
  'aws_elasticache_replication_group': [
    { id:'ECACHE-001', title:'ElastiCache Replication Group Not Encrypted at Rest',    severity:'High',   cwe:['CWE-311'], attack:['T1530'], check:(a)=>!a.at_rest_encryption_enabled, remediation:'Set at_rest_encryption_enabled = true.' },
    { id:'ECACHE-002', title:'ElastiCache Replication Group Not Encrypted in Transit', severity:'High',   cwe:['CWE-319'], attack:['T1040'], check:(a)=>!a.transit_encryption_enabled,  remediation:'Set transit_encryption_enabled = true.' },
    { id:'ECACHE-003', title:'ElastiCache Replication Group No Auth Token',            severity:'Medium', cwe:['CWE-306'], attack:['T1078'], check:(a)=>!a.auth_token,                  remediation:'Set auth_token for Redis AUTH enforcement.' },
  ],
  // ── API Gateway ───────────────────────────────────────────────────────────
  'aws_api_gateway_rest_api': [
    { id:'APIGW-001', title:'API Gateway Execute-API Endpoint Not Disabled',severity:'Medium', cwe:['CWE-284'],     attack:['T1190'], check:(a)=>!a.disable_execute_api_endpoint, remediation:'Set disable_execute_api_endpoint = true; access via custom domain with WAF.' },
    { id:'APIGW-002', title:'API Gateway No WAF ACL Associated',            severity:'High',   cwe:['CWE-693'],     attack:['T1190','T1499'], check:(a)=>!a.body?.includes('aws_wafv2_web_acl_association'), remediation:'Associate an aws_wafv2_web_acl_association resource with the API stage.' },
  ],
  'aws_apigatewayv2_api': [
    { id:'APIGW2-001', title:'API GW v2 No CORS Configuration',             severity:'Low',    cwe:['CWE-346'],     attack:['T1059.009'], check:(a)=>!a.cors_configuration, remediation:'Configure cors_configuration with explicit allow_origins — avoid wildcard.' },
    { id:'APIGW2-002', title:'API GW v2 No Authorizer Configured',          severity:'High',   cwe:['CWE-306'],     attack:['T1190'],     check:(a)=>!a.authorizer_id&&!a.authorization_type&&a.authorization_type!=='JWT'&&a.authorization_type!=='AWS_IAM', remediation:'Attach a JWT or IAM authorizer; never expose unauthenticated routes in production.' },
  ],
  // ── SNS ───────────────────────────────────────────────────────────────────
  'aws_sns_topic': [
    { id:'SNS-001', title:'SNS Topic Not Encrypted with KMS',         severity:'High',   cwe:['CWE-311','CWE-326'], attack:['T1530'],     check:(a)=>!a.kms_master_key_id, remediation:'Set kms_master_key_id to a CMK ARN — never use unencrypted topics for sensitive payloads.' },
    { id:'SNS-002', title:'SNS Topic Policy Allows Public Publish',   severity:'Critical',cwe:['CWE-284'],           attack:['T1059.009'], check:(a)=>{ const p=JSON.stringify(a.policy||''); return p.includes('"Principal":"*"')||p.includes('"Principal":{"AWS":"*"}'); }, remediation:'Restrict sns:Publish to specific IAM principals; never use Principal = "*".' },
  ],
  // ── SQS ───────────────────────────────────────────────────────────────────
  'aws_sqs_queue': [
    { id:'SQS-001', title:'SQS Queue Not Encrypted',                   severity:'High',   cwe:['CWE-311','CWE-326'], attack:['T1530'], check:(a)=>!a.kms_master_key_id&&!a.sqs_managed_sse_enabled, remediation:'Set sqs_managed_sse_enabled = true or specify kms_master_key_id for SSE-KMS.' },
    { id:'SQS-002', title:'SQS Queue Policy Allows Public Access',     severity:'Critical',cwe:['CWE-284'],           attack:['T1530'], check:(a)=>{ const p=JSON.stringify(a.policy||''); return p.includes('"Principal":"*"')||p.includes('"Principal":{"AWS":"*"}'); }, remediation:'Restrict sqs:SendMessage to specific IAM principals or VPC endpoint conditions.' },
    { id:'SQS-003', title:'SQS Queue Visibility Timeout Too Low',      severity:'Low',    cwe:['CWE-400'],           attack:['T1499'], check:(a)=>a.visibility_timeout_seconds<30, remediation:'Set visibility_timeout_seconds >= Lambda timeout (min 30s) to prevent duplicate processing.' },
  ],
  // ── CloudFront ────────────────────────────────────────────────────────────
  'aws_cloudfront_distribution': [
    { id:'CF-001', title:'CloudFront Allows HTTP (Not HTTPS-Only)',    severity:'High',   cwe:['CWE-319'],     attack:['T1040'],     check:(a)=>!a.viewer_protocol_policy||a.viewer_protocol_policy==='allow-all', remediation:'Set viewer_protocol_policy = "redirect-to-https" or "https-only" in all cache behaviors.' },
    { id:'CF-002', title:'CloudFront No WAF Web ACL Associated',       severity:'High',   cwe:['CWE-693'],     attack:['T1190','T1499'], check:(a)=>!a.web_acl_id, remediation:'Set web_acl_id to an aws_wafv2_web_acl ARN (must be in us-east-1 for CloudFront).' },
    { id:'CF-003', title:'CloudFront Logging Disabled',                severity:'Medium', cwe:['CWE-778'],     attack:['T1562.008'], check:(a)=>!a.logging_config, remediation:'Configure logging_config { bucket = ... } to capture all edge access logs.' },
    { id:'CF-004', title:'CloudFront Geo Restriction Not Configured',  severity:'Low',    cwe:['CWE-284'],     attack:['T1190'],     check:(a)=>!a.restrictions&&!a.geo_restriction, remediation:'Configure geo_restriction if the application should be limited to specific countries.' },
  ],
  // ── Load Balancer ─────────────────────────────────────────────────────────
  'aws_lb_listener': [
    { id:'LB-001', title:'Load Balancer Listener Using HTTP Not HTTPS', severity:'High',   cwe:['CWE-319'],     attack:['T1040'], check:(a)=>a.protocol==='HTTP'&&!a.redirect, remediation:'Redirect HTTP → HTTPS or use HTTPS listener with a valid ACM certificate.' },
    { id:'LB-002', title:'Load Balancer HTTPS Using Insecure TLS Policy',severity:'Medium',cwe:['CWE-326'],     attack:['T1040'], check:(a)=>a.protocol==='HTTPS'&&a.ssl_policy&&['ELBSecurityPolicy-2015-05','ELBSecurityPolicy-TLS-1-0-2015-04'].includes(a.ssl_policy), remediation:'Use ELBSecurityPolicy-TLS13-1-2-2021-06 or newer. Avoid legacy TLS 1.0/1.1 policies.' },
  ],
  // ── Secrets Manager ───────────────────────────────────────────────────────
  'aws_secretsmanager_secret': [
    { id:'SM-001', title:'Secrets Manager Secret No Automatic Rotation', severity:'High',   cwe:['CWE-324'],     attack:['T1555.006'], check:(a)=>!a.rotation_lambda_arn&&!a.rotation_rules, remediation:'Configure rotation_rules { automatically_after_days = 90 } and a rotation Lambda.' },
    { id:'SM-002', title:'Secrets Manager ForceDelete (No Recovery Window)', severity:'High',cwe:['CWE-400'],    attack:['T1485'],     check:(a)=>a.recovery_window_in_days===0||a.force_overwrite_replica_secret===true, remediation:'Set recovery_window_in_days = 30 (default). Avoid force delete in production.' },
  ],
  // ── RDS Cluster ───────────────────────────────────────────────────────────
  'aws_rds_cluster': [
    { id:'RDSC-001', title:'RDS Cluster Not Encrypted at Rest',        severity:'High',   cwe:['CWE-311','CWE-326'], attack:['T1530'],     check:(a)=>!a.storage_encrypted, remediation:'Set storage_encrypted = true and specify kms_key_id for the cluster.' },
    { id:'RDSC-002', title:'RDS Cluster Deletion Protection Disabled', severity:'Medium', cwe:['CWE-400'],           attack:['T1485'],     check:(a)=>!a.deletion_protection, remediation:'Set deletion_protection = true to prevent accidental cluster deletion.' },
    { id:'RDSC-003', title:'RDS Cluster Backup Retention Too Short',   severity:'High',   cwe:['CWE-400'],           attack:['T1485','T1490'], check:(a)=>!a.backup_retention_period||a.backup_retention_period<7, remediation:'Set backup_retention_period >= 7 days. Minimum 35 days for PCI/HIPAA.' },
    { id:'RDSC-004', title:'RDS Cluster Not Multi-AZ',                 severity:'Medium', cwe:['CWE-400'],           attack:['T1485'],     check:(a)=>!a.availability_zones||!a.multi_az, remediation:'Configure multi-AZ by specifying multiple availability_zones or setting multi_az = true.' },
  ],
  // ── ECS Task Definition ───────────────────────────────────────────────────
  'aws_ecs_task_definition': [
    { id:'ECS-001', title:'ECS Task Definition Privileged Container',  severity:'Critical', cwe:['CWE-250','CWE-269'], attack:['T1611'], check:(a)=>{ const body=JSON.stringify(a); return body.includes('"privileged":true')||body.includes('"privileged": true'); }, remediation:'Never run privileged = true in production. Use specific Linux capabilities instead.' },
    { id:'ECS-002', title:'ECS Task No Read-Only Root Filesystem',     severity:'Medium',   cwe:['CWE-732'],           attack:['T1036'],  check:(a)=>!a.readonlyRootFilesystem&&!a.readonly_root_filesystem, remediation:'Set readonlyRootFilesystem = true in container definitions to prevent container escape.' },
    { id:'ECS-003', title:'ECS Task Not Using awslogs Log Driver',     severity:'Medium',   cwe:['CWE-778'],           attack:['T1562.008'], check:(a)=>!a.logConfiguration&&!a.log_configuration, remediation:'Configure logConfiguration with logDriver = "awslogs" for CloudWatch integration.' },
  ],
  // ── ECR ───────────────────────────────────────────────────────────────────
  'aws_ecr_repository': [
    { id:'ECR-001', title:'ECR Repository Scan on Push Disabled',     severity:'Medium', cwe:['CWE-1104'],     attack:['T1195.002'], check:(a)=>!a.image_scanning_configuration||!a.scan_on_push, remediation:'Set image_scanning_configuration { scan_on_push = true } for automatic vulnerability scanning.' },
    { id:'ECR-002', title:'ECR Repository Image Tags Are Mutable',    severity:'Medium', cwe:['CWE-494'],      attack:['T1195.002'], check:(a)=>!a.image_tag_mutability||a.image_tag_mutability!=='IMMUTABLE', remediation:'Set image_tag_mutability = "IMMUTABLE" to prevent tag overwriting / supply chain attacks.' },
    { id:'ECR-003', title:'ECR Repository Not Encrypted with CMK',    severity:'Medium', cwe:['CWE-311'],      attack:['T1530'],     check:(a)=>!a.encryption_configuration||!a.kms_key, remediation:'Set encryption_configuration { encryption_type = "KMS", kms_key = var.kms_arn }.' },
  ],
  // ── CloudFormation resource checks (CFNXXX IDs) ──────────────────────────
  'AWS::S3::Bucket': [
    { id:'CFNS3-001', title:'S3 Public Access Not Blocked', severity:'Critical', cwe:['CWE-284','CWE-732'], attack:['T1530'],
      check:(a)=>!a.block_public_acls&&!a.block_public_policy,
      remediation:'Set PublicAccessBlockConfiguration.BlockPublicAcls and BlockPublicPolicy to true.' },
    { id:'CFNS3-002', title:'S3 Versioning Disabled', severity:'Medium', cwe:['CWE-400'], attack:['T1485'],
      check:(a)=>!a.versioning_enabled,
      remediation:'Set VersioningConfiguration.Status to "Enabled".' },
    { id:'CFNS3-003', title:'S3 Encryption Not Configured', severity:'High', cwe:['CWE-311'], attack:['T1530'],
      check:(a)=>!a.server_side_encryption_configuration,
      remediation:'Add BucketEncryption with ServerSideEncryptionConfiguration.' },
    { id:'CFNS3-004', title:'S3 Access Logging Disabled', severity:'Medium', cwe:['CWE-778'], attack:['T1562.008'],
      check:(a)=>!a.logging,
      remediation:'Add LoggingConfiguration with DestinationBucketName.' },
  ],
  'AWS::IAM::Role': [
    { id:'CFNIAM-001', title:'IAM Role Allows Wildcard Actions (*)', severity:'Critical', cwe:['CWE-250','CWE-269'], attack:['T1078.004','T1548'],
      check:(a)=>{ const p=a.inline_policy||''; return p.includes('"Action":"*"')||p.includes('"Action":["*"]'); },
      remediation:'Replace wildcard actions with specific IAM actions.' },
    { id:'CFNIAM-002', title:'IAM Role Has No Permission Boundary', severity:'High', cwe:['CWE-269'], attack:['T1548'],
      check:(a)=>!a.permissions_boundary&&!a.__intrinsic_PermissionsBoundary,
      remediation:'Attach a PermissionsBoundary to all IAM roles in pave templates.' },
    { id:'CFNIAM-003', title:'IAM Role Trust Policy Allows Broad Principal', severity:'High', cwe:['CWE-284'], attack:['T1078.004'],
      check:(a)=>{ try { const d=JSON.parse(a.assume_role_policy||'{}'); return (d.Statement||[]).some(s=>s.Principal==='*'||s.Principal?.AWS==='*'); } catch{return false;}},
      remediation:'Restrict AssumeRolePolicyDocument Principal to specific accounts or services.' },
  ],
  'AWS::IAM::ManagedPolicy': [
    { id:'CFNIAM-004', title:'Managed Policy Allows Wildcard Actions (*)', severity:'Critical', cwe:['CWE-250'], attack:['T1078.004','T1548'],
      check:(a)=>(a.body||'').includes('"Action":"*"'),
      remediation:'Replace wildcard Action in ManagedPolicy with specific IAM actions.' },
  ],
  'AWS::Organizations::Policy': [
    { id:'CFNORG-001', title:'SCP Has No Deny Statements (Allows Only)', severity:'Medium', cwe:['CWE-284'], attack:['T1078.004'],
      check:(a)=>{ try { const d=JSON.parse(a.assume_role_policy||'{}'); return !(d.Statement||[]).some(s=>s.Effect==='Deny'); } catch{return false;}},
      remediation:'Add explicit Deny statements to SCP for privileged actions.' },
  ],
  'AWS::KMS::Key': [
    { id:'CFNKMS-001', title:'KMS Key Rotation Disabled', severity:'Medium', cwe:['CWE-326'], attack:['T1600'],
      check:(a)=>a.enable_key_rotation===false||a.enable_key_rotation==='false',
      remediation:'Set EnableKeyRotation to true.' },
  ],
  'AWS::RDS::DBInstance': [
    { id:'CFNRDS-001', title:'RDS Not Encrypted at Rest', severity:'High', cwe:['CWE-311'], attack:['T1530'],
      check:(a)=>!a.storage_encrypted,
      remediation:'Set StorageEncrypted to true.' },
    { id:'CFNRDS-002', title:'RDS Publicly Accessible', severity:'Critical', cwe:['CWE-284'], attack:['T1190'],
      check:(a)=>a.publicly_accessible===true,
      remediation:'Set PubliclyAccessible to false.' },
    { id:'CFNRDS-003', title:'RDS Deletion Protection Disabled', severity:'Medium', cwe:['CWE-400'], attack:['T1485'],
      check:(a)=>!a.deletion_protection,
      remediation:'Set DeletionProtection to true.' },
  ],
  'AWS::EC2::SecurityGroup': [
    { id:'CFNSG-001', title:'Security Group Allows Unrestricted Inbound (0.0.0.0/0)', severity:'High', cwe:['CWE-284'], attack:['T1190','T1046'],
      check:(a)=>{ try { const ips=(a.SecurityGroupIngress||[]); return ips.some(r=>r.CidrIp==='0.0.0.0/0'||r.CidrIpv6==='::/0'); } catch{return false;}},
      remediation:'Restrict SecurityGroupIngress CidrIp to known IP ranges. Avoid 0.0.0.0/0.' },
  ],
};
