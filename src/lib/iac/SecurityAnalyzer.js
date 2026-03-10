// src/lib/iac/SecurityAnalyzer.js
import { ATTACK_TECHNIQUES, TF_ATTACK_MAP, CWE_DETAILS, STRIDE_PER_ELEMENT, getElementType as _getElementType } from '../../data/attack-data.js';
import { TF_MISCONFIG_CHECKS } from '../../data/misconfig-checks.js';
import { CONFIDENCE_BY_METHOD, mkEvidence, CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS, NIST_CSF_CHECKS } from '../../data/control-detection.js';
import { TIERS } from '../../constants/tiers.js';
import { RT } from '../../data/resource-types.js';
import { parseHCLBody } from './TerraformParser.js';
import { KB } from '../../data/kb-domains.js';

function tfAttr(body, name) {
  const m = body.match(new RegExp(`\\b${name.replace(/\./g,"\\.")}\\s*=\\s*(?:"([^"\\n]*)"|([^\\s,\\n\\]]+))`, "m"));
  if (!m) return null;
  return m[1] !== undefined ? m[1] : m[2];
}
const tfBool  = (body, name) => tfAttr(body, name);
const tfBlock = (body, name) => new RegExp(`\\b${name}\\s*\\{`).test(body);

// Per-resource security rule checks (Checkov/tfsec style, based on actual parsed attributes)
function runSecurityChecks(resources, variables) {
  const findings = [];
  const push = (sev, code, id, msg, detail, technique, cwe) =>
    findings.push({ sev, code, id, msg, detail, technique, cwe });
  const types = new Set(resources.map(r => r.type));

  resources.forEach(r => {
    const b = r.body || "";
    const id = r.id;
    const a = n => tfAttr(b, n);
    const hb = n => tfBlock(b, n);

    // ── RDS / Aurora ──────────────────────────────────────────────────────
    if (r.type === "aws_db_instance" || r.type === "aws_rds_cluster") {
      if (a("publicly_accessible") === "true")
        push("CRITICAL","TF-RDS-001",id,`RDS ${id}: publicly_accessible = true`,
          "Database is directly reachable from the internet. Set publicly_accessible = false and restrict access via Security Group referencing only the application tier SG.",
          "T1190","CWE-284");
      if (!b.includes("storage_encrypted") || a("storage_encrypted") === "false")
        push("HIGH","TF-RDS-002",id,`RDS ${id}: encryption at rest not explicitly enabled`,
          "storage_encrypted is not set to true. Unencrypted RDS data is readable if the underlying EBS snapshot or storage is accessed. Enable SSE with a customer-managed KMS key.",
          "T1530","CWE-311");
      if (!b.includes("backup_retention_period") || a("backup_retention_period") === "0")
        push("MEDIUM","TF-RDS-003",id,`RDS ${id}: no backup retention configured`,
          "backup_retention_period = 0 disables automated backups. Set ≥ 7 days (35 max) to support point-in-time recovery. Required by PCI-DSS and most compliance frameworks.",
          "T1485","CWE-400");
      if (!b.includes("deletion_protection") || a("deletion_protection") === "false")
        push("MEDIUM","TF-RDS-004",id,`RDS ${id}: deletion protection disabled`,
          "deletion_protection = false allows the database to be deleted with a single API call. Enable for all production databases.",
          "T1485","CWE-400");
      if (r.type === "aws_db_instance" && (!b.includes("multi_az") || a("multi_az") === "false"))
        push("LOW","TF-RDS-005",id,`RDS ${id}: not configured for Multi-AZ`,
          "Single-AZ RDS instance has no automatic failover. Configure multi_az = true for production workloads to eliminate the database as a single point of failure.",
          "T1499","CWE-400");
    }

    // ── S3 Buckets ────────────────────────────────────────────────────────
    if (r.type === "aws_s3_bucket") {
      const hasACL = b.includes('"public-read"') || b.includes('"public-read-write"');
      if (hasACL)
        push("CRITICAL","TF-S3-001",id,`S3 ${id}: public-read or public-read-write ACL`,
          'ACL set to public-read or public-read-write makes all objects publicly accessible. Remove ACL attribute entirely and use bucket policies with explicit identity conditions.',
          "T1530","CWE-732");
    }
    if (r.type === "aws_s3_bucket_public_access_block") {
      if (a("block_public_acls") !== "true")
        push("HIGH","TF-S3-002",id,`S3 public access block ${id}: block_public_acls not true`,
          "block_public_acls = true prevents new public ACL grants on objects. Must be true to prevent inadvertent public exposure via ACLs.",
          "T1530","CWE-732");
      if (a("ignore_public_acls") !== "true")
        push("HIGH","TF-S3-003",id,`S3 public access block ${id}: ignore_public_acls not true`,
          "ignore_public_acls = true causes S3 to ignore any existing public ACLs. Required alongside block_public_acls for complete ACL protection.",
          "T1530","CWE-732");
      if (a("block_public_policy") !== "true")
        push("HIGH","TF-S3-004",id,`S3 public access block ${id}: block_public_policy not true`,
          "block_public_policy = true prevents bucket policies that grant public access. Without this, a bucket policy could re-open access.",
          "T1530","CWE-284");
      if (a("restrict_public_buckets") !== "true")
        push("HIGH","TF-S3-005",id,`S3 public access block ${id}: restrict_public_buckets not true`,
          "restrict_public_buckets = true restricts access to buckets with public policies to only AWS services and authorized users. All four settings should be true.",
          "T1530","CWE-284");
    }

    // ── Lambda ────────────────────────────────────────────────────────────
    if (r.type === "aws_lambda_function") {
      const hasEnv = hb("environment") && b.includes("variables");
      if (hasEnv && /\b(password|secret|key|token|credential|api_key|access_key|private_key)\b/i.test(b))
        push("HIGH","TF-LAMBDA-001",id,`Lambda ${id}: likely plaintext credential in environment variable`,
          "Lambda environment variables are stored in plaintext in the function configuration and visible in the AWS Console. Use Secrets Manager or SSM SecureString and fetch at runtime.",
          "T1552","CWE-798");
      if (!hb("vpc_config"))
        push("LOW","TF-LAMBDA-002",id,`Lambda ${id}: not deployed in a VPC`,
          "Lambda without vpc_config runs in an AWS-managed VPC with default internet egress. If the function accesses private resources (RDS, ElastiCache), deploy in VPC private subnet.",
          "T1021","CWE-284");
      if (!b.includes("reserved_concurrent_executions"))
        push("LOW","TF-LAMBDA-003",id,`Lambda ${id}: no concurrency limit set`,
          "Without reserved_concurrent_executions, a Lambda can consume all account concurrency, blocking other functions. Set an appropriate limit to prevent Denial of Service.",
          "T1499","CWE-400");
    }

    // ── KMS Keys ─────────────────────────────────────────────────────────
    if (r.type === "aws_kms_key") {
      if (a("enable_key_rotation") !== "true")
        push("MEDIUM","TF-KMS-001",id,`KMS key ${id}: key rotation disabled`,
          "enable_key_rotation = true enables automatic annual rotation of the key material. Recommended by CIS AWS Benchmark 3.8. Reduces risk of key compromise over time.",
          "T1552","CWE-326");
      const win = parseInt(a("deletion_window_in_days") || "30");
      if (win < 14)
        push("LOW","TF-KMS-002",id,`KMS key ${id}: deletion window ${win} days (< 14 recommended)`,
          "A short deletion window increases risk of accidental permanent key deletion. Set deletion_window_in_days ≥ 14 to allow recovery from accidental delete.",
          "T1485","CWE-400");
    }

    // ── Security Groups ───────────────────────────────────────────────────
    if (r.type === "aws_security_group" || r.type === "aws_security_group_rule") {
      const isIngress = b.includes("ingress") || r.type === "aws_security_group_rule" && a("type") === "ingress";
      const publicCIDR = b.includes('"0.0.0.0/0"') || b.includes('"::/"') || b.includes('"::/0"');
      if (publicCIDR && isIngress) {
        const fromPortM = b.match(/from_port\s*=\s*(\d+)/m);
        const port = fromPortM ? parseInt(fromPortM[1]) : -1;
        if (port === 22)
          push("CRITICAL","TF-SG-001",id,`Security group ${id}: SSH (port 22) open to 0.0.0.0/0`,
            "SSH should never be open to the internet. Restrict to VPN gateway or bastion host CIDR. Use AWS Systems Manager Session Manager as an alternative to SSH entirely.",
            "T1021.004","CWE-284");
        else if (port === 3389)
          push("CRITICAL","TF-SG-002",id,`Security group ${id}: RDP (port 3389) open to 0.0.0.0/0`,
            "RDP open to the internet is the #1 initial access vector for ransomware. Restrict to VPN CIDR only. Consider replacing with SSM Fleet Manager for remote desktop.",
            "T1021.001","CWE-284");
        else if ([3306,5432,1433,27017,6379,9200,5984,6380].includes(port))
          push("CRITICAL","TF-SG-003",id,`Security group ${id}: database port ${port} open to 0.0.0.0/0`,
            `Database port ${port} is publicly accessible. Database ports should never be reachable from the internet — restrict to the application tier Security Group reference only.`,
            "T1190","CWE-284");
        else if (port === 0 || port === -1)
          push("HIGH","TF-SG-004",id,`Security group ${id}: unrestricted public ingress (all ports)`,
            "Ingress rule allows all ports from 0.0.0.0/0 creating maximum attack surface. Restrict to specific ports required for application function.",
            "T1190","CWE-284");
        else if (port > 0)
          push("MEDIUM","TF-SG-005",id,`Security group ${id}: port ${port} open to 0.0.0.0/0`,
            `Port ${port} is open to the internet. Verify this is intentional (e.g., port 80/443 for web traffic). If not, restrict source to known CIDRs.`,
            "T1190","CWE-284");
      }
    }

    // ── EC2 Instances ─────────────────────────────────────────────────────
    if (r.type === "aws_instance") {
      if (a("associate_public_ip_address") === "true")
        push("MEDIUM","TF-EC2-001",id,`EC2 ${id}: public IP association enabled`,
          "associate_public_ip_address = true makes the instance directly reachable from the internet if Security Groups allow it. Place instances behind ALB in private subnets instead.",
          "T1190","CWE-284");
      const httpTokens = a("http_tokens");
      if (!b.includes("metadata_options") || !httpTokens || httpTokens !== "required")
        push("HIGH","TF-EC2-002",id,`EC2 ${id}: IMDSv1 may be active (http_tokens not required)`,
          "IMDSv1 allows any SSRF vulnerability to retrieve IAM role credentials without a session token. Set metadata_options { http_tokens = required } to enforce IMDSv2 on all instances.",
          "T1552.005","CWE-306");
    }

    // ── EBS Volumes ───────────────────────────────────────────────────────
    if (r.type === "aws_ebs_volume") {
      if (!b.includes("encrypted") || a("encrypted") === "false")
        push("MEDIUM","TF-EBS-001",id,`EBS volume ${id}: not encrypted`,
          "encrypted = true should be set for all EBS volumes. Unencrypted volumes can be copied and read if snapshots are shared or infrastructure is compromised.",
          "T1530","CWE-311");
    }

    // ── IAM Policies (pave-layer-aware) ────────────────────────────────────
    if (r.type === "aws_iam_policy" || r.type === "aws_iam_role_policy") {
      const hasWildcardAction = b.includes('"*"') && (b.includes('"Action"') || b.includes('"actions"'));
      const hasIamStar = /["']iam:\*["']/.test(b) || (b.includes('"iam:*"'));
      const hasStsStar = /sts:AssumeRole[^"]*\*/.test(b) || b.includes('"sts:*"');
      const hasS3Star  = b.includes('"s3:*"') && b.includes('"*"') && b.includes('"Resource"');
      const hasBoundaryRef = b.includes("permissions_boundary") || b.includes("iam_permissions_boundary");

      if (hasIamStar)
        push("CRITICAL","TF-IAM-001a",id,`IAM ${id}: iam:* wildcard — permission hierarchy escape`,
          'iam:* allows creating new roles, modifying permission boundaries, and attaching admin policies. This breaks the pave-layer hierarchy entirely — a compromised principal can grant itself or others unlimited access regardless of SCP guardrails. Remove iam:* and replace with only the specific IAM actions absolutely required (e.g. iam:PassRole on specific role ARNs).',
          "T1078","CWE-269");
      else if (hasStsStar)
        push("CRITICAL","TF-IAM-001b",id,`IAM ${id}: sts:AssumeRole or sts:* on wildcard resource — cross-account pivot`,
          'Wildcard sts:AssumeRole allows assuming ANY role in ANY account where the trust policy permits. In a pave architecture this enables cross-layer privilege escalation. Restrict to specific target role ARNs with aws:PrincipalOrgID and aws:ResourceOrgID conditions.',
          "T1078","CWE-269");
      else if (hasWildcardAction) {
        const sev = hasBoundaryRef ? "MEDIUM" : "HIGH";
        push(sev,"TF-IAM-001",id,`IAM ${id}: wildcard Action (*) in policy${hasBoundaryRef ? " (permission boundary present — review for pave-layer compliance)" : " — no permission boundary detected"}`,
          hasBoundaryRef
            ? 'Policy has Action:"*" but a permission boundary reference was detected. In a pave-layer architecture, wildcard actions can be acceptable at Layer 4 (service layer) when bounded by SCPs + permission boundaries scoped to a specific service and resource prefix. Verify: (1) boundary policy excludes iam:* and sts:AssumeRole *, (2) Resource ARN is scoped to team-specific prefix, not "*".'
            : 'Policy has Action:"*" with no permission boundary detected. In a pave-layer architecture this is HIGH risk — without a permission boundary ceiling, any principal with this policy can perform all AWS actions. Add permissions_boundary to the associated aws_iam_role and scope Resource to specific ARN prefixes.',
          "T1078","CWE-269");
      }
      if (hasS3Star)
        push("HIGH","TF-IAM-002",id,`IAM ${id}: s3:* on wildcard resource — state file exfiltration risk`,
          'Wildcard s3:* Resource:"*" grants access to all S3 buckets including terraform.tfstate files from other workspaces, which contain all Terraform outputs including sensitive values. Restrict to specific bucket ARNs/prefixes: arn:aws:s3:::my-team-bucket/* and explicitly deny access to state buckets.',
          "T1530","CWE-732");
    }

    // ── IAM Roles (pave-layer boundary check) ─────────────────────────────
    if (r.type === "aws_iam_role") {
      const hasBoundary = b.includes("permissions_boundary");
      const hasTrustWildcard = b.includes('"Principal"') && b.includes('"*"');
      const hasOidcTrust = b.includes("Federated") && (b.includes("oidc") || b.includes("token.actions.githubusercontent.com") || b.includes("app.terraform.io"));
      const hasWildcardSub = hasOidcTrust && (b.includes('"sub": "*"') || b.includes("sub:\"*\"") || b.includes("sub: \"*\""));

      if (hasTrustWildcard)
        push("CRITICAL","TF-IAM-003",id,`IAM role ${id}: trust policy allows Principal:"*" — any AWS principal can assume`,
          'Principal:"*" in a role trust policy allows any AWS account, user, or service to request AssumeRole. Restrict Principal to specific account ARNs, service principals, or OIDC federated providers. Add aws:PrincipalOrgID condition to restrict to your organization.',
          "T1078","CWE-284");
      if (hasWildcardSub)
        push("CRITICAL","TF-IAM-004",id,`IAM role ${id}: OIDC trust has wildcard sub-claim — any repo/workspace can assume`,
          'A wildcard (*) sub-claim condition allows ANY GitHub repository or TFE workspace to assume this role. This is a critical misconfiguration in CI/CD pipelines — any attacker with access to the OIDC provider can assume the role. Scope sub-claim to specific repo path (repo:org/repo:ref:refs/heads/main) or TFE workspace ID.',
          "T1078","CWE-290");
      if (!hasBoundary && !b.includes("aws:iam::aws:policy/service-role"))
        push("MEDIUM","TF-IAM-005",id,`IAM role ${id}: no permissions_boundary — uncapped privilege ceiling`,
          'In a pave-layer architecture, all roles created by product/service-layer Terraform should have a permissions_boundary attached. Without it, the role\'s effective permissions are bounded only by what identity policies grant — no ceiling. Add permissions_boundary = data.aws_iam_policy.pave_boundary.arn or the appropriate organizational boundary policy ARN.',
          "T1078","CWE-269");
    }

    // ── OIDC Provider ─────────────────────────────────────────────────────
    if (r.type === "aws_iam_openid_connect_provider") {
      if (!b.includes("thumbprint_list") || b.includes('thumbprint_list = []'))
        push("HIGH","TF-IAM-006",id,`OIDC provider ${id}: empty or missing thumbprint_list`,
          'OIDC provider without a valid thumbprint list may not validate the OIDC server TLS certificate. Provide the correct thumbprint for the OIDC issuer (GitHub: 6938fd4d98bab03faadb97b34396831e3780aea1).',
          "T1556","CWE-295");
    }

    // ── Load Balancers ────────────────────────────────────────────────────
    if (r.type === "aws_lb" || r.type === "aws_alb") {
      if (!b.includes("access_logs") || a("enabled") === "false")
        push("LOW","TF-LB-001",id,`Load balancer ${id}: access logging not configured`,
          "ALB access logs record all requests including source IP, latency, and target responses. Essential for forensics and detecting attack patterns. Enable with an S3 destination.",
          "T1562.008","CWE-778");
    }

    // ── ElastiCache ───────────────────────────────────────────────────────
    if (r.type === "aws_elasticache_replication_group") {
      if (!b.includes("transit_encryption_enabled") || a("transit_encryption_enabled") === "false")
        push("MEDIUM","TF-CACHE-001",id,`ElastiCache replication group ${id}: transit encryption disabled`,
          "transit_encryption_enabled = true encrypts data between Redis clients and nodes. Without it, data is transmitted in plaintext within the VPC.",
          "T1530","CWE-311");
      if (!b.includes("at_rest_encryption_enabled") || a("at_rest_encryption_enabled") === "false")
        push("MEDIUM","TF-CACHE-002",id,`ElastiCache replication group ${id}: at-rest encryption disabled`,
          "at_rest_encryption_enabled = true enables encryption of data stored on Redis nodes. Required for compliance with HIPAA, PCI-DSS.",
          "T1530","CWE-311");
    }

    // ── EKS ───────────────────────────────────────────────────────────────
    if (r.type === "aws_eks_cluster") {
      if (!b.includes("endpoint_private_access") || a("endpoint_private_access") === "false")
        push("MEDIUM","TF-EKS-001",id,`EKS ${id}: private endpoint access not enabled`,
          "endpoint_private_access = true ensures kubectl traffic stays within the VPC. With only public endpoint, all Kubernetes API server traffic traverses the public internet.",
          "T1190","CWE-284");
      if (b.includes("endpoint_public_access") && a("endpoint_public_access") === "true" && !b.includes("public_access_cidrs"))
        push("HIGH","TF-EKS-002",id,`EKS ${id}: public endpoint with no CIDR restriction`,
          "Public Kubernetes API server without public_access_cidrs restriction allows anyone to attempt authentication against the API server. Restrict to known admin CIDRs.",
          "T1190","CWE-284");
    }

    // ── CloudTrail ────────────────────────────────────────────────────────
    if (r.type === "aws_cloudtrail") {
      if (!b.includes("is_multi_region_trail") || a("is_multi_region_trail") === "false")
        push("MEDIUM","TF-TRAIL-001",id,`CloudTrail ${id}: not configured as multi-region trail`,
          "is_multi_region_trail = true enables logging across all AWS regions. Single-region trails miss API calls in other regions, creating blind spots. CIS AWS Benchmark 3.1.",
          "T1562.008","CWE-778");
      if (!b.includes("include_global_service_events") || a("include_global_service_events") === "false")
        push("MEDIUM","TF-TRAIL-002",id,`CloudTrail ${id}: global service events not included`,
          "include_global_service_events = true captures IAM, STS, and CloudFront events that are global. Without this, IAM activity may not be logged.",
          "T1562.008","CWE-778");
      if (!b.includes("log_file_validation_enabled") || a("log_file_validation_enabled") === "false")
        push("LOW","TF-TRAIL-003",id,`CloudTrail ${id}: log file validation disabled`,
          "log_file_validation_enabled = true creates SHA-256 digest files to detect tampering or deletion of CloudTrail log files. Supports non-repudiation requirements.",
          "T1562.008","CWE-778");
    }
  });

  // ── Architecture-level gap checks (missing resources) ──────────────────
  if (resources.some(r => r.type === "aws_s3_bucket") && !types.has("aws_s3_bucket_public_access_block"))
    push("HIGH","TF-ARCH-001","architecture",
      "S3 buckets present but no aws_s3_bucket_public_access_block resource found",
      "All S3 buckets require explicit public access blocks. Without this resource, buckets inherit account-level settings which may not be restrictive. Add aws_s3_bucket_public_access_block for each bucket.",
      "T1530","CWE-732");
  if (resources.some(r => r.type === "aws_lambda_function") && !types.has("aws_cloudwatch_log_group"))
    push("MEDIUM","TF-ARCH-002","architecture",
      "Lambda function(s) present but no aws_cloudwatch_log_group resource found",
      "Lambda auto-creates log groups without retention policies or encryption. Define aws_cloudwatch_log_group resources explicitly with retention_in_days and kms_key_id for compliance.",
      "T1562.008","CWE-778");
  if (!types.has("aws_cloudtrail") && resources.length > 3)
    push("HIGH","TF-ARCH-003","architecture",
      "No aws_cloudtrail resource defined — API audit logging may not be managed",
      "CloudTrail is not managed by this Terraform configuration. Verify it is configured outside this code. All AWS API calls should be logged to detect unauthorized access and satisfy compliance requirements.",
      "T1562.008","CWE-778");
  if (!types.has("aws_guardduty_detector") && resources.length > 3)
    push("MEDIUM","TF-ARCH-004","architecture",
      "No aws_guardduty_detector resource found",
      "AWS GuardDuty provides ML-based threat detection for credential compromise, reconnaissance, and data exfiltration. Not managing it in Terraform risks it being unconfigured or disabled.",
      "T1562.008","CWE-778");
  if (resources.some(r => ["aws_lb","aws_alb","aws_api_gateway_rest_api","aws_apigatewayv2_api"].includes(r.type)) &&
      !types.has("aws_wafv2_web_acl"))
    push("MEDIUM","TF-ARCH-005","architecture",
      "Public-facing endpoints detected but no aws_wafv2_web_acl found",
      "Load balancers and API Gateways are internet-facing attack surfaces. AWS WAF v2 with managed rule groups (AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet) provides OWASP Top 10 protection.",
      "T1190","CWE-284");
  if (resources.some(r => r.type === "aws_db_instance" || r.type === "aws_rds_cluster") && !types.has("aws_backup_vault"))
    push("MEDIUM","TF-ARCH-006","architecture",
      "Database(s) detected but no aws_backup_vault resource found",
      "AWS Backup provides centralized backup management with Vault Lock for immutable backups. Without it, database backups may not meet RPO/RTO requirements or be protected from ransomware deletion.",
      "T1485","CWE-400");

  // ── Variable security checks ────────────────────────────────────────────
  variables.forEach(v => {
    const lower = v.name.toLowerCase();
    if (v.hasDefault && /password|secret|key|token|credential|private_key|api_key/.test(lower))
      push("HIGH","TF-VAR-001",`var.${v.name}`,
        `Variable '${v.name}' appears sensitive but has a default value`,
        "Sensitive variables (passwords, keys, tokens) must not have default values. This risks hardcoding credentials in code or passing them through insecure channels. Use Secrets Manager integration or mark sensitive=true with no default.",
        "T1552","CWE-798");
  });

  // Sort by severity
  const order = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
  return findings.sort((a,b) => (order[a.sev]??4) - (order[b.sev]??4));
}

// Identify trust boundaries from actual resource set
function identifyTrustBoundaries(resources) {
  const types = resources.map(r => r.type);
  const has = (...ts) => ts.some(t => types.includes(t));
  const boundaries = [];
  if (has("aws_internet_gateway"))
    boundaries.push({ zone:"Internet ↔ AWS VPC", type:"Network", risk:"HIGH",
      desc:"Internet Gateway establishes the external-to-internal boundary. ALL traffic from the public internet enters your VPC here. Every resource reachable from this boundary must be protected by Security Groups, NACLs, and application-layer controls (WAF).",
      control:"WAF (aws_wafv2_web_acl), NACLs (aws_network_acl), Security Groups, AWS Shield" });
  if (has("aws_nat_gateway"))
    boundaries.push({ zone:"Public Subnet ↔ Private Subnet", type:"Network", risk:"MEDIUM",
      desc:"NAT Gateway creates an asymmetric boundary — private resources initiate outbound connections but cannot receive unsolicited inbound traffic from the internet. Enforces trust zone separation between presentation and application/data tiers.",
      control:"Route tables (private subnet → NAT only), NACLs denying direct internet inbound to private subnets" });
  if (has("aws_organizations_organization","aws_organizations_policy","aws_organizations_organizational_unit"))
    boundaries.push({ zone:"AWS Organization ↔ Member Accounts", type:"Identity", risk:"HIGH",
      desc:"SCPs define the maximum permissions possible within member accounts — no IAM policy in a member account can exceed SCP boundaries. Cross-account trust is established via sts:AssumeRole with explicit trust policies.",
      control:"Service Control Policies (aws_organizations_policy), aws:PrincipalOrgID condition key, cross-account role conditions" });
  if (types.some(t => t.startsWith("xsphere_")))
    boundaries.push({ zone:"xSphere Private Cloud ↔ AWS", type:"Hybrid", risk:"HIGH",
      desc:"Hybrid trust boundary between dedicated private cloud infrastructure and AWS public cloud. Traffic crosses this boundary via Direct Connect or IPSec VPN. Authentication and network controls must exist on both sides of this boundary.",
      control:"Direct Connect (aws_dx_connection), VPN Gateway (aws_vpn_gateway), firewall rules, network ACLs on both platforms" });
  if (has("aws_vpc_peering_connection","aws_transit_gateway","aws_transit_gateway_vpc_attachment"))
    boundaries.push({ zone:"Cross-VPC / Transit Gateway", type:"Network", risk:"MEDIUM",
      desc:"VPC peering or Transit Gateway creates inter-VPC connectivity. Traffic between VPCs must traverse route tables and Security Groups — it does NOT automatically inherit the security controls of either VPC. Least-privilege routing required.",
      control:"Security group cross-SG references, NACLs on peered VPC subnets, Transit Gateway route tables with explicit allowed CIDRs" });
  if (types.some(t => t.includes("iam_role") || t.includes("iam_policy")))
    boundaries.push({ zone:"IAM Identity & Authorization Boundary", type:"Identity", risk:"HIGH",
      desc:"IAM defines trust relationships between every actor and every AWS resource. Every API call crosses an IAM boundary. This is the primary control plane for cloud security — misconfigurations here directly expand attack surface across all other boundaries.",
      control:"Least privilege policies, permission boundaries (aws_iam_role.permissions_boundary), IAM conditions, SCP guardrails, IAM Access Analyzer" });
  if (types.some(t => t.includes("lambda") || t.includes("ecs_task") || t.includes("eks_")))
    boundaries.push({ zone:"Compute Execution Isolation Boundary", type:"Execution", risk:"MEDIUM",
      desc:"Serverless functions (Lambda), container tasks (ECS), and Kubernetes pods execute in isolated environments. The execution role defines what AWS services that code can reach. Container escape attacks can cross this boundary to reach the underlying instance profile.",
      control:"Lambda execution role scoping, ECS task role (not task execution role) least privilege, EKS pod security standards, seccomp profiles, no privileged containers" });
  if (has("aws_api_gateway_rest_api","aws_apigatewayv2_api"))
    boundaries.push({ zone:"API Gateway Authorization Boundary", type:"Application", risk:"HIGH",
      desc:"API Gateway is the enforcement point for authentication and authorization on all API calls. It separates anonymous internet callers from authenticated backend services. Authorizer misconfigurations bypass this boundary entirely.",
      control:"IAM authorizers or Cognito User Pool authorizers on all non-public methods, WAF association, request throttling, API key enforcement" });
  return boundaries;
}

// Build plain-English architecture narrative from parsed data
function buildArchitectureNarrative(tierGroups, surf, modules, remoteStates, files) {
  const lines = [];
  const tiers = Object.keys(tierGroups).filter(k => tierGroups[k]?.length > 0);
  const total = Object.values(tierGroups).flat().length;

  lines.push(`This Terraform configuration declares ${total} managed resource(s) across ${tiers.length} infrastructure tier(s), parsed from ${files.length} file(s).`);

  if (tierGroups.xsphere?.length)
    lines.push(`Private Cloud Foundation (xSphere): ${tierGroups.xsphere.length} xSphere resource(s) define dedicated private cloud infrastructure — VMs, clusters, datastores, and virtual networks running in isolated US-based data centers. This forms the on-premises anchor of the hybrid architecture, communicating with AWS via Direct Connect or VPN.`);

  if (tierGroups.org?.length)
    lines.push(`AWS Governance Layer (Organizations): ${tierGroups.org.length} organization-level resource(s) establish multi-account governance. SCPs define the absolute maximum permission boundaries for all member accounts — no IAM policy can exceed SCP restrictions regardless of how permissive it is.`);

  if (tierGroups.security?.length) {
    const iamCount = surf.iam.length, kmsCount = surf.kms.length;
    lines.push(`Identity & Security Controls: ${tierGroups.security.length} security resource(s) including ${iamCount} IAM principal/policy resource(s)${kmsCount ? ` and ${kmsCount} KMS encryption key(s)` : ""}. This tier is the authorization control plane — every resource access decision flows through IAM. Compromising a high-privilege IAM role is equivalent to a full account takeover.`);
  }

  if (tierGroups.cicd?.length)
    lines.push(`CI/CD Automation (Pipeline): ${tierGroups.cicd.length} CI/CD resource(s) automate infrastructure deployment. The CI/CD pipeline IAM role typically has broad deployment permissions — this makes the pipeline itself a high-value target for supply chain attacks. Any injected Terraform or pipeline code runs with these elevated permissions.`);

  if (tierGroups.network?.length) {
    const hasIGW = resources => resources?.some(r => r.type === "aws_internet_gateway");
    const hasNAT = resources => resources?.some(r => r.type === "aws_nat_gateway");
    const netRes = tierGroups.network;
    lines.push(`Network Architecture (VPC): ${netRes.length} network resource(s)${hasIGW(netRes) ? " including an Internet Gateway providing external connectivity" : ""}${hasNAT(netRes) ? " and a NAT Gateway enabling private subnet egress without direct internet exposure" : ""}. Security groups provide stateful micro-segmentation at the resource level while NACLs provide stateless subnet-level controls.`);
  }

  if (tierGroups.compute?.length) {
    const parts = [];
    if (surf.lb.length) parts.push(`${surf.lb.length} load balancer(s) as public entry points`);
    if (surf.apigw.length) parts.push(`${surf.apigw.length} API Gateway endpoint(s)`);
    if (surf.lambda.length) parts.push(`${surf.lambda.length} Lambda function(s)`);
    if (surf.eks.length) parts.push(`${surf.eks.length} EKS/Kubernetes cluster(s)`);
    lines.push(`Compute & APIs: ${tierGroups.compute.length} compute resource(s)${parts.length ? " including " + parts.join(", ") : ""}. The compute tier processes application logic and is the primary target for execution-based attacks. Each compute unit's IAM execution role defines its lateral movement potential.`);
  }

  if (tierGroups.storage?.length) {
    const parts = [];
    if (surf.s3.length) parts.push(`${surf.s3.length} S3 bucket(s)`);
    if (surf.rds.length) parts.push(`${surf.rds.length} relational database(s)`);
    if (surf.dynamo.length) parts.push(`${surf.dynamo.length} DynamoDB table(s)`);
    lines.push(`Data Storage: ${tierGroups.storage.length} storage resource(s)${parts.length ? " including " + parts.join(", ") : ""}. The storage tier holds the data assets most valuable to adversaries — encryption at rest, access logging, and strict IAM controls are critical. Terraform state files stored in S3 may also contain sensitive connection strings and credentials.`);
  }

  if (modules.length)
    lines.push(`Terraform Modularity: ${modules.length} module reference(s) abstract infrastructure patterns. Modules sourced from public registries introduce supply chain risk if versions are not pinned — a malicious module update could inject unauthorized resources or IAM permissions.`);

  if (remoteStates.length)
    lines.push(`Cross-Stack Dependencies: ${remoteStates.length} remote state reference(s) create runtime dependencies on upstream stack outputs. Remote state access bypasses standard resource dependency graphs — the S3 bucket holding remote state is a critical asset requiring strict access controls.`);

  return lines;
}

// STRIDE-LM threat analysis mapped to each detected tier
function buildStrideLMByTier(tierGroups) {
  const result = [];
  const CATS = [
    { cat:"S",  label:"Spoofing" },
    { cat:"T",  label:"Tampering" },
    { cat:"R",  label:"Repudiation" },
    { cat:"I",  label:"Information Disclosure" },
    { cat:"D",  label:"Denial of Service" },
    { cat:"E",  label:"Elevation of Privilege" },
    { cat:"LM", label:"Lateral Movement" },
  ];

  if (tierGroups.security?.length)
    result.push({ tier:"Security · IAM · KMS", color:"#C62828", cats:[
      { cat:"S",  threats:["Unauthorized sts:AssumeRole via overly broad trust policy (Principal: '*' or missing conditions)","OIDC provider with weak aud/sub conditions enabling token substitution attack"] },
      { cat:"T",  threats:["iam:PutRolePolicy or iam:CreatePolicyVersion used to inject backdoor permissions into existing roles","KMS key policy modified to disable encryption for attacker-controlled principal"] },
      { cat:"R",  threats:["Secrets Manager GetSecretValue calls with no CloudTrail data events configured — no audit trail of secret access","IAM role activity in regions without CloudTrail enabled losing cross-region visibility"] },
      { cat:"I",  threats:["SSM Parameter Store SecureString accessed by over-permissioned execution role — plaintext value exposed","Secrets Manager secret read without resource-based policy restricting access to specific IAM principals"] },
      { cat:"D",  threats:["aws:kms DeleteKey call destroying customer-managed KMS key — all encrypted data rendered unreadable","IAM policy attachment locking out legitimate administrators from account (attacker deletes IAM recovery paths)"] },
      { cat:"E",  threats:["iam:CreatePolicyVersion replacing restrictive policy with AdministratorAccess — full account takeover in one API call","sts:AssumeRole misconfiguration allowing cross-account escalation from less-privileged account"] },
      { cat:"LM", threats:["Compromised IAM role with sts:AssumeRole permissions used to pivot into multiple AWS accounts simultaneously","IAM role chaining: Lambda role → assume secondary role with broader permissions → access RDS, S3, ECS cluster"] },
    ]});

  if (tierGroups.network?.length)
    result.push({ tier:"Network · VPC · Security Groups", color:"#6A1B9A", cats:[
      { cat:"S",  threats:["IP address spoofing within VPC to bypass security group source-IP-based rules (mitigate: use SG-to-SG references)","VPN Pre-Shared Key compromise enabling man-in-the-middle on hybrid connection"] },
      { cat:"T",  threats:["Unauthorized aws_route_table modification redirecting subnet traffic through attacker-controlled EC2 instance","Security group ingress rule modification opening previously restricted ports to public internet"] },
      { cat:"R",  threats:["VPC Flow Logs disabled or not covering all ENIs — network traffic patterns unrecoverable for forensic investigation","No NACL change CloudTrail logging — unauthorized rule modifications undetected until audit"] },
      { cat:"I",  threats:["IMDSv1 accessible from within VPC enabling SSRF → credential exfiltration without additional authentication","Unrestricted egress rules (all traffic 0.0.0.0/0) enabling data exfiltration over any protocol/port"] },
      { cat:"D",  threats:["NACL misconfiguration blocking legitimate application traffic causing cascading availability failure","Security group rule quota exhaustion (60 rules/SG default) preventing addition of emergency security rules"] },
      { cat:"E",  threats:["VPC endpoint policy allowing access beyond intended service scope — enables access to services in other accounts","Transit Gateway route table misconfiguration providing access to isolated network segments"] },
      { cat:"LM", threats:["VPC peering without NACL restrictions allows unrestricted east-west traffic between all resources in both VPCs","Transit Gateway all-to-all route table enables lateral movement between production, staging, and development VPCs"] },
    ]});

  if (tierGroups.compute?.length)
    result.push({ tier:"Compute · Lambda · API Gateway · EKS", color:"#1B5E20", cats:[
      { cat:"S",  threats:["API Gateway with authorization=NONE on sensitive methods — any internet user can invoke backend resources","Lambda function URL without auth_type=AWS_IAM accessible from public internet without any authentication"] },
      { cat:"T",  threats:["Lambda code update (UpdateFunctionCode) replacing approved function with backdoored version","ALB listener rule modification redirecting production traffic to attacker-controlled target group"] },
      { cat:"R",  threats:["Lambda execution without an aws_cloudwatch_log_group resource — auto-created log group has no retention or KMS encryption","API Gateway access logging disabled — no record of caller IP, request path, authentication status, or response code"] },
      { cat:"I",  threats:["Lambda environment variable containing plaintext API key/password readable via GetFunctionConfiguration API","EC2 IMDSv1 SSRF: any application vulnerability in the compute layer can retrieve the instance IAM role credentials"] },
      { cat:"D",  threats:["Lambda reserved_concurrent_executions not set — single event source can consume all account concurrency quota","ALB connection table exhaustion via SYN flood if AWS Shield Standard is insufficient for attack volume"] },
      { cat:"E",  threats:["Lambda execution role with iam:* or broad resource permissions — function invocation equivalent to console admin access","ECS task role (not execution role) with access to iam:PassRole enables in-container privilege escalation"] },
      { cat:"LM", threats:["Lambda execution role with access to RDS, Secrets Manager, S3, and SQS enables multi-service data exfiltration in single execution","EKS pod escape via privileged container → node EC2 instance profile → full VPC resource access"] },
    ]});

  if (tierGroups.storage?.length)
    result.push({ tier:"Storage · Databases · S3", color:"#0D47A1", cats:[
      { cat:"S",  threats:["S3 presigned URL shared beyond intended audience — valid for URL TTL regardless of IAM policy changes","RDS credentials shared between multiple application services losing per-service identity accountability"] },
      { cat:"T",  threats:["S3 object overwrite without versioning enabled — original data unrecoverable after malicious overwrite","RDS data modification by over-permissioned application execution role — no row-level access control at IAM level"] },
      { cat:"R",  threats:["S3 server access logging or CloudTrail S3 data events not enabled — GetObject/PutObject calls untracked","DynamoDB read/write operations without CloudTrail data events — no audit of what data was accessed or modified"] },
      { cat:"I",  threats:["S3 bucket without Block Public Access — bucket policy or ACL misconfiguration immediately exposes all objects to internet","RDS snapshot shared cross-account or made public — complete database copy accessible to unauthorized parties"] },
      { cat:"D",  threats:["S3 Glacier storage class change on critical objects by attacker — data retrieval takes hours, effective operational DoS","DynamoDB capacity (RCU/WCU) exhaustion via write-heavy attack consuming provisioned throughput, blocking application"] },
      { cat:"E",  threats:["Terraform state file in S3 contains sensitive output values (DB passwords, private keys, connection strings) in plaintext — state file read = credentials exfiltration"] },
      { cat:"LM", threats:["Application database credentials in S3 state file read → direct RDS connection → lateral movement to data layer","Lambda role accessing S3 + RDS + DynamoDB in single execution — compromise of one service exposes all three data stores"] },
    ]});

  if (tierGroups.org?.length)
    result.push({ tier:"AWS Organizations · SCPs", color:"#B71C1C", cats:[
      { cat:"S",  threats:["AWS Management Account credential compromise — affects all member accounts simultaneously; no SCP restricts management account","Delegated administrator account compromise (Security Hub, GuardDuty) — attacker gains visibility into org-wide findings"] },
      { cat:"T",  threats:["SCP policy content modification to remove security guardrails (delete deny statements) across all member accounts instantly","OU membership change moving account to less-restricted OU to bypass security SCPs"] },
      { cat:"R",  threats:["Organization-level CloudTrail disabled — API logging lost across all member accounts simultaneously — complete audit gap"] },
      { cat:"I",  threats:["Resource-based policy approved at Org level granting cross-account data access beyond intended scope"] },
      { cat:"E",  threats:["Management account IAM escalation affects delegated admin accounts — single privilege escalation has org-wide impact"] },
      { cat:"LM", threats:["Single management account compromise enables attacker to call sts:AssumeRole in ANY member account — entire AWS organization compromised via one account"] },
    ]});

  if (tierGroups.cicd?.length)
    result.push({ tier:"CI/CD · Jenkins · IaC Pipeline", color:"#BF360C", cats:[
      { cat:"S",  threats:["Typosquatted Terraform module name on public registry (terraform-aws-module vs terraform-aws-modules) — malicious module impersonates legitimate one","Webhook secret compromise enabling injection of unauthorized pipeline triggers appearing as legitimate source events"] },
      { cat:"T",  threats:["Terraform plan/apply output manipulation in pipeline — injecting resource modifications between plan approval and apply execution","Build artifact replacement in S3 between approval stage and deployment stage — substituting signed binary with backdoored version"] },
      { cat:"R",  threats:["No pipeline execution audit log — cannot determine who approved or triggered deployments during incident investigation","Direct Terraform state file modification (terraform state rm, state mv) without pipeline — bypasses review and leaves no commit history"] },
      { cat:"I",  threats:["CI/CD environment variables containing AWS access keys logged in pipeline output — credentials exposed in log storage","Terraform state file read from S3 by pipeline runner exposing sensitive outputs to all users with pipeline log access"] },
      { cat:"E",  threats:["CI/CD pipeline IAM role with deployment permissions is de-facto admin access — any pipeline code injection escalates to full infrastructure control"] },
      { cat:"LM", threats:["Pipeline execution role deployed across multiple AWS accounts enabling single pipeline compromise to modify all environments simultaneously"] },
    ]});

  if (tierGroups.xsphere?.length)
    result.push({ tier:"xSphere Private Cloud", color:"#0277BD", cats:[
      { cat:"S",  threats:["xSphere administrator credential compromise — full control of all VMs on private cloud infrastructure","VM impersonation via snapshot clone — attacker creates duplicate of legitimate VM with different IP"] },
      { cat:"T",  threats:["Direct VM disk modification at hypervisor level bypassing OS-level controls","xSphere template modification injecting malicious code into base images for all new VMs"] },
      { cat:"R",  threats:["xSphere API access without centralized logging — VM operations (create, delete, snapshot) untracked"] },
      { cat:"I",  threats:["VM memory snapshot contains credentials, session tokens, and encryption keys in plaintext — offline extraction possible"] },
      { cat:"D",  threats:["Storage array failure or misconfiguration causing mass VM outage — no Multi-AZ equivalent in single private cloud"] },
      { cat:"E",  threats:["Hypervisor-level access bypasses all VM-level security controls — guest OS isolation depends on hypervisor integrity"] },
      { cat:"LM", threats:["xSphere admin access enables lateral movement to AWS by accessing Direct Connect configuration and VPN credentials"] },
    ]});

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// KNOWLEDGE BASE CONTEXT MINING
// Extracts structured signals from userDocs content to augment the threat model.
// Returns a docContext object that generateAnalysis injects as additional signals.
// ─────────────────────────────────────────────────────────────────────────────
// Per-doc role classifier: identifies what role each document plays in the architecture
function classifyDoc(doc) {
  const name = (doc.name || "").toLowerCase();
  const ext  = name.split(".").pop();
  const text = (doc.content || "").toLowerCase().substring(0, 8000); // first 8KB for classification

  const roles = [];

  // Classify by filename patterns
  if (/readme|overview|architecture|design|hld|lld|adr/.test(name))       roles.push("architecture-doc");
  if (/runbook|playbook|incident|ops|operation/.test(name))                roles.push("runbook");
  if (/security|threat|risk|pentest|vuln|cve/.test(name))                 roles.push("security-doc");
  if (/pipeline|ci|cd|deploy|release|workflow/.test(name))                roles.push("pipeline-doc");
  if (/iam|policy|role|permission|access|rbac/.test(name))                roles.push("iam-doc");
  if (/network|vpc|subnet|routing|firewall|sg/.test(name))                roles.push("network-doc");
  if (/database|rds|dynamo|redis|aurora|db/.test(name))                   roles.push("database-doc");
  if (/monitor|alarm|alert|cloudwatch|grafana|datadog/.test(name))        roles.push("monitoring-doc");
  if (/compliance|fedramp|hipaa|pci|soc|iso|nist/.test(name))            roles.push("compliance-doc");
  if (/tfvars|variables|vars/.test(name) || ext === "tfvars")             roles.push("tf-variables");
  if (/output|export|interface/.test(name))                               roles.push("tf-outputs");
  if (ext === "json" && /policy|trust|assume/.test(name))                 roles.push("iam-policy-json");
  if (ext === "yaml" || ext === "yml") {
    if (/github|workflow|action/.test(name))                              roles.push("github-actions");
    else if (/jenkins|pipeline/.test(name))                               roles.push("jenkinsfile");
    else if (/k8s|kube|deploy|service|ingress/.test(name))               roles.push("k8s-manifest");
    else                                                                   roles.push("yaml-config");
  }
  if (ext === "json") {
    if (/package/.test(name))                                              roles.push("npm-package");
    else                                                                   roles.push("json-config");
  }
  if (ext === "md" || ext === "txt")                                       roles.push("documentation");
  if (ext === "pdf")                                                        roles.push("documentation");
  if (ext === "py")                                                         roles.push("python-script");
  if (ext === "sh" || ext === "bash")                                       roles.push("shell-script");
  if (ext === "groovy" || name === "jenkinsfile")                           roles.push("jenkinsfile");
  if (ext === "tf" || ext === "hcl")                                        roles.push("terraform");
  if (ext === "sentinel")                                                   roles.push("sentinel-policy");

  // Classify by content if no strong filename signal
  if (!roles.length) {
    if (/resource\s+"aws_|resource\s+"xsphere_/.test(text))              roles.push("terraform");
    if (/pipeline\s*\{|stage\s*\{|steps\s*\{/.test(text))               roles.push("pipeline-doc");
    if (/apiversion:|kind:\s*(deployment|service|ingress)/i.test(text))  roles.push("k8s-manifest");
    if (/Statement.*Action.*Effect/i.test(text))                         roles.push("iam-policy-json");
    if (roles.length === 0)                                               roles.push("general-doc");
  }

  // Determine architecture tier the doc belongs to
  let archTier = "Unknown";
  if (/\bl0\b|org\s+layer|management\s+account|control\s+tower|scp\b/.test(text))  archTier = "L0 Org/Management";
  else if (/\bl1\b|account\s+vend|aft|account\s+factory/.test(text))               archTier = "L1 Account Vending";
  else if (/\bl2\b|account\s+pave|baseline|guardduty|cloudtrail/.test(text))       archTier = "L2 Account Pave";
  else if (/\bl3\b|product\s+pave|transit\s+gateway|shared\s+vpc/.test(text))      archTier = "L3 Product Pave";
  else if (/\bl4\b|service\s+layer|workload|application/.test(text))                archTier = "L4 Service";
  else if (/ci\/?cd|pipeline|deploy|build|release/.test(text))                      archTier = "CI/CD";
  else if (/iam|role|policy|permission|assume/.test(text))                           archTier = "IAM/Security";
  else if (/vpc|subnet|security.group|network|routing/.test(text))                  archTier = "Network";
  else if (/rds|dynamo|s3|aurora|database|storage/.test(text))                      archTier = "Storage";
  else if (/kubernetes|eks|lambda|ecs|fargate|compute/.test(text))                  archTier = "Compute";

  return { roles: roles.length ? roles : ["general-doc"], archTier, ext };
}

function buildContextFromDocs(userDocs) {
  if (!userDocs || !userDocs.length) return { signals: [], mentions: {}, compliance: [], paveHints: [], docInventory: [] };

  const validDocs = userDocs.filter(d => d.content && !d.binary);
  const allText = validDocs.map(d => d.content).join("\n");
  const lower = allText.toLowerCase();

  // ── Per-document classification & inventory ────────────────────────────
  const docInventory = validDocs.map(d => {
    const info = classifyDoc(d);
    return { name: d.name, path: d.path, size: d.size, ...info };
  });

  const signals = [];
  const mentions = {};

  // ── Tool / platform detection ──────────────────────────────────────────
  const TOOLS = [
    { key:"spinnaker",    label:"Spinnaker",      sev:"MEDIUM", msg:"Spinnaker CD pipeline referenced in context docs",
      detail:"Spinnaker manages deploy pipelines with broad AWS permissions. Verify the Spinnaker service account role is scoped per-application, not account-wide. Terraspin modules and stage-level IAM bindings should follow least-privilege." },
    { key:"jenkins",      label:"Jenkins",        sev:"MEDIUM", msg:"Jenkins CI referenced in context docs",
      detail:"Jenkins build agents often run with IAM roles that can trigger Terraform plan/apply. Ensure ephemeral agent instances use narrow IAM roles, OIDC-based credential injection (Vault or AWS Assume Role via OIDC), and that credentials are never stored in build logs or artifact archives." },
    { key:"vault",        label:"HashiCorp Vault", sev:"LOW",   msg:"Vault secrets engine referenced in context docs",
      detail:"Vault dynamic secrets reduce long-lived credential exposure. Verify the Vault AWS secrets engine role has minimum permissions, lease TTL is short (≤1h), and audit logging is enabled. Vault token orphan leakage is a common lateral movement vector." },
    { key:"xsphere",      label:"xSphere",        sev:"MEDIUM", msg:"xSphere private cloud referenced in context docs",
      detail:"xSphere ↔ AWS hybrid connectivity (Direct Connect or VPN) creates a trust boundary between on-prem and cloud. Verify the Direct Connect virtual interface is private (not public), BGP authentication is enabled, and cross-environment IAM roles enforce ExternalId or session conditions." },
    { key:"terragrunt",   label:"Terragrunt",      sev:"LOW",   msg:"Terragrunt orchestration referenced in context docs",
      detail:"Terragrunt introduces implicit run_all dependency ordering. Verify that remote_state blocks use encrypted S3 and DynamoDB locking. Circular dependencies in terragrunt.hcl dependency graphs can cause state corruption." },
    { key:"atlantis",     label:"Atlantis",        sev:"MEDIUM", msg:"Atlantis referenced in context docs",
      detail:"Atlantis runs terraform plan/apply from PR comments with full deployment IAM permissions. Ensure only authorized repos trigger Atlantis, plan output is not written to PR comments (credential leak risk), and the server token is rotated regularly." },
    { key:"argo",         label:"Argo CD/Workflow", sev:"MEDIUM", msg:"Argo CD or Argo Workflows referenced in context docs",
      detail:"Argo Workflows can execute arbitrary code in pods. Verify workflow service accounts use the minimum RBAC permissions, workflow templates enforce parameter validation, and artifact storage (S3/MinIO) is encrypted and access-controlled." },
    { key:"datadog",      label:"Datadog",         sev:"LOW",   msg:"Datadog monitoring referenced in context docs",
      detail:"Datadog agents use API keys that provide read access to metrics and traces — treat as sensitive credentials. Verify API keys are stored in Secrets Manager (not Lambda env vars or plaintext tfvars), and the Datadog IAM integration role has only required permissions." },
    { key:"new relic",    label:"New Relic",        sev:"LOW",   msg:"New Relic referenced in context docs",
      detail:"New Relic license keys and ingest keys are long-lived credentials. Rotate via Secrets Manager, restrict network policy to allow only New Relic ingest endpoints, and audit which services are exporting traces." },
    { key:"pagerduty",    label:"PagerDuty",        sev:"LOW",   msg:"PagerDuty referenced in context docs",
      detail:"PagerDuty integrations expose service API keys in Terraform. Ensure these keys are managed via Secrets Manager or SSM SecureString, not committed to tfvars or state." },
    { key:"okta",         label:"Okta",             sev:"MEDIUM", msg:"Okta identity provider referenced in context docs",
      detail:"Okta as the OIDC/SAML IdP is a high-value target — a compromised Okta account enables SSO bypass into all federated services. Verify MFA enforcement, admin role segregation, and that AWS OIDC trust policies enforce sub-claim conditions matching expected Okta groups." },
    { key:"kubernetes",   label:"Kubernetes",       sev:"MEDIUM", msg:"Kubernetes/EKS referenced in context docs",
      detail:"Kubernetes RBAC and IAM must be co-designed. Verify pods use IRSA (IAM Roles for Service Accounts), node instance profiles are minimal, and Network Policies restrict pod-to-pod lateral movement." },
    { key:"wiz",          label:"Wiz CSPM",          sev:"LOW",   msg:"Wiz cloud security posture referenced in context docs",
      detail:"Wiz reads cloud configuration via a cross-account role. Verify the Wiz role has ReadOnly permissions only, ExternalId is required in the trust policy, and the scanner role cannot write to S3 or KMS." },
    { key:"checkov",      label:"Checkov",           sev:"LOW",   msg:"Checkov static analysis referenced in context docs",
      detail:"Checkov findings in docs indicate a known policy baseline. Cross-reference Threataform findings with Checkov suppressions to identify intentionally suppressed controls that may require compensating control documentation." },
    { key:"tfe\|terraform enterprise\|terraform cloud", label:"TFE/Terraform Cloud", sev:"MEDIUM", msg:"Terraform Enterprise/Cloud referenced in context docs",
      detail:"TFE workspaces with 'remote' execution mode run plans/applies with organization-scoped tokens. Verify workspace variable sets scope secrets correctly, run triggers are restricted to authorized VCS branches, and audit logs capture all apply events." },
    { key:"github action",label:"GitHub Actions",  sev:"MEDIUM", msg:"GitHub Actions CI/CD referenced in context docs",
      detail:"GitHub Actions OIDC federation eliminates static IAM keys. Verify the assume-role trust policy restricts sub-claim to specific repositories and branches (not *), token expiry is ≤1h, and GITHUB_TOKEN permissions are minimal." },
  ];

  TOOLS.forEach(t => {
    const re = new RegExp(`(?:${t.key})`, "i");
    if (re.test(lower)) {
      mentions[t.label] = true;
      signals.push({ sev: t.sev, msg: t.msg, detail: t.detail, src: "context-doc" });
    }
  });

  // ── Compliance frameworks ──────────────────────────────────────────────
  const COMPLIANCE = [
    { key:/fedramp/i,         label:"FedRAMP",         req:"Requires FIPS 140-2 encryption, continuous monitoring, POA&M tracking, and strict access controls. All TF resources must align with FedRAMP High/Moderate control baseline." },
    { key:/hipaa/i,           label:"HIPAA",           req:"PHI must be encrypted at rest (AES-256) and in transit (TLS 1.2+). Audit logging required for all PHI access. Verify CloudTrail data events on S3 buckets and RDS." },
    { key:/pci.?dss/i,        label:"PCI-DSS",         req:"CHD environments require network segmentation, encryption, vulnerability scanning, and MFA for admin access. Terraform state files may contain connection strings — treat as in-scope." },
    { key:/soc\s*2/i,         label:"SOC 2",           req:"Availability, confidentiality, and security controls required. Verify CloudTrail, Config, and GuardDuty are enabled. Change management must be enforced (no manual AWS console changes)." },
    { key:/iso.?27001/i,      label:"ISO 27001",       req:"ISMS controls require risk register, access control policy, and incident response. Terraform configurations must be version-controlled and reviewed before apply." },
    { key:/cis.?aws/i,        label:"CIS AWS Benchmark",req:"Verify CIS Level 1 & 2 controls: MFA on root, CloudTrail multi-region, S3 block public access, KMS key rotation, VPC flow logs, and no access keys on root." },
    { key:/nist\s*800/i,      label:"NIST 800-53",     req:"NIST SP 800-53 controls require IA-5 credential management, AU-2 audit events, SC-8 transmission confidentiality, and AC-6 least privilege for all IAM roles." },
  ];
  const complianceDetected = [];
  COMPLIANCE.forEach(c => {
    if (c.key.test(allText)) {
      complianceDetected.push(c.label);
      signals.push({
        sev: "MEDIUM", src: "context-doc",
        msg: `${c.label} compliance context detected in documentation`,
        detail: c.req
      });
    }
  });

  // ── Architecture patterns ──────────────────────────────────────────────
  if (/hub.?and.?spoke|hub-spoke|transit\s+gateway/i.test(allText))
    signals.push({ sev:"LOW", src:"context-doc", msg:"Hub-and-spoke network topology detected in docs",
      detail:"Transit Gateway hub-and-spoke topologies concentrate cross-VPC traffic at a single routing point. Ensure TGW route tables are segmented (shared services VPC ≠ workload VPCs), VPC attachment policies restrict lateral east-west traffic, and RAM shares are scoped by OU." });

  if (/blue.?green|canary\s+deploy|rolling\s+deploy/i.test(allText))
    signals.push({ sev:"LOW", src:"context-doc", msg:"Advanced deployment strategy referenced in docs (blue-green/canary)",
      detail:"Blue-green and canary deployments require dual-environment IAM permissions and temp resource coexistence. Verify the deployment role cannot modify production state during canary phase, and that load balancer listener rules enforce traffic weight limits." });

  if (/multi.?account|landing\s+zone|control\s+tower/i.test(allText))
    signals.push({ sev:"MEDIUM", src:"context-doc", msg:"Multi-account / landing zone architecture referenced in docs",
      detail:"Multi-account architectures require SCP guardrails at the OU level, cross-account IAM roles with ExternalId, and centralized logging aggregation. Verify the log archive account is isolated (no workload resources) and management account access is restricted to break-glass scenarios." });

  // ── Per-doc-type deep analysis signals ────────────────────────────────
  const k8sManifests = docInventory.filter(d => d.roles.includes("k8s-manifest"));
  if (k8sManifests.length)
    signals.push({ sev:"MEDIUM", src:"context-doc", msg:`${k8sManifests.length} Kubernetes manifest(s) in context docs`,
      detail:`Kubernetes manifests detected (${k8sManifests.map(d=>d.name).slice(0,3).join(", ")}). These define workload identities and network exposure. Verify: (1) ServiceAccounts do not use default SA tokens — use projected volumes with bounded TTL; (2) Ingress resources have TLS termination and no wildcard hosts; (3) Pods run as non-root with readOnlyRootFilesystem; (4) NetworkPolicy resources restrict pod-to-pod traffic; (5) RBAC ClusterRoleBindings are not bound to 'system:anonymous'.` });

  const ghActions = docInventory.filter(d => d.roles.includes("github-actions"));
  if (ghActions.length)
    signals.push({ sev:"MEDIUM", src:"context-doc", msg:`${ghActions.length} GitHub Actions workflow(s) detected`,
      detail:`GitHub Actions workflows (${ghActions.map(d=>d.name).slice(0,3).join(", ")}) define CI/CD pipelines that interact with AWS. Verify: OIDC federation is used instead of static access keys; the aws-actions/configure-aws-credentials action specifies role-session-name; branch protection rules prevent unapproved PRs from triggering deploy workflows; secrets are stored in GitHub Encrypted Secrets, not env: blocks.` });

  const jenkinsfiles = docInventory.filter(d => d.roles.includes("jenkinsfile"));
  if (jenkinsfiles.length)
    signals.push({ sev:"MEDIUM", src:"context-doc", msg:`${jenkinsfiles.length} Jenkinsfile/Groovy pipeline(s) detected`,
      detail:`Jenkins pipeline definitions (${jenkinsfiles.map(d=>d.name).slice(0,3).join(", ")}) define deployment automation. Verify: credentials() binding is used (never hardcoded); ephemeral agents run in isolated pods/VMs; withCredentials blocks limit secret scope; pipeline scripts are approved in Jenkins Script Security; no sh steps that echo credentials.` });

  const iamJsons = docInventory.filter(d => d.roles.includes("iam-policy-json"));
  if (iamJsons.length) {
    const hasStar = iamJsons.some(d => /"Action"\s*:\s*"\*"/.test(d.content || ""));
    signals.push({ sev: hasStar ? "CRITICAL" : "MEDIUM", src:"context-doc",
      msg:`${iamJsons.length} IAM policy JSON doc(s) in context${hasStar ? " — wildcard Action:* detected" : ""}`,
      detail:`IAM policy documents (${iamJsons.map(d=>d.name).slice(0,3).join(", ")}) define permission boundaries. ${hasStar ? "CRITICAL: Action:* found in a standalone IAM policy JSON — this grants full control over all services. Restrict to minimum required actions." : "Review each policy statement for overly broad Action/Resource combinations. Apply least-privilege. Ensure Deny statements use StringEquals conditions, not StringLike with wildcards."}`});
  }

  const shellScripts = docInventory.filter(d => d.roles.includes("shell-script"));
  if (shellScripts.length)
    signals.push({ sev:"LOW", src:"context-doc", msg:`${shellScripts.length} shell script(s) in context docs`,
      detail:`Shell scripts (${shellScripts.map(d=>d.name).slice(0,3).join(", ")}) may embed AWS CLI calls, credential exports, or terraform commands. Review for: hardcoded credentials (export AWS_ACCESS_KEY_ID), curl | bash patterns, set +e that suppresses error handling, and unquoted variable expansion enabling injection.` });

  const tfVarDocs = docInventory.filter(d => d.roles.includes("tf-variables"));
  if (tfVarDocs.length) {
    const hasCreds = tfVarDocs.some(d => /password\s*=|secret\s*=|access_key\s*=|private_key\s*=/i.test(d.content || ""));
    if (hasCreds)
      signals.push({ sev:"HIGH", src:"context-doc", msg:"tfvars file(s) may contain plaintext credentials",
        detail:`Context document tfvars files (${tfVarDocs.map(d=>d.name).slice(0,3).join(", ")}) appear to contain credential-like variable assignments. tfvars files should NEVER contain real secrets. Use -var-file with encrypted vault injection, or reference Secrets Manager ARNs as variable values. Ensure these files are in .gitignore.` });
  }

  const yamlConfigs = docInventory.filter(d => d.roles.includes("yaml-config"));
  if (yamlConfigs.length)
    signals.push({ sev:"LOW", src:"context-doc", msg:`${yamlConfigs.length} YAML config file(s) provide additional architecture context`,
      detail:`YAML configuration files (${yamlConfigs.map(d=>d.name).slice(0,3).join(", ")}) may define service configuration, environment variables, or infrastructure parameters. Review for hardcoded endpoints, unencrypted database connection strings, or service discovery patterns that bypass IAM.` });

  // ── Sensitive pattern warnings (any file type) ────────────────────────
  const credDocs = validDocs.filter(d =>
    /(?:password|secret_key|access_key|private_key|api_key|client_secret|AKIA[A-Z0-9]{16})\s*[=:]/i.test(d.content || ""));
  if (credDocs.length)
    signals.push({ sev:"HIGH", src:"context-doc", msg:`Potential credentials found in ${credDocs.length} context doc(s): ${credDocs.map(d=>d.name).slice(0,3).join(", ")}`,
      detail:"Context documents contain patterns matching credentials (password=, access_key=, AKIA...). These files must not be committed to version control. Use Vault, AWS Secrets Manager, or SSM SecureString. Rotate any keys that may have been exposed." });

  // ── Pave-layer hints from doc text ────────────────────────────────────
  const paveHints = [];
  if (/\bl0\b|org\s+layer|management\s+account|control\s+tower/i.test(allText)) paveHints.push("L0");
  if (/\bl1\b|account\s+vend|aft|account\s+factory/i.test(allText)) paveHints.push("L1");
  if (/\bl2\b|account\s+pave|baseline\s+account/i.test(allText)) paveHints.push("L2");
  if (/\bl3\b|product\s+pave|platform\s+team|shared\s+service/i.test(allText)) paveHints.push("L3");
  if (/\bl4\b|service\s+layer|workload|application\s+team/i.test(allText)) paveHints.push("L4");

  return { signals, mentions, compliance: complianceDetected, paveHints, docInventory };
}

function generateAnalysis(pr, allFiles, userDocs, scopeFilePaths = null) {
  const allResources   = pr?.resources      || [];
  const modules        = pr?.modules        || [];
  const connections    = pr?.connections    || [];
  const outputs        = pr?.outputs        || [];
  const variables      = pr?.variables      || [];
  const remoteStates   = pr?.remoteStates   || [];
  const paveLayers     = pr?.paveLayers     || {};
  const unpinnedMods   = pr?.unpinnedModules|| [];

  // ── Mine knowledge from context documents ─────────────────────────────
  const docContext = buildContextFromDocs(userDocs);

  // ── Scope filtering ───────────────────────────────────────────────────────
  // null = all in scope; new Set() = none; Set([...]) = subset
  // scopeIsSubset = true whenever scope excludes at least one file (including empty Set = none)
  const scopeIsSubset = scopeFilePaths instanceof Set
    && (allFiles || []).some(f => !scopeFilePaths.has(f.path));

  const resources = scopeIsSubset
    ? allResources.filter(r => scopeFilePaths.has(r.file))
    : allResources;

  const outScopeResources = scopeIsSubset
    ? allResources.filter(r => !scopeFilePaths.has(r.file))
    : [];

  const inScopeIds  = new Set(resources.map(r => r.id));
  const outScopeIds = new Set(outScopeResources.map(r => r.id));

  // Connections that cross the scope boundary (one end in-scope, other out-of-scope)
  const crossScopeConns = scopeIsSubset
    ? connections.filter(c =>
        (inScopeIds.has(c.from) && outScopeIds.has(c.to)) ||
        (outScopeIds.has(c.from) && inScopeIds.has(c.to)))
    : [];

  // Out-of-scope resources that in-scope resources directly depend on (upstream context)
  const dependencyResources = outScopeResources.filter(r =>
    crossScopeConns.some(c => inScopeIds.has(c.from) && c.to === r.id));

  // Out-of-scope resources that depend on in-scope resources (downstream callers)
  const inboundResources = outScopeResources.filter(r =>
    crossScopeConns.some(c => c.from === r.id && inScopeIds.has(c.to)));

  const scopeInfo = scopeIsSubset ? {
    active: true,
    inScopeFileCount: scopeFilePaths.size,
    totalFileCount: (allFiles || []).length,
    inScopeResourceCount: resources.length,
    totalResourceCount: allResources.length,
    outScopeResourceCount: outScopeResources.length,
    crossScopeConnCount: crossScopeConns.length,
    dependencyResources,
    inboundResources,
    outScopeFiles: (allFiles || []).filter(f => !scopeFilePaths.has(f.path)),
  } : { active: false, dependencyResources: [], inboundResources: [] };
  // ─────────────────────────────────────────────────────────────────────────

  const rOfType = (...kws) => resources.filter(r => kws.some(k => (r.type||"").includes(k)));

  // Group by tier (in-scope resources only)
  const tierGroups = {};
  resources.forEach(r => {
    const tid = (RT[r.type] || RT._default).t;
    if (!tierGroups[tid]) tierGroups[tid] = [];
    tierGroups[tid].push(r);
  });

  // Connection kind counts
  const connCounts = { implicit:0, explicit:0, "module-input":0, other:0 };
  connections.forEach(c => {
    const k = c.kind || "other";
    connCounts[k] !== undefined ? connCounts[k]++ : connCounts.other++;
  });

  // Degree map → top connected resources
  const deg = {};
  resources.forEach(r => { deg[r.id] = 0; });
  connections.forEach(c => { if(deg[c.from]!==undefined) deg[c.from]++; if(deg[c.to]!==undefined) deg[c.to]++; });
  const topR = [...resources].sort((a,b)=>(deg[b.id]||0)-(deg[a.id]||0)).slice(0,6);

  // Security surface
  const surf = {
    iam:    rOfType("iam_role","iam_policy","iam_user","iam_group","iam_instance_profile"),
    sg:     rOfType("security_group"),
    kms:    rOfType("kms_key","kms_alias"),
    waf:    rOfType("wafv2","waf_"),
    lb:     rOfType("_lb","alb","elb","nlb","load_balancer"),
    apigw:  rOfType("api_gateway","apigatewayv2"),
    rds:    rOfType("rds_","db_instance","aurora"),
    s3:     rOfType("aws_s3_bucket"),
    eks:    rOfType("eks_","kubernetes"),
    lambda: rOfType("lambda_function"),
    vpc:    rOfType("aws_vpc","subnet","route_table","internet_gateway","nat_gateway"),
    dynamo: rOfType("dynamodb"),
  };

  // Threat modeling signals
  const signals = [];
  const entry = [...surf.lb, ...surf.apigw];
  if (entry.length)
    signals.push({ sev:"HIGH", msg:`Public entry points: ${entry.slice(0,4).map(r=>r.id).join(", ")}${entry.length>4?" …":""}`, detail:"Load balancers and API Gateways are internet-facing attack surfaces. Verify WAF attachment, TLS termination policy, and least-privilege IAM authorizers." });
  if (surf.s3.length && !surf.kms.length)
    signals.push({ sev:"HIGH", msg:`${surf.s3.length} S3 bucket(s) with no KMS key detected`, detail:"No aws_kms_key resources found. S3 data may be unencrypted at rest. Enable SSE-KMS or SSE-S3 and enforce via bucket policy." });
  if (surf.iam.length > 8)
    signals.push({ sev:"HIGH", msg:`${surf.iam.length} IAM principals/policies — broad privilege surface`, detail:"Large IAM surface increases blast radius of credential compromise. Audit for wildcard actions (Action:'*') and overly permissive trust relationships." });
  if (remoteStates.length)
    signals.push({ sev:"MEDIUM", msg:`${remoteStates.length} remote state reference(s)`, detail:"Remote state access exposes upstream outputs. Verify S3 bucket policies, DynamoDB state locks, and cross-account assume-role permissions." });
  const explicitCount = connections.filter(c=>c.kind==="explicit").length;
  if (explicitCount)
    signals.push({ sev:"MEDIUM", msg:`${explicitCount} explicit depends_on override(s)`, detail:"Explicit dependencies can mask architectural coupling. Review each depends_on to confirm it is not hiding a missing IAM or network dependency." });
  if (surf.rds.length)
    signals.push({ sev:"MEDIUM", msg:`${surf.rds.length} RDS/Aurora instance(s)`, detail:"Verify SG restricts inbound to app tier only, encryption_at_rest enabled, automated backups configured, no public_accessibility." });
  if (surf.eks.length)
    signals.push({ sev:"MEDIUM", msg:`${surf.eks.length} EKS/Kubernetes cluster(s)`, detail:"Verify node group IMDSv2, RBAC least-privilege, private endpoint, and network policies restricting pod-to-pod traffic." });
  if (modules.some(m=>(m.source||"").includes("registry.terraform.io")||(m.source||"").startsWith("hashicorp/")))
    signals.push({ sev:"MEDIUM", msg:"Public Terraform registry modules in use", detail:"Verify pinned version constraints, review source for unexpected resource creation, consider vendoring to private registry." });
  if (surf.kms.length)
    signals.push({ sev:"LOW", msg:`${surf.kms.length} KMS key(s) — encryption strategy detected`, detail:"Ensure key rotation enabled, resource-based policies grant minimum access, and CloudTrail logs all key usage events." });
  if (surf.waf.length)
    signals.push({ sev:"LOW", msg:`WAF resource(s) detected`, detail:"Verify managed rule groups cover OWASP Top 10 and confirm association with all ALBs and API Gateways." });
  if (surf.sg.length)
    signals.push({ sev:"LOW", msg:`${surf.sg.length} security group(s) defined`, detail:"Audit for 0.0.0.0/0 ingress beyond ports 80/443, unrestricted egress, and orphaned groups." });
  if (variables.length)
    signals.push({ sev:"LOW", msg:`${variables.length} input variable(s) — check for sensitive defaults`, detail:"Variables with sensitive=true must not have defaults. Audit for passwords, tokens, or key IDs passed as plaintext." });
  if (outputs.length)
    signals.push({ sev:"LOW", msg:`${outputs.length} output(s) — potential sensitive data exposure`, detail:"Mark sensitive=true for credentials, keys, and connection strings to prevent leakage into downstream state." });

  // ── Pave-layer signals (from file path detection) ─────────────────────
  const paveLayerKeys = Object.keys(paveLayers);
  if (paveLayerKeys.length > 0) {
    const layerList = paveLayerKeys.sort().join(", ");
    signals.push({ sev:"MEDIUM", msg:`TFE-Pave layer(s) detected from file paths: ${layerList}`,
      detail:`File path analysis detected resources at pave layer(s): ${layerList}. The TFE-Pave pattern enforces layered IAM delegation — L0 (Org/SCPs) → L1 (Account Vending/AFT) → L2 (Account Pave/baseline) → L3 (Product Pave/shared platform) → L4 (Service/workload). Every cross-layer IAM trust must be bounded by permission boundaries defined at the parent layer. Resources from higher layers (L0/L1) must never be directly modified by lower-layer pipelines.` });
    // Per-layer specifics
    if (paveLayers.L0) signals.push({ sev:"HIGH", msg:"L0 Org/Management Terraform code detected — highest privilege layer",
      detail:"L0 Terraform manages SCPs, Control Tower, and OU structure. This code has the highest blast radius of any layer — a misconfigured SCP or OU policy affects all member accounts. Apply changes only via a locked-down pipeline with required human approval, MFA-enforced IAM user, and no console access. State file for L0 must be in a dedicated isolated S3 bucket." });
    if (paveLayers.L1) signals.push({ sev:"HIGH", msg:"L1 Account Vending (AFT) code detected",
      detail:"L1 AFT (Account Factory for Terraform) provisions new AWS accounts and bootstraps them with permission boundaries and initial roles. Ensure AFT customizations do not grant iam:CreateRole without permission_boundary, and the AFT pipeline role cannot assume roles in any account it has not explicitly created." });
    if (paveLayers.L2) signals.push({ sev:"MEDIUM", msg:"L2 Account Pave code detected — baseline controls layer",
      detail:"L2 establishes per-account security baselines: CloudTrail, GuardDuty, Config, and permission boundaries. Verify all L2 resources are deployed before any L3/L4 workload resources, and that the pave role is restricted from modifying its own permission boundaries." });
    if (paveLayers.L3) signals.push({ sev:"MEDIUM", msg:"L3 Product Pave code detected — shared platform services",
      detail:"L3 provides shared VPC, Transit Gateway, and the ProductTeamDeployer role used by L4 service teams. Verify the ProductTeamDeployer role has a permission boundary preventing privilege escalation beyond the product account, and that TGW route tables isolate product accounts from each other." });
    if (paveLayers.L4) signals.push({ sev:"LOW", msg:"L4 Service/workload code detected — application layer",
      detail:"L4 service code deploys application workloads under the ProductTeamDeployer role, which is bounded by L3 permission boundaries and L0/L1 SCPs. Verify service roles use inline or managed policies that do not exceed the ProductTeamDeployer boundary, and that state files do not contain cross-layer sensitive outputs." });
  }

  // ── Unpinned registry module supply chain signals ─────────────────────
  if (unpinnedMods.length > 0)
    signals.push({ sev:"HIGH", msg:`${unpinnedMods.length} Terraform registry module(s) lack version constraints`,
      detail:`Unpinned modules (no version = "x.y.z"): ${unpinnedMods.map(m=>m.name).slice(0,5).join(", ")}. Without version pinning, a registry module can be updated to a malicious version that injects unauthorized resources or IAM permissions on the next terraform init. Pin all registry modules to exact versions and vendor them to a private registry.` });

  // ── Module output / data-ref connection counts ────────────────────────
  const modOutCount = connections.filter(c=>c.kind==="module-output").length;
  const dataRefCount = connections.filter(c=>c.kind==="data-ref").length;
  if (modOutCount > 0)
    signals.push({ sev:"LOW", msg:`${modOutCount} module output reference(s) detected`,
      detail:"Resources consuming module outputs create implicit data flow dependencies. If the upstream module changes its output structure, consuming resources may receive unexpected values. Use explicit output validation and type constraints in module definitions." });
  if (dataRefCount > 0)
    signals.push({ sev:"LOW", msg:`${dataRefCount} data source reference(s) detected`,
      detail:"Data sources read live cloud state into Terraform. Misconfigured data source filters (e.g., reading the wrong AMI or security group) can silently inject wrong resource attributes. Verify all data source filters are sufficiently specific." });

  // ── Inject document context signals ───────────────────────────────────
  docContext.signals.forEach(s => signals.push(s));

  // ── Pave-layer hints from docs augment narrative ───────────────────────
  const allPaveLayers = new Set([...paveLayerKeys, ...docContext.paveHints]);

  const tierList = Object.entries(tierGroups).filter(([k])=>k!=="_default")
    .map(([k,v])=>`${TIERS[k]?.label||k} (${v.length})`).join(", ");

  // Run deep security checks
  const secFindings = runSecurityChecks(resources, variables);
  const critCount = secFindings.filter(f=>f.sev==="CRITICAL").length;
  const highCount = secFindings.filter(f=>f.sev==="HIGH").length;

  // Trust boundary analysis
  const trustBoundaries = identifyTrustBoundaries(resources);

  // Add scope boundary trust boundary when scope is restricted
  if (scopeInfo.active && scopeInfo.crossScopeConnCount > 0) {
    trustBoundaries.unshift({
      zone: "Scope Boundary — Threat Model Perimeter (In-Scope ↔ Context Infrastructure)",
      type: "Scope",
      risk: "HIGH",
      desc: `${scopeInfo.crossScopeConnCount} Terraform connection(s) cross the threat model scope boundary. ${scopeInfo.dependencyResources.length} upstream dependency resource(s) (out-of-scope) provide services consumed by in-scope resources. ${scopeInfo.inboundResources.length} downstream resource(s) consume outputs from in-scope resources. Every cross-boundary data flow represents a trust transition that must be explicitly authenticated, authorized, and encrypted. Misconfigurations at this boundary allow an attacker to move between the threat model perimeter and the broader infrastructure.`,
      control: "Authenticate every cross-boundary API/data call (IAM, SigV4, mTLS); authorize at resource-policy level; encrypt all data in transit (TLS 1.2+); log cross-boundary access via CloudTrail data events; apply least-privilege IAM on cross-account and cross-service access points"
    });
  }

  // Architecture narrative
  const narrative = buildArchitectureNarrative(tierGroups, surf, modules, remoteStates, allFiles);

  // STRIDE-LM per-tier analysis
  const strideLM = buildStrideLMByTier(tierGroups);

  // MITRE ATT&CK technique mapping from findings
  const attackMap = {};
  secFindings.forEach(f => {
    if (f.technique && ATTACK_TECHNIQUES[f.technique]) {
      if (!attackMap[f.technique]) attackMap[f.technique] = { ...ATTACK_TECHNIQUES[f.technique], findings:[] };
      attackMap[f.technique].findings.push(f);
    }
  });

  const docSignalCount = docContext.signals.length;
  const toolMentions = Object.keys(docContext.mentions);
  const execSummary =
    `Threataform analyzed ${allFiles.length} Terraform file(s)${userDocs.length ? ` + ${userDocs.length} context document(s)` : ""} ` +
    `containing ${resources.length} managed resource(s), ${modules.length} module(s), and ${connections.length} connection(s). ` +
    (tierList ? `Resources span tiers: ${tierList}. ` : "") +
    (paveLayerKeys.length ? `TFE-Pave layers detected: ${paveLayerKeys.sort().join(", ")}. ` : "") +
    `Data flows: ${connCounts.implicit} implicit, ${connCounts.explicit} explicit depends_on, ` +
    `${connCounts["module-input"]} module input${modOutCount ? `, ${modOutCount} module output` : ""}${dataRefCount ? `, ${dataRefCount} data source` : ""}. ` +
    (remoteStates.length ? `${remoteStates.length} remote state backend(s). ` : "") +
    `Security scan: ${critCount} CRITICAL, ${highCount} HIGH, ` +
    `${secFindings.filter(f=>f.sev==="MEDIUM").length} MEDIUM, ${secFindings.filter(f=>f.sev==="LOW").length} LOW finding(s). ` +
    `${trustBoundaries.length} trust boundary/boundaries. ` +
    (toolMentions.length ? `Tools/platforms detected in context docs: ${toolMentions.slice(0,6).join(", ")}. ` : "") +
    (docContext.compliance.length ? `Compliance frameworks: ${docContext.compliance.join(", ")}. ` : "") +
    `${signals.filter(s=>s.sev==="HIGH").length} HIGH, ${signals.filter(s=>s.sev==="MEDIUM").length} MEDIUM, ` +
    `${signals.filter(s=>s.sev==="LOW").length} LOW architecture signal(s)` +
    (docSignalCount ? ` (${docSignalCount} from context docs)` : "") + `. ` +
    `${strideLM.length} tier(s) mapped with STRIDE-LM.`;

  return { execSummary, tierGroups, connCounts, topR, surf, signals, modules, remoteStates,
    variables, outputs, secFindings, trustBoundaries, narrative, strideLM, attackMap, scopeInfo,
    docContext, paveLayers, allPaveLayers,
    scale:{ resources:resources.length, modules:modules.length, connections:connections.length,
            files:(allFiles||[]).length, contextDocs: (userDocs||[]).length,
            modOutRefs: modOutCount, dataRefs: dataRefCount },
    fileNames:(allFiles||[]).map(f=>f.path), userDocs:userDocs||[], timestamp:new Date().toISOString() };
}

export { tfAttr, tfBool, tfBlock, runSecurityChecks, identifyTrustBoundaries, buildArchitectureNarrative, buildStrideLMByTier, classifyDoc, buildContextFromDocs, generateAnalysis };
