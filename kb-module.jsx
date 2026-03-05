
// ═══════════════════════════════════════════════════════════════════════════════
// ENTERPRISE TERRAFORM ARCHITECTURE INTELLIGENCE PLATFORM
// ═══════════════════════════════════════════════════════════════════════════════
// Covers:
//  1. xSphere Private Cloud ↔ AWS Hybrid Integration
//  2. Spinnaker CD Platform & Terraform Orchestration  
//  3. AWS IAM · Organizations · OUs · SCPs (Zero-Trust / Defense-in-Depth)
//  4. Jenkins / Jules CI → Terraform → xSphere Bootstrap Pipeline
//  5. Enterprise Multi-Repo TF Dependency DFD (top-down)
//  6. Upload .tf files → parse module trees → generate draw.io DFD
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useCallback, useRef, useEffect } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// KNOWLEDGE BASE
// ─────────────────────────────────────────────────────────────────────────────

const KB = {

  xsphere: {
    title: "xSphere Private Cloud ↔ AWS Integration",
    icon: "☁",
    color: "#0091DA",
    summary: "xSphere (xsphere.cloud) is a US-based private cloud provider offering customized, single-tenant private clouds on dedicated infrastructure. It integrates with AWS, Azure, and GCP via high-speed private connections, creating a unified hybrid cloud fabric for enterprises requiring data sovereignty and compliance.",
    sections: [
      {
        title: "xSphere Terraform Resources",
        items: [
          "xsphere_virtual_machine — full VM lifecycle on dedicated private cloud infrastructure",
          "xsphere_datacenter — logical grouping of compute, storage, and network",
          "xsphere_cluster — high-availability cluster within xSphere data center",
          "xsphere_datastore — dedicated storage backing for VMs (SAN/NAS)",
          "xsphere_network — private network segments within xSphere environment",
          "xsphere_distributed_virtual_switch — fabric-level network abstraction",
          "xsphere_tag / xsphere_tag_category — drives automation, RBAC, cost tagging",
          "xsphere_content_library — share VM templates across xSphere environments",
        ]
      },
      {
        title: "xSphere ↔ AWS Hybrid Integration",
        items: [
          "AWS Direct Connect / VPN — private high-speed connectivity from xSphere US data centers to AWS VPC",
          "xSphere as AWS bootstrap — Terraform manages AWS infrastructure from xSphere private cloud base",
          "Lambda from xSphere data stores — serverless compute in AWS triggered by xSphere-hosted data",
          "Route53 DNS integration — xSphere VM IPs registered in AWS Route53 via Terraform outputs",
          "S3 data replication — xSphere storage synced to S3 for DR and analytics workloads",
          "Terraform Cloud Agents — pull-based agent inside xSphere network; no inbound port needed",
          "Cross-provider outputs — xSphere VM attributes fed into AWS resource configurations",
          "Hybrid state management — Terraform state in S3 manages both xSphere and AWS resources",
        ]
      },
      {
        title: "Hybrid Architecture Flow",
        items: [
          "1. xSphere API ← provider auth (XSPHERE_USER / XSPHERE_PASSWORD / XSPHERE_SERVER)",
          "2. Terraform plans against xsphere provider + aws provider simultaneously",
          "3. xsphere_virtual_machine provisions from template on dedicated infrastructure",
          "4. aws_dx_connection / aws_vpn_connection — private connectivity to xSphere",
          "5. VMs tagged in xSphere → Config Management reads tags for automation",
          "6. xSphere backup → AWS S3 for offsite DR and compliance archival",
          "7. Cross-provider outputs: VM IP → aws_route53_record; resource ARNs → SSM",
        ]
      },
      {
        title: "Security & Compliance",
        items: [
          "FedRAMP / FISMA / HIPAA / SOC 2 / ISO 27001 / CMMC 2.0 / HITRUST compliance",
          "Single-tenant isolation — dedicated infrastructure with no shared hardware",
          "US-only data residency — all data stored in US-based data centers",
          "24/7 managed threat prevention — ML traffic inspection, sandbox analysis",
          "Encryption at rest and in transit with customer-managed keys",
          "Compliance automation via Terraform — infrastructure compliance enforced as code",
        ]
      }
    ]
  },

  spinnaker: {
    title: "Spinnaker CD Platform",
    icon: "⬡",
    color: "#139BB4",
    summary: "Spinnaker (Netflix/Google, now Linux Foundation CD Foundation) is the gold-standard multi-cloud CD platform. It orchestrates full deployment pipelines across AWS EC2/ECS/EKS, GCP, Azure, Kubernetes, and bare-metal — integrating with Jenkins/Travis CI for the CI phase and Terraform for IaC provisioning stages.",
    sections: [
      {
        title: "Core Spinnaker Microservices",
        items: [
          "Deck — React SPA UI (port 9000)",
          "Gate — API gateway; all external calls enter here",
          "Orca — Pipeline orchestration engine; manages stage state machines",
          "Clouddriver — Cloud provider abstraction; AWS, GCP, k8s, xSphere adapters",
          "Front50 — Persistent storage for pipelines, apps, projects (S3/GCS/AZBlob)",
          "Rosco — Bakery; builds machine images (AMI, GCE image) via Packer",
          "Igor — CI integration hub (Jenkins, Travis, GitHub Actions, AWS CodeBuild)",
          "Echo — Event bus; triggers pipelines on git push, cron, webhook, pubsub",
          "Fiat — Authorization; RBAC via OAuth/SAML/LDAP/GitHub Teams",
          "Kayenta — Automated canary analysis; queries Prometheus/Datadog/Stackdriver",
          "Halyard — Configuration management tool for Spinnaker deployment",
        ]
      },
      {
        title: "Terraform ↔ Spinnaker Integration",
        items: [
          "Terraspin (OpsMx) — open-source microservice; executes tf plan/apply/destroy as Spinnaker custom stage",
          "Custom webhook stage → POST to Terraspin API with TF module path + vars",
          "Custom job stage — Kubernetes Job runs terraform container; Orca polls completion",
          "Native stage (plugin) — extends Orca + Deck for first-class TF pipeline stages",
          "Pipeline outputs — TF apply outputs (IPs, ARNs) passed as SpEL expressions to downstream stages",
          "Artifact store — Front50 or S3 stores .tfplan files as pipeline artifacts",
          "RBAC via Fiat — restrict who can trigger apply vs plan stages",
        ]
      },
      {
        title: "Jenkins → Spinnaker → AWS Pipeline",
        items: [
          "1. Dev pushes code → GitHub webhook → Jenkins (CI: build, test, Docker push)",
          "2. Jenkins triggers Spinnaker pipeline via Igor API call",
          "3. Spinnaker Bake stage — Rosco builds AMI from latest artifact",
          "4. Terraform stage (Terraspin) — tf apply to provision/update infra",
          "5. Deploy stage — ECS/EKS rolling deploy with new AMI/image",
          "6. Canary stage (Kayenta) — automated traffic comparison, metric scoring",
          "7. Manual judgment gate — optional human approval before prod",
          "8. Blue/Green promote or rollback based on canary score",
          "9. Echo → Slack/PagerDuty notification on success/failure",
        ]
      },
      {
        title: "AWS Account Configuration for Spinnaker",
        items: [
          "Managed accounts: SpinnakerManaged IAM role in each target account",
          "Managing account: SpinnakerManaging role in Spinnaker's account assumes SpinnakerManaged",
          "ECS/EKS/EC2 providers registered via hal config provider aws/kubernetes",
          "S3 bucket for Front50 persistence; DynamoDB for distributed locking",
          "Aurora PostgreSQL — production persistence layer (replaces S3+DDB for large orgs)",
          "Redis — Orca/Clouddriver caching; ElastiCache in production",
          "Terraform module: Young-ook/spinnaker/aws — EKS + Aurora + S3 + Helm",
        ]
      },
      {
        title: "xSphere Integration",
        items: [
          "Clouddriver xSphere adapter — register xSphere endpoint for pipeline deployments",
          "Bake xSphere templates — Rosco + Packer builds VM templates for xSphere private cloud",
          "Deploy to xSphere — Clouddriver provisions VMs from templates on private infrastructure",
          "Hybrid pipeline: Bake AMI for AWS + xSphere template in parallel",
          "Terraform in pipeline manages firewall rules for newly deployed xSphere workloads",
          "xSphere private cloud as deployment target alongside AWS for enterprise pipelines",
        ]
      }
    ]
  },

  iam: {
    title: "AWS IAM · Organizations · OUs · SCPs",
    icon: "🔐",
    color: "#DD344C",
    summary: "AWS IAM is the identity and authorization fabric for all AWS API calls. In an enterprise, it operates in layers: Organization-level SCPs → OU inheritance → Account-level IAM policies → Resource-based policies → Permission Boundaries → Session policies. Every Deny at any layer is final. Understanding evaluation order is the foundation of zero-trust AWS.",
    sections: [
      {
        title: "IAM Policy Evaluation Order (Defense-in-Depth)",
        items: [
          "① Explicit Deny anywhere = FINAL DENY (overrides all Allows)",
          "② SCPs (Org-level) — defines MAX permissions for all principals in member accounts",
          "③ RCPs (Resource Control Policies) — org-level constraints on resource access",
          "④ Resource-based policies — S3 bucket policy, KMS key policy, Lambda resource policy",
          "⑤ Identity-based policies — IAM role/user/group attached policies",
          "⑥ Permission Boundaries — ceiling on what identity-based policy can grant",
          "⑦ Session policies — AssumeRole temporary restrictions",
          "RESULT: Effective = intersection of all Allow layers with no Deny at any layer",
          "CRITICAL: SCPs do NOT affect management account — protect it with strict IAM",
        ]
      },
      {
        title: "AWS Organizations Hierarchy",
        items: [
          "Root — single root per org; management account lives here",
          "Management Account — org administration only; NEVER run workloads here",
          "Security OU → Log-Archive Account + Security-Tooling Account",
          "Infrastructure OU → Network-Shared-Services + Shared-Services Accounts",
          "Workloads OU → Dev OU / Test OU / Staging OU / Prod OU (nested)",
          "Sandbox OU → Dev experimentation; strict cost + service SCPs",
          "Suspended OU → Accounts pending closure; deny-all SCP attached",
          "SCP inheritance: Root SCPs apply to ALL children; OU SCPs add restrictions",
          "Max 5 SCPs per entity (account or OU); combine with aws_iam_policy_document",
        ]
      },
      {
        title: "Essential SCPs (Zero-Trust Baselines)",
        items: [
          "deny-leave-organization — prevents accounts escaping governance",
          "deny-unapproved-regions — NotAction global services (IAM/Route53/CloudFront/STS)",
          "deny-disable-cloudtrail — protect audit trail; org trail in log-archive account",
          "deny-delete-guardduty — prevent detection evasion",
          "deny-disable-securityhub / deny-disable-config — preserve visibility",
          "deny-root-usage — force MFA; never use root for day-to-day operations",
          "deny-public-s3-buckets — DenyPutBucketPublicAccessBlock",
          "deny-unencrypted-ebs / deny-unencrypted-s3 — data-at-rest controls",
          "require-tags — enforce cost allocation; condition StringEquals aws:RequestedRegion",
          "sandbox-deny-expensive-services — block Redshift, EMR, Direct Connect in sandbox",
          "restrict-ec2-instance-types — deny .metal, xlarge+ in non-prod OUs",
        ]
      },
      {
        title: "IAM Zero-Trust Patterns for Terraform",
        items: [
          "Role Vending Machine (RVM) — central Terraform module provisions least-privilege pipeline roles",
          "Permission Boundaries on all TF-created roles — ceiling prevents privilege escalation",
          "OIDC trust (GitHub Actions / Jenkins) — short-lived tokens; no static keys",
          "Cross-account role chaining: pipeline account → AssumeRole → target account",
          "Read-only plan role + separate apply role — principle of least privilege per action",
          "terraform_remote_state with IAM policy — only allowed backends can read state",
          "KMS encryption on state files (S3 SSE-KMS) + DynamoDB lock table",
          "aws_iam_policy_document data source — version-controlled JSON policies in TF",
          "Condition keys: aws:CalledVia, aws:ViaAWSService — restrict TF role to IaC use only",
          "SCPs: deny iam:CreateRole if no permission boundary attached (condition)",
        ]
      },
      {
        title: "Account Factory / Control Tower Automation",
        items: [
          "AWS Control Tower — orchestrates org setup, enrolls accounts, enforces guardrails",
          "Account Factory for Terraform (AFT) — Terraform module; Git-driven account vending",
          "AFT pipeline: account request PR → TF apply → new account in correct OU",
          "Guardrails = SCPs (preventive) + Config Rules (detective) + CloudFormation hooks (proactive)",
          "IAM Identity Center (SSO) — centralized human access; permission sets map to roles",
          "terraform-provider-aws: aws_organizations_organization / aws_organizations_policy / aws_organizations_policy_attachment",
          "lifecycle { ignore_changes = [name, email] } — AWS accounts cannot be deleted via API",
        ]
      }
    ]
  },

  jenkins: {
    title: "Jenkins / Jules → Terraform → xSphere/AWS",
    icon: "⚙",
    color: "#D24939",
    summary: "Jenkins is the most widely deployed open-source CI/CD server. In enterprise Terraform workflows it serves as the orchestrator: pulling HCL from Git, running terraform init/plan/apply, managing workspace switching, handling secrets via Credentials API, and integrating approvals. Combined with xSphere provider it can bootstrap full AWS landing zones from a private cloud CI server.",
    sections: [
      {
        title: "Jenkins–Terraform Pipeline Stages",
        items: [
          "Checkout — git checkout scm; branch strategy: main=prod, develop=staging",
          "Credentials — withCredentials([AmazonWebServicesCredentialsBinding]) or EC2 IAM role",
          "Terraform Init — terraform init -backend-config=envs/${ENV}/backend.hcl -reconfigure",
          "Workspace — terraform workspace select ${ENV} || terraform workspace new ${ENV}",
          "Validate — terraform validate; tflint; checkov --directory .; tfsec .",
          "Plan — terraform plan -out=tfplan -var-file=envs/${ENV}/terraform.tfvars -no-color",
          "Approval — input() step for prod; auto-approve for dev/staging",
          "Apply — terraform apply -input=false tfplan",
          "Output capture — sh 'terraform output -json > tf_outputs.json'; archive artifact",
          "Post — always { cleanWs(); archiveArtifacts 'tfplan*,tf_outputs.json' }",
        ]
      },
      {
        title: "Jenkins Credential Management",
        items: [
          "AWS credentials: AmazonWebServicesCredentialsBinding plugin → env vars",
          "EC2 IAM role: Jenkins on EC2 inherits instance profile — no static keys",
          "OIDC: jenkins-oidc plugin → AssumeRoleWithWebIdentity — recommended for TFC",
          "HashiCorp Vault plugin — dynamic short-lived AWS STS tokens per build",
          "XSPHERE_USER / XSPHERE_PASSWORD — Jenkins secret text credentials",
          "TF_VAR_db_password — inject sensitive vars without .tfvars commit",
          "environment { } block scoping — credentials only visible inside stage",
        ]
      },
      {
        title: "Jenkins → xSphere → AWS Bootstrap",
        items: [
          "1. Jenkins Job: provision-xsphere-agent — terraform apply xsphere_virtual_machine",
          "2. VM is provisioned from golden template on xSphere private cloud",
          "3. cloud-init / user_data configures: Java, awscli, terraform, git",
          "4. Jenkins Cloud xSphere plugin registers new VM as ephemeral agent",
          "5. Child pipeline runs on xSphere agent: terraform init → plan → apply → AWS",
          "6. AWS resources created: VPC, ECS cluster, RDS, etc.",
          "7. tf outputs (VPC ID, endpoint ARNs) written to SSM Parameter Store",
          "8. Post-build: xsphere_virtual_machine destroyed (ephemeral agent lifecycle)",
          "Alternative: Terraform creates Jenkins EC2 agent → agent builds AWS infra",
        ]
      },
      {
        title: "Jules (GitLab CI / Alternative)",
        items: [
          "GitLab CI (.gitlab-ci.yml) — same pattern as Jenkinsfile but YAML-native",
          "gitlab-terraform — official HashiCorp GitLab CI template with MR-integrated plan output",
          "GitLab environments — protect prod branch; require manual approval via environment rules",
          "OIDC JWT: id_tokens → AssumeRoleWithWebIdentity — no static AWS keys in CI",
          "GitLab Terraform state — built-in HTTP backend; no S3 needed for smaller teams",
          "GitLab Runners on xSphere — runner VM provisioned via terraform-provider-xsphere",
          "Parallel matrix jobs — run tf plan for dev/staging/prod simultaneously",
          "GitLab Merge Train — serialize tf applies to prevent state conflicts",
        ]
      },
      {
        title: "Multi-Environment Pipeline Architecture",
        items: [
          "State isolation: separate S3 key per environment + workspace",
          "Backend config injection: -backend-config flag; never hardcode account IDs in .tf",
          "Cross-account assume-role: TF_VAR_role_arn per env; pipeline assumes role before apply",
          "Plan storage: S3 artifact with SHA; apply only from stored plan (no re-plan)",
          "Drift detection: nightly Jenkins job runs terraform plan; alerts on diff",
          "Policy scan pipeline: checkov, tfsec, terrascan, Sentinel (HCP TF)",
          "Cost estimation: Infracost plugin in Jenkins PR comment",
          "State locking: DynamoDB prevents concurrent applies across pipeline runs",
        ]
      }
    ]
  },

  enterprise_dfd: {
    title: "Enterprise Terraform DFD Architecture",
    icon: "🗺",
    color: "#6C3483",
    summary: "Large enterprises scatter Terraform code across dozens of repos, teams, and module registries. The key patterns are: (1) Root modules call child modules (local or registry), (2) Remote state data sources link across state boundaries, (3) Module registries (public, private, GitHub) serve versioned modules, (4) Terragrunt orchestrates dependency order. The DFD generator above reverse-engineers all of this from uploaded .tf files.",
    sections: [
      {
        title: "Enterprise TF Repository Topologies",
        items: [
          "Monorepo — all IaC in one repo; /modules/, /environments/, /global/; simple but scales poorly",
          "Multi-repo — separate repo per module; private Terraform Registry; versioned releases",
          "infrastructure-live + infrastructure-modules (Gruntwork pattern) — live = instances, modules = reusable code",
          "Platform team modules — shared networking, security, observability modules in org registry",
          "Team-owned root modules — each app team owns their tf; calls platform modules",
          "Service Catalog pattern — Control Tower + AWS Service Catalog + Terraform blueprints",
          "GitOps TF — Atlantis or Terraform Cloud VCS-driven; auto plan on PR, apply on merge",
        ]
      },
      {
        title: "Module Call Chain (DFD Nodes)",
        items: [
          "Root Module (entry point) — main.tf + variables.tf + outputs.tf + backend.tf",
          "Local child module — source = './modules/vpc'; compiled into root plan",
          "Registry module — source = 'terraform-aws-modules/vpc/aws'; version pinned",
          "Git module — source = 'git::https://github.com/org/modules//vpc?ref=v2.0'",
          "Remote state dependency — data.terraform_remote_state.network.outputs.vpc_id",
          "Provider alias — multi-region/multi-account; aws.us-east-1, aws.eu-west-1",
          "Module composition — module A outputs → module B inputs (implicit dependency)",
          "Workspace = environment — same module code, different .tfvars + state",
        ]
      },
      {
        title: "Cross-State Data Flow Patterns",
        items: [
          "S3 backend + DynamoDB lock — standard enterprise remote state",
          "terraform_remote_state — read outputs from another state file (coupling risk)",
          "SSM Parameter Store — loose coupling; module writes ARN → another reads via data source",
          "AWS Secrets Manager — sensitive outputs (passwords, certs) passed cross-module",
          "Event-driven IaC — EventBridge triggers TF pipeline on resource change detection",
          "Terragrunt dependency block — explicit cross-module dependency with retry logic",
          "Stack outputs via CDK TF — TypeScript/Python classes; outputs compiled to TF JSON",
        ]
      },
      {
        title: "DFD Analysis Techniques",
        items: [
          "terraform graph — built-in DOT format; pipe to Graphviz for PNG/SVG",
          "Blast Radius — interactive d3.js; last supports TF 0.12; community fork exists",
          "Rover — modern TF visualizer; tfplan.json input; module/resource view",
          "Inframap — provider-aware filtering; shows only meaningful resource connections",
          "terraform-graph-beautifier — prettifies DOT output; module grouping",
          "Custom parser approach (this tool) — multi-file upload; cross-file reference detection",
          "Terragrunt DAG — terragrunt graph-dependencies shows inter-module order",
          "Dependency injection: look for module.X.output_Y as input to module Z",
        ]
      },
      {
        title: "Security DFD Layers (Zero-Trust Lens)",
        items: [
          "Org Control Plane: Terraform manages SCPs → restricts everything below",
          "Landing Zone layer: VPC, Transit Gateway, DNS managed by platform TF",
          "Security tooling layer: GuardDuty, SecurityHub, Config deployed via TF",
          "Account provisioning: AFT pipeline → creates accounts → enrolls in Control Tower",
          "Application layer: app teams' TF calls platform modules via approved registry only",
          "State encryption: all TF state in encrypted S3 + strict IAM; never public",
          "Pipeline IAM: OIDC trust only; permission boundary on all TF-created roles",
          "Sentinel gates: policy-as-code checked BEFORE tf apply in HCP TF",
          "Drift alerts: nightly plan comparison → Security Hub finding if unexpected change",
        ]
      }
    ]
  },

  wiz: {
    title: "Wiz CSPM — Cloud Security Posture",
    icon: "🛡",
    color: "#1A73E8",
    summary: "Wiz is an agentless CNAPP providing continuous cloud security posture management. It connects via APIs with zero agents, delivering full visibility across VMs, containers, serverless, and AI workloads. Its graph-based engine correlates misconfigurations with exposure, identities, and attack paths across AWS, Azure, GCP, and OCI.",
    sections: [
      {
        title: "Cloud Configuration Rules (CCRs)",
        items: [
          "2,800+ built-in rules — assess posture against cloud-native best practices",
          "Unified rule engine — same rules evaluate runtime AND IaC (Terraform, CloudFormation)",
          "Custom rules via OPA/Rego — author organization-specific policies",
          "Rule lifecycle management — version-controlled via GitOps",
          "Auto-remediation — trigger automated fixes for known misconfigurations",
        ]
      },
      {
        title: "AWS Detective Controls",
        items: [
          "Security Hub — Wiz findings pushed for centralized security dashboard",
          "AWS Config — correlates Config rule evaluations with graph-based attack path context",
          "GuardDuty — enriches findings with infrastructure topology and blast radius",
          "CloudTrail — analyzes API patterns for anomaly detection",
          "Detective controls complement preventive SCPs — detect what SCPs cannot prevent",
        ]
      },
      {
        title: "Terraform Integration",
        items: [
          "HCP Terraform Connector — maps cloud resources to Terraform definitions via state files",
          "Wiz Terraform Provider — manage policies and configurations as code",
          "Wiz Code (IaC Scanning) — scans Terraform plans pre-deployment",
          "Run Tasks — Wiz scans execute as HCP Terraform run tasks; block non-compliant deploys",
          "State file as source of truth — automatic IaC-to-cloud resource mapping",
        ]
      },
      {
        title: "Attack Path Analysis",
        items: [
          "Graph-based security context — correlates misconfigurations with exploitability",
          "Toxic combination detection — compound risks (public exposure + admin privs + unpatched CVE)",
          "Blast radius visualization — downstream impact of resource compromise",
          "Lateral movement mapping — attacker paths across VPCs, accounts, services",
          "Priority scoring — risk-based ranking replaces volume-based alert fatigue",
        ]
      },
      {
        title: "Preventive vs Detective Controls",
        items: [
          "Preventive (shift-left) — Wiz Code scans IaC before deployment",
          "Detective (runtime) — continuous scanning detects drift and misconfigurations",
          "SCPs = preventive guardrails; Wiz CCRs = detective controls",
          "Complementary pairing — SCPs prevent + Wiz detects = defense-in-depth",
          "Feedback loop — runtime findings drive new SCP rules and module hardening",
        ]
      }
    ]
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// TERRAFORM PARSER (multi-file, cross-reference, module tree)
// ─────────────────────────────────────────────────────────────────────────────

const RESOURCE_TIERS = {
  // xSphere
  xsphere_virtual_machine: { label:"xSphere VM", tier:"xsphere", icon:"🖥", color:"#0091DA" },
  xsphere_datacenter: { label:"xSphere DC", tier:"xsphere", icon:"🏢", color:"#0091DA" },
  xsphere_cluster: { label:"xSphere Cluster", tier:"xsphere", icon:"🔗", color:"#0091DA" },
  xsphere_datastore: { label:"Datastore", tier:"xsphere", icon:"💽", color:"#0091DA" },
  xsphere_network: { label:"xSphere Network", tier:"xsphere", icon:"🌐", color:"#0091DA" },
  xsphere_distributed_virtual_switch: { label:"xDVS", tier:"xsphere", icon:"🔀", color:"#0091DA" },
  xsphere_tag: { label:"xSphere Tag", tier:"xsphere", icon:"🏷", color:"#0091DA" },
  xsphere_content_library: { label:"Content Library", tier:"xsphere", icon:"📚", color:"#0091DA" },
  // AWS Organizations/IAM
  aws_organizations_organization: { label:"AWS Org", tier:"org", icon:"🏛", color:"#DD344C" },
  aws_organizations_organizational_unit: { label:"OU", tier:"org", icon:"📁", color:"#DD344C" },
  aws_organizations_account: { label:"AWS Account", tier:"org", icon:"👤", color:"#DD344C" },
  aws_organizations_policy: { label:"SCP", tier:"org", icon:"🛡", color:"#DD344C" },
  aws_organizations_policy_attachment: { label:"SCP Attach", tier:"org", icon:"📎", color:"#DD344C" },
  aws_iam_role: { label:"IAM Role", tier:"security", icon:"🔑", color:"#E74C3C" },
  aws_iam_policy: { label:"IAM Policy", tier:"security", icon:"📋", color:"#E74C3C" },
  aws_iam_role_policy_attachment: { label:"Policy Attach", tier:"security", icon:"📎", color:"#E74C3C" },
  aws_iam_openid_connect_provider: { label:"OIDC Provider", tier:"security", icon:"🔓", color:"#E74C3C" },
  aws_kms_key: { label:"KMS Key", tier:"security", icon:"🗝", color:"#E74C3C" },
  aws_secretsmanager_secret: { label:"Secret", tier:"security", icon:"🔒", color:"#E74C3C" },
  aws_cognito_user_pool: { label:"Cognito Pool", tier:"security", icon:"👥", color:"#E74C3C" },
  // Jenkins/CI
  aws_codepipeline: { label:"CodePipeline", tier:"cicd", icon:"⚙", color:"#D24939" },
  aws_codebuild_project: { label:"CodeBuild", tier:"cicd", icon:"🔨", color:"#D24939" },
  aws_codecommit_repository: { label:"CodeCommit", tier:"cicd", icon:"📦", color:"#D24939" },
  // Spinnaker stack
  aws_eks_cluster: { label:"EKS (Spinnaker)", tier:"spinnaker", icon:"☸", color:"#139BB4" },
  aws_rds_cluster: { label:"Aurora (Front50)", tier:"spinnaker", icon:"🗄", color:"#139BB4" },
  aws_elasticache_replication_group: { label:"Redis (Orca)", tier:"spinnaker", icon:"⚡", color:"#139BB4" },
  // Networking
  aws_vpc: { label:"VPC", tier:"network", icon:"🌐", color:"#7B1FA2" },
  aws_subnet: { label:"Subnet", tier:"network", icon:"📡", color:"#7B1FA2" },
  aws_security_group: { label:"Security Group", tier:"network", icon:"🔐", color:"#7B1FA2" },
  aws_internet_gateway: { label:"IGW", tier:"network", icon:"🚪", color:"#7B1FA2" },
  aws_nat_gateway: { label:"NAT GW", tier:"network", icon:"↗", color:"#7B1FA2" },
  aws_transit_gateway: { label:"Transit GW", tier:"network", icon:"🔀", color:"#7B1FA2" },
  aws_dx_connection: { label:"Direct Connect", tier:"network", icon:"⚡", color:"#7B1FA2" },
  // Compute
  aws_instance: { label:"EC2", tier:"compute", icon:"🖥", color:"#2E7D32" },
  aws_lambda_function: { label:"Lambda", tier:"compute", icon:"λ", color:"#2E7D32" },
  aws_ecs_cluster: { label:"ECS Cluster", tier:"compute", icon:"🐳", color:"#2E7D32" },
  aws_ecs_service: { label:"ECS Service", tier:"compute", icon:"🔄", color:"#2E7D32" },
  aws_autoscaling_group: { label:"ASG", tier:"compute", icon:"📈", color:"#2E7D32" },
  // Storage/DB
  aws_s3_bucket: { label:"S3", tier:"storage", icon:"🪣", color:"#1565C0" },
  aws_dynamodb_table: { label:"DynamoDB", tier:"storage", icon:"⚡", color:"#1565C0" },
  aws_db_instance: { label:"RDS", tier:"storage", icon:"🗄", color:"#1565C0" },
  aws_elasticache_cluster: { label:"ElastiCache", tier:"storage", icon:"⚡", color:"#1565C0" },
  // Default
  _default: { label:"Resource", tier:"compute", icon:"◆", color:"#546E7A" }
};

const TIER_META = {
  xsphere:  { label:"xSphere Private Cloud",    bg:"#E3F2FD", border:"#0091DA", hdr:"#0277BD", order:0 },
  org:      { label:"AWS Org / IAM Control",    bg:"#FCE4EC", border:"#DD344C", hdr:"#B71C1C", order:1 },
  security: { label:"Security & IAM",           bg:"#FFEBEE", border:"#E74C3C", hdr:"#C62828", order:2 },
  cicd:     { label:"CI/CD (Jenkins/Jules)",    bg:"#FBE9E7", border:"#D24939", hdr:"#BF360C", order:3 },
  spinnaker:{ label:"Spinnaker CD Platform",    bg:"#E0F7FA", border:"#139BB4", hdr:"#00838F", order:4 },
  network:  { label:"Network / VPC",            bg:"#F3E5F5", border:"#7B1FA2", hdr:"#6A1B9A", order:5 },
  compute:  { label:"Compute & API",            bg:"#E8F5E9", border:"#2E7D32", hdr:"#1B5E20", order:6 },
  storage:  { label:"Storage & Database",       bg:"#E3F2FD", border:"#1565C0", hdr:"#0D47A1", order:7 },
};

function parseTerraformMultiFile(files) {
  // files: [{path, content}, ...]
  const allResources = [], allConns = [], allModules = [], allOutputs = [], allVariables = [];
  const fileSummary = [];

  files.forEach(({ path, content }) => {
    const fname = path.split("/").pop();
    const resources = [], locals = [];

    // ── Resources ──────────────────────────────────────────────────────────
    const resRe = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    let m;
    while ((m = resRe.exec(content)) !== null) {
      const [, rtype, rname, body] = m;
      const id = `${rtype}.${rname}`;
      // extract label
      const LABELS = ["name","bucket","function_name","cluster_id","cluster_identifier","table_name","queue_name","topic_name","identifier","description","title","role_name","pipeline_name","project_name"];
      let label = rname;
      for (const a of LABELS) {
        const lm = body.match(new RegExp(`\\b${a}\\s*=\\s*"([^"]{1,50})"`, "m"));
        if (lm) { label = lm[1]; break; }
      }
      const multi = /\bfor_each\s*=/.test(body) ? "for_each" : /\bcount\s*=/.test(body) ? "count" : null;
      resources.push({ id, type:rtype, name:rname, label, body, multi, file:path });
      allResources.push({ id, type:rtype, name:rname, label, body, multi, file:path });

      // implicit edges from body references
      const refRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = refRe.exec(body)) !== null) {
        const tgt = `${rm[1]}.${rm[2]}`;
        if (tgt !== id) allConns.push({ from:id, to:tgt, type:"implicit", file:path });
      }
      // depends_on
      const depM = body.match(/depends_on\s*=\s*\[([^\]]+)\]/);
      if (depM) {
        const dr = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let dm;
        while ((dm = dr.exec(depM[1])) !== null)
          allConns.push({ from:id, to:`${dm[1]}.${dm[2]}`, type:"explicit", file:path });
      }
    }

    // ── Module calls ───────────────────────────────────────────────────────
    const modRe = /\bmodule\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = modRe.exec(content)) !== null) {
      const [, mname, body] = m;
      const srcM = body.match(/source\s*=\s*"([^"]+)"/);
      const verM = body.match(/version\s*=\s*"([^"]+)"/);
      const src = srcM ? srcM[1] : "unknown";
      const ver = verM ? verM[1] : null;
      const srcType = src.startsWith("./") || src.startsWith("../") ? "local"
                    : src.startsWith("git::") ? "git"
                    : src.startsWith("tfr:") ? "registry"
                    : src.includes("registry.terraform.io") ? "registry"
                    : src.includes("github.com") ? "git"
                    : "registry";
      allModules.push({ id:`module.${mname}`, name:mname, source:src, version:ver, srcType, body, file:path });
      // inputs → resource refs
      const refRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = refRe.exec(body)) !== null)
        allConns.push({ from:`module.${mname}`, to:`${rm[1]}.${rm[2]}`, type:"module-input", file:path });
    }

    // ── Outputs ────────────────────────────────────────────────────────────
    const outRe = /\boutput\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = outRe.exec(content)) !== null) {
      const [, oname, body] = m;
      const valM = body.match(/value\s*=\s*(.+)/);
      allOutputs.push({ name:oname, value:valM ? valM[1].trim() : "", file:path });
    }

    // ── Variables ──────────────────────────────────────────────────────────
    const varRe = /\bvariable\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    while ((m = varRe.exec(content)) !== null) {
      const [, vname, body] = m;
      const defM = body.match(/default\s*=\s*(.+)/);
      const typM = body.match(/type\s*=\s*(\S+)/);
      allVariables.push({ name:vname, type:typM?typM[1]:"any", hasDefault:!!defM, file:path });
    }

    // ── Remote state references ────────────────────────────────────────────
    const rsRe = /data\s+"terraform_remote_state"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|\s*$))/g;
    while ((m = rsRe.exec(content)) !== null) {
      const [, rsname, body] = m;
      const keyM = body.match(/key\s*=\s*"([^"]+)"/);
      const bucketM = body.match(/bucket\s*=\s*"([^"]+)"/);
      allModules.push({ id:`remote_state.${rsname}`, name:rsname, source:"remote_state", version:null, srcType:"remote_state",
        body, file:path, key:keyM?keyM[1]:null, bucket:bucketM?bucketM[1]:null });
    }

    // ── Sentinel ───────────────────────────────────────────────────────────
    if (fname.endsWith(".sentinel") || /^#\s*--\s*[^\s]+\.sentinel\s*--/.test(content)) {
      const pname = fname.replace(".sentinel", "");
      allModules.push({ id:`sentinel.${pname}`, name:pname, source:"sentinel", version:null, srcType:"sentinel", body:"", file:path });
    }

    fileSummary.push({ path, resourceCount:resources.length });
  });

  // Deduplicate resources
  const seenR = new Set();
  const uniqueResources = allResources.filter(r => { if (seenR.has(r.id)) return false; seenR.add(r.id); return true; });
  const seenM = new Set();
  const uniqueModules = allModules.filter(r => { if (seenM.has(r.id)) return false; seenM.add(r.id); return true; });

  // Deduplicate edges & resolve
  const validIds = new Set([...uniqueResources.map(r=>r.id), ...uniqueModules.map(m=>m.id)]);
  const seenE = new Set();
  const uniqueConns = allConns.filter(c => {
    const k = `${c.from}||${c.to}`;
    if (seenE.has(k) || c.from===c.to || !validIds.has(c.from)) return false;
    seenE.add(k); return true;
  });

  return { resources:uniqueResources, modules:uniqueModules, connections:uniqueConns,
           outputs:allOutputs, variables:allVariables, fileSummary };
}

export { KB, parseTerraformMultiFile, RESOURCE_TIERS, TIER_META };
