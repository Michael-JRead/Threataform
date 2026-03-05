import { useState, useCallback, useRef, useMemo, Component } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// ENTERPRISE TERRAFORM ARCHITECTURE INTELLIGENCE PLATFORM  v1.0
// ─────────────────────────────────────────────────────────────────────────────
//  Deep knowledge areas:
//  1. xSphere Private Cloud ↔ AWS Hybrid Integration
//  2. Spinnaker.io CD Platform & Terraform Orchestration
//  3. AWS IAM · Organizations · OUs · SCPs (Zero-Trust / Defense-in-Depth)
//  4. Jenkins / Jules → Terraform → xSphere/AWS Bootstrap Pipelines
//  5. Enterprise Multi-Repo TF DFD — Upload files → parse → draw.io XML
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// KNOWLEDGE BASE
// ─────────────────────────────────────────────────────────────────────────────
const KB = {
  xsphere: {
    title: "xSphere Private Cloud ↔ AWS Integration",
    color: "#0277BD", light: "#E1F5FE", accent: "#01579B",
    icon: "☁",
    sections: [
      {
        heading: "What is xSphere?",
        body: "xSphere (xsphere.cloud) is a US-based private cloud provider that builds fully customized, single-tenant private clouds deployed in US data centers. Unlike shared public cloud, each xSphere environment runs on dedicated infrastructure with isolated networking — giving enterprises complete control over data residency, security, and performance. xSphere integrates with AWS, Azure, and GCP via high-speed private connections, creating a unified hybrid cloud fabric."
      },
      {
        heading: "xSphere Terraform Resources",
        items: [
          "xsphere_virtual_machine — Full VM lifecycle on dedicated private cloud infrastructure",
          "xsphere_datacenter — Logical grouping of compute, storage, and network in xSphere",
          "xsphere_cluster — High-availability cluster within xSphere data center",
          "xsphere_datastore — Dedicated storage backing for VMs (SAN/NAS)",
          "xsphere_network — Private network segments within xSphere environment",
          "xsphere_distributed_virtual_switch — Fabric-level network abstraction across hosts",
          "xsphere_tag / xsphere_tag_category — Drives automation, RBAC, and cost tagging",
          "xsphere_content_library — Share VM templates and ISOs across xSphere environments",
        ]
      },
      {
        heading: "xSphere ↔ AWS Hybrid Integration",
        items: [
          "AWS Direct Connect / VPN — Private high-speed connectivity from xSphere US data centers to AWS VPC",
          "xSphere as AWS bootstrap — Terraform manages AWS infrastructure from xSphere private cloud base",
          "Lambda from xSphere data stores — Serverless compute in AWS triggered by xSphere-hosted data",
          "Route53 DNS integration — xSphere VM IPs registered in AWS Route53 via Terraform outputs",
          "S3 data replication — xSphere storage synced to S3 for DR and analytics workloads",
          "Terraform Cloud Agents — Pull-based agent inside xSphere network; no inbound port needed",
          "Cross-provider outputs — xSphere VM attributes fed into AWS resource configurations",
          "Hybrid state management — Terraform state in S3 manages both xSphere and AWS resources",
        ]
      },
      {
        heading: "Cross-Provider Terraform Pattern",
        body: `provider "xsphere" {
  server   = var.xsphere_host
  user     = var.xsphere_user
  password = var.xsphere_pass
}
provider "aws" {
  region = var.aws_region
  assume_role { role_arn = var.deploy_role_arn }
}
# xSphere VM IP → Route53 record cross-provider
resource "xsphere_virtual_machine" "app" {
  name         = "web-\${terraform.workspace}"
  cluster_id   = data.xsphere_cluster.main.id
  datastore_id = data.xsphere_datastore.primary.id
}
resource "aws_route53_record" "app" {
  records = [xsphere_virtual_machine.app.default_ip_address]
}`
      },
      {
        heading: "Security & Compliance",
        items: [
          "FedRAMP / FISMA — Federal-grade security controls for government workloads",
          "HIPAA / HITRUST — Healthcare compliance with BAA support and ePHI data residency",
          "SOC 2 Type II / ISO 27001 — Enterprise audit and information security standards",
          "CMMC 2.0 — Defense industrial base cybersecurity maturity certification",
          "Single-tenant isolation — Dedicated infrastructure with no shared hardware or networking",
          "US-only data residency — All data stored in US-based data centers; no cross-border transfers",
        ]
      },
      {
        heading: "Managed Threat Prevention",
        items: [
          "24/7 managed security operations — Continuous monitoring and incident response",
          "ML-based traffic inspection — Machine learning models analyze network traffic for anomalies",
          "Sandbox file analysis — Unknown files detonated in isolated sandbox before delivery",
          "AV/malware analysis — Multi-engine scanning with real-time threat intelligence feeds",
          "Customized advanced firewall — Rules tailored to each customer's application architecture",
          "Automated remediation — Threat detection triggers automated containment and response",
        ]
      },
      {
        heading: "Healthcare & Compliance Focus",
        items: [
          "HITRUST CSF certification — Gold standard for healthcare information security",
          "HIPAA BAA support — Business Associate Agreements for ePHI handling",
          "ePHI data residency controls — Patient data guaranteed in US data centers only",
          "Encryption at rest and in transit — All data encrypted with customer-managed keys",
          "Compliance automation via Terraform — Infrastructure compliance enforced as code",
          "Audit trail — Complete logging of all infrastructure changes for compliance reporting",
        ]
      }
    ]
  },

  spinnaker: {
    title: "Spinnaker.io — Multi-Cloud CD Platform",
    color: "#00838F", light: "#E0F7FA", accent: "#006064",
    icon: "⚙",
    sections: [
      {
        heading: "What is Spinnaker?",
        body: "Spinnaker (created at Netflix + Google, now Linux Foundation CD Foundation) is the gold-standard multi-cloud Continuous Delivery platform. It orchestrates full deployment pipelines — baking machine images, provisioning infra via Terraform, deploying to ECS/EKS/GCE/Azure/xSphere, running canary analysis, and triggering rollbacks — all from one declarative pipeline."
      },
      {
        heading: "Core Microservices Architecture",
        items: [
          "Deck — React SPA (port 9000); pipeline UI builder",
          "Gate — API gateway; all external traffic enters here (port 8084)",
          "Orca — Pipeline orchestration engine; manages stage state machines, retries",
          "Clouddriver — Cloud provider abstraction layer (AWS, GCP, k8s, xSphere, Azure adapters)",
          "Front50 — Persistent store for pipelines/applications/projects (S3/GCS/AZBlob backend)",
          "Rosco — Bakery; builds machine images via Packer (AMI, xSphere templates, GCE)",
          "Igor — CI integration hub; polls Jenkins, Travis CI, GitHub Actions, CodeBuild",
          "Echo — Event bus; triggers pipelines from git push, cron, webhook, Pub/Sub",
          "Fiat — Authorization; RBAC via OAuth2/SAML/LDAP/GitHub Teams/Azure Groups",
          "Kayenta — Automated Canary Analysis; queries Prometheus, Datadog, Stackdriver",
        ]
      },
      {
        heading: "Terraform ↔ Spinnaker Integration Methods",
        items: [
          "Terraspin (OpsMx OSS) — microservice exposing tf plan/apply/destroy as Spinnaker custom stages via webhook or Kubernetes Job",
          "Custom Webhook Stage → POST to Terraspin REST API with module path, workspace, vars; Orca polls for completion",
          "Custom Job Stage — Kubernetes Job runs `hashicorp/terraform` container; Orca monitors Job status",
          "Native Plugin (Deck+Orca extension) — first-class TF stage in UI; deepest integration; requires plugin development",
          "Pipeline Expressions (SpEL) — downstream stages consume TF outputs: `${#stage('Terraform Apply')['outputs']['vpc_id']}`",
          "Artifact integration — `.tfplan` file stored in S3/GCS as pipeline artifact; apply stage references artifact",
        ]
      },
      {
        heading: "Jenkins → Spinnaker → AWS Full Pipeline",
        items: [
          "1. Dev commits → GitHub webhook → Jenkins (CI: build, unit test, Docker push to ECR)",
          "2. Jenkins triggers Spinnaker via Igor webhook POST: pipeline name + artifact tag",
          "3. Spinnaker Bake Stage — Rosco calls Packer → builds AMI with new artifact",
          "4. Terraform Stage (Terraspin) — tf apply: update ECS task definition, security groups",
          "5. Deploy Stage — ECS/EKS rolling deploy to staging with blue/green traffic shift",
          "6. Integration Test Stage — Jenkins job runs automated test suite against staging URL",
          "7. Manual Judgment Gate — Slack notification to on-call; 2h window for human approval",
          "8. Canary Stage (Kayenta) — 10% traffic split; compare error rates vs baseline 30min",
          "9. Promote Stage — 100% traffic to new version if canary score ≥ 75",
          "10. Echo → PagerDuty + Slack on any failure; auto-rollback if canary fails",
        ]
      },
      {
        heading: "AWS Infrastructure for Spinnaker",
        items: [
          "EKS cluster — runs all Spinnaker microservices as Kubernetes Deployments",
          "Aurora PostgreSQL — Front50 persistence (replaces S3+DDB at scale)",
          "ElastiCache Redis — Orca/Clouddriver distributed caching",
          "S3 bucket — artifact storage, Rosco bake cache",
          "SpinnakerManaged IAM role — in each target account; assumed by SpinnakerManaging role",
          "SpinnakerManaging IAM role — in Spinnaker's EKS cluster IRSA annotation",
          "Terraform module: `Young-ook/spinnaker/aws` — creates full stack via EKS + Helm",
        ]
      },
      {
        heading: "xSphere + Spinnaker",
        items: [
          "Clouddriver xSphere adapter — register xSphere endpoint for Spinnaker pipeline deployments",
          "Rosco bake xSphere — Packer builds VM templates from CI artifacts for xSphere private cloud",
          "Spinnaker deploys to xSphere — Clouddriver provisions VMs from templates on private infrastructure",
          "Hybrid pipeline — Bake AMI (AWS) + xSphere template in parallel Spinnaker stages",
          "Terraform stage manages firewall rules for newly deployed xSphere workloads",
          "xSphere private cloud as deployment target alongside AWS for hybrid enterprise pipelines",
        ]
      }
    ]
  },

  iam: {
    title: "AWS IAM · Organizations · OUs · SCPs",
    color: "#B71C1C", light: "#FFEBEE", accent: "#7F0000",
    icon: "🔐",
    sections: [
      {
        heading: "IAM Policy Evaluation Order — The Decision Tree",
        body: "AWS evaluates all policy types in sequence. A single Explicit Deny at ANY level is FINAL — it cannot be overridden. Understanding this chain is the foundation of zero-trust AWS architecture.",
        items: [
          "① Explicit Deny anywhere → FINAL DENY (exits evaluation immediately)",
          "② SCPs (Organization level) — defines MAXIMUM permissions for ALL principals in member accounts. Does NOT grant permissions. Does NOT apply to management account.",
          "③ RCPs (Resource Control Policies, new 2024) — org-level constraints on resource policies across accounts",
          "④ Resource-based policies — S3 bucket policy, KMS key policy, Lambda resource policy, role trust policies",
          "⑤ Identity-based policies — IAM role/user/group inline + managed attached policies",
          "⑥ Permission Boundaries — ceiling on what identity-based policies can grant; does NOT grant anything itself",
          "⑦ Session policies — AssumeRole/GetFederationToken temporary scope restriction",
          "EFFECTIVE PERMISSION = intersection of all Allows at all layers with zero Denies",
        ]
      },
      {
        heading: "AWS Organizations Hierarchy",
        body: "The organization forms a tree. SCPs inherit downward — a policy on a parent OU applies to all child OUs and accounts beneath it.",
        items: [
          "Root — single per org; management account; SCPs here apply to ALL member accounts",
          "Management Account — org admin only; SCPs do NOT protect it; guard with strict IAM + MFA",
          "Security OU → Log-Archive Account (CloudTrail org trail, VPC flow logs)",
          "Security OU → Security-Tooling Account (GuardDuty delegated admin, SecurityHub, IAM Identity Center)",
          "Infrastructure OU → Network-Shared-Services (Transit Gateway, Route53 Resolver, shared VPCs)",
          "Infrastructure OU → Shared-Services (AMI factory, Artifactory, Terraform state S3)",
          "Workloads OU → Dev OU / Test OU / Staging OU / Prod OU (nested per app or BU)",
          "Sandbox OU → unrestricted dev experimentation; strict cost + expensive-service SCPs",
          "Suspended OU → accounts pending closure; deny-all SCP; no active resources",
        ]
      },
      {
        heading: "Critical SCPs — Zero-Trust Baseline",
        items: [
          "deny-leave-organization — Prevent accounts exiting governance boundary",
          "deny-unapproved-regions — NotAction list global services (IAM/Route53/CloudFront/STS/Support/Budgets)",
          "deny-disable-cloudtrail — Protect audit trail; org trail in log-archive",
          "deny-delete-guardduty — Prevent detection evasion by compromised workload",
          "deny-disable-config / deny-disable-securityhub — Preserve security visibility",
          "deny-root-usage — Block root API calls (except account-level operations via Condition)",
          "deny-public-s3-access — DenyPutBucketPublicAccessBlock; force block-public-access setting",
          "deny-unencrypted-ebs / deny-unencrypted-s3 — Enforce data-at-rest encryption",
          "require-mandatory-tags — Condition StringLike aws:RequestTag/CostCenter [*]",
          "sandbox-service-restrictions — Deny EMR, Redshift, Direct Connect, large instances in Sandbox OU",
          "restrict-ec2-instance-types — Deny p4*, x1*, metal, 48xlarge+ in non-prod (cost guardrail)",
        ]
      },
      {
        heading: "Zero-Trust IAM for Terraform Pipelines",
        items: [
          "Role Vending Machine (RVM) — Central TF module creates least-privilege pipeline roles; security team required reviewer",
          "Permission Boundary on ALL TF-created roles — SCP denies iam:CreateRole unless boundary ARN in condition",
          "OIDC Trust (GitHub Actions / Jenkins) — id_token → AssumeRoleWithWebIdentity; zero static keys",
          "Cross-account pattern: pipeline-account IAM role → AssumeRole → target-account deploy role",
          "Read-only plan role + separate apply role — plan never has write permissions",
          "aws:CalledVia condition — restrict TF role to be assumed only from specific services",
          "S3 state encrypted SSE-KMS + DynamoDB lock + access via IAM; never public",
          "Sentinel policies in HCP Terraform — hard-mandatory checks before apply; cannot bypass",
          "Conditional SCP: `{Condition: {StringNotEquals: {'aws:RequestedRegion': ['us-east-1','eu-west-1']}}}`",
        ]
      },
      {
        heading: "Account Factory / Control Tower + AFT",
        items: [
          "AWS Control Tower — orchestrates landing zone; enrolls accounts into OUs; enforces guardrails",
          "Account Factory for Terraform (AFT) — Git-driven account vending machine; PR = new account request",
          "AFT Pipeline: TF module in CodePipeline → aws_organizations_account → enroll → baseline IaC apply",
          "Guardrail types: Preventive (SCP) + Detective (Config Rule) + Proactive (CloudFormation hook)",
          "IAM Identity Center — centralized SSO for humans; permission sets → account roles; eliminate IAM users",
          "lifecycle { ignore_changes = [name, email] } on aws_organizations_account — accounts cannot be deleted via API",
        ]
      }
    ]
  },

  jenkins: {
    title: "Jenkins / Jules → Terraform → xSphere/AWS",
    color: "#BF360C", light: "#FBE9E7", accent: "#870000",
    icon: "⚙",
    sections: [
      {
        heading: "Jenkins as Terraform Orchestrator",
        body: "Jenkins is the most widely deployed CI/CD server in enterprise. For Terraform it acts as: source of truth trigger, secrets injector, approval gate, artifact manager, and workspace switcher. The Jenkins Terraform plugin provides declarative tool installation; the AWS Credentials plugin handles STS-based auth."
      },
      {
        heading: "Production Jenkinsfile Pattern",
        body: `pipeline {
  agent { label 'terraform' }
  environment {
    TF_IN_AUTOMATION = 'true'
    AWS_DEFAULT_REGION = 'us-east-1'
  }
  parameters {
    choice(name: 'ACTION', choices: ['plan','apply','destroy'])
    choice(name: 'ENV', choices: ['dev','staging','prod'])
  }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Init') {
      steps {
        withCredentials([[
          $class: 'AmazonWebServicesCredentialsBinding',
          credentialsId: "aws-\${ENV}-role",
          accessKeyVariable: 'AWS_ACCESS_KEY_ID',
          secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
        ]]) {
          sh """
            terraform init \\
              -backend-config="envs/\${ENV}/backend.hcl" \\
              -reconfigure
            terraform workspace select \${ENV} || \\
              terraform workspace new \${ENV}
          """
        }
      }
    }
    stage('Validate') {
      steps { sh 'terraform validate && tflint && checkov -d .' }
    }
    stage('Plan') {
      steps {
        sh 'terraform plan -out=tfplan -var-file=envs/\${ENV}/terraform.tfvars'
        sh 'terraform show -json tfplan > tfplan.json'
        archiveArtifacts 'tfplan,tfplan.json'
      }
    }
    stage('Approval') {
      when { expression { ENV == 'prod' } }
      steps { input message: 'Apply to PROD?', ok: 'Approve' }
    }
    stage('Apply') {
      when { expression { ACTION == 'apply' } }
      steps { sh 'terraform apply -input=false tfplan' }
    }
  }
  post { always { cleanWs() } }
}`
      },
      {
        heading: "Jenkins → xSphere → AWS Bootstrap",
        items: [
          "1. Jenkins Job: `provision-xsphere-agent` → terraform apply xsphere_virtual_machine (golden template clone)",
          "2. cloud-init installs: Java 17, awscli v2, terraform, git, tflint, checkov on VM",
          "3. Jenkins Cloud xSphere Plugin registers new VM as ephemeral Jenkins agent (JNLP/SSH)",
          "4. Child pipeline executes ON xSphere agent: full Terraform AWS apply from private cloud network",
          "5. AWS resources created via cross-account role: VPC, ECS cluster, RDS Aurora, ALB",
          "6. TF outputs (VPC ID, cluster ARN, endpoint URLs) written to SSM Parameter Store",
          "7. xSphere VM destroyed post-build — fully ephemeral; no persistent agents",
          "8. Alternative: Jenkins creates EC2 spot agent → agent applies remaining infra in-cloud",
        ]
      },
      {
        heading: "Jules / GitLab CI Equivalent Pattern",
        items: [
          ".gitlab-ci.yml with include: template `Terraform/Base.gitlab-ci.yml` (official HashiCorp template)",
          "MR pipeline: `terraform plan` output posted as MR comment automatically",
          "Protected environments: prod branch requires manual approval via environment rules",
          "OIDC JWT tokens: `id_tokens: AWS_JWT: ...` → AssumeRoleWithWebIdentity — zero static keys",
          "GitLab Terraform HTTP backend — built-in state management for smaller teams",
          "GitLab Runner on xSphere — runner VM provisioned and destroyed via terraform-provider-xsphere",
          "Matrix strategy: parallel `plan` jobs per environment (dev/staging/prod) in same pipeline",
          "GitLab Merge Train — serializes `terraform apply` runs to prevent concurrent state conflicts",
        ]
      },
      {
        heading: "Security Hardening for CI Pipelines",
        items: [
          "OIDC over static keys ALWAYS — GitHub Actions/GitLab/Jenkins OIDC plugin → STS AssumeRoleWithWebIdentity",
          "HashiCorp Vault dynamic secrets — Vault AWS secrets engine issues STS creds with 1h TTL per build",
          "Role per pipeline, not per team — RVM provisions unique least-privilege role per repo",
          "Plan-only role has zero write permissions — apply role assumed only for apply stage",
          "Separate credentials per environment — dev/staging/prod use separate AWS accounts + roles",
          "Sentinel policy check in pipeline — optional: ship .plan to HCP TF for policy evaluation before apply",
          "State access policy — only the pipeline IAM role can access state S3 prefix; deny all humans",
          "tfplan artifact signed hash — verify plan not tampered between plan and apply stages",
        ]
      }
    ]
  },

  dfd: {
    title: "Enterprise Multi-Repo Terraform DFD",
    color: "#4527A0", light: "#EDE7F6", accent: "#1A0072",
    icon: "🗺",
    sections: [
      {
        heading: "Why Enterprise TF is Complex",
        body: "Large enterprises scatter Terraform code across dozens of repos, teams, registries, and account boundaries. A 'root module' may call 10+ child modules, each from different sources (local, git, registry, private). Remote state data sources link across state boundaries. Understanding the full dependency graph requires parsing all this simultaneously — which is exactly what the Upload & Analyze tab does."
      },
      {
        heading: "Repository Topologies",
        items: [
          "Monorepo — /modules/, /environments/, /global/ in one repo. Simple; scales poorly; merge conflicts at scale",
          "Multi-repo — separate git repo per module; private Terraform Registry (HCP or Artifactory); semver releases",
          "infrastructure-live + infrastructure-modules (Gruntwork pattern) — live = deployed instances, modules = reusable code",
          "Platform team modules — networking/security/observability modules owned by Platform; published to org registry",
          "App team root modules — consume platform modules; own their tf; PR triggers Atlantis/TFC auto-plan",
          "Terragrunt stack — `terragrunt.hcl` files orchestrate order; `dependency {}` blocks declare cross-module outputs",
          "Account Factory pattern — AFT provisions accounts; account baseline TF runs automatically on new account",
        ]
      },
      {
        heading: "Module Dependency Node Types",
        items: [
          "Root Module — entry point with main.tf + backend.tf; run `terraform init/plan/apply` directly",
          "Local child module — `source = './modules/vpc'`; compiled into root plan; same state file",
          "Registry module — `source = 'terraform-aws-modules/vpc/aws'; version = '~>5.0'`; fetched on init",
          "Git module — `source = 'git::https://github.com/org/modules//vpc?ref=v2.1.0'`; pinned by ref",
          "Remote state node — `data.terraform_remote_state.network.outputs.vpc_id`; cross-state coupling",
          "Provider alias node — `aws.us-east-1` / `aws.eu-west-1`; multi-region/account from single root",
          "Sentinel policy node — `.sentinel` file; enforced as gate between plan and apply",
          "null_resource / terraform_data — explicit ordering nodes; local-exec provisioners",
          "data source node — reads existing infra; implicit dependency on underlying resource",
        ]
      },
      {
        heading: "Cross-State Data Flow Patterns",
        items: [
          "terraform_remote_state — reads outputs from another state file. Tight coupling; use sparingly",
          "SSM Parameter Store — module writes ARN via `aws_ssm_parameter`; consumer reads via `data.aws_ssm_parameter`. Loose coupling.",
          "AWS Secrets Manager — sensitive outputs (passwords, certs) shared cross-module via data source",
          "Event-driven IaC — EventBridge detects drift; triggers pipeline with `terraform plan`; SNS alert if diff",
          "Terragrunt dependency block — `dependency.vpc.outputs.vpc_id`; explicit with automatic retry on failure",
          "TFC workspace variables — outputs from workspace A pumped into workspace B via TFC API automation",
        ]
      },
      {
        heading: "DFD Visualization Tools",
        items: [
          "`terraform graph | dot -Tsvg > graph.svg` — built-in; single module only; verbose for large configs",
          "Rover — modern visualizer; accepts tfplan.json; shows module hierarchy + resource connections interactively",
          "Inframap — provider-aware; filters to meaningful connections (VPC→subnet→ec2 not meta nodes)",
          "terraform-graph-beautifier — prettifies DOT; groups by module; much more readable than raw",
          "Blast Radius — interactive d3.js; supports TF ≤0.12; good for historical configs",
          "This tool (Upload & Analyze) — parses raw .tf files; cross-file references; module source detection; draw.io XML export",
          "Terragrunt `graph-dependencies` — shows inter-module execution order as DOT graph",
        ]
      },
      {
        heading: "Zero-Trust DFD Security Layers",
        items: [
          "Layer 0 — Org/Root: TF manages SCPs → restricts every account below",
          "Layer 1 — Landing Zone: Platform TF owns VPC, TGW, DNS, RAM sharing",
          "Layer 2 — Security tooling: GuardDuty delegated admin, SecurityHub, Config aggregator via TF",
          "Layer 3 — Account baseline: CloudTrail, Config recorder, default SG lockdown applied via AFT pipeline",
          "Layer 4 — App networking: App team TF calls platform VPC module; gets pre-approved subnets/SGs only",
          "Layer 5 — App compute: App TF deploys workloads; IAM role has permission boundary from RVM",
          "Layer 6 — State plane: All state in S3+KMS; pipeline IAM role only; no human direct access",
          "Layer 7 — Policy gate: Sentinel policies in HCP TF check every plan before apply; hard-mandatory cannot be bypassed",
        ]
      }
    ]
  },

  wiz: {
    title: "Wiz CSPM — Cloud Security Posture",
    color: "#1A73E8", light: "#E8F0FE", accent: "#174EA6",
    icon: "🛡",
    sections: [
      {
        heading: "What is Wiz CSPM?",
        body: "Wiz is an agentless Cloud-Native Application Protection Platform (CNAPP) that provides continuous cloud security posture management. It connects to cloud environments via APIs — no agents required — delivering 100% visibility across VMs, containers, serverless, and AI workloads. Wiz uses a graph-based security context engine to correlate misconfigurations with exposure, identities, vulnerabilities, and lateral movement paths across AWS, Azure, GCP, OCI, and Alibaba Cloud."
      },
      {
        heading: "Cloud Configuration Rules (CCRs)",
        items: [
          "2,800+ built-in rules — assess security posture against cloud-native best practices",
          "Unified rule engine — same rules evaluate runtime AND Infrastructure-as-Code (Terraform, CloudFormation)",
          "Severity classification — Critical / High / Medium / Low with auto-prioritization",
          "Auto-remediation — rules can trigger automated fixes for known misconfiguration patterns",
          "Custom rules via OPA/Rego — author organization-specific policies using Open Policy Agent",
          "Rule lifecycle management — version-controlled via GitOps; deploy/test/rollback via CI/CD",
        ]
      },
      {
        heading: "AWS Detective Controls Integration",
        items: [
          "AWS Security Hub — Wiz findings pushed to Security Hub for centralized security dashboard",
          "AWS Config — Wiz correlates Config rule evaluations with graph-based attack path context",
          "Amazon GuardDuty — Wiz enriches GuardDuty findings with infrastructure topology and blast radius",
          "IAM Access Analyzer — Wiz maps IAM findings to actual resource exposure and lateral movement",
          "CloudTrail — Wiz analyzes API call patterns for anomaly detection and forensic investigation",
          "Detective controls complement preventive SCPs — detect what SCPs cannot prevent",
        ]
      },
      {
        heading: "Terraform Integration",
        items: [
          "Wiz HCP Terraform Connector — maps cloud resources back to Terraform definitions via state files",
          "Wiz Terraform Provider — manage Wiz policies, connectors, and configurations as code",
          "Wiz Code (IaC Scanning) — scans Terraform plans pre-deployment; catches misconfigurations before apply",
          "Run Tasks integration — Wiz scans execute as HCP Terraform run tasks; block non-compliant deploys",
          "Detective-to-preventive — runtime CCR findings inform new pre-deploy scan rules",
          "State file as source of truth — automatic IaC-to-cloud resource mapping with zero configuration",
        ]
      },
      {
        heading: "OPA / Rego Custom Rules",
        items: [
          "Open Policy Agent (OPA) engine — Wiz natively supports custom Rego policies",
          "Query cloud-native APIs — rules access full cloud resource graph for context-aware evaluation",
          "Policy-as-code workflow — author rules in Git, test in CI, deploy via Wiz API or Terraform provider",
          "Rego playground — test custom rules against live cloud graph before enforcement",
          "Shared policy library — organization-wide custom rule packages for consistent governance",
          "Graduated enforcement — warn → alert → block as rules mature from draft to production",
        ]
      },
      {
        heading: "Compliance Frameworks",
        items: [
          "250+ built-in compliance frameworks — continuous assessment and automated reporting",
          "PCI-DSS — payment card industry data security standard mapping",
          "CIS Benchmarks — Center for Internet Security hardening baselines for AWS, Azure, GCP, K8s",
          "SOC 2 Type II — service organization control trust criteria mapping",
          "HIPAA — healthcare information protection rule alignment",
          "NIST 800-53 / NIST CSF — federal information security framework controls",
          "AI-specific frameworks — emerging AI/ML security and governance standards",
          "Custom framework mapping — map internal policies to Wiz controls for unified reporting",
        ]
      },
      {
        heading: "Attack Path Analysis",
        items: [
          "Graph-based security context — correlates misconfigurations with real-world exploitability",
          "Toxic combination detection — identifies compound risks (e.g., public exposure + admin privs + unpatched CVE)",
          "Blast radius visualization — shows downstream impact of compromising a given resource",
          "Lateral movement mapping — traces potential attacker paths across VPCs, accounts, and services",
          "Priority scoring — risk-based ranking replaces volume-based alert fatigue",
          "Integration with DFD — attack paths overlay on architecture diagrams for executive reporting",
        ]
      },
      {
        heading: "Preventive vs Detective Controls",
        items: [
          "Preventive (shift-left) — Wiz Code scans IaC before deployment; blocks non-compliant Terraform plans",
          "Detective (runtime) — continuous cloud scanning detects drift, new misconfigurations, and anomalies",
          "SCPs = preventive guardrails — restrict what CAN happen at the AWS Organizations level",
          "Wiz CCRs = detective controls — detect what DID happen in runtime cloud configurations",
          "Complementary pairing — SCPs prevent + Wiz detects = defense-in-depth security posture",
          "Feedback loop — Wiz runtime findings drive new SCP rules and Terraform module hardening",
        ]
      }
    ]
  },

  // ── MITRE ATT&CK ──────────────────────────────────────────────────────────
  attack: {
    title: "MITRE ATT&CK® Enterprise v18.1 — Cloud / IaaS",
    color: "#B71C1C", light: "#FFEBEE", accent: "#7F0000",
    icon: "⚔",
    sections: [
      {
        heading: "Framework Overview — v18.1 (October 28, 2025)",
        body: "MITRE ATT&CK® v18.1 contains 14 tactics, 216 techniques, and 475 sub-techniques across the Enterprise matrix. The Cloud/IaaS layer covers AWS, Azure, GCP IaaS, SaaS, and Office 365.\n\n✅ VERSION v18.1 (October 28, 2025): New techniques include T1059.013 (Container CLI/API), T1677 (Poisoned Pipeline Execution), T1678 (Delay Execution), T1679 (Selective Exclusion), T1680 (Local Storage Discovery), T1681 (Search Threat Vendor Data), T1676 (Linked Devices), T1213.006 (Databases), T1546.018 (Python Startup Hooks), T1518.002 (Backup Software Discovery), T1562.013 (Disable/Modify Network Device Firewall), T1036.012 (Browser Fingerprint), T1485.001 (Lifecycle-Triggered Deletion), T1496.001-004 (Resource Hijacking sub-techniques), T1666 (Modify Cloud Resource Hierarchy), T1671 (Cloud Application Integration), T1673 (Virtual Machine Discovery), T1675 (ESXi Administration Command). 14 Tactics: TA0043 Reconnaissance, TA0042 Resource Development, TA0001-TA0011 (all standard tactics), TA0010 Exfiltration, TA0040 Impact. Source: attack.mitre.org"
      },
      {
        heading: "TA0043 · Reconnaissance",
        items: [
          "T1595 — Active Scanning: Systematically probe internet-facing cloud infrastructure (EC2, ALB, API Gateway, S3) for open ports, services, vulnerabilities. Sub: T1595.001 Scanning IP Blocks, T1595.002 Vulnerability Scanning, T1595.003 Wordlist Scanning. Mitigate: WAF rate limiting, GuardDuty IP threat intel, private endpoints.",
          "T1596 — Search Open Technical Databases: Use Shodan, Censys, certificate transparency logs, BGP databases to enumerate cloud infrastructure without active scanning. Sub: T1596.001 DNS/Passive DNS, T1596.002 WHOIS, T1596.003 Digital Certificates, T1596.004 CDNs, T1596.005 Scan Databases.",
          "T1593.003 — Search Code Repositories: Automated scanning of public GitHub/GitLab for leaked AWS keys, Terraform state files (terraform.tfstate), .env files, private keys. Mitigate: GitHub secret scanning, git-secrets pre-commit hooks, TruffleHog CI integration.",
          "T1590 — Gather Victim Network Information: Enumerate VPC CIDR ranges, public IP space, AS numbers via BGP, DNS, and AWS error messages (403 ARN exposure). Sub: T1590.001-T1590.006.",
          "T1589 — Gather Victim Identity Information: Identify AWS account IDs from error messages, IAM user emails from Cognito user pools, employee names for spearphishing. Sub: T1589.001 Credentials, T1589.002 Email Addresses, T1589.003 Employee Names.",
          "T1591 — Gather Victim Org Information: OSINT for cloud technologies, Terraform module sources, third-party vendor relationships, key personnel with AWS access. Sub: T1591.001-T1591.004.",
          "T1597 — Search Closed Sources: Purchase cloud credentials, exploits, or victim architecture data from dark web markets and breach databases. Sub: T1597.001 Threat Intel Vendors, T1597.002 Purchase Technical Data.",
          "T1681 — Search Threat Vendor Data (NEW v18): Adversaries monitor threat intelligence vendor reporting about their own campaigns to rotate infrastructure before defenders block it. Mitigate: Restrict threat intel platform access, monitor for unusual threat data queries.",
          "T1598 — Phishing for Information: Send phishing to cloud admins to elicit architecture info, credentials, or API documentation. Sub: T1598.001-T1598.004 including vishing (voice phishing for MFA bypass).",
          "T1594 — Search Victim-Owned Websites: Gather technical info from company websites, job postings (reveals tech stack), and developer documentation.",
          "Mitigations: S3 Block Public Access, GuardDuty malicious IP threat lists, private ECR registries, GitHub secret scanning, credential rotation when exposed.",
        ]
      },
      {
        heading: "TA0042 · Resource Development",
        items: [
          "T1583 — Acquire Infrastructure: Lease cloud VPS, domains, or serverless functions for staging and C2. Sub: T1583.001 Domains (look-alike domains), T1583.003 VPS, T1583.006 Web Services, T1583.007 Serverless (Lambda/Functions as C2). Mitigate: Egress allowlisting in security groups.",
          "T1586.003 — Compromise Cloud Accounts: Hijack legitimate cloud accounts via credential stuffing or MFA fatigue to use as trusted attack infrastructure. Detect: GuardDuty IAM credential anomaly findings.",
          "T1584 — Compromise Infrastructure: Compromise third-party managed services, CDN nodes, or SaaS providers used by the target. Sub: T1584.001-T1584.008.",
          "T1587 — Develop Capabilities: Develop custom malware, IaC backdoor templates, or tooling targeting specific cloud APIs. Sub: T1587.001 Malware, T1587.002 Code Signing Certs, T1587.004 Exploits.",
          "T1588 — Obtain Capabilities: Download or purchase cloud attack tools (Pacu, CloudFox, ScoutSuite, Stratus Red Team, CloudMapper). Sub: T1588.002 Tool, T1588.005 Exploits.",
          "T1608 — Stage Capabilities: Upload malicious container images or Terraform modules to cloud-accessible storage prior to use. Sub: T1608.001 Upload Malware, T1608.002 Upload Tool.",
          "T1677 — Poisoned Pipeline Execution (NEW v18): Compromise CI/CD pipeline inputs (Terraform modules, GitHub Actions workflows, container base images in ECR) to inject malicious code deployed to production via IaC pipelines. Mitigate: Pin Terraform module versions to exact git SHA, pin GitHub Actions to commit SHA (not @main/@v1), private module registry, artifact signing (Sigstore/Cosign), SBOM generation.",
          "T1585.003 — Establish Cloud Accounts: Create fake AWS accounts or IAM users mimicking internal naming conventions for attack infrastructure or persistence.",
          "Mitigations: Monitor for new accounts in AWS Organization, SCP deny LeaveOrganization, anomaly detection on new cross-account role trust relationships.",
        ]
      },
      {
        heading: "TA0001 · Initial Access",
        items: [
          "T1078.004 — Valid Accounts: Cloud Accounts: Compromised IAM access keys, console credentials, or service principal secrets. Mitigate: MFA on all human IAM users (aws:MultiFactorAuthPresent condition), access key rotation ≤90 days, CloudTrail ConsoleLogin anomaly monitoring, GuardDuty UnauthorizedAccess findings.",
          "T1190 — Exploit Public-Facing Application: Exploit unpatched CVEs in internet-facing cloud workloads (ALB-fronted apps, API Gateway backends, EC2 web servers, Lambda Function URLs). Mitigate: WAF with AWSManagedRulesCommonRuleSet, patch management, AWS Inspector vulnerability scanning.",
          "T1195 — Supply Chain Compromise: Malicious Terraform modules, container base images, Lambda layers, or NPM/PyPI packages injected into IaC deployments. Sub: T1195.001 Software Dependencies (package registry poisoning), T1195.002 Software Supply Chain (CI/CD artifact tampering), T1195.003 Hardware Supply Chain. Mitigate: Private Terraform registry, Cosign image signing, SBOM, Dependabot.",
          "T1566 — Phishing: Social engineering targeting cloud console users or developers. Sub: T1566.001 Spearphishing Attachment (malicious .tf file), T1566.002 Spearphishing Link (fake AWS SSO page), T1566.003 Via Service (Teams/Slack), T1566.004 Voice (vishing for MFA bypass). Mitigate: Phishing-resistant MFA (FIDO2/YubiKey), security awareness training.",
          "T1199 — Trusted Relationship: Compromise MSPs, consulting firms, or SaaS vendors with IAM cross-account access. Often via compromised third-party AssumeRole. Mitigate: aws:PrincipalOrgID condition on all cross-account trust policies, periodic third-party access review.",
          "T1133 — External Remote Services: Exploit VPN, SSM Session Manager, RDP/SSH bastions with compromised credentials. Mitigate: VPN with phishing-resistant MFA, SSM with CloudTrail logging, no direct internet SSH/RDP.",
          "T1659 — Content Injection: Inject malicious content into data channels (BGP hijacking, DNS poisoning, MITM on unencrypted connections) to redirect cloud traffic.",
          "T1669 — Wi-Fi Networks (v18): Access via wireless networks to reach hybrid environments with AWS Direct Connect connectivity.",
        ]
      },
      {
        heading: "TA0002 · Execution",
        items: [
          "T1059.009 — Command and Scripting Interpreter: Cloud API: Use AWS CLI, Boto3 SDK, or AWS CloudShell to execute commands against cloud APIs. Mitigate: Restrict IAM permissions for CLI, CloudTrail management+data events, disable CloudShell for non-admins.",
          "T1059.013 — Container CLI/API (NEW v18): Execute commands via container management APIs — Docker daemon API (/var/run/docker.sock), containerd gRPC API, Kubernetes exec/attach API — to run code inside containers without a traditional shell. Mitigate: Remove docker socket mounts from containers, restrict kubectl exec (EKS RBAC), Falco runtime rules for container exec, EKS Pod Security Standards (restricted profile).",
          "T1651 — Cloud Administration Command: Execute commands via AWS Systems Manager Run Command, EC2 Instance Connect, ECS Exec, SSM Session Manager. Mitigate: Restrict ssm:SendCommand to specific instance IDs/tags, SSM session logging to CloudWatch+S3, require MFA for session initiation.",
          "T1648 — Serverless Execution: Abuse Lambda functions, Step Functions, EventBridge rules, or API Gateway integrations for code execution without server management. Mitigate: Lambda resource policies restricting invocation, CloudTrail Lambda data events, concurrency limits.",
          "T1677 — Poisoned Pipeline Execution (NEW v18): Inject malicious code into CI/CD pipelines via direct modification (IAM access to CodeBuild/CodePipeline), indirect script injection (poisoned git refs, GitHub Actions), or malicious PRs. Mitigate: Branch protection, pipeline approval gates, OIDC-based IAM (not long-lived CI keys), minimal pipeline role permissions.",
          "T1610 — Deploy Container: Deploy malicious containers to ECS/EKS/Fargate. Mitigate: ECR scan-on-push, pod security admission (restricted), container image signing (Cosign), restrict ecs:RunTask/CreateService.",
          "T1204 — User Execution: Trick admins into executing malicious IaC (terraform apply on attacker module), Lambda packages, or container images. Sub: T1204.002 Malicious File, T1204.003 Malicious Image. Mitigate: Mandatory terraform plan review in PRs, IaC scanning gates.",
          "T1675 — ESXi Administration Command (v18): Exploit VMware Tools to execute commands on guest VMs from compromised ESXi hosts (hybrid xSphere+AWS environments).",
          "T1053.007 — Container Orchestration Job: Create Kubernetes CronJobs or ECS Scheduled Tasks for recurring malicious execution. Mitigate: Audit CronJob creation events, restrict batch/v1/cronjobs create/modify.",
        ]
      },
      {
        heading: "TA0003 · Persistence",
        items: [
          "T1136.003 — Create Account: Cloud Account: Create backdoor IAM users, service accounts, or Cognito users. Monitor CloudTrail: CreateUser, CreateLoginProfile, CreateAccessKey from unexpected principals.",
          "T1098.001 — Account Manipulation: Additional Cloud Credentials: Add extra IAM access keys via CreateAccessKey. Mitigate: Max 2 access keys per user, CloudTrail alert on CreateAccessKey, regular key audit.",
          "T1098.003 — Account Manipulation: Additional Cloud Roles: Attach additional IAM policies to existing roles (AttachRolePolicy, PutRolePolicy). Mitigate: IAM Access Analyzer, SCP deny AttachRolePolicy for non-admins, alert on policy modifications.",
          "T1098.006 — Account Manipulation: Additional Container Cluster Roles: Create privileged ClusterRole/RoleBindings in EKS. Mitigate: OPA/Kyverno admission control, RBAC audit.",
          "T1671 — Cloud Application Integration (v18): Create malicious OAuth application integrations in SaaS (Microsoft 365, Google Workspace) to maintain access through delegated permissions that survive password changes.",
          "T1525 — Implant Internal Image: Backdoor AMIs or ECR container images so all resources deployed from them are compromised. Mitigate: Image signing (Cosign), scan-on-push, immutable tags, periodic baseline comparison.",
          "T1546.018 — Event Triggered Execution: Python Startup Hooks (NEW v18): Abuse Python startup hooks (.pth files, sitecustomize.py, PYTHONSTARTUP env var) in Lambda Python runtimes or ECS Python containers to execute code on every Python invocation without modifying the main function. Mitigate: Lambda layer integrity checking, immutable container images, env var restrictions, Falco runtime security.",
          "T1505.003 — Web Shell: Plant web shells on EC2/ECS web servers for persistent backdoor. Mitigate: WAF detecting web shell signatures, immutable container images, runtime file integrity monitoring.",
          "T1078.004 — Valid Accounts: Cloud Accounts: Stolen long-lived IAM credentials used for persistent access without deploying tools. Mitigate: Anomaly detection, credential rotation, GuardDuty UnauthorizedAccess findings.",
          "T1053.007 — Container Orchestration Job: Kubernetes CronJobs in EKS for recurring malicious workloads surviving pod restarts. Also maps to Execution (TA0002).",
        ]
      },
      {
        heading: "TA0004 · Privilege Escalation",
        items: [
          "T1548.005 — Temporary Elevated Cloud Access: Exploit JIT access (IAM Identity Center), iam:PassRole to EC2/Lambda/ECS, or sts:AssumeRole with misconfigured trust for elevated permissions. Mitigate: MFA conditions in trust policies, restrict iam:PassRole to specific services (iam:PassedToService condition), time-limited JIT access.",
          "T1484.002 — Domain Trust Modification: Modify IAM trust policies (UpdateAssumeRolePolicy) to add external principals, creating persistent backdoor assume-role. Mitigate: SCP deny iam:UpdateAssumeRolePolicy for non-admins, CloudTrail alert on trust policy modifications.",
          "T1611 — Escape to Host: Break out of ECS containers or EKS pods to underlying EC2 host instance profile (more privileged). Attack vectors: privileged container, host namespace sharing, docker socket, runc vulnerabilities. Mitigate: No privileged containers, read-only rootfs, seccomp/AppArmor, pod security standards (restricted).",
          "T1068 — Exploitation for Privilege Escalation: Exploit unpatched kernel CVEs on EC2/EKS nodes for root access. Mitigate: AWS Inspector, patch management, EKS managed node groups with auto-update.",
          "IAM Escalation Paths: iam:CreatePolicyVersion (replace with admin policy), iam:SetDefaultPolicyVersion, iam:AttachRolePolicy (attach admin policy), iam:PutRolePolicy (add inline admin), iam:CreateAccessKey (on admin user), iam:AddUserToGroup (admin group), iam:PassRole + ec2:RunInstances (instance with admin profile). Detect: Cloudsplaining, IAM Access Analyzer policy generation, CIEM tools.",
          "T1134 — Access Token Manipulation: Steal/reuse AWS STS tokens or OAuth tokens to impersonate higher-privileged identities before expiry. Sub: T1134.001 Token Impersonation/Theft.",
          "T1098.003 — Additional Cloud Roles: Attach higher-privilege IAM policies to current role/user. Also maps to Persistence (TA0003).",
        ]
      },
      {
        heading: "TA0005 · Defense Evasion",
        items: [
          "T1578 — Modify Cloud Compute Infrastructure: Modify IaaS compute to evade detection or destroy evidence. Sub: T1578.001 Create Snapshot (exfil to attacker account), T1578.002 Create Cloud Instance (unused region), T1578.003 Delete Cloud Instance (destroy forensics), T1578.004 Revert Cloud Instance (eliminate artifacts), T1578.005 Modify Cloud Compute Configurations. Detect: CloudTrail EC2/RDS snapshot and instance lifecycle events.",
          "T1562.008 — Impair Defenses: Disable Cloud Logs: Disable CloudTrail, GuardDuty, Security Hub, AWS Config. Mitigate: SCP deny cloudtrail:DeleteTrail/StopLogging, guardduty:DeleteDetector, securityhub:DisableSecurityHub; immediate alerts on these API calls.",
          "T1562.013 — Disable/Modify Network Device Firewall (NEW v18): Modify cloud network security (Security Group rules with AuthorizeSecurityGroupIngress 0.0.0.0/0, NACL rules, WAF rules) to enable unrestricted access. Mitigate: Detect AuthorizeSecurityGroupIngress with /0 via Config rule restricted-ssh, SCP deny for critical SG modifications.",
          "T1666 — Modify Cloud Resource Hierarchy (v18): Use LeaveOrganization or account transfers to escape SCP guardrails and centralized security controls. Detect: CloudTrail LeaveOrganization event, alert immediately via SNS.",
          "T1535 — Unused/Unsupported Cloud Regions: Create resources in non-monitored regions where GuardDuty/Security Hub may not be enabled. Mitigate: SCP deny actions in non-approved regions (aws:RequestedRegion condition), Config aggregator all-regions.",
          "T1679 — Selective Exclusion (NEW v18): Selectively exclude specific resources or time windows from security monitoring or encryption to create blind spots. Mitigate: Prevent unapproved GuardDuty suppression rules and Security Hub suppressions via change management; SCP restrictions.",
          "T1678 — Delay Execution (NEW v18): Use time-based delays (sleep calls, EventBridge scheduled rules) to defer malicious execution past sandbox analysis timeouts and monitoring windows. Mitigate: Lambda execution time anomaly detection, behavioral analytics.",
          "T1036.012 — Browser Fingerprint (NEW v18): Manipulate browser fingerprinting (user agent, screen resolution, timezone, WebGL) to make automated/malicious sessions appear as legitimate human users, evading bot detection and fraud systems.",
          "T1070 — Indicator Removal: Delete CloudTrail S3 logs, CloudWatch log groups, VPC Flow Logs, or GuardDuty findings. Mitigate: S3 Object Lock on CloudTrail bucket, log file integrity validation, immutable audit log account.",
          "T1550.001 — Application Access Token: Use stolen OAuth tokens, Lambda execution tokens, or PATs without triggering MFA re-authentication.",
        ]
      },
      {
        heading: "TA0006 · Credential Access",
        items: [
          "T1552.005 — Unsecured Credentials: Cloud Instance Metadata API: SSRF exploits IMDSv1 endpoint (169.254.169.254) without auth to retrieve IAM role credentials. Capital One breach (2019): SSRF retrieved EC2 role credentials → accessed 106M customer S3 records. Mitigate: IMDSv2 (http_tokens = required in aws_instance metadata_options), hop limit = 1.",
          "T1552.001 — Credentials in Files: Plaintext credentials in Terraform state files (.tfstate), Lambda env vars, ECS task definition environment blocks, EC2 user_data, SSM non-SecureString. Mitigate: State encryption (SSE-KMS), manage_master_user_password=true for RDS, Secrets Manager for all credentials.",
          "T1555.006 — Cloud Secrets Management Stores: Unauthorized GetSecretValue on Secrets Manager, GetParameter on SSM SecureString. Mitigate: Resource-based policies restricting to specific IAM roles, CloudTrail data events on GetSecretValue, VPC endpoint policy.",
          "T1606.002 — Forge Web Credentials: SAML Tokens: Golden SAML — adversary obtains IdP (AD FS/Okta) private signing key and forges SAML assertions to authenticate as any AWS user without valid credentials. Mitigate: Protect IdP signing keys (HSM), SAML assertion encryption.",
          "T1528 — Steal Application Access Token: Steal OAuth tokens, Lambda role credentials, GitHub PATs, or Kubernetes service account tokens. Mitigate: Short token lifetimes, workload identity (IRSA/OIDC for EKS), no long-lived credentials in code.",
          "T1110.003 — Brute Force: Password Spraying: Spray common passwords against Cognito user pools or AWS IAM console users. Mitigate: Cognito Advanced Security (ENFORCED), account lockout, GuardDuty BruteForce findings.",
          "T1621 — MFA Request Generation: MFA bombing — generate excessive push notifications until user approves fraudulent auth. Mitigate: Number matching in MFA apps, suspicious MFA activity alerts, block after N declined requests.",
          "T1539 — Steal Web Session Cookie: Steal authenticated AWS console or application session cookies. Mitigate: Short console session durations (1hr), Secure+HttpOnly+SameSite=Strict cookie flags.",
        ]
      },
      {
        heading: "TA0007 · Discovery",
        items: [
          "T1580 — Cloud Infrastructure Discovery: Enumerate EC2, S3, RDS, Lambda, ECS, EKS, IAM via DescribeInstances, ListBuckets, DescribeDBInstances, ListRoles. Mitigate: Restrict discovery APIs to specific roles, GuardDuty Reconnaissance findings.",
          "T1087.004 — Account Discovery: Cloud Account: List IAM users/groups/roles via ListUsers, ListRoles, GetAccountAuthorizationDetails. Mitigate: Restrict iam:List* to security tooling accounts.",
          "T1526 — Cloud Service Discovery: Identify enabled AWS services, regions, accounts via DescribeRegions, ListFunctions, DescribeStacks. Mitigate: SCP restrict to approved regions.",
          "T1619 — Cloud Storage Object Discovery: Enumerate S3 bucket contents via ListObjectsV2. Mitigate: Bucket policies requiring authentication, S3 Block Public Access, CloudTrail S3 data events.",
          "T1613 — Container and Resource Discovery: Enumerate ECS clusters/tasks, EKS namespaces/pods, ECR repos/images. Mitigate: Restrict ecr:DescribeRepositories, ecs:ListTasks.",
          "T1518.001 — Security Software Discovery: Identify GuardDuty detectors, Security Hub, Config rules, WAF ACLs to plan evasion. Mitigate: Restrict guardduty:GetDetector, securityhub:GetFindings to security team roles.",
          "T1518.002 — Backup Software Discovery (NEW v18): Identify backup solutions (AWS Backup Vault, S3 versioning, RDS automated backups, Glacier vaults) to plan data destruction or ransomware. Mitigate: Restrict backup:ListBackupPlans, s3:GetBucketVersioning to backup admin roles.",
          "T1680 — Local Storage Discovery (NEW v18): Enumerate locally-attached cloud storage — EBS volumes (DescribeVolumes), instance store, EFS mounts — to identify exfiltration or encryption targets. Mitigate: Restrict ec2:DescribeVolumes, enforce EBS encryption, Macie for sensitive data scanning.",
          "T1538 — Cloud Service Dashboard: Access AWS Management Console with stolen credentials for visual reconnaissance. Mitigate: CloudTrail ConsoleLogin monitoring, IP-restricted console access.",
          "T1069.003 — Permission Groups Discovery: Cloud Groups: List IAM groups, attached policies, and members to identify escalation paths. Mitigate: Restrict iam:ListGroupsForUser, iam:GetGroupPolicy.",
          "T1673 — Virtual Machine Discovery (v18): Enumerate running VMs on compromised ESXi hosts or vCenter (esxcli vm process list) in hybrid environments.",
        ]
      },
      {
        heading: "TA0008 · Lateral Movement",
        items: [
          "T1021.007 — Remote Services: Cloud Services: Move between cloud services via compromised credentials — EC2 role → RDS → Secrets Manager → S3 → Lambda. IAM enables API-based lateral movement without network pivoting. Mitigate: VPC segmentation, IAM permission boundaries per-service, resource-based policies with aws:SourceVpc/aws:PrincipalOrgID.",
          "Cross-account AssumeRole: sts:AssumeRole to jump between AWS accounts in an Organization via existing trust relationships. Mitigate: SCPs restricting cross-account assume-role, aws:PrincipalOrgID on all trust policies, CloudTrail cross-account AssumeRole monitoring.",
          "T1611 — Escape to Host: Container escape from ECS/EKS to underlying EC2 host instance profile (more privileged). Vectors: privileged container, host PID namespace, docker socket, kernel exploits. Mitigate: Pod Security Standards (restricted), no privileged containers, seccomp/AppArmor, Falco.",
          "T1676 — Linked Devices (NEW v18): Exploit linked device trust relationships to move between cloud and on-premises — MDM-managed devices with both corporate network and AWS IAM access, Intune/Jamf-enrolled endpoints. Mitigate: Zero-trust device posture checks, conditional access requiring managed+compliant device.",
          "T1550.001 — Application Access Token: Reuse stolen OAuth tokens, Lambda role credentials, or PATs across downstream services for horizontal movement.",
          "T1021.001 — Remote Desktop Protocol: RDP to Windows EC2 instances. Mitigate: No direct port 3389, use SSM Session Manager for bastion-less access, session logging.",
          "T1021.004 — SSH: SSH to Linux EC2. Mitigate: No port 22 exposed, SSM Session Manager, EC2 Instance Connect (ephemeral keys), no permanent stored key pairs.",
          "VPC Peering/Transit Gateway: Traverse unrestricted VPC peering or Transit Gateway route tables to reach other environments. Mitigate: NACL source restrictions on peering, Transit Gateway policy tables, separate accounts per environment.",
          "EKS RBAC Escalation: Modify ClusterRoleBindings to expand namespace access or escalate to cluster-admin. Mitigate: OPA/Kyverno admission control, regular RBAC audit (kubectl auth can-i --list).",
        ]
      },
      {
        heading: "TA0009 · Collection",
        items: [
          "T1530 — Data from Cloud Storage: Read sensitive S3 data (PII, credentials, backups), EBS snapshots shared to attacker account, RDS snapshot exports. Mitigate: Bucket policies with aws:PrincipalOrgID, S3 Block Public Access, Macie for PII classification, CloudTrail S3 data events (GetObject).",
          "T1602 — Data from Configuration Repository: Access Terraform state files in S3 containing DB passwords, connection strings, private keys, API tokens in outputs. Mitigate: SSE-KMS encryption on state bucket, restrict bucket policy to pipeline role only, versioning enabled.",
          "T1213.006 — Data from Databases (NEW v18): Directly query cloud databases (RDS MySQL/PostgreSQL, Aurora, DynamoDB, DocumentDB, ElastiCache) to exfiltrate structured PII, credentials, business data. Mitigate: RDS IAM authentication (iam_database_authentication_enabled), VPC endpoint for database access, DynamoDB ABAC (dynamodb:LeadingKeys), db-level audit logging.",
          "T1213.003 — Data from Code Repositories: Steal source code from CodeCommit/GitHub including IaC with embedded credentials, private infrastructure docs. Mitigate: CodeCommit resource-based policy with MFA condition, GitHub SAML SSO with Advanced Security.",
          "T1213.001 — Data from Confluence: Access Confluence pages with AWS account IDs, runbooks, emergency credentials, architecture diagrams.",
          "T1681 — Search Threat Vendor Data (NEW v18): Access threat intel platforms, SIEM, or security vendor APIs with stolen credentials to understand what defenders know — enabling real-time evasion. Mitigate: Restrict security tooling access, monitor for unusual threat intel queries.",
          "T1005 — Data from Local System: Collect from EC2 filesystems (/etc/passwd, .ssh/, app configs), EBS volumes, Lambda /tmp.",
          "T1039 — Data from Network Shared Drive: Collect data from EFS or FSx shares mounted across EC2 fleet.",
          "T1560 — Archive Collected Data: Compress/encrypt collected data before exfiltration (tar+gpg on EC2, Lambda zip, S3 multipart upload for large datasets).",
        ]
      },
      {
        heading: "TA0011 · Command and Control (C2)",
        items: [
          "T1071.001 — Web Protocols: C2 via HTTPS callbacks to Lambda Function URLs, API Gateway endpoints, or CloudFront distributions to blend with legitimate web traffic. Mitigate: VPC Flow Logs, GuardDuty C2 findings, egress-only SGs restricting destination CIDRs.",
          "T1071.004 — DNS: DNS-based C2 using Route53-hosted zones for data exfil and command channels. Mitigate: Route53 Resolver DNS Firewall with C2 domain blocklists, DNSSEC, DNS query logging.",
          "T1102 — Web Service: Use legitimate cloud services as C2 relay — S3 bucket polling for commands, SQS bidirectional communication, SNS command push, GitHub API. Mitigate: Monitor API calls to S3/SQS/SNS from unexpected EC2, GuardDuty Backdoor findings.",
          "T1090.004 — Domain Fronting: Route C2 through CloudFront using Host header manipulation — SNI points to legitimate CDN but traffic goes to attacker origin. Mitigate: CloudFront strict origin policies, HTTP Host header inspection.",
          "T1090.001 — Internal Proxy: Use compromised EC2 instances or Lambda as C2 relay within VPC to hide true C2 source from perimeter monitoring.",
          "T1573 — Encrypted Channel: Encrypt C2 with TLS certificate pinning to prevent MITM detection. Custom encryption over DNS/ICMP. AWS KMS-encrypted SQS payloads.",
          "T1568 — Dynamic Resolution: DGA or fast-flux DNS to dynamically change C2 domains, preventing blocklist blocking. Route53 API can programmatically rotate DNS records.",
          "T1572 — Protocol Tunneling: Tunnel C2 through SSH, DNS, or HTTP(S) to evade protocol-specific controls.",
          "Mitigations: VPC Flow Logs (all traffic), Route53 Resolver DNS Firewall, GuardDuty threat intel, egress SGs allowing only specific ports/CIDRs, PrivateLink for all AWS service access.",
        ]
      },
      {
        heading: "TA0010 · Exfiltration",
        items: [
          "T1537 — Transfer Data to Cloud Account: Exfiltrate S3 data to adversary-controlled AWS account via cross-account PutObject or aws s3 sync, or share EBS/RDS snapshots. Mitigate: S3 bucket policies with aws:PrincipalOrgID deny, VPC endpoint policy restricting to org accounts.",
          "T1567.002 — Exfiltration to Cloud Storage: Transfer to attacker-controlled S3 (different account), GCS, or Azure Blob. Mitigate: VPC endpoint policies allowing only org-account S3, egress filtering.",
          "T1567.001 — Exfiltration to Code Repository: Push sensitive data to public GitHub/GitLab repos disguised as code commits.",
          "T1567.004 — Exfiltration Over Webhook: Use SES, SNS, EventBridge API Destinations, or Lambda HTTP calls to send data to attacker-controlled webhooks.",
          "T1048 — Exfiltration Over Alternative Protocol: Exfiltrate via DNS queries (Route53 subdomain encoding), ICMP, or non-HTTP protocols to bypass HTTP monitoring.",
          "T1485.001 — Lifecycle-Triggered Deletion (NEW v18): Modify S3 lifecycle policies or DynamoDB TTL to schedule deletion of specific objects — time-delayed data destruction appearing as normal administration.",
          "T1030 — Data Transfer Size Limits: Split exfiltration into small chunks below CloudWatch threshold alarms to evade volume-based detection.",
          "Detect via: CloudTrail S3 data events (GetObject/PutObject volumes), cross-account PutObject events, CloudWatch Network metrics, GuardDuty Exfiltration findings (Exfiltration:S3/ObjectRead.Unusual, Policy:S3/BucketBlockPublicAccessDisabled), Macie sensitive data disclosures, VPC Flow Logs to non-approved CIDRs.",
        ]
      },
      {
        heading: "TA0040 · Impact",
        items: [
          "T1485 — Data Destruction: Delete S3 objects/versions (DeleteObject, DeleteObjects), suspend bucket versioning, delete RDS instances, DynamoDB tables, EBS volumes. Mitigate: S3 Object Lock (COMPLIANCE mode), MFA delete, RDS deletion_protection=true, DynamoDB deletion_protection_enabled=true, SCP deny DeleteBucket.",
          "T1490 — Inhibit System Recovery: Delete/modify AWS Backup vaults, RDS snapshots, S3 versioning (PutBucketVersioning:Suspended), Terraform state. Mitigate: AWS Backup Vault Lock (WORM), separate backup account with restrictive SCP, S3 Object Lock on backup objects, cross-account copies.",
          "T1496.001 — Resource Hijacking: Compute Hijacking: Deploy XMRig or GPU cryptomining on EC2, Lambda (up to 15min × max concurrency), ECS/Fargate. Detect: GuardDuty CryptoCurrency findings, CPUUtilization alarms, billing anomaly detection, mining pool network connections.",
          "T1496.004 — Resource Hijacking: Cloud Service Hijacking: Abuse SES for spam, SNS for mass notifications, API Gateway as proxy. Detect: SES sending quota spikes, GuardDuty Backdoor:EC2/SMTP findings.",
          "T1486 — Data Encrypted for Impact: Ransomware overwriting S3 objects with attacker-encrypted versions (attacker KMS key), encrypting EBS volumes, running OS-level ransomware on EC2. Mitigate: S3 versioning + MFA delete + Object Lock, AWS Backup Vault Lock, cross-account immutable backups, SCP deny kms:DisableKey.",
          "T1491.002 — External Defacement: Modify CloudFront-served S3 static site or ALB-fronted web app. Mitigate: S3 versioning, CloudFront signed URLs for writes, CodePipeline as sole deployment mechanism.",
          "T1531 — Account Access Removal: Delete IAM users, rotate all credentials, modify root MFA to lock out admins during attack. Mitigate: SCP protecting breakglass accounts, Config rules for IAM changes.",
          "T1498 — Network Denial of Service: Volumetric DDoS against public ALB, API Gateway, CloudFront. Mitigate: AWS Shield Advanced (L3/L4 DDoS), CloudFront for absorption, WAF rate-based rules.",
          "T1657 — Financial Theft: Cryptomining on GPU instances ($25+/hr → $600+/day), click fraud, BEC targeting cloud finance ops. AWS bills of $100K+ reported from compromised accounts.",
          "T1565 — Data Manipulation: Alter data at rest in RDS/DynamoDB/S3 to corrupt business logic, financial records, or cause compliance violations without triggering availability-based alerts.",
        ]
      },
    ]
  },

  // ── MITRE CWE ─────────────────────────────────────────────────────────────
  cwe: {
    title: "MITRE CWE — Common Weakness Enumeration",
    color: "#E65100", light: "#FBE9E7", accent: "#BF360C",
    icon: "🕳",
    sections: [
      {
        heading: "Framework Overview & Version Notice",
        body: "The Common Weakness Enumeration (CWE) is a community-developed list of software and hardware weakness types maintained by MITRE. It provides a common language for describing root-cause security weaknesses in architecture, design, code, or implementation. CWE-IDs are referenced by CVEs, OWASP, NIST, and automated scanning tools.\n\n⚠️ VERSION NOTICE: This knowledge base reflects CWE v4.16 (2025) and the 2025 CWE Top 25 Most Dangerous Software Weaknesses. CWE entries are updated regularly. Always verify at cwe.mitre.org for the current authoritative list. The Top 25 is published annually and severity rankings change."
      },
      {
        heading: "CWE-284 · Improper Access Control (Pillar)",
        items: [
          "Pillar weakness (highest abstraction) — product does not restrict or incorrectly restricts access to a resource from an unauthorized actor",
          "Cloud examples: misconfigured S3 bucket ACLs granting public access, IAM wildcard policies (Action:* Resource:*), public RDS instances, unprotected API endpoints, default security groups",
          "Descendants: CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-285 (Improper Authorization), CWE-732 (Incorrect Permission Assignment)",
          "Terraform mitigation: aws_s3_bucket_public_access_block with all four booleans = true, scoped IAM policies, aws_api_gateway_method with authorization != NONE",
          "Severity: Ranges from CRITICAL (public data exposure) to HIGH (unauthorized resource access)",
        ]
      },
      {
        heading: "CWE-732 · Incorrect Permission Assignment for Critical Resource",
        items: [
          "Product specifies permissions for a security-critical resource that allow it to be read or modified by unintended actors",
          "Cloud examples: S3 bucket readable by public/anonymous users, IAM policies with Resource:* on sensitive services, overly broad KMS key policies, EC2 AMIs shared publicly",
          "Consequence — confidentiality: read credentials, configs, PII; integrity: modify critical data; availability: delete/destroy critical resources",
          "Terraform mitigation: principle of least privilege in aws_iam_policy documents, explicit resource ARNs (not *), KMS key policies with specific principal ARNs",
          "Detection: AWS IAM Access Analyzer, Checkov CKV_AWS_* rules, S3 Block Public Access settings",
        ]
      },
      {
        heading: "CWE-862 · Missing Authorization (Class)",
        items: [
          "Product does not perform an authorization check when an actor attempts to access a resource or perform an action",
          "Cloud examples: Lambda functions invokable without authentication (aws_lambda_permission with principal=*), API Gateway without authorizer (authorization=NONE on public methods), public ALB without WAF or auth",
          "Consequence: unauthorized data access, unauthorized resource modification, privilege escalation without any IAM check",
          "Terraform mitigation: API Gateway with authorization=AWS_IAM or COGNITO_USER_POOLS, Lambda resource policies restricting invocation principals",
          "Detection: Automated scan for authorization=NONE on API Gateway methods, lambda:InvokeFunction with Principal='*'",
        ]
      },
      {
        heading: "CWE-311 · Missing Encryption of Sensitive Data",
        items: [
          "Product transmits or stores sensitive data without encryption, leaving it readable if storage or network is compromised",
          "Cloud examples: RDS without storage_encrypted=true, S3 without SSE configuration, EBS without encrypted=true, ElastiCache without transit_encryption_enabled, Lambda environment vars with plaintext credentials",
          "Consequence: information disclosure if storage media is compromised, backup file accessed, or data intercepted in transit",
          "Terraform mitigation: aws_db_instance.storage_encrypted=true, aws_s3_bucket_server_side_encryption_configuration, aws_ebs_volume.encrypted=true, aws_elasticache_replication_group.transit_encryption_enabled=true",
          "Compliance: Required by PCI-DSS 3.4, HIPAA §164.312(e)(2)(ii), FedRAMP SC-28",
        ]
      },
      {
        heading: "CWE-326 · Inadequate Encryption Strength",
        items: [
          "Product stores or transmits sensitive data using an encryption scheme that is insufficient to protect confidentiality against anticipated attacks",
          "Cloud examples: TLS 1.0/1.1 on ALB listeners, weak cipher suites on CloudFront, KMS key without annual rotation, MD5/SHA1 for integrity checks",
          "Terraform mitigation: aws_lb_listener.ssl_policy = ELBSecurityPolicy-TLS13-1-2-2021-06 (TLS 1.3 preferred), aws_cloudfront_distribution.viewer_certificate.minimum_protocol_version = TLSv1.2_2021",
          "KMS: aws_kms_key.enable_key_rotation = true for automatic annual key rotation",
          "Compliance: NIST SP 800-52 requires TLS 1.2 minimum; TLS 1.3 recommended",
        ]
      },
      {
        heading: "CWE-306 · Missing Authentication for Critical Function",
        items: [
          "Product does not require authentication for functionality that requires a provable identity or authorization",
          "Cloud examples: EC2 IMDSv1 (no authentication token required — SSRF can directly retrieve credentials), public S3 objects with no authentication, HTTP-only ALB listener without redirect",
          "EC2 IMDSv1 impact: Any SSRF vulnerability can retrieve IAM role credentials without any additional authentication step",
          "Terraform mitigation: aws_instance with metadata_options { http_tokens = required http_endpoint = enabled }, force HTTP→HTTPS redirect on ALB",
          "Why IMDSv2 matters: IMDSv2 requires a PUT request to obtain a session token before GET credential requests — breaks most SSRF chains",
        ]
      },
      {
        heading: "CWE-400 · Uncontrolled Resource Consumption",
        items: [
          "Product does not properly control the allocation and maintenance of a limited resource — enabling DoS or cost explosion",
          "Cloud examples: Lambda without concurrency limits, SQS without dead-letter queue, API Gateway without throttling/usage plans, ASG without max_size, DynamoDB without capacity limits",
          "Financial DoS: In cloud environments, resource exhaustion also causes unexpected cost explosion — effectively a financial denial of service",
          "Terraform mitigation: aws_lambda_function.reserved_concurrent_executions, aws_api_gateway_usage_plan with throttle settings, aws_autoscaling_group.max_size, aws_sqs_queue with redrive_policy",
          "Detection: CloudWatch billing alarms, Budget alerts, Lambda throttling metrics",
        ]
      },
      {
        heading: "CWE-798 · Use of Hard-coded Credentials",
        items: [
          "Product contains hard-coded credentials (password, cryptographic key, API token) in source code or IaC",
          "Cloud examples: Terraform variable default values containing passwords, aws_db_instance.password as plaintext literal, API keys in Lambda environment variables, access keys in provider blocks",
          "Supply chain risk: Hard-coded credentials in IaC committed to version control expose secrets to all repo viewers and in git history",
          "Terraform mitigation: No defaults on sensitive variables (sensitive=true), aws_db_instance.manage_master_user_password=true (Secrets Manager integration), data.aws_secretsmanager_secret_version references",
          "Detection: TruffleHog, GitGuardian, git-secrets pre-commit hooks; Checkov CKV_SECRET checks",
        ]
      },
      {
        heading: "CWE-269 · Improper Privilege Management",
        items: [
          "Product does not properly assign, modify, track, or check privileges — resulting in excessive access that amplifies blast radius of any compromise",
          "Cloud examples: IAM policies with Action:* Resource:*, EC2 instance profiles with AdministratorAccess, EKS pods with cluster-admin ClusterRole, Lambda execution roles with full S3/RDS/IAM access",
          "Blast radius: A single compromised credential with excessive privileges can reach all resources in account — equivalent of a domain admin compromise in on-prem environments",
          "Terraform mitigation: Scoped IAM policies (specific actions, specific resource ARNs), aws_iam_role with permission_boundaries, SCP guardrails via aws_organizations_policy",
          "Best practice: IAM Access Analyzer for external access analysis; Trusted Advisor for unused permissions; CIEM tools for cloud identity governance",
        ]
      },
      {
        heading: "CWE-778 · Insufficient Logging",
        items: [
          "Product does not log security-relevant events, losing forensic capability and violating compliance requirements",
          "Cloud examples: No aws_cloudtrail resource (or not multi-region), no vpc_flow_log for network traffic, no aws_cloudwatch_log_group for Lambda retention, no S3 server access logging, no ALB access logs",
          "Forensic impact: Without logging, breach investigations cannot determine timeline, scope, attacker path, or exfiltrated data volume",
          "Terraform mitigation: aws_cloudtrail with is_multi_region_trail=true and include_global_service_events=true, aws_flow_log on all VPCs, aws_s3_bucket_logging, aws_lb.access_logs",
          "Compliance: Required by SOC 2, PCI-DSS 10.x, HIPAA §164.312(b), FedRAMP AU-2/AU-3",
        ]
      },
      {
        heading: "CWE-16 · Configuration (Class) — IaC Misconfiguration",
        items: [
          "Weakness introduced during system configuration — the parent category for cloud infrastructure misconfiguration findings",
          "Cloud examples: Default VPC in use with default security group, default KMS keys instead of customer-managed (CMK), public AMIs, default S3 encryption (SSE-S3 vs SSE-KMS), permissive default NACL",
          "IaC-specific: Terraform configurations that omit security attributes often inherit insecure defaults from AWS — the absence of a setting can be as dangerous as an incorrect setting",
          "Mitigation: IaC scanning (Checkov, tfsec, Terrascan), CSPM continuous monitoring (Wiz, Security Hub, AWS Config), terraform plan review gates in CI/CD",
          "Principle: Secure by default — every resource definition should explicitly set all security-relevant attributes rather than relying on provider defaults",
        ]
      },
    ]
  },

  // ── STRIDE-LM ─────────────────────────────────────────────────────────────
  stride: {
    title: "STRIDE-LM — Threat Modeling Framework",
    color: "#4527A0", light: "#EDE7F6", accent: "#311B92",
    icon: "🎯",
    sections: [
      {
        heading: "Framework Overview",
        body: "STRIDE-LM extends Microsoft's original STRIDE threat modeling methodology (1999, Loren Kohnfelder & Praerit Garg) with a Lateral Movement (LM) category attributed to Lockheed Martin practitioners in the context of network defense and cyber kill chain analysis.\n\nSTRIDE categorizes threats by what the adversary is doing (their goal). Each letter represents a distinct threat category. STRIDE-LM adds LM (Lateral Movement) as a seventh category — critical for cloud environments where a single compromised credential can reach dozens of services across multiple accounts and regions.\n\nUse STRIDE-LM during architecture decomposition: for each component and data flow in your Terraform architecture, ask which of the 7 categories an adversary could exploit."
      },
      {
        heading: "STRIDE-LM vs STRIDE",
        items: [
          "STRIDE (Microsoft, 1999): Spoofing · Tampering · Repudiation · Information Disclosure · Denial of Service · Elevation of Privilege — 6 categories",
          "STRIDE-LM: Adds Lateral Movement as a 7th category, attributed to Lockheed Martin network defense practitioners",
          "Why LM is distinct from EoP: Elevation of Privilege = gaining higher permissions on the SAME system. Lateral Movement = using any-level permissions to move to DIFFERENT systems/services/accounts",
          "Cloud relevance: In AWS, a single IAM role can access 100+ services — lateral movement between services is the primary post-compromise threat, not traditional network pivoting",
          "Practical difference: EC2 compromise → SSM privilege escalation = EoP (STRIDE E). EC2 role → S3 → Secrets Manager → RDS = Lateral Movement (STRIDE-LM L)",
          "Application: Apply all 7 categories to each Terraform resource type and each data flow in your connection graph",
        ]
      },
      {
        heading: "S · Spoofing Identity",
        items: [
          "Definition: Impersonating another user, service, or system component to gain unauthorized access to resources or perform actions under a false identity",
          "Cloud/IaC examples: Compromised IAM credentials impersonating legitimate developers, forged JWT/SAML tokens for SSO bypass, unauthorized EC2 instance impersonating internal API endpoint, typosquatting Terraform module names",
          "Terraform attack surface: aws_iam_role trust policies allowing overly broad principal assumptions (Principal: '*'), OIDC providers without sub/aud condition constraints, no MFA enforcement on sensitive assume-role actions",
          "Controls: MFA conditions in IAM trust policies (aws:MultiFactorAuthPresent), OIDC aud+sub condition keys, VPC endpoint policies, mutual TLS for service-to-service auth, digital certificate enforcement",
          "Detection: CloudTrail ConsoleLogin events from unexpected geo, AssumeRole from unknown principals, GuardDuty credential anomaly findings (UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration)",
        ]
      },
      {
        heading: "T · Tampering with Data",
        items: [
          "Definition: Altering data, code, configurations, or system state without authorization — making the system less trustworthy or useful to legitimate users",
          "Cloud/IaC examples: Modifying Terraform configurations to inject backdoor IAM policies, tampering with CI/CD pipeline build artifacts, compromised instance writing corrupt data to RDS/DynamoDB, unauthorized S3 object overwrite",
          "Terraform attack surface: S3 state bucket without versioning + MFA delete, no DynamoDB state lock allowing concurrent modifications, unprotected ECR image repositories, CI/CD roles with write access to state",
          "Controls: S3 Object Lock + versioning on state bucket, DynamoDB state locking, code signing for IaC and container images, Git branch protection + required reviews, CloudTrail log file integrity validation",
          "Detection: CloudTrail API calls on state bucket (unexpected PutObject/DeleteObject), DynamoDB stream anomalies, CodePipeline execution without approval stage",
        ]
      },
      {
        heading: "R · Repudiation",
        items: [
          "Definition: An actor's ability to plausibly deny having performed an action — loss of accountability and forensic capability",
          "Cloud/IaC examples: Infrastructure changes without audit trail (no CloudTrail), service account activity with no logging, attacker disabling CloudTrail before conducting operations, no S3 access logging for data access audit",
          "Terraform attack surface: Missing aws_cloudtrail resource, CloudTrail not multi-region (missing global service events), no S3 server access logging, no ALB/API Gateway access logs, Lambda without log group retention",
          "Controls: Immutable CloudTrail logging to write-protected S3 bucket, CloudTrail log file integrity validation (SHA-256 digest), CloudWatch Logs with tamper-resistant retention, dedicated audit account for centralized log aggregation",
          "Critical alert: cloudtrail:StopLogging, cloudtrail:DeleteTrail, cloudtrail:PutEventSelectors must generate immediate PagerDuty/SNS alerts",
        ]
      },
      {
        heading: "I · Information Disclosure",
        items: [
          "Definition: Exposing sensitive information (credentials, PII, architecture details, business data) to actors who are not authorized to access it",
          "Cloud/IaC examples: Public S3 buckets containing PII or credentials, unencrypted RDS/EBS/ElastiCache, IMDSv1 SSRF enabling credential theft, Terraform state files with plaintext DB passwords, Lambda env vars with API keys, misconfigured CloudFront caching private data",
          "Terraform attack surface: Missing aws_s3_bucket_public_access_block, no server-side encryption on S3/RDS/EBS, outputs without sensitive=true for credentials, variables with sensitive defaults, Lambda environment with credential patterns",
          "Controls: S3 Block Public Access (all 4 settings), encryption at rest (KMS CMK), encryption in transit (TLS 1.2+), Secrets Manager for all credentials, IMDSv2 enforcement, Terraform sensitive=true on all credential variables and outputs, Macie for S3 data classification",
          "Detection: GuardDuty S3:BucketPublicAccess findings, Macie sensitive data alerts, CloudTrail GetSecretValue anomalies, unexpected GetObject volumes",
        ]
      },
      {
        heading: "D · Denial of Service",
        items: [
          "Definition: Making the system unavailable to legitimate users — through resource exhaustion, system crashes, data destruction, or cost explosion",
          "Cloud/IaC examples: Lambda concurrency exhaustion blocking all invocations, cryptocurrency mining consuming EC2 capacity, RDS deletion causing application outage, DDoS against public ALB/API Gateway, DynamoDB WCU exhaustion via write-heavy attack",
          "Financial DoS: In cloud environments resource exhaustion also causes unexpected cost explosion — AWS monthly bills of $100K+ reported from compromised accounts running GPU instances",
          "Terraform attack surface: Lambda without reserved_concurrent_executions, API Gateway without throttling, RDS without deletion_protection=true, no aws_shield_subscription or aws_wafv2_web_acl, no aws_backup_vault",
          "Controls: AWS Shield Advanced for L3/L4 DDoS, WAF for L7, Lambda concurrency limits, API Gateway throttling/usage plans, RDS + DynamoDB deletion protection, AWS Budgets with anomaly alerts, AWS Backup with Vault Lock",
          "Detection: CloudWatch billing anomaly detection, GuardDuty EC2 resource hijacking findings, Lambda throttling alarms",
        ]
      },
      {
        heading: "E · Elevation of Privilege",
        items: [
          "Definition: Gaining capabilities or access permissions beyond what was explicitly granted — moving from limited to higher privilege within the same system or account",
          "Cloud/IaC examples: IAM policy with Action:* enabling unintended admin access, sts:AssumeRole misconfiguration allowing cross-account escalation, Lambda execution role with iam:* permissions, iam:CreatePolicyVersion to replace restrictive policy with admin policy",
          "Common IAM escalation paths: iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:CreateAccessKey, iam:CreateLoginProfile, iam:AttachRolePolicy, iam:PutRolePolicy, iam:PassRole — each can be abused for EoP",
          "Terraform attack surface: aws_iam_policy with Action=['*'] or Resource=['*'], no permission boundaries on roles, trust policies without conditions, AdministratorAccess managed policy attachments",
          "Controls: Least privilege (specific actions + specific resource ARNs), permission boundaries on all roles (aws_iam_role.permissions_boundary), SCP deny iam:CreatePolicyVersion in member accounts, regular IAM Access Analyzer reviews, JIT privileged access model",
          "Detection: CloudTrail AttachRolePolicy, PutRolePolicy, CreatePolicyVersion events from non-admin principals; IAM Access Analyzer external access findings",
        ]
      },
      {
        heading: "LM · Lateral Movement",
        items: [
          "Definition: Expanding access and control beyond the initial point of compromise — moving between resources, services, accounts, or regions to reach additional targets",
          "Origin: Added by Lockheed Martin practitioners extending STRIDE for network defense where post-compromise containment is as important as initial defense",
          "Why LM is critical for cloud: AWS IAM allows a single role to access 100+ services API-first — lateral movement happens via API calls, not network pivoting. A compromised Lambda role can reach RDS, S3, Secrets Manager, and SQS in seconds.",
          "Cloud/IaC examples: Compromised EC2 role accessing RDS + Secrets Manager + S3 in sequence, cross-account sts:AssumeRole chaining through multiple accounts, VPC peering exploitation for inter-environment access, EKS pod escape to node instance profile, Lambda→SQS→Lambda chaining for multi-hop movement",
          "Terraform attack surface: Unrestricted VPC peering without NACL restrictions, Transit Gateway allowing all-to-all cross-VPC traffic, EC2 instance profiles with broad service permissions, EKS RBAC without namespace isolation, Lambda roles with access to multiple sensitive services",
          "Controls: Network segmentation (private subnets, NACLs with source-SG references, VPC endpoint policies), IAM permission boundaries limiting service-to-service access, aws:SourceVpc / aws:PrincipalOrgID conditions, EKS Network Policies + pod security, service mesh mTLS",
          "Detection: VPC Flow Logs for unexpected inter-service traffic patterns, CloudTrail AssumeRole chains across accounts, GuardDuty findings for unusual cross-service API patterns",
        ]
      },
      {
        heading: "Applying STRIDE-LM to Terraform",
        items: [
          "Step 1 — Decompose: Identify all Terraform resources by tier (xSphere, Org, Security, CI/CD, Network, Compute, Storage) using the DFD Output",
          "Step 2 — Map data flows: Use the connection graph (implicit refs, explicit depends_on, module inputs) to identify how resources interact — each connection is a potential threat path",
          "Step 3 — Apply per-element: For each resource type and connection, ask: which STRIDE-LM categories apply? Document as: 'An attacker can [threat category] [component] to achieve [impact]'",
          "Step 4 — Rate risk: Severity = Likelihood × Impact. CVSS v3.1 or DREAD scoring. Prioritize findings by actual exploitability given your architecture.",
          "Step 5 — Map to Terraform controls: For each threat, identify the specific Terraform attribute or resource that mitigates it. Reference the Security Findings tab for automated detection.",
          "Step 6 — Automate validation: Checkov, tfsec, Terrascan in CI/CD pipeline. Policy-as-Code via Sentinel or OPA. CSPM for runtime drift detection.",
          "Per-tier STRIDE-LM analysis: Available in the Threataform Analysis section after uploading your Terraform files — generates tier-by-tier threat mapping based on your actual resources.",
        ]
      },
    ]
  },

  // ── TFE-PAVE PATTERN ──────────────────────────────────────────────────────
  tfePave: {
    title: "TFE-Pave — Hierarchical IAM & Enterprise Terraform Layers",
    color: "#2E7D32", light: "#E8F5E9", accent: "#1B5E20",
    icon: "🏗",
    sections: [
      {
        heading: "What is the Pave Pattern?",
        body: "In enterprise Terraform deployments, 'paving' refers to laying the foundational IAM, networking, and governance controls before workloads are deployed. The pave pattern is a layered hierarchy where each layer deploys only within the permissions granted by the layer above it. This creates nested permission ceilings — SCPs constrain accounts, permission boundaries constrain roles, and session policies constrain assume-role chains — forming a defense-in-depth IAM architecture."
      },
      {
        heading: "The Five-Layer Pave Hierarchy",
        items: [
          "Layer 0 — Org/Management: TF manages AWS Organizations, SCPs, OU structure, Control Tower landing zone. OrganizationAccountAccessRole. Runs from management account or delegated admin. Controls ALL layers below via SCP deny trees.",
          "Layer 1 — Account Vending (AFT): Account Factory for Terraform provisions new AWS accounts via Git PR. Bootstraps IAM Identity Center permission sets. Enrolls accounts into OUs. Deploys account-level SCPs. tfe-account-vending-role has sts:AssumeRole into new accounts.",
          "Layer 2 — Account Pave (Baseline): Per-account baseline IaC runs immediately after account creation. Deploys CloudTrail, Config recorder, default SG lockdown, GuardDuty enrollment, SecurityHub. Creates pave-role with permission boundary. The permission boundary is the ceiling all downstream roles inherit.",
          "Layer 3 — Product Pave (Platform Team): Platform/SRE team IaC deploys shared VPC, Transit Gateway attachments, shared security groups, Route53 zones. Creates ProductTeamDeployer role for the product team. Role has permission boundary that CANNOT exceed what Layer 2 granted.",
          "Layer 4 — Service Pave (Product Team): Individual product team IaC deploys their service resources (ECS, RDS, Lambda, Kinesis). ServiceRole created here is bounded by ProductTeamDeployer boundary. Wildcards at this layer are CONDITIONALLY SAFE — see Wildcard Safety section.",
        ]
      },
      {
        heading: "Key Roles at Each Layer",
        items: [
          "OrganizationAccountAccessRole (Layer 0) — Auto-created in new member accounts. Full admin in the account but controlled by management account trust. Guard with strict MFA + IP conditions on management account.",
          "tfe-pave-role (Layer 2) — Assumed by TFE runners for account baseline. Created with iam:PassRole restriction. Must include permission boundary attachment as a condition (SCP enforces this).",
          "PlatformDeployer / SRE-Deployer (Layer 3) — Platform team's Terraform role. Can create VPCs, TGW attachments, shared SGs. CANNOT exceed the permission boundary set in Layer 2. Cannot modify SCPs or OU structure.",
          "ProductTeamDeployer (Layer 3→4) — Created by Platform team for each product team. Scoped to specific services. Permission boundary enforced. May have iam:CreateRole if PB condition is required (SCP-enforced).",
          "ServiceRole (Layer 4) — Runtime role for the actual service (ECS task role, Lambda execution role). Created by ProductTeamDeployer. Bounded by ProductTeamDeployer's permission boundary ceiling. This is where wildcard policies MAY appear.",
          "OIDC Identity Providers (all layers) — TFE/GitHub Actions assume roles via OIDC. Sub-claim MUST be workspace-scoped: `repo:org/repo:ref:refs/heads/main` or TFE workspace ID. Global `sub: *` is a critical vulnerability.",
        ]
      },
      {
        heading: "Wildcard IAM Policies — When Safe vs Dangerous",
        items: [
          "SAFE: Wildcard on a specific service at Layer 4 when ALL of: (1) SCP restricts the account to approved services only, (2) Permission boundary caps maximum privilege (IAM boundary policy), (3) iam:* and sts:AssumeRole * are explicitly excluded from the wildcard scope, (4) Resource ARN scoped to specific prefix/account/region.",
          "SAFE example: `kinesis:*` on `arn:aws:kinesis:us-east-1:123456789:stream/product-team-*` — bounded by PB + SCP, resource-scoped to team prefix. Even if the role is compromised, blast radius is limited to that team's Kinesis streams.",
          "DANGEROUS: Wildcard iam:* — can create new roles, modify permission boundaries, attach admin policies. Escape hatch for the entire permission hierarchy. NEVER acceptable at any pave layer.",
          "DANGEROUS: sts:AssumeRole on * — cross-account pivot vector. Allows assuming ANY role in ANY account if trust policy permits. SCP deny-all sts:AssumeRole except specific targets required.",
          "DANGEROUS: Wildcard in management account or Layer 0/1 — no SCP ceiling applies to management account. Any wildcard here is truly unrestricted admin.",
          "DANGEROUS: s3:* on * (no resource scope) — can read any S3 bucket including terraform.tfstate files containing secrets, other teams' outputs, cross-account ARNs. State files are secrets.",
          "DANGEROUS: Wildcard without permission boundary — if iam:CreateRole is permitted without requiring the boundary ARN, an attacker can create an unbound admin role. SCP condition: `iam:PermissionsBoundary == arn:aws:iam::ACCOUNT:policy/PaveBoundary`.",
          "CONTEXT RULE: When analyzing Terraform with wildcards, determine the layer first. Layer 4 wildcards scoped to a service + resource prefix with PB+SCP hierarchy = LOW risk. Same wildcard in Layer 0 = CRITICAL.",
        ]
      },
      {
        heading: "Permission Boundary Mechanics",
        items: [
          "A permission boundary is an IAM managed policy attached to a role/user that defines the MAXIMUM permissions — even if inline/managed policies grant more.",
          "Effective permissions = INTERSECTION of identity-based policies AND permission boundary. The smaller set wins.",
          "Boundaries do NOT grant permissions — they only restrict. A role with AdministratorAccess + a PB that allows only kinesis:* effectively has only kinesis:*.",
          "Boundaries are inherited via iam:CreateRole condition — SCP enforces that newly created roles MUST attach the org-standard boundary policy ARN. Without this SCP, anyone with iam:CreateRole can create unbound admin roles.",
          "Critical SCP pattern: `{Effect: Deny, Action: iam:CreateRole, Condition: {StringNotEquals: {iam:PermissionsBoundary: arn:aws:iam::*:policy/OrgStandardBoundary}}}` — blocks role creation without the required boundary.",
          "Boundary policy design: Include all services the tier is allowed to use. Exclude iam:*, sts:AssumeRole *, ec2:*, and any service not needed by that tier.",
          "Boundary ARN in Terraform: `iam_permissions_boundary = data.aws_iam_policy.pave_boundary.arn` in every `aws_iam_role` created by product/service teams.",
        ]
      },
      {
        heading: "OIDC & Workspace-Scoped Trust",
        items: [
          "TFE OIDC: HCP Terraform/TFE generates per-run OIDC JWT tokens. Sub-claim format: `organization:ORG:project:PROJ:workspace:WS:run_phase:apply`",
          "GitHub Actions OIDC: Sub-claim format: `repo:org/repo:ref:refs/heads/main` or `:environment:prod`",
          "CRITICAL FINDING: `Condition: {StringEquals: {token.actions.githubusercontent.com:sub: *}}` — wildcard sub allows ANY repo to assume the role. Use exact repo path or `StringLike` with org-prefix at minimum.",
          "CRITICAL FINDING: TFE trust with `sub: organization:ORG:*` — all workspaces in the org can assume the role. Scope to specific workspace: `organization:ORG:project:PROJ:workspace:SPECIFIC_WS:*`",
          "Workspace blast radius: If a TFE workspace assumes a role, compromise of that workspace = full access to that role's permissions. Separate workspaces per environment/account. Never share a workspace across prod+dev.",
          "OIDC audience claim: Always specify `sts.amazonaws.com` as the `aud` claim. Never use `*` for aud.",
          "Session policies: Add `sts:SetSourceIdentity` with workspace name for enhanced CloudTrail attribution. Enables per-workspace audit trail even when roles are shared.",
        ]
      },
      {
        heading: "Terraform State as a Secret",
        items: [
          "`terraform_remote_state` data source reads another workspace's state file — which contains ALL outputs, including sensitive ones (passwords, private keys, ARNs, account IDs).",
          "State files stored in S3 must use: SSE-KMS encryption, S3 bucket policy restricting access to specific pipeline roles only, S3 versioning (for rollback), and DynamoDB lock table.",
          "Access pattern: Only the Terraform pipeline IAM role should have `s3:GetObject` on the state prefix. Human access should go through `terraform show` via the pipeline, never direct S3 console access.",
          "Cross-workspace state coupling risk: If workspace A's state is readable by workspace B's role, an attacker compromising B can exfiltrate A's secrets. Prefer SSM Parameter Store for sharing non-sensitive outputs.",
          "Blast radius of state compromise: An attacker reading terraform.tfstate can enumerate: all resource IDs, ARNs, private IPs, database endpoints, and any `sensitive = true` values stored in plaintext in the state.",
          "HCP Terraform/TFE state encryption: Enable state encryption at rest. Restrict `tfe_workspace` data source to authorized callers only. Audit TFE API token scope.",
        ]
      },
      {
        heading: "Cross-Layer Security Findings",
        items: [
          "CRITICAL: iam:* or sts:AssumeRole * at any product/service layer — permission hierarchy escape. Immediate remediation.",
          "CRITICAL: No permission boundary on roles created by product/service TF — any new role is uncapped. Add iam:PermissionsBoundary to all aws_iam_role resources at Layer 3+.",
          "HIGH: OIDC sub-claim uses wildcard (*) — any repo/workspace can assume the role. Scope to specific workspace or repo.",
          "HIGH: terraform_remote_state without backend encryption — state secrets readable by anyone with S3 access.",
          "HIGH: Wildcard resource ARN on S3 (s3:* on *) — can access other teams' state files and data buckets.",
          "MEDIUM: Wildcard on single-service without resource scope (kinesis:* on *) — overly broad for service's function. Scope to `arn:aws:kinesis:REGION:ACCOUNT:stream/TEAM-PREFIX-*`.",
          "MEDIUM: Missing aws:RequestedRegion SCP condition — resources can be created outside approved regions. Relevant for data residency compliance.",
          "LOW: Wildcard on single-service with resource prefix scope and permission boundary in place — acceptable for product team deployment patterns.",
          "INFO: Layer 4 service role with wildcard on own service prefix + PB + SCP — standard pave pattern, not a finding.",
        ]
      }
    ]
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// RESOURCE METADATA
// ─────────────────────────────────────────────────────────────────────────────
const RT = {
  xsphere_virtual_machine:{l:"xSphere VM",t:"xsphere",i:"🖥",c:"#0277BD"},
  xsphere_datacenter:{l:"xSphere DC",t:"xsphere",i:"🏢",c:"#0277BD"},
  xsphere_cluster:{l:"xSphere Cluster",t:"xsphere",i:"🔗",c:"#0277BD"},
  xsphere_datastore:{l:"Datastore",t:"xsphere",i:"💽",c:"#0277BD"},
  xsphere_network:{l:"xSphere Net",t:"xsphere",i:"🌐",c:"#0277BD"},
  xsphere_distributed_virtual_switch:{l:"xDVS",t:"xsphere",i:"🔀",c:"#0277BD"},
  xsphere_tag:{l:"xSphere Tag",t:"xsphere",i:"🏷",c:"#0277BD"},
  xsphere_content_library:{l:"Content Lib",t:"xsphere",i:"📚",c:"#0277BD"},
  aws_organizations_organization:{l:"AWS Org",t:"org",i:"🏛",c:"#B71C1C"},
  aws_organizations_organizational_unit:{l:"OU",t:"org",i:"📁",c:"#B71C1C"},
  aws_organizations_account:{l:"AWS Account",t:"org",i:"👤",c:"#B71C1C"},
  aws_organizations_policy:{l:"SCP",t:"org",i:"🛡",c:"#B71C1C"},
  aws_organizations_policy_attachment:{l:"SCP Attach",t:"org",i:"📎",c:"#B71C1C"},
  aws_iam_role:{l:"IAM Role",t:"security",i:"🔑",c:"#C62828"},
  aws_iam_policy:{l:"IAM Policy",t:"security",i:"📋",c:"#C62828"},
  aws_iam_role_policy:{l:"Inline Policy",t:"security",i:"📄",c:"#C62828"},
  aws_iam_role_policy_attachment:{l:"Policy Attach",t:"security",i:"📎",c:"#C62828"},
  aws_iam_instance_profile:{l:"Instance Profile",t:"security",i:"👤",c:"#C62828"},
  aws_iam_openid_connect_provider:{l:"OIDC Provider",t:"security",i:"🔓",c:"#C62828"},
  aws_kms_key:{l:"KMS Key",t:"security",i:"🗝",c:"#C62828"},
  aws_kms_alias:{l:"KMS Alias",t:"security",i:"🏷",c:"#C62828"},
  aws_secretsmanager_secret:{l:"Secret",t:"security",i:"🔒",c:"#C62828"},
  aws_secretsmanager_secret_version:{l:"Secret Ver",t:"security",i:"🔒",c:"#C62828"},
  aws_cognito_user_pool:{l:"Cognito Pool",t:"security",i:"👥",c:"#C62828"},
  aws_ssm_parameter:{l:"SSM Param",t:"security",i:"⚙",c:"#C62828"},
  aws_guardduty_detector:{l:"GuardDuty",t:"security",i:"🔍",c:"#C62828"},
  aws_config_config_rule:{l:"Config Rule",t:"security",i:"📏",c:"#C62828"},
  aws_securityhub_account:{l:"Security Hub",t:"security",i:"🛡",c:"#C62828"},
  aws_codepipeline:{l:"CodePipeline",t:"cicd",i:"⚙",c:"#BF360C"},
  aws_codebuild_project:{l:"CodeBuild",t:"cicd",i:"🔨",c:"#BF360C"},
  aws_codecommit_repository:{l:"CodeCommit",t:"cicd",i:"📦",c:"#BF360C"},
  aws_codedeploy_app:{l:"CodeDeploy",t:"cicd",i:"🚀",c:"#BF360C"},
  aws_cloudformation_stack:{l:"CloudFormation",t:"cicd",i:"📋",c:"#BF360C"},
  aws_service_catalog_portfolio:{l:"Svc Catalog",t:"cicd",i:"🗂",c:"#BF360C"},
  aws_eks_cluster:{l:"EKS Cluster",t:"compute",i:"☸",c:"#1B5E20"},
  aws_eks_node_group:{l:"EKS Node Grp",t:"compute",i:"⬡",c:"#1B5E20"},
  aws_eks_fargate_profile:{l:"EKS Fargate",t:"compute",i:"☁",c:"#1B5E20"},
  aws_vpc:{l:"VPC",t:"network",i:"🌐",c:"#6A1B9A"},
  aws_subnet:{l:"Subnet",t:"network",i:"📡",c:"#6A1B9A"},
  aws_security_group:{l:"Security Group",t:"network",i:"🔐",c:"#6A1B9A"},
  aws_security_group_rule:{l:"SG Rule",t:"network",i:"📏",c:"#6A1B9A"},
  aws_internet_gateway:{l:"IGW",t:"network",i:"🚪",c:"#6A1B9A"},
  aws_nat_gateway:{l:"NAT GW",t:"network",i:"↗",c:"#6A1B9A"},
  aws_eip:{l:"Elastic IP",t:"network",i:"📍",c:"#6A1B9A"},
  aws_route_table:{l:"Route Table",t:"network",i:"🗺",c:"#6A1B9A"},
  aws_vpc_peering_connection:{l:"VPC Peering",t:"network",i:"🔗",c:"#6A1B9A"},
  aws_transit_gateway:{l:"Transit GW",t:"network",i:"🔀",c:"#6A1B9A"},
  aws_transit_gateway_vpc_attachment:{l:"TGW Attach",t:"network",i:"📎",c:"#6A1B9A"},
  aws_vpc_endpoint:{l:"VPC Endpoint",t:"network",i:"⚡",c:"#6A1B9A"},
  aws_dx_connection:{l:"Direct Connect",t:"network",i:"⚡",c:"#6A1B9A"},
  aws_vpn_gateway:{l:"VPN GW",t:"network",i:"🔒",c:"#6A1B9A"},
  aws_lb:{l:"Load Balancer",t:"compute",i:"⚖",c:"#1B5E20"},
  aws_alb:{l:"ALB",t:"compute",i:"⚖",c:"#1B5E20"},
  aws_api_gateway_rest_api:{l:"API Gateway",t:"compute",i:"🔌",c:"#1B5E20"},
  aws_apigatewayv2_api:{l:"HTTP API",t:"compute",i:"🔌",c:"#1B5E20"},
  aws_instance:{l:"EC2 Instance",t:"compute",i:"🖥",c:"#1B5E20"},
  aws_launch_template:{l:"Launch Template",t:"compute",i:"📋",c:"#1B5E20"},
  aws_autoscaling_group:{l:"ASG",t:"compute",i:"📈",c:"#1B5E20"},
  aws_lambda_function:{l:"Lambda",t:"compute",i:"λ",c:"#1B5E20"},
  aws_lambda_permission:{l:"Lambda Perm",t:"compute",i:"🔓",c:"#1B5E20"},
  aws_ecs_cluster:{l:"ECS Cluster",t:"compute",i:"🐳",c:"#1B5E20"},
  aws_ecs_service:{l:"ECS Service",t:"compute",i:"🔄",c:"#1B5E20"},
  aws_ecs_task_definition:{l:"Task Def",t:"compute",i:"📋",c:"#1B5E20"},
  aws_ecr_repository:{l:"ECR Repo",t:"compute",i:"📦",c:"#1B5E20"},
  aws_apprunner_service:{l:"App Runner",t:"compute",i:"🚀",c:"#1B5E20"},
  aws_cloudfront_distribution:{l:"CloudFront",t:"compute",i:"🌍",c:"#1B5E20"},
  aws_wafv2_web_acl:{l:"WAF v2",t:"security",i:"🛡",c:"#C62828"},
  aws_acm_certificate:{l:"ACM Cert",t:"security",i:"📜",c:"#C62828"},
  aws_route53_zone:{l:"Route53 Zone",t:"compute",i:"🌐",c:"#1B5E20"},
  aws_route53_record:{l:"DNS Record",t:"compute",i:"📡",c:"#1B5E20"},
  aws_s3_bucket:{l:"S3 Bucket",t:"storage",i:"🪣",c:"#0D47A1"},
  aws_s3_bucket_policy:{l:"S3 Policy",t:"storage",i:"📋",c:"#0D47A1"},
  aws_s3_bucket_versioning:{l:"S3 Versioning",t:"storage",i:"🔖",c:"#0D47A1"},
  aws_dynamodb_table:{l:"DynamoDB",t:"storage",i:"⚡",c:"#0D47A1"},
  aws_db_instance:{l:"RDS Instance",t:"storage",i:"🗄",c:"#0D47A1"},
  aws_rds_cluster:{l:"Aurora Cluster",t:"storage",i:"🗄",c:"#0D47A1"},
  aws_rds_cluster_instance:{l:"Aurora Instance",t:"storage",i:"🗄",c:"#0D47A1"},
  aws_elasticache_cluster:{l:"ElastiCache",t:"storage",i:"⚡",c:"#0D47A1"},
  aws_elasticache_replication_group:{l:"Redis RG",t:"storage",i:"⚡",c:"#0D47A1"},
  aws_efs_file_system:{l:"EFS",t:"storage",i:"📁",c:"#0D47A1"},
  aws_ebs_volume:{l:"EBS Volume",t:"storage",i:"💽",c:"#0D47A1"},
  aws_backup_vault:{l:"Backup Vault",t:"storage",i:"💾",c:"#0D47A1"},
  aws_sqs_queue:{l:"SQS Queue",t:"compute",i:"📨",c:"#1B5E20"},
  aws_sns_topic:{l:"SNS Topic",t:"compute",i:"📣",c:"#1B5E20"},
  aws_kinesis_stream:{l:"Kinesis",t:"compute",i:"🌊",c:"#1B5E20"},
  aws_cloudwatch_log_group:{l:"CW Log Group",t:"compute",i:"📊",c:"#1B5E20"},
  aws_cloudwatch_metric_alarm:{l:"CW Alarm",t:"compute",i:"🔔",c:"#1B5E20"},
  aws_cloudwatch_event_rule:{l:"EventBridge",t:"compute",i:"⚡",c:"#1B5E20"},
  aws_xray_group:{l:"X-Ray",t:"compute",i:"🔍",c:"#1B5E20"},
  _default:{l:"Resource",t:"compute",i:"◆",c:"#546E7A"}
};

const TIERS = {
  xsphere: {label:"xSphere Private Cloud", bg:"#E3F2FD", border:"#0277BD", hdr:"#01579B", ord:0},
  org:     {label:"AWS Org · SCPs · OUs", bg:"#FCE4EC", border:"#B71C1C", hdr:"#7F0000", ord:1},
  security:{label:"Security · IAM · KMS", bg:"#FFEBEE", border:"#C62828", hdr:"#B71C1C", ord:2},
  cicd:    {label:"CI/CD · Jenkins · IaC", bg:"#FBE9E7", border:"#BF360C", hdr:"#870000", ord:3},
  network: {label:"Network · VPC · TGW",  bg:"#F3E5F5", border:"#6A1B9A", hdr:"#4A148C", ord:4},
  compute: {label:"Compute · API · Events",bg:"#E8F5E9", border:"#1B5E20", hdr:"#004D40", ord:5},
  storage: {label:"Storage · Database",   bg:"#E3F2FD", border:"#0D47A1", hdr:"#01579B", ord:6},
};

// ─────────────────────────────────────────────────────────────────────────────
// TERRAFORM PARSER
// ─────────────────────────────────────────────────────────────────────────────
function parseTFMultiFile(files) {
  const resources=[], modules=[], connections=[], outputs=[], variables=[], remoteStates=[];

  files.forEach(({path, content}) => {
    const fname = path.split("/").pop();

    // Resources
    const rRe = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
    let m;
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
      resources.push({id, type:rtype, name:rname, label, body, multi, file:path});
      // implicit deps
      const depRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = depRe.exec(body)) !== null) {
        const to = `${rm[1]}.${rm[2]}`;
        if (to !== id) connections.push({from:id, to, kind:"implicit", file:path});
      }
      // explicit depends_on
      const dm = body.match(/depends_on\s*=\s*\[([^\]]+)\]/);
      if (dm) {
        const dr = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let d;
        while ((d = dr.exec(dm[1])) !== null)
          connections.push({from:id, to:`${d[1]}.${d[2]}`, kind:"explicit", file:path});
      }
    }

    // Modules
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
      modules.push({id:`module.${mname}`, name:mname, source:src, shortSrc, version:ver, srcType, body, file:path});
      // module inputs referencing resources
      const refRe = /\b(aws_[\w]+|xsphere_[\w]+)\.([\w-]+)\b/g; let rm;
      while ((rm = refRe.exec(body)) !== null)
        connections.push({from:`module.${mname}`, to:`${rm[1]}.${rm[2]}`, kind:"module-input", file:path});
    }

    // Outputs
    const oRe = /\boutput\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|\s*$))/g;
    while ((m = oRe.exec(content)) !== null) {
      const [,oname,body] = m;
      const vM = body.match(/value\s*=\s*(.+)/);
      outputs.push({name:oname, value:vM?vM[1].trim():"", file:path});
    }

    // Variables
    const vRe = /\bvariable\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|\s*$))/g;
    while ((m = vRe.exec(content)) !== null) {
      const [,vname,body] = m;
      const dM = body.match(/default\s*=\s*(.+)/);
      const tM = body.match(/type\s*=\s*(\S+)/);
      variables.push({name:vname, type:tM?tM[1]:"any", hasDefault:!!dM, file:path});
    }

    // Remote state
    const rsRe = /data\s+"terraform_remote_state"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|\s*$))/g;
    while ((m = rsRe.exec(content)) !== null) {
      const [,rsname,body] = m;
      const keyM = body.match(/key\s*=\s*"([^"]+)"/);
      const buckM = body.match(/bucket\s*=\s*"([^"]+)"/);
      remoteStates.push({name:rsname, key:keyM?keyM[1]:null, bucket:buckM?buckM[1]:null, file:path});
      modules.push({id:`remote_state.${rsname}`, name:rsname, source:"remote_state", shortSrc:"remote state",
                    version:null, srcType:"remote_state", body, file:path});
    }

    // Sentinel
    if (fname.endsWith(".sentinel")) {
      const pname = fname.replace(".sentinel","");
      modules.push({id:`sentinel.${pname}`, name:pname, source:"sentinel", shortSrc:"policy", version:null, srcType:"sentinel", body:"", file:path});
    }
  });

  // Dedup
  const seenR=new Set(), seenM=new Set(), seenC=new Set();
  const uResources = resources.filter(r=>{if(seenR.has(r.id))return false;seenR.add(r.id);return true;});
  const uModules = modules.filter(m=>{if(seenM.has(m.id))return false;seenM.add(m.id);return true;});
  const valid = new Set([...uResources.map(r=>r.id),...uModules.map(m=>m.id)]);
  const uConns = connections.filter(c=>{
    const k=`${c.from}||${c.to}`;
    if(seenC.has(k)||c.from===c.to||!valid.has(c.from))return false;
    seenC.add(k);return true;
  });

  return {resources:uResources, modules:uModules, connections:uConns, outputs, variables, remoteStates};
}

// ─────────────────────────────────────────────────────────────────────────────
// DFD XML GENERATOR
// ─────────────────────────────────────────────────────────────────────────────
const xe = s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const NW=84, NH=60, LH=32, VGAP=12, HGAP=18, TPAD=18, TVPAD=22, HDRH=40, TGAP=60, CPAD=28;
const MAXCOLS=6;
const LEGEND_W=252;

function buildLegendCells(lx, ly) {
  const LW=LEGEND_W, LHDR=28, LR=24, TR=20, SH=18;
  const cells=[];
  let lid=9000;
  const nid=()=>`lg_${++lid}`;
  const FID="legend_frame";

  cells.push(
    `<mxCell id="${FID}" value="Legend" style="swimlane;startSize=${LHDR};fillColor=#1A237E;swimlaneFillColor=#0D1117;strokeColor=#283593;strokeWidth=2;fontColor=#90CAF9;fontSize=12;fontStyle=1;align=center;rounded=1;arcSize=3;html=1;" vertex="1" parent="1"><mxGeometry x="${lx}" y="${ly}" width="${LW}" height="516" as="geometry"/></mxCell>`
  );
  let y=LHDR+8;

  const hdr=(t)=>{
    cells.push(`<mxCell id="${nid()}" value="${xe(t)}" style="text;html=1;align=left;fontStyle=1;fontSize=9;fontColor=#64B5F6;strokeColor=none;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="10" y="${y}" width="${LW-20}" height="16" as="geometry"/></mxCell>`);
    y+=SH;
  };
  const div=()=>{
    cells.push(`<mxCell id="${nid()}" value="" style="line;strokeColor=#283593;strokeWidth=1;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="8" y="${y}" width="${LW-16}" height="8" as="geometry"/></mxCell>`);
    y+=12;
  };
  const nodeRow=(lbl,fill,stroke,extra="")=>{
    cells.push(
      `<mxCell id="${nid()}" value="" style="rounded=1;arcSize=6;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;${extra}resizable=0;" vertex="1" parent="${FID}"><mxGeometry x="10" y="${y+3}" width="28" height="17" as="geometry"/></mxCell>`,
      `<mxCell id="${nid()}" value="${xe(lbl)}" style="text;html=1;align=left;fontSize=9;fontColor=#B0BEC5;strokeColor=none;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="46" y="${y+3}" width="${LW-56}" height="17" as="geometry"/></mxCell>`
    );
    y+=LR;
  };
  const edgeRow=(lbl,eStyle,dotCol)=>{
    const sid=nid(), tid=nid();
    cells.push(
      `<mxCell id="${sid}" value="" style="ellipse;fillColor=${dotCol};strokeColor=${dotCol};" vertex="1" parent="${FID}"><mxGeometry x="10" y="${y+8}" width="7" height="7" as="geometry"/></mxCell>`,
      `<mxCell id="${tid}" value="" style="ellipse;fillColor=none;strokeColor=none;" vertex="1" parent="${FID}"><mxGeometry x="82" y="${y+8}" width="7" height="7" as="geometry"/></mxCell>`,
      `<mxCell id="${nid()}" value="" style="${eStyle}exitX=1;exitY=0.5;exitPerimeter=0;entryX=0;entryY=0.5;entryPerimeter=0;" edge="1" source="${sid}" target="${tid}" parent="${FID}"><mxGeometry relative="1" as="geometry"/></mxCell>`,
      `<mxCell id="${nid()}" value="${xe(lbl)}" style="text;html=1;align=left;fontSize=9;fontColor=#B0BEC5;strokeColor=none;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="97" y="${y+4}" width="${LW-107}" height="16" as="geometry"/></mxCell>`
    );
    y+=LR;
  };
  const tierRow=(lbl,fill,stroke)=>{
    cells.push(
      `<mxCell id="${nid()}" value="" style="rounded=1;arcSize=3;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;resizable=0;" vertex="1" parent="${FID}"><mxGeometry x="10" y="${y+3}" width="28" height="13" as="geometry"/></mxCell>`,
      `<mxCell id="${nid()}" value="${xe(lbl)}" style="text;html=1;align=left;fontSize=9;fontColor=#B0BEC5;strokeColor=none;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="46" y="${y+2}" width="${LW-56}" height="15" as="geometry"/></mxCell>`
    );
    y+=TR;
  };

  // ── Section 1: Node Types ─────────────────────────────────────────
  hdr("NODE TYPES");
  nodeRow("AWS Resource (managed)",  "#FFFFFF","#546E7A");
  nodeRow("Data Source (read-only)", "#F5F5F5","#0277BD","dashed=1;dashPattern=4 3;");
  nodeRow("Terraform Module",        "#EDE7F6","#4527A0","dashed=1;dashPattern=5 3;");
  nodeRow("Sentinel Policy Gate",    "#FFF8E1","#E65100");
  nodeRow("Remote State Reference",  "#E3F2FD","#1565C0","dashed=1;dashPattern=6 4;");
  div();

  // ── Section 2: Connection Types ───────────────────────────────────
  hdr("CONNECTION TYPES");
  edgeRow("Implicit reference",    "html=1;edgeStyle=none;strokeColor=#78909C;strokeWidth=1.5;endArrow=block;endFill=1;startArrow=none;",                                   "#78909C");
  edgeRow("Explicit depends_on",   "html=1;edgeStyle=none;strokeColor=#E53935;strokeWidth=2;dashed=1;dashPattern=5 3;endArrow=block;endFill=1;startArrow=none;",           "#E53935");
  edgeRow("Module input / output", "html=1;edgeStyle=none;strokeColor=#2E7D32;strokeWidth=2;endArrow=open;endFill=0;startArrow=none;",                                     "#2E7D32");
  edgeRow("Remote state read",     "html=1;edgeStyle=none;strokeColor=#6A1B9A;strokeWidth=2;dashed=1;dashPattern=8 4;endArrow=open;endFill=0;startArrow=oval;startFill=1;","#6A1B9A");
  edgeRow("Data source read",      "html=1;edgeStyle=none;strokeColor=#0277BD;strokeWidth=1.5;dashed=1;dashPattern=4 4;endArrow=open;endFill=0;startArrow=none;",          "#0277BD");
  div();

  // ── Section 3: Tier Boundaries ────────────────────────────────────
  hdr("TIER BOUNDARIES");
  tierRow("xSphere Private Cloud",  "#E8EAF6","#3949AB");
  tierRow("Org / Account",          "#F3E5F5","#6A1B9A");
  tierRow("Security · IAM · KMS",   "#FFEBEE","#C62828");
  tierRow("CI/CD · Jenkins · IaC",  "#FFF3E0","#E65100");
  tierRow("Network · VPC · TGW",    "#E8F5E9","#2E7D32");
  tierRow("Compute · API · Events", "#E3F2FD","#1565C0");
  tierRow("Storage · Database",     "#FFF8E1","#F57F17");

  cells.push(`<mxCell id="${nid()}" value="threataform · enterprise terraform dfd" style="text;html=1;align=center;fontSize=7;fontColor=#37474F;strokeColor=none;fillColor=none;" vertex="1" parent="${FID}"><mxGeometry x="0" y="${y+4}" width="${LW}" height="12" as="geometry"/></mxCell>`);
  return cells;
}

function generateDFDXml(resources, modules, connections) {
  const TORD = ["xsphere","org","security","cicd","network","compute","storage"];
  const groups = {};
  TORD.forEach(t=>{groups[t]=[];});

  resources.forEach(r=>{
    const meta = RT[r.type]||RT._default;
    if(!groups[meta.t])groups[meta.t]=[];
    groups[meta.t].push({...r, _meta:meta, _isModule:false});
  });
  modules.forEach(m=>{
    const t = "cicd";
    if(!groups[t])groups[t]=[];
    const mcolor = m.srcType==="sentinel"?"#E65100":m.srcType==="remote_state"?"#1565C0":"#558B2F";
    groups[t].push({...m, _meta:{l:m.name, t, i:"-", c:mcolor}, _isModule:true});
  });

  const activeTiers = TORD.filter(t=>groups[t]&&groups[t].length>0);
  // idMap stores { cid, tier, tierIdx } for smart edge routing
  const idMap = new Map();
  const containers=[], edges=[], vertices=[];
  let cellN=100;

  // VERTICAL LAYOUT: tiers stack top-to-bottom, uniform width = max tier width
  const maxNodes = activeTiers.reduce((mx,t)=>Math.max(mx,groups[t].length),1);
  const effectiveCols = Math.min(maxNodes, MAXCOLS);
  const tierW = TPAD*2 + effectiveCols*(NW+HGAP) - HGAP;
  let globalY = CPAD;

  activeTiers.forEach((t,ti)=>{
    const nodes=groups[t];
    const rows=Math.ceil(nodes.length/MAXCOLS);
    const tH=HDRH+TVPAD+rows*(NH+LH+VGAP)-VGAP+TVPAD;

    const tm = TIERS[t]||{label:t, bg:"#F5F5F5", border:"#999", hdr:"#555"};
    const tcid=`tier_${t}`;
    containers.push(
      `<mxCell id="${tcid}" value="${xe(tm.label)} (${nodes.length})" style="swimlane;startSize=${HDRH};fillColor=${tm.hdr};swimlaneFillColor=${tm.bg};strokeColor=${tm.border};strokeWidth=2;fontColor=#FFFFFF;fontSize=12;fontStyle=1;align=left;swimlaneLine=1;rounded=1;arcSize=2;whiteSpace=wrap;html=1;" vertex="1" parent="1">\n          <mxGeometry x="${CPAD}" y="${globalY}" width="${tierW}" height="${tH}" as="geometry"/>\n        </mxCell>`
    );

    nodes.forEach((n,i)=>{
      const col=i%MAXCOLS, row=Math.floor(i/MAXCOLS);
      const nx=CPAD+TPAD+col*(NW+HGAP);
      const ny=globalY+HDRH+TVPAD+row*(NH+LH+VGAP);
      const cid=`n_${++cellN}`;
      idMap.set(n.id, {cid, tier:t, tierIdx:ti});
      const meta=n._meta;
      const shortType = n._isModule
        ? `${n.srcType||"module"}`
        : (n.type||"").replace(/^aws_|^xsphere_/,"").replace(/_/g," ").substring(0,20);
      const rawMulti = n.multi ? ` [${n.multi}]` : "";
      const rawName = (n.label||n.name||"").substring(0,18) + rawMulti;
      const rawLbl = `<b style="font-size:9px">${rawName}</b><br/><span style="font-size:7px;color:#888">${shortType}</span>`;
      const bdrDash = n._isModule||n.srcType==="remote_state" ? "dashed=1;" : "";
      const bgColor = n._isModule ? "#FAFFF5" : "#FFFFFF";
      const style=`rounded=1;arcSize=8;fillColor=${bgColor};strokeColor=${meta.c||"#546E7A"};strokeWidth=1.5;fontColor=#333;fontSize=10;html=1;align=center;whiteSpace=wrap;verticalAlign=top;${bdrDash}`;
      vertices.push(
        `<mxCell id="${cid}" value="${xe(rawLbl)}" style="${style}" vertex="1" parent="1">\n          <mxGeometry x="${nx}" y="${ny}" width="${NW}" height="${NH+LH}" as="geometry"/>\n        </mxCell>`
      );
    });

    globalY += tH + TGAP;
  });

  const totalW = tierW + CPAD*2;
  const totalH = globalY;

  // Edges with smart exit/entry routing to minimize overlap
  // Cross-tier: top/bottom routing. Same-tier: left/right routing.
  const seenE=new Set();
  connections.forEach(c=>{
    const sInfo=idMap.get(c.from), tInfo=idMap.get(c.to);
    if(!sInfo||!tInfo)return;
    const ek=`${sInfo.cid}|${tInfo.cid}`;
    if(seenE.has(ek))return;
    seenE.add(ek);
    const color=c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#2E7D32":"#78909C";
    const dash=c.kind==="explicit"?"dashed=1;dashPattern=6 3;":"";
    const lbl=c.kind==="explicit"?"depends_on":c.kind==="module-input"?"input":"";
    // Smart routing: tiers are vertical bands; route edges along tier boundaries
    let routing;
    if (sInfo.tier === tInfo.tier) {
      // Same tier: side-to-side to avoid overlapping with cross-tier arrows
      routing = "exitX=1;exitY=0.5;exitPerimeter=0;entryX=0;entryY=0.5;entryPerimeter=0;";
    } else if (sInfo.tierIdx < tInfo.tierIdx) {
      // Downward flow (higher → lower in stack): exit bottom, enter top
      routing = "exitX=0.5;exitY=1;exitPerimeter=0;entryX=0.5;entryY=0;entryPerimeter=0;";
    } else {
      // Upward flow (lower → higher): exit top, enter bottom
      routing = "exitX=0.5;exitY=0;exitPerimeter=0;entryX=0.5;entryY=1;entryPerimeter=0;";
    }
    edges.push(
      `<mxCell id="e_${++cellN}" value="${lbl}" style="edgeStyle=orthogonalEdgeStyle;html=1;rounded=1;strokeColor=${color};strokeWidth=1.5;${dash}endArrow=block;endFill=1;fontSize=8;fontColor=${color};${routing}jettySize=8;orthogonalLoop=1;" edge="1" source="${sInfo.cid}" target="${tInfo.cid}" parent="1">\n          <mxGeometry relative="1" as="geometry"/>\n        </mxCell>`
    );
  });

  const legendCells=buildLegendCells(totalW+40, CPAD);
  const allCells=[...containers,...edges,...vertices,...legendCells];
  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<mxfile host="enterprise-tf-dfd" version="21.0.0">`,
    `  <diagram id="tf-dfd" name="Enterprise Terraform DFD">`,
    `    <mxGraphModel dx="1800" dy="1200" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${Math.max(1654,totalW+LEGEND_W+100)}" pageHeight="${Math.max(1169,totalH+100)}" math="0" shadow="0">`,
    `      <root>`,
    `        <mxCell id="0"/>`,
    `        <mxCell id="1" parent="0"/>`,
    ...allCells.map(c=>`        ${c}`),
    `      </root>`,
    `    </mxGraphModel>`,
    `  </diagram>`,
    `</mxfile>`
  ].join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// SYNTAX HIGHLIGHT
// ─────────────────────────────────────────────────────────────────────────────
function hlXml(raw) {
  const xe2 = s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  let out="";
  const re=/(<\?xml[\s\S]*?\?>)|(<!--[\s\S]*?-->)|(<\/[\w:]+\s*>)|(<[\w:][\s\S]*?>)|([^<]+)/g;
  let m;
  while((m=re.exec(raw))!==null){
    if(m[1]) out+=`<span style="color:#f97583">${xe2(m[1])}</span>`;
    else if(m[2]) out+=`<span style="color:#6a737d">${xe2(m[2])}</span>`;
    else if(m[3]){ const nm=m[3].match(/^<\/([\w:]+)/); out+=nm?`&lt;<span style="color:#79c0ff">/${xe2(nm[1])}</span>&gt;`:xe2(m[3]); }
    else if(m[4]){ const nm=m[4].match(/^<([\w:]+)/); const tn=nm?nm[1]:""; const rest=m[4].slice(1+tn.length).replace(/\/?>$/,""); const sc=m[4].endsWith("/>");
      const hr=rest.replace(/([\w:]+)(\s*=\s*")((?:[^"\\]|\\.)*)(")/g,(_,a,eq,v,cl)=>`<span style="color:#ffa657">${xe2(a)}</span>${xe2(eq)}<span style="color:#a5d6ff">${xe2(v)}</span>${cl}`);
      out+=`&lt;<span style="color:#79c0ff">${xe2(tn)}</span>${hr}${sc?"/":""}`.trimEnd()+"&gt;";
    }
    else if(m[5]) out+=`<span style="color:#4a7a80">${xe2(m[5])}</span>`;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// UI CONSTANTS & DESIGN TOKENS
// ─────────────────────────────────────────────────────────────────────────────
const MONO = {fontFamily:"'JetBrains Mono','Fira Code','Cascadia Code',monospace"};
const SANS = {fontFamily:"'Inter','DM Sans','system-ui',sans-serif"};

// Color palette
const C = {
  bg:        "#09090E",
  surface:   "#111118",
  surface2:  "#16161F",
  border:    "#1E1E2E",
  border2:   "#2A2A40",
  text:      "#E8E8F0",
  textSub:   "#9090A8",
  textMuted: "#5A5A70",
  accent:    "#FF9900",
  accentDim: "#FF990022",
  blue:      "#4A90E2",
  green:     "#4CAF50",
  red:       "#EF5350",
  critRed:   "#FF1744",
  orange:    "#FF7043",
  purple:    "#9C27B0",
};

// Severity system
const SEV_COLOR = { CRITICAL:"#FF1744", HIGH:"#EF5350", MEDIUM:"#FFA726", LOW:"#66BB6A" };
const SEV_BG    = { CRITICAL:"#200010", HIGH:"#200808", MEDIUM:"#1A1000", LOW:"#081808" };

// Reusable card/box style
const card = (borderColor = C.border) => ({
  background: C.surface,
  border: `1px solid ${borderColor}`,
  borderRadius: 8,
  overflow: "hidden",
});

// Section header bar
const sectionBar = (color = C.accent) => ({
  background: C.surface2,
  borderBottom: `1px solid ${C.border}`,
  padding: "10px 18px",
  fontSize: 11,
  fontWeight: 700,
  color,
  letterSpacing: ".08em",
  textTransform: "uppercase",
  display: "flex",
  alignItems: "center",
  gap: 8,
});

// ─────────────────────────────────────────────────────────────────────────────
// KNOWLEDGE PANEL
// ─────────────────────────────────────────────────────────────────────────────
function KBPanel({domain}) {
  const d = KB[domain];
  if (!d) return null;
  const [openSec, setOpenSec] = useState(0);

  return (
    <div style={{display:"flex", flexDirection:"column", gap:0}}>
      {/* Domain header */}
      <div style={{
        padding:"24px 28px 20px",
        background:`linear-gradient(135deg, ${d.color}18, ${C.surface})`,
        borderBottom:`2px solid ${d.color}44`,
        borderRadius:"10px 10px 0 0",
      }}>
        <div style={{
          display:"flex", alignItems:"center", gap:14, marginBottom:10
        }}>
          <div style={{
            width:42, height:42, borderRadius:10,
            background:`linear-gradient(135deg,${d.color}33,${d.color}11)`,
            border:`1px solid ${d.color}44`,
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:20, flexShrink:0
          }}>{d.icon}</div>
          <div>
            <div style={{...SANS, fontSize:18, fontWeight:700, color:C.text, letterSpacing:"-.01em"}}>{d.title}</div>
            <div style={{fontSize:11, color:d.color, marginTop:2, fontWeight:500}}>
              {d.sections.length} section{d.sections.length !== 1 ? "s" : ""}
            </div>
          </div>
        </div>
        {d.sections[0]?.body && (
          <div style={{...SANS, fontSize:13, color:C.textSub, lineHeight:1.75, maxWidth:720, marginTop:4}}>
            {d.sections[0].body.length > 320 ? d.sections[0].body.substring(0, 320) + "…" : d.sections[0].body}
          </div>
        )}
      </div>

      {/* Accordion sections */}
      <div style={{
        background:C.surface, border:`1px solid ${d.color}22`,
        borderTop:"none", borderRadius:"0 0 10px 10px", overflow:"hidden"
      }}>
        {d.sections.map((sec, si) => {
          const isOpen = openSec === si;
          return (
            <div key={si} style={{borderBottom:`1px solid ${C.border}`}}>
              <button
                onClick={()=>setOpenSec(isOpen ? null : si)}
                style={{
                  width:"100%", textAlign:"left",
                  padding:"14px 20px",
                  background: isOpen ? `${d.color}10` : "transparent",
                  border:"none", cursor:"pointer",
                  display:"flex", alignItems:"center", justifyContent:"space-between",
                  ...SANS, fontSize:13, fontWeight:600,
                  color: isOpen ? d.color : C.text,
                  transition:"background .15s, color .15s",
                }}
              >
                <div style={{display:"flex", alignItems:"center", gap:10}}>
                  <span style={{
                    width:22, height:22, borderRadius:5,
                    background: isOpen ? `${d.color}22` : `${C.border}`,
                    display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:9, color: isOpen ? d.color : C.textMuted,
                    fontWeight:700, flexShrink:0
                  }}>{si+1}</span>
                  <span>{sec.heading}</span>
                </div>
                <span style={{
                  fontSize:11, color: isOpen ? d.color : C.textMuted,
                  transform: isOpen ? "rotate(180deg)" : "none",
                  transition:"transform .2s", lineHeight:1
                }}>▼</span>
              </button>

              {isOpen && (
                <div style={{padding:"4px 20px 18px", background:C.bg}}>
                  {sec.body && !sec.items && (
                    <div style={{
                      ...MONO, fontSize:12, background:"#0D1117",
                      color:"#C9D1D9", padding:"16px 18px", borderRadius:8,
                      marginBottom:12, lineHeight:1.85, whiteSpace:"pre-wrap",
                      overflowX:"auto", border:`1px solid ${C.border}`
                    }}>
                      {sec.body}
                    </div>
                  )}
                  {sec.body && sec.items && (
                    <div style={{
                      ...SANS, fontSize:13, color:C.textSub,
                      lineHeight:1.75, marginBottom:14, padding:"10px 0 4px"
                    }}>
                      {sec.body}
                    </div>
                  )}
                  {sec.items && (
                    <div style={{display:"flex", flexDirection:"column", gap:0}}>
                      {sec.items.map((item, ii) => (
                        <div key={ii} style={{
                          display:"flex", gap:12, alignItems:"flex-start",
                          padding:"9px 0",
                          borderBottom:`1px solid ${C.border}`,
                        }}>
                          <span style={{
                            color:d.color, fontSize:12, marginTop:1,
                            flexShrink:0, fontWeight:700
                          }}>›</span>
                          <span style={{
                            ...SANS, fontSize:13, color:C.textSub, lineHeight:1.7
                          }}>{item}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// USER DOCUMENTS PANEL
// ─────────────────────────────────────────────────────────────────────────────
const DOC_TYPE_META = {
  // Terraform / IaC
  tf:       { label:"TF",      color:"#7C4DFF" },
  hcl:      { label:"HCL",     color:"#9C27B0" },
  tfvars:   { label:"TFVARS",  color:"#AB47BC" },
  sentinel: { label:"SENTINEL",color:"#CE93D8" },
  // Config / data
  json:     { label:"JSON",    color:"#F9A825" },
  yaml:     { label:"YAML",    color:"#FFA726" },
  yml:      { label:"YAML",    color:"#FFA726" },
  toml:     { label:"TOML",    color:"#FF8F00" },
  xml:      { label:"XML",     color:"#FB8C00" },
  csv:      { label:"CSV",     color:"#66BB6A" },
  // Docs
  md:       { label:"MD",      color:"#42A5F5" },
  txt:      { label:"TXT",     color:"#78909C" },
  pdf:      { label:"PDF",     color:"#EF5350" },
  // Code
  py:       { label:"PY",      color:"#26A69A" },
  sh:       { label:"SH",      color:"#4CAF50" },
  bash:     { label:"SH",      color:"#4CAF50" },
  ts:       { label:"TS",      color:"#29B6F6" },
  js:       { label:"JS",      color:"#FFEE58" },
  go:       { label:"GO",      color:"#00BCD4" },
  rb:       { label:"RB",      color:"#EF5350" },
  // CI/CD & infra
  groovy:   { label:"GROOVY",  color:"#BF360C" },
  jenkinsfile:{label:"JENKINS",color:"#D84315" },
  dockerfile:{label:"DOCKER",  color:"#0288D1" },
  env:      { label:"ENV",     color:"#78909C" },
  // Catch-all
  log:      { label:"LOG",     color:"#607D8B" },
};

function UserDocsPanel({docs, onAdd, onDelete, onClear}) {
  const [openDoc, setOpenDoc]       = useState(null);
  const [docDragging, setDocDragging] = useState(false);
  const [folderOpen, setFolderOpen] = useState({});

  const handleDrop = e => {
    e.preventDefault(); setDocDragging(false);
    if (e.dataTransfer.files?.length) onAdd(e.dataTransfer.files);
  };

  // Group docs by top-level folder (from webkitRelativePath)
  const grouped = useMemo(() => {
    const g = {}; // { folderLabel: [{doc, idx}] }
    docs.forEach((doc, idx) => {
      const parts = (doc.path || doc.name).split(/[/\\]/);
      const folder = parts.length > 1 ? parts.slice(0, -1).join("/") : "__root__";
      if (!g[folder]) g[folder] = [];
      g[folder].push({ doc, idx });
    });
    return g;
  }, [docs]);

  const totalKB = docs.reduce((s, d) => s + (d.content?.length || 0), 0) / 1024;
  const folderCount = Object.keys(grouped).filter(k => k !== "__root__").length;

  const renderDocRow = ({ doc, idx }) => {
    const ext = (doc.name || "").split(".").pop().toLowerCase();
    const typeMeta = DOC_TYPE_META[ext] || { label: ext.toUpperCase().slice(0,8) || "FILE", color:"#78909C" };
    const isOpen = openDoc === idx;
    return (
      <div key={idx} style={{borderTop:`1px solid ${C.border}`}}>
        <div
          style={{
            display:"flex", alignItems:"center", justifyContent:"space-between",
            padding:"10px 18px",
            background: isOpen ? `${C.blue}08` : "transparent",
            cursor:"pointer", transition:"background .15s",
          }}
          onClick={()=>setOpenDoc(isOpen ? null : idx)}
        >
          <div style={{display:"flex", alignItems:"center", gap:10, minWidth:0}}>
            <span style={{
              fontSize:9, fontWeight:700, color:typeMeta.color,
              background:`${typeMeta.color}15`, border:`1px solid ${typeMeta.color}33`,
              borderRadius:4, padding:"2px 6px", flexShrink:0, textAlign:"center"
            }}>{typeMeta.label}</span>
            <div style={{minWidth:0}}>
              <div style={{...SANS, fontSize:12, fontWeight:600, color:C.text,
                overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:320}}>
                {doc.name}
              </div>
              <div style={{fontSize:10, color:C.textMuted, marginTop:1}}>
                {doc.binary ? "binary / not shown" : `${(doc.content.length/1024).toFixed(1)} KB`}
              </div>
            </div>
          </div>
          <div style={{display:"flex", alignItems:"center", gap:8, flexShrink:0}}>
            <span style={{fontSize:11, color:C.textMuted, transform:isOpen?"rotate(180deg)":"none", transition:"transform .2s"}}>▼</span>
            <button onClick={e=>{e.stopPropagation();onDelete(idx);}}
              style={{ background:"transparent", border:`1px solid ${C.red}44`,
                borderRadius:5, padding:"3px 10px", color:C.red, fontSize:11, cursor:"pointer", ...SANS }}>
              ✕
            </button>
          </div>
        </div>
        {isOpen && !doc.binary && (
          <div style={{padding:"0 18px 14px", background:C.bg}}>
            <pre style={{
              ...MONO, fontSize:11, background:"#0D1117", color:"#C9D1D9",
              padding:"14px 16px", borderRadius:8, lineHeight:1.75,
              whiteSpace:"pre-wrap", overflowX:"auto",
              maxHeight:380, overflowY:"auto", margin:0, border:`1px solid ${C.border}`
            }}>
              {doc.content.slice(0, 40000)}{doc.content.length > 40000 ? "\n\n… (truncated for display — full content used in analysis)" : ""}
            </pre>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{display:"flex", flexDirection:"column", gap:0}}>
      {/* Header */}
      <div style={{
        padding:"22px 26px 18px",
        background:`linear-gradient(135deg, #78909C18, ${C.surface})`,
        borderBottom:`2px solid #78909C44`,
        borderRadius:"10px 10px 0 0",
      }}>
        <div style={{display:"flex", alignItems:"center", gap:14, marginBottom:10}}>
          <div style={{
            width:42, height:42, borderRadius:10,
            background:"#78909C22", border:"1px solid #78909C44",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:20, flexShrink:0
          }}>📂</div>
          <div style={{flex:1}}>
            <div style={{...SANS, fontSize:17, fontWeight:700, color:C.text}}>My Documents & Folders</div>
            <div style={{fontSize:11, color:"#78909C", marginTop:2}}>
              {docs.length} file{docs.length !== 1 ? "s" : ""}
              {folderCount > 0 && ` across ${folderCount} folder${folderCount !== 1?"s":""}`}
              {" · "}{totalKB.toFixed(1)} KB stored
            </div>
          </div>
          {docs.length > 0 && (
            <button onClick={onClear}
              style={{background:"transparent", border:`1px solid ${C.red}55`, borderRadius:6,
                padding:"6px 14px", color:C.red, fontSize:11, cursor:"pointer", ...SANS}}>
              Clear All
            </button>
          )}
        </div>
        <div style={{...SANS, fontSize:12, color:C.textSub, lineHeight:1.7}}>
          Upload entire Terraform repo folders or individual files of any type. All text-readable files are ingested for analysis — .tf, .hcl, .tfvars, .json, .yaml, .md, .sh, .py, Dockerfiles, Jenkinsfiles, and more.
        </div>
      </div>

      <div style={{background:C.surface, border:"1px solid #78909C22", borderTop:"none", borderRadius:"0 0 10px 10px", overflow:"hidden"}}>
        {/* Drop zone + buttons */}
        <div style={{padding:"14px 16px"}}>
          <div
            onDrop={handleDrop}
            onDragOver={e=>{e.preventDefault();setDocDragging(true);}}
            onDragLeave={()=>setDocDragging(false)}
            style={{
              border:`2px dashed ${docDragging ? C.blue : C.border2}`,
              borderRadius:10, padding:"22px 20px", textAlign:"center",
              background: docDragging ? `${C.blue}10` : C.bg,
              transition:"all .2s",
            }}
          >
            <div style={{fontSize:26, marginBottom:6, opacity:docDragging?1:0.5}}>📂</div>
            <div style={{...SANS, color:C.textMuted, fontSize:12, marginBottom:14}}>
              Drop any files or folders here — all file types accepted
            </div>
            <div style={{display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap"}}>
              {/* Browse folder */}
              <label style={{
                background:`${C.accent}18`, border:`1px solid ${C.accent}55`,
                borderRadius:6, padding:"8px 18px",
                color:C.accent, fontSize:12, cursor:"pointer", ...SANS,
                display:"inline-flex", alignItems:"center", gap:6,
              }}>
                📂 Select Folder
                <input type="file" webkitdirectory="" multiple
                  onChange={e=>{if(e.target.files?.length)onAdd(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
              {/* Browse files */}
              <label style={{
                background:C.surface, border:`1px solid ${C.border2}`,
                borderRadius:6, padding:"8px 18px",
                color:C.textSub, fontSize:12, cursor:"pointer", ...SANS,
                display:"inline-flex", alignItems:"center", gap:6,
              }}>
                📄 Browse Files
                <input type="file" multiple
                  onChange={e=>{if(e.target.files?.length)onAdd(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
            </div>
          </div>
          <div style={{fontSize:10, color:C.textMuted, textAlign:"center", marginTop:8, ...SANS}}>
            All files read client-side — nothing leaves your browser
          </div>
        </div>

        {docs.length === 0 && (
          <div style={{padding:"20px", textAlign:"center", color:C.textMuted, fontSize:12, ...SANS, borderTop:`1px solid ${C.border}`}}>
            No files uploaded yet. Select a Terraform folder from Bitbucket or upload individual files to enrich your analysis.
          </div>
        )}

        {/* Grouped file list */}
        {Object.entries(grouped).map(([folder, items]) => {
          if (folder === "__root__") {
            return items.map(renderDocRow);
          }
          const isFolderOpen = folderOpen[folder] !== false; // default open
          return (
            <div key={folder} style={{borderTop:`1px solid ${C.border}`}}>
              {/* Folder header */}
              <div
                onClick={()=>setFolderOpen(s=>({...s,[folder]:!isFolderOpen}))}
                style={{
                  display:"flex", alignItems:"center", gap:10,
                  padding:"9px 18px", cursor:"pointer",
                  background:`${C.surface2}`, borderBottom:isFolderOpen?`1px solid ${C.border}`:"none",
                }}
              >
                <span style={{fontSize:13}}>{isFolderOpen ? "📂" : "📁"}</span>
                <span style={{...SANS, fontSize:12, fontWeight:700, color:C.textSub,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", flex:1}}>
                  {folder}
                </span>
                <span style={{fontSize:10, color:C.textMuted, background:C.bg,
                  border:`1px solid ${C.border}`, borderRadius:10, padding:"1px 8px", flexShrink:0}}>
                  {items.length} file{items.length !== 1 ? "s" : ""}
                </span>
                <span style={{fontSize:10, color:C.textMuted}}>{isFolderOpen?"▲":"▼"}</span>
              </div>
              {isFolderOpen && items.map(renderDocRow)}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ANALYSIS ERROR BOUNDARY
// ─────────────────────────────────────────────────────────────────────────────
class AnalysisErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(e) { return { err: e }; }
  render() {
    if (this.state.err) {
      return (
        <div style={{ padding:32, color:"#EF5350", fontFamily:"monospace", fontSize:12, background:"#0C0C18", margin:24, borderRadius:6, border:"1px solid #EF535044" }}>
          <div style={{ fontWeight:700, marginBottom:8 }}>AnalysisPanel Error</div>
          <div>{String(this.state.err.message)}</div>
          <pre style={{ fontSize:10, color:"#666", marginTop:12, whiteSpace:"pre-wrap" }}>{this.state.err.stack}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// THREATAFORM ANALYSIS ENGINE
// ─────────────────────────────────────────────────────────────────────────────

// MITRE ATT&CK technique reference table (Enterprise v16.1 Cloud/IaaS)
const ATTACK_TECHNIQUES = {
  "T1078":     { name:"Valid Accounts",                              tactic:"Initial Access · Persistence · Defense Evasion · Privilege Escalation" },
  "T1078.004": { name:"Valid Accounts: Cloud Accounts",             tactic:"Initial Access · Persistence" },
  "T1190":     { name:"Exploit Public-Facing Application",          tactic:"Initial Access" },
  "T1195":     { name:"Supply Chain Compromise",                    tactic:"Initial Access" },
  "T1021":     { name:"Remote Services",                            tactic:"Lateral Movement" },
  "T1021.001": { name:"Remote Services: Remote Desktop Protocol",   tactic:"Lateral Movement" },
  "T1021.004": { name:"Remote Services: SSH",                       tactic:"Lateral Movement" },
  "T1530":     { name:"Data from Cloud Storage Object",             tactic:"Collection" },
  "T1537":     { name:"Transfer Data to Cloud Account",             tactic:"Exfiltration" },
  "T1552":     { name:"Unsecured Credentials",                      tactic:"Credential Access" },
  "T1552.005": { name:"Unsecured Credentials: Cloud Instance Metadata API", tactic:"Credential Access" },
  "T1555.006": { name:"Credentials from Password Stores: Cloud Secrets Management Stores", tactic:"Credential Access" },
  "T1562.008": { name:"Impair Defenses: Disable Cloud Logs",        tactic:"Defense Evasion" },
  "T1578":     { name:"Modify Cloud Compute Infrastructure",        tactic:"Defense Evasion" },
  "T1580":     { name:"Cloud Infrastructure Discovery",             tactic:"Discovery" },
  "T1619":     { name:"Cloud Storage Object Discovery",             tactic:"Discovery" },
  "T1485":     { name:"Data Destruction",                           tactic:"Impact" },
  "T1486":     { name:"Data Encrypted for Impact",                  tactic:"Impact" },
  "T1490":     { name:"Inhibit System Recovery",                    tactic:"Impact" },
  "T1496":     { name:"Resource Hijacking",                         tactic:"Impact" },
  "T1498":     { name:"Network Denial of Service",                  tactic:"Impact" },
  "T1499":     { name:"Endpoint Denial of Service",                 tactic:"Impact" },
  "T1602":     { name:"Data from Configuration Repository",         tactic:"Collection" },
  "T1611":     { name:"Escape to Host",                             tactic:"Privilege Escalation" },
  "T1098.001": { name:"Account Manipulation: Additional Cloud Credentials", tactic:"Persistence" },
  "T1098.003": { name:"Account Manipulation: Additional Cloud Roles", tactic:"Persistence" },
  "T1136.003": { name:"Create Account: Cloud Account",              tactic:"Persistence" },
  "T1484":     { name:"Domain Policy Modification",                 tactic:"Privilege Escalation · Defense Evasion" },
  "T1548.005": { name:"Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", tactic:"Privilege Escalation · Defense Evasion" },
};

// Extract a named attribute value from an HCL resource body
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

function generateAnalysis(pr, allFiles, userDocs, scopeFilePaths = null) {
  const allResources = pr?.resources    || [];
  const modules      = pr?.modules      || [];
  const connections  = pr?.connections  || [];
  const outputs      = pr?.outputs      || [];
  const variables    = pr?.variables    || [];
  const remoteStates = pr?.remoteStates || [];

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

  const execSummary =
    `Threataform analyzed ${allFiles.length} file(s) containing ${resources.length} managed resource(s), ` +
    `${modules.length} module(s), and ${connections.length} connection(s). ` +
    (tierList ? `Resources span the following infrastructure tiers: ${tierList}. ` : "") +
    `Data flows include ${connCounts.implicit} implicit reference(s), ${connCounts.explicit} explicit depends_on(s), ` +
    `and ${connCounts["module-input"]} module input/output(s). ` +
    (remoteStates.length ? `${remoteStates.length} remote state backend(s) introduce cross-stack dependencies. ` : "") +
    `Security scan: ${critCount} CRITICAL, ${highCount} HIGH, ` +
    `${secFindings.filter(f=>f.sev==="MEDIUM").length} MEDIUM, ${secFindings.filter(f=>f.sev==="LOW").length} LOW finding(s). ` +
    `${trustBoundaries.length} trust boundary/boundaries identified. ` +
    `${signals.filter(s=>s.sev==="HIGH").length} HIGH, ${signals.filter(s=>s.sev==="MEDIUM").length} MEDIUM, and ` +
    `${signals.filter(s=>s.sev==="LOW").length} LOW architecture signal(s). ` +
    `${strideLM.length} tier(s) mapped with STRIDE-LM threat analysis.`;

  return { execSummary, tierGroups, connCounts, topR, surf, signals, modules, remoteStates,
    variables, outputs, secFindings, trustBoundaries, narrative, strideLM, attackMap, scopeInfo,
    scale:{ resources:resources.length, modules:modules.length, connections:connections.length, files:(allFiles||[]).length },
    fileNames:(allFiles||[]).map(f=>f.path), userDocs:userDocs||[], timestamp:new Date().toISOString() };
}

// ─────────────────────────────────────────────────────────────────────────────
// SCOPE SELECTOR — lets users define which files are "in scope" for threat modeling
// ─────────────────────────────────────────────────────────────────────────────
function ScopeSelector({ files, scopeFiles, onScopeChange }) {
  const [open, setOpen] = useState(false);
  const [folderOpenState, setFolderOpenState] = useState({});

  // Group files by folder prefix
  const folderMap = useMemo(() => {
    const m = {};
    files.forEach(f => {
      const parts = f.path.replace(/\\/g,"/").split("/");
      const folder = parts.length > 1 ? parts.slice(0,-1).join("/") : "(root)";
      if (!m[folder]) m[folder] = [];
      m[folder].push(f);
    });
    return m;
  }, [files]);

  const folders = useMemo(() => Object.keys(folderMap).sort(), [folderMap]);

  // null = all in scope; new Set() = none selected; Set([...]) = subset
  const effectiveScope = (scopeFiles === null || scopeFiles === undefined)
    ? new Set(files.map(f => f.path))
    : scopeFiles;
  const inScopeCount  = effectiveScope.size;
  const allSelected   = scopeFiles === null || inScopeCount === files.length;
  const noneSelected  = scopeFiles !== null && scopeFiles !== undefined && inScopeCount === 0;
  const scopeActive   = scopeFiles !== null && scopeFiles !== undefined && inScopeCount > 0 && inScopeCount < files.length;

  const isFolderFull    = folder => folderMap[folder].every(f => effectiveScope.has(f.path));
  const isFolderPartial = folder => {
    const s = folderMap[folder].filter(f => effectiveScope.has(f.path)).length;
    return s > 0 && s < folderMap[folder].length;
  };

  const toggleFolder = (folder, e) => {
    e.stopPropagation();
    const next = new Set(effectiveScope);
    if (isFolderFull(folder)) folderMap[folder].forEach(f => next.delete(f.path));
    else                       folderMap[folder].forEach(f => next.add(f.path));
    onScopeChange(next);
  };

  const toggleFile = (path, e) => {
    e.stopPropagation();
    const next = new Set(effectiveScope);
    if (next.has(path)) next.delete(path); else next.add(path);
    onScopeChange(next);
  };

  const selectAll   = () => onScopeChange(null);
  const deselectAll = () => onScopeChange(new Set());

  const borderColor = scopeActive ? "#1E88E5" : "#333";

  return (
    <div style={{
      marginBottom:16, background:C.surface2,
      border:`1px solid ${borderColor}44`,
      borderLeft:`3px solid ${borderColor}`,
      borderRadius:8, overflow:"hidden"
    }}>
      {/* Header row */}
      <button onClick={()=>setOpen(o=>!o)} style={{
        width:"100%", textAlign:"left", background:"none", border:"none",
        cursor:"pointer", padding:"12px 18px", display:"flex", alignItems:"center", gap:12, ...SANS
      }}>
        <div style={{flex:1}}>
          <span style={{fontSize:13, fontWeight:700, color: scopeActive?"#42A5F5":C.textSub, letterSpacing:".05em"}}>
            Threat Model Scope
          </span>
          {" "}
          <span style={{fontSize:12, color:C.textMuted}}>
            {noneSelected
              ? `No files selected — analysis disabled`
              : scopeActive
              ? `${inScopeCount} of ${files.length} files in scope · ${files.length - inScopeCount} context-only`
              : `All ${files.length} files in scope (full analysis)`}
          </span>
        </div>
        {scopeActive && (
          <span style={{fontSize:11, padding:"3px 10px", borderRadius:4,
            background:"#1565C033", color:"#42A5F5", border:"1px solid #1565C055", fontWeight:600}}>SCOPE ACTIVE</span>
        )}
        <span style={{fontSize:12, color:C.textMuted}}>{open?"▲":"▼"}</span>
      </button>

      {open && (
        <div style={{borderTop:`1px solid ${C.border}`}}>
          {/* Quick controls */}
          <div style={{padding:"8px 18px", display:"flex", gap:8, alignItems:"center",
            background:C.surface, borderBottom:`1px solid ${C.border}`}}>
            <span style={{fontSize:12, color:C.textMuted, marginRight:4}}>Select:</span>
            <button onClick={selectAll} style={{
              fontSize:11, padding:"4px 12px", borderRadius:4, cursor:"pointer", ...SANS,
              border:"1px solid #4CAF5055", background:"#4CAF5011", color:"#4CAF50"
            }}>All</button>
            <button onClick={deselectAll} style={{
              fontSize:11, padding:"4px 12px", borderRadius:4, cursor:"pointer", ...SANS,
              border:"1px solid #EF535055", background:"#EF535011", color:"#EF5350"
            }}>None</button>
            <span style={{fontSize:11, color:C.textMuted, marginLeft:"auto", maxWidth:420, textAlign:"right"}}>
              Checked files → full threat analysis · Unchecked files → infrastructure context only
            </span>
          </div>

          {/* File tree */}
          <div style={{maxHeight:360, overflowY:"auto"}}>
            {folders.map(folder => {
              const folderFiles = folderMap[folder];
              const full    = isFolderFull(folder);
              const partial = isFolderPartial(folder);
              const isExpanded = folderOpenState[folder] !== false;
              const selCount = folderFiles.filter(f => effectiveScope.has(f.path)).length;

              return (
                <div key={folder}>
                  <div
                    onClick={()=>setFolderOpenState(s=>({...s,[folder]:!isExpanded}))}
                    style={{display:"flex", alignItems:"center", gap:10, padding:"7px 18px",
                      background:C.surface, borderBottom:`1px solid ${C.border}`, cursor:"pointer",
                      userSelect:"none"}}
                  >
                    <input type="checkbox"
                      checked={full}
                      ref={el => { if(el) el.indeterminate = partial && !full; }}
                      onChange={e=>toggleFolder(folder,e)}
                      onClick={e=>e.stopPropagation()}
                      style={{cursor:"pointer", accentColor:"#1E88E5", flexShrink:0}}
                    />
                    <span style={{...MONO, fontSize:12, flex:1,
                      color: full?C.text : partial?"#90CAF9" : C.textMuted}}>
                      {isExpanded?"▾ ":"▸ "}{folder}
                    </span>
                    <span style={{fontSize:11, color:C.textMuted}}>
                      {selCount}/{folderFiles.length}
                    </span>
                  </div>

                  {isExpanded && folderFiles.map((f,fi) => {
                    const isIn = effectiveScope.has(f.path);
                    const fname = f.path.replace(/\\/g,"/").split("/").pop();
                    return (
                      <div key={fi}
                        onClick={e=>toggleFile(f.path,e)}
                        style={{display:"flex", alignItems:"center", gap:10,
                          padding:"5px 18px 5px 40px",
                          background: isIn ? "#050D1A" : "transparent",
                          borderBottom:`1px solid ${C.border}`, cursor:"pointer", userSelect:"none"}}
                      >
                        <input type="checkbox" checked={!!isIn} onChange={e=>toggleFile(f.path,e)}
                          onClick={e=>e.stopPropagation()}
                          style={{cursor:"pointer", accentColor:"#1E88E5", flexShrink:0}}
                        />
                        <span style={{...MONO, fontSize:12, flex:1,
                          color: isIn ? "#90CAF9" : C.textMuted}}>{fname}</span>
                        {isIn && (
                          <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                            background:"#1565C033", color:"#42A5F5", border:"1px solid #1565C044"}}>
                            in scope
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function AnalysisPanel({ parseResult, files, userDocs, scopeFiles, onScopeChange }) {
  const A = useMemo(
    () => generateAnalysis(parseResult, files, userDocs, scopeFiles),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [parseResult, files, userDocs, scopeFiles]
  );
  const [strideOpen, setStrideOpen] = useState(null);
  const [activeSection, setActiveSection] = useState(null);
  const SEV_C = { CRITICAL:"#FF1744", HIGH:"#EF5350", MEDIUM:"#FFA726", LOW:"#66BB6A" };
  const SEV_B = { CRITICAL:"#1C0006", HIGH:"#1C0404", MEDIUM:"#191000", LOW:"#071407" };

  const Section = ({ id, title, color=C.accent, count, children }) => {
    const isOpen = activeSection !== id; // sections open by default; click to collapse
    return (
      <div style={{ marginBottom:16, background:C.surface2, border:`1px solid ${C.border}`, borderLeft:`3px solid ${color}`, borderRadius:8, overflow:"hidden" }}>
        <button
          onClick={()=>setActiveSection(activeSection===id ? null : id)}
          style={{ width:"100%", display:"flex", alignItems:"center", gap:10, background:C.surface, padding:"11px 20px", border:"none", cursor:"pointer", ...SANS }}
        >
          <span style={{ flex:1, fontSize:12, fontWeight:700, color, letterSpacing:".07em", textTransform:"uppercase", textAlign:"left" }}>{title}</span>
          {count !== undefined && (
            <span style={{ fontSize:11, fontWeight:700, background:`${color}20`, color, border:`1px solid ${color}44`, borderRadius:4, padding:"1px 8px" }}>{count}</span>
          )}
          <span style={{ fontSize:11, color:C.textMuted, marginLeft:4 }}>{isOpen?"▲":"▼"}</span>
        </button>
        {isOpen && <div style={{ padding:"16px 20px" }}>{children}</div>}
      </div>
    );
  };

  const Badge = ({ sev }) => (
    <span style={{ background:SEV_B[sev], color:SEV_C[sev], border:`1px solid ${SEV_C[sev]}55`, borderRadius:4, padding:"2px 8px", fontSize:10, fontWeight:700, letterSpacing:".06em", marginRight:6 }}>{sev}</span>
  );

  const Pill = ({ label, val, color=C.accent }) => (
    <div style={{ background:C.surface2, border:`1px solid ${C.border}`, borderRadius:8, padding:"12px 16px", textAlign:"center" }}>
      <div style={{ fontSize:26, fontWeight:700, color, fontFamily:"monospace" }}>{val}</div>
      <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>{label}</div>
    </div>
  );

  const total = A.connCounts.implicit + A.connCounts.explicit + A.connCounts["module-input"] + A.connCounts.other;
  const critFindings = A.secFindings.filter(f=>f.sev==="CRITICAL");
  const highFindings = A.secFindings.filter(f=>f.sev==="HIGH");

  const STRIDE_COLORS = { S:"#EF5350", T:"#FF7043", R:"#FFCA28", I:"#AB47BC", D:"#42A5F5", E:"#FF9800", LM:"#E040FB" };
  const STRIDE_LABELS = { S:"Spoofing", T:"Tampering", R:"Repudiation", I:"Info Disclosure", D:"Denial of Service", E:"Elevation of Privilege", LM:"Lateral Movement" };

  return (
    <div style={{ padding:"24px 32px", maxWidth:1120, ...SANS }}>

      {/* Scope Selector */}
      {files.length > 0 && onScopeChange && (
        <ScopeSelector files={files} scopeFiles={scopeFiles} onScopeChange={onScopeChange}/>
      )}

      {/* Scope Summary Banner */}
      {A.scopeInfo.active && (
        <div style={{
          marginBottom:16, padding:"16px 20px", borderRadius:8,
          background:C.surface2,
          border:`1px solid #1565C044`, borderLeft:"3px solid #1E88E5"
        }}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:14}}>
            <div>
              <div style={{fontSize:13, fontWeight:700, color:"#42A5F5", letterSpacing:".05em", marginBottom:6}}>
                SCOPE ACTIVE — Focused Threat Model
              </div>
              <div style={{fontSize:13, color:C.textSub, lineHeight:1.7, maxWidth:560}}>
                Security findings, STRIDE-LM, and ATT&CK mapping apply only to{" "}
                <span style={{color:C.text, fontWeight:600}}>{A.scopeInfo.inScopeFileCount} in-scope file(s)</span>.{" "}
                {A.scopeInfo.outScopeResourceCount} resource(s) from{" "}
                {A.scopeInfo.totalFileCount - A.scopeInfo.inScopeFileCount} context file(s) provide dependency context.
                {A.scopeInfo.crossScopeConnCount > 0 && ` ${A.scopeInfo.crossScopeConnCount} cross-boundary connection(s) detected.`}
              </div>
            </div>
            <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
              {[
                {label:"In-Scope",       val:A.scopeInfo.inScopeResourceCount,          c:"#42A5F5"},
                {label:"Context",        val:A.scopeInfo.outScopeResourceCount,          c:"#546E7A"},
                {label:"Cross-Boundary", val:A.scopeInfo.crossScopeConnCount,            c:"#FF7043"},
                {label:"Upstream Deps",  val:A.scopeInfo.dependencyResources.length,     c:"#AB47BC"},
                {label:"Downstream",     val:A.scopeInfo.inboundResources.length,        c:"#FFCA28"},
              ].map(p=>(
                <div key={p.label} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"8px 14px", textAlign:"center", minWidth:80}}>
                  <div style={{fontSize:22, fontWeight:700, color:p.c, fontFamily:"monospace"}}>{p.val}</div>
                  <div style={{fontSize:11, color:C.textMuted, marginTop:3}}>{p.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:20, flexWrap:"wrap", gap:14 }}>
        <div>
          <div style={{ fontSize:20, fontWeight:700, color:C.text, letterSpacing:".04em" }}>Threataform Analysis</div>
          <div style={{ fontSize:12, color:C.textMuted, marginTop:5 }}>
            {new Date(A.timestamp).toLocaleString()} · {A.scale.files} file(s) · ATT&CK Enterprise v18.1 · CWE v4.16
            {A.scopeInfo.active ? ` · ${A.scopeInfo.inScopeResourceCount} in-scope resources` : ""}
          </div>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10 }}>
          <Pill label={A.scopeInfo.active ? "In-Scope" : "Resources"} val={A.scale.resources} color={C.green}/>
          <Pill label="Modules"     val={A.scale.modules}          color={C.blue}/>
          <Pill label="Connections" val={A.scale.connections}      color={C.accent}/>
          <Pill label="CRITICAL"    val={critFindings.length}      color={C.critRed}/>
          <Pill label="Findings"    val={A.secFindings.length}     color={C.red}/>
        </div>
      </div>

      {/* Executive Summary */}
      <Section id="exec" title="Executive Summary" color={C.accent}>
        <p style={{ fontSize:13, color:C.textSub, lineHeight:1.8, margin:0 }}>{A.execSummary}</p>
      </Section>

      {/* Architecture Narrative */}
      {A.narrative.length > 0 && (
        <Section id="narrative" title="Architecture Narrative" color="#26C6DA" count={A.narrative.length}>
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            {A.narrative.map((line,i) => (
              <div key={i} style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
                <span style={{ color:"#26C6DA", fontSize:13, marginTop:1, flexShrink:0 }}>▸</span>
                <div style={{ fontSize:13, color:C.textSub, lineHeight:1.7 }}>{line}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Trust Boundaries */}
      {A.trustBoundaries.length > 0 && (
        <Section id="trust" title="Trust Boundaries" color="#7C4DFF" count={A.trustBoundaries.length}>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {A.trustBoundaries.map((b,i) => (
              <div key={i} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"12px 16px" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
                  <span style={{ fontSize:13, fontWeight:700, color:"#B39DDB" }}>{b.zone}</span>
                  <div style={{ display:"flex", gap:6 }}>
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:4, background:C.surface2, color:C.textMuted }}>{b.type}</span>
                    <span style={{ fontSize:10, padding:"2px 8px", borderRadius:4,
                      background: b.risk==="HIGH"?SEV_B.HIGH:SEV_B.MEDIUM,
                      color: b.risk==="HIGH"?SEV_C.HIGH:SEV_C.MEDIUM }}>{b.risk} RISK</span>
                  </div>
                </div>
                <div style={{ fontSize:13, color:C.textSub, lineHeight:1.6, marginBottom:6 }}>{b.desc}</div>
                <div style={{ fontSize:11, color:C.textMuted }}>Controls: {b.control}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Security Findings (Checkov-style) */}
      <Section id="findings" title={`Security Findings`} color={C.critRed} count={`${A.secFindings.length} (${critFindings.length} CRITICAL · ${highFindings.length} HIGH)`}>
        {A.secFindings.length === 0 && (
          <div style={{ fontSize:13, color:C.textMuted }}>No security findings detected based on parsed resource attributes.</div>
        )}
        {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
          const grp = A.secFindings.filter(f=>f.sev===sev);
          if (!grp.length) return null;
          return (
            <div key={sev} style={{ marginBottom:14 }}>
              <div style={{ fontSize:11, color:SEV_C[sev], fontWeight:700, marginBottom:8, letterSpacing:".1em", textTransform:"uppercase" }}>── {sev} ({grp.length})</div>
              {grp.map((f,i) => (
                <div key={i} style={{ marginBottom:8, padding:"12px 16px", background:SEV_B[sev], border:`1px solid ${SEV_C[sev]}22`, borderRadius:6 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6, flexWrap:"wrap" }}>
                    <Badge sev={sev}/>
                    <span style={{ fontSize:11, color:C.textMuted, ...MONO }}>{f.code}</span>
                    <span style={{ fontSize:13, fontWeight:600, color:SEV_C[sev], flex:1 }}>{f.msg}</span>
                  </div>
                  <div style={{ fontSize:12, color:C.textSub, lineHeight:1.6, marginBottom:8 }}>{f.detail}</div>
                  <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                    {f.technique && ATTACK_TECHNIQUES[f.technique] && (
                      <span style={{ fontSize:11, color:"#EF9A9A", background:"#1A0008", border:"1px solid #B71C1C33", borderRadius:4, padding:"2px 8px" }}>
                        ATT&CK {f.technique} · {ATTACK_TECHNIQUES[f.technique].tactic}
                      </span>
                    )}
                    {f.cwe && (
                      <span style={{ fontSize:11, color:"#FFAB91", background:"#1A0800", border:"1px solid #E6510033", borderRadius:4, padding:"2px 8px" }}>
                        {f.cwe}
                      </span>
                    )}
                    <span style={{ fontSize:10, color:C.textMuted, ...MONO }}>{f.id}</span>
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </Section>

      {/* STRIDE-LM Threat Analysis by Tier */}
      {A.strideLM.length > 0 && (
        <Section id="stride" title="STRIDE-LM Threat Analysis by Infrastructure Tier" color="#E040FB" count={A.strideLM.length + " tiers"}>
          <div style={{ fontSize:12, color:C.textMuted, marginBottom:14, lineHeight:1.7 }}>
            Per-tier threats based on STRIDE-LM: S=Spoofing · T=Tampering · R=Repudiation · I=Info Disclosure · D=Denial of Service · E=Elevation of Privilege · LM=Lateral Movement. Click a tier to expand.
          </div>
          {A.strideLM.map((tierData, ti) => (
            <div key={ti} style={{ marginBottom:8, border:`1px solid ${tierData.color}33`, borderRadius:6, overflow:"hidden" }}>
              <button
                onClick={() => setStrideOpen(strideOpen===ti ? null : ti)}
                style={{ width:"100%", background: strideOpen===ti ? tierData.color+"18" : C.surface,
                  border:"none", cursor:"pointer", padding:"11px 16px", display:"flex", alignItems:"center",
                  justifyContent:"space-between", ...SANS }}
              >
                <span style={{ fontSize:13, fontWeight:700, color:tierData.color }}>{tierData.tier}</span>
                <div style={{ display:"flex", gap:4, alignItems:"center" }}>
                  {Object.keys(STRIDE_COLORS).map(cat => (
                    <span key={cat} style={{ fontSize:10, fontWeight:700, color:STRIDE_COLORS[cat],
                      background:STRIDE_COLORS[cat]+"22", borderRadius:3, padding:"2px 6px" }}>{cat}</span>
                  ))}
                  <span style={{ fontSize:11, color:C.textMuted, marginLeft:8 }}>{strideOpen===ti?"▲":"▼"}</span>
                </div>
              </button>
              {strideOpen===ti && (
                <div style={{ background:C.surface2, padding:"14px 16px", borderTop:`1px solid ${C.border}` }}>
                  {tierData.cats.map((c,ci) => (
                    <div key={ci} style={{ marginBottom:12, paddingBottom:12, borderBottom:`1px solid ${C.border}` }}>
                      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
                        <span style={{ fontSize:12, fontWeight:800, color:STRIDE_COLORS[c.cat],
                          background:STRIDE_COLORS[c.cat]+"22", borderRadius:4, padding:"3px 8px",
                          minWidth:32, textAlign:"center" }}>{c.cat}</span>
                        <span style={{ fontSize:13, fontWeight:600, color:STRIDE_COLORS[c.cat] }}>{STRIDE_LABELS[c.cat]}</span>
                      </div>
                      {c.threats.map((t,ti2) => (
                        <div key={ti2} style={{ display:"flex", gap:10, alignItems:"flex-start", marginBottom:5 }}>
                          <span style={{ color:STRIDE_COLORS[c.cat], fontSize:12, marginTop:1, flexShrink:0 }}>›</span>
                          <span style={{ fontSize:12, color:C.textSub, lineHeight:1.6 }}>{t}</span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* MITRE ATT&CK Technique Mapping */}
      {Object.keys(A.attackMap).length > 0 && (
        <Section id="attack" title="MITRE ATT&CK® Technique Mapping" color="#B71C1C" count={Object.keys(A.attackMap).length}>
          <div style={{ fontSize:12, color:C.textMuted, marginBottom:12 }}>Techniques mapped from security findings — attack.mitre.org · Enterprise v18.1 Cloud/IaaS matrix</div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:10 }}>
            {Object.entries(A.attackMap).map(([tid, data]) => (
              <div key={tid} style={{ background:C.surface, border:"1px solid #B71C1C33", borderRadius:6, padding:"12px 14px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                  <span style={{ fontSize:11, fontWeight:700, color:"#FF1744", ...MONO,
                    background:"#1A0008", border:"1px solid #FF174433", borderRadius:4, padding:"2px 8px" }}>{tid}</span>
                  <span style={{ fontSize:13, fontWeight:600, color:"#EF9A9A" }}>{data.name}</span>
                </div>
                <div style={{ fontSize:12, color:C.textMuted, marginBottom:6 }}>{data.tactic}</div>
                <div style={{ fontSize:11, color:C.textMuted }}>{data.findings.length} finding(s): {data.findings.slice(0,3).map(f=>f.code).join(", ")}{data.findings.length>3?"…":""}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Architecture Inventory */}
      <Section id="inventory" title="Architecture Inventory by Tier" color={C.green} count={A.scale.resources}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:10 }}>
          {Object.entries(A.tierGroups).map(([tid, res]) => {
            const tm = TIERS[tid] || { label:tid, border:"#555", hdr:"#111" };
            return (
              <div key={tid} style={{ background:C.surface, border:`1px solid ${tm.border}33`, borderLeft:`3px solid ${tm.border}`, borderRadius:6, padding:"12px 14px" }}>
                <div style={{ fontSize:12, fontWeight:700, color:tm.border, marginBottom:8 }}>
                  {tm.label} <span style={{ color:C.textMuted, fontWeight:400 }}>({res.length})</span>
                </div>
                {res.slice(0,8).map((r,i) => (
                  <div key={i} style={{ fontSize:11, color:C.textSub, ...MONO, padding:"2px 0", display:"flex", gap:6 }}>
                    <span style={{ color:RT[r.type]?.c||C.textMuted, fontSize:10, flexShrink:0 }}>▸</span>
                    <span style={{ color:C.textSub, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.id}</span>
                  </div>
                ))}
                {res.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{res.length-8} more</div>}
              </div>
            );
          })}
        </div>
      </Section>

      {/* Architecture Signals (existing) */}
      {A.signals.length > 0 && (
        <Section id="signals" title="Architecture Signals" color={C.accent} count={A.signals.length}>
          {["HIGH","MEDIUM","LOW"].map(sev => {
            const grp = A.signals.filter(s=>s.sev===sev);
            if (!grp.length) return null;
            return (
              <div key={sev} style={{ marginBottom:10 }}>
                {grp.map((s,i) => (
                  <div key={i} style={{ marginBottom:8, padding:"12px 16px", background:SEV_B[sev]||C.surface, border:`1px solid ${SEV_C[sev]||C.border}22`, borderRadius:6 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                      <Badge sev={sev}/>
                      <span style={{ fontSize:13, fontWeight:600, color:SEV_C[sev]||C.text }}>{s.msg}</span>
                    </div>
                    <div style={{ fontSize:12, color:C.textSub, lineHeight:1.6 }}>{s.detail}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </Section>
      )}

      {/* Data Flow Analysis */}
      <Section id="dataflow" title="Data Flow Analysis" color={C.blue} count={total}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:16 }}>
          <Pill label="Total Connections"   val={total}                          color={C.blue}/>
          <Pill label="Implicit Refs"       val={A.connCounts.implicit}          color="#78909C"/>
          <Pill label="Explicit depends_on" val={A.connCounts.explicit}          color={C.red}/>
          <Pill label="Module I/O"          val={A.connCounts["module-input"]}   color={C.green}/>
        </div>
        {A.topR.length > 0 && (
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Top Connected Resources — Highest Dependency Degree</div>
            {A.topR.map((r,i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:10, padding:"6px 0", borderBottom:`1px solid ${C.border}` }}>
                <span style={{ fontSize:11, color:C.textMuted, minWidth:24, textAlign:"right" }}>#{i+1}</span>
                <span style={{ fontSize:12, color:RT[r.type]?.c||C.textSub, ...MONO, flex:1 }}>{r.id}</span>
                <span style={{ fontSize:11, color:C.textMuted }}>{r.type}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Security Surface */}
      <Section id="surface" title="Security Surface Inventory" color={C.purple}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10 }}>
          {[
            { label:"IAM Principals & Policies", items:A.surf.iam,                     color:"#E040FB" },
            { label:"Security Groups",            items:A.surf.sg,                      color:"#FF7043" },
            { label:"KMS Keys",                   items:A.surf.kms,                     color:"#26C6DA" },
            { label:"Load Balancers / API GW",    items:[...A.surf.lb,...A.surf.apigw], color:"#EF5350" },
            { label:"RDS / Aurora",               items:A.surf.rds,                     color:"#42A5F5" },
            { label:"S3 Buckets",                 items:A.surf.s3,                      color:"#FFCA28" },
            { label:"EKS / Kubernetes",           items:A.surf.eks,                     color:"#66BB6A" },
            { label:"Lambda Functions",           items:A.surf.lambda,                  color:"#FF9800" },
            { label:"WAF",                        items:A.surf.waf,                     color:"#26C6DA" },
          ].map(({ label, items, color }) => (
            <div key={label} style={{ background:C.surface, borderRadius:6, padding:"10px 12px", border:`1px solid ${C.border}`, borderTop:`2px solid ${color}` }}>
              <div style={{ fontSize:12, color, fontWeight:700, marginBottom:6 }}>{label} <span style={{ color:C.textMuted, fontWeight:400 }}>({items.length})</span></div>
              {items.slice(0,4).map((r,i) => (
                <div key={i} style={{ fontSize:11, color:C.textMuted, ...MONO, overflow:"hidden", whiteSpace:"nowrap", textOverflow:"ellipsis", padding:"1px 0" }}>{r.id}</div>
              ))}
              {items.length>4 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{items.length-4} more</div>}
            </div>
          ))}
        </div>
      </Section>

      {/* Terraform Patterns */}
      <Section id="patterns" title="Terraform Patterns" color="#26C6DA">
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:14 }}>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Modules ({A.modules.length})</div>
            {A.modules.slice(0,8).map((m,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#CE93D8" }}>module.</span>{m.name}
                {m.source && <span style={{ color:C.textMuted }}> ← {m.source.substring(0,38)}{m.source.length>38?"…":""}</span>}
              </div>
            ))}
            {A.modules.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.modules.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Remote States ({A.remoteStates.length})</div>
            {A.remoteStates.slice(0,8).map((rs,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#42A5F5" }}>{rs.address||rs.id||`remote_${i}`}</span>
              </div>
            ))}
            {A.remoteStates.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.remoteStates.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Variables ({A.variables.length})</div>
            {A.variables.slice(0,8).map((v,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#FFD54F" }}>var.</span>{v.name}
                {v.sensitive && <span style={{ color:C.red, marginLeft:8, fontSize:10 }}>[sensitive]</span>}
              </div>
            ))}
            {A.variables.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.variables.length-8} more</div>}
          </div>
          <div>
            <div style={{ fontSize:11, color:C.textMuted, fontWeight:700, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em" }}>Outputs ({A.outputs.length})</div>
            {A.outputs.slice(0,8).map((o,i) => (
              <div key={i} style={{ fontSize:12, color:C.textSub, ...MONO, padding:"3px 0" }}>
                <span style={{ color:"#4DD0E1" }}>output.</span>{o.name}
                {o.sensitive && <span style={{ color:C.red, marginLeft:8, fontSize:10 }}>[sensitive]</span>}
              </div>
            ))}
            {A.outputs.length>8 && <div style={{ fontSize:11, color:C.textMuted, marginTop:4 }}>+{A.outputs.length-8} more</div>}
          </div>
        </div>
      </Section>

      {/* Supporting Documents */}
      {A.userDocs.length > 0 && (
        <Section id="docs" title="Supporting Documents" color="#78909C" count={A.userDocs.length}>
          <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
            {A.userDocs.map((d,i) => {
              const ext = (d.name||"").split(".").pop().toLowerCase();
              const typeMeta = DOC_TYPE_META[ext] || { label: ext.toUpperCase().slice(0,6)||"FILE", color:"#78909C" };
              return (
                <div key={i} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"9px 13px", display:"flex", gap:10, alignItems:"flex-start" }}>
                  <span style={{
                    fontSize:9, fontWeight:700, color:typeMeta.color,
                    background:`${typeMeta.color}15`, border:`1px solid ${typeMeta.color}33`,
                    borderRadius:4, padding:"2px 6px", flexShrink:0, marginTop:1
                  }}>{typeMeta.label}</span>
                  <div style={{minWidth:0}}>
                    <div style={{ fontSize:12, color:"#90A4AE", fontWeight:600, marginBottom:3,
                      overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {d.path || d.name}
                    </div>
                    {!d.binary && (
                      <div style={{ fontSize:10, color:C.textMuted, ...MONO, whiteSpace:"pre-wrap",
                        maxHeight:60, overflow:"hidden", lineHeight:1.5 }}>
                        {(d.content||"").substring(0,300)}{(d.content||"").length>300?"…":""}
                      </div>
                    )}
                    {d.binary && <div style={{fontSize:10, color:C.textMuted, fontStyle:"italic"}}>binary file</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Upstream Infrastructure Dependencies (scope context) */}
      {A.scopeInfo.active && A.scopeInfo.dependencyResources.length > 0 && (
        <Section id="upstream" title="Upstream Infrastructure Dependencies — Context (Out of Scope)" color="#AB47BC" count={A.scopeInfo.dependencyResources.length}>
          <div style={{fontSize:13, color:C.textSub, marginBottom:12, lineHeight:1.7}}>
            These resources are defined <strong style={{color:"#CE93D8"}}>outside the threat model scope</strong> but are directly referenced by in-scope resources.
            Their security posture directly impacts the in-scope system's risk profile — review their configurations as part of the broader risk assessment.
          </div>
          <div style={{display:"flex", flexDirection:"column", gap:4}}>
            {A.scopeInfo.dependencyResources.map((r,i) => {
              const meta = RT[r.type] || RT._default;
              return (
                <div key={i} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
                  padding:"8px 14px", display:"flex", alignItems:"center", gap:10}}>
                  <div style={{width:10, height:10, borderRadius:2, background:meta.c, flexShrink:0}}/>
                  <span style={{...MONO, fontSize:12, color:"#CE93D8", flex:1}}>{r.id}</span>
                  <span style={{fontSize:11, color:C.textMuted}}>{r.type}</span>
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background:"#AB47BC22", color:"#CE93D8", border:"1px solid #AB47BC33", flexShrink:0}}>upstream context</span>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Downstream Callers (scope context) */}
      {A.scopeInfo.active && A.scopeInfo.inboundResources.length > 0 && (
        <Section id="downstream" title="Downstream Callers — Context (Out of Scope)" color="#FFCA28" count={A.scopeInfo.inboundResources.length}>
          <div style={{fontSize:13, color:C.textSub, marginBottom:12, lineHeight:1.7}}>
            These resources are defined <strong style={{color:"#FFE082"}}>outside the threat model scope</strong> but depend on in-scope resources.
            Each caller is a potential entry vector if improperly authenticated or authorized at the scope boundary.
          </div>
          <div style={{display:"flex", flexDirection:"column", gap:4}}>
            {A.scopeInfo.inboundResources.map((r,i) => {
              const meta = RT[r.type] || RT._default;
              return (
                <div key={i} style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:6,
                  padding:"8px 14px", display:"flex", alignItems:"center", gap:10}}>
                  <div style={{width:10, height:10, borderRadius:2, background:meta.c, flexShrink:0}}/>
                  <span style={{...MONO, fontSize:12, color:"#FFE082", flex:1}}>{r.id}</span>
                  <span style={{fontSize:11, color:C.textMuted}}>{r.type}</span>
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background:"#FFCA2822", color:"#FFE082", border:"1px solid #FFCA2833", flexShrink:0}}>downstream caller</span>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      {/* Analyzed Files */}
      <Section id="files" title={A.scopeInfo.active ? "File Scope Map" : "Analyzed Files"} color="#546E7A" count={A.fileNames.length}>
        <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
          {A.fileNames.map((f,i) => {
            const isInScope = !A.scopeInfo.active || (scopeFiles && scopeFiles.has(f));
            return (
              <div key={i} style={{ fontSize:12, ...MONO, display:"flex", alignItems:"center", gap:8, padding:"3px 0" }}>
                <span style={{ color: isInScope ? C.green : C.textMuted }}>▸</span>
                <span style={{color: isInScope ? "#66BB6A" : C.textMuted, flex:1}}>{f}</span>
                {A.scopeInfo.active && (
                  <span style={{fontSize:11, padding:"2px 8px", borderRadius:4,
                    background: isInScope ? "#2E7D3222" : "#33333322",
                    color: isInScope ? C.green : C.textMuted,
                    border:`1px solid ${isInScope?"#2E7D3233":"#33333333"}`}}>
                    {isInScope ? "in scope" : "context"}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </Section>

    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [mainTab, setMainTab] = useState("knowledge");
  const [kbDomain, setKbDomain] = useState("xsphere");
  const [files, setFiles] = useState([]);
  const [parseResult, setParseResult] = useState(null);
  const [xml, setXml] = useState("");
  const [dfdTab, setDfdTab] = useState("stats");
  const [copied, setCopied] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [scopeFiles, setScopeFiles] = useState(null); // null = all in scope

  // User documents (persisted in localStorage)
  const [userDocs, setUserDocs] = useState(() => {
    try { const s = localStorage.getItem("tf-intel-user-docs"); return s ? JSON.parse(s) : []; }
    catch { return []; }
  });
  const saveUserDocs = useCallback((docs) => {
    setUserDocs(docs);
    try { localStorage.setItem("tf-intel-user-docs", JSON.stringify(docs)); } catch {}
  }, []);
  const addUserDocs = useCallback((fileList) => {
    // Skip: images, compiled binaries, archives, lock files with no text value
    const SKIP_EXT = /\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|zip|tar|gz|7z|exe|dll|so|dylib|class|jar|war|pyc|lock)$/i;
    // Files that are text-readable (attempt readAsText on everything else)
    const candidates = Array.from(fileList)
      .filter(f => !SKIP_EXT.test(f.name) && f.size < 5 * 1024 * 1024); // skip >5MB
    if (!candidates.length) return;
    Promise.all(candidates.map(f => new Promise((res) => {
      const path = f.webkitRelativePath || f.name;
      const name = f.name;
      const ext  = name.includes(".") ? name.split(".").pop().toLowerCase() : "txt";
      const r = new FileReader();
      r.onload = ev => {
        const content = ev.target.result;
        // Heuristic: if first 512 bytes contain many non-printable chars it's binary
        const sample = content.slice(0, 512);
        const nonPrint = (sample.match(/[\x00-\x08\x0E-\x1F\x7F]/g) || []).length;
        if (nonPrint > 20) {
          res({ path, name, ext, content:"[binary file — not displayed]", binary:true, size:f.size });
        } else {
          res({ path, name, ext, content, binary:false, size:f.size });
        }
      };
      r.onerror = () => res(null);
      r.readAsText(f);
    }))).then(loaded => {
      const valid = loaded.filter(Boolean);
      if (!valid.length) return;
      // Deduplicate by path against existing docs
      const existingPaths = new Set(userDocs.map(d => d.path || d.name));
      const newDocs = valid.filter(d => !existingPaths.has(d.path || d.name));
      if (newDocs.length) saveUserDocs([...userDocs, ...newDocs]);
    });
  }, [userDocs, saveUserDocs]);

  const readFiles = useCallback((fileList) => {
    const tf = Array.from(fileList)
      .filter(f=>/\.(tf|hcl|sentinel|tfvars)$/.test(f.name))
      .sort((a,b)=>(a.webkitRelativePath||a.name).localeCompare(b.webkitRelativePath||b.name));
    if (!tf.length) { setError("No .tf, .hcl, or .sentinel files found."); return; }
    setError("");
    Promise.all(tf.map(f=>new Promise((res,rej)=>{
      const r=new FileReader();
      r.onload=ev=>res({path:f.webkitRelativePath||f.name, content:ev.target.result});
      r.onerror=()=>rej(new Error("Read failed: "+f.name));
      r.readAsText(f);
    }))).then(loaded=>{
      setFiles(loaded);
      setScopeFiles(null); // null = all files in scope by default
      const result = parseTFMultiFile(loaded);
      setParseResult(result);
      if (result.resources.length > 0 || result.modules.length > 0) {
        const x = generateDFDXml(result.resources, result.modules, result.connections);
        setXml(x);
        setDfdTab("stats");
        setMainTab("analysis");
      } else {
        setError("No resources or modules found in uploaded files.");
      }
    }).catch(e=>setError(e.message));
  }, []);

  const handleDrop = useCallback(e=>{ e.preventDefault(); setDragging(false); readFiles(e.dataTransfer.files); }, [readFiles]);
  const download = () => {
    const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([xml],{type:"application/xml"}));
    a.download="enterprise-tf-dfd.drawio"; a.click();
  };
  const copy = () => {
    const done = () => { setCopied(true); setTimeout(()=>setCopied(false),2000); };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(xml).then(done).catch(()=>{
        const ta=document.createElement("textarea"); ta.value=xml;
        document.body.appendChild(ta); ta.select(); document.execCommand("copy");
        document.body.removeChild(ta); done();
      });
    } else {
      const ta=document.createElement("textarea"); ta.value=xml;
      document.body.appendChild(ta); ta.select(); document.execCommand("copy");
      document.body.removeChild(ta); done();
    }
  };

  const KB_DOMAINS = [
    {id:"xsphere",  label:"xSphere Cloud",         color:"#0277BD"},
    {id:"spinnaker",label:"Spinnaker.io",           color:"#00838F"},
    {id:"iam",      label:"IAM · Org · OUs · SCPs", color:"#B71C1C"},
    {id:"jenkins",  label:"Jenkins / Jules",        color:"#BF360C"},
    {id:"dfd",      label:"Enterprise DFD",         color:"#4527A0"},
    {id:"wiz",      label:"Wiz CSPM",               color:"#1A73E8"},
    {id:"attack",   label:"MITRE ATT&CK®",          color:"#B71C1C"},
    {id:"cwe",      label:"MITRE CWE",              color:"#E65100"},
    {id:"stride",   label:"STRIDE-LM",              color:"#4527A0"},
    {id:"tfePave",  label:"TFE-Pave / Hier. IAM",  color:"#2E7D32"},
    {id:"userdocs", label:"My Documents",           color:"#78909C"},
  ];

  const MAIN_TABS = [
    {id:"knowledge", label:"Knowledge Base",      icon:"📚"},
    {id:"upload",    label:"Upload & Analyze",    icon:"📤"},
    {id:"analysis",  label:"Threataform Analysis",icon:"🔬"},
    {id:"dfd",       label:"DFD Output",          icon:"🗺"},
  ];

  return (
    <div style={{...SANS, background:C.bg, minHeight:"100vh", color:C.text}}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>

      {/* ── HEADER ── */}
      <div style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 24px", display:"flex", alignItems:"center", height:58,
        position:"sticky", top:0, zIndex:100,
      }}>
        {/* Brand */}
        <div style={{display:"flex", alignItems:"center", gap:12, marginRight:36, flexShrink:0}}>
          <div style={{
            width:34, height:34, borderRadius:8, flexShrink:0,
            background:"linear-gradient(135deg,#FF6B35,#FF9900)",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:16, boxShadow:"0 2px 8px #FF990040"
          }}>⬡</div>
          <div>
            <div style={{fontSize:14, fontWeight:700, color:C.text, letterSpacing:"-.01em", lineHeight:1.2}}>
              Threataform
            </div>
            <div style={{fontSize:10, color:C.textMuted, marginTop:1}}>
              Enterprise Terraform Intelligence
            </div>
          </div>
        </div>

        {/* Nav tabs */}
        <nav style={{display:"flex", gap:2, alignItems:"center"}}>
          {MAIN_TABS.map(t => {
            const active = mainTab === t.id;
            const hasData = t.id === "analysis" || t.id === "dfd" ? !!parseResult : true;
            return (
              <button key={t.id} onClick={()=>setMainTab(t.id)} style={{
                display:"flex", alignItems:"center", gap:7,
                background: active ? `${C.accent}12` : "transparent",
                border: active ? `1px solid ${C.accent}40` : "1px solid transparent",
                borderRadius:7, padding:"7px 16px",
                color: active ? C.accent : hasData ? C.textSub : C.textMuted,
                fontSize:13, cursor:"pointer", ...SANS,
                fontWeight: active ? 600 : 400,
                transition:"all .15s",
                opacity: !hasData && t.id !== "upload" ? 0.5 : 1,
              }}>
                <span style={{fontSize:14}}>{t.icon}</span>
                <span>{t.label}</span>
                {(t.id === "analysis" || t.id === "dfd") && parseResult && (
                  <span style={{
                    width:6, height:6, borderRadius:"50%",
                    background:C.green, flexShrink:0
                  }}/>
                )}
              </button>
            );
          })}
        </nav>

        {/* Action buttons */}
        {xml && (
          <div style={{marginLeft:"auto", display:"flex", gap:8, alignItems:"center"}}>
            <button onClick={copy} style={{
              background: copied ? "#0D2010" : C.surface2,
              border:`1px solid ${copied ? C.green+"66" : C.border2}`,
              borderRadius:7, padding:"7px 16px",
              color: copied ? C.green : C.textSub,
              fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:6,
              transition:"all .15s",
            }}>
              {copied ? "✓" : "⎘"} {copied ? "Copied!" : "Copy XML"}
            </button>
            <button onClick={download} style={{
              background:"linear-gradient(135deg,#FF6B3520,#FF990020)",
              border:`1px solid ${C.accent}55`,
              borderRadius:7, padding:"7px 16px",
              color:C.accent, fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:6,
              fontWeight:600,
            }}>
              ⬇ Export .drawio
            </button>
          </div>
        )}
      </div>

      {/* ── KNOWLEDGE BASE TAB ── */}
      {mainTab==="knowledge" && (
        <div style={{display:"grid", gridTemplateColumns:"256px 1fr", height:"calc(100vh - 58px)"}}>
          {/* Sidebar */}
          <div style={{
            background:C.surface, borderRight:`1px solid ${C.border}`,
            display:"flex", flexDirection:"column", overflowY:"auto"
          }}>
            <div style={{padding:"18px 16px 10px", fontSize:10, color:C.textMuted, textTransform:"uppercase", letterSpacing:".12em", fontWeight:600}}>
              Knowledge Domains
            </div>
            <div style={{flex:1, padding:"0 8px"}}>
              {KB_DOMAINS.map(d => {
                const active = kbDomain === d.id;
                const icon = d.id === "userdocs" ? "📄" : (KB[d.id]?.icon || "◆");
                const badge = d.id === "userdocs" && userDocs.length > 0 ? userDocs.length : null;
                return (
                  <div key={d.id}>
                    {d.id === "userdocs" && (
                      <div style={{borderTop:`1px solid ${C.border}`, margin:"10px 4px 8px"}}/>
                    )}
                    <button onClick={()=>setKbDomain(d.id)} style={{
                      display:"flex", alignItems:"center", gap:10,
                      width:"100%", textAlign:"left",
                      padding:"10px 12px",
                      background: active ? `${d.color}15` : "transparent",
                      border:"none",
                      borderRadius:8,
                      color: active ? d.color : C.textSub,
                      cursor:"pointer",
                      ...SANS, fontSize:13, fontWeight: active ? 600 : 400,
                      transition:"all .15s",
                      marginBottom:2,
                    }}>
                      <span style={{
                        width:28, height:28, borderRadius:7, flexShrink:0,
                        background: active ? `${d.color}20` : C.surface2,
                        border:`1px solid ${active ? d.color+"44" : C.border}`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        fontSize:14,
                      }}>{icon}</span>
                      <span style={{flex:1, lineHeight:1.3}}>{d.label}</span>
                      {badge && (
                        <span style={{
                          background:`${d.color}22`, color:d.color,
                          border:`1px solid ${d.color}44`,
                          borderRadius:10, padding:"1px 7px", fontSize:10, fontWeight:600
                        }}>{badge}</span>
                      )}
                    </button>
                  </div>
                );
              })}
            </div>

            {/* Tips */}
            <div style={{padding:"14px 16px 18px", borderTop:`1px solid ${C.border}`}}>
              <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".07em"}}>
                Quick Tips
              </div>
              {[
                "Upload .tf files to auto-generate DFD",
                "Cross-file references detected",
                "Module trees visualized",
                "Sentinel policy gates shown",
                "Export to draw.io / Lucidchart",
              ].map((tip, i) => (
                <div key={i} style={{display:"flex", gap:8, alignItems:"flex-start", marginBottom:5}}>
                  <span style={{color:C.accent, fontSize:10, marginTop:1}}>›</span>
                  <span style={{fontSize:12, color:C.textMuted, lineHeight:1.5}}>{tip}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Content */}
          <div style={{overflowY:"auto", padding:"24px 28px", background:C.bg}}>
            {kbDomain === "userdocs"
              ? <UserDocsPanel docs={userDocs} onAdd={addUserDocs}
                  onDelete={(i) => saveUserDocs(userDocs.filter((_,idx)=>idx!==i))}
                  onClear={() => saveUserDocs([])} />
              : <KBPanel domain={kbDomain} />
            }
          </div>
        </div>
      )}

      {/* ── UPLOAD TAB ── */}
      {mainTab==="upload" && (
        <div style={{padding:"32px 40px", maxWidth:960, height:"calc(100vh - 58px)", overflowY:"auto"}}>
          {/* Page heading */}
          <div style={{marginBottom:28}}>
            <div style={{...SANS, fontSize:22, fontWeight:700, color:C.text, marginBottom:8, letterSpacing:"-.02em"}}>
              Upload Terraform Files
            </div>
            <div style={{fontSize:14, color:C.textSub, lineHeight:1.7, maxWidth:640}}>
              Upload any combination of .tf, .hcl, .sentinel, and .tfvars files. Cross-file references, module dependency trees, remote state links, and Sentinel policy gates are detected automatically.
            </div>
          </div>

          {/* Drop zone */}
          <div
            onDrop={handleDrop}
            onDragOver={e=>{e.preventDefault();setDragging(true);}}
            onDragLeave={()=>setDragging(false)}
            style={{
              border:`2px dashed ${dragging ? C.accent : C.border2}`,
              borderRadius:14, padding:"52px 32px", textAlign:"center",
              background: dragging ? `${C.accent}08` : C.surface,
              transition:"all .2s", marginBottom:20,
              boxShadow: dragging ? `0 0 24px ${C.accent}20` : "none",
            }}
          >
            <div style={{fontSize:40, marginBottom:12, opacity:dragging?1:0.6}}>📁</div>
            <div style={{...SANS, color:C.textSub, fontSize:15, marginBottom:6, fontWeight:500}}>
              {dragging ? "Drop files to upload" : "Drag & drop your Terraform files here"}
            </div>
            <div style={{fontSize:13, color:C.textMuted, marginBottom:22}}>
              .tf · .hcl · .sentinel · .tfvars
            </div>
            <div style={{display:"flex", gap:12, justifyContent:"center"}}>
              <label style={{
                background:C.surface2, border:`1px solid ${C.border2}`,
                borderRadius:8, padding:"10px 22px",
                color:C.textSub, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:8, fontWeight:500,
                transition:"all .15s",
              }}>
                <span>📄</span> Select Files
                <input type="file" accept=".tf,.hcl,.sentinel,.tfvars" multiple
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
              <label style={{
                background:`linear-gradient(135deg,${C.accent}18,${C.accent}08)`,
                border:`1px solid ${C.accent}55`,
                borderRadius:8, padding:"10px 22px",
                color:C.accent, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:8, fontWeight:600,
                transition:"all .15s",
              }}>
                <span>📂</span> Select Folder
                <input type="file" accept=".tf,.hcl,.sentinel,.tfvars" webkitdirectory=""
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
            </div>
          </div>

          {error && (
            <div style={{
              padding:"14px 18px", background:"#200808",
              border:`1px solid ${C.red}44`, borderRadius:8,
              color:"#FF8A80", fontSize:13, marginBottom:20,
              display:"flex", gap:10, alignItems:"flex-start"
            }}>
              <span style={{fontSize:16}}>⚠</span>
              <span>{error}</span>
            </div>
          )}

          {files.length > 0 && (
            <div style={{
              ...card(C.green+"44"),
              marginBottom:20,
            }}>
              <div style={{...sectionBar(C.green)}}>
                <span>✓</span>
                <span>{files.length} file{files.length !== 1 ? "s" : ""} loaded</span>
              </div>
              <div style={{padding:"12px 16px", maxHeight:180, overflowY:"auto", display:"flex", flexDirection:"column", gap:4}}>
                {files.map((f,i) => (
                  <div key={i} style={{display:"flex", gap:10, alignItems:"center"}}>
                    <span style={{color:C.green, fontSize:12, flexShrink:0}}>▸</span>
                    <span style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.6}}>{f.path}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {parseResult && (
            <div style={{...card(), marginBottom:20}}>
              <div style={{...sectionBar(C.accent)}}>
                <span>📊</span>
                <span>Parse Results</span>
              </div>
              <div style={{padding:"20px 18px"}}>
                {/* Stats grid */}
                <div style={{display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:20}}>
                  {[
                    {label:"Resources",     val:parseResult.resources.length,          c:C.green},
                    {label:"Modules",       val:parseResult.modules.length,            c:C.accent},
                    {label:"Connections",   val:parseResult.connections.length,        c:C.blue},
                    {label:"Outputs",       val:parseResult.outputs.length,            c:"#9C27B0"},
                    {label:"Variables",     val:parseResult.variables.length,          c:"#00BCD4"},
                    {label:"Remote States", val:parseResult.remoteStates?.length||0,   c:"#E91E63"},
                  ].map(s => (
                    <div key={s.label} style={{
                      background:C.bg, borderRadius:8, padding:"14px 16px",
                      border:`1px solid ${s.c}30`,
                    }}>
                      <div style={{fontSize:26, fontWeight:700, color:s.c, lineHeight:1}}>{s.val}</div>
                      <div style={{fontSize:12, color:C.textMuted, marginTop:5}}>{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Tier breakdown */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:12, color:C.textMuted, marginBottom:10, fontWeight:600, textTransform:"uppercase", letterSpacing:".07em"}}>
                    Resource Tier Breakdown
                  </div>
                  <div style={{display:"flex", flexWrap:"wrap", gap:8}}>
                    {Object.entries(
                      parseResult.resources.reduce((acc,r)=>{
                        const t=(RT[r.type]||RT._default).t;
                        acc[t]=(acc[t]||0)+1; return acc;
                      },{})
                    ).sort((a,b)=>b[1]-a[1]).map(([t,n])=>(
                      <div key={t} style={{
                        fontSize:12, padding:"6px 12px", borderRadius:6,
                        background:`${TIERS[t]?.border||"#555"}15`,
                        color:TIERS[t]?.border||"#888",
                        border:`1px solid ${TIERS[t]?.border||"#555"}33`,
                        fontWeight:600,
                      }}>
                        {TIERS[t]?.label||t}
                        <span style={{marginLeft:8, opacity:0.7, fontWeight:400}}>{n}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{display:"flex", gap:10}}>
                  <button onClick={()=>setMainTab("analysis")} style={{
                    background:"linear-gradient(135deg,#FF6B35,#FF9900)",
                    border:"none", borderRadius:8, padding:"10px 24px",
                    color:"#000", fontWeight:700, fontSize:13, cursor:"pointer", ...SANS,
                    display:"flex", alignItems:"center", gap:8,
                  }}>🔬 View Analysis →</button>
                  <button onClick={()=>setMainTab("dfd")} style={{
                    background:C.surface2, border:`1px solid ${C.accent}44`,
                    borderRadius:8, padding:"10px 24px",
                    color:C.accent, fontWeight:600, fontSize:13, cursor:"pointer", ...SANS,
                    display:"flex", alignItems:"center", gap:8,
                  }}>🗺 View DFD →</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── THREATAFORM ANALYSIS TAB ── */}
      {mainTab==="analysis" && (
        <div style={{flex:1, overflow:"auto", background:C.bg, height:"calc(100vh - 58px)"}}>
          {parseResult ? (
            <AnalysisErrorBoundary>
              <AnalysisPanel parseResult={parseResult} files={files} userDocs={userDocs} scopeFiles={scopeFiles} onScopeChange={setScopeFiles}/>
            </AnalysisErrorBoundary>
          ) : (
            <div style={{
              height:"100%", display:"flex", flexDirection:"column",
              alignItems:"center", justifyContent:"center",
              gap:20, padding:40,
            }}>
              <div style={{
                width:80, height:80, borderRadius:20,
                background:`linear-gradient(135deg,${C.accent}20,${C.accent}08)`,
                border:`1px solid ${C.accent}30`,
                display:"flex", alignItems:"center", justifyContent:"center",
                fontSize:36,
              }}>🔬</div>
              <div>
                <div style={{fontSize:20, fontWeight:700, color:C.text, textAlign:"center", marginBottom:10}}>
                  Threataform Analysis
                </div>
                <div style={{fontSize:14, color:C.textSub, textAlign:"center", maxWidth:480, lineHeight:1.75}}>
                  Upload Terraform files to generate a full architectural analysis — STRIDE-LM threat modeling, MITRE ATT&CK® mapping, security findings, trust boundaries, and architecture narrative.
                </div>
              </div>
              <button onClick={()=>setMainTab("upload")} style={{
                background:"linear-gradient(135deg,#FF6B35,#FF9900)",
                border:"none", borderRadius:8, padding:"12px 28px",
                color:"#000", fontWeight:700, fontSize:14, cursor:"pointer", ...SANS,
              }}>Upload .tf Files →</button>
            </div>
          )}
        </div>
      )}

      {/* ── DFD OUTPUT TAB ── */}
      {mainTab==="dfd" && (
        <div style={{display:"flex", flexDirection:"column", height:"calc(100vh - 58px)"}}>
          {/* Sub-tab bar */}
          <div style={{
            background:C.surface, borderBottom:`1px solid ${C.border}`,
            padding:"0 24px", display:"flex", gap:4, alignItems:"center", height:48,
          }}>
            {[
              {id:"stats",    label:"Stats",              icon:"📊"},
              {id:"xml",      label:"XML Output",         icon:"⌨"},
              {id:"guide",    label:"Import Guide",       icon:"📖"},
              {id:"legend",   label:"Legend",             icon:"🗂"},
              {id:"analysis", label:"Analysis",           icon:"🔬"},
            ].map(t => {
              const active = dfdTab === t.id;
              return (
                <button key={t.id} onClick={()=>setDfdTab(t.id)} style={{
                  display:"flex", alignItems:"center", gap:6,
                  background: active ? `${C.accent}12` : "transparent",
                  border: active ? `1px solid ${C.accent}40` : "1px solid transparent",
                  borderRadius:6, padding:"6px 14px",
                  color: active ? C.accent : C.textMuted,
                  fontSize:13, cursor:"pointer", ...SANS,
                  fontWeight: active ? 600 : 400,
                  transition:"all .15s",
                }}>
                  <span style={{fontSize:13}}>{t.icon}</span>
                  <span>{t.label}</span>
                </button>
              );
            })}
            {!xml && !parseResult && (
              <span style={{fontSize:12, color:C.textMuted, marginLeft:16}}>
                ← Upload files in the "Upload & Analyze" tab first
              </span>
            )}
          </div>

          <div style={{flex:1, overflow:"auto", background:"#080810"}}>

            {/* STATS */}
            {dfdTab==="stats" && parseResult && (
              <div style={{padding:"20px 28px", maxWidth:800}}>
                <div style={{fontSize:15, fontWeight:700, color:"#FFF", marginBottom:16}}>Terraform Architecture Analysis</div>

                {/* Files */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8}}>📁 Analyzed Files ({files.length})</div>
                  <div style={{display:"flex", flexDirection:"column", gap:3}}>
                    {files.map((f,i)=>(
                      <div key={i} style={{fontSize:10, color:"#3A5A3A", ...MONO, display:"flex", justifyContent:"space-between"}}>
                        <span><span style={{color:"#2E7D32",marginRight:6}}>▸</span>{f.path}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Resource table */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#4CAF50", fontWeight:600, marginBottom:8}}>🧩 Resources ({parseResult.resources.length})</div>
                  <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                    <div style={{display:"grid", gridTemplateColumns:"1fr 1fr auto", background:"#111120", padding:"6px 12px", fontSize:9, color:"#444", textTransform:"uppercase", letterSpacing:".1em"}}>
                      <span>Resource ID</span><span>Label</span><span>Tier</span>
                    </div>
                    {parseResult.resources.slice(0,50).map((r,i)=>{
                      const meta=RT[r.type]||RT._default;
                      return (
                        <div key={i} style={{display:"grid", gridTemplateColumns:"1fr 1fr auto", padding:"5px 12px", borderTop:"1px solid #111120", background:i%2===0?"#0A0A14":"#0C0C18"}}>
                          <span style={{...MONO, fontSize:10, color:"#4a8a8a"}}>{r.id.substring(0,40)}</span>
                          <span style={{fontSize:10, color:"#999"}}>{r.label}</span>
                          <span style={{fontSize:9, padding:"1px 6px", borderRadius:2, background:meta.c+"22", color:meta.c}}>{meta.t}</span>
                        </div>
                      );
                    })}
                    {parseResult.resources.length > 50 && (
                      <div style={{padding:"6px 12px", fontSize:10, color:"#444"}}>...and {parseResult.resources.length-50} more</div>
                    )}
                  </div>
                </div>

                {/* Modules */}
                {parseResult.modules.length > 0 && (
                  <div style={{marginBottom:20}}>
                    <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8}}>📦 Modules & Remote State ({parseResult.modules.length})</div>
                    <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                      {parseResult.modules.map((m,i)=>(
                        <div key={i} style={{padding:"6px 12px", borderTop:i>0?"1px solid #111120":"none", background:i%2===0?"#0A0A14":"#0C0C18", display:"flex", justifyContent:"space-between", alignItems:"center"}}>
                          <span style={{...MONO, fontSize:10, color:"#4a8a8a"}}>{m.id.substring(0,40)}</span>
                          <span style={{fontSize:10, color:"#666"}}>{m.shortSrc}</span>
                          <span style={{fontSize:9, padding:"1px 6px", borderRadius:2,
                            background: m.srcType==="sentinel"?"#E65100"+"22":m.srcType==="local"?"#2E7D32"+"22":m.srcType==="git"?"#1565C0"+"22":"#9C27B0"+"22",
                            color: m.srcType==="sentinel"?"#E65100":m.srcType==="local"?"#4CAF50":m.srcType==="git"?"#2196F3":"#CE93D8"
                          }}>{m.srcType}{m.version?` v${m.version}`:""}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Connections */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#2196F3", fontWeight:600, marginBottom:8}}>→ Connections ({parseResult.connections.length})</div>
                  <div style={{background:"#0C0C18", border:"1px solid #1E1E2E", borderRadius:6, overflow:"hidden"}}>
                    {parseResult.connections.slice(0,30).map((c,i)=>(
                      <div key={i} style={{padding:"5px 12px", borderTop:i>0?"1px solid #111120":"none", background:i%2===0?"#0A0A14":"#0C0C18", display:"flex", gap:8, alignItems:"center", fontSize:10}}>
                        <span style={{...MONO, color:"#4a8a8a", flex:1}}>{c.from.substring(0,30)}</span>
                        <span style={{color:c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#4CAF50":"#546E7A", fontSize:10}}>→</span>
                        <span style={{...MONO, color:"#6a8a6a", flex:1}}>{c.to.substring(0,30)}</span>
                        <span style={{fontSize:9, padding:"1px 5px", borderRadius:2,
                          background:c.kind==="explicit"?"#E5393522":c.kind==="module-input"?"#4CAF5022":"#54647422",
                          color:c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#4CAF50":"#78909C"
                        }}>{c.kind}</span>
                      </div>
                    ))}
                    {parseResult.connections.length>30&&<div style={{padding:"6px 12px",fontSize:10,color:"#444"}}>...and {parseResult.connections.length-30} more connections</div>}
                  </div>
                </div>
              </div>
            )}

            {/* XML */}
            {dfdTab==="xml" && xml && (
              <pre style={{margin:0, padding:"16px", background:"transparent", fontSize:10, lineHeight:1.7, ...MONO, whiteSpace:"pre-wrap", wordBreak:"break-all"}}>
                <code dangerouslySetInnerHTML={{__html:hlXml(xml)}}/>
              </pre>
            )}
            {dfdTab==="xml" && !xml && (
              <div style={{padding:"40px", textAlign:"center", color:"#333", fontSize:12}}>
                Upload .tf files first to generate XML
              </div>
            )}

            {/* GUIDE */}
            {dfdTab==="guide" && (
              <div style={{padding:"24px 28px", maxWidth:780}}>
                <div style={{fontSize:16, fontWeight:700, color:C.text, marginBottom:4}}>Import Guide</div>
                <div style={{fontSize:13, color:C.textSub, marginBottom:24}}>Step-by-step instructions for importing your generated DFD into diagramming tools</div>

                {/* Tool cards */}
                <div style={{display:"flex", flexDirection:"column", gap:14, marginBottom:28}}>
                  {[
                    {
                      name:"draw.io / diagrams.net", color:"#1E88E5", badge:"Recommended",
                      steps:[
                        "Click the ⬇ Download button in the top-right to save your .drawio file",
                        "Open app.diagrams.net in any browser (free, no account needed)",
                        "Drag and drop the .drawio file onto the canvas — or use File → Import From → Device",
                        "All tier swim lanes, nodes, and connection arrows are preserved automatically",
                        "Press Ctrl+Shift+H (Cmd+Shift+H on Mac) to fit the diagram to the window",
                      ]
                    },
                    {
                      name:"Lucidchart", color:"#FF7043", badge:null,
                      steps:[
                        "Download the .drawio file using the ⬇ Download button",
                        "In Lucidchart: File → Import → Diagrams.net (.drawio)",
                        "Full layout and tier swim lanes are preserved; nodes render as labeled boxes",
                      ]
                    },
                    {
                      name:"Microsoft Visio", color:"#2E7D32", badge:null,
                      steps:[
                        "Download the .drawio file",
                        "In draw.io, use File → Export As → Visio (.vsdx) to convert",
                        "Or install the Diagrams.net add-in for Visio from the Microsoft AppSource store",
                      ]
                    },
                  ].map((tool,ti)=>(
                    <div key={ti} style={{background:C.surface2, border:`1px solid ${tool.color}30`, borderLeft:`3px solid ${tool.color}`, borderRadius:8, overflow:"hidden"}}>
                      <div style={{padding:"12px 18px", borderBottom:`1px solid ${C.border}`, display:"flex", alignItems:"center", gap:10}}>
                        <span style={{fontSize:14, fontWeight:700, color:tool.color}}>{tool.name}</span>
                        {tool.badge && (
                          <span style={{fontSize:10, fontWeight:700, background:`${tool.color}20`, color:tool.color, border:`1px solid ${tool.color}44`, borderRadius:4, padding:"2px 8px"}}>{tool.badge}</span>
                        )}
                      </div>
                      <div style={{padding:"14px 18px", display:"flex", flexDirection:"column", gap:9}}>
                        {tool.steps.map((step,si)=>(
                          <div key={si} style={{display:"flex", gap:12, alignItems:"flex-start"}}>
                            <div style={{minWidth:22, height:22, borderRadius:"50%", background:`${tool.color}20`, border:`1px solid ${tool.color}44`, color:tool.color, fontSize:11, fontWeight:700, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0}}>{si+1}</div>
                            <span style={{fontSize:13, color:C.textSub, lineHeight:1.55, paddingTop:2}}>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Tier swim lane reference */}
                <div style={{marginBottom:24}}>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Tier Swim Lane Reference</div>
                  <div style={{display:"flex", flexDirection:"column", gap:6}}>
                    {[
                      {k:"xsphere",  desc:"Private cloud VMs, clusters, datastores, and virtual networks"},
                      {k:"org",      desc:"AWS Organizations, organizational units, accounts, and SCPs"},
                      {k:"security", desc:"IAM roles/policies, KMS keys, Secrets Manager, WAF, GuardDuty"},
                      {k:"cicd",     desc:"CodePipeline, CodeBuild, Terraform modules, Sentinel policy gates"},
                      {k:"network",  desc:"VPC, subnets, security groups, gateways, Transit GW, Direct Connect"},
                      {k:"compute",  desc:"EC2, Lambda, EKS, ECS, ALB, API Gateway, CloudFront, SQS, SNS"},
                      {k:"storage",  desc:"S3, RDS, DynamoDB, ElastiCache, EFS, EBS, Backup Vault"},
                    ].map(({k,desc})=>{
                      const t=TIERS[k]; if(!t)return null;
                      return (
                        <div key={k} style={{display:"flex", alignItems:"center", gap:14, padding:"9px 16px", background:C.surface2, border:`1px solid ${t.border}30`, borderLeft:`3px solid ${t.border}`, borderRadius:6}}>
                          <div style={{width:16, height:16, borderRadius:3, background:t.hdr, border:`1px solid ${t.border}60`, flexShrink:0}}/>
                          <span style={{color:t.border, fontWeight:700, fontSize:13, minWidth:200}}>{t.label}</span>
                          <span style={{color:C.textSub, fontSize:12}}>{desc}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Edge type reference */}
                <div>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Connection Type Reference</div>
                  <div style={{display:"flex", flexDirection:"column", gap:8}}>
                    {[
                      {c:"#78909C", dash:false, l:"Implicit reference",    d:"Resource attribute cross-reference (auto-detected from Terraform HCL body)"},
                      {c:"#E53935", dash:true,  l:"Explicit depends_on",   d:"Manually declared dependency via depends_on = [...]"},
                      {c:"#4CAF50", dash:false, l:"Module input / output", d:"Module input directly references a resource attribute or output"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:16, padding:"10px 16px", background:C.surface2, border:`1px solid ${C.border}`, borderRadius:6}}>
                        <svg width="50" height="14" style={{flexShrink:0}}>
                          <line x1="2" y1="7" x2="38" y2="7" stroke={e.c} strokeWidth="2" strokeDasharray={e.dash?"6 3":"none"}/>
                          <polygon points="36,4 50,7 36,10" fill={e.c}/>
                        </svg>
                        <span style={{fontSize:13, fontWeight:600, color:e.c, minWidth:160}}>{e.l}</span>
                        <span style={{fontSize:12, color:C.textMuted}}>{e.d}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* LEGEND */}
            {dfdTab==="legend" && (
              <div style={{padding:"24px 28px", maxWidth:960}}>
                <div style={{fontSize:16, fontWeight:700, color:C.text, marginBottom:4}}>DFD Resource Type Legend</div>
                <div style={{fontSize:13, color:C.textSub, marginBottom:20}}>All resource types mapped to infrastructure tiers — no emoji, color-coded by tier</div>

                {/* Tier color key */}
                <div style={{marginBottom:22}}>
                  <div style={{fontSize:11, fontWeight:700, color:C.accent, textTransform:"uppercase", letterSpacing:".1em", marginBottom:10}}>Tier Color Key</div>
                  <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
                    {Object.entries(TIERS).map(([k,t])=>(
                      <div key={k} style={{display:"flex", alignItems:"center", gap:8, padding:"7px 14px", background:C.surface2, border:`1px solid ${t.border}40`, borderLeft:`3px solid ${t.border}`, borderRadius:6}}>
                        <div style={{width:12, height:12, borderRadius:2, background:t.hdr, border:`1px solid ${t.border}60`, flexShrink:0}}/>
                        <span style={{color:t.border, fontWeight:600, fontSize:12}}>{t.label}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Resource types per tier */}
                <div style={{display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:24}}>
                  {Object.entries(TIERS).map(([tid, tmeta])=>{
                    const resInTier = Object.entries(RT).filter(([k,v])=>v.t===tid&&k!=="_default");
                    return (
                      <div key={tid} style={{background:C.surface2, border:`1px solid ${tmeta.border}30`, borderRadius:8, overflow:"hidden"}}>
                        <div style={{background:tmeta.hdr, padding:"8px 14px", fontSize:11, fontWeight:700, color:"#FFF", letterSpacing:".04em"}}>
                          {tmeta.label} <span style={{opacity:0.65, fontWeight:400}}>({resInTier.length})</span>
                        </div>
                        <div style={{padding:"10px 14px", display:"flex", flexDirection:"column", gap:5}}>
                          {resInTier.slice(0,14).map(([k,v])=>(
                            <div key={k} style={{display:"flex", gap:8, alignItems:"center"}}>
                              <div style={{width:10, height:10, borderRadius:2, background:v.c, border:`1px solid ${v.c}88`, flexShrink:0}}/>
                              <span style={{fontSize:12, color:C.text}}>{v.l}</span>
                              <span style={{fontSize:10, color:C.textMuted, ...MONO, marginLeft:"auto"}}>{k.replace(/^aws_|^xsphere_/,"").replace(/_/g,"_").substring(0,22)}</span>
                            </div>
                          ))}
                          {resInTier.length>14&&<div style={{fontSize:10,color:C.textMuted,marginTop:4}}>+{resInTier.length-14} more types</div>}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Connection types */}
                <div style={{marginBottom:16}}>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Connection Types</div>
                  <div style={{display:"flex", gap:10, flexWrap:"wrap"}}>
                    {[
                      {c:"#78909C", dash:false, l:"Implicit Reference",    d:"Auto-detected attribute cross-reference"},
                      {c:"#E53935", dash:true,  l:"Explicit depends_on",   d:"Manual depends_on = [...] declaration"},
                      {c:"#4CAF50", dash:false, l:"Module Input / Output", d:"Module input references resource attribute"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:14, padding:"12px 16px", background:C.surface2, border:`1px solid ${C.border}`, borderLeft:`3px solid ${e.c}`, borderRadius:8, flex:1, minWidth:220}}>
                        <svg width="44" height="14" style={{flexShrink:0}}>
                          <line x1="2" y1="7" x2="32" y2="7" stroke={e.c} strokeWidth="2" strokeDasharray={e.dash?"6 3":"none"}/>
                          <polygon points="30,4 44,7 30,10" fill={e.c}/>
                        </svg>
                        <div>
                          <div style={{fontSize:12, fontWeight:600, color:e.c}}>{e.l}</div>
                          <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{e.d}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Node types */}
                <div>
                  <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>Node Border Styles</div>
                  <div style={{display:"flex", gap:10, flexWrap:"wrap"}}>
                    {[
                      {fill:"#FFFFFF", stroke:"#546E7A", dash:false,  l:"AWS / xSphere Resource", d:"Standard managed resource"},
                      {fill:"#FAFFF5", stroke:"#558B2F", dash:true,   l:"Terraform Module",       d:"local / git / registry module"},
                      {fill:"#E3F2FD", stroke:"#1565C0", dash:true,   l:"Remote State Reference", d:"terraform_remote_state data source"},
                      {fill:"#FFF8E1", stroke:"#E65100", dash:false,  l:"Sentinel Policy Gate",   d:"Policy-as-code enforcement point"},
                    ].map(e=>(
                      <div key={e.l} style={{display:"flex", alignItems:"center", gap:12, padding:"10px 14px", background:C.surface2, border:`1px solid ${C.border}`, borderRadius:8, flex:1, minWidth:200}}>
                        <div style={{width:28, height:20, borderRadius:4, background:e.fill, border:`1.5px ${e.dash?"dashed":"solid"} ${e.stroke}`, flexShrink:0}}/>
                        <div>
                          <div style={{fontSize:12, fontWeight:600, color:C.text}}>{e.l}</div>
                          <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{e.d}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* THREATAFORM ANALYSIS */}
            {dfdTab==="analysis" && parseResult && (
              <AnalysisErrorBoundary>
                <AnalysisPanel parseResult={parseResult} files={files} userDocs={userDocs} scopeFiles={scopeFiles} onScopeChange={setScopeFiles}/>
              </AnalysisErrorBoundary>
            )}
            {dfdTab==="analysis" && !parseResult && (
              <div style={{height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:14,opacity:0.35,padding:40}}>
                <div style={{fontSize:48}}>🔬</div>
                <div style={{fontSize:14,letterSpacing:".1em",textAlign:"center"}}>Upload .tf files to generate<br/>your Threataform Analysis</div>
                <button onClick={()=>setMainTab("upload")} style={{background:"none",border:"1px solid #333",borderRadius:4,padding:"6px 16px",color:"#555",fontSize:11,cursor:"pointer"}}>Go to Upload →</button>
              </div>
            )}

            {/* Empty state */}
            {dfdTab==="stats" && !parseResult && (
              <div style={{height:"100%", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:14, opacity:0.3, padding:40}}>
                <div style={{fontSize:48}}>🗺</div>
                <div style={{fontSize:14, letterSpacing:".1em", textAlign:"center"}}>Upload .tf files to generate<br/>your enterprise DFD</div>
                <button onClick={()=>setMainTab("upload")} style={{background:"none",border:"1px solid #333",borderRadius:4,padding:"6px 16px",color:"#555",fontSize:11,cursor:"pointer"}}>Go to Upload →</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
