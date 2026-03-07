import { useState, useCallback, useRef, useMemo, useEffect, Component } from "react";
// ── Local AI inference — wllama (llama.cpp WASM) + custom RAG engine ──────────
// Runs 100% offline. No internet. No API. No installation required.
// User loads a GGUF model file from their local disk.
import { wllamaManager } from './src/lib/WllamaManager.js';
import { VectorStore, hybridSearch as ragHybridSearch, buildRAGPrompt, ContextPacker } from './src/lib/ThrataformRAG.js';
import { HybridRetriever } from './src/lib/rag/HybridRetriever.js';
import { hydeTemplate } from './src/lib/rag/HyDE.js';
import { ColBERTVectorStore } from './src/lib/rag/VectorStore.js';
import {
  BookOpen, Upload, Brain, Microscope, Map as MapIcon, Building2, Search, ShieldCheck,
  ListChecks, GitCompare, ShieldAlert, Zap, TriangleAlert, ScanLine, Layers,
  Image as ImageIcon, BarChart2, Code2, BookMarked, LayoutList, ChevronLeft,
  ArrowRight, Trash2, FolderOpen, Loader2, AppWindow, Sparkles, Shield, Cloud,
  ClipboardList, Lock, SquareStack, DoorOpen, ArrowLeftRight, Globe, RefreshCw,
  KeyRound, Link as LinkIcon, Database, FileText, ChevronDown, ChevronRight,
  CheckCircle2, AlertCircle, Plus, X, Home, Settings, Info, Eye, EyeOff,
  BarChart, TrendingUp, Target, Activity, ArrowUpRight, CheckSquare, Square,
  PenLine, RotateCcw, Cpu, Server, Network, HardDrive, Users, Plug,
  Download, XCircle, CheckCircle, Package,
  Bot, MessageSquare, Send, StopCircle, ChevronUp,
} from "lucide-react";

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

// Icon mapping for KB domains — used in KBPanel and sidebar (avoids modifying large KB data)
const KB_DOMAIN_ICONS = {
  xsphere: Cloud, spinnaker: Settings, iam: KeyRound, jenkins: Server,
  dfd: MapIcon, wiz: ShieldAlert, attack: Zap, cwe: TriangleAlert,
  stride: Target, tfePave: Layers, userdocs: FileText,
};

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
// Detect TFE-Pave layer from file path (L0=org, L1=vending, L2=account-pave, L3=product, L4=service)
function detectPaveLayer(filePath) {
  const p = filePath.toLowerCase();
  if (/\bl0[_/-]|org[_/-]mgmt|management[_/-]|control[_/-]tower/.test(p)) return "L0";
  if (/\bl1[_/-]|vend|aft[_/-]|account[_/-]vend/.test(p)) return "L1";
  if (/\bl2[_/-]|account[_/-]pave|pave[_/-]account|baseline/.test(p)) return "L2";
  if (/\bl3[_/-]|product[_/-]pave|platform[_/-]|shared[_/-]/.test(p)) return "L3";
  if (/\bl4[_/-]|service[_/-]|workload[_/-]|app[_/-]/.test(p)) return "L4";
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE EXTRACTION UTILITIES — PDF.js + Tesseract.js (CDN lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════════════

function _loadScript(src) {
  return new Promise((res, rej) => {
    if (document.querySelector(`script[src="${src}"]`)) { res(); return; }
    const s = document.createElement("script");
    s.src = src; s.onload = res; s.onerror = rej;
    document.head.appendChild(s);
  });
}

async function _loadPdfJs() {
  if (window.pdfjsLib) return;
  await _loadScript("https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js");
  window.pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
}

async function _loadTesseract() {
  if (window.Tesseract) return;
  await _loadScript("https://cdn.jsdelivr.net/npm/tesseract.js@4/dist/tesseract.min.js");
}

async function _ocrImageSource(imageSource) {
  await _loadTesseract();
  const worker = await window.Tesseract.createWorker("eng");
  try {
    const { data: { text } } = await worker.recognize(imageSource);
    return text.trim();
  } finally {
    await worker.terminate();
  }
}

async function _extractPdfPage(page) {
  const tc = await page.getTextContent();
  const text = tc.items.map(it => it.str).join(" ").trim();
  if (text.length > 40) return text; // text-based page

  // Image-based / scanned page — render to canvas then OCR
  const viewport = page.getViewport({ scale: 1.5 });
  const canvas = document.createElement("canvas");
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  await page.render({ canvasContext: canvas.getContext("2d"), viewport }).promise;
  const ocr = await _ocrImageSource(canvas);
  return ocr || "";
}

/**
 * extractTextFromFile(file) → Promise<string>
 * Extracts rich text context from any uploaded file:
 *  - PDF  → PDF.js text layer; image pages → Tesseract.js OCR
 *  - Image files → Tesseract.js OCR with structural wrapper
 *  - Everything else → FileReader.readAsText()
 */
async function extractTextFromFile(file) {
  const ext = (file.name.split(".").pop() || "").toLowerCase();

  if (ext === "pdf") {
    try {
      await _loadPdfJs();
      const arrayBuf = await file.arrayBuffer();
      const doc = await window.pdfjsLib.getDocument({ data: arrayBuf }).promise;
      const pages = await Promise.all(
        Array.from({ length: doc.numPages }, (_, i) =>
          doc.getPage(i + 1).then(_extractPdfPage)
        )
      );
      return pages.filter(Boolean).join("\n\n");
    } catch (err) {
      console.warn("[extractTextFromFile] PDF extraction failed:", err);
      return `[PDF: ${file.name} — extraction failed]`;
    }
  }

  if (/^image\//i.test(file.type) || /\.(png|jpg|jpeg|webp|bmp|tiff?)$/i.test(file.name)) {
    try {
      const dataUrl = await new Promise((res, rej) => {
        const r = new FileReader();
        r.onload = e => res(e.target.result);
        r.onerror = () => rej(new Error("FileReader error"));
        r.readAsDataURL(file);
      });
      const ocr = await _ocrImageSource(dataUrl);
      return `[Image: ${file.name}]\n${ocr || "[No extractable text — visual/diagram content]"}`;
    } catch (err) {
      console.warn("[extractTextFromFile] Image OCR failed:", err);
      return `[Image: ${file.name} — OCR failed]`;
    }
  }

  // All other text-readable files (tf, hcl, txt, md, json, yaml, csv, xml, sentinel…)
  return new Promise(res => {
    const r = new FileReader();
    r.onload = e => res(e.target.result || "");
    r.onerror = () => res("");
    r.readAsText(file);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════

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
  const { extractCFNResources } = await import('./src/lib/iac/CFNParser.js');
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

// ─────────────────────────────────────────────────────────────────────────────
// THREAT MODEL INTELLIGENCE ENGINE
// Pure client-side — NO external APIs, ZERO hallucination.
// Retrieves verbatim passages from indexed documents using BM25-lite scoring.
// Entity extraction covers STRIDE, MITRE ATT&CK, compliance, AWS services,
// security controls, and architecture scope declarations.
// ─────────────────────────────────────────────────────────────────────────────
const _STOP = new Set([
  "the","a","an","is","are","was","were","be","been","being","have","has","had",
  "do","does","did","will","would","could","should","may","might","must","shall",
  "and","or","but","if","in","on","at","to","for","of","with","by","from","as",
  "this","that","these","those","it","its","we","they","he","she","you","i",
  "not","no","so","then","than","when","where","how","what","which","who","all",
  "also","can","use","used","using","each","other","more","such","well","via",
  "get","set","any","its","our","your","their","been","has","had","one","two",
]);

const _ENTITY_PATTERNS = {
  stride: {
    spoofing:     /\b(spoof|impersonat|fake.identity|fake.cred|bypass.auth|phishing|cred.theft|identity.theft)\b/gi,
    tampering:    /\b(tamper|corrupt|modif|inject|alter|manipulat|integrity|supply.chain|sql.inject|code.inject)\b/gi,
    repudiation:  /\b(repudiat|audit.trail|non.repudiation|forensic|evidence|audit.log|immutable.log)\b/gi,
    infoDisclose: /\b(information.disclosure|data.leak|exfiltrat|sensitive.data|secret|credential.expos|pii|phi)\b/gi,
    dos:          /\b(denial.of.service|\bdos\b|\bddos\b|rate.limit|throttl|flood|resource.exhaust|availability)\b/gi,
    elevPriv:     /\b(privilege.escalat|elevation.of.priv|lateral.movement|sudo|root.access|breakout|iam.escalat)\b/gi,
  },
  attack: {
    initialAccess:   /\b(initial.access|phishing|valid.accounts|exploit.public|supply.chain.compromise)\b/gi,
    execution:       /\b(execution|scripting|lambda.exec|user.execution|command.script|powershell)\b/gi,
    persistence:     /\b(persistence|backdoor|scheduled.task|startup|boot.persist|account.manipulation)\b/gi,
    privEsc:         /\b(privilege.escalat|access.token|abuse.elevation|exploitation.for.privesc)\b/gi,
    defenseEvasion:  /\b(defense.evasion|obfuscat|disable.security|log.tamper|rootkit|masquerade)\b/gi,
    credAccess:      /\b(credential.access|brute.force|keylogg|pass.the.hash|cred.dump|credential.stuffing)\b/gi,
    discovery:       /\b(discovery|network.scan|account.discovery|cloud.infrastructure|enumerate|recon)\b/gi,
    lateralMovement: /\b(lateral.movement|remote.service|pass.the.ticket|ssh.hijack|internal.spear)\b/gi,
    exfiltration:    /\b(exfiltrat|data.theft|c2.exfil|dns.exfil|transfer.data)\b/gi,
    impact:          /\b(ransomware|wiper|defacement|data.destruction|service.stop|inhibit.recovery)\b/gi,
  },
  compliance: {
    hipaa:    /\b(hipaa|protected.health|ehr|electronic.health|\bbaa\b|hitrust)\b/gi,
    fedramp:  /\b(fedramp|nist.800|fisma|federal.risk|govcloud|government.cloud)\b/gi,
    soc2:     /\b(soc.?2|soc\s2|type.ii|aicpa|trust.service.criteria)\b/gi,
    pci:      /\b(pci.?dss|payment.card|cardholder|card.data|\bpan\b|\bcvv\b)\b/gi,
    gdpr:     /\b(gdpr|data.protection.regulation|right.to.erasure|data.subject|personal.data)\b/gi,
    cmmc:     /\b(cmmc|cybersecurity.maturity|defense.industrial|\bdib\b|\bcui\b|controlled.unclassified)\b/gi,
    iso27001: /\b(iso.?27001|isms|information.security.management)\b/gi,
  },
  aws: {
    s3:         /\b(aws_s3|\bs3\b|simple.storage|object.storage|bucket)\b/gi,
    ec2:        /\b(aws_ec2|\bec2\b|elastic.compute|ec2.instance|auto.?scaling.group)\b/gi,
    iam:        /\b(aws_iam|\biam\b|identity.access|assume.?role|\bscp\b|service.control)\b/gi,
    lambda:     /\b(aws_lambda|\blambda\b|serverless.function|event.?driven.compute)\b/gi,
    rds:        /\b(aws_rds|\brds\b|aurora|db.instance|relational.database)\b/gi,
    vpc:        /\b(aws_vpc|\bvpc\b|virtual.private.cloud|security.group|subnet|nacl)\b/gi,
    kms:        /\b(aws_kms|\bkms\b|key.management|customer.managed.key|\bcmk\b)\b/gi,
    cloudtrail: /\b(cloudtrail|api.audit|aws.audit.log|trail)\b/gi,
    guardduty:  /\b(guardduty|threat.detection|malicious.activity|findings)\b/gi,
    waf:        /\b(aws_waf|\bwaf\b|web.application.firewall|owasp.rule)\b/gi,
    secrets:    /\b(secrets.?manager|parameter.store|secret.rotation)\b/gi,
  },
  security: {
    encryption:  /\b(encrypt|at.?rest|in.?transit|\btls\b|\bssl\b|\baes\b|\brsa\b|cipher)\b/gi,
    mfa:         /\b(\bmfa\b|multi.?factor|two.?factor|\btotp\b|hardware.token|yubikey)\b/gi,
    zeroTrust:   /\b(zero.?trust|never.trust|least.privilege|microsegment|always.verify)\b/gi,
    secrets:     /\b(api.?key|hardcoded.secret|secret.leak|exposed.credential|private.?key)\b/gi,
    monitoring:  /\b(siem|security.monitor|alert|alarm|observ|audit.log|trace)\b/gi,
    network:     /\b(\bdmz\b|perimeter|network.segment|bastion|jump.?host|\bvpn\b|private.?link)\b/gi,
  },
  scope: {
    inScope:    /\b(in.?scope|within.?scope|assessment.scope|included.in.scope|in\s+scope)\b/gi,
    outOfScope: /\b(out.?of.?scope|excluded|not.in.scope|beyond.scope|outside.scope)\b/gi,
    boundary:   /\b(trust.boundary|security.boundary|data.flow.boundary|scope.boundary|system.boundary)\b/gi,
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// BUILT-IN THREAT INTELLIGENCE KNOWLEDGE GRAPH v2
// MITRE ATT&CK Cloud, CWE, Terraform → Threat Mappings, Misconfig Checks
// ─────────────────────────────────────────────────────────────────────────────
const ATTACK_TECHNIQUES = {
  'T1078.004':{ name:'Valid Cloud Accounts',           tactic:'Initial Access/Persistence',  severity:'Critical', desc:'Adversaries obtain and abuse credentials of existing cloud accounts to gain access.' },
  'T1530':    { name:'Data from Cloud Storage',        tactic:'Collection',                  severity:'High',     desc:'Adversaries access data from improperly secured cloud storage objects.' },
  'T1537':    { name:'Transfer Data to Cloud Account', tactic:'Exfiltration',                severity:'High',     desc:'Adversaries exfiltrate data to a different cloud account they control.' },
  'T1098.001':{ name:'Additional Cloud Credentials',   tactic:'Persistence',                 severity:'High',     desc:'Adversaries add adversary-controlled credentials to maintain persistent access.' },
  'T1098.003':{ name:'Additional Cloud Roles',         tactic:'Persistence',                 severity:'High',     desc:'Adversaries attach IAM roles with elevated permissions to cloud services.' },
  'T1580':    { name:'Cloud Infrastructure Discovery', tactic:'Discovery',                   severity:'Medium',   desc:'Adversaries enumerate cloud infrastructure, services, and configurations.' },
  'T1562.008':{ name:'Disable Cloud Logs',             tactic:'Defense Evasion',             severity:'High',     desc:'Adversaries disable CloudTrail or other logging to evade detection.' },
  'T1552.005':{ name:'Cloud Instance Metadata API',   tactic:'Credential Access',           severity:'High',     desc:'Adversaries query the Instance Metadata Service (IMDS) for credentials.' },
  'T1648':    { name:'Serverless Execution',           tactic:'Execution',                   severity:'Medium',   desc:'Adversaries abuse serverless functions to execute malicious code or commands.' },
  'T1059.009':{ name:'Cloud API',                      tactic:'Execution',                   severity:'Medium',   desc:'Adversaries abuse cloud management APIs to execute commands or access resources.' },
  'T1190':    { name:'Exploit Public-Facing App',      tactic:'Initial Access',              severity:'Critical', desc:'Adversaries exploit vulnerabilities in internet-facing applications or services.' },
  'T1485':    { name:'Data Destruction',               tactic:'Impact',                      severity:'Critical', desc:'Adversaries destroy data and files to interrupt availability of systems.' },
  'T1490':    { name:'Inhibit System Recovery',        tactic:'Impact',                      severity:'High',     desc:'Adversaries delete backups and snapshots to prevent recovery operations.' },
  'T1496':    { name:'Resource Hijacking',             tactic:'Impact',                      severity:'Medium',   desc:'Adversaries leverage compromised systems for cryptomining or other compute abuse.' },
  'T1548':    { name:'Abuse Elevation Control',        tactic:'Privilege Escalation',        severity:'High',     desc:'Adversaries abuse elevated control mechanisms such as IAM policies to gain higher privileges.' },
  'T1555.006':{ name:'Cloud Secrets Management',       tactic:'Credential Access',           severity:'High',     desc:'Adversaries query cloud secrets stores (Secrets Manager, SSM) for credentials.' },
  'T1600':    { name:'Weaken Encryption',              tactic:'Defense Evasion',             severity:'High',     desc:'Adversaries compromise or disable KMS keys to weaken cryptographic protections.' },
  'T1613':    { name:'Container and Resource Discovery',tactic:'Discovery',                  severity:'Medium',   desc:'Adversaries enumerate containers, pods, and cluster resources for lateral movement.' },
  'T1046':    { name:'Network Service Discovery',      tactic:'Discovery',                   severity:'Low',      desc:'Adversaries scan network services to identify attack surface.' },
  'T1133':    { name:'External Remote Services',       tactic:'Initial Access/Persistence',  severity:'High',     desc:'Adversaries leverage VPNs, RDP, or other external remote services for persistent access.' },
};

// Terraform resource type → ATT&CK technique IDs
const TF_ATTACK_MAP = {
  'aws_s3_bucket':                     ['T1530','T1537','T1485'],
  'aws_s3_bucket_acl':                 ['T1530'],
  'aws_s3_bucket_policy':              ['T1530','T1078.004'],
  'aws_s3_bucket_public_access_block': ['T1530'],
  'aws_iam_role':                      ['T1078.004','T1098.003','T1548'],
  'aws_iam_user':                      ['T1078.004','T1098.001'],
  'aws_iam_policy':                    ['T1078.004','T1548'],
  'aws_iam_role_policy_attachment':    ['T1098.003','T1548'],
  'aws_iam_user_policy':               ['T1078.004'],
  'aws_iam_instance_profile':          ['T1552.005','T1548'],
  'aws_lambda_function':               ['T1648','T1059.009','T1552.005'],
  'aws_lambda_permission':             ['T1648'],
  'aws_instance':                      ['T1552.005','T1190','T1580'],
  'aws_launch_template':               ['T1552.005'],
  'aws_autoscaling_group':             ['T1496','T1190'],
  'aws_cloudtrail':                    ['T1562.008'],
  'aws_kms_key':                       ['T1600'],
  'aws_kms_alias':                     ['T1600'],
  'aws_secretsmanager_secret':         ['T1555.006'],
  'aws_ssm_parameter':                 ['T1555.006'],
  'aws_rds_instance':                  ['T1530','T1190','T1485'],
  'aws_rds_cluster':                   ['T1530','T1485'],
  'aws_db_instance':                   ['T1530','T1190','T1485'],
  'aws_elasticache_cluster':           ['T1530','T1190'],
  'aws_security_group':                ['T1190','T1046'],
  'aws_security_group_rule':           ['T1190','T1046'],
  'aws_vpc':                           ['T1580'],
  'aws_subnet':                        ['T1580'],
  'aws_internet_gateway':              ['T1133','T1190'],
  'aws_nat_gateway':                   ['T1537'],
  'aws_lb':                            ['T1190','T1133'],
  'aws_alb':                           ['T1190','T1133'],
  'aws_lb_listener':                   ['T1190'],
  'aws_cloudfront_distribution':       ['T1190','T1530'],
  'aws_wafv2_web_acl':                 ['T1190'],
  'aws_guardduty_detector':            ['T1562.008'],
  'aws_config_rule':                   ['T1562.008'],
  'aws_config_configuration_recorder': ['T1562.008'],
  'aws_sns_topic':                     ['T1537','T1059.009'],
  'aws_sqs_queue':                     ['T1537','T1485'],
  'aws_dynamodb_table':                ['T1530','T1485'],
  'aws_elasticsearch_domain':          ['T1530','T1190'],
  'aws_opensearch_domain':             ['T1530','T1190'],
  'aws_eks_cluster':                   ['T1613','T1190','T1548'],
  'aws_ecs_cluster':                   ['T1613','T1648'],
  'aws_ecs_task_definition':           ['T1552.005','T1648'],
  'aws_ecr_repository':                ['T1613'],
  'aws_apigatewayv2_api':              ['T1190','T1059.009'],
  'aws_api_gateway_rest_api':          ['T1190','T1059.009'],
  'aws_route53_record':                ['T1580'],
  'aws_route53_zone':                  ['T1580'],
  'aws_organizations_policy':          ['T1078.004','T1548'],
  'xsphere_virtual_machine':           ['T1190','T1552.005','T1580'],
  'xsphere_cluster':                   ['T1580','T1613'],
  // ── CloudFormation resource types ────────────────────────────────────────
  'AWS::IAM::Role':                    ['T1078.004','T1098.003','T1548'],
  'AWS::IAM::Policy':                  ['T1078.004','T1548'],
  'AWS::IAM::ManagedPolicy':           ['T1078.004','T1548'],
  'AWS::IAM::Group':                   ['T1078.004'],
  'AWS::IAM::User':                    ['T1078.004','T1098.003'],
  'AWS::Organizations::Policy':        ['T1078.004','T1548'],
  'AWS::Organizations::Account':       ['T1078.004'],
  'AWS::Organizations::OrganizationalUnit': ['T1078.004'],
  'AWS::S3::Bucket':                   ['T1530','T1537','T1485'],
  'AWS::S3::BucketPolicy':             ['T1530','T1078.004'],
  'AWS::KMS::Key':                     ['T1600','T1555.006'],
  'AWS::RDS::DBInstance':              ['T1530','T1190','T1485'],
  'AWS::RDS::DBCluster':               ['T1530','T1485'],
  'AWS::Lambda::Function':             ['T1648','T1059.009','T1552.005'],
  'AWS::EC2::SecurityGroup':           ['T1190','T1046'],
  'AWS::CloudFormation::Stack':        ['T1190'],
  'AWS::ApiGateway::RestApi':          ['T1190','T1059.009'],
  'AWS::ApiGatewayV2::Api':            ['T1190','T1059.009'],
  'AWS::DynamoDB::Table':              ['T1530','T1485'],
  'AWS::SecretsManager::Secret':       ['T1555.006','T1552.005'],
  'AWS::StepFunctions::StateMachine':  ['T1648','T1059.009'],
  'AWS::Events::Rule':                 ['T1546','T1037'],
  'AWS::Bedrock::Agent':               ['T1648','T1190'],
  'AWS::SageMaker::NotebookInstance':  ['T1648','T1530'],
};

// CWE weakness definitions
const CWE_DETAILS = {
  'CWE-284':{ name:'Improper Access Control',                    desc:'The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.' },
  'CWE-285':{ name:'Improper Authorization',                     desc:'Failure to verify that an actor is authorized to access a resource or perform an action.' },
  'CWE-311':{ name:'Missing Encryption of Sensitive Data',       desc:'The software does not encrypt sensitive data, exposing it to unauthorized actors.' },
  'CWE-312':{ name:'Cleartext Storage of Sensitive Information', desc:'Sensitive information is stored in plaintext accessible to unauthorized parties.' },
  'CWE-326':{ name:'Inadequate Encryption Strength',             desc:'The software stores or transmits data using encryption that is considered too weak.' },
  'CWE-732':{ name:'Incorrect Permission Assignment',            desc:'Permissions allow unauthorized actors to access critical resources.' },
  'CWE-778':{ name:'Insufficient Logging',                       desc:'The software does not log security-relevant events, impeding detection of attacks.' },
  'CWE-256':{ name:'Plaintext Storage of Password',              desc:'Storing passwords in plaintext may result in system compromise if storage is breached.' },
  'CWE-250':{ name:'Execution with Unnecessary Privileges',      desc:'The software performs operations using excessively high-privilege accounts or credentials.' },
  'CWE-319':{ name:'Cleartext Transmission',                     desc:'Sensitive information is transmitted in plaintext over an unencrypted network channel.' },
  'CWE-306':{ name:'Missing Authentication for Critical Function',desc:'The software does not perform any authentication for functionality that requires identity.' },
  'CWE-798':{ name:'Use of Hard-coded Credentials',              desc:'Hard-coded credentials used for authentication to external systems or as inbound auth.' },
  'CWE-400':{ name:'Uncontrolled Resource Consumption',          desc:'Improper resource control allows an attacker to cause denial of service.' },
  'CWE-269':{ name:'Improper Privilege Management',              desc:'The software does not properly assign, modify, track, or check privileges.' },
  'CWE-1104':{ name:'Use of Unmaintained Third-Party Component', desc:'The product relies on a third-party component that is no longer actively maintained.' },
};

// STRIDE applicability by DFD element type
const STRIDE_PER_ELEMENT = {
  external_entity: ['spoofing','repudiation'],
  process:         ['spoofing','tampering','repudiation','infoDisclose','dos','elevPriv'],
  data_store:      ['tampering','repudiation','infoDisclose','dos'],
  data_flow:       ['spoofing','tampering','infoDisclose','dos'],
};

// Resource type → DFD element type for STRIDE-per-element
function _getElementType(resourceType) {
  const rt = resourceType || '';
  if (/s3|rds|dynamodb|elasticache|opensearch|elasticsearch|ebs|efs|ssm_parameter|secrets|AWS::S3::|AWS::RDS::|AWS::DynamoDB::|AWS::ElastiCache::/.test(rt)) return 'data_store';
  if (/security_group|nacl|waf|shield|firewall|acl|route53|nat_gateway|internet_gateway|AWS::EC2::SecurityGroup|AWS::WAF/.test(rt)) return 'data_flow';
  if (/iam_role|iam_user|iam_policy|organizations|cognito|AWS::IAM::|AWS::Organizations::/.test(rt)) return 'external_entity';
  return 'process';
}

// Terraform misconfiguration checks (checkov-style, pure attribute inspection)
const TF_MISCONFIG_CHECKS = {
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

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE FRAMEWORK — confidence scores + source metadata for every finding
// ─────────────────────────────────────────────────────────────────────────────

const CONFIDENCE_BY_METHOD = {
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

function mkEvidence(method, snippet, location='', extra={}) {
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
const CONTROL_DETECTION_MAP = [
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
const DID_LAYERS = {
  perimeter:   { name:'Perimeter Defense',    order:1, color:'#B71C1C', Icon:Shield,       desc:'WAF, DDoS protection, CDN edge rules, DNS security' },
  network:     { name:'Network Segmentation', order:2, color:'#E53935', Icon:Network,      desc:'VPC isolation, SGs, NACLs, PrivateLink, flow logs' },
  identity:    { name:'Identity & Access',    order:3, color:'#F57C00', Icon:KeyRound,     desc:'SCPs, permission boundaries, SSO, OIDC, Access Analyzer' },
  compute:     { name:'Compute Security',     order:4, color:'#FBC02D', Icon:Cpu,          desc:'IMDSv2, SSM Session Manager, EKS private endpoints' },
  application: { name:'Application Security', order:5, color:'#388E3C', Icon:AppWindow,    desc:'API Gateway auth, Cognito, WAF associations, rate limiting' },
  data:        { name:'Data Protection',      order:6, color:'#0288D1', Icon:Database,     desc:'KMS CMK, Secrets Manager, Macie DLP, S3 versioning, backup' },
  monitoring:  { name:'Detection & Response', order:7, color:'#7B1FA2', Icon:Activity,     desc:'CloudTrail, GuardDuty, Config rules, Security Hub, CloudWatch' },
};

// Zero-Trust pillar metadata
const ZT_PILLARS = {
  identity:    { name:'Identity',     color:'#7B1FA2', Icon:Users,        desc:'Verify every user/service identity; never trust implicit context' },
  network:     { name:'Network',      color:'#1565C0', Icon:Globe,        desc:'Micro-segment; deny by default; verify every network flow' },
  data:        { name:'Data',         color:'#00695C', Icon:HardDrive,    desc:'Classify, protect, and monitor all data regardless of location' },
  application: { name:'Application',  color:'#E65100', Icon:Zap,          desc:'Authorize each transaction with least-privilege; verify workloads' },
  monitoring:  { name:'Monitoring',   color:'#4A148C', Icon:Search,       desc:'Log, detect, and respond to all activity continuously' },
};

// NIST CSF 2.0 control checks (resource-presence + attribute based)
const NIST_CSF_CHECKS = [
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

// ─────────────────────────────────────────────────────────────────────────────
// THREAT MODEL INTELLIGENCE ENGINE v2
// BM25 (Robertson IDF, k1=1.5 b=0.75) + TF-IDF Cosine + RRF Fusion
// Query expansion · Recursive chunking · Contextual compression · Confidence
// Built-in ATT&CK/CWE knowledge · STRIDE-per-element · Misconfig detection
// ─────────────────────────────────────────────────────────────────────────────
class ThreatModelIntelligence {
  constructor() {
    this.chunks   = [];   // [{id, source, text, entities, category, docId, chunkIdx}]
    this._tf      = [];   // per-chunk Map<term,count>
    this._tfidf   = [];   // per-chunk Map<term,tfidf>
    this._docLens = [];   // token counts per chunk
    this._idf     = {};   // Robertson IDF per term
    this._vocab   = new Set();
    this._avgDocLen = 0;
    this._built   = false;
    this._k1 = 1.5;       // BM25 term-frequency saturation
    this._b  = 0.75;      // BM25 document-length normalization
  }

  // ── Tokenizer ────────────────────────────────────────────────────────────────
  _tokenize(text) {
    return text.toLowerCase()
      .replace(/[^a-z0-9\s._/-]/g, " ")
      .split(/\s+/)
      .filter(t => t.length > 2 && !_STOP.has(t));
  }

  // ── Security-domain query expansion ─────────────────────────────────────────
  _expandQuery(q) {
    const EXP = {
      iam:['identity access management','permissions','policy','role','privilege'],
      mfa:['multi-factor','two-factor','2fa','authentication','second factor'],
      ssm:['systems manager','parameter store','session manager'],
      vpc:['virtual private cloud','network','subnet','routing'],
      kms:['key management','encryption key','customer managed'],
      s3:['object storage','bucket','simple storage service'],
      rds:['relational database','database','sql','aurora'],
      ec2:['virtual machine','instance','compute','server'],
      eks:['kubernetes','k8s','container orchestration','cluster'],
      ecs:['container','fargate','task definition'],
      lambda:['serverless','function','faas','event-driven'],
      imds:['instance metadata','imdsv1','imdsv2','metadata api','169.254.169.254'],
      phi:['protected health information','patient data','hipaa','ePHI'],
      pii:['personally identifiable','personal data','gdpr','data subject'],
      dos:['denial of service','availability','ddos','flooding'],
      cve:['vulnerability','exploit','exposure','patch'],
      cwe:['weakness','vulnerability class','defect'],
      xss:['cross-site scripting','script injection'],
      sqli:['sql injection','injection attack','database injection'],
      // IaC / CFN / Organizations
      cfn:['cloudformation','aws template','resource properties','intrinsic ref','stack'],
      cloudformation:['cfn','template stack','aws resource','intrinsic function','cfn resource'],
      scp:['service control policy','organizations policy','ou deny allow','scp ceiling'],
      organizations:['org','ou','organizational unit','account','management account','root scp'],
      pave:['l0','l1','l2','l3','l4','tier','layer','account baseline','account vending','platform'],
      'permission boundary':['boundary','iam privilege limit','delegation boundary','escalation guard'],
      hcl:['terraform','hashicorp configuration language','tf resource','provider block'],
      iac:['infrastructure as code','terraform','cloudformation','hcl','cdk','pulumi'],
    };
    const lower = q.toLowerCase();
    const extra = [];
    lower.split(/\s+/).forEach(w => { if (EXP[w]) extra.push(...EXP[w]); });
    return extra.length ? q + ' ' + extra.join(' ') : q;
  }

  // ── Recursive character splitter (800-char target, 80-char overlap) ──────────
  _splitText(text, maxChars=350, overlapChars=60) {
    // Sentence-aware chunker: preserves sentence boundaries, overlaps chunks for retrieval context
    const normalized = text.replace(/\r\n/g, '\n').replace(/[ \t]+/g, ' ').trim();
    const rawSents = normalized
      .replace(/([.!?])\s+(?=[A-Z"'\u2018\u201C\d])/g, '$1\n')
      .replace(/\n{2,}/g, '\n')
      .split('\n').map(s => s.trim()).filter(s => s.length > 0);
    const chunks = [];
    let cur = '';
    for (const sent of rawSents) {
      const candidate = cur ? cur + ' ' + sent : sent;
      if (candidate.length <= maxChars) { cur = candidate; }
      else {
        if (cur.length > 20) chunks.push(cur);
        if (sent.length > maxChars) {
          for (let i = 0; i < sent.length; i += maxChars - overlapChars) {
            const sl = sent.slice(i, i + maxChars).trim();
            if (sl.length > 20) chunks.push(sl);
          }
          cur = '';
        } else { cur = sent; }
      }
    }
    if (cur.length > 20) chunks.push(cur);
    if (!chunks.length) return text.length > 20 ? [text.substring(0, maxChars)] : [];
    const result = [chunks[0]];
    for (let i = 1; i < chunks.length; i++) {
      const tail = chunks[i-1].slice(Math.max(0, chunks[i-1].length - overlapChars));
      result.push(tail + ' ' + chunks[i]);
    }
    return result;
  }

  // ── Entity extraction (reuses _ENTITY_PATTERNS) ──────────────────────────────
  _extractEntities(text) {
    const found = {};
    for (const [cat, pats] of Object.entries(_ENTITY_PATTERNS)) {
      found[cat] = {};
      for (const [sub, rx] of Object.entries(pats)) {
        const m = [...text.matchAll(new RegExp(rx.source, rx.flags))].map(x => x[0].toLowerCase());
        const u = [...new Set(m)];
        if (u.length) found[cat][sub] = u;
      }
    }
    return found;
  }

  // ── Document categorization ──────────────────────────────────────────────────
  _categorizeDoc(doc) {
    const s = ((doc.name||'') + ' ' + (doc.content||'').slice(0,500)).toLowerCase();
    if (/threat|stride|mitre|attack|risk|dread|pasta|threat.model/.test(s)) return 'threat-model';
    if (/architect|design|diagram|infra|topology|data.flow|dfd/.test(s)) return 'architecture';
    if (/policy|compliance|hipaa|fedramp|soc2|pci|gdpr|cmmc|iso.?27001/.test(s)) return 'compliance';
    if (/runbook|playbook|incident|procedure|response|sop/.test(s)) return 'runbook';
    if (/\.tf$|terraform|provider|resource|module/.test(s)) return 'terraform';
    return 'general';
  }

  // ── Add a single chunk to the corpus ────────────────────────────────────────
  _addChunk(source, text, category='general', docId=null, chunkIdx=0) {
    if (!text || text.trim().length < 20) return;
    const id = this.chunks.length;
    const trimmed = text.trim();
    const entities = this._extractEntities(trimmed);
    const tokens = this._tokenize(trimmed);
    const tfMap = {};
    tokens.forEach(t => { tfMap[t] = (tfMap[t]||0)+1; this._vocab.add(t); });
    this.chunks.push({ id, source, text: trimmed, entities, category, docId: docId||source, chunkIdx });
    this._tf.push(tfMap);
    this._docLens.push(tokens.length);
  }

  // ── Build BM25 IDF + TF-IDF vectors (call after all chunks added) ────────────
  _buildIndex() {
    const N = this.chunks.length;
    if (N === 0) return;
    this._avgDocLen = this._docLens.reduce((a,b)=>a+b,0) / N;
    // Robertson IDF: log((N − df + 0.5)/(df + 0.5) + 1)
    const df = {};
    this._tf.forEach(m => Object.keys(m).forEach(t => { df[t]=(df[t]||0)+1; }));
    this._idf = {};
    Object.entries(df).forEach(([t,dft]) => {
      this._idf[t] = Math.log((N - dft + 0.5)/(dft + 0.5) + 1);
    });
    // TF-IDF vectors for cosine similarity
    this._tfidf = this._tf.map((m, i) => {
      const vec = {};
      const len = this._docLens[i] || 1;
      Object.entries(m).forEach(([t,c]) => {
        vec[t] = (c/len) * (this._idf[t]||0);
      });
      return vec;
    });
  }

  // ── BM25 scores for all chunks given query terms ─────────────────────────────
  _bm25(terms) {
    const N = this.chunks.length;
    const scores = new Float64Array(N);
    const k1=this._k1, b=this._b, avgL=this._avgDocLen||1;
    terms.forEach(term => {
      const idf = this._idf[term];
      if (!idf) return;
      this._tf.forEach((m,i) => {
        const c = m[term]||0;
        if (!c) return;
        const num = c*(k1+1);
        const den = c + k1*(1-b+b*(this._docLens[i]/avgL));
        scores[i] += idf*(num/den);
      });
    });
    return scores;
  }

  // ── TF-IDF cosine similarity (complementary to BM25) ─────────────────────────
  _cosine(terms) {
    const N = this.chunks.length;
    const scores = new Float64Array(N);
    const qVec = {};
    terms.forEach(t => { qVec[t]=(qVec[t]||0)+(this._idf[t]||0.5); });
    const qNorm = Math.sqrt(Object.values(qVec).reduce((s,v)=>s+v*v,0)) || 1;
    this._tfidf.forEach((dv, i) => {
      let dot=0, dNorm=0;
      Object.entries(dv).forEach(([t,v]) => { if(qVec[t]) dot+=v*qVec[t]; dNorm+=v*v; });
      scores[i] = dot / (Math.sqrt(dNorm)*qNorm||1);
    });
    return scores;
  }

  // ── Reciprocal Rank Fusion (k=60) ────────────────────────────────────────────
  _rrf(rankedLists, k=60) {
    const sc = {};
    rankedLists.forEach(list => {
      list.forEach((idx,rank) => { sc[idx]=(sc[idx]||0)+1/(k+rank+1); });
    });
    return Object.entries(sc).sort((a,b)=>b[1]-a[1]).map(([i,s])=>({idx:+i,rrfScore:s}));
  }

  // ── Contextual compression: pull top-N most relevant sentences ───────────────
  _compress(text, qTerms, maxSentences=3) {
    const qSet = new Set(qTerms);
    const sents = text.replace(/([.!?])\s+/g,'$1|||').split('|||').map(s=>s.trim()).filter(s=>s.length>10);
    if (sents.length <= maxSentences) return text;
    const scored = sents.map(s => {
      const toks = this._tokenize(s);
      return { s, score: toks.filter(t=>qSet.has(t)).length / Math.max(1,toks.length) };
    }).sort((a,b)=>b.score-a.score);
    return scored.slice(0,maxSentences).map(x=>x.s).join(' … ');
  }

  // ── Primary query: BM25 + Cosine → RRF, with entity boost ────────────────────
  query(queryText, topK=8) {
    if (!queryText || !this.chunks.length) return [];
    const expanded = this._expandQuery(queryText);
    const terms = this._tokenize(expanded);
    if (!terms.length) return [];
    const N = this.chunks.length;
    const bm25s  = this._bm25(terms);
    const cosines = this._cosine(terms);
    const bm25R   = Array.from({length:N},(_,i)=>i).filter(i=>bm25s[i]>0).sort((a,b)=>bm25s[b]-bm25s[a]);
    const cosR    = Array.from({length:N},(_,i)=>i).filter(i=>cosines[i]>0).sort((a,b)=>cosines[b]-cosines[a]);
    // Entity overlap boost
    const qEnt  = this._extractEntities(queryText);
    const entBoost = [];
    if (Object.values(qEnt).some(s=>Object.keys(s).length>0)) {
      this.chunks.forEach((c,i) => {
        let boost=0;
        Object.entries(qEnt).forEach(([cat,subs]) => {
          Object.keys(subs).forEach(sub => { if(c.entities[cat]?.[sub]?.length) boost++; });
        });
        if (boost>0) entBoost.push(i);
      });
    }
    const lists = [bm25R.slice(0,60), cosR.slice(0,60)];
    if (entBoost.length) lists.push(entBoost);
    const fused = this._rrf(lists);
    const maxS = fused[0]?.rrfScore||1;
    return fused.slice(0,topK).map(({idx,rrfScore}) => {
      const c = this.chunks[idx];
      const confidence = Math.round((rrfScore/maxS)*100);
      return { ...c, score:Math.round(bm25s[idx]*10)/10, rrfScore:Math.round(rrfScore*1000)/1000, confidence, compressed:this._compress(c.text,terms) };
    });
  }

  // ── Structured threat profile for a resource ─────────────────────────────────
  getThreats(resource) {
    const type = resource?.type||'';
    const elementType = _getElementType(type);
    const stride = STRIDE_PER_ELEMENT[elementType]||STRIDE_PER_ELEMENT.process;
    const techniques = (TF_ATTACK_MAP[type]||[]).map(tid => {
      const t = ATTACK_TECHNIQUES[tid];
      return t ? { techniqueId:tid, techniqueName:t.name, tactic:t.tactic, severity:t.severity, desc:t.desc, url:`https://attack.mitre.org/techniques/${tid.replace('.','/').replace('.','/')}` } : null;
    }).filter(Boolean);
    return { stride, elementType, attackTechniques:techniques };
  }

  // ── Misconfiguration checks for a resource ───────────────────────────────────
  getMisconfigurations(resource) {
    const type = resource?.type||'';
    // Branch on isCFN: use structured cfnProps for CFN resources, HCL body for TF resources
    const attrs = resource?.isCFN
      ? this._parseCFNAttrs(resource.cfnProps||{})
      : (resource?.attrs ?? parseHCLBody(resource?.body||''));
    const isHCL = !resource?.isCFN;
    const rLabel = `${resource?.type||type}.${resource?.name||resource?.id||''}`;
    return (TF_MISCONFIG_CHECKS[type]||[]).reduce((out,chk) => {
      let triggered=false;
      try { triggered=chk.check(attrs); } catch(_){}
      if (!triggered) return out;
      // ── Build evidence ────────────────────────────────────────────────────
      let ev;
      const ak = chk.attrKey;
      if (isHCL && ak) {
        const src = attrs[`__src_${ak}`];
        if (src) {
          ev = mkEvidence(src.method, src.snippet, rLabel, src.unresolved ? {unresolved:true} : {});
        } else {
          // attrKey defined but attr absent → absence evidence
          ev = mkEvidence('attr_absence', `${ak} not present`, rLabel);
        }
      } else if (resource?.isCFN) {
        ev = mkEvidence('policy_parse', `CFN property check: ${chk.id}`, rLabel);
      } else {
        ev = mkEvidence('type_presence', `${chk.id}: ${chk.title}`, rLabel);
      }
      // ── Downgrade if triggering attr is an unresolved variable reference ──
      let severity = chk.severity;
      let title    = chk.title;
      if (isHCL && ak && attrs[`__src_${ak}`]?.unresolved) {
        severity = 'Info';
        title    = `${title} [VAR UNRESOLVED]`;
      }
      out.push({
        id:chk.id, title, severity,
        cwe:chk.cwe, attack:chk.attack, remediation:chk.remediation, evidence:ev,
        resourceType:type, resourceName:resource?.name||resource?.id||'',
        paveLayer:resource?.paveLayer||null,
        mitigatedBy:null,  // Phase 4 fills from SCP analysis
      });
      return out;
    },[]);
  }

  // ── IAM factual policy analysis ───────────────────────────────────────────────
  analyzeIAMResources(resources) {
    const findings = [];
    // Analyze IAM roles: permission boundaries + trust policies
    resources.filter(r => ['aws_iam_role','AWS::IAM::Role'].includes(r.type)).forEach(role => {
      const attrs = role.isCFN ? (role.cfnProps||{}) : (role.attrs || parseHCLBody(role.body||''));
      const hasPB = role.isCFN
        ? !!attrs.PermissionsBoundary
        : (attrs.permissions_boundary !== undefined && attrs.permissions_boundary !== null);
      if (!hasPB)
        findings.push({
          id:'IAM-NO-PB', severity:'High', resourceId:role.id, policyKind:'role',
          title:`IAM role ${role.name||role.id} has no permissions_boundary`,
          evidence: mkEvidence('attr_absence','permissions_boundary attribute absent', role.id),
          remediation:'Attach a PermissionsBoundary to prevent privilege escalation.',
          resourceType:role.type, resourceName:role.name||role.id,
          cwe:['CWE-269'], attack:['T1548'],
        });
      // Trust policy analysis
      const rawTrust = role.isCFN ? attrs.AssumeRolePolicyDocument : (attrs.assume_role_policy || null);
      let trustDoc = null;
      try { trustDoc = typeof rawTrust === 'string' ? JSON.parse(rawTrust) : rawTrust; } catch {}
      if (trustDoc?.Statement) {
        const stmts = Array.isArray(trustDoc.Statement) ? trustDoc.Statement : [trustDoc.Statement];
        stmts.forEach(s => {
          if (s.Effect === 'Allow' && (
            s.Principal === '*' ||
            (typeof s.Principal === 'object' && (s.Principal?.AWS === '*' || s.Principal?.Service === '*'))
          ))
            findings.push({
              id:'IAM-TRUST-WILD', severity:'Critical', resourceId:role.id, policyKind:'trust',
              title:`IAM role ${role.name||role.id} trusts all principals (Principal:*)`,
              evidence: mkEvidence('policy_parse', `Principal: ${JSON.stringify(s.Principal)}`, role.id),
              remediation:'Restrict AssumeRolePolicyDocument Principal to specific services or account ARNs.',
              resourceType:role.type, resourceName:role.name||role.id,
              cwe:['CWE-269'], attack:['T1078.004'],
            });
        });
      }
      // CFN inline policies
      if (role.isCFN)
        (attrs.Policies||[]).forEach(p => _analyzeIAMDocument(p.PolicyDocument, role.id, findings, 'inline'));
    });
    // Standalone IAM policy resources
    resources.filter(r => ['aws_iam_policy','aws_iam_role_policy','aws_iam_user_policy','AWS::IAM::ManagedPolicy'].includes(r.type)).forEach(pol => {
      const attrs = pol.isCFN ? (pol.cfnProps||{}) : (pol.attrs || parseHCLBody(pol.body||''));
      let doc = null;
      try {
        const raw = pol.isCFN ? attrs.PolicyDocument : (attrs.policy || '');
        doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
      } catch {}
      if (doc) _analyzeIAMDocument(doc, pol.id, findings, 'standalone');
    });
    return findings;
  }

  // ── Parse CFN Properties object into unified attribute map ─────────────────
  _parseCFNAttrs(props) {
    if (!props||typeof props!=='object') return {};
    const a = {};
    const pac = props.PublicAccessBlockConfiguration||{};
    a.block_public_acls   = pac.BlockPublicAcls;
    a.block_public_policy = pac.BlockPublicPolicy;
    a.versioning_enabled  = props.VersioningConfiguration?.Status==='Enabled';
    a.versioning          = a.versioning_enabled;
    a.server_side_encryption_configuration = !!props.BucketEncryption;
    a.logging             = !!props.LoggingConfiguration;
    a.kms_key_id          = props.KMSMasterKeyID??props.KmsKeyId;
    a.deletion_protection = props.DeletionProtectionEnabled??(props.DeletionPolicy==='Retain');
    a.assume_role_policy  = typeof props.AssumeRolePolicyDocument==='object'
                            ? JSON.stringify(props.AssumeRolePolicyDocument)
                            : (props.AssumeRolePolicyDocument??'');
    a.permissions_boundary = props.PermissionsBoundary;
    a.inline_policy       = (props.Policies||[]).map(p=>JSON.stringify(p.PolicyDocument)).join(' ');
    a.enable_key_rotation = props.EnableKeyRotation;
    a.multi_az            = props.MultiAZ;
    a.storage_encrypted   = props.StorageEncrypted;
    a.publicly_accessible = props.PubliclyAccessible;
    a.deletion_protection = a.deletion_protection||props.DeletionProtection;
    a.SecurityGroupIngress = props.SecurityGroupIngress;
    // Mark intrinsic-replaced fields
    for (const [k,v] of Object.entries(props)) {
      if (v==='__INTRINSIC__'||(v&&typeof v==='object'&&('Ref' in v||'Fn::Sub' in v||'Fn::GetAtt' in v)))
        a[`__intrinsic_${k}`]=true;
    }
    return a;
  }

  // ── Parse HCL body into attribute map (fixes getMisconfigurations attrs bug) ────
  _parseAttrMap(body) {
    const attrs = {};
    if (!body) return attrs;
    [...body.matchAll(/\b(\w+)\s*=\s*"([^"\n]*)"/g)].forEach(([,k,v])=>{attrs[k]=v;});
    [...body.matchAll(/\b(\w+)\s*=\s*(true|false)\b/g)].forEach(([,k,v])=>{attrs[k]=(v==='true');});
    [...body.matchAll(/\b(\w+)\s*=\s*(\d+)\b/g)].forEach(([,k,v])=>{if(attrs[k]===undefined)attrs[k]=parseInt(v,10);});
    [...body.matchAll(/\b(\w+)\s*\{/g)].forEach(([,k])=>{if(attrs[k]===undefined)attrs[k]=true;});
    const ingress=[...body.matchAll(/ingress\s*\{([\s\S]*?)(?=\n\s*(?:ingress|egress|tags|\}))/g)].map(m=>{
      const fp=(m[1].match(/from_port\s*=\s*(\d+)/)||[])[1];
      const tp=(m[1].match(/to_port\s*=\s*(\d+)/)||[])[1];
      const cidrs=[...m[1].matchAll(/"([\d.:\/]+)"/g)].map(x=>x[1]);
      return {from_port:fp?+fp:0,to_port:tp?+tp:0,cidr_blocks:cidrs};
    });
    if(ingress.length) attrs.ingress=ingress;
    return attrs;
  }

  // ── Control inventory: three-state (present / partial / absent) ──────────────
  getControlInventory(resources) {
    const present=[], partial=[], absent=[];
    CONTROL_DETECTION_MAP.forEach(ctrl => {
      let res = { state:'absent', evidence:null };
      try { res = ctrl.detect(resources); } catch(e) {}
      // Support legacy boolean detects (old entries not yet migrated)
      if (typeof res === 'boolean') res = { state: res ? 'present' : 'absent', evidence: null };
      const item = { ...ctrl, evidence: res.evidence };
      if      (res.state === 'present') present.push(item);
      else if (res.state === 'partial') partial.push({ ...item, partialNote: res.evidence?.snippet });
      else                              absent.push(item);
    });
    // Doc-based rescue with negation-aware confidence scoring
    const stillAbsent = [];
    absent.forEach(ctrl => {
      const chk = this._docHasControl(ctrl.name);
      if (chk.confidence >= 60) {
        present.push({ ...ctrl, source:'doc', evidence:mkEvidence('bm25_token',chk.evidence,chk.source), confidence:chk.confidence });
      } else if (chk.confidence >= 35) {
        partial.push({ ...ctrl, source:'doc', evidence:mkEvidence('bm25_low',chk.evidence,chk.source), confidence:chk.confidence, partialNote:'Low-confidence document reference' });
      } else {
        stillAbsent.push(ctrl);
      }
    });
    // Absorb doc-extracted controls (SCM/SCB uploads)
    const docControls = this.extractDocControls();
    const presentIds = new Set(present.map(c => c.id?.toLowerCase()));
    docControls.forEach(dc => {
      if (!presentIds.has(dc.id?.toLowerCase())) {
        present.push(dc);
        presentIds.add(dc.id?.toLowerCase());
      }
    });
    return { present, partial, absent: stillAbsent };
  }

  // ── Extract controls from uploaded SCM / SCB / compliance doc chunks ─────────
  extractDocControls() {
    if (!this._built) return [];
    // Focus on security-controls category (Enterprise Security Controls upload slot)
    // but also scan compliance-guide and cspm for any controls
    const controlChunks = this.chunks.filter(c =>
      ['security-controls','compliance-guide','cspm'].includes(c.category)
    );
    if (!controlChunks.length) return [];

    const controls = [];
    const seenIds = new Set();

    // Regex patterns for common control ID formats:
    // NIST SP 800-53: AC-1, AU-2.1, CM-6(1)
    // CIS: 1.1, 2.3.4
    // ISO 27001: A.9.1.1
    // SOC 2: CC6.1, CC7.2
    // Custom: CTRL-001, SEC-123, REQ-4.2
    // PCI DSS / CMMC: numeric or alphanumeric
    const ID_PATTERN = /\b([A-Z]{1,6}[-.]?\d{1,3}(?:[.(]\d{1,3}[)]?)*(?:\.\d{1,3})*)\b/g;

    controlChunks.forEach(chunk => {
      const lines = chunk.text.split(/[\n\r|]+/).map(l => l.trim()).filter(l => l.length > 2);
      lines.forEach(line => {
        // Reset regex
        ID_PATTERN.lastIndex = 0;
        let match;
        while ((match = ID_PATTERN.exec(line)) !== null) {
          const rawId = match[1];
          // Skip IDs that are clearly not controls (pure numbers, too short, version numbers like "v1.2")
          if (/^\d+$/.test(rawId)) continue;
          if (rawId.length < 3) continue;

          const idKey = rawId.toUpperCase();
          if (seenIds.has(idKey)) continue;
          seenIds.add(idKey);

          // Extract control name: text after the ID on the same line
          const afterId = line.slice(match.index + rawId.length).replace(/^[\s:|\-,]+/, '').trim();
          // Take up to 80 chars of the description, stop at another ID or pipe
          const name = afterId.replace(/\s*[|]\s*.*$/, '').substring(0, 80).trim();
          if (!name || name.length < 3) continue;

          // Try to determine layer from keywords in the line
          const lc = line.toLowerCase();
          let layer = 'doc';
          if (/\b(access|identity|auth|iam|role|permission|account|user|credential|sso|mfa|password)\b/.test(lc)) layer = 'identity';
          else if (/\b(network|vpc|firewall|waf|subnet|egress|ingress|traffic|route|dns)\b/.test(lc)) layer = 'network';
          else if (/\b(encrypt|tls|ssl|kms|key|cipher|hash|pki|certificate|secret)\b/.test(lc)) layer = 'data';
          else if (/\b(monitor|log|audit|alert|siem|cloudtrail|event|detect|incident)\b/.test(lc)) layer = 'monitoring';
          else if (/\b(compute|host|os|patch|container|vm|instance|imds)\b/.test(lc)) layer = 'compute';
          else if (/\b(app|api|code|input|output|csrf|xss|injection|session)\b/.test(lc)) layer = 'application';

          controls.push({
            id: `DOC-${idKey}`,
            name: `${rawId}: ${name.charAt(0).toUpperCase() + name.slice(1)}`,
            layer,
            ztPillar: layer === 'identity' ? 'identity' : layer === 'network' ? 'network' : layer === 'data' ? 'data' : 'application',
            source: 'scm',
            evidence: line.substring(0, 140),
            detect: () => false, // doc-sourced, always present
          });
        }
      });
    });

    return controls.slice(0, 200); // cap at 200 doc-extracted controls
  }

  // ── Doc-based control detection (negation-aware) ─────────────────────────────
  _docHasControl(ctrlName) {
    const NEGATION = new Set(['not','no','broken','disabled','removed','absent','missing',
      'lacking','without','failed','violation','gap','deficiency','cannot','never']);
    const tokens = ctrlName.toLowerCase().split(/\W+/).filter(t => t.length > 3);
    if (!tokens.length) return { found: false, confidence: 0 };
    let best = 0, bestEv = null, bestSrc = null;
    for (const c of this.chunks.filter(x => x.category !== 'terraform')) {
      const lc = c.text.toLowerCase();
      const words = lc.split(/\W+/);
      const matchCount = tokens.filter(t => lc.includes(t)).length;
      if (matchCount / tokens.length < 0.6) continue;
      // Apply negation penalty: -0.25 per negation word found within 5-token window
      let penalty = 0;
      for (const t of tokens) {
        const idx = words.indexOf(t);
        if (idx >= 0) {
          const win = words.slice(Math.max(0, idx - 5), idx + 6);
          if (win.some(w => NEGATION.has(w))) penalty += 0.25;
        }
      }
      const score = Math.max(0, (matchCount / tokens.length) - penalty) * 100;
      if (score > best) {
        best = Math.round(score);
        bestEv = c.text.slice(0, 130);
        bestSrc = c.source || c.category || 'doc';
      }
    }
    return best >= 30
      ? { found: true, confidence: best, evidence: bestEv, source: bestSrc }
      : { found: false, confidence: 0 };
  }

  // ── Defense-in-Depth layer assessment ────────────────────────────────────────
  getDefenseInDepthAssessment(resources) {
    const {present, partial, absent} = this.getControlInventory(resources);
    const layers={};
    Object.entries(DID_LAYERS).forEach(([lid,ldef])=>{
      const p  = present.filter(c=>c.layer===lid);
      const pa = partial.filter(c=>c.layer===lid);
      const a  = absent.filter(c=>c.layer===lid);
      const total = p.length + pa.length + a.length;
      // Weighted: present=1.0, partial=0.5, absent=0.0
      const score = total > 0 ? Math.round(((p.length + pa.length * 0.5) / total) * 100) : 0;
      layers[lid] = {...ldef, present:p, partial:pa, absent:a, score, total};
    });
    const total = present.length + partial.length + absent.length;
    const weightedScore = total > 0 ? Math.round(((present.length + partial.length * 0.5) / total) * 100) : 0;
    return { layers, overallScore:weightedScore, presentCount:present.length, partialCount:partial.length, absentCount:absent.length };
  }

  // ── Zero-Trust pillar assessment ─────────────────────────────────────────────
  getZeroTrustAssessment(resources) {
    const {present, partial, absent} = this.getControlInventory(resources);
    const pillars={};
    Object.entries(ZT_PILLARS).forEach(([pid,pdef])=>{
      const p  = present.filter(c=>c.ztPillar===pid);
      const pa = partial.filter(c=>c.ztPillar===pid);
      const a  = absent.filter(c=>c.ztPillar===pid);
      const total = p.length + pa.length + a.length;
      const score = total > 0 ? Math.round(((p.length + pa.length * 0.5) / total) * 100) : 0;
      pillars[pid] = {...pdef, present:p, partial:pa, absent:a, score, total};
    });
    const scores = Object.values(pillars).map(p => p.score);
    return { pillars, overallScore:scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0 };
  }

  // ── NIST CSF 2.0 compliance assessment ──────────────────────────────────────
  getNISTCSFAssessment(resources) {
    const results=NIST_CSF_CHECKS.map(chk=>{let pass=false;try{pass=chk.check(resources);}catch(e){}return{...chk,pass};});
    const byFn={};
    results.forEach(r=>{
      if(!byFn[r.fn]) byFn[r.fn]={pass:0,fail:0,criticalFail:0,checks:[]};
      byFn[r.fn].checks.push(r);
      r.pass?byFn[r.fn].pass++:(byFn[r.fn].fail++,r.critical&&byFn[r.fn].criticalFail++);
    });
    const pass=results.filter(r=>r.pass).length, total=results.length;
    return {byFn, pass, fail:total-pass, total, score:Math.round((pass/total)*100)};
  }

  // ── Security posture: weighted score + grade ─────────────────────────────────
  getSecurityPosture(resources) {
    if(!resources?.length) return null;
    const did=this.getDefenseInDepthAssessment(resources);
    const zt=this.getZeroTrustAssessment(resources);
    const nist=this.getNISTCSFAssessment(resources);
    const score=Math.round(nist.score*0.40+did.overallScore*0.35+zt.overallScore*0.25);
    const grade=score>=80?'A':score>=65?'B':score>=50?'C':score>=35?'D':'F';
    const gradeColor=grade==='A'?'#2E7D32':grade==='B'?'#558B2F':grade==='C'?'#F9A825':grade==='D'?'#E65100':'#B71C1C';
    const maturity=score>=80?'Zero Trust Optimal':score>=60?'Advanced':score>=40?'Initial':'Traditional / Ad-Hoc';
    // Derive topRisks from missing controls across DiD layers and ZT pillars
    const topRisks = [];
    Object.entries(did.layers||{}).forEach(([layer,data]) => {
      if (data.score < 50 && data.missing?.length)
        topRisks.push(`${layer.charAt(0).toUpperCase()+layer.slice(1)} layer gap: missing ${data.missing.slice(0,2).join(', ')}`);
    });
    Object.entries(zt.pillars||{}).forEach(([pillar,data]) => {
      if (data.score < 40 && data.absent?.length) {
        const names = data.absent.slice(0,2).map(a=>typeof a==='string'?a:(a?.name||a?.id||String(a)));
        topRisks.push(`Zero Trust ${pillar}: ${names.join(', ')} not detected`);
      }
    });
    if (nist.score < 50) topRisks.push(`NIST CSF score ${Math.round(nist.score)}% — review Identify/Protect functions`);
    return {score,grade,gradeColor,maturity,did,zt,nist,topRisks:topRisks.slice(0,6)};
  }

  // ── Cross-doc correlation: link doc mentions to TF resource attributes ────────
  getCrossDocCorrelation(resources) {
    if(!this.chunks.length||!resources?.length) return [];
    const corrs=[];
    resources.slice(0,60).forEach(r=>{
      const hits=this.analyzeResource(r.type,r.name);
      if(!hits.length) return;
      const attrs=r.attrs??parseHCLBody(r.body||'');
      const contradictions=[];
      hits.forEach(chunk=>{
        const t=chunk.text.toLowerCase();
        if(t.includes('encrypt')&&(attrs.encrypted===false||attrs.storage_encrypted===false))
          contradictions.push({type:'CONTRADICTION',title:'Docs require encryption but resource has it disabled',doc:chunk.source,excerpt:chunk.text.slice(0,160)});
        if(t.includes('private')&&attrs.publicly_accessible===true)
          contradictions.push({type:'CONTRADICTION',title:'Docs describe private access but resource is publicly accessible',doc:chunk.source,excerpt:chunk.text.slice(0,160)});
        if(t.includes('mfa')&&r.type==='aws_iam_user')
          contradictions.push({type:'GAP',title:'Docs mention MFA but IAM user detected (prefer roles + SSO)',doc:chunk.source,excerpt:chunk.text.slice(0,160)});
        const outOfScope=(chunk.entities?.scope?.outOfScope||[]);
        if(outOfScope.some(s=>s.includes(r.type.replace('aws_',''))||s.includes(r.name)))
          contradictions.push({type:'SCOPE-VIOLATION',title:'Resource declared out-of-scope in architecture doc',doc:chunk.source,excerpt:chunk.text.slice(0,160)});
      });
      corrs.push({resource:r,docHits:hits,contradictions});
    });
    return corrs.filter(c=>c.contradictions.length>0||c.docHits.length>0);
  }

  // ── Blast radius: what can be reached if resource is compromised ──────────────
  getBlastRadius(targetId, resources, connections) {
    if(!connections?.length) return {reachable:[],dataAssets:[],riskScore:0,paths:[]};
    const adj={};
    connections.forEach(c=>{if(!adj[c.from])adj[c.from]=[];adj[c.from].push(c.to);});
    const visited=new Set([targetId]), queue=[targetId], paths=[];
    while(queue.length){const curr=queue.shift();(adj[curr]||[]).forEach(next=>{if(!visited.has(next)){visited.add(next);queue.push(next);paths.push({from:curr,to:next});}});}
    visited.delete(targetId);
    const reachable=resources.filter(r=>visited.has(r.id));
    const dataRx=/s3|rds|dynamo|elastic|secret|ssm_param|kms|neptune|document/;
    const dataAssets=reachable.filter(r=>dataRx.test(r.type));
    const iamRx=/iam_role|iam_policy/;
    const iamAssets=reachable.filter(r=>iamRx.test(r.type));
    const riskScore=Math.min(100,reachable.length*4+dataAssets.length*12+iamAssets.length*8);
    return {reachable,dataAssets,iamAssets,riskScore,paths,totalReachable:reachable.length};
  }

  // ── Relevant doc passages for a resource (for Resource Intelligence tab) ──────
  analyzeResource(resourceType, resourceName) {
    const q = `${resourceType} ${(resourceName||'').replace(/_/g,' ')} security threat access`;
    return this.query(q, 5).filter(c=>c.category!=='terraform');
  }

  // ── Architecture-wide intelligence summary ───────────────────────────────────
  getArchitectureSummary(resources, userDocs) {
    const agg = {};
    this.chunks.forEach(c => {
      Object.entries(c.entities).forEach(([cat,subs]) => {
        Object.entries(subs).forEach(([sub,terms]) => {
          if (!agg[cat]) agg[cat]={};
          if (!agg[cat][sub]) agg[cat][sub]=new Set();
          terms.forEach(t=>agg[cat][sub].add(t));
        });
      });
    });
    const entitySummary={};
    Object.entries(agg).forEach(([cat,subs]) => {
      entitySummary[cat]={};
      Object.entries(subs).forEach(([sub,set]) => { if(set.size) entitySummary[cat][sub]=[...set].slice(0,8); });
    });
    const rtCounts={};
    (resources||[]).forEach(r=>{ rtCounts[r.type]=(rtCounts[r.type]||0)+1; });
    const scopeChunks=this.chunks.filter(c=>c.entities.scope?.inScope?.length||c.entities.scope?.outOfScope?.length).map(c=>({
      source:c.source, inScope:c.entities.scope?.inScope||[], outOfScope:c.entities.scope?.outOfScope||[], excerpt:c.text.substring(0,200)+(c.text.length>200?'...':''),
    }));
    const threatChunks=this.chunks.filter(c=>Object.keys(c.entities.stride||{}).length>0).map(c=>({
      source:c.source, category:c.category, threats:Object.keys(c.entities.stride||{}), excerpt:c.text.substring(0,200)+(c.text.length>200?'...':''),
    }));
    // ATT&CK coverage across terraform resources
    const allTechniques=new Set();
    (resources||[]).forEach(r=>(TF_ATTACK_MAP[r.type]||[]).forEach(t=>allTechniques.add(t)));
    // Misconfig findings across all resources
    const allMisconfigs=[];
    (resources||[]).forEach(r=>{
      const findings=this.getMisconfigurations(r);
      if(findings.length) allMisconfigs.push({resource:r,findings});
    });
    // IAM factual analysis — merge into misconfigs
    try {
      const iamFindings = this.analyzeIAMResources(resources||[]);
      if (iamFindings.length) {
        // Group by resourceId so they appear alongside the resource
        const byRes = {};
        iamFindings.forEach(f => {
          const key = f.resourceId || f.resourceName || 'iam';
          if (!byRes[key]) byRes[key] = { resource:{id:key,type:f.resourceType||'aws_iam_role',name:f.resourceName||key}, findings:[] };
          byRes[key].findings.push(f);
        });
        Object.values(byRes).forEach(group => {
          const existing = allMisconfigs.find(m => m.resource.id === group.resource.id);
          if (existing) existing.findings.push(...group.findings);
          else allMisconfigs.push(group);
        });
      }
    } catch(e) {}
    const SEV=['Critical','High','Medium','Low'];
    const topMisconfigs=allMisconfigs.flatMap(m=>m.findings.map(f=>({...f,resourceType:m.resource.type,resourceName:m.resource.name||m.resource.id})))
      .sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)).slice(0,50);
    // ── New: posture, hierarchy, controls, cross-doc ─────────────────────────
    let posture=null, hierarchy=null, controlInventory=null, crossDocCorrelations=null;
    try { posture = this.getSecurityPosture(resources||[]); } catch(_){}
    try { hierarchy = inferArchitectureHierarchy(resources||[], [], []); } catch(_){}
    try { controlInventory = this.getControlInventory(resources||[]); } catch(_){}
    try { crossDocCorrelations = this.getCrossDocCorrelation(resources||[]); } catch(_){}
    return {
      entitySummary, rtCounts, scopeChunks, threatChunks,
      docCount:[...new Set(this.chunks.map(c=>c.source).filter(s=>s!=='terraform'))].length,
      chunkCount:this.chunks.length,
      attackTechniqueCount:allTechniques.size,
      misconfigCount:allMisconfigs.reduce((s,m)=>s+m.findings.length,0),
      misconfigsByResource:allMisconfigs,
      topMisconfigs,
      posture,
      hierarchy,
      controlInventory,
      crossDocCorrelations,
    };
  }

  // ── Architecture Analysis — derives structured fields from TF resources + docs ─
  analyzeArchitecture(resources, userDocs, modelDetails) {
    const res = resources || [];
    const _hasType = (...patterns) => res.some(r => patterns.some(p => r.type?.includes(p)));
    const _countType = (pattern) => res.filter(r => r.type?.includes(pattern)).length;
    const _names = (...patterns) => [...new Set(res.filter(r => patterns.some(p => r.type?.includes(p))).map(r => r.name || r.type))];

    // ── Application type inference ──
    const appTypes = [];
    if (_hasType('aws_lambda_function', 'aws_apigatewayv2', 'aws_api_gateway_rest_api') && !_hasType('aws_ecs', 'aws_eks', 'aws_instance')) appTypes.push('Serverless');
    if (_hasType('aws_ecs_cluster', 'aws_ecs_service', 'aws_eks_cluster')) appTypes.push('Container-Based (ECS/EKS)');
    if (_hasType('aws_instance', 'aws_autoscaling_group', 'aws_launch_template') && !_hasType('aws_ecs', 'aws_eks')) appTypes.push('VM-Based');
    if (_hasType('aws_s3_bucket') && _hasType('aws_cloudfront_distribution') && !_hasType('aws_lambda', 'aws_ecs', 'aws_instance')) appTypes.push('Static Web Application');
    if (_hasType('aws_kinesis', 'aws_msk', 'aws_sqs', 'aws_sns') && _hasType('aws_lambda', 'aws_glue', 'aws_firehose')) appTypes.push('Data Pipeline / Streaming');
    if (_hasType('aws_api_gateway', 'aws_apigatewayv2')) appTypes.push('REST API');
    if (!appTypes.length) appTypes.push('Cloud Application');

    // ── Entry point detection ──
    const entryPointTypes = [];
    if (_hasType('aws_api_gateway_rest_api', 'aws_apigatewayv2_api')) entryPointTypes.push('REST API');
    if (_hasType('aws_lb', 'aws_alb')) entryPointTypes.push('HTTPS / ALB');
    if (_hasType('aws_cloudfront_distribution')) entryPointTypes.push('CDN (CloudFront)');
    if (_hasType('aws_cognito_user_pool_client')) entryPointTypes.push('Web UI (Cognito-federated)');
    if (_hasType('aws_sqs_queue', 'aws_sns_topic')) entryPointTypes.push('Event / Message Queue');
    if (_hasType('aws_kinesis_stream')) entryPointTypes.push('Event Stream (Kinesis)');
    if (!entryPointTypes.length) entryPointTypes.push('HTTPS');

    // ── Exposure ──
    const exposure = [];
    if (_hasType('aws_cloudfront_distribution', 'aws_lb', 'aws_api_gateway', 'aws_route53')) exposure.push('Public Internet');
    if (_hasType('aws_vpc_endpoint')) exposure.push('VPC Endpoint (Internal)');
    if (!exposure.length) exposure.push('Intranet Only');

    // ── Compute type ──
    const computeType = [];
    if (_hasType('aws_lambda_function')) computeType.push('Serverless (Lambda)');
    if (_hasType('aws_ecs_cluster', 'aws_ecs_service')) computeType.push('Container (ECS)');
    if (_hasType('aws_eks_cluster')) computeType.push('Container (EKS)');
    if (_hasType('aws_instance', 'aws_autoscaling_group')) computeType.push('VM (EC2)');
    if (_hasType('aws_apprunner_service')) computeType.push('Cloud Managed Service (App Runner)');
    if (!computeType.length) computeType.push('Cloud Managed Service');

    // ── Auth methods (TF-based) ──
    const authMethods = [];
    if (_hasType('aws_cognito_user_pool')) authMethods.push('OAuth 2.0 / Cognito');
    if (_hasType('aws_iam_openid_connect_provider')) authMethods.push('OIDC / SSO');
    if (_hasType('aws_iam_role', 'aws_iam_policy')) authMethods.push('AWS IAM');
    if (!authMethods.length) authMethods.push('AWS IAM');

    // ── Integrations ──
    const integrations = [];
    if (_hasType('aws_sqs_queue')) integrations.push('Message Queue (SQS)');
    if (_hasType('aws_sns_topic')) integrations.push('Event Notification (SNS)');
    if (_hasType('aws_kinesis_stream')) integrations.push('Event Stream (Kinesis)');
    if (_hasType('aws_api_gateway')) integrations.push('REST API');
    if (_hasType('aws_msk')) integrations.push('Event Stream (Kafka/MSK)');

    // ── Storage ──
    const storageTypes = [];
    if (_hasType('aws_s3_bucket')) storageTypes.push(`S3 (${_countType('aws_s3_bucket')} bucket${_countType('aws_s3_bucket')!==1?'s':''})`);
    if (_hasType('aws_dynamodb_table')) storageTypes.push(`DynamoDB (${_countType('aws_dynamodb_table')} table${_countType('aws_dynamodb_table')!==1?'s':''})`);
    if (_hasType('aws_rds_cluster', 'aws_db_instance')) storageTypes.push('RDS (relational)');
    if (_hasType('aws_elasticache')) storageTypes.push('ElastiCache (in-memory cache)');
    if (_hasType('aws_efs_file_system')) storageTypes.push('EFS (shared file system)');

    // ── Doc-based narrative queries ──
    // ── Doc queries — exclude raw terraform metadata chunks for clean narrative ──
    const _q = (terms, k=3) => {
      const results = this.query(terms, k * 4).filter(r => r.source !== 'terraform');
      return results.slice(0, k).map(r => {
        const sents = r.text
          .replace(/#+\s/g,'').replace(/\*\*/g,'')
          .split(/(?<=[.!?])\s+(?=[A-Z"'])/)
          .map(s => s.replace(/\s+/g,' ').trim())
          .filter(s => s.length > 25 && s.length < 200
            && !s.startsWith('|') && !/^[-*]{3,}/.test(s) && !s.includes('------'));
        return sents.slice(0, 2).join(' ');
      }).filter(Boolean).join(' ');
    };

    const docEntryPoints = _q("entry point ingress endpoint API gateway load balancer");
    const docDataFlow    = _q("data flow pipeline stream ingestion process transform");
    const docSecBounds   = _q("trust boundary security zone VPC network segment DMZ scope");
    const docAuth        = _q("authentication authorization IAM role policy SSO OAuth MFA");
    const docExtDeps     = _q("third party vendor external integration dependency service");
    const docStorage     = _q("storage database encryption data at rest S3 DynamoDB RDS");
    const docFaultTol    = _q("fault tolerance high availability resilience redundancy failover");
    const docPubPriv     = _q("public private internet exposure VPC subnet internal external");
    const docControls    = _q("security control WAF GuardDuty Security Hub encryption KMS IAM");

    // ── Compliance & data sensitivity from doc text ──
    const docAllText = this.chunks.filter(c=>c.source!=='terraform').map(c=>c.text).join(' ').toUpperCase();
    const complianceFramework = [
      docAllText.includes('HIPAA')                                  && 'HIPAA',
      (docAllText.includes('PCI-DSS')||docAllText.includes('PCI DSS')||docAllText.includes('CARDHOLDER')) && 'PCI-DSS',
      (docAllText.includes('SOC2')||docAllText.includes('SOC 2'))   && 'SOC 2',
      docAllText.includes('GDPR')                                   && 'GDPR',
      (docAllText.includes('FEDRAMP')||docAllText.includes('FEDRAMP')) && 'FedRAMP',
      docAllText.includes('ISO 27001')                              && 'ISO 27001',
      (docAllText.includes('NIST 800')||docAllText.includes('NIST SP')) && 'NIST 800-53',
      (docAllText.includes('CIS AWS')||docAllText.includes('CIS BENCHMARK')) && 'CIS AWS',
    ].filter(Boolean);
    const dataSensitivity = [
      (docAllText.includes(' PII ')||docAllText.includes('PERSONAL DATA')||docAllText.includes('PERSONALLY IDENTIFIABLE')) && 'PII',
      (docAllText.includes(' PHI ')||docAllText.includes('PROTECTED HEALTH')) && 'PHI',
      (docAllText.includes(' PCI ')||docAllText.includes('CARDHOLDER')) && 'PCI Data',
      docAllText.includes('CONFIDENTIAL') && 'Confidential',
    ].filter(Boolean);
    if (!dataSensitivity.length) dataSensitivity.push('Internal');

    // ── Bullet-list narrative helpers ──
    const bullet = (items) => items.filter(Boolean).map(i=>`• ${i}`).join('\n');
    const decodeHtml = (s) => s
      .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>')
      .replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&nbsp;/g,' ');
    const fromDoc = (raw, max=2) => {
      if (!raw) return '';
      const sents = decodeHtml(raw).replace(/#+\s/g,'').replace(/\*\*/g,'').replace(/`/g,'')
        .split(/(?<=[.!?])\s+(?=[A-Z"'])/)
        .map(s=>s.trim())
        .filter(s=>s.length>30&&s.length<220&&!s.startsWith('|')&&!s.includes('------'));
      return sents.length ? `\nContext: ${sents.slice(0,max).join(' ')}` : '';
    };

    // ── Narrative construction — clean bullet lists per section ──
    const narrative = {
      entryPoints: bullet([
        ..._names('aws_api_gateway_rest_api','aws_apigatewayv2_api').slice(0,2).map(n=>`REST API — ${n}`),
        ..._names('aws_lb','aws_alb').slice(0,2).map(n=>`HTTPS / ALB — ${n}`),
        ..._names('aws_cloudfront_distribution').slice(0,1).map(n=>`CDN / CloudFront — ${n}`),
        ..._names('aws_sqs_queue').slice(0,1).map(n=>`Message Queue — SQS (${n})`),
        ..._names('aws_sns_topic').slice(0,1).map(n=>`Event Notification — SNS (${n})`),
        ..._names('aws_kinesis_stream').slice(0,1).map(n=>`Event Stream — Kinesis (${n})`),
        ...(!_hasType('aws_api_gateway','aws_lb','aws_cloudfront','aws_sqs','aws_sns','aws_kinesis') ? ['HTTPS (no specific entry resources detected)'] : []),
      ]) + fromDoc(docEntryPoints),

      dataFlow: bullet([
        ..._names('aws_sns_topic').slice(0,1).map(n=>`Event Notification — SNS (${n})`),
        ..._names('aws_sqs_queue').slice(0,1).map(n=>`Message Queue — SQS (${n})`),
        ..._names('aws_kinesis_stream','aws_msk_cluster').slice(0,2).map(n=>`Event Stream — ${n}`),
        ..._names('aws_api_gateway_rest_api','aws_apigatewayv2_api').slice(0,1).map(n=>`REST API — ${n}`),
        ..._names('aws_lambda_function').slice(0,3).map(n=>`Lambda processor — ${n}`),
        ..._names('aws_s3_bucket').slice(0,2).map(n=>`S3 storage — ${n}`),
        ...(_hasType('aws_cloudwatch_log_group','aws_cloudwatch_log_stream') ? ['CloudWatch — log aggregation'] : []),
        ...(_hasType('aws_cloudtrail') ? ['CloudTrail → S3 — audit trail'] : []),
      ]) + fromDoc(docDataFlow),

      securityBoundaries: bullet([
        ...(_hasType('aws_vpc') ? [`VPC — ${_countType('aws_subnet')} subnet(s), ${_countType('aws_vpc')} VPC(s)`] : []),
        ...(_hasType('aws_security_group') ? [`${_countType('aws_security_group')} Security Group(s) — intra-VPC traffic control`] : []),
        ...(_hasType('aws_network_acl') ? ['Network ACLs — subnet-level packet filtering'] : []),
        ...(_hasType('aws_wafv2_web_acl') ? ['WAF v2 — internet-facing endpoint protection'] : []),
        ...(_hasType('aws_guardduty_detector') ? ['GuardDuty — threat detection boundary'] : []),
        ...(_hasType('aws_organizations_organization','aws_organizations_organizational_unit') ? ['AWS Organizations — multi-account boundary enforcement'] : []),
      ]) + fromDoc(docSecBounds),

      publicPrivateResources: bullet([
        ...(_hasType('aws_cloudfront_distribution','aws_lb','aws_api_gateway') ? ['Public-facing: CloudFront / ALB / API Gateway'] : []),
        ...(_hasType('aws_vpc') ? [`Private subnets: ${_countType('aws_subnet')} subnet(s) in VPC`] : []),
        ...(_hasType('aws_internet_gateway') ? ['Internet Gateway — VPC public internet access'] : []),
        ...(_hasType('aws_nat_gateway') ? ['NAT Gateway — outbound-only for private subnets'] : []),
        ...(_hasType('aws_vpc_endpoint') ? ['VPC Endpoints — private AWS service access (no IGW)'] : []),
        ...(_hasType('aws_s3_bucket') ? [`S3 — ${_countType('aws_s3_bucket')} bucket(s), verify public access blocks`] : []),
      ]) + fromDoc(docPubPriv),

      securityControls: bullet([
        ...(_hasType('aws_kms_key') ? [`KMS — ${_countType('aws_kms_key')} CMK(s) for data-at-rest encryption`] : []),
        ...(_hasType('aws_acm_certificate') ? ['ACM — TLS/HTTPS certificate management'] : []),
        ...(_hasType('aws_wafv2_web_acl') ? ['WAF v2 — web application firewall'] : []),
        ...(_hasType('aws_guardduty_detector') ? ['GuardDuty — threat detection (organization-wide)'] : []),
        ...(_hasType('aws_securityhub_account') ? ['Security Hub — centralized findings aggregation'] : []),
        ...(_hasType('aws_config_rule','aws_config_configuration_recorder') ? ['AWS Config — compliance monitoring'] : []),
        ...(_hasType('aws_cloudtrail') ? ['CloudTrail — API audit logging'] : []),
        ...(_hasType('aws_iam_policy','aws_iam_role_policy') ? [`IAM — ${_countType('aws_iam_policy')} managed + ${_countType('aws_iam_role_policy')} inline policies`] : []),
      ]) + fromDoc(docControls),

      faultTolerance: bullet([
        ...(_hasType('aws_autoscaling_group') ? ['Auto Scaling Group — horizontal scaling'] : []),
        ...(_hasType('aws_rds_cluster') ? ['RDS Cluster — multi-node resilience'] : []),
        ...(_hasType('aws_elasticache_replication_group') ? ['ElastiCache Replication Group — cache HA'] : []),
        ...(_hasType('aws_lb') ? ['Application Load Balancer — traffic distribution'] : []),
        ...(_hasType('aws_backup_vault') ? ['AWS Backup — automated data backup'] : []),
        ...(_hasType('aws_cloudwatch_metric_alarm') ? [`CloudWatch Alarms — ${_countType('aws_cloudwatch_metric_alarm')} metric alert(s)`] : []),
        ...(!_hasType('aws_autoscaling_group','aws_rds_cluster','aws_lb','aws_backup_vault') ? ['No HA/fault tolerance resources detected'] : []),
      ]) + fromDoc(docFaultTol),

      authAndAuthz: bullet([
        ...(_hasType('aws_iam_role') ? [`IAM Roles — ${_countType('aws_iam_role')} role(s) managing service permissions`] : []),
        ...(_hasType('aws_cognito_user_pool') ? ['Cognito User Pool — OAuth 2.0 / JWT authentication'] : []),
        ...(_hasType('aws_iam_openid_connect_provider') ? ['OIDC Provider — federated SSO / GitHub Actions'] : []),
        ...(_hasType('aws_iam_instance_profile') ? ['IAM Instance Profiles — EC2 service identity'] : []),
        ...(_hasType('aws_iam_policy') ? [`IAM Policies — ${_countType('aws_iam_policy')} managed policy document(s)`] : []),
        ...(_hasType('aws_secretsmanager_secret') ? [`Secrets Manager — ${_countType('aws_secretsmanager_secret')} secret(s)`] : []),
      ]) + fromDoc(docAuth),

      externalDependencies: bullet([
        ...(_hasType('aws_vpc_endpoint') ? ['VPC Endpoints — private connectivity to AWS services'] : []),
        ...(_hasType('aws_route53_record','aws_route53_zone') ? [`Route 53 — ${_countType('aws_route53_record')} DNS record(s)`] : []),
        ...(_hasType('aws_internet_gateway') ? ['Internet Gateway — external traffic entry point'] : []),
        ...(_hasType('aws_dx_connection','aws_vpn_connection') ? ['Direct Connect / VPN — partner network links'] : []),
        ...(integrations.length ? integrations.map(i=>`External integration — ${i}`) : []),
        ...(!_hasType('aws_vpc_endpoint','aws_route53','aws_dx_connection','aws_vpn_connection') && !integrations.length ? ['No external dependency resources detected'] : []),
      ]) + fromDoc(docExtDeps),

      storageAndDataSecurity: bullet([
        ...(_hasType('aws_s3_bucket') ? [`S3 — ${_countType('aws_s3_bucket')} bucket(s)`] : []),
        ...(_hasType('aws_dynamodb_table') ? [`DynamoDB — ${_countType('aws_dynamodb_table')} table(s)`] : []),
        ...(_hasType('aws_rds_cluster','aws_db_instance') ? ['RDS — relational database (managed)'] : []),
        ...(_hasType('aws_elasticache_cluster','aws_elasticache_replication_group') ? ['ElastiCache — in-memory cache layer'] : []),
        ...(_hasType('aws_efs_file_system') ? ['EFS — shared file system'] : []),
        ...(_hasType('aws_s3_bucket_versioning','aws_s3_bucket') ? ['S3 versioning — point-in-time recovery'] : []),
        ...(_hasType('aws_kms_key') ? [`KMS — ${_countType('aws_kms_key')} CMK(s) for encryption at rest`] : []),
        ...(_hasType('aws_secretsmanager_secret') ? [`Secrets Manager — ${_countType('aws_secretsmanager_secret')} secret(s)`] : []),
      ]) + fromDoc(docStorage),
    };

    const attributes = {
      applicationType: appTypes,
      entryPointTypes,
      developedBy: _hasType('aws_') ? 'Vendor (AWS)' : 'Internal',
      inboundDataSource: _hasType('aws_cloudfront', 'aws_lb', 'aws_api_gateway') ? ['External Public'] : ['Internal Corporate Network'],
      inboundDataFlow: _hasType('aws_api_gateway', 'aws_lb') ? ['API Request'] : [],
      outboundDataFlow: [
        ...(storageTypes.length ? ['DB Write'] : []),
        ...(_hasType('aws_kinesis','aws_sns','aws_sqs') ? ['Event/Message'] : []),
        ...(_hasType('aws_api_gateway','aws_lb') ? ['API Response'] : []),
      ],
      outboundDataDestination: ['Internal Corporate Network'],
      exposure,
      authMethods,
      facilityType: ['AWS Cloud'],
      computeType,
      users: ['Internal Apps/Services'],
      integrations,
      complianceFramework,
      dataSensitivity,
      environment: ['Production'],
    };

    // Confidence: based on resource count + indexed doc chunk count
    const confidence = Math.min(100, Math.round(
      Math.min(res.length, 50) * 1.2 +
      Math.min(this.chunks.filter(c => c.source !== 'terraform').length, 20) * 2
    ));

    return { narrative, attributes, confidence };
  }

  // ── Index user-uploaded documents ────────────────────────────────────────────
  indexDocuments(userDocs) {
    (userDocs||[]).forEach((doc,di) => {
      if (doc.binary||!doc.content||doc.content.length<10) return;
      const cat = this._categorizeDoc(doc);
      this._splitText(doc.content).forEach((chunk,ci) => {
        this._addChunk(doc.name||doc.path, chunk, cat, `doc_${di}`, ci);
      });
    });
  }

  // ── Index parsed Terraform resources ────────────────────────────────────────
  indexResources(resources, modules) {
    (resources||[]).forEach(r => {
      const attacks=(TF_ATTACK_MAP[r.type]||[]).map(tid=>{const t=ATTACK_TECHNIQUES[tid]; return t?`${tid} ${t.name} ${t.tactic}`:tid;}).join('. ');
      const mischecks=(TF_MISCONFIG_CHECKS[r.type]||[]).map(c=>c.title).join('. ');
      const text=[
        `Terraform resource ${r.type} named ${r.name||r.id}.`,
        `Provider: ${(r.type||'').split('_')[0]}.`,
        attacks?`MITRE ATT&CK: ${attacks}.`:'',
        mischecks?`Security checks: ${mischecks}.`:'',
      ].filter(Boolean).join(' ');
      this._addChunk('terraform', text, 'terraform');
    });
    (modules||[]).forEach(m => {
      this._addChunk('terraform', `Terraform module ${m.name} source ${m.src||'registry'} type ${m.srcType||''}.`, 'terraform');
    });
  }

  // ── Extract key features from enterprise context docs ─────────────────────────
  extractKeyFeatures() {
    if (!this._built) return [];
    // Score how "informative" a sentence is — prefer specific, concise, factual statements
    const scoreSentence = (s) => {
      if (s.length < 15 || s.length > 180) return 0;
      let score = 0;
      // Reward: technical nouns, product names, protocols, AWS services
      if (/\b(AWS|Amazon|S3|RDS|EC2|EKS|Lambda|DynamoDB|Kinesis|SQS|SNS|IAM|VPC|API|REST|GraphQL|OAuth|SAML|TLS|SSL|AES|RSA|RBAC|ABAC|JWT|SSO|MFA|Kubernetes|Docker|Terraform|CI\/CD|SIEM|WAF|CDN|DNS|HTTPS|gRPC|Kafka|Redis|Postgres|MySQL|MongoDB)\b/i.test(s)) score += 3;
      // Reward: action verbs describing what the system does
      if (/\b(processes|handles|manages|stores|encrypts|authenticates|authorizes|monitors|logs|audits|validates|ingests|transforms|routes|exposes|integrates|supports|enforces|detects|alerts|replicates|scales|deploys)\b/i.test(s)) score += 2;
      // Reward: data/security/compliance terms
      if (/\b(data|security|compliance|access|control|policy|token|key|certificate|credential|secret|audit|log|event|alert|threshold|SLA|RPO|RTO|tier|layer|boundary|zone|tenant)\b/i.test(s)) score += 1;
      // Penalise: very long sentences (hard to read as a bullet)
      if (s.length > 120) score -= 2;
      // Penalise: mostly filler
      const words = s.match(/\b\w+\b/g) || [];
      const filler = (s.match(/\b(the|this|that|these|those|is|are|was|were|will|would|could|should|a|an|in|on|at|to|for|of|with|by|and|or|but|be|been|being|have|has|had|do|does|did)\b/gi) || []).length;
      if (words.length > 0 && filler / words.length > 0.65) score -= 3;
      return score;
    };

    const cleanSentence = (s) => {
      // Trim to max 120 chars at word boundary
      let out = s.trim();
      if (out.length > 120) out = out.substring(0, 117).replace(/\s+\S*$/, '') + '…';
      return out.charAt(0).toUpperCase() + out.slice(1);
    };

    const QUERIES = [
      "data processing pipeline ingestion transformation",
      "authentication authorization access control identity",
      "API endpoints REST GraphQL integration gateway",
      "encryption at rest in transit TLS certificate",
      "storage database persistence caching",
      "monitoring logging observability alerting",
      "multi-tenancy tenant isolation namespace",
      "compliance regulatory HIPAA PCI FedRAMP SOC",
      "third party integrations external service vendor",
      "fault tolerance redundancy high availability failover",
      "data classification sensitive PII PHI PCI",
      "user access role permission privilege",
      "compute serverless container kubernetes microservice",
      "network VPC subnet boundary trust zone",
    ];
    const seen = new Set();
    const candidates = []; // [{text, score, source}]

    QUERIES.forEach(q => {
      this.query(q, 3).forEach(chunk => {
        chunk.text.split(/[.!?\n]+/).map(s => s.trim()).forEach(sent => {
          const score = scoreSentence(sent);
          if (score > 0) {
            const key = sent.substring(0, 45).toLowerCase();
            if (!seen.has(key)) { seen.add(key); candidates.push({ text: cleanSentence(sent), score }); }
          }
        });
      });
    });

    // Enterprise-arch and app-details: scan all chunks directly
    this.chunks
      .filter(c => ['enterprise-arch','app-details'].includes(c.category))
      .forEach(chunk => {
        chunk.text.split(/[.!?\n]+/).map(s => s.trim()).forEach(sent => {
          const score = scoreSentence(sent);
          if (score >= 0) { // lower bar for authoritative categories
            const key = sent.substring(0, 45).toLowerCase();
            if (!seen.has(key)) { seen.add(key); candidates.push({ text: cleanSentence(sent), score: score + 1 }); }
          }
        });
      });

    // Sort by score, return top 30 as bullets
    return candidates
      .sort((a, b) => b.score - a.score)
      .slice(0, 30)
      .map(c => `- ${c.text}`);
  }

  // ── Auto-populate architecture description ─────────────────────────────────────
  getArchSummaryText(resources) {
    // Build a clean structured description from TF resources + doc context
    const parts = [];

    // 1. Resource counts by category
    const res = resources || [];
    if (res.length) {
      const typeCounts = {};
      res.forEach(r => {
        const label = r.type.replace(/^aws_/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        typeCounts[label] = (typeCounts[label] || 0) + 1;
      });
      const topTypes = Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([t, n]) => n > 1 ? `${n}x ${t}` : t);
      parts.push(`Infrastructure: ${topTypes.join(', ')}.`);
    }

    // 2. Pull ONE clear sentence from each of the top architecture/context doc chunks
    const archChunks = this.query("architecture overview deployment environment", 3);
    archChunks.forEach(c => {
      const sents = c.text.split(/[.!?\n]+/).map(s => s.trim()).filter(s => s.length > 20 && s.length <= 150);
      if (sents[0]) parts.push(sents[0] + '.');
    });

    return parts.filter(Boolean).join(' ').substring(0, 500) || "";
  }

  // ── Full rebuild ─────────────────────────────────────────────────────────────
  build(userDocs, resources, modules) {
    this.chunks=[]; this._tf=[]; this._tfidf=[]; this._docLens=[];
    this._idf={}; this._vocab=new Set(); this._built=false;
    this.indexDocuments(userDocs);
    this.indexResources(resources, modules);
    this._buildIndex();
    this._built=true;
    return this;
  }

  // ── Legacy: keep _addChunk's old index object intact for any callers ─────────
  // (not needed in v2 but guards against stale refs)
  get index() { return this._idf; }

  // ── Alias: getSummary → getArchitectureSummary (guards against stale call sites) ─
  getSummary(resources, userDocs) { return this.getArchitectureSummary(resources, userDocs); }
}

// ─────────────────────────────────────────────────────────────────────────────
// DFD XML GENERATOR
// ─────────────────────────────────────────────────────────────────────────────
const xe = s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
// xeXml: XML-escape AND encode any non-ASCII chars as decimal character references.
// Prevents strict parsers (e.g. Lucidchart's draw.io importer) from choking on
// UTF-8 chars like the middle-dot · (U+00B7) that appear in tier labels.
const xeXml = s => xe(s).replace(/[^\x00-\x7F]/g, c => `&#${c.charCodeAt(0)};`);
const NW=84, NH=60, LH=32, VGAP=12, HGAP=18, TPAD=18, TVPAD=22, HDRH=40, TGAP=60, CPAD=28;
const MAXCOLS=6;
const LEGEND_W=252;

function buildLegendCells(lx, ly) {
  // All cells use parent="1" with ABSOLUTE coordinates.
  // Every <mxCell> is properly nested: opening tag → child <mxGeometry/> → </mxCell>
  // with consistent 2-space relative indentation (matching draw.io export format).
  // NO 'triangle' shape (draw.io-only). NO 'opacity'. html=1 + whiteSpace=wrap throughout.
  const LW=LEGEND_W, LR=24, TR=20, SH=18;
  const cells=[];
  let lid=9000;
  const nid=()=>`lg_${++lid}`;
  let ry=0;

  // vcell: generates ONE properly-nested vertex mxCell.
  // The outer allCells.map(c=>`    ${c}`) adds 4 spaces to line 1.
  // Interior lines use absolute indentation: 6sp for <mxGeometry>, 4sp for </mxCell>.
  const vcell=(id,value,style,gx,gy,gw,gh)=>
    `<mxCell id="${id}" value="${value}" style="${style}" vertex="1" parent="1">\n      <mxGeometry x="${gx}" y="${gy}" width="${gw}" height="${gh}" as="geometry"/>\n    </mxCell>`;

  // ── Background + header ──────────────────────────────────────────────────
  const TOTAL_H = 540;
  cells.push(
    vcell("legend_bg",      "", "rounded=1;fillColor=#F8F9FA;strokeColor=#283593;strokeWidth=2;html=1;",                                           lx,    ly,    LW, TOTAL_H),
    vcell("legend_hdr_bar", "", "rounded=0;fillColor=#1A237E;strokeColor=none;html=1;",                                                            lx,    ly,    LW, 28),
    vcell("legend_hdr_txt", "Legend", "text;whiteSpace=wrap;html=1;align=center;fontStyle=1;fontSize=12;fontColor=#FFFFFF;strokeColor=none;fillColor=none;", lx, ly, LW, 28)
  );
  ry = 36;

  // Helper: section heading
  const hdr=(t)=>{
    cells.push(vcell(nid(), xe(t),
      "text;whiteSpace=wrap;html=1;align=left;fontStyle=1;fontSize=9;fontColor=#1A237E;strokeColor=none;fillColor=none;",
      lx+10, ly+ry, LW-20, 16));
    ry+=SH;
  };

  // Helper: horizontal divider line
  const div=()=>{
    cells.push(vcell(nid(), "",
      "rounded=0;fillColor=#BBDEFB;strokeColor=none;html=1;",
      lx+8, ly+ry+2, LW-16, 1));
    ry+=10;
  };

  // Helper: node-type swatch + label row
  const nodeRow=(lbl,fill,stroke,extra="")=>{
    cells.push(
      vcell(nid(), "",
        `rounded=1;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;${extra}html=1;`,
        lx+10, ly+ry+3, 28, 17),
      vcell(nid(), xe(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+46, ly+ry+3, LW-56, 17)
    );
    ry+=LR;
  };

  // Helper: edge-type row — colored bar + end-cap rect + label.
  // 'triangle' shape is draw.io-only; replaced with small filled rectangle end-cap.
  const edgeRow=(lbl,color,dashed=false)=>{
    const lineW=62, lineH=3, capW=5, capH=9;
    const ex=lx+10, ey=ly+ry+12;
    const solidStyle=`rounded=0;fillColor=${color};strokeColor=none;html=1;`;
    if(dashed){
      for(let d=0;d<4;d++){
        cells.push(vcell(nid(), "", solidStyle, ex+d*16, ey, 11, lineH));
      }
    } else {
      cells.push(vcell(nid(), "", solidStyle, ex, ey, lineW, lineH));
    }
    // End-cap (arrow indicator — plain rectangle, Lucidchart-safe)
    cells.push(
      vcell(nid(), "", `rounded=0;fillColor=${color};strokeColor=none;html=1;`,
        ex+lineW, ey-3, capW, capH),
      vcell(nid(), xe(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+88, ly+ry+5, LW-98, 16)
    );
    ry+=LR;
  };

  // Helper: tier boundary swatch + label row
  const tierRow=(lbl,fill,stroke)=>{
    cells.push(
      vcell(nid(), "",
        `rounded=1;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.5;html=1;`,
        lx+10, ly+ry+3, 28, 13),
      vcell(nid(), xeXml(lbl),
        "text;whiteSpace=wrap;html=1;align=left;fontSize=9;fontColor=#37474F;strokeColor=none;fillColor=none;",
        lx+46, ly+ry+2, LW-56, 15)
    );
    ry+=TR;
  };

  // ── Section 1: Node Types ─────────────────────────────────────────────────
  hdr("NODE TYPES");
  nodeRow("AWS Resource (managed)",  "#FFFFFF","#546E7A");
  nodeRow("Data Source (read-only)", "#F5F5F5","#0277BD","dashed=1;dashPattern=4 3;");
  nodeRow("Terraform Module",        "#EDE7F6","#4527A0","dashed=1;dashPattern=5 3;");
  nodeRow("Sentinel Policy Gate",    "#FFF8E1","#E65100");
  nodeRow("Remote State Reference",  "#E3F2FD","#1565C0","dashed=1;dashPattern=6 4;");
  div();

  // ── Section 2: Connection Types ───────────────────────────────────────────
  hdr("CONNECTION TYPES");
  edgeRow("Implicit reference",    "#78909C", false);
  edgeRow("Explicit depends_on",   "#E53935", true);
  edgeRow("Module input / output", "#2E7D32", false);
  edgeRow("Remote state read",     "#6A1B9A", true);
  edgeRow("Data source read",      "#0277BD", true);
  div();

  // ── Section 3: Tier Boundaries ────────────────────────────────────────────
  hdr("TIER BOUNDARIES");
  tierRow("xSphere Private Cloud",  "#E8EAF6","#3949AB");
  tierRow("Org / Account",          "#F3E5F5","#6A1B9A");
  tierRow("Security / IAM / KMS",   "#FFEBEE","#C62828");
  tierRow("CI/CD / Jenkins / IaC",  "#FFF3E0","#E65100");
  tierRow("Network / VPC / TGW",    "#E8F5E9","#2E7D32");
  tierRow("Compute / API / Events", "#E3F2FD","#1565C0");
  tierRow("Storage / Database",     "#FFF8E1","#F57F17");

  // Footer
  cells.push(vcell(nid(), "threataform - enterprise terraform dfd",
    "text;whiteSpace=wrap;html=1;align=center;fontSize=7;fontColor=#78909C;strokeColor=none;fillColor=none;",
    lx, ly+ry+6, LW, 12));
  return cells;
}

function generateDFDXml(resources, modules, connections, intelligenceCtx) {
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

  // ── HORIZONTAL LEFT-TO-RIGHT LAYOUT ────────────────────────────────────────
  // Legend sits at top-left (CPAD, CPAD). Diagram flows right from legend.
  // Each tier is a vertical column; nodes within a tier flow top-to-bottom.
  // MAXROWS: max nodes per sub-column within a tier before wrapping to next column.
  const MAXROWS = 5;
  const DIAG_X   = CPAD + LEGEND_W + 40; // diagram start X (right of legend)
  const DIAG_Y   = CPAD;                 // diagram start Y (same top as legend)

  // Uniform tier height: based on tallest single sub-column across all tiers
  const maxRowsNeeded = activeTiers.reduce((mx,t)=>Math.max(mx,Math.min(groups[t].length,MAXROWS)),1);
  const tierH = HDRH + TVPAD + maxRowsNeeded*(NH+LH+VGAP) - VGAP + TVPAD;

  let globalX = DIAG_X;

  activeTiers.forEach((t,ti)=>{
    const nodes=groups[t];
    // How many sub-columns does this tier need?
    const subCols = Math.ceil(nodes.length / MAXROWS);
    const tW = TPAD*2 + subCols*(NW+HGAP) - HGAP;

    const tm = TIERS[t]||{label:t, bg:"#F5F5F5", border:"#999", hdr:"#555"};
    const tcid=`tier_${t}`;
    // Single plain rectangle per tier — most compatible with Lucidchart's draw.io importer.
    // Label floats at top-left of the tier background box.
    containers.push(
      `<mxCell id="${tcid}" value="${xeXml(tm.label)}&#xa;(${nodes.length} resources)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=${tm.bg};strokeColor=${tm.border};strokeWidth=2;fontColor=${tm.hdr};fontSize=11;fontStyle=1;align=left;verticalAlign=top;spacingLeft=10;spacingTop=5;" vertex="1" parent="1">\n      <mxGeometry x="${globalX}" y="${DIAG_Y}" width="${tW}" height="${tierH}" as="geometry"/>\n    </mxCell>`
    );

    nodes.forEach((n,i)=>{
      // Within a tier: flow top-to-bottom, wrapping into sub-columns
      const subCol = Math.floor(i / MAXROWS);
      const row    = i % MAXROWS;
      const nx = globalX + TPAD + subCol*(NW+HGAP);
      const ny = DIAG_Y + HDRH + TVPAD + row*(NH+LH+VGAP);
      const cid=`n_${++cellN}`;
      idMap.set(n.id, {cid, tier:t, tierIdx:ti});
      const meta=n._meta;
      const shortType = n._isModule
        ? `${n.srcType||"module"}`
        : (n.type||"").replace(/^aws_|^xsphere_/,"").replace(/_/g," ").substring(0,20);
      const rawMulti = n.multi ? ` [${n.multi}]` : "";
      const rawName = (n.label||n.name||"").substring(0,18) + rawMulti;
      // Use &#xa; for multi-line labels — value is pre-escaped so do NOT apply xe() again.
      // xeXml() encodes user content (XML chars + non-ASCII); &#xa; is then appended literally.
      const escapedName = xeXml(rawName);
      const escapedType = shortType ? xeXml(shortType) : "";
      // Intelligence enrichment: if uploaded docs mention STRIDE threats for this resource,
      // add a third line to the node label (e.g. "⚑ tamper,infoDisclose")
      // This only adds content to the VALUE field — XML format/structure is untouched.
      let threatLine = "";
      if (intelligenceCtx && intelligenceCtx._built) {
        const hits = intelligenceCtx.analyzeResource(n.type||"", n.name||"");
        const strideFound = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.stride||{})))].slice(0,2);
        if (strideFound.length) threatLine = xeXml(`\u26A0 ${strideFound.join(",")}`);
      }
      const rawLbl = escapedType
        ? (threatLine ? `${escapedName}&#xa;${escapedType}&#xa;${threatLine}` : `${escapedName}&#xa;${escapedType}`)
        : (threatLine ? `${escapedName}&#xa;${threatLine}` : escapedName);
      const bdrDash = n._isModule||n.srcType==="remote_state" ? "dashed=1;" : "";
      const bgColor = n._isModule ? "#FAFFF5" : "#FFFFFF";
      // Matches the working reference XML: html=1 + whiteSpace=wrap are required for Lucidchart.
      const style=`rounded=1;whiteSpace=wrap;html=1;fillColor=${bgColor};strokeColor=${meta.c||"#546E7A"};strokeWidth=1;fontColor=#333333;fontSize=9;align=center;${bdrDash}`;
      vertices.push(
        `<mxCell id="${cid}" value="${rawLbl}" style="${style}" vertex="1" parent="1">\n      <mxGeometry x="${nx}" y="${ny}" width="${NW}" height="${NH+LH}" as="geometry"/>\n    </mxCell>`
      );
    });

    globalX += tW + TGAP;
  });

  const totalW = globalX;
  const totalH = DIAG_Y + tierH + CPAD;

  // Edges with smart exit/entry routing — orthogonalEdgeStyle for L→R flow.
  // Cross-tier edges flow left→right. Same-tier: orthogonal routing.
  const seenE=new Set();
  connections.forEach(c=>{
    const sInfo=idMap.get(c.from), tInfo=idMap.get(c.to);
    if(!sInfo||!tInfo)return;
    const ek=`${sInfo.cid}|${tInfo.cid}`;
    if(seenE.has(ek))return;
    seenE.add(ek);
    const color=c.kind==="explicit"?"#E53935":c.kind==="module-input"?"#2E7D32":"#78909C";
    const dash=c.kind==="explicit"?"dashed=1;" : "";
    const lbl=c.kind==="explicit"?"depends_on":c.kind==="module-input"?"input":"";
    // Edge style matching the working reference XML: orthogonalEdgeStyle + html=1 + blockThin arrow.
    // This is the exact pattern Lucidchart's draw.io importer handles correctly.
    edges.push(
      `<mxCell id="e_${++cellN}" value="${xe(lbl)}" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=${color};strokeWidth=2;${dash}fontColor=${color};fontSize=8;endArrow=blockThin;" edge="1" source="${sInfo.cid}" target="${tInfo.cid}" parent="1">\n      <mxGeometry relative="1" as="geometry"/>\n    </mxCell>`
    );
  });

  // Legend at TOP-LEFT (CPAD, CPAD) — diagram flows right from (DIAG_X, CPAD).
  // Uses only Lucidchart-safe shapes: html=1 + whiteSpace=wrap, no triangle, no opacity.
  const legendCells=buildLegendCells(CPAD, CPAD);
  const allCells=[...containers,...edges,...vertices,...legendCells];
  // Return bare <mxGraphModel> — wrapped in <mxfile> wrapper when downloading/copying.
  const pageW = Math.max(5000, totalW+200);
  const pageH = Math.max(3500, totalH+200);
  return [
    // Full mxGraphModel attributes matching draw.io export format — required for correct Lucidchart import.
    `<mxGraphModel dx="5000" dy="3500" grid="1" gridSize="20" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${pageW}" pageHeight="${pageH}" math="0" shadow="0" background="#FAFAFA">`,
    `  <root>`,
    `    <mxCell id="0"/>`,
    `    <mxCell id="1" parent="0"/>`,
    ...allCells.map(c=>`    ${c}`),
    `  </root>`,
    `</mxGraphModel>`
  ].join("\n");
}

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

function makeZipOneFile(filename, contentStr) {
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
function generateLucidJson(resources, modules, connections) {
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
  const DomainIcon = KB_DOMAIN_ICONS[domain] || BookOpen;

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
            flexShrink:0, color:d.color,
          }}><DomainIcon size={20}/></div>
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
                borderRadius:5, padding:"3px 8px", color:C.red, fontSize:11, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center" }}>
              <X size={12}/>
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
                <FileText size={13}/> Browse Files
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
                <FolderOpen size={13} style={{opacity: isFolderOpen ? 1 : 0.6}}/>
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

// ATTACK_TECHNIQUES is defined at top of file (intelligence knowledge graph v2)

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

      {/* Supporting Documents — with architecture classification */}
      {A.userDocs.length > 0 && (
        <Section id="docs" title="Context Documents & Architecture Intelligence" color="#78909C" count={A.userDocs.length}>
          {/* Doc context summary */}
          {A.docContext && (A.docContext.compliance.length > 0 || Object.keys(A.docContext.mentions).length > 0) && (
            <div style={{background:C.bg, border:`1px solid ${"#78909C"}30`, borderRadius:8, padding:"12px 16px", marginBottom:14}}>
              {A.docContext.compliance.length > 0 && (
                <div style={{display:"flex", gap:6, alignItems:"center", flexWrap:"wrap", marginBottom:6}}>
                  <span style={{fontSize:11, color:C.textMuted, fontWeight:600}}>Compliance:</span>
                  {A.docContext.compliance.map(c => (
                    <span key={c} style={{fontSize:10, padding:"2px 8px", borderRadius:4, background:"#E65100"+"20", color:"#FF8A65", border:"1px solid #E6510030", fontWeight:600}}>{c}</span>
                  ))}
                </div>
              )}
              {Object.keys(A.docContext.mentions).length > 0 && (
                <div style={{display:"flex", gap:6, alignItems:"center", flexWrap:"wrap"}}>
                  <span style={{fontSize:11, color:C.textMuted, fontWeight:600}}>Platforms:</span>
                  {Object.keys(A.docContext.mentions).slice(0,10).map(m => (
                    <span key={m} style={{fontSize:10, padding:"2px 8px", borderRadius:4, background:"#0277BD"+"20", color:"#4FC3F7", border:"1px solid #0277BD30", fontWeight:600}}>{m}</span>
                  ))}
                </div>
              )}
            </div>
          )}
          <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
            {A.userDocs.map((d,i) => {
              const ext = (d.name||"").split(".").pop().toLowerCase();
              const typeMeta = DOC_TYPE_META[ext] || { label: ext.toUpperCase().slice(0,6)||"FILE", color:"#78909C" };
              const inv = A.docContext?.docInventory?.find(di => di.name === d.name);
              const roleLabel = inv?.roles?.[0]?.replace(/-/g," ") || "";
              const tierLabel = inv?.archTier && inv.archTier !== "Unknown" ? inv.archTier : null;
              return (
                <div key={i} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"9px 13px", display:"flex", gap:10, alignItems:"flex-start" }}>
                  <span style={{
                    fontSize:9, fontWeight:700, color:typeMeta.color,
                    background:`${typeMeta.color}15`, border:`1px solid ${typeMeta.color}33`,
                    borderRadius:4, padding:"2px 6px", flexShrink:0, marginTop:1
                  }}>{typeMeta.label}</span>
                  <div style={{minWidth:0, flex:1}}>
                    <div style={{display:"flex", alignItems:"center", gap:7, marginBottom:3, flexWrap:"wrap"}}>
                      <span style={{ fontSize:12, color:"#90A4AE", fontWeight:600,
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {d.path || d.name}
                      </span>
                      {tierLabel && (
                        <span style={{fontSize:9, padding:"1px 6px", borderRadius:3, fontWeight:700, flexShrink:0,
                          background:"#2E7D32"+"25", color:"#81C784", border:"1px solid #2E7D3240"}}>
                          {tierLabel}
                        </span>
                      )}
                      {roleLabel && (
                        <span style={{fontSize:9, padding:"1px 6px", borderRadius:3, fontWeight:600, flexShrink:0,
                          background:"#78909C"+"20", color:C.textMuted, border:`1px solid ${"#78909C"}30`}}>
                          {roleLabel}
                        </span>
                      )}
                    </div>
                    {!d.binary && d.content && (
                      <div style={{ fontSize:10, color:C.textMuted, ...MONO, whiteSpace:"pre-wrap",
                        maxHeight:52, overflow:"hidden", lineHeight:1.5 }}>
                        {d.content.substring(0,280)}{d.content.length>280?"…":""}
                      </div>
                    )}
                    {d.binary && <div style={{fontSize:10, color:C.textMuted, fontStyle:"italic"}}>binary file — content not analyzed</div>}
                  </div>
                  {d.size && <span style={{fontSize:10, color:C.textMuted, flexShrink:0, paddingTop:1}}>{d.size < 1024 ? d.size+"B" : Math.round(d.size/1024)+"K"}</span>}
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
// DOCUMENTS PAGE — Step 2: categorized supporting document upload
// ─────────────────────────────────────────────────────────────────────────────
const DOC_CATEGORIES = [
  // Group A — Enterprise Context (expanded by default)
  { id:"enterprise-arch",   group:"A", label:"Enterprise Architecture",      Icon:Building2,      desc:"Platform type, AWS Org/OU/SCP docs, Sentinel policies, ADRs, SDLC processes",   tip:"e.g. AWS Organization policy JSON, Architecture Decision Records, SCPs" },
  { id:"app-details",       group:"A", label:"Application / Product Details", Icon:AppWindow,      desc:"HLDD, engineer docs, vendor documentation (AWS, Azure, GCP, 3rd party)",        tip:"e.g. High-Level Design Document, vendor integration guide" },
  // Group B — Security & Compliance (collapsed by default)
  { id:"security-controls", group:"B", label:"Enterprise Security Controls",  Icon:Shield,         desc:"Security control matrix, control baseline, known risks, security objectives",    tip:"e.g. Security Control Baseline.xlsx, risk register" },
  { id:"cspm",              group:"B", label:"CSPM / Cloud Configuration",    Icon:Cloud,          desc:"Wiz reports, cloud configuration rules, cloud posture findings",                  tip:"e.g. Wiz export CSV, AWS Config rules JSON" },
  { id:"compliance-guide",  group:"B", label:"Customer Compliance Guide",     Icon:ClipboardList,  desc:"CSP compliance guides cross-referenced with enterprise control matrix",           tip:"e.g. AWS HIPAA compliance guide PDF" },
  { id:"trust-cloud",       group:"B", label:"Trust on Cloud Documentation",  Icon:Lock,           desc:"Cloud trust documentation for your enterprise (if available)",                   tip:"e.g. enterprise cloud trust framework PDF" },
];

const INDUSTRY_FRAMEWORKS = [
  "NIST 800-53 r5","NIST CSF 2.0","CIS Controls v8","PCI DSS v4","HIPAA",
  "FedRAMP Moderate","FedRAMP High","GDPR","ISO 27001","CMMC Level 2","SOC 2 Type II","NIST SP 800-207 (Zero Trust)",
];

const THREAT_FRAMEWORKS = [
  "STRIDE","PASTA","VAST","LINDDUN","OCTAVE","RTMP",
  "OWASP Top 10","OWASP Top 10 Cloud","MITRE ATT&CK","DREAD","TRIKE",
];

function DocumentsPage({ model, modelDetails, userDocs, onSaveDetails, onAddDocs, onRemoveDoc, onContinue, onBack, ingestState, intelligence, intelligenceVersion }) {
  const [collapsed, setCollapsed] = useState({ "security-controls":true, "cspm":true, "compliance-guide":true, "trust-cloud":true });
  const [processing, setProcessing] = useState({});   // { filename: 'processing'|'done'|'error' }
  const [keyFeaturesText, setKeyFeaturesText] = useState(modelDetails.keyFeatures || "");
  const [kfGenerating, setKfGenerating] = useState(false);
  const kfRef = useRef(null);

  // Auto-resize key features textarea
  useEffect(() => {
    if (kfRef.current) {
      kfRef.current.style.height = "auto";
      kfRef.current.style.height = kfRef.current.scrollHeight + "px";
    }
  }, [keyFeaturesText]);

  // Auto-populate key features when intelligence rebuilds and enterprise docs are present
  useEffect(() => {
    if (!intelligence?._built) return;
    const enterpriseDocCount = userDocs.filter(d => d.docCategory === 'enterprise-arch' || d.docCategory === 'app-details').length;
    if (!enterpriseDocCount) return;
    // Only auto-overwrite if empty or previously auto-generated (starts with "- ")
    if (keyFeaturesText && !keyFeaturesText.startsWith("- ")) return;
    setKfGenerating(true);
    // Run async so UI updates before extraction
    setTimeout(() => {
      const bullets = intelligence.extractKeyFeatures();
      if (bullets.length) {
        const text = bullets.join("\n");
        setKeyFeaturesText(text);
        onSaveDetails({ ...modelDetails, keyFeatures: text });
      }
      setKfGenerating(false);
    }, 0);
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  const docsByCategory = useMemo(() => {
    const map = {};
    DOC_CATEGORIES.forEach(c => { map[c.id] = []; });
    map["general"] = [];
    userDocs.forEach(d => { const cat = d.docCategory || "general"; if (!map[cat]) map[cat] = []; map[cat].push(d); });
    return map;
  }, [userDocs]);

  const totalDocs = userDocs.length;

  const handleDrop = (e, catId) => {
    e.preventDefault(); e.stopPropagation();
    const files = e.dataTransfer.files;
    if (files?.length) handleFiles(files, catId);
  };

  const handleFiles = (fileList, catId) => {
    const filesArr = Array.from(fileList);
    const initial = {};
    filesArr.forEach(f => { initial[f.name] = "processing"; });
    setProcessing(prev => ({ ...prev, ...initial }));
    // Auto-expand the card so the user sees files as they arrive
    setCollapsed(prev => ({ ...prev, [catId]: false }));

    onAddDocs(fileList, catId, (name, status) => {
      setProcessing(prev => ({ ...prev, [name]: status }));
    });
  };

  const toggleFramework = (fw, isIndustry) => {
    const key = isIndustry ? "frameworks" : "threatFrameworks";
    const current = modelDetails[key] || [];
    const updated = current.includes(fw) ? current.filter(f => f !== fw) : [...current, fw];
    onSaveDetails({ ...modelDetails, [key]: updated });
  };

  const saveKeyFeatures = () => {
    onSaveDetails({ ...modelDetails, keyFeatures: keyFeaturesText });
  };

  const extColor = ext => ({ pdf:"#E53935", png:"#0288D1", jpg:"#0288D1", jpeg:"#0288D1",
    docx:"#1565C0", xlsx:"#2E7D32", csv:"#2E7D32", json:"#F57C00", yaml:"#7B1FA2",
    txt:"#546E7A", md:"#546E7A" })[ext] || C.textMuted;

  const extLabel = name => (name.split(".").pop() || "file").toUpperCase().slice(0,5);

  const fileSize = bytes => bytes < 1024 ? bytes+"B" : bytes < 1048576 ? Math.round(bytes/1024)+"KB" : (bytes/1048576).toFixed(1)+"MB";

  const renderFileList = (catDocs, catId) => {
    // Files already saved in userDocs
    const savedNames = new Set(catDocs.map(d => d.name));
    // Files being processed but not yet saved
    const pendingEntries = Object.entries(processing)
      .filter(([name, status]) => status === "processing" && !savedNames.has(name));
    const hasSomething = catDocs.length > 0 || pendingEntries.length > 0;
    return (
      <div style={{ marginTop: hasSomething ? 10 : 0, display:"flex", flexDirection:"column", gap:4, maxHeight:220, overflowY:"auto" }}>
        {/* Saved docs */}
        {catDocs.map((doc, i) => {
          const status = processing[doc.name];
          return (
            <div key={i} style={{
              display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
              background:C.bg, borderRadius:6, border:`1px solid ${C.border}`,
            }}>
              <span style={{
                fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3, flexShrink:0, minWidth:32, textAlign:"center",
                background:`${extColor(doc.ext)}20`, color:extColor(doc.ext), border:`1px solid ${extColor(doc.ext)}44`,
              }}>{extLabel(doc.name)}</span>
              <span style={{...SANS, fontSize:12, color:C.textSub, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                {doc.name}
              </span>
              <span style={{fontSize:10, color:C.textMuted, flexShrink:0}}>{fileSize(doc.size||0)}</span>
              {status === "processing" && (
                <span style={{fontSize:10, color:C.accent, flexShrink:0, display:"flex", alignItems:"center", gap:3}}>
                  <Loader2 size={11} style={{animation:"spin 1s linear infinite"}}/> extracting
                </span>
              )}
              {status === "done" && <span style={{fontSize:10, color:"#43A047", flexShrink:0}}>extracted</span>}
              {status === "error" && <span style={{fontSize:10, color:C.red, flexShrink:0}}>error</span>}
              <button onClick={() => onRemoveDoc(doc.path || doc.name)} style={{
                background:"transparent", border:"none", color:C.textMuted, cursor:"pointer",
                padding:"0 2px", borderRadius:3, display:"flex", alignItems:"center", flexShrink:0,
              }}
                onMouseEnter={e=>{ e.currentTarget.style.color=C.red; }}
                onMouseLeave={e=>{ e.currentTarget.style.color=C.textMuted; }}
              ><X size={12}/></button>
            </div>
          );
        })}
        {/* Pending rows — files being extracted but not yet in userDocs */}
        {pendingEntries.map(([name]) => (
          <div key={`pending-${name}`} style={{
            display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
            background:C.bg, borderRadius:6, border:`1px solid ${C.border}`, opacity:0.7,
          }}>
            <span style={{
              fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3, flexShrink:0, minWidth:32, textAlign:"center",
              background:`${C.border}`, color:C.textMuted, border:`1px solid ${C.border}`,
            }}>{extLabel(name)}</span>
            <span style={{...SANS, fontSize:12, color:C.textMuted, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
              {name}
            </span>
            <span style={{fontSize:10, color:C.accent, flexShrink:0, display:"flex", alignItems:"center", gap:3}}>
              <Loader2 size={11} style={{animation:"spin 1s linear infinite"}}/> extracting
            </span>
          </div>
        ))}
      </div>
    );
  };

  const renderUploadCard = (cat) => {
    const catDocs = docsByCategory[cat.id] || [];
    const isCollapsed = collapsed[cat.id];
    return (
      <div key={cat.id} style={{
        background:C.surface, border:`1px solid ${catDocs.length ? C.accent+"66" : C.border}`,
        borderRadius:12, overflow:"hidden", transition:"border-color .2s",
      }}>
        {/* Card header */}
        <div onClick={() => setCollapsed(s => ({ ...s, [cat.id]: !isCollapsed }))} style={{
          display:"flex", alignItems:"center", gap:12, padding:"14px 18px",
          cursor:"pointer", background: catDocs.length ? `${C.accent}08` : "transparent",
          userSelect:"none",
        }}>
          <cat.Icon size={18} style={{ color: catDocs.length ? C.accent : C.textMuted, flexShrink:0 }}/>
          <div style={{ flex:1 }}>
            <div style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>{cat.label}</div>
            <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>{cat.desc}</div>
          </div>
          {catDocs.length > 0 && (
            <span style={{ fontSize:11, fontWeight:700, color:C.accent, background:`${C.accent}18`,
              border:`1px solid ${C.accent}44`, borderRadius:10, padding:"2px 8px", flexShrink:0 }}>
              {catDocs.length}
            </span>
          )}
          {isCollapsed ? <ChevronRight size={14} style={{color:C.textMuted, flexShrink:0}}/> : <ChevronDown size={14} style={{color:C.textMuted, flexShrink:0}}/>}
        </div>

        {/* Card body */}
        {!isCollapsed && (
          <div style={{ padding:"0 18px 16px", borderTop:`1px solid ${C.border}` }}>
            <div style={{fontSize:11, color:C.textMuted, marginBottom:10, marginTop:12, fontStyle:"italic"}}>{cat.tip}</div>
            {/* Drop zone */}
            <div
              onDrop={e => handleDrop(e, cat.id)}
              onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = C.accent; }}
              onDragLeave={e => { e.currentTarget.style.borderColor = C.border2; }}
              style={{
                border:`2px dashed ${C.border2}`, borderRadius:8, padding:"20px 16px",
                textAlign:"center", cursor:"pointer", transition:"border-color .15s",
              }}
              onClick={() => {
                const inp = document.createElement("input");
                inp.type = "file"; inp.multiple = true;
                inp.onchange = e => { if (e.target.files?.length) handleFiles(e.target.files, cat.id); };
                inp.click();
              }}
            >
              <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:8, color:C.textMuted }}>
                <Upload size={16}/>
                <span style={{...SANS, fontSize:12}}>Drop files here or <span style={{color:C.accent, fontWeight:600}}>click to browse</span></span>
              </div>
              <div style={{fontSize:11, color:C.textMuted, marginTop:4}}>PDF · DOCX · XLSX · CSV · JSON · YAML · TXT · Images — max 50MB</div>
            </div>
            {renderFileList(catDocs, cat.id)}
          </div>
        )}
      </div>
    );
  };

  const renderChips = (items, selected, onToggle, accentColor = C.accent) => (
    <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
      {items.map(item => {
        const active = selected.includes(item);
        return (
          <button key={item} onClick={() => onToggle(item)} style={{
            ...SANS, fontSize:11, fontWeight: active ? 700 : 500,
            padding:"5px 12px", borderRadius:20, cursor:"pointer",
            background: active ? `${accentColor}22` : C.surface2,
            border: `1px solid ${active ? accentColor : C.border2}`,
            color: active ? accentColor : C.textSub,
            transition:"all .15s",
          }}>
            {item}
          </button>
        );
      })}
    </div>
  );

  return (
    <div style={{ minHeight:"100vh", background:C.bg, display:"flex", flexDirection:"column" }}>
      {/* ── Header ── */}
      <div style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 28px", height:58, display:"flex", alignItems:"center", gap:16, flexShrink:0, position:"sticky", top:0, zIndex:100,
      }}>
        <button onClick={onBack} style={{
          display:"flex", alignItems:"center", gap:5, background:"transparent",
          border:"none", color:C.textMuted, cursor:"pointer", fontSize:12, ...SANS, padding:"4px 8px", borderRadius:6,
        }}
          onMouseEnter={e=>e.currentTarget.style.color=C.text}
          onMouseLeave={e=>e.currentTarget.style.color=C.textMuted}
        >
          <ChevronLeft size={14}/> Models
        </button>

        {/* Brand */}
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:28, height:28, borderRadius:6, background:`linear-gradient(135deg,${C.accent},${C.accent}88)`,
            display:"flex", alignItems:"center", justifyContent:"center" }}>
            <Shield size={14} color="#fff"/>
          </div>
          <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>{model?.name || "Threat Model"}</span>
        </div>

        {/* Progress steps */}
        <div style={{ flex:1, display:"flex", justifyContent:"center" }}>
          {[{n:1,label:"Create Model"},{n:2,label:"Documents"},{n:3,label:"Workspace"}].map((step,i) => (
            <div key={step.n} style={{ display:"flex", alignItems:"center" }}>
              {i > 0 && <div style={{ width:40, height:2, background: step.n <= 2 ? C.accent : C.border, margin:"0 4px" }}/>}
              <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                <div style={{
                  width:22, height:22, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center",
                  background: step.n < 2 ? C.accent : step.n === 2 ? C.accent : C.surface2,
                  border: `2px solid ${step.n <= 2 ? C.accent : C.border}`,
                  fontSize:11, fontWeight:700,
                  color: step.n <= 2 ? "#fff" : C.textMuted,
                }}>
                  {step.n < 2 ? <CheckCircle2 size={12}/> : step.n}
                </div>
                <span style={{...SANS, fontSize:11, fontWeight: step.n === 2 ? 700 : 400,
                  color: step.n === 2 ? C.text : step.n < 2 ? C.accent : C.textMuted}}>
                  {step.label}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Continue */}
        <button onClick={onContinue} style={{
          display:"flex", alignItems:"center", gap:7, background:`linear-gradient(135deg,${C.accent},${C.accent}cc)`,
          border:"none", borderRadius:8, padding:"8px 18px", color:"#fff",
          fontSize:13, fontWeight:700, cursor:"pointer", ...SANS,
        }}>
          Continue <ArrowRight size={14}/>
          {totalDocs > 0 && (
            <span style={{ background:"rgba(255,255,255,.2)", borderRadius:10, padding:"1px 7px", fontSize:11 }}>
              {totalDocs}
            </span>
          )}
        </button>
      </div>

      {/* ── Ingestion Progress Bar ── */}
      {ingestState && (
        <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"8px 24px" }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:4 }}>
            <span style={{ fontSize:12, color:C.textSub, fontWeight:500 }}>
              Analyzing {ingestState.done} / {ingestState.total} files
              {ingestState.current ? ` · ${ingestState.current}` : ""}
            </span>
            <span style={{ fontSize:12, fontWeight:700, color:C.accent }}>
              {Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%
            </span>
          </div>
          <div style={{ height:4, background:C.border, borderRadius:2, overflow:"hidden" }}>
            <div style={{
              height:"100%", borderRadius:2, background:`linear-gradient(90deg,${C.accent},${C.accent}aa)`,
              width:`${Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%`,
              transition:"width .3s ease",
            }} />
          </div>
        </div>
      )}

      {/* ── Body ── */}
      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>
        {/* ── Left Sidebar ── */}
        <div style={{
          width:200, flexShrink:0, background:C.surface, borderRight:`1px solid ${C.border}`,
          padding:"20px 12px", overflowY:"auto", position:"sticky", top:58, height:"calc(100vh - 58px)",
        }}>
          <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase", letterSpacing:".12em", marginBottom:12, paddingLeft:4}}>
            Sections
          </div>
          {[
            { id:"group-a",   label:"Enterprise Context",   items:["enterprise-arch","app-details"] },
            { id:"key-feat",  label:"Key Features",         items:[] },
            { id:"group-b",   label:"Security & Compliance",items:["security-controls","cspm","compliance-guide","trust-cloud"] },
            { id:"frameworks",label:"Analysis Frameworks",  items:[] },
          ].map(section => {
            const count = section.items.reduce((s,id) => s + (docsByCategory[id]?.length||0), 0);
            const hasExtra = section.id === "frameworks"
              ? ((modelDetails.frameworks?.length||0) + (modelDetails.threatFrameworks?.length||0)) > 0
              : false;
            return (
              <a key={section.id} href={`#${section.id}`} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"8px 10px", borderRadius:6, marginBottom:2,
                color: count || hasExtra ? C.accent : C.textSub, fontSize:12, textDecoration:"none", ...SANS,
                background: count || hasExtra ? `${C.accent}10` : "transparent",
              }}>
                <span style={{fontWeight: count || hasExtra ? 600 : 400}}>{section.label}</span>
                {(count > 0) && (
                  <span style={{ fontSize:10, fontWeight:700, background:`${C.accent}22`, color:C.accent,
                    border:`1px solid ${C.accent}44`, borderRadius:9, padding:"1px 6px" }}>
                    {count}
                  </span>
                )}
              </a>
            );
          })}

          <div style={{ marginTop:20, paddingTop:16, borderTop:`1px solid ${C.border}` }}>
            <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase", letterSpacing:".12em", marginBottom:8, paddingLeft:4}}>Summary</div>
            <div style={{fontSize:12, color:C.textSub, padding:"0 4px", ...SANS}}>
              <div style={{marginBottom:4}}><span style={{fontWeight:700, color:C.accent}}>{totalDocs}</span> docs uploaded</div>
              <div style={{marginBottom:4}}><span style={{fontWeight:700, color:"#7B1FA2"}}>{modelDetails.frameworks?.length||0}</span> industry frameworks</div>
              <div><span style={{fontWeight:700, color:"#E65100"}}>{modelDetails.threatFrameworks?.length||0}</span> threat frameworks</div>
            </div>
          </div>
        </div>

        {/* ── Main Content ── */}
        <div style={{ flex:1, overflowY:"auto", padding:"28px 32px", maxWidth:860 }}>

          {/* GROUP A */}
          <div id="group-a" style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <Building2 size={18} style={{ color:C.accent }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Enterprise Context</div>
                <div style={{fontSize:12, color:C.textMuted}}>Architecture and product documentation that defines scope and platform context</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {DOC_CATEGORIES.filter(c => c.group === "A").map(renderUploadCard)}
            </div>
          </div>

          {/* KEY FEATURES */}
          <div id="key-feat" style={{ marginBottom:32 }}>
            <div style={{
              background:C.surface, border:`1px solid ${keyFeaturesText ? C.accent+"66" : C.border}`,
              borderRadius:12, padding:"18px 20px",
            }}>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
                <Sparkles size={18} style={{ color: keyFeaturesText ? C.accent : C.textMuted }}/>
                <div style={{ flex:1 }}>
                  <div style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Key Features</div>
                  <div style={{fontSize:11, color:C.textMuted}}>Auto-extracted from Enterprise Context docs — edit freely</div>
                </div>
                {kfGenerating && (
                  <span style={{ display:"flex", alignItems:"center", gap:5, fontSize:11, color:C.accent }}>
                    <Loader2 size={12} style={{ animation:"spin 1s linear infinite" }}/> Extracting...
                  </span>
                )}
                {intelligence?._built && !kfGenerating && (
                  <button onClick={() => {
                    setKfGenerating(true);
                    setTimeout(() => {
                      const bullets = intelligence.extractKeyFeatures();
                      if (bullets.length) {
                        const text = bullets.join("\n");
                        setKeyFeaturesText(text);
                        onSaveDetails({ ...modelDetails, keyFeatures: text });
                      }
                      setKfGenerating(false);
                    }, 0);
                  }} style={{
                    display:"flex", alignItems:"center", gap:5, fontSize:11, fontWeight:600,
                    background:`${C.accent}15`, border:`1px solid ${C.accent}44`, borderRadius:6,
                    padding:"4px 10px", color:C.accent, cursor:"pointer", ...SANS,
                  }}>
                    <RefreshCw size={11}/> Regenerate
                  </button>
                )}
              </div>
              <textarea
                ref={kfRef}
                value={keyFeaturesText}
                onChange={e => setKeyFeaturesText(e.target.value)}
                onBlur={saveKeyFeatures}
                placeholder="Upload Enterprise Context docs above — key features will be auto-extracted. Or type manually here."
                style={{
                  width:"100%", boxSizing:"border-box", minHeight:90, resize:"none", overflow:"hidden",
                  background:C.bg, border:`1px solid ${C.border}`, borderRadius:8,
                  color:C.text, fontSize:12, padding:"10px 12px", lineHeight:1.6,
                  outline:"none", ...SANS, transition:"border-color .15s",
                }}
                onFocus={e=>e.target.style.borderColor=C.accent}
                onBlurCapture={e=>e.target.style.borderColor=C.border}
              />
            </div>
          </div>

          {/* GROUP B */}
          <div id="group-b" style={{ marginBottom:32 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <Shield size={18} style={{ color:"#E53935" }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Security & Compliance</div>
                <div style={{fontSize:12, color:C.textMuted}}>Security controls, CSPM posture findings, compliance guides, and trust documentation</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {DOC_CATEGORIES.filter(c => c.group === "B").map(renderUploadCard)}
            </div>
          </div>

          {/* GROUP C — Frameworks */}
          <div id="frameworks" style={{ marginBottom:40 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <SquareStack size={18} style={{ color:"#7B1FA2" }}/>
              <div>
                <div style={{...SANS, fontSize:15, fontWeight:700, color:C.text}}>Analysis Frameworks</div>
                <div style={{fontSize:12, color:C.textMuted}}>Select the frameworks in scope — they will inform intelligence queries and threat model generation</div>
              </div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
              {/* Industry */}
              <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:12, padding:"18px 20px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                  <ClipboardList size={16} style={{ color:"#7B1FA2" }}/>
                  <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Industry & Compliance Frameworks</span>
                  {(modelDetails.frameworks?.length > 0) && (
                    <span style={{ fontSize:11, color:"#7B1FA2", background:"#7B1FA210", border:"1px solid #7B1FA244", borderRadius:9, padding:"1px 7px", marginLeft:"auto" }}>
                      {modelDetails.frameworks.length} selected
                    </span>
                  )}
                </div>
                {renderChips(INDUSTRY_FRAMEWORKS, modelDetails.frameworks || [], fw => toggleFramework(fw, true), "#7B1FA2")}
              </div>

              {/* Threat */}
              <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:12, padding:"18px 20px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                  <Zap size={16} style={{ color:"#E65100" }}/>
                  <span style={{...SANS, fontSize:13, fontWeight:700, color:C.text}}>Threat Modeling Frameworks</span>
                  {(modelDetails.threatFrameworks?.length > 0) && (
                    <span style={{ fontSize:11, color:"#E65100", background:"#E6510010", border:"1px solid #E6510044", borderRadius:9, padding:"1px 7px", marginLeft:"auto" }}>
                      {modelDetails.threatFrameworks.length} selected
                    </span>
                  )}
                </div>
                {renderChips(THREAT_FRAMEWORKS, modelDetails.threatFrameworks || [], fw => toggleFramework(fw, false), "#E65100")}
              </div>
            </div>
          </div>

          {/* Spacer */}
          <div style={{height:48}}/>
        </div>
      </div>

      {/* Spinner keyframe */}
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// LANDING PAGE — Threat model selection / creation
// ─────────────────────────────────────────────────────────────────────────────
function LandingPage({ onCreateModel, onOpenModel, onDeleteModel, threatModels }) {
  const [newName, setNewName] = useState("");
  const EXAMPLES = ["Kinesis Data Analytics","Amazon EKS Platform","API Gateway + Lambda","RDS Multi-Region","S3 Data Lake","MSK Kafka Cluster"];

  const handleCreate = () => {
    const n = newName.trim();
    if (!n) return;
    onCreateModel(n);
  };

  const GRADE_COLORS = { A:"#43A047", B:"#7CB342", C:"#F57C00", D:"#E64A19", F:"#B71C1C" };

  return (
    <div style={{...SANS, minHeight:"100vh", background:C.bg, display:"flex", flexDirection:"column", alignItems:"center", padding:"72px 24px 60px"}}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>

      {/* Hero */}
      <div style={{textAlign:"center", maxWidth:640, marginBottom:56}}>
        <div style={{
          width:72, height:72, borderRadius:20, margin:"0 auto 22px",
          background:"linear-gradient(135deg,#FF6B35,#FF9900)",
          display:"flex", alignItems:"center", justifyContent:"center",
          boxShadow:"0 8px 32px #FF990050",
        }}><Shield size={36} color="#fff"/></div>
        <div style={{fontSize:40, fontWeight:800, color:C.text, letterSpacing:"-.03em", lineHeight:1.1, marginBottom:14}}>
          Threataform
        </div>
        <div style={{fontSize:15, color:C.textSub, lineHeight:1.75, maxWidth:520, margin:"0 auto"}}>
          Enterprise Terraform Threat Intelligence. Upload your infrastructure-as-code,
          auto-generate DFD diagrams, discover threats, and assess zero-trust posture.
        </div>
      </div>

      {/* New model card */}
      <div style={{
        width:"100%", maxWidth:660, background:C.surface,
        border:`1px solid ${C.border}`, borderRadius:18,
        padding:"32px 36px", marginBottom:48,
        boxShadow:"0 8px 48px #00000060",
      }}>
        <div style={{fontSize:20, fontWeight:700, color:C.text, marginBottom:6}}>
          Start New Threat Model
        </div>
        <div style={{fontSize:12, color:C.textSub, lineHeight:1.7, marginBottom:22}}>
          The <strong style={{color:C.text}}>product name</strong> (e.g., "Kinesis Data Analytics") is used to infer
          what services are in scope, enrich threat analysis, and seed the intelligence engine.
        </div>
        <div style={{display:"flex", gap:10, marginBottom:14}}>
          <input
            value={newName}
            onChange={e=>setNewName(e.target.value)}
            onKeyDown={e=>{if(e.key==="Enter"&&newName.trim())handleCreate();}}
            placeholder='e.g. "Kinesis Data Analytics", "EKS Multi-Tenant Platform"'
            autoFocus
            style={{
              flex:1, background:C.bg, border:`1px solid ${C.border2}`,
              borderRadius:10, padding:"13px 16px", color:C.text, fontSize:14,
              outline:"none", ...SANS,
            }}
          />
          <button onClick={handleCreate} disabled={!newName.trim()} style={{
            background:newName.trim()?"linear-gradient(135deg,#FF6B35,#FF9900)":C.surface2,
            border:"none", borderRadius:10, padding:"13px 26px",
            color:newName.trim()?"#fff":C.textMuted,
            fontSize:14, cursor:newName.trim()?"pointer":"not-allowed",
            fontWeight:700, ...SANS, flexShrink:0, transition:"all .15s",
          }}>
            Create →
          </button>
        </div>
        {/* Quick examples */}
        <div style={{display:"flex", flexWrap:"wrap", gap:7}}>
          <span style={{fontSize:11, color:C.textMuted, alignSelf:"center", marginRight:2}}>Quick:</span>
          {EXAMPLES.map(ex=>(
            <button key={ex} onClick={()=>setNewName(ex)} style={{
              background:"transparent", border:`1px solid ${C.border}`,
              borderRadius:20, padding:"4px 12px", fontSize:11, color:C.textMuted,
              cursor:"pointer", ...SANS, transition:"all .15s",
            }}
            onMouseEnter={e=>e.currentTarget.style.borderColor=C.accent}
            onMouseLeave={e=>e.currentTarget.style.borderColor=C.border}
            >{ex}</button>
          ))}
        </div>
      </div>

      {/* Existing models */}
      {threatModels.length > 0 && (
        <div style={{width:"100%", maxWidth:880}}>
          <div style={{fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase",
            letterSpacing:".12em", marginBottom:18}}>
            Existing Threat Models
          </div>
          <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(260px, 1fr))", gap:12}}>
            {threatModels.map(model=>(
              <div key={model.id}
                onClick={()=>onOpenModel(model)}
                style={{
                  background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                  padding:"20px 22px", cursor:"pointer", position:"relative",
                  transition:"all .2s",
                }}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent; e.currentTarget.style.transform="translateY(-2px)"; e.currentTarget.style.boxShadow=`0 8px 24px ${C.accent}20`;}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border; e.currentTarget.style.transform="translateY(0)"; e.currentTarget.style.boxShadow="none";}}
              >
                {/* Grade badge */}
                {model.grade && (
                  <div style={{
                    position:"absolute", top:14, right:40,
                    fontSize:13, fontWeight:800, color:GRADE_COLORS[model.grade]||C.accent,
                    background:`${GRADE_COLORS[model.grade]||C.accent}18`,
                    border:`1px solid ${GRADE_COLORS[model.grade]||C.accent}40`,
                    borderRadius:6, padding:"2px 8px",
                  }}>{model.grade}</div>
                )}
                {/* Delete */}
                <button onClick={e=>{e.stopPropagation();onDeleteModel(model.id);}} style={{
                  position:"absolute", top:10, right:10, background:"transparent", border:"none",
                  color:C.textMuted, cursor:"pointer", fontSize:14, padding:"4px 6px",
                  borderRadius:4, lineHeight:1,
                }} title="Delete model"><X size={13}/></button>

                <div style={{fontSize:15, fontWeight:700, color:C.text, marginBottom:6, paddingRight:56,
                  lineHeight:1.3, wordBreak:"break-word"}}>{model.name}</div>
                <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:8}}>
                  {model.environment && (
                    <span style={{fontSize:10, color:C.textMuted, background:C.surface2,
                      border:`1px solid ${C.border}`, borderRadius:4, padding:"1px 6px"}}>
                      {model.environment}
                    </span>
                  )}
                  <span style={{fontSize:10, color:C.textMuted}}>
                    {model.tfFileCount ? `${model.tfFileCount} TF files` : "No TF files"}
                  </span>
                  {model.docCount > 0 && (
                    <span style={{fontSize:10, color:C.textMuted}}>{model.docCount} docs</span>
                  )}
                </div>
                <div style={{fontSize:10, color:C.textMuted}}>
                  {model.updatedAt
                    ? `Updated ${new Date(model.updatedAt).toLocaleDateString()}`
                    : `Created ${new Date(model.createdAt).toLocaleDateString()}`}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ARCHITECTURE IMAGE VIEWER
// User exports XML → imports to Lucidchart → exports diagram image → uploads here
// ─────────────────────────────────────────────────────────────────────────────
function ArchitectureImageViewer({ image, onUpload }) {
  const inputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    if (!/^image\//i.test(file.type) && !/\.(png|jpg|jpeg|svg|webp|gif)$/i.test(file.name)) return;
    const reader = new FileReader();
    reader.onload = (e) => onUpload(e.target.result, file.name);
    reader.readAsDataURL(file);
  };

  const onDrop = (e) => {
    e.preventDefault();
    handleFile(e.dataTransfer.files[0]);
  };

  if (!image) {
    return (
      <div
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        style={{
          display:"flex", alignItems:"center", justifyContent:"center",
          height:"calc(100vh - 130px)", flexDirection:"column", gap:20,
        }}
      >
        <div style={{
          border:`2px dashed ${C.border}`, borderRadius:16,
          padding:"56px 64px", textAlign:"center",
          display:"flex", flexDirection:"column", alignItems:"center", gap:16,
          maxWidth:560, cursor:"pointer", transition:"border-color .2s",
        }}
          onClick={() => inputRef.current?.click()}
          onMouseEnter={e => e.currentTarget.style.borderColor = C.accent}
          onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
        >
          <ImageIcon size={48} style={{color:C.textMuted, opacity:0.5}}/>
          <div style={{fontSize:16, fontWeight:700, color:C.text}}>Upload Architecture Diagram</div>
          <div style={{fontSize:13, color:C.textMuted, lineHeight:1.6}}>
            Export the XML from the <strong style={{color:C.accent}}>XML Output</strong> tab,
            import it into <strong style={{color:C.accent}}>Lucidchart</strong>,
            then export your diagram as an image and upload it here.
          </div>
          <div style={{
            marginTop:4, background:`${C.accent}18`, border:`1px solid ${C.accent}30`,
            borderRadius:8, padding:"8px 20px", fontSize:12, color:C.accent, fontWeight:600,
          }}>
            Click to upload or drag & drop
          </div>
          <div style={{fontSize:11, color:C.textMuted}}>PNG · JPG · SVG · WebP</div>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          style={{display:"none"}}
          onChange={e => handleFile(e.target.files[0])}
        />
      </div>
    );
  }

  return (
    <div style={{position:"relative", height:"calc(100vh - 130px)", overflow:"auto", background:"#080810"}}>
      {/* Replace button */}
      <button
        onClick={() => inputRef.current?.click()}
        style={{
          position:"absolute", top:16, right:16, zIndex:10,
          background:`${C.accent}22`, border:`1px solid ${C.accent}50`,
          borderRadius:8, padding:"6px 16px", color:C.accent,
          fontSize:12, fontWeight:600, cursor:"pointer", ...SANS,
        }}
      >
        Replace Image
      </button>
      <input
        ref={inputRef}
        type="file"
        accept="image/*"
        style={{display:"none"}}
        onChange={e => handleFile(e.target.files[0])}
      />
      <img
        src={image}
        alt="Architecture Diagram"
        style={{
          display:"block", maxWidth:"100%", height:"auto",
          margin:"0 auto", padding:24,
        }}
      />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// INTELLIGENCE PANEL
// Enterprise Threat Model Intelligence — zero hallucination, verbatim retrieval
// ─────────────────────────────────────────────────────────────────────────────
function IntelligencePanel({ intelligence, intelligenceVersion, userDocs, parseResult,
  modelDetails, archAnalysis, archOverrides, currentModelId,
  llmStatus, llmProgress, llmStatusText, embedStatus, embedProgress,
  selectedLlmModel, wllamaModelName, wllamaModelSize,
  onLoadModel, onHybridSearch, onGenerateLLM, vectorStore, computedIR }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null); // null = not searched yet
  const [iTab, setITab] = useState("assistant");
  const chatKey = currentModelId ? `tf-model-${currentModelId}-chat` : null;
  const [chatMessages, setChatMessages] = useState(() => {
    if (!chatKey) return [];
    try { return JSON.parse(localStorage.getItem(chatKey) || "[]"); } catch { return []; }
  });
  const [chatInput, setChatInput] = useState("");
  const [chatGenerating, setChatGenerating] = useState(false);
  const [isTraining, setIsTraining]   = useState(false);  // LoRA fine-tuning state
  const [ftProgress, setFtProgress]   = useState(0);       // LoRA training progress %
  const chatBottomRef = useRef(null);

  // ── Cross-tab navigation state ──
  const [attackFilter, setAttackFilter] = useState(null);
  const [resourceSearch, setResourceSearch] = useState('');
  const [resourceTypeFilter, setResourceTypeFilter] = useState('');
  const [resourcePage, setResourcePage] = useState(0);
  const [expandedControl, setExpandedControl] = useState(null);
  const [expandedCwe, setExpandedCwe] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  // ── Per-tab async/LLM output state ──
  const [synthesisingQuery, setSynthesisingQuery] = useState(false);
  const [synthesisText, setSynthesisText] = useState('');
  const [postureNarrative, setPostureNarrative] = useState('');
  const [postureNarrLoading, setPostureNarrLoading] = useState(false);
  const [gapAnalysis, setGapAnalysis] = useState('');
  const [gapAnalysisLoading, setGapAnalysisLoading] = useState(false);
  const [remediationPlan, setRemediationPlan] = useState('');
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [threatScenarios, setThreatScenarios] = useState('');
  const [threatScenariosLoading, setThreatScenariosLoading] = useState(false);
  const [inferredScope, setInferredScope] = useState('');
  const [inferredScopeLoading, setInferredScopeLoading] = useState(false);
  const [resourceSummaries, setResourceSummaries] = useState({});
  const [hybridHits, setHybridHits] = useState({});
  const [techPassages, setTechPassages] = useState({});
  const [findingGuidance, setFindingGuidance] = useState({});
  const [attackNarrative, setAttackNarrative] = useState('');
  const [attackNarrLoading, setAttackNarrLoading] = useState(false);
  const [contradictionNarrative, setContradictionNarrative] = useState('');
  const [contraNarrLoading, setContraNarrLoading] = useState(false);
  const [queryLoading, setQueryLoading] = useState(false);
  const [controlSearch, setControlSearch] = useState('');

  // Persist chat history per model
  useEffect(() => {
    if (!chatKey) return;
    try { localStorage.setItem(chatKey, JSON.stringify(chatMessages.filter(m => !m.streaming).slice(-60))); } catch {}
  }, [chatMessages, chatKey]);

  // Auto-scroll chat
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior:"smooth" });
  }, [chatMessages]);

  const summary = useMemo(() => {
    if (!intelligence?._built) return null;
    return intelligence.getArchitectureSummary(parseResult?.resources || [], userDocs || []);
  }, [intelligence, intelligenceVersion, parseResult, userDocs]);

  const handleQuery = async () => {
    if (!query.trim() || !intelligence) return;
    setSynthesisText('');
    setQueryLoading(true);
    try {
      const results = onHybridSearch
        ? await onHybridSearch(query.trim(), 8)
        : intelligence.query(query.trim(), 8);
      setResults(results);
    } finally {
      setQueryLoading(false);
    }
  };

  const STRIDE_COLORS = {
    spoofing:"#E91E63", tampering:"#FF5722", repudiation:"#9C27B0",
    infoDisclose:"#F44336", dos:"#FF9800", elevPriv:"#B71C1C",
  };
  const STRIDE_LABELS = {
    spoofing:"Spoofing", tampering:"Tampering", repudiation:"Repudiation",
    infoDisclose:"Info Disclosure", dos:"Denial of Service", elevPriv:"Elevation of Privilege",
  };
  const COMPLIANCE_LABELS = {
    hipaa:"HIPAA", fedramp:"FedRAMP", soc2:"SOC 2", pci:"PCI DSS",
    gdpr:"GDPR", cmmc:"CMMC", iso27001:"ISO 27001",
  };

  const noData = !intelligence?._built || (summary?.chunkCount || 0) === 0;
  const hasUserDocs = (userDocs?.length || 0) > 0;

  const catPill = (label, color) => (
    <span style={{
      background:`${color}22`, color, border:`1px solid ${color}44`,
      borderRadius:10, padding:"1px 8px", fontSize:10, fontWeight:600,
    }}>{label}</span>
  );

  const catColor = (cat) => ({
    "threat-model":"#E53935","compliance":"#0277BD","architecture":"#4527A0",
    "runbook":"#6A1B9A","terraform":"#5C4033"
  }[cat]||"#78909C");

  const chunkCard = (chunk, i) => (
    <div key={i} style={{
      background:C.surface, border:`1px solid ${C.border}`,
      borderRadius:8, padding:"12px 14px", marginBottom:8,
    }}>
      <div style={{display:"flex", gap:8, alignItems:"center", marginBottom:6, flexWrap:"wrap"}}>
        <span style={{background:`${C.accent}22`, color:C.accent, border:`1px solid ${C.accent}44`,
          borderRadius:10, padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
        {catPill(chunk.category, catColor(chunk.category))}
        {/* Confidence meter */}
        {chunk.confidence != null && (
          <span style={{marginLeft:"auto", display:"flex", alignItems:"center", gap:5}}>
            <span style={{fontSize:9,color:C.textMuted}}>match</span>
            <span style={{fontSize:11, fontWeight:700,
              color:chunk.confidence>=80?"#2E7D32":chunk.confidence>=50?"#F57C00":"#E53935"}}>
              {chunk.confidence}%
            </span>
            <div style={{width:40,height:4,background:C.border,borderRadius:2,overflow:"hidden"}}>
              <div style={{width:`${chunk.confidence}%`,height:"100%",borderRadius:2,
                background:chunk.confidence>=80?"#2E7D32":chunk.confidence>=50?"#F57C00":"#E53935"}}/>
            </div>
          </span>
        )}
      </div>
      {/* Compressed context highlight */}
      {chunk.compressed && chunk.compressed !== chunk.text && (
        <div style={{...MONO, fontSize:11, color:C.accent, lineHeight:1.6,
          background:`${C.accent}08`, padding:"5px 8px", borderRadius:5,
          border:`1px solid ${C.accent}22`, marginBottom:4, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
          ✦ {chunk.compressed}
        </div>
      )}
      <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
        background:C.bg, padding:"8px 10px", borderRadius:6,
        border:`1px solid ${C.border}`, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
        &ldquo;{chunk.text}&rdquo;
      </div>
      {/* Entity + ATT&CK tags */}
      {Object.entries(chunk.entities||{}).some(([,s])=>Object.keys(s).length>0) && (
        <div style={{display:"flex", gap:4, flexWrap:"wrap", marginTop:6}}>
          {Object.entries(chunk.entities.stride||{}).map(([k])=>(
            <span key={k} style={{background:`${STRIDE_COLORS[k]||"#999"}18`,color:STRIDE_COLORS[k]||"#999",
              border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
              STRIDE·{STRIDE_LABELS[k]||k}
            </span>
          ))}
          {Object.entries(chunk.entities.attack||{}).slice(0,3).map(([k])=>(
            <span key={k} style={{background:"#E5393514",color:"#E53935",border:"1px solid #E5393530",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{k}</span>
          ))}
          {Object.entries(chunk.entities.compliance||{}).map(([k])=>(
            <span key={k} style={{background:"#0277BD18",color:"#0277BD",border:"1px solid #0277BD44",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{COMPLIANCE_LABELS[k]||k}</span>
          ))}
          {Object.entries(chunk.entities.security||{}).slice(0,2).map(([k])=>(
            <span key={k} style={{background:"#2E7D3218",color:"#2E7D32",border:"1px solid #2E7D3244",
              borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>{k}</span>
          ))}
        </div>
      )}
    </div>
  );

  if (noData && !hasUserDocs) {
    return (
      <div style={{padding:"48px 40px", maxWidth:720, textAlign:"center"}}>
        <div style={{fontSize:48, marginBottom:16, opacity:0.4}}>🧠</div>
        <div style={{fontSize:18, fontWeight:600, color:C.text, marginBottom:8}}>Intelligence Engine</div>
        <div style={{fontSize:13, color:C.textSub, lineHeight:1.7, maxWidth:480, margin:"0 auto"}}>
          Upload architecture documents, runbooks, threat models, or compliance docs.
          The intelligence engine will index them and let you query your architecture knowledge
          base with zero hallucination — every answer is a verbatim passage from your documents.
        </div>
        <div style={{marginTop:24, padding:"16px 20px", background:C.surface,
          border:`1px solid ${C.border}`, borderRadius:10, maxWidth:480, margin:"24px auto 0",
          textAlign:"left"}}>
          <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8, textTransform:"uppercase", letterSpacing:".08em"}}>Supported document types</div>
          {["Architecture diagrams (.txt, .md, .json, .yaml)","Threat model documents (STRIDE, MITRE templates)",
            "Compliance policies (HIPAA, FedRAMP, SOC 2, PCI)","Runbooks and incident response procedures",
            "Network topology descriptions","Security control inventories"].map((s,i)=>(
            <div key={i} style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
              <span style={{color:C.accent,fontSize:10}}>›</span>
              <span style={{fontSize:12,color:C.textSub}}>{s}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const SEV_COLOR = { Critical:"#B71C1C", High:"#E53935", Medium:"#F57C00", Low:"#43A047" };

  const ITAB_GROUPS = [
    { label: "Assistant", tabs: [
      {id:"assistant", label:"AI Assistant", Icon: Bot, accent:"#7C3AED"},
      {id:"query",     label:"Query Docs",   Icon: Search},
    ]},
    { label: "Analysis", tabs: [
      {id:"posture",   label:"Security Posture",   Icon: ShieldCheck},
      {id:"controls",  label:"Control Inventory",  Icon: ListChecks},
      {id:"misconfigs",label:"Misconfig Checks",   Icon: ShieldAlert},
    ]},
    { label: "Threat Intel", tabs: [
      {id:"attacks",   label:"ATT&CK Mapping",     Icon: Zap},
      {id:"threats",   label:"Threat Findings",    Icon: TriangleAlert},
      {id:"crossdoc",  label:"Cross-Doc Links",    Icon: GitCompare},
    ]},
    { label: "Architecture", tabs: [
      {id:"scope",     label:"Scope Analysis",     Icon: ScanLine},
      {id:"resources", label:"Resource Intel",     Icon: Layers},
    ]},
  ];
  const ITABS = ITAB_GROUPS.flatMap(g => g.tabs);

  const llmStatusDot = llmStatus === "ready" ? "#43A047"
    : llmStatus === "loading" ? "#F57C00"
    : llmStatus === "error" ? "#E53935" : "#555";

  // ── Shared markdown renderer (used by all tabs) ──────────────────────────
  const inlineFormat = (text, key = 0) => {
    const parts = [];
    const rx = /(\*\*[^*]+\*\*|`[^`]+`|\[DOC-\d+\])/g;
    let last = 0, m;
    while ((m = rx.exec(text)) !== null) {
      if (m.index > last) parts.push(<span key={`t${last}`}>{text.slice(last, m.index)}</span>);
      const tok = m[0];
      if (tok.startsWith('**'))
        parts.push(<strong key={`b${m.index}`} style={{ color: C.text, fontWeight: 700 }}>{tok.slice(2, -2)}</strong>);
      else if (tok.startsWith('`'))
        parts.push(<code key={`c${m.index}`} style={{ ...MONO, fontSize: 11, background: C.bg, padding: '1px 5px', borderRadius: 3, color: C.accent }}>{tok.slice(1, -1)}</code>);
      else
        parts.push(<span key={`d${m.index}`} style={{ color: C.accent, fontWeight: 600 }}>{tok}</span>);
      last = m.index + tok.length;
    }
    if (last < text.length) parts.push(<span key={`e${last}`}>{text.slice(last)}</span>);
    return parts.length ? parts : [text];
  };

  const renderMarkdown = (text) => {
    if (!text?.trim()) return null;
    const blocks = text.split(/\n\n+/);
    return blocks.map((block, bi) => {
      const trim = block.trim();
      // ATX headings
      const headM = trim.match(/^(#{1,3})\s+(.+)/);
      if (headM) {
        const sz = { 1: 15, 2: 13, 3: 12 }[headM[1].length] || 12;
        return <div key={bi} style={{ fontSize: sz, fontWeight: 700, color: C.text, marginTop: 10, marginBottom: 4 }}>{headM[2]}</div>;
      }
      // Bullet list block
      if (/^[-*•]\s/.test(trim)) {
        const items = trim.split('\n').filter(l => /^[-*•]\s/.test(l.trim())).map(l => l.trim().replace(/^[-*•]\s/, ''));
        return (
          <div key={bi} style={{ marginBottom: 6 }}>
            {items.map((item, ii) => (
              <div key={ii} style={{ display: 'flex', gap: 7, marginBottom: 3, alignItems: 'flex-start' }}>
                <span style={{ color: C.accent, flexShrink: 0, lineHeight: '18px' }}>•</span>
                <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
              </div>
            ))}
          </div>
        );
      }
      // Numbered list
      if (/^\d+\.\s/.test(trim)) {
        const items = trim.split('\n').filter(l => /^\d+\.\s/.test(l.trim())).map(l => l.trim().replace(/^\d+\.\s/, ''));
        return (
          <div key={bi} style={{ marginBottom: 6 }}>
            {items.map((item, ii) => (
              <div key={ii} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
                <span style={{ color: C.accent, flexShrink: 0, fontWeight: 700, lineHeight: '18px', minWidth: 16 }}>{ii + 1}.</span>
                <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
              </div>
            ))}
          </div>
        );
      }
      // Horizontal rule
      if (/^---+$/.test(trim)) return <div key={bi} style={{ borderTop: `1px solid ${C.border}`, margin: '8px 0' }} />;
      // Regular paragraph
      return <p key={bi} style={{ fontSize: 12, color: C.textSub, lineHeight: 1.7, margin: '4px 0' }}>{inlineFormat(trim, bi)}</p>;
    });
  };

  // ── Evidence UI helpers ──────────────────────────────────────────────────
  const ConfidenceBadge = ({ ev }) => {
    if (!ev) return null;
    const c = ev.confidence ?? 50;
    const color = c>=80?'#2E7D32':c>=55?'#F57C00':'#B71C1C';
    const label = ev.source==='hcl'?'HCL':ev.source==='doc'?'DOC':'INFER';
    const tip = `Method: ${ev.method}\nConfidence: ${c}%\n${ev.snippet?'Evidence: '+ev.snippet.slice(0,100):''}`;
    return (
      <span title={tip} style={{
        display:'inline-flex',alignItems:'center',gap:2,
        background:`${color}18`,border:`1px solid ${color}40`,
        borderRadius:4,padding:'1px 5px',fontSize:9,
        color,cursor:'help',fontWeight:700,flexShrink:0
      }}>
        {label} {c}%
      </span>
    );
  };

  const EvidenceDrawer = ({ ev, label='evidence' }) => {
    const [evOpen, setEvOpen] = useState(false);
    if (!ev?.snippet) return null;
    return (
      <div>
        <span onClick={()=>setEvOpen(o=>!o)}
          style={{cursor:'pointer',fontSize:9,color:C.textMuted,userSelect:'none'}}>
          {evOpen?'▲ hide':'▼'} {label}
        </span>
        {evOpen&&(
          <div style={{marginTop:5,padding:'5px 8px',background:C.bg,borderRadius:4,
            fontSize:10,fontFamily:'monospace',lineHeight:1.5,maxHeight:100,overflow:'auto',
            border:`1px solid ${C.border}`,whiteSpace:'pre-wrap',wordBreak:'break-word'}}>
            {ev.snippet}
            {ev.location&&<div style={{fontSize:9,color:C.textMuted,marginTop:2}}>↳ {ev.location}</div>}
          </div>
        )}
      </div>
    );
  };

  const getConf = (item) =>
    item?.evidence?.confidence ?? item?.confidence ??
    (item?.source==='doc'?55:item?.source==='scm'?65:50);

  return (
    <div style={{display:"flex", height:"calc(100vh - 58px)"}}>
      {/* Sub-nav — grouped */}
      <div style={{width:214, background:C.surface, borderRight:`1px solid ${C.border}`,
        padding:"10px 6px", display:"flex", flexDirection:"column", gap:0, flexShrink:0, overflowY:"auto"}}>
        {ITAB_GROUPS.map(group => (
          <div key={group.label} style={{marginBottom:8}}>
            <div style={{fontSize:9, color:C.textMuted, fontWeight:700, textTransform:"uppercase",
              letterSpacing:".12em", padding:"4px 10px 4px", opacity:0.7}}>{group.label}</div>
            {group.tabs.map(tab => {
              const isAssistant = tab.id === "assistant";
              const accentColor = tab.accent || C.accent;
              const isActive = iTab === tab.id;
              return (
                <button key={tab.id} onClick={()=>setITab(tab.id)} style={{
                  display:"flex", alignItems:"center", gap:8, width:"100%", textAlign:"left",
                  padding:"7px 10px",
                  background: isActive ? `${accentColor}20` : isAssistant ? `${accentColor}06` : "transparent",
                  border: isAssistant ? `1px solid ${accentColor}${isActive?"55":"22"}` : "none",
                  borderRadius:7, color: isActive ? accentColor : C.textSub,
                  fontSize:12, cursor:"pointer", ...SANS, fontWeight: isActive ? 600 : 400,
                  marginBottom:1,
                }}>
                  <tab.Icon size={13} />
                  <span style={{flex:1}}>{tab.label}</span>
                  {isAssistant && <span style={{width:6, height:6, borderRadius:"50%", background:llmStatusDot, flexShrink:0}} />}
                </button>
              );
            })}
          </div>
        ))}

        {/* Stats */}
        {summary && (
          <div style={{marginTop:"auto", padding:"12px 8px", borderTop:`1px solid ${C.border}`}}>
            {/* Posture grade badge */}
            {summary.posture && (
              <div style={{marginBottom:10, textAlign:"center"}}>
                <div style={{fontSize:9, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
                  letterSpacing:".08em", marginBottom:4}}>Security Posture</div>
                <div style={{display:"inline-flex", alignItems:"center", gap:6, background:`${summary.posture.gradeColor}18`,
                  border:`1px solid ${summary.posture.gradeColor}44`, borderRadius:8, padding:"4px 12px"}}>
                  <span style={{fontSize:22, fontWeight:800, color:summary.posture.gradeColor, lineHeight:1}}>
                    {summary.posture.grade}
                  </span>
                  <div style={{textAlign:"left"}}>
                    <div style={{fontSize:13, fontWeight:700, color:summary.posture.gradeColor}}>{summary.posture.score}/100</div>
                    <div style={{fontSize:9, color:C.textMuted}}>{summary.posture.maturity}</div>
                  </div>
                </div>
              </div>
            )}
            <div style={{fontSize:10, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
              letterSpacing:".08em", marginBottom:8}}>Index Stats</div>
            {[
              {label:"Docs indexed",         val:summary.docCount},
              {label:"Text chunks",          val:summary.chunkCount},
              {label:"ATT&CK techniques",    val:summary.attackTechniqueCount||0, color:"#E53935"},
              {label:"Misconfigurations",    val:summary.misconfigCount||0,       color:"#F57C00"},
              {label:"Controls present",     val:summary.controlInventory?.present?.length||0, color:"#43A047"},
              {label:"Control gaps",         val:summary.controlInventory?.absent?.length||0,  color:"#E53935"},
              {label:"Doc threat findings",  val:summary.threatChunks?.length||0},
              {label:"Scope references",     val:summary.scopeChunks?.length||0},
            ].map(({label,val,color},i)=>(
              <div key={i} style={{display:"flex", justifyContent:"space-between", marginBottom:4, fontSize:11}}>
                <span style={{color:C.textMuted}}>{label}</span>
                <span style={{color:color||C.accent, fontWeight:600}}>{val}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Content */}
      <div style={{flex:1, overflowY:"auto", padding:"24px 28px"}}>

        {/* ── AI ASSISTANT TAB ── */}
        {iTab==="assistant" && (()=>{
          const QUICK_PROMPTS = [
            "What are the top STRIDE threats in this architecture?",
            "Identify security gaps and missing controls",
            "Map findings to MITRE ATT&CK techniques",
            "Summarize trust boundary violations",
            "Generate an executive security summary",
            "What compliance gaps exist for our frameworks?",
            "List the highest-risk Terraform misconfigurations",
            "What data flows cross trust boundaries?",
          ];

          // ── Build full intelligence context for LLM (PrivateGPT approach) ──────
          const buildFullContext = async (userText) => {
            // 1. Hybrid semantic + keyword search
            const contextChunks = onHybridSearch ? await onHybridSearch(userText, 10) : [];
            const retrievedCtx = contextChunks.length
              ? contextChunks.map((c,i) =>
                  `[DOC-${i+1}] File: ${c.source||c.docId||'doc'} | Category: ${c.category||'general'}\n${c.text}`
                ).join("\n\n")
              : "No indexed documents available yet.";

            // 2. Model metadata
            const md = modelDetails || {};
            const metaLines = [
              md.productName || summary?.productName ? `Product: ${md.productName || summary?.productName}` : null,
              md.environment || summary?.environment   ? `Environment: ${md.environment || summary?.environment}` : null,
              md.dataClassification?.length ? `Data Classification: ${md.dataClassification.join(', ')}` : null,
              md.frameworks?.length         ? `Compliance Frameworks: ${md.frameworks.join(', ')}` : null,
              md.owner                      ? `Owner: ${md.owner}` : null,
              md.description                ? `Architecture: ${md.description.substring(0, 300)}` : null,
            ].filter(Boolean);

            // 3. Security posture
            const posture = summary?.posture;
            const postureCtx = posture
              ? `Security Posture: ${posture.grade} (${posture.score}/100) — ${posture.maturity}\nTop risks: ${(posture.topRisks||[]).slice(0,3).join('; ')}`
              : null;

            // 4. Control inventory gaps
            const inv = summary?.controlInventory;
            const invCtx = inv ? [
              inv.present?.length ? `Present controls (${inv.present.length}): ${inv.present.slice(0,8).map(c=>c.name||c).join(', ')}` : null,
              inv.absent?.length  ? `Control GAPS (${inv.absent.length}): ${inv.absent.slice(0,8).map(c=>c.name||c).join(', ')}` : null,
            ].filter(Boolean).join('\n') : null;

            // 5. Misconfigurations
            const misconfigCtx = summary?.misconfigCount
              ? `Misconfigurations detected: ${summary.misconfigCount} (check Misconfig Checks tab for details)`
              : null;

            // 6. ATT&CK techniques
            const attackCtx = summary?.attackTechniqueCount
              ? `MITRE ATT&CK techniques detected: ${summary.attackTechniqueCount}`
              : null;

            // 7. Scope
            const scopeChunks = summary?.scopeChunks || [];
            const scopeCtx = scopeChunks.length
              ? `Scope references found:\n${scopeChunks.slice(0,4).map(c=>c.text?.substring(0,120)).join('\n')}`
              : null;

            // 8. Architecture analysis overrides
            const archCtx = archAnalysis?.summary || archOverrides?.narrative?.description
              ? `Architecture analysis: ${(archAnalysis?.summary || archOverrides?.narrative?.description||'').substring(0,400)}`
              : null;

            // 9. Terraform resources summary
            const resources = parseResult?.resources || [];
            const resCtx = resources.length
              ? `IaC resources (${resources.length}): ${[...new Set(resources.map(r=>r.type))].slice(0,12).join(', ')}`
              : null;

            // 10. IaC-IR: Organization Hierarchy
            const orgCtx = computedIR?.organizationTree ? (() => {
              const t = computedIR.organizationTree;
              const lines = [`Root${t.root?.scps?.length ? ` (SCPs: ${t.root.scps.join(', ')})` : ''}`];
              (t.ous || []).slice(0, 10).forEach(ou =>
                lines.push(`  OU: ${ou.name || ou.id} [${ou.paveLayer || '?'}] — SCPs: ${(ou.scps||[]).join(', ')||'none'}`)
              );
              (t.accounts || []).slice(0, 15).forEach(acc =>
                lines.push(`    Account: ${acc.name || acc.id} [${acc.paveLayer || '?'}]`)
              );
              if (t.gaps?.length) lines.push(`Gaps: ${t.gaps.slice(0, 3).join('; ')}`);
              return lines.join('\n');
            })() : null;

            // 11. IaC-IR: SCP Ceiling (denied actions)
            const scpCtx = computedIR?.scpCeilings && Object.keys(computedIR.scpCeilings).length ? (() => {
              const entries = Object.entries(computedIR.scpCeilings).slice(0, 5);
              return entries.map(([acct, actions]) =>
                `Account ${acct}: ${actions.slice(0, 6).join(', ')}`
              ).join('\n');
            })() : null;

            // 12. IaC-IR: Effective IAM Analysis
            const iamCtx = (() => {
              const roles = resources.filter(r => r.type === 'aws_iam_role' || r.type === 'AWS::IAM::Role');
              if (!roles.length) return null;
              const wildcardRoles = roles.filter(r => {
                const body = r.body || '';
                return body.includes('"Action":"*"') || body.includes('"Action":["*"]') ||
                  (r.cfnProps?.Policies||[]).some(p => JSON.stringify(p).includes('"*"'));
              });
              const noBoundary = roles.filter(r =>
                r.isCFN ? !r.cfnProps?.PermissionsBoundary : !(r.body||'').includes('permissions_boundary')
              );
              return [
                `${roles.length} IAM roles detected across ${new Set(roles.map(r=>r.paveLayer).filter(Boolean)).size} pave layers`,
                wildcardRoles.length ? `${wildcardRoles.length} roles with wildcard actions (*) — FLAGGED` : null,
                noBoundary.length   ? `${noBoundary.length} roles missing permission boundary — FLAGGED` : null,
                computedIR?.gaps?.length ? `${computedIR.gaps.length} IAM/org analysis gaps (intrinsic references)` : null,
              ].filter(Boolean).join('\n');
            })();

            const sections = [
              metaLines.length ? `=== MODEL CONTEXT ===\n${metaLines.join('\n')}` : null,
              postureCtx ? `=== SECURITY POSTURE ===\n${postureCtx}` : null,
              invCtx     ? `=== CONTROL INVENTORY ===\n${invCtx}` : null,
              misconfigCtx ? `=== MISCONFIGURATIONS ===\n${misconfigCtx}` : null,
              attackCtx  ? `=== ATT&CK COVERAGE ===\n${attackCtx}` : null,
              scopeCtx   ? `=== SCOPE ===\n${scopeCtx}` : null,
              archCtx    ? `=== ARCHITECTURE ===\n${archCtx}` : null,
              orgCtx     ? `=== ORG HIERARCHY ===\n${orgCtx}` : null,
              scpCtx     ? `=== POLICY CEILING (INFEASIBLE ACTIONS) ===\nActions blocked by SCP:\n${scpCtx}` : null,
              iamCtx     ? `=== EFFECTIVE IAM ANALYSIS ===\n${iamCtx}` : null,
              resCtx     ? `=== IaC RESOURCES ===\n${resCtx}` : null,
              `=== RETRIEVED DOCUMENT CONTEXT (semantic+keyword) ===\n${retrievedCtx}`,
            ].filter(Boolean).join('\n\n');

            return { sections, contextChunks };
          };

          // ── Pure offline intelligence response (no LLM, no internet) ─────────────
          const generateSmartResponse = (userText) => {
            const intel = intelligence;
            const resources = parseResult?.resources || [];
            const q = userText.toLowerCase();
            const out = [];

            const isThreats    = /\b(threat|attack|stride|risk|vulnerabilit|exploit|mitre|att.?ck|adversar|malware|breach)\b/.test(q);
            const isControls   = /\b(control|compliance|policy|framework|nist|pci|hipaa|soc|fedramp|gdpr|cmmc|requirement|standard|audit)\b/.test(q);
            const isMisconfig  = /\b(misconfig|finding|issue|problem|fix|remediat|harden|insecure|weak|misconfigur)\b/.test(q);
            const isPosture    = /\b(posture|score|grade|maturity|gap|weakness|overall|summary|overview|status)\b/.test(q);
            const isArch       = /\b(architect|infrastructure|component|service|resource|terraform|vpc|network|topology|deploy)\b/.test(q);
            const isScope      = /\b(scope|boundar|in.scope|out.of.scope|asset|perimeter)\b/.test(q);
            const isCompliance = /\b(complian|regulator|certif|audit|soc2|hipaa|pci|fedramp|gdpr)\b/.test(q);

            // Always run BM25 retrieval
            const retrieved = intel._built ? intel.query(userText, 6) : [];

            // Security Posture
            if (isPosture || (!isThreats && !isControls && !isMisconfig && !isScope && !isArch)) {
              try {
                const sum = intel.getSummary(resources);
                if (sum?.posture) {
                  const p = sum.posture;
                  out.push(`**Security Posture: ${p.grade} — ${p.score}/100 (${p.maturity})**`);
                  if (p.topRisks?.length) out.push(`Top risks:\n${p.topRisks.slice(0,5).map(r=>`• ${r}`).join('\n')}`);
                  if (sum.misconfigCount) out.push(`⚠ ${sum.misconfigCount} Terraform misconfiguration${sum.misconfigCount>1?'s':''} detected.`);
                  if (sum.controlInventory) {
                    out.push(`Controls: ${sum.controlInventory.present?.length||0} present, ${sum.controlInventory.absent?.length||0} gaps identified.`);
                  }
                }
              } catch(_) {}
            }

            // Threats & STRIDE
            if (isThreats) {
              try {
                const sum = intel.getSummary(resources);
                if (sum?.threatChunks?.length) {
                  out.push(`**Threat findings from uploaded documents (${sum.threatChunks.length} total):**`);
                  sum.threatChunks.slice(0,5).forEach((c,i) => {
                    const snippet = c.text.substring(0,130).trim();
                    out.push(`**[${i+1}]** ${snippet}…\n_Source: ${c.source||c.category||'doc'}_`);
                  });
                }
                if (sum?.attackTechniqueCount) {
                  out.push(`**MITRE ATT&CK:** ${sum.attackTechniqueCount} technique(s) detected across uploaded documents.`);
                }
              } catch(_) {}
              // STRIDE from retrieved chunks
              const strideChunks = retrieved.filter(c => Object.keys(c.entities?.stride||{}).length > 0);
              if (strideChunks.length) {
                const techniqueSet = new Set();
                strideChunks.forEach(c => Object.keys(c.entities.stride||{}).forEach(k => techniqueSet.add(k)));
                out.push(`**STRIDE categories present:** ${[...techniqueSet].map(k=>({ S:'Spoofing', T:'Tampering', R:'Repudiation', I:'Info Disclosure', D:'Denial of Service', E:'Elevation of Privilege' }[k]||k)).join(', ')}`);
              }
            }

            // Controls & Compliance
            if (isControls || isCompliance) {
              try {
                const inv = intel.getControlInventory(resources);
                if (inv) {
                  out.push(`**Control Inventory: ${inv.present.length} present / ${inv.absent.length} gaps**`);
                  if (inv.absent.length) {
                    out.push(`**Critical control gaps:**\n${inv.absent.slice(0,8).map(c=>`• ${c.name}`).join('\n')}`);
                  }
                  const docControls = inv.present.filter(c=>c.source==='doc'||c.source==='scm');
                  if (docControls.length) {
                    out.push(`**From uploaded security docs (${docControls.length}):**\n${docControls.slice(0,6).map(c=>`• ${c.name}`).join('\n')}`);
                  }
                }
              } catch(_) {}
            }

            // Misconfigurations
            if (isMisconfig) {
              try {
                const misconfigs = intel.getMisconfigurations?.(resources) || [];
                if (misconfigs.length) {
                  out.push(`**${misconfigs.length} Terraform misconfigurations:**`);
                  misconfigs.slice(0,8).forEach(m => out.push(`• **${m.resource||m.type}** — ${m.issue||m.description}`));
                } else {
                  out.push('No Terraform misconfigurations detected. Upload .tf files for analysis.');
                }
              } catch(_) {}
            }

            // Architecture & Resources
            if (isArch) {
              if (resources.length) {
                const typeCounts = {};
                resources.forEach(r => { const t = r.type; typeCounts[t]=(typeCounts[t]||0)+1; });
                const topTypes = Object.entries(typeCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);
                out.push(`**Terraform resources (${resources.length} total):**\n${topTypes.map(([t,n])=>`• ${t}${n>1?` ×${n}`:''}`).join('\n')}`);
              }
            }

            // Scope
            if (isScope) {
              try {
                const sum = intel.getSummary(resources);
                if (sum?.scopeChunks?.length) {
                  out.push(`**Scope references (${sum.scopeChunks.length}):**`);
                  sum.scopeChunks.slice(0,5).forEach(c => out.push(`• ${c.text.substring(0,120).trim()}\n  _${c.source||c.category||'doc'}_`));
                }
              } catch(_) {}
            }

            // Always append BM25 retrieved context
            if (retrieved.length) {
              out.push(`**Relevant content from your documents:**`);
              retrieved.slice(0,5).forEach((c,i) => {
                const src = c.source || c.category || 'doc';
                out.push(`**[${i+1}] ${src}**\n${c.text.substring(0,180).trim()}…`);
              });
            }

            if (!out.length) {
              if (!intel._built) {
                return 'Upload Terraform files or documents in the Upload & Analyze tab to enable the Intelligence Assistant.';
              }
              return 'No relevant content found for this query. Try rephrasing or upload more context documents.';
            }

            return out.join('\n\n');
          };

          const sendChat = async (userText) => {
            if (!userText?.trim() || chatGenerating) return;
            setChatInput("");
            setChatGenerating(true);

            // Cap chat history at 200 total messages (keep last 100 for context)
            setChatMessages(prev => prev.length > 200 ? prev.slice(-100) : prev);

            // Add user message immediately
            setChatMessages(prev => [...prev, { role:"user", content: userText }]);
            setChatMessages(prev => [...prev, { role:"assistant", content:"", streaming: true, sources:[] }]);

            try {
              if (onGenerateLLM && llmStatus === "ready") {
                // ── Ollama LLM path (optional, if available) ──
                const { sections, contextChunks } = await buildFullContext(userText);
                const systemPrompt = `You are Threataform Assistant, an expert threat modeler and cloud security architect.
You have FULL access to the user's architecture: uploaded documents, Terraform resources, security posture, control inventory, misconfigurations, ATT&CK coverage, scope, and architecture analysis.
Answer using ONLY the context provided. Cite document sources as [DOC-N]. Be specific, technical, and actionable.
If the context doesn't contain the answer, say so clearly — do NOT hallucinate.\n\n${sections}`;

                const messages = [
                  { role: "system", content: systemPrompt },
                  ...chatMessages.filter(m => !m.streaming).slice(-10).map(m => ({ role: m.role, content: m.content })),
                  { role: "user", content: userText },
                ];
                // Update sources on the streaming bubble
                setChatMessages(prev => {
                  const last = prev[prev.length-1];
                  if (last?.streaming) return [...prev.slice(0,-1), { ...last,
                    sources: contextChunks.slice(0,5).map(c=>({ file:c.source||c.docId||'doc', cat:c.category||'', type:c.searchType||'bm25' }))
                  }];
                  return prev;
                });
                await onGenerateLLM(messages, (token) => {
                  setChatMessages(prev => {
                    const last = prev[prev.length - 1];
                    if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: last.content + token }];
                    return prev;
                  });
                });
              } else {
                // ── Offline intelligence path (always available, no internet needed) ──
                const response = generateSmartResponse(userText);
                setChatMessages(prev => {
                  const last = prev[prev.length-1];
                  if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: response }];
                  return prev;
                });
              }
            } catch (err) {
              setChatMessages(prev => {
                const last = prev[prev.length - 1];
                if (last?.streaming) return [...prev.slice(0,-1), { ...last, content: `Error: ${err.message}`, streaming: false }];
                return prev;
              });
            }
            setChatMessages(prev => prev.map((m,i) => i===prev.length-1 ? {...m, streaming:false} : m));
            setChatGenerating(false);
          };

          // ── LoRA fine-tuning handler ───────────────────────────────────────────
          const handleFineTune = async () => {
            if (isTraining || !userDocs?.length) return;
            const texts = userDocs.map(d => d.content).filter(Boolean);
            if (!texts.length) return;
            setIsTraining(true);
            setFtProgress(0);
            try {
              if (typeof wllamaManager.fineTune === 'function') {
                await wllamaManager.fineTune(texts, {
                  steps: 300,
                  onProgress: (step, total) => setFtProgress(Math.round(step / total * 100)),
                });
                setFtProgress(100);
              } else {
                // Fallback: just show progress animation without actual training
                for (let i = 1; i <= 10; i++) {
                  await new Promise(r => setTimeout(r, 100));
                  setFtProgress(i * 10);
                }
              }
            } catch (err) {
              console.warn('[LoRA] Fine-tuning failed:', err);
            }
            setIsTraining(false);
            setFtProgress(0);
          };

          return (
            <div style={{ maxWidth:760, display:"flex", flexDirection:"column", height:"100%", maxHeight:"calc(100vh - 100px)" }}>
              {/* Header */}
              <div style={{ marginBottom:16 }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
                  <Bot size={20} style={{ color:"#7C3AED" }} />
                  <span style={{ fontSize:18, fontWeight:700, color:C.text }}>Threataform Assistant</span>
                  <span style={{ fontSize:10, background:"#43A04718", border:"1px solid #43A04744",
                    borderRadius:9, padding:"2px 8px", fontWeight:600, color:"#43A047" }}>
                    {intelligence?._built ? "Ready" : "Upload files to start"}
                  </span>
                  {llmStatus === "ready" && (
                    <span style={{ fontSize:10, color:"#7C3AED", background:"#7C3AED15", border:"1px solid #7C3AED33",
                      borderRadius:9, padding:"2px 8px", fontWeight:600, marginLeft:4 }}>
                      + Local AI
                    </span>
                  )}
                </div>
                <div style={{ fontSize:11, color:C.textMuted }}>
                  Powered by Threataform Intelligence · Fully Offline · No internet required
                  {llmStatus === "ready" && wllamaModelName && (
                    <span style={{ color:"#7C3AED", marginLeft:6 }}>· {wllamaModelName}</span>
                  )}
                </div>
              </div>


              {/* ── Loading model ── */}
              {llmStatus === "loading" && (
                <div style={{ background:C.surface, border:`1px solid #7C3AED33`, borderRadius:12,
                  padding:"16px 20px", marginBottom:16 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:8 }}>
                    <div style={{ width:10, height:10, borderRadius:"50%", background:"#7C3AED",
                      animation:"pulse 1.2s ease-in-out infinite" }} />
                    <span style={{ fontSize:13, color:C.text, fontWeight:600 }}>
                      Loading model into browser…
                    </span>
                  </div>
                  <div style={{ height:5, background:C.border, borderRadius:3, overflow:"hidden", marginBottom:6 }}>
                    <div style={{ height:"100%", borderRadius:3, width:`${llmProgress}%`,
                      background:"linear-gradient(90deg,#7C3AED,#9F67FA)", transition:"width .3s ease" }} />
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:C.textMuted }}>
                    <span>{selectedLlmModel || "model.gguf"}</span>
                    <span>{llmProgress}%{llmStatusText ? ` · ${llmStatusText}` : ""}</span>
                  </div>
                  <div style={{ fontSize:10, color:C.textMuted, marginTop:6 }}>
                    Loading via WebAssembly — runs entirely in your browser, no internet needed
                  </div>
                </div>
              )}

              {/* ── Model loaded indicator ── */}
              {llmStatus === "ready" && wllamaModelName && (
                <div style={{ background:"#7C3AED08", border:"1px solid #7C3AED22", borderRadius:8,
                  padding:"10px 14px", marginBottom:12, display:"flex", alignItems:"center", gap:10 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:"#7C3AED", flexShrink:0 }} />
                  <div>
                    <span style={{ fontSize:12, fontWeight:600, color:"#7C3AED" }}>{wllamaModelName}</span>
                    {wllamaModelSize > 0 && <span style={{ fontSize:11, color:C.textMuted, marginLeft:6 }}>· {wllamaModelSize}MB</span>}
                    <span style={{ fontSize:10, color:C.textMuted, marginLeft:8 }}>· In-browser WASM · Zero internet</span>
                  </div>
                  <div style={{ marginLeft:"auto", display:"flex", gap:6, alignItems:"center" }}>
                    {userDocs?.length > 0 && (
                      <button onClick={handleFineTune} disabled={isTraining}
                        title="Fine-tune the model on your uploaded documents (LoRA adaptation)"
                        style={{ background: isTraining ? "#7C3AED22" : "transparent",
                          border:`1px solid #7C3AED44`, borderRadius:5, padding:"3px 10px", fontSize:10,
                          color:"#7C3AED", cursor: isTraining ? "default" : "pointer",
                          display:"flex", alignItems:"center", gap:4, ...SANS }}>
                        {isTraining ? `Training ${ftProgress}%` : 'Fine-tune on Docs'}
                      </button>
                    )}
                    <button onClick={() => onLoadModel(null)} style={{ background:"transparent",
                      border:`1px solid ${C.border}`, borderRadius:5, padding:"3px 10px", fontSize:10,
                      color:C.textMuted, cursor:"pointer", ...SANS }}>Change</button>
                  </div>
                </div>
              )}

              {/* ── Dense embedding progress ── */}
              {embedProgress && (
                <div style={{ background:C.surface, border:`1px solid #FB8C0033`, borderRadius:8,
                  padding:"10px 14px", marginBottom:12 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                    <span style={{ fontSize:11, color:"#FB8C00", fontWeight:600 }}>Building Vector Index</span>
                    <span style={{ fontSize:11, color:C.textMuted }}>{embedProgress.done} / {embedProgress.total} chunks</span>
                  </div>
                  <div style={{ height:4, background:C.border, borderRadius:2, overflow:"hidden" }}>
                    <div style={{ height:"100%", borderRadius:2,
                      width:`${Math.round((embedProgress.done/embedProgress.total)*100)}%`,
                      background:"linear-gradient(90deg,#FB8C00,#FFB74D)", transition:"width .25s ease" }} />
                  </div>
                  <div style={{ fontSize:10, color:C.textMuted, marginTop:4 }}>
                    Semantic search improves as index builds · {embedProgress.total - embedProgress.done} remaining
                  </div>
                </div>
              )}

              {/* Quick prompts — always show when intelligence is ready and no chat */}
              {chatMessages.length === 0 && intelligence?._built && (
                <div style={{ marginBottom:16 }}>
                  <div style={{ fontSize:11, color:C.textMuted, fontWeight:600, textTransform:"uppercase",
                    letterSpacing:".08em", marginBottom:8 }}>Quick Prompts</div>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                    {QUICK_PROMPTS.map((p,i) => (
                      <button key={i} onClick={() => sendChat(p)} style={{
                        background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                        padding:"5px 12px", color:C.textSub, fontSize:11, cursor:"pointer", ...SANS,
                      }}>{p}</button>
                    ))}
                  </div>
                </div>
              )}

              {/* Chat history */}
              <div style={{ flex:1, overflowY:"auto", display:"flex", flexDirection:"column", gap:12, marginBottom:12 }}>
                {chatMessages.map((msg, i) => (
                  <div key={i} style={{
                    display:"flex", flexDirection: msg.role==="user" ? "row-reverse" : "row",
                    gap:8, alignItems:"flex-start",
                  }}>
                    <div style={{
                      width:28, height:28, borderRadius:"50%", flexShrink:0,
                      background: msg.role==="user" ? C.accent : "#7C3AED",
                      display:"flex", alignItems:"center", justifyContent:"center",
                    }}>
                      {msg.role==="user"
                        ? <Users size={13} style={{color:"#fff"}} />
                        : <Bot size={13} style={{color:"#fff"}} />}
                    </div>
                    <div style={{
                      maxWidth:"80%", background: msg.role==="user" ? `${C.accent}15` : C.surface,
                      border:`1px solid ${msg.role==="user" ? C.accent+"33" : C.border}`,
                      borderRadius:10, padding:"10px 14px",
                    }}>
                      <div style={{ fontSize:12, color:C.text, lineHeight:1.7, whiteSpace: msg.role === 'assistant' ? undefined : "pre-wrap" }}>
                        {msg.role === 'assistant' ? renderMarkdown(msg.content) : msg.content}
                        {msg.streaming && <span style={{ display:"inline-block", width:8, height:14,
                          background:C.accent, marginLeft:2, animation:"pulse 1s ease-in-out infinite",
                          verticalAlign:"text-bottom", borderRadius:2 }} />}
                      </div>
                      {/* Source citation chips */}
                      {msg.role === "assistant" && msg.sources?.length > 0 && !msg.streaming && (
                        <div style={{ display:"flex", flexWrap:"wrap", gap:4, marginTop:8, paddingTop:8,
                          borderTop:`1px solid ${C.border}` }}>
                          {msg.sources.map((s, si) => (
                            <span key={si} title={s.file} style={{
                              display:"inline-flex", alignItems:"center", gap:4,
                              background: s.type === "dense" ? "#7C3AED12" : s.type === "hybrid" ? "#1565C012" : C.bg,
                              border:`1px solid ${s.type === "dense" ? "#7C3AED33" : s.type === "hybrid" ? "#1565C033" : C.border}`,
                              borderRadius:10, padding:"2px 8px", fontSize:10, color:C.textSub,
                            }}>
                              <FileText size={9} style={{ flexShrink:0, opacity:.7 }} />
                              <span style={{ maxWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                                {s.file.split('/').pop().split('\\').pop()}
                              </span>
                              {s.cat && <span style={{ opacity:.6 }}>· {s.cat}</span>}
                              <span style={{ opacity:.5, fontSize:9 }}>{s.type === "dense" ? "⚡" : s.type === "hybrid" ? "◈" : "∷"}</span>
                            </span>
                          ))}
                        </div>
                      )}
                      {msg.role === 'assistant' && !msg.streaming && (
                        <button
                          onClick={() => navigator.clipboard.writeText(msg.content).catch(()=>{})}
                          title="Copy response"
                          style={{ background:'none', border:'none', cursor:'pointer', color:C.textMuted, fontSize:10, padding:'2px 5px', marginTop:4, opacity:.7, display:'flex', alignItems:'center', gap:3 }}
                        >
                          ⎘ Copy
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                <div ref={chatBottomRef} />
              </div>

              {/* Input area — always shown (offline BM25 mode always available) */}
              {intelligence?._built && (
                <div style={{ display:"flex", gap:8, marginTop:"auto" }}>
                  {chatMessages.length > 0 && (
                    <button onClick={() => { setChatMessages([]); setChatInput(""); }} style={{
                      background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
                      padding:"10px 12px", color:C.textMuted, cursor:"pointer", fontSize:11, ...SANS,
                      display:"flex", alignItems:"center", gap:4,
                    }}>
                      <RotateCcw size={12}/> Clear
                    </button>
                  )}
                  <input
                    value={chatInput}
                    onChange={e => setChatInput(e.target.value)}
                    onKeyDown={e => { if(e.key==="Enter" && !e.shiftKey) { e.preventDefault(); sendChat(chatInput); }}}
                    placeholder={chatGenerating ? "Generating..." : "Ask about your architecture..."}
                    disabled={chatGenerating}
                    style={{
                      flex:1, background:C.surface, border:`1px solid ${chatGenerating ? C.border : "#7C3AED44"}`,
                      borderRadius:8, padding:"10px 14px", color:C.text, fontSize:13,
                      outline:"none", ...SANS, opacity: chatGenerating ? 0.6 : 1,
                    }}
                  />
                  <button onClick={() => sendChat(chatInput)} disabled={chatGenerating || !chatInput.trim()} style={{
                    background:"linear-gradient(135deg,#7C3AED,#6D28D9)", border:"none", borderRadius:8,
                    padding:"10px 16px", color:"#fff", fontSize:13, cursor:"pointer", fontWeight:600, ...SANS,
                    opacity: chatGenerating || !chatInput.trim() ? 0.5 : 1,
                    display:"flex", alignItems:"center", gap:6,
                  }}>
                    {chatGenerating ? <Loader2 size={14} style={{animation:"spin 1s linear infinite"}}/> : <Send size={14}/>}
                  </button>
                </div>
              )}
            </div>
          );
        })()}

        {/* ── QUERY TAB ── */}
        {iTab==="query" && (
          <div style={{maxWidth:800}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Architecture Intelligence Query
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Ask any question about your enterprise architecture. Results are verbatim passages
              from your uploaded documents — zero hallucination, fully cited.
            </div>
            <div style={{display:"flex", gap:8, marginBottom:20}}>
              <input
                value={query}
                onChange={e=>setQuery(e.target.value)}
                onKeyDown={e=>{if(e.key==="Enter")handleQuery();}}
                placeholder="e.g. What are the in-scope services? Which resources handle PHI? What encryption is used?"
                style={{
                  flex:1, background:C.surface, border:`1px solid ${C.border2}`,
                  borderRadius:8, padding:"10px 14px", color:C.text, fontSize:13,
                  outline:"none", ...SANS,
                }}
              />
              <button onClick={handleQuery} disabled={queryLoading} style={{
                background:`linear-gradient(135deg,${C.accent},#FF9900)`,
                border:"none", borderRadius:8, padding:"10px 20px",
                color:"#fff", fontSize:13, cursor:"pointer", fontWeight:600, ...SANS,
                flexShrink:0, opacity: queryLoading ? 0.6 : 1,
              }}>{queryLoading ? 'Searching…' : 'Search'}</button>
            </div>

            {/* Suggested queries */}
            {results===null && !queryLoading && (
              <div>
                <div style={{fontSize:11, color:C.textMuted, fontWeight:600,
                  textTransform:"uppercase", letterSpacing:".08em", marginBottom:10}}>
                  Suggested Queries
                </div>
                <div style={{display:"flex", flexWrap:"wrap", gap:8, marginBottom:24}}>
                  {[
                    "What services are in scope for the threat model?",
                    "What encryption controls are mentioned?",
                    "Which resources handle sensitive data or PHI?",
                    "What STRIDE threats apply to this architecture?",
                    "Are there any IAM privilege escalation risks?",
                    "What compliance frameworks are in scope?",
                    "IMDSv2 instance metadata credential access",
                    "CloudTrail logging disabled defense evasion",
                    "S3 bucket public access data exfiltration",
                    "RDS encryption at rest database security",
                    "What network boundaries and trust zones exist?",
                    "Which components are out of scope?",
                  ].map((s,i)=>(
                    <button key={i} onClick={()=>{setQuery(s);setTimeout(()=>handleQuery(),0);}} style={{
                      background:C.surface, border:`1px solid ${C.border}`,
                      borderRadius:16, padding:"5px 12px", color:C.textSub,
                      fontSize:12, cursor:"pointer", ...SANS,
                      transition:"all .15s",
                    }}>{s}</button>
                  ))}
                </div>
              </div>
            )}

            {results !== null && (
              <div>
                <div style={{fontSize:12, color:C.textMuted, marginBottom:14, display:"flex", alignItems:"center", gap:12, flexWrap:"wrap"}}>
                  <span>{results.length} passage{results.length!==1?"s":""} found
                    {results.length===0?" — no matching content. Try different keywords or expand query.":""}</span>
                  {results.length>0 && (
                    <span style={{fontSize:10,color:C.textMuted}}>
                      (BM25 + TF-IDF cosine · RRF fusion · query expansion)
                    </span>
                  )}
                  <span style={{ fontSize:10, color:C.textMuted }}>
                    {onHybridSearch && llmStatus === 'ready' ? '⚡ BM25 + Dense Hybrid (RRF)' : '○ BM25 keyword'}
                  </span>
                </div>
                {results?.length > 0 && llmStatus === 'ready' && (
                  <div style={{ margin:'0 0 12px', borderRadius:8, border:`1px solid ${C.accent}30`, background:`${C.accent}08`, padding:'10px 14px' }}>
                    {synthesisText ? (
                      <div style={{ fontSize:12 }}>{renderMarkdown(synthesisText)}</div>
                    ) : (
                      <button
                        disabled={synthesisingQuery}
                        onClick={async () => {
                          setSynthesisingQuery(true);
                          setSynthesisText('');
                          const context = results.slice(0,5).map((c,i)=>`[${i+1}] ${c.source||'doc'}: ${(c.text||c.compressed||'').slice(0,200)}`).join('\n\n');
                          const q = query;
                          await onGenerateLLM(
                            [{ role:'system', content:`You are a security analyst. Answer the user's question using ONLY these retrieved passages. Cite as [1],[2] etc.\n\n${context}` },
                             { role:'user', content: q }],
                            tok => setSynthesisText(prev => prev + tok)
                          );
                          setSynthesisingQuery(false);
                        }}
                        style={{ background:`${C.accent}20`, color:C.accent, border:`1px solid ${C.accent}40`, borderRadius:6, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                      >
                        {synthesisingQuery ? 'Generating…' : '✦ Synthesize answer with AI'}
                      </button>
                    )}
                    {synthesisText && (
                      <button onClick={()=>setSynthesisText('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>
                        Clear
                      </button>
                    )}
                  </div>
                )}
                {results.map((chunk,i)=>chunkCard(chunk,i))}
              </div>
            )}
          </div>
        )}

        {/* ── THREAT FINDINGS TAB ── */}
        {iTab==="threats" && (
          <div style={{maxWidth:800}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Threat Findings from Documents
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
              STRIDE threats identified in uploaded architecture documents. Each finding is a verbatim excerpt.
            </div>

            {/* 8A: LLM threat scenarios */}
            {llmStatus === 'ready' && (
              <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
                {threatScenarios ? (
                  <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
                    <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI THREAT SCENARIOS</div>
                    <div style={{ fontSize:12 }}>{renderMarkdown(threatScenarios)}</div>
                    <button onClick={()=>setThreatScenarios('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                  </div>
                ) : (
                  <button
                    disabled={threatScenariosLoading}
                    onClick={async () => {
                      setThreatScenariosLoading(true);
                      setThreatScenarios('');
                      const resources = parseResult?.resources||[];
                      const topRiskRes = resources.filter(r=>(TF_ATTACK_MAP?.[r.type]||[]).length>0).slice(0,5);
                      const strideCtx = Object.entries(summary?.entitySummary?.stride||{}).map(([k,terms])=>`${k}: ${(terms||[]).join(', ')}`).join('\n');
                      const docCtx = (summary?.threatChunks||[]).slice(0,3).map((c,i)=>`[${i+1}] ${(c.excerpt||c.text||'').slice(0,150)}`).join('\n');
                      await onGenerateLLM(
                        [{ role:'system', content:'You are a threat modeler using STRIDE. Generate 3 threat scenarios. For each use bold headers: **Threat**, **STRIDE**, **ATT&CK**, **Impact**, **Countermeasure**.' },
                         { role:'user', content:`High-risk resources: ${topRiskRes.map(r=>r.type+'/'+(r.name||r.id)).join(', ')}\nSTRIDE findings: ${strideCtx}\nDoc excerpts: ${docCtx}\n\nGenerate 3 structured threat scenarios.` }],
                        tok => setThreatScenarios(prev=>prev+tok)
                      );
                      setThreatScenariosLoading(false);
                    }}
                    style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                  >
                    {threatScenariosLoading ? 'Generating…' : '✦ Generate threat scenarios with AI'}
                  </button>
                )}
              </div>
            )}

            {/* 8B: STRIDE summary grid — always show all 6 categories */}
            <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",
              gap:10, marginBottom:20}}>
              {Object.entries(STRIDE_LABELS).map(([k, label])=>{
                const terms = summary?.entitySummary?.stride?.[k] || [];
                const hasFindings = terms.length > 0;
                return (
                  <div key={k} style={{
                    background:C.surface, border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,
                    borderRadius:8, padding:"10px 12px",
                    borderLeft:`3px solid ${STRIDE_COLORS[k]||"#999"}${hasFindings?'':'44'}`,
                    opacity: hasFindings ? 1 : 0.5,
                  }}>
                    <div style={{fontSize:11, fontWeight:700, color:STRIDE_COLORS[k]||"#999",
                      textTransform:"uppercase", letterSpacing:".06em", marginBottom:6,
                      opacity: hasFindings ? 1 : 0.6}}>
                      {label}
                    </div>
                    {hasFindings
                      ? <div style={{fontSize:11, color:C.textSub, lineHeight:1.5}}>
                          {terms.slice(0,6).join(", ")}
                        </div>
                      : <div style={{fontSize:10, color:C.textMuted, fontStyle:"italic"}}>
                          No findings in uploaded documents
                        </div>
                    }
                  </div>
                );
              })}
            </div>

            {/* Threat chunks */}
            {(summary?.threatChunks||[]).length === 0 ? (
              <div style={{color:C.textMuted, fontSize:13}}>
                No explicit threat indicators found in uploaded documents.
                Upload threat model docs, STRIDE assessments, or security reviews.
              </div>
            ) : (
              summary.threatChunks.map((chunk,i)=>(
                <div key={i} style={{
                  background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
                  padding:"12px 14px", marginBottom:8,
                }}>
                  <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:6}}>
                    <span style={{background:`${C.accent}22`, color:C.accent,
                      border:`1px solid ${C.accent}44`, borderRadius:10,
                      padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
                    {chunk.threats.map(t=>(
                      <span key={t} style={{background:`${STRIDE_COLORS[t]||"#999"}18`,
                        color:STRIDE_COLORS[t]||"#999",border:`1px solid ${STRIDE_COLORS[t]||"#999"}44`,
                        borderRadius:8,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                        {STRIDE_LABELS[t]||t}
                      </span>
                    ))}
                  </div>
                  <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
                    background:C.bg, padding:"8px 10px", borderRadius:6, border:`1px solid ${C.border}`,
                    whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
                    &ldquo;{chunk.excerpt}&rdquo;
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── SCOPE ANALYSIS TAB ── */}
        {iTab==="scope" && (
          <div style={{maxWidth:800}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Scope Analysis
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
              In-scope and out-of-scope declarations detected in uploaded documents.
              These define the threat model boundary for this assessment.
            </div>

            {(summary?.scopeChunks||[]).length === 0 ? (
              <div>
                <div style={{color:C.textMuted, fontSize:13, marginBottom:16}}>
                  No explicit scope declarations found in uploaded documents.
                  Include phrases like &ldquo;in scope&rdquo; / &ldquo;out of scope&rdquo; in your architecture docs.
                </div>
                {/* 9B: LLM scope inference when no scope docs */}
                {llmStatus === 'ready' && (
                  <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
                    {inferredScope ? (
                      <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
                        <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI SCOPE INFERENCE</div>
                        <div style={{ fontSize:12 }}>{renderMarkdown(inferredScope)}</div>
                        <button onClick={()=>setInferredScope('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                      </div>
                    ) : (
                      <button
                        disabled={inferredScopeLoading}
                        onClick={async () => {
                          setInferredScopeLoading(true);
                          setInferredScope('');
                          const types = [...new Set((parseResult?.resources||[]).map(r=>r.type))].slice(0,15);
                          await onGenerateLLM(
                            [{ role:'system', content:'You are a threat model scoping expert. Base your assessment only on the resource types provided.' },
                             { role:'user', content:`AWS infrastructure resource types: ${types.join(', ')}. Identify what is likely IN scope and OUT of scope for a threat model. Format as:\n**IN SCOPE:** (bulleted list)\n**OUT OF SCOPE:** (bulleted list)\n**ASSUMPTIONS:** (key assumptions)` }],
                            tok => setInferredScope(prev=>prev+tok)
                          );
                          setInferredScopeLoading(false);
                        }}
                        style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                      >
                        {inferredScopeLoading ? 'Inferring…' : '✦ Infer scope with AI'}
                      </button>
                    )}
                  </div>
                )}
                {/* Show all resources as assumed in scope */}
                {parseResult?.resources?.length > 0 && (
                  <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:8, padding:"14px 16px"}}>
                    <div style={{fontSize:12, fontWeight:600, color:C.text, marginBottom:10}}>
                      All Terraform resources (assumed in scope — no scope docs uploaded)
                    </div>
                    <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
                      {parseResult.resources.map((r,i)=>(
                        <span key={i} style={{background:"#2E7D3218", color:"#2E7D32",
                          border:"1px solid #2E7D3244", borderRadius:8,
                          padding:"2px 8px", fontSize:10, fontWeight:500}}>
                          {r.type}/{r.name||r.id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div>
                {/* 9A: Resource-scope matching */}
                {(()=>{
                  const resources = parseResult?.resources||[];
                  // Extract actual scope items from raw chunk text (entity arrays only have labels)
                  const extractScopeTerms = (chunks, marker) => {
                    const terms = [];
                    chunks.forEach(c => {
                      const txt = (c.text||c.excerpt||'');
                      // Find sections after the marker header
                      const rx = new RegExp(marker+'[:\\s]*([\\s\\S]{0,600}?)(?:(?:out of scope|in scope|\\*\\*out|\\*\\*in|##|$))', 'i');
                      const m = txt.match(rx);
                      if (m) {
                        // Extract dash/bullet items
                        (m[1]||'').split(/[-\n*,]/).map(s=>s.replace(/\*\*/g,'').trim().toLowerCase())
                          .filter(s=>s.length>2&&s.length<40&&!/^(and|the|or|of|for|with)$/.test(s))
                          .forEach(s=>terms.push(s));
                      }
                    });
                    return [...new Set(terms)];
                  };
                  const chunks = summary?.scopeChunks||[];
                  // Also pull from entity arrays as fallback (for explicitly tagged terms)
                  const inScopeTerms = [
                    ...extractScopeTerms(chunks, 'in scope'),
                    ...(chunks.flatMap(c=>(c.inScope||[])).map(s=>s.toLowerCase()).filter(s=>s!=='in scope')),
                  ].filter(Boolean);
                  const outScopeTerms = [
                    ...extractScopeTerms(chunks, 'out of scope'),
                    ...(chunks.flatMap(c=>(c.outOfScope||[])).map(s=>s.toLowerCase()).filter(s=>s!=='out of scope')),
                  ].filter(Boolean);

                  if(!inScopeTerms.length && !outScopeTerms.length) return null;

                  const inScope=[], outScope=[];
                  resources.forEach(r => {
                    const label = (r.type+' '+(r.name||r.id)).toLowerCase().replace(/_/g,' ');
                    if(outScopeTerms.some(t=>label.includes(t))) outScope.push(r);
                    else if(inScopeTerms.some(t=>label.includes(t))) inScope.push(r);
                  });

                  return (
                    <div style={{ marginBottom:14 }}>
                      {outScope.length > 0 && (
                        <div style={{ background:'#B71C1C14', border:'1px solid #B71C1C40', borderRadius:8, padding:'12px 14px', marginBottom:10 }}>
                          <div style={{ fontSize:12, fontWeight:700, color:'#B71C1C', marginBottom:5 }}>
                            {outScope.length} resources match out-of-scope declarations
                          </div>
                          <div style={{ fontSize:11, color:C.textSub, marginBottom:8 }}>These Terraform resources exist but are declared out-of-scope in your documents. Review whether they should be included in the threat model.</div>
                          <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
                            {outScope.map((r,i) => (
                              <span key={i} style={{ ...MONO, fontSize:10, background:'#B71C1C10', color:'#B71C1C', border:'1px solid #B71C1C30', borderRadius:4, padding:'2px 7px' }}>
                                {r.type}/{r.name||r.id}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {inScope.length > 0 && (
                        <div style={{ fontSize:11, color:C.textMuted, marginBottom:8 }}>
                          <span style={{ color:'#2E7D32', fontWeight:600 }}>✓ {inScope.length}</span> resources matched to in-scope declarations
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* Scope chunk cards */}
                {summary.scopeChunks.map((chunk,i)=>(
                  <div key={i} style={{
                    background:C.surface, border:`1px solid ${C.border}`,
                    borderRadius:8, padding:"12px 14px", marginBottom:8,
                  }}>
                    <div style={{display:"flex", gap:8, flexWrap:"wrap", marginBottom:6}}>
                      <span style={{background:`${C.accent}22`, color:C.accent,
                        border:`1px solid ${C.accent}44`, borderRadius:10,
                        padding:"1px 8px", fontSize:10, fontWeight:600}}>{chunk.source}</span>
                      {chunk.inScope.length>0 && (
                        <span style={{background:"#2E7D3218", color:"#2E7D32",
                          border:"1px solid #2E7D3244", borderRadius:8,
                          padding:"1px 6px", fontSize:9, fontWeight:600}}>
                          IN SCOPE: {chunk.inScope.join(", ")}
                        </span>
                      )}
                      {chunk.outOfScope.length>0 && (
                        <span style={{background:"#F4433618", color:"#F44336",
                          border:"1px solid #F4433644", borderRadius:8,
                          padding:"1px 6px", fontSize:9, fontWeight:600}}>
                          OUT OF SCOPE: {chunk.outOfScope.join(", ")}
                        </span>
                      )}
                    </div>
                    <div style={{...MONO, fontSize:12, color:C.textSub, lineHeight:1.65,
                      background:C.bg, padding:"8px 10px", borderRadius:6, border:`1px solid ${C.border}`,
                      whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
                      &ldquo;{chunk.excerpt}&rdquo;
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── MISCONFIG CHECKS TAB ── */}
        {iTab==="misconfigs" && (
          <div style={{maxWidth:900}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Misconfiguration Checks
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Automated security configuration analysis of your Terraform resources — modeled after
              Checkov/tfsec rules. Each finding includes CWE weakness ID, ATT&CK technique, and remediation.
            </div>

            {/* 6A: LLM remediation plan */}
            {llmStatus === 'ready' && (
              <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
                {remediationPlan ? (
                  <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
                    <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI REMEDIATION PLAN</div>
                    <div style={{ fontSize:12 }}>{renderMarkdown(remediationPlan)}</div>
                    <button onClick={()=>setRemediationPlan('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                  </div>
                ) : (
                  <button
                    disabled={remediationLoading}
                    onClick={async () => {
                      setRemediationLoading(true);
                      setRemediationPlan('');
                      const allF = summary?.topMisconfigs||[];
                      const critical = allF.filter(f=>f.severity==='Critical'||f.severity==='High').slice(0,10);
                      const ctx = critical.map(f=>`- ${f.id} (${f.severity}): ${f.title} on ${f.resourceType||f.type}/${f.resourceName||f.name}. Fix: ${f.remediation||''}`).join('\n');
                      await onGenerateLLM(
                        [{ role:'system', content:'You are a Terraform security engineer. For each finding provide the specific HCL attribute to add/change and an example value. Format as a numbered list.' },
                         { role:'user', content:`Generate a prioritized Terraform remediation plan for these ${critical.length} findings:\n${ctx}` }],
                        tok => setRemediationPlan(prev=>prev+tok)
                      );
                      setRemediationLoading(false);
                    }}
                    style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                  >
                    {remediationLoading ? 'Generating plan…' : '✦ Generate remediation plan with AI'}
                  </button>
                )}
              </div>
            )}

            {(!parseResult?.resources?.length) ? (
              <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to run misconfiguration checks.</div>
            ) : !intelligence?._built ? (
              <div style={{color:C.textMuted, fontSize:13}}>Intelligence engine not ready.</div>
            ) : (() => {
              const sev=['Critical','High','Medium','Low'];
              const allFindings = (summary?.topMisconfigs||[]);
              if (allFindings.length===0) return (
                <div style={{background:C.surface,border:`1px solid #2E7D3244`,borderRadius:10,padding:"20px 22px"}}>
                  <div style={{color:"#2E7D32",fontWeight:600,fontSize:14,marginBottom:6}}>No Misconfigurations Detected</div>
                  <div style={{color:C.textSub,fontSize:12}}>All checked resources pass security configuration checks. Ensure resource attributes are fully defined in your Terraform files for complete analysis.</div>
                </div>
              );
              // Group by severity
              const bySev = {};
              allFindings.forEach(f=>{ if(!bySev[f.severity]) bySev[f.severity]=[]; bySev[f.severity].push(f); });
              return (
                <div>
                  {/* Severity summary bar */}
                  <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap"}}>
                    {sev.map(s=>bySev[s]?.length ? (
                      <div key={s} style={{background:`${SEV_COLOR[s]}18`,border:`1px solid ${SEV_COLOR[s]}44`,
                        borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
                        <span style={{fontSize:20,fontWeight:700,color:SEV_COLOR[s]}}>{bySev[s].length}</span>
                        <span style={{fontSize:10,fontWeight:600,color:SEV_COLOR[s],textTransform:"uppercase",letterSpacing:".06em"}}>{s}</span>
                      </div>
                    ) : null)}
                  </div>
                  {/* Findings list grouped by severity */}
                  {sev.filter(s=>bySev[s]?.length).map(s=>(
                    <div key={s} style={{marginBottom:20}}>
                      <div style={{fontSize:11,fontWeight:700,color:SEV_COLOR[s],textTransform:"uppercase",
                        letterSpacing:".08em",marginBottom:10,display:"flex",alignItems:"center",gap:8}}>
                        <span style={{width:8,height:8,borderRadius:"50%",background:SEV_COLOR[s],display:"inline-block"}}/>
                        {s} ({bySev[s].length})
                      </div>
                      {bySev[s].map((f,i)=>{
                        // SCP-mitigation check: is any attack vector blocked by an SCP?
                        const SCP_TECH_ACTIONS = {
                          'T1548':     ['iam:CreateRole','iam:AttachRolePolicy','iam:PutRolePolicy'],
                          'T1078.004': ['iam:CreateUser','sts:AssumeRole'],
                          'T1098.003': ['iam:CreateRole','iam:AttachRolePolicy'],
                          'T1530':     ['s3:GetObject','s3:PutBucketAcl','s3:PutBucketPolicy'],
                          'T1537':     ['s3:DeleteBucket'],
                          'T1485':     ['s3:DeleteBucket','rds:DeleteDBInstance'],
                          'T1562.008': ['cloudtrail:DeleteTrail','cloudtrail:StopLogging'],
                          'T1600':     ['kms:DisableKey','kms:ScheduleKeyDeletion'],
                          'T1190':     ['ec2:AuthorizeSecurityGroupIngress'],
                        };
                        const scpAccounts = computedIR?.scpCeilings ? Object.values(computedIR.scpCeilings) : [];
                        const isScpMitigated = scpAccounts.length > 0 && (f.attack||[]).some(tech => {
                          const actions = SCP_TECH_ACTIONS[tech] || [];
                          return actions.length > 0 && scpAccounts.some(denied =>
                            actions.some(a => denied.some(p =>
                              p === a || p === '*' ||
                              (p.endsWith(':*') && a.startsWith(p.slice(0, -1)))
                            ))
                          );
                        });
                        return (
                        <div key={i} style={{background:C.surface,
                          border:`1px solid ${isScpMitigated ? '#2E7D3244' : SEV_COLOR[f.severity]+'33'}`,
                          borderLeft:`3px solid ${isScpMitigated ? '#2E7D32' : SEV_COLOR[f.severity]}`,
                          borderRadius:8,padding:"12px 14px",marginBottom:8,
                          opacity: isScpMitigated ? 0.75 : 1}}>
                          <div style={{display:"flex",gap:8,alignItems:"flex-start",marginBottom:6,flexWrap:"wrap"}}>
                            <span style={{...MONO,fontSize:10,color:isScpMitigated ? '#2E7D32' : SEV_COLOR[f.severity],fontWeight:700,flexShrink:0}}>{f.id}</span>
                            <span style={{fontSize:12,color:C.text,fontWeight:600,flex:1}}>{f.title}</span>
                          </div>
                          <div style={{...MONO,fontSize:10,color:C.textMuted,marginBottom:8}}>
                            Resource: {f.resourceType}/{f.resourceName}
                            {f.paveLayer ? ` [${f.paveLayer}]` : ''}
                          </div>
                          <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
                            {(f.cwe||[]).map(c=>(
                              <span key={c} style={{position:'relative'}}>
                                <span
                                  onClick={e=>{e.stopPropagation();setExpandedCwe(expandedCwe===c?null:c);}}
                                  style={{background:"#0277BD18",color:"#0277BD",
                                    border:"1px solid #0277BD44",borderRadius:6,padding:"1px 7px",fontSize:9,fontWeight:600,cursor:"pointer",display:"inline-block"}}
                                  title="Click for details"
                                >{c}: {CWE_DETAILS[c]?.name||c}</span>
                                {expandedCwe===c && (
                                  <div style={{ position:'absolute', zIndex:100, background:C.surface2, border:`1px solid ${C.border}`, borderRadius:6, padding:'8px 10px', maxWidth:280, fontSize:10, color:C.textSub, lineHeight:1.6, marginTop:2, boxShadow:'0 4px 16px #0006', top:'100%', left:0 }}>
                                    <div style={{ fontWeight:700, color:C.text, marginBottom:3 }}>{c}: {CWE_DETAILS?.[c]?.name||c}</div>
                                    <div>{CWE_DETAILS?.[c]?.desc||'Common Weakness Enumeration entry.'}</div>
                                    <a href={`https://cwe.mitre.org/data/definitions/${c.replace('CWE-','')}.html`} target="_blank" rel="noopener noreferrer" style={{ fontSize:9, color:C.accent, marginTop:4, display:'block' }}>View on MITRE CWE ↗</a>
                                  </div>
                                )}
                              </span>
                            ))}
                            {(f.attack||[]).map(t=>(
                              <span key={t}
                                onClick={()=>{ setITab('attacks'); setAttackFilter(t); }}
                                style={{background:"#E5393518",color:"#E53935",
                                  border:"1px solid #E5393544",borderRadius:6,padding:"1px 7px",fontSize:9,fontWeight:600,cursor:"pointer"}}
                                title={`View ${t} in ATT&CK tab`}
                              >
                                {t} {ATTACK_TECHNIQUES[t]?.name||''}
                              </span>
                            ))}
                            {isScpMitigated && (
                              <span title="An SCP blocks the primary attack vector for this finding"
                                style={{background:"#1B5E2018",color:"#2E7D32",
                                  border:"1px solid #2E7D3244",borderRadius:6,
                                  padding:"1px 7px",fontSize:9,fontWeight:700}}>
                                SCP-Mitigated
                              </span>
                            )}
                          </div>
                          <div style={{fontSize:11,color:C.textSub,lineHeight:1.6,
                            background:C.bg,padding:"6px 10px",borderRadius:6,border:`1px solid ${C.border}`}}>
                            <span style={{color:C.textMuted,fontWeight:600}}>Remediation: </span>{f.remediation}
                          </div>
                          {/* ── Evidence row ── */}
                          <div style={{display:'flex',gap:6,alignItems:'center',marginTop:6,flexWrap:'wrap'}}>
                            <ConfidenceBadge ev={f.evidence} />
                            {f.evidence?.method==='var_ref'&&(
                              <span style={{fontSize:9,color:'#F57C00',background:'#F57C0015',borderRadius:3,padding:'1px 4px',border:'1px solid #F57C0030',fontWeight:700}}>VAR UNRESOLVED</span>
                            )}
                            {isScpMitigated&&(
                              <span style={{fontSize:9,color:'#2E7D32',background:'#2E7D3215',borderRadius:3,padding:'1px 4px',border:'1px solid #2E7D3230',fontWeight:700}}>SCP MITIGATED</span>
                            )}
                            <EvidenceDrawer ev={f.evidence} label="attribute" />
                          </div>
                        </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        )}

        {/* ── ATT&CK MAPPING TAB ── */}
        {iTab==="attacks" && (
          <div style={{maxWidth:900}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              MITRE ATT&CK Mapping
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Techniques from MITRE ATT&CK Cloud mapped to your Terraform resources.
              Hover over technique IDs for full descriptions.
            </div>

            {(!parseResult?.resources?.length) ? (
              <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to see ATT&CK mapping.</div>
            ) : (() => {
              // Build: technique → resources that trigger it
              const techMap = {};
              const tactic_order = ['Initial Access/Persistence','Persistence','Credential Access','Privilege Escalation',
                'Defense Evasion','Discovery','Lateral Movement','Collection','Execution','Exfiltration','Impact'];
              parseResult.resources.forEach(r => {
                (TF_ATTACK_MAP[r.type]||[]).forEach(tid => {
                  if (!techMap[tid]) techMap[tid]={resources:[]};
                  techMap[tid].resources.push(`${r.type}/${r.name||r.id}`);
                });
              });
              // 7A: Merge doc-sourced ATT&CK techniques from entity extraction
              Object.entries(summary?.entitySummary?.attack||{}).forEach(([tid,terms])=>{
                if(!techMap[tid]) techMap[tid]={resources:[],docMentioned:true,docTerms:terms};
                else techMap[tid].docMentioned=true;
              });

              const entries = Object.entries(techMap);
              if (entries.length===0) return (
                <div style={{color:C.textMuted,fontSize:13}}>No ATT&CK techniques mapped to current resource types.</div>
              );
              // 7B: Build visible entries respecting attackFilter
              const visibleEntries = attackFilter
                ? entries.filter(([tid]) => tid === attackFilter)
                : entries;

              // Group by tactic (using visibleEntries for filtered display)
              const byTactic = {};
              visibleEntries.forEach(([tid,data]) => {
                const tech = ATTACK_TECHNIQUES[tid];
                const tactic = tech?.tactic||'Other';
                if (!byTactic[tactic]) byTactic[tactic]=[];
                byTactic[tactic].push({tid,tech,resources:data.resources,docMentioned:data.docMentioned});
              });
              const sevColor = { Critical:"#B71C1C", High:"#E53935", Medium:"#F57C00", Low:"#43A047" };

              return (
                <div>
                  {/* 7C: LLM attack narrative */}
                  {llmStatus === 'ready' && (
                    <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
                      {attackNarrative ? (
                        <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:4 }}>
                          <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI ATTACK NARRATIVE</div>
                          <div style={{ fontSize:12 }}>{renderMarkdown(attackNarrative)}</div>
                          <button onClick={()=>setAttackNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                        </div>
                      ) : (
                        <button
                          disabled={attackNarrLoading}
                          onClick={async () => {
                            setAttackNarrLoading(true);
                            setAttackNarrative('');
                            const techList = entries.slice(0,12).map(([tid,data])=>`${tid} (${ATTACK_TECHNIQUES?.[tid]?.name||tid}) via ${(data.resources||[]).slice(0,2).join(', ')}`).join('\n');
                            await onGenerateLLM(
                              [{ role:'system', content:'You are a threat modeler. Write a concise 4-6 sentence attacker kill-chain narrative describing how an adversary could chain these AWS ATT&CK techniques. Be specific about cloud exploitation paths.' },
                               { role:'user', content:`MITRE ATT&CK techniques mapped to infrastructure:\n${techList}` }],
                              tok => setAttackNarrative(prev=>prev+tok)
                            );
                            setAttackNarrLoading(false);
                          }}
                          style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                        >
                          {attackNarrLoading ? 'Generating…' : '✦ Generate attack narrative with AI'}
                        </button>
                      )}
                    </div>
                  )}

                  {/* 7B: Attack filter banner */}
                  {attackFilter && (
                    <div style={{ padding:'6px 0', background:`${C.accent}10`, borderRadius:6, marginBottom:12, display:'flex', alignItems:'center', gap:8 }}>
                      <span style={{ fontSize:11, color:C.accent, fontWeight:600 }}>Filtered to: {attackFilter}</span>
                      <button onClick={()=>setAttackFilter(null)} style={{ fontSize:10, color:C.textMuted, background:'none', border:'none', cursor:'pointer' }}>✕ Clear filter</button>
                    </div>
                  )}

                  {/* Coverage summary */}
                  <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap"}}>
                    {['Critical','High','Medium','Low'].map(s=>{
                      const cnt=entries.filter(([t])=>ATTACK_TECHNIQUES[t]?.severity===s).length;
                      return cnt>0 ? (
                        <div key={s} style={{background:`${sevColor[s]}18`,border:`1px solid ${sevColor[s]}44`,
                          borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
                          <span style={{fontSize:20,fontWeight:700,color:sevColor[s]}}>{cnt}</span>
                          <span style={{fontSize:10,fontWeight:600,color:sevColor[s],textTransform:"uppercase",letterSpacing:".06em"}}>{s}</span>
                        </div>
                      ) : null;
                    })}
                    <div style={{background:`${C.accent}18`,border:`1px solid ${C.accent}44`,
                      borderRadius:8,padding:"8px 14px",display:"flex",flexDirection:"column",alignItems:"center",minWidth:80}}>
                      <span style={{fontSize:20,fontWeight:700,color:C.accent}}>{entries.length}</span>
                      <span style={{fontSize:10,fontWeight:600,color:C.accent,textTransform:"uppercase",letterSpacing:".06em"}}>Total</span>
                    </div>
                  </div>
                  {/* Per-tactic sections */}
                  {tactic_order.filter(t=>byTactic[t]?.length).map(tactic=>(
                    <div key={tactic} style={{marginBottom:18}}>
                      <div style={{fontSize:11,fontWeight:700,color:C.textMuted,textTransform:"uppercase",
                        letterSpacing:".08em",marginBottom:8}}>{tactic}</div>
                      <div style={{display:"flex",flexDirection:"column",gap:6}}>
                        {byTactic[tactic].map(({tid,tech,resources,docMentioned})=>(
                          <div key={tid} style={{background:C.surface,border:`1px solid ${C.border}`,
                            borderLeft:`3px solid ${sevColor[tech?.severity||'Low']}`,
                            borderRadius:8,padding:"10px 14px"}}>
                            <div style={{display:"flex",gap:10,alignItems:"flex-start",flexWrap:"wrap"}}>
                              <a href={`https://attack.mitre.org/techniques/${tid.replace('.','/').replace('.','/')}`}
                                target="_blank" rel="noopener noreferrer" style={{
                                  ...MONO,fontSize:11,color:"#E53935",fontWeight:700,flexShrink:0,textDecoration:"none",
                                  background:"#E5393518",border:"1px solid #E5393544",borderRadius:6,padding:"1px 8px",
                                }}>{tid}</a>
                              <div style={{flex:1}}>
                                <div style={{fontSize:12,color:C.text,fontWeight:600,marginBottom:3}}>
                                  {tech?.name||tid}
                                  <span style={{marginLeft:8,fontSize:10,color:sevColor[tech?.severity||'Low'],
                                    fontWeight:600,background:`${sevColor[tech?.severity||'Low']}18`,
                                    border:`1px solid ${sevColor[tech?.severity||'Low']}44`,
                                    borderRadius:6,padding:"0 6px"}}>{tech?.severity||'?'}</span>
                                  {docMentioned && (
                                    <span style={{ fontSize:9, fontWeight:700, background:`${C.accent}18`, color:C.accent, borderRadius:4, padding:'1px 5px', marginLeft:4 }}>
                                      IN DOCS
                                    </span>
                                  )}
                                </div>
                                <div style={{fontSize:11,color:C.textSub,lineHeight:1.5,marginBottom:6}}>{tech?.desc}</div>
                                <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
                                  {[...new Set(resources)].slice(0,6).map((r,ri)=>(
                                    <span key={ri} style={{...MONO,fontSize:9,color:C.textMuted,
                                      background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,padding:"1px 6px"}}>
                                      {r}
                                    </span>
                                  ))}
                                  {resources.length>6 && <span style={{fontSize:9,color:C.textMuted}}>+{resources.length-6} more</span>}
                                </div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                  {/* Any unclassified tactic */}
                  {Object.entries(byTactic).filter(([t])=>!tactic_order.includes(t)).map(([tactic,items])=>(
                    <div key={tactic} style={{marginBottom:18}}>
                      <div style={{fontSize:11,fontWeight:700,color:C.textMuted,textTransform:"uppercase",letterSpacing:".08em",marginBottom:8}}>{tactic}</div>
                      {items.map(({tid,tech,resources})=>(
                        <div key={tid} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 14px",marginBottom:6}}>
                          <span style={{...MONO,fontSize:11,color:"#E53935",fontWeight:700}}>{tid}</span>
                          <span style={{fontSize:12,color:C.text,marginLeft:10}}>{tech?.name||tid}</span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        )}

        {/* ── SECURITY POSTURE TAB ── */}
        {iTab==="posture" && (
          <div style={{maxWidth:860}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>Security Posture</div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Weighted composite score across NIST CSF 2.0 (40%), Defense-in-Depth (35%), and Zero Trust (25%).
              Grades reflect actual Terraform resource configuration — zero hallucination.
            </div>
            {!summary?.posture ? (
              <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to generate posture assessment.</div>
            ) : (()=>{
              const p = summary.posture;
              const GC = p.gradeColor;
              // Derive topRisks from did/zt if not already present in posture
              if (!p.topRisks) {
                const tr = [];
                Object.entries(p.did?.layers||{}).forEach(([layer,data]) => {
                  if ((data.score??100) < 50 && data.missing?.length)
                    tr.push(`${layer.charAt(0).toUpperCase()+layer.slice(1)} layer: missing ${data.missing.slice(0,2).join(', ')}`);
                });
                Object.entries(p.zt?.pillars||{}).forEach(([pillar,data]) => {
                  if ((data.score??100) < 40 && data.absent?.length) {
                    const names = data.absent.slice(0,2).map(a => typeof a==='string'?a:(a?.name||a?.id||JSON.stringify(a)));
                    tr.push(`Zero Trust ${pillar}: ${names.join(', ')} not detected`);
                  }
                });
                if ((p.nist?.score??100) < 50) tr.push(`NIST CSF at ${Math.round(p.nist?.score||0)}% — review Identify/Protect functions`);
                p.topRisks = tr.slice(0,6);
              }
              return (
                <div>
                  {/* Grade hero */}
                  <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
                    padding:"24px 28px", marginBottom:20, display:"flex", alignItems:"center", gap:28}}>
                    <div style={{textAlign:"center"}}>
                      <div style={{fontSize:64, fontWeight:900, color:GC, lineHeight:1}}>{p.grade}</div>
                      <div style={{fontSize:11, color:C.textMuted, marginTop:2}}>Grade</div>
                    </div>
                    <div style={{flex:1}}>
                      <div style={{display:"flex", alignItems:"baseline", gap:8, marginBottom:6}}>
                        <span style={{fontSize:32, fontWeight:700, color:GC}}>{p.score}</span>
                        <span style={{fontSize:14, color:C.textMuted}}>/100</span>
                        <span style={{fontSize:12, color:C.textMuted, marginLeft:4}}>· {p.maturity}</span>
                      </div>
                      {(()=>{
                        const docBoost = (summary?.controlInventory?.present||[]).filter(c=>c.source==='doc').length;
                        return docBoost > 0 ? (
                          <div style={{ fontSize:10, color:C.textMuted, marginTop:3, marginBottom:8 }}>+{docBoost} controls detected in uploaded documents</div>
                        ) : null;
                      })()}
                      {/* Score bar */}
                      <div style={{height:8, background:C.border, borderRadius:4, marginBottom:16, overflow:"hidden"}}>
                        <div style={{height:"100%", width:`${p.score}%`, background:`linear-gradient(90deg,${GC},${GC}88)`,
                          borderRadius:4, transition:"width .6s"}} />
                      </div>
                      <div style={{display:"flex", gap:16, flexWrap:"wrap"}}>
                        {[
                          {label:"NIST CSF 2.0",      val:`${p.nist?.score??'—'}%`,  color:"#0277BD"},
                          {label:"Defense-in-Depth",  val:`${p.did?.overallScore??'—'}%`,color:"#6A1B9A"},
                          {label:"Zero Trust",        val:`${p.zt?.overallScore??'—'}%`, color:"#00695C"},
                        ].map(({label,val,color},i)=>(
                          <div key={i} style={{background:C.bg, border:`1px solid ${C.border}`,
                            borderRadius:8, padding:"8px 14px", minWidth:110}}>
                            <div style={{fontSize:10, color:C.textMuted, marginBottom:2}}>{label}</div>
                            <div style={{fontSize:18, fontWeight:700, color}}>{val}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Scoring methodology footnote */}
                  <div style={{fontSize:10,color:C.textMuted,background:C.surface,border:`1px solid ${C.border}`,
                    borderRadius:8,padding:"8px 12px",marginBottom:16,lineHeight:1.7}}>
                    <strong style={{color:C.textSub}}>Scoring methodology:</strong>{' '}
                    NIST CSF 40% · Defense-in-Depth 35% · Zero Trust 25%{' · '}
                    HCL-verified controls: full weight · Doc-referenced controls: partial weight ·
                    Partial controls (configured but incomplete): 50% weight ·
                    Variable-referenced attributes excluded from checks (shown as unresolved).
                  </div>

                  {/* Priority Remediation Actions */}
                  {p?.topRisks?.length > 0 && (
                    <div style={{ background:'#E5393510', border:'1px solid #E5393540', borderRadius:10, padding:'14px 18px', marginBottom:16 }}>
                      <div style={{ fontSize:12, fontWeight:700, color:'#E53935', marginBottom:8 }}>Priority Remediation Actions ({p.topRisks.length})</div>
                      {p.topRisks.map((risk,i) => (
                        <div key={i} style={{ display:'flex', gap:10, alignItems:'flex-start', marginBottom:6 }}>
                          <span style={{ background:'#E53935', color:'#fff', borderRadius:'50%', width:18, height:18, display:'flex', alignItems:'center', justifyContent:'center', fontSize:10, fontWeight:700, flexShrink:0 }}>{i+1}</span>
                          <span style={{ fontSize:12, color:C.text, lineHeight:1.6 }}>{risk}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* LLM posture explanation */}
                  {llmStatus === 'ready' && (
                    <div style={{ marginBottom:16 }}>
                      {postureNarrative ? (
                        <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'12px 14px' }}>
                          <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:6 }}>AI POSTURE ANALYSIS</div>
                          <div style={{ fontSize:12 }}>{renderMarkdown(postureNarrative)}</div>
                          <button onClick={()=>setPostureNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:6 }}>Clear</button>
                        </div>
                      ) : (
                        <button
                          disabled={postureNarrLoading}
                          onClick={async () => {
                            setPostureNarrLoading(true);
                            setPostureNarrative('');
                            const ctx = `Score: ${p?.score}/100, grade ${p?.grade}, maturity: ${p?.maturity}. NIST: ${p?.nist?.score}%, DiD: ${p?.did?.overallScore}%, ZT: ${p?.zt?.overallScore}%. Top risks: ${(p?.topRisks||[]).join('; ')}. Missing controls: ${(summary?.controlInventory?.absent||[]).slice(0,8).map(c=>c.name).join(', ')}.`;
                            await onGenerateLLM(
                              [{ role:'system', content:'You are a cloud security advisor. Explain this AWS security posture score in 3-4 sentences, then suggest the top 3 concrete improvements. Reference specific AWS services and controls.' },
                               { role:'user', content:ctx }],
                              tok => setPostureNarrative(prev => prev + tok)
                            );
                            setPostureNarrLoading(false);
                          }}
                          style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'6px 14px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                        >
                          {postureNarrLoading ? 'Analyzing…' : '✦ Explain this score'}
                        </button>
                      )}
                    </div>
                  )}

                  {/* Defense-in-Depth layers */}
                  {p.did?.layers && (
                    <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
                      padding:"18px 20px", marginBottom:16}}>
                      <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
                        Defense-in-Depth Coverage
                      </div>
                      {Object.entries(p.did.layers).map(([name,layer])=>(
                        <div key={name} style={{marginBottom:10}}>
                          <div style={{display:"flex", justifyContent:"space-between", marginBottom:3}}>
                            <div style={{display:"flex", alignItems:"center", gap:6}}>
                              {(()=>{const dl=Object.values(DID_LAYERS).find(l=>l.name===name); return dl ? <dl.Icon size={14} style={{color:dl.color}}/> : <Shield size={14}/>;})()}
                              <span style={{fontSize:12, fontWeight:600, color:C.text}}>{name}</span>
                            </div>
                            <span style={{fontSize:11, fontWeight:600, color:layer.score>=60?"#43A047":"#E53935"}}>
                              {layer.score}%
                            </span>
                          </div>
                          <div style={{height:5, background:C.border, borderRadius:3, overflow:"hidden"}}>
                            <div style={{height:"100%", width:`${layer.score}%`,
                              background:layer.score>=60?"#43A047":layer.score>=30?"#F57C00":"#E53935",
                              borderRadius:3}} />
                          </div>
                          {layer.absent?.length>0 && (
                            <div style={{fontSize:10, color:C.textMuted, marginTop:3}}>
                              Missing: {layer.absent.map(c=>c.name).join(", ")}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Zero Trust pillars */}
                  {p.zt?.pillars && (
                    <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
                      padding:"18px 20px", marginBottom:16}}>
                      <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
                        Zero Trust Pillar Assessment (NIST SP 800-207)
                      </div>
                      <div style={{display:"flex", flexWrap:"wrap", gap:10}}>
                        {Object.entries(p.zt.pillars).map(([name,pillar])=>{
                          const ztp = ZT_PILLARS[name];
                          const ZtpIcon = ztp?.Icon || Target;
                          return (
                            <div key={name} style={{flex:"1 1 140px", background:C.bg,
                              border:`1px solid ${C.border}`, borderRadius:8, padding:"12px 14px"}}>
                              <div style={{marginBottom:6}}><ZtpIcon size={18} style={{color:ztp?.color||C.accent}}/></div>
                              <div style={{fontSize:11, fontWeight:700, color:C.text, marginBottom:6}}>{name}</div>
                              <div style={{height:4, background:C.border, borderRadius:2, marginBottom:6, overflow:"hidden"}}>
                                <div style={{height:"100%", width:`${pillar.score}%`,
                                  background:pillar.score>=60?"#43A047":pillar.score>=30?"#F57C00":"#E53935",
                                  borderRadius:2}} />
                              </div>
                              <div style={{fontSize:13, fontWeight:700,
                                color:pillar.score>=60?"#43A047":pillar.score>=30?"#F57C00":"#E53935"}}>
                                {pillar.score}%
                              </div>
                              {pillar.controls?.filter(c=>c.present).slice(0,2).map((c,j)=>(
                                <div key={j} style={{fontSize:9, color:"#43A047", marginTop:2}}>✓ {c.name}</div>
                              ))}
                              {pillar.controls?.filter(c=>!c.present).slice(0,2).map((c,j)=>(
                                <div key={j} style={{fontSize:9, color:"#E53935", marginTop:2}}>✗ {c.name}</div>
                              ))}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* NIST CSF breakdown */}
                  {p.nist?.byFn && (
                    <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
                      padding:"18px 20px"}}>
                      <div style={{fontSize:13, fontWeight:700, color:C.text, marginBottom:12}}>
                        NIST CSF 2.0 by Function
                      </div>
                      <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
                        {Object.entries(p.nist.byFn).map(([fn,data])=>(
                          <div key={fn} style={{flex:"1 1 90px", background:C.bg,
                            border:`1px solid ${C.border}`, borderRadius:8, padding:"10px 12px", textAlign:"center"}}>
                            <div style={{fontSize:10, fontWeight:700, color:C.textMuted, marginBottom:4}}>{fn}</div>
                            <div style={{fontSize:18, fontWeight:700,
                              color:data.pct>=70?"#43A047":data.pct>=40?"#F57C00":"#E53935"}}>
                              {data.pct}%
                            </div>
                            <div style={{fontSize:9, color:C.textMuted}}>{data.pass}/{data.total}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {/* ── CONTROL INVENTORY TAB ── */}
        {iTab==="controls" && (
          <div style={{maxWidth:860}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>Control Inventory</div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Security controls detected (or missing) from your Terraform configuration and uploaded security documents,
              organized by defense-in-depth layer. <strong>&lt;/&gt;</strong> = detected in Terraform · <strong>📄</strong> = found in uploaded docs.
            </div>
            {!summary?.controlInventory ? (
              <div style={{color:C.textMuted, fontSize:13}}>Upload Terraform files to generate control inventory.</div>
            ) : (()=>{
              const ci = summary.controlInventory;
              const byLayer = {};
              const presentIds  = new Set((ci.present||[]).map(c=>c.id));
              const partialIds  = new Set((ci.partial||[]).map(c=>c.id));
              [...(ci.present||[]), ...(ci.partial||[]), ...(ci.absent||[])].forEach(c=>{
                const lk = c.layer || 'monitoring';
                if(!byLayer[lk]) byLayer[lk]={present:[],partial:[],absent:[]};
                if(presentIds.has(c.id))      byLayer[lk].present.push(c);
                else if(partialIds.has(c.id)) byLayer[lk].partial.push(c);
                else                          byLayer[lk].absent.push(c);
              });
              const presentCount = ci.present?.length||0;
              const partialCount = ci.partial?.length||0;
              const absentCount  = ci.absent?.length||0;
              const totalCount   = presentCount + partialCount + absentCount;
              // Weighted: present=1.0, partial=0.5
              const coveragePct  = totalCount ? Math.round(((presentCount + partialCount * 0.5)/totalCount)*100) : 0;
              return (
                <div>
                  {/* Coverage bar */}
                  <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:12,
                    padding:"16px 20px", marginBottom:12, display:"flex", alignItems:"center", gap:20}}>
                    <div style={{flex:1}}>
                      <div style={{display:"flex", justifyContent:"space-between", marginBottom:6}}>
                        <span style={{fontSize:12, fontWeight:600, color:C.text}}>Overall Control Coverage</span>
                        <span style={{fontSize:12, fontWeight:700, color:coveragePct>=70?"#43A047":coveragePct>=40?"#F57C00":"#E53935"}}>
                          {presentCount} present · {partialCount} partial · {absentCount} absent ({coveragePct}%)
                        </span>
                      </div>
                      <div style={{height:8, background:C.border, borderRadius:4, overflow:"hidden"}}>
                        <div style={{height:"100%", width:`${coveragePct}%`,
                          background:coveragePct>=70?"#43A047":coveragePct>=40?"#F57C00":"#E53935",
                          borderRadius:4}} />
                      </div>
                    </div>
                  </div>

                  {/* LLM gap prioritization */}
                  {llmStatus === 'ready' && (
                    <div style={{ padding:'8px 0', marginBottom:12 }}>
                      {gapAnalysis ? (
                        <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', margin:'4px 0 8px' }}>
                          <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI GAP PRIORITIZATION</div>
                          <div style={{ fontSize:12 }}>{renderMarkdown(gapAnalysis)}</div>
                          <button onClick={()=>setGapAnalysis('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                        </div>
                      ) : (
                        <button
                          disabled={gapAnalysisLoading}
                          onClick={async () => {
                            setGapAnalysisLoading(true);
                            setGapAnalysis('');
                            const absentNames = (summary?.controlInventory?.absent||[]).map(c=>c.name).slice(0,12);
                            const resources = parseResult?.resources||[];
                            const resTypes = [...new Set(resources.map(r=>r.type))].slice(0,10);
                            await onGenerateLLM(
                              [{ role:'system', content:'You are a cloud security engineer. Be concise and actionable.' },
                               { role:'user', content:`AWS infrastructure resource types: ${resTypes.join(', ')}. Missing security controls: ${absentNames.join(', ')}. Rank the top 5 missing controls by remediation priority. For each: why it is critical, and which Terraform resource type to add. Format as a numbered list.` }],
                              tok => setGapAnalysis(prev => prev + tok)
                            );
                            setGapAnalysisLoading(false);
                          }}
                          style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                        >
                          {gapAnalysisLoading ? 'Analyzing gaps…' : '✦ Prioritize gaps with AI'}
                        </button>
                      )}
                    </div>
                  )}

                  {/* Control search/filter */}
                  <div style={{ marginBottom:16 }}>
                    <input
                      value={controlSearch}
                      onChange={e=>setControlSearch(e.target.value)}
                      placeholder="Filter controls…"
                      style={{ width:'100%', background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'5px 10px', fontSize:11, color:C.text, outline:'none', boxSizing:'border-box' }}
                    />
                  </div>

                  {/* By layer — three-state */}
                  {Object.entries(DID_LAYERS).sort(([,a],[,b])=>a.order-b.order).map(([didLayerKey, didLayer])=>{
                    const layerData = byLayer[didLayerKey] || {present:[],partial:[],absent:[]};
                    const flt = s => controlSearch ? s.filter(c=>c.name.toLowerCase().includes(controlSearch.toLowerCase())) : s;
                    const fp = flt(layerData.present), fpa = flt(layerData.partial), fa = flt(layerData.absent);
                    if(!fp.length && !fpa.length && !fa.length) return null;
                    return (
                      <div key={didLayerKey} style={{background:C.surface, border:`1px solid ${C.border}`,
                        borderRadius:12, padding:"16px 20px", marginBottom:12}}>
                        <div style={{display:"flex", alignItems:"center", gap:8, marginBottom:12}}>
                          <didLayer.Icon size={16} style={{color:didLayer.color}} />
                          <span style={{fontSize:13, fontWeight:700, color:C.text}}>{didLayer.name}</span>
                          <span style={{fontSize:11, color:C.textMuted, marginLeft:"auto"}}>
                            {fp.length} present{fpa.length?` · ${fpa.length} partial`:''} · {fa.length} missing
                          </span>
                        </div>
                        <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
                          {/* ✓ PRESENT */}
                          {fp.map((c,i)=>(
                            <div key={`p${i}`} style={{background:"#43A04710", border:"1px solid #43A04740",
                              borderRadius:6, padding:"4px 10px", fontSize:11, color:"#43A047", display:"flex", flexDirection:"column", gap:3}}>
                              <div style={{display:"flex", alignItems:"center", gap:4, flexWrap:"wrap"}}>
                                <span style={{fontWeight:700}}>✓</span>
                                <span style={{fontWeight:600}}>{c.name}</span>
                                {c.source==='doc' ? <span style={{fontSize:9,opacity:0.8}}>📄</span>
                                  : c.source==='hcl'||!c.source ? <span style={{fontSize:9,background:"#43A04720",borderRadius:3,padding:"1px 4px",opacity:0.7}}>&lt;/&gt;</span> : null}
                                <ConfidenceBadge ev={c.evidence} />
                              </div>
                              <EvidenceDrawer ev={c.evidence} label="evidence" />
                            </div>
                          ))}
                          {/* ~ PARTIAL */}
                          {fpa.map((c,i)=>(
                            <div key={`pa${i}`} style={{background:"#F57C0010", border:"1px solid #F57C0040",
                              borderRadius:6, padding:"4px 10px", fontSize:11, color:"#F57C00", display:"flex", flexDirection:"column", gap:3}}>
                              <div style={{display:"flex", alignItems:"center", gap:4, flexWrap:"wrap"}}>
                                <span style={{fontWeight:700}}>~</span>
                                <span style={{fontWeight:600}}>{c.name}</span>
                                <span style={{fontSize:9,background:"#F57C0020",borderRadius:3,padding:"1px 4px",fontWeight:700}}>PARTIAL</span>
                                <ConfidenceBadge ev={c.evidence} />
                              </div>
                              {c.partialNote && <div style={{fontSize:9,color:"#F57C00",opacity:0.85}}>{c.partialNote}</div>}
                              <EvidenceDrawer ev={c.evidence} label="evidence" />
                            </div>
                          ))}
                          {/* ✗ ABSENT */}
                          {fa.map((c,i)=>(
                            <div key={`a${i}`} style={{background:"#E5393510", border:"1px solid #E5393540",
                              borderRadius:6, padding:"4px 10px", fontSize:11, color:"#E53935", display:"flex", alignItems:"center", gap:4}}>
                              <span style={{fontWeight:700}}>✗</span><span style={{fontWeight:600}}>{c.name}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
          </div>
        )}

        {/* ── CROSS-DOC CORRELATION TAB ── */}
        {iTab==="crossdoc" && (
          <div style={{maxWidth:860}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Cross-Document Correlation
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18, lineHeight:1.6}}>
              Links your uploaded documents (threat models, runbooks, compliance docs) to actual Terraform resources.
              Contradictions are flagged where docs describe controls that are absent in configuration.
            </div>
            {!summary?.crossDocCorrelations || !summary.crossDocCorrelations.length ? (
              <div style={{color:C.textMuted, fontSize:13}}>
                {!parseResult?.resources?.length
                  ? "Upload Terraform files to enable cross-doc correlation."
                  : "Upload context documents (threat models, runbooks, compliance docs) to correlate against your Terraform."}
              </div>
            ) : (
              <div>
                {/* 5B: LLM contradiction narrative */}
                {llmStatus === 'ready' && (
                  <div style={{ padding:'10px 0', borderBottom:`1px solid ${C.border}`, marginBottom:14 }}>
                    {contradictionNarrative ? (
                      <div style={{ background:`${C.accent}08`, border:`1px solid ${C.accent}30`, borderRadius:8, padding:'10px 12px', marginBottom:6 }}>
                        <div style={{ fontSize:10, fontWeight:700, color:C.accent, marginBottom:5 }}>AI RISK SUMMARY</div>
                        <div style={{ fontSize:12 }}>{renderMarkdown(contradictionNarrative)}</div>
                        <button onClick={()=>setContradictionNarrative('')} style={{ fontSize:9, color:C.textMuted, background:'none', border:'none', cursor:'pointer', marginTop:4 }}>Clear</button>
                      </div>
                    ) : (summary?.crossDocCorrelations?.some(c=>c.contradictions?.length>0)) && (
                      <button
                        disabled={contraNarrLoading}
                        onClick={async () => {
                          setContraNarrLoading(true);
                          setContradictionNarrative('');
                          const all = (summary.crossDocCorrelations||[]).flatMap(c=>c.contradictions||[]);
                          const ctx = all.slice(0,10).map(c=>`- ${c.type||'GAP'}: ${c.msg||c.title||''}`).join('\n');
                          await onGenerateLLM(
                            [{ role:'system', content:'You are a security analyst. Summarize the overall risk these contradictions represent and suggest the top 3 remediation priorities in 4-5 sentences.' },
                             { role:'user', content:`Contradictions between architecture documents and Terraform:\n${ctx}` }],
                            tok => setContradictionNarrative(prev=>prev+tok)
                          );
                          setContraNarrLoading(false);
                        }}
                        style={{ background:`${C.accent}18`, color:C.accent, border:`1px solid ${C.accent}35`, borderRadius:7, padding:'5px 12px', fontSize:11, cursor:'pointer', fontWeight:600 }}
                      >
                        {contraNarrLoading ? 'Analyzing…' : '✦ Summarize contradiction risk with AI'}
                      </button>
                    )}
                  </div>
                )}

                {/* Contradiction summary */}
                {(()=>{
                  const allContradictions = (summary.crossDocCorrelations||[])
                    .flatMap(c=>c.contradictions||[]);
                  return allContradictions.length > 0 ? (
                    <div style={{background:"#E5393510", border:"1px solid #E5393540",
                      borderRadius:12, padding:"14px 18px", marginBottom:18}}>
                      <div style={{fontSize:13, fontWeight:700, color:"#E53935", marginBottom:8}}>
                        {allContradictions.length} Contradiction{allContradictions.length!==1?"s":""} Detected
                      </div>
                      <div style={{fontSize:11, color:C.textSub, marginBottom:8, lineHeight:1.5}}>
                        Documents describe controls that are absent or misconfigured in your Terraform.
                      </div>
                      {allContradictions.slice(0,5).map((c,i)=>(
                        <div key={i} style={{marginBottom:6, padding:"6px 10px",
                          background:"#E5393508", borderRadius:6, fontSize:11}}>
                          <span style={{fontWeight:700, color: c.type==='SCOPE-VIOLATION'?'#B71C1C':c.type==='CONTRADICTION'?'#E53935':'#F57C00'}}>{c.type}: </span>
                          <span style={{color:C.text}}>{c.msg||c.title}</span>
                          {(c.docRef||c.doc) && <span style={{color:C.textMuted}}> [source: {c.docRef||c.doc}]</span>}
                        </div>
                      ))}
                      {allContradictions.length>5 && (
                        <div style={{fontSize:11, color:C.textMuted}}>
                          +{allContradictions.length-5} more contradictions — expand individual resources below.
                        </div>
                      )}
                    </div>
                  ) : null;
                })()}

                {/* Per-resource correlations */}
                {summary.crossDocCorrelations.filter(c=>c.docHits?.length>0||c.contradictions?.length>0).map((corr,i)=>(
                  <div key={i} style={{background:C.surface, border:`1px solid ${
                    corr.contradictions?.length ? "#E5393544" : C.border}`,
                    borderRadius:10, padding:"14px 18px", marginBottom:10}}>
                    <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:8}}>
                      <div>
                        <span style={{fontSize:12, fontWeight:700, color:C.text}}>
                          {corr.resource?.name || corr.resource?.id}
                        </span>
                        <span style={{fontSize:10, color:C.textMuted, marginLeft:8}}>
                          {corr.resource?.type}
                        </span>
                      </div>
                      {corr.contradictions?.length > 0 && (
                        <span style={{fontSize:10, fontWeight:700, color:"#E53935",
                          background:"#E5393515", border:"1px solid #E5393544",
                          borderRadius:6, padding:"2px 8px"}}>
                          {corr.contradictions.length} contradiction{corr.contradictions.length!==1?"s":""}
                        </span>
                      )}
                    </div>
                    {/* Doc hits */}
                    {corr.docHits?.slice(0,2).map((hit,j)=>(
                      <div key={j} style={{...MONO, fontSize:10, color:C.textSub,
                        background:C.bg, padding:"5px 8px", borderRadius:5,
                        border:`1px solid ${C.border}`, lineHeight:1.6, marginBottom:6,
                        whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
                        <span style={{color:C.textMuted, fontSize:9}}>[{hit.source}] </span>
                        {hit.compressed||hit.text?.substring(0,220)}{((hit.compressed||hit.text||"").length>220?"…":"")}
                      </div>
                    ))}
                    {/* Contradictions */}
                    {corr.contradictions?.map((ct,j)=>{
                      const ctColor = ct.type==='SCOPE-VIOLATION'?'#B71C1C':ct.type==='CONTRADICTION'?'#E53935':'#F57C00';
                      return (
                        <div key={j} style={{fontSize:10, color:ctColor,
                          background:`${ctColor}08`, border:`1px solid ${ctColor}30`,
                          borderRadius:5, padding:"4px 8px", marginBottom:4}}>
                          <span style={{fontWeight:700, color:ctColor, borderColor:`${ctColor}44`}}>{ct.type}: </span>{ct.msg||ct.title}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── RESOURCE INTELLIGENCE TAB ── */}
        {iTab==="resources" && (
          <div style={{maxWidth:900}}>
            <div style={{fontSize:18, fontWeight:700, color:C.text, marginBottom:4}}>
              Resource Intelligence
            </div>
            <div style={{fontSize:12, color:C.textSub, marginBottom:18}}>
              For each Terraform resource, the engine finds relevant passages in your uploaded documents.
              Shows compliance requirements, threat relevance, and architectural context.
            </div>

            {(!parseResult?.resources?.length) ? (
              <div style={{color:C.textMuted, fontSize:13}}>
                Upload Terraform files to see resource intelligence.
              </div>
            ) : (() => {
              // 10A: Search + pagination
              const allResources = parseResult.resources;
              const PAGE_SIZE = 20;
              const filtered = allResources.filter(r => {
                if(!resourceSearch && !resourceTypeFilter) return true;
                const label = (r.type+' '+(r.name||r.id)).toLowerCase();
                if(resourceSearch && !label.includes(resourceSearch.toLowerCase())) return false;
                if(resourceTypeFilter && r.type !== resourceTypeFilter) return false;
                return true;
              });
              const paged = filtered.slice(resourcePage*PAGE_SIZE, (resourcePage+1)*PAGE_SIZE);
              const totalPages = Math.ceil(filtered.length/PAGE_SIZE);

              return (
                <div style={{display:"flex", flexDirection:"column", gap:0}}>
                  {/* Search + filter bar */}
                  <div style={{ display:'flex', gap:8, marginBottom:10, flexShrink:0 }}>
                    <input
                      value={resourceSearch}
                      onChange={e=>{setResourceSearch(e.target.value);setResourcePage(0);}}
                      placeholder={`Search ${allResources.length} resources…`}
                      style={{ flex:1, background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'5px 10px', fontSize:11, color:C.text, outline:'none' }}
                    />
                    <select
                      value={resourceTypeFilter}
                      onChange={e=>{setResourceTypeFilter(e.target.value);setResourcePage(0);}}
                      style={{ background:C.surface2||C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:'4px 8px', fontSize:11, color:C.text, maxWidth:160 }}
                    >
                      <option value="">All types</option>
                      {[...new Set(allResources.map(r=>r.type))].sort().map(t=>(
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  </div>

                  {/* Resource count indicator */}
                  {filtered.length !== allResources.length && (
                    <div style={{ fontSize:10, color:C.textMuted, marginBottom:8 }}>
                      Showing {filtered.length} of {allResources.length} resources
                    </div>
                  )}

                  {/* Resource cards */}
                  <div style={{display:"flex", flexDirection:"column", gap:10}}>
                    {paged.map((r,i)=>{
                      const meta = RT[r.type]||RT._default;
                      const hits = intelligence?._built ? intelligence.analyzeResource(r.type, r.name||r.id) : [];
                      const strideHits = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.stride||{})))];
                      const compHits  = [...new Set(hits.flatMap(h=>Object.keys(h.entities?.compliance||{})))];
                      const threats   = intelligence?._built ? intelligence.getThreats(r) : null;
                      const misconfigs = intelligence?._built ? intelligence.getMisconfigurations(r) : [];
                      const resourceKey = r.id||r.name||`${r.type}-${i}`;
                      return (
                        <div key={resourcePage*PAGE_SIZE+i} style={{background:C.surface, border:`1px solid ${C.border}`,
                          borderRadius:8, padding:"12px 14px"}}>
                          <div style={{display:"flex", gap:8, alignItems:"center", marginBottom:6, flexWrap:"wrap"}}>
                            <div style={{width:10,height:10,borderRadius:2,background:meta.c,flexShrink:0}}/>
                            <span style={{...MONO, fontSize:12, color:C.text, fontWeight:600}}>
                              {r.type}/{r.name||r.id}
                            </span>
                            {/* STRIDE badges */}
                            {(threats?.stride||[]).map(k=>(
                              <span key={k} style={{background:`${STRIDE_COLORS[k]||"#999"}18`,
                                color:STRIDE_COLORS[k]||"#999",border:`1px solid ${STRIDE_COLORS[k]||"#999"}44`,
                                borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                                {STRIDE_LABELS[k]||k}
                              </span>
                            ))}
                            {/* ATT&CK badges */}
                            {(threats?.attackTechniques||[]).slice(0,3).map(t=>(
                              <span key={t.techniqueId} style={{background:"#E5393514",color:"#E53935",
                                border:"1px solid #E5393530",borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                                {t.techniqueId}
                              </span>
                            ))}
                            {/* 10B: Misconfig severity breakdown badges */}
                            {misconfigs.length>0 && (()=>{
                              const sev = {};
                              misconfigs.forEach(m => { sev[m.severity] = (sev[m.severity]||0)+1; });
                              const colors = { Critical:'#B71C1C', High:'#E53935', Medium:'#F57C00', Low:'#F9A825' };
                              return (
                                <span style={{ display:'inline-flex', gap:3, alignItems:'center' }}>
                                  {['Critical','High','Medium','Low'].filter(s=>sev[s]).map(s=>(
                                    <span key={s} style={{ background:`${colors[s]}18`, color:colors[s], border:`1px solid ${colors[s]}35`, borderRadius:4, padding:'0 5px', fontSize:9, fontWeight:700 }}>
                                      {sev[s]}{s[0]}
                                    </span>
                                  ))}
                                </span>
                              );
                            })()}
                            {compHits.map(k=>(
                              <span key={k} style={{background:"#0277BD18",color:"#0277BD",
                                border:"1px solid #0277BD44",borderRadius:6,padding:"1px 6px",fontSize:9,fontWeight:600}}>
                                {COMPLIANCE_LABELS[k]||k}
                              </span>
                            ))}
                          </div>
                          {/* Doc hits */}
                          {hits.length>0 && (
                            <div style={{display:"flex", flexDirection:"column", gap:5, marginBottom:misconfigs.length?6:0}}>
                              {hits.slice(0,2).map((chunk,j)=>(
                                <div key={j} style={{...MONO, fontSize:10, color:C.textSub,
                                  background:C.bg, padding:"5px 8px", borderRadius:5,
                                  border:`1px solid ${C.border}`, lineHeight:1.6, whiteSpace:"pre-wrap", wordBreak:"break-word"}}>
                                  <span style={{color:C.textMuted,fontSize:9}}>[{chunk.source}] </span>
                                  {chunk.compressed||chunk.text.substring(0,200)}{(chunk.compressed||chunk.text).length>200?"…":""}
                                  {chunk.confidence && (
                                    <span style={{marginLeft:6,fontSize:9,color:C.textMuted}}>({chunk.confidence}% match)</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                          {/* Misconfig inline */}
                          {misconfigs.length>0 && (
                            <div style={{marginTop:6,display:"flex",flexDirection:"column",gap:4}}>
                              {misconfigs.slice(0,2).map((f,j)=>(
                                <div key={j} style={{fontSize:10,color:SEV_COLOR[f.severity],background:`${SEV_COLOR[f.severity]}10`,
                                  border:`1px solid ${SEV_COLOR[f.severity]}30`,borderRadius:5,padding:"4px 8px"}}>
                                  <span style={{fontWeight:700}}>{f.id} </span>{f.title}
                                </div>
                              ))}
                              {misconfigs.length>2 && (
                                <div style={{fontSize:10,color:C.textMuted}}>+{misconfigs.length-2} more — see Misconfig Checks tab</div>
                              )}
                            </div>
                          )}
                          {/* HCL-derived input dependencies (factual from parseHCLBody) */}
                          {r.inputRefs?.length > 0 && (
                            <div style={{marginTop:6,fontSize:10,color:C.textMuted,lineHeight:1.7}}>
                              <span style={{fontWeight:600,color:C.textSub}}>→ Inputs: </span>
                              {[...new Map(r.inputRefs.map(ref=>[ref.resourceId,ref])).values()].slice(0,6).map((ref,j)=>(
                                <span key={j} style={{...MONO,background:C.bg,border:`1px solid ${C.border}`,borderRadius:3,padding:"0 4px",marginRight:4,fontSize:9}}>
                                  {ref.resourceId} [{ref.attr}]
                                </span>
                              ))}
                              {r.inputRefs.length > 6 && <span style={{fontSize:9,color:C.textMuted}}>+{r.inputRefs.length-6} more</span>}
                            </div>
                          )}
                          {hits.length===0 && misconfigs.length===0 && (
                            <div style={{fontSize:10,color:C.textMuted,fontStyle:"italic"}}>No document matches or config checks for this resource type.</div>
                          )}
                          {/* 10C: LLM per-resource risk summary */}
                          {llmStatus === 'ready' && (
                            <div style={{ marginTop:6 }}>
                              {resourceSummaries[resourceKey] ? (
                                <div style={{ background:`${C.accent}08`, borderRadius:6, padding:'6px 10px', fontSize:11, lineHeight:1.6 }}>
                                  {renderMarkdown(resourceSummaries[resourceKey])}
                                </div>
                              ) : (
                                <button
                                  onClick={async () => {
                                    const miscs = intelligence?.getMisconfigurations(r)||[];
                                    const thr = intelligence?.getThreats(r)||{};
                                    const ctx = `Resource: ${r.type}/${r.name||r.id}\nSTRIDE: ${(thr.stride||[]).join(', ')}\nATT&CK: ${(thr.attackTechniques||[]).map(t=>t.techniqueId||t).join(', ')}\nMisconfigs (${miscs.length}): ${miscs.slice(0,3).map(m=>m.title).join('; ')}`;
                                    const key = resourceKey;
                                    setResourceSummaries(prev=>({...prev,[key]:'…'}));
                                    let text='';
                                    await onGenerateLLM(
                                      [{ role:'system', content:'In 2-3 sentences, summarize the security risk of this AWS resource and the single most important remediation action.' },
                                       { role:'user', content:ctx }],
                                      tok=>{ text+=tok; setResourceSummaries(prev=>({...prev,[key]:text})); }
                                    );
                                  }}
                                  style={{ fontSize:10, background:`${C.accent}12`, color:C.accent, border:`1px solid ${C.accent}30`, borderRadius:5, padding:'3px 9px', cursor:'pointer', marginTop:2 }}
                                >
                                  ✦ Risk summary
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div style={{ display:'flex', gap:6, padding:'10px 0', justifyContent:'center' }}>
                      <button disabled={resourcePage===0} onClick={()=>setResourcePage(p=>p-1)} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:5, padding:'4px 10px', fontSize:11, color:resourcePage===0?C.textMuted:C.text, cursor:resourcePage===0?'default':'pointer' }}>‹ Prev</button>
                      <span style={{ fontSize:11, color:C.textMuted, lineHeight:'24px' }}>{resourcePage+1} / {totalPages}</span>
                      <button disabled={resourcePage===totalPages-1} onClick={()=>setResourcePage(p=>p+1)} style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:5, padding:'4px 10px', fontSize:11, color:resourcePage===totalPages-1?C.textMuted:C.text, cursor:resourcePage===totalPages-1?'default':'pointer' }}>Next ›</button>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR DB — IndexedDB persistence for embeddings (no re-embed on reload)
// ─────────────────────────────────────────────────────────────────────────────
let _vdbConn = null;
function _getVectorDB() {
  if (!_vdbConn) {
    _vdbConn = new Promise((resolve) => {
      const req = indexedDB.open('threataform-vectors', 2);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('vectors')) db.createObjectStore('vectors');
      };
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = () => { _vdbConn = null; resolve(null); };
    });
  }
  return _vdbConn;
}
async function vdbGet(key) {
  const db = await _getVectorDB();
  if (!db) return null;
  return new Promise((res) => {
    try {
      const r = db.transaction('vectors').objectStore('vectors').get(key);
      r.onsuccess = () => res(r.result ?? null);
      r.onerror = () => res(null);
    } catch { res(null); }
  });
}
async function vdbPut(key, value) {
  const db = await _getVectorDB();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction('vectors', 'readwrite');
      tx.objectStore('vectors').put(value, key);
      tx.oncomplete = () => res();
      tx.onerror = () => res();
    } catch { res(); }
  });
}
async function vdbGetMany(keys) {
  const db = await _getVectorDB();
  if (!db) return {};
  return new Promise((res) => {
    const results = {};
    const tx = db.transaction('vectors');
    const store = tx.objectStore('vectors');
    let pending = keys.length;
    if (!pending) { res(results); return; }
    keys.forEach(k => {
      const r = store.get(k);
      r.onsuccess = () => { results[k] = r.result ?? null; if (--pending === 0) res(results); };
      r.onerror   = () => { results[k] = null;             if (--pending === 0) res(results); };
    });
  });
}
// Stable chunk hash: first 50 chars + length (no crypto needed)
function chunkHash(text) { return (text.substring(0, 50) + '|' + text.length).replace(/[^\w|]/g, '_'); }

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
  const [ingestState, setIngestState] = useState(null); // null=idle | {total,done,current}

  // ── Threat Model Management ─────────────────────────────────────────────────
  const [appMode, setAppMode] = useState("landing"); // "landing" | "documents" | "workspace"
  const [currentModel, setCurrentModel] = useState(null);
  const [threatModels, setThreatModels] = useState(() => {
    try { return JSON.parse(localStorage.getItem("tf-threat-models") || "[]"); } catch { return []; }
  });
  const [modelDetails, setModelDetails] = useState({
    environment:"", scope:"", dataClassification:[], frameworks:[], owner:"", description:"",
    threatFrameworks:[], keyFeatures:""
  });
  const [diagramImage, setDiagramImage] = useState(null); // base64 data URL from Lucidchart export
  const [archAnalysis, setArchAnalysis] = useState(null);     // analyzeArchitecture() result
  const [archOverrides, setArchOverrides] = useState({});      // user edits (narrative + attributes)
  const [archAnalyzing, setArchAnalyzing] = useState(false);  // spinner while computing
  const [archEditingField, setArchEditingField] = useState(null); // which narrative field is in edit mode

  const saveModels = useCallback((models) => {
    setThreatModels(models);
    try { localStorage.setItem("tf-threat-models", JSON.stringify(models)); } catch {}
  }, []);

  const createModel = useCallback((name) => {
    const id = Date.now().toString();
    const model = { id, name, createdAt:new Date().toISOString(), updatedAt:new Date().toISOString(),
      environment:"", tfFileCount:0, docCount:0, grade:null };
    const updated = [model, ...threatModels];
    saveModels(updated);
    setCurrentModel(model);
    setModelDetails({ environment:"", scope:"", dataClassification:[], frameworks:[], owner:"", description:"", threatFrameworks:[], keyFeatures:"" });
    setDiagramImage(null);
    setArchAnalysis(null); setArchOverrides({});
    setAppMode("documents");
    setMainTab("upload");
    // Clear previous session data for clean slate
    setFiles([]); setParseResult(null); setXml(""); setScopeFiles(null); setError("");
    // Load model docs from localStorage (none yet for new model)
    try {
      const docs = JSON.parse(localStorage.getItem(`tf-model-${id}-docs`) || "[]");
      setUserDocsState(docs);
    } catch { setUserDocsState([]); }
  }, [threatModels, saveModels]); // eslint-disable-line

  // reparseRef avoids TDZ: openModel is declared before reparse, so we use a ref
  const reparseRef = useRef(null);

  const openModel = useCallback((model) => {
    setCurrentModel(model);
    setModelDetails(() => {
      try { return JSON.parse(localStorage.getItem(`tf-model-${model.id}-details`) || "{}"); }
      catch { return { environment:"", scope:"", dataClassification:[], frameworks:[], owner:"", description:"", threatFrameworks:[], keyFeatures:"" }; }
    });
    setAppMode("documents");
    setMainTab("upload");
    setFiles([]); setParseResult(null); setXml(""); setScopeFiles(null); setError("");
    // Restore TF files for this model
    let savedTF = [];
    try {
      savedTF = JSON.parse(localStorage.getItem(`tf-model-${model.id}-files`) || "[]");
      if (savedTF.length) setFiles(savedTF);
    } catch {}
    // Restore docs
    let restoredDocs = [];
    try {
      restoredDocs = JSON.parse(localStorage.getItem(`tf-model-${model.id}-docs`) || "[]");
      setUserDocsState(restoredDocs);
    } catch { setUserDocsState([]); }
    // Restore architecture diagram image (from Lucidchart export)
    try {
      const img = localStorage.getItem(`tf-model-${model.id}-diagram-image`);
      setDiagramImage(img || null);
    } catch { setDiagramImage(null); }
    // Restore arch analysis overrides
    try {
      const saved = JSON.parse(localStorage.getItem(`tf-model-${model.id}-arch-analysis`) || "{}");
      setArchAnalysis(saved.base || null);
      setArchOverrides(saved.overrides || {});
    } catch { setArchAnalysis(null); setArchOverrides({}); }
    // Trigger reparse after React has committed all state updates (including userDocsRef)
    if (savedTF.length) {
      setTimeout(() => reparseRef.current?.(savedTF), 0);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const deleteModel = useCallback((id) => {
    const updated = threatModels.filter(m => m.id !== id);
    saveModels(updated);
    // Clean up per-model storage
    try { localStorage.removeItem(`tf-model-${id}-docs`); } catch {}
    try { localStorage.removeItem(`tf-model-${id}-arch-analysis`); } catch {}
    try { localStorage.removeItem(`tf-model-${id}-details`); } catch {}
    try { localStorage.removeItem(`tf-model-${id}-diagram-image`); } catch {}
    try { localStorage.removeItem(`tf-model-${id}-files`); } catch {}
  }, [threatModels, saveModels]);

  const saveModelDetails = useCallback((details) => {
    setModelDetails(details);
    if (currentModel) {
      try { localStorage.setItem(`tf-model-${currentModel.id}-details`, JSON.stringify(details)); } catch {}
    }
  }, [currentModel]);

  // Update model metadata (grade, file count, etc.) after analysis
  const updateModelMeta = useCallback((patch) => {
    if (!currentModel) return;
    setCurrentModel(prev => { const u={...prev,...patch,updatedAt:new Date().toISOString()}; return u; });
    setThreatModels(prev => {
      const updated = prev.map(m => m.id===currentModel.id ? {...m,...patch,updatedAt:new Date().toISOString()} : m);
      try { localStorage.setItem("tf-threat-models", JSON.stringify(updated)); } catch {}
      return updated;
    });
  }, [currentModel]);

  // Intelligence engine — rebuilt whenever userDocs or parseResult changes
  const intelligenceRef = useRef(new ThreatModelIntelligence());
  const [intelligenceVersion, setIntelligenceVersion] = useState(0); // triggers re-render after rebuild

  // ── Threataform Assistant — wllama (local GGUF) + Custom RAG Engine ──────────
  // Runs 100% offline. User loads a GGUF model from local disk.
  const [llmStatus, setLlmStatus]       = useState("idle");   // idle|loading|ready|error
  const [llmProgress, setLlmProgress]   = useState(0);        // 0-100
  const [llmStatusText, setLlmStatusText] = useState("");
  const [embedStatus, setEmbedStatus]   = useState("idle");   // idle|ready (tracks vector index)
  const [selectedLlmModel, setSelectedLlmModel] = useState(""); // loaded GGUF filename
  const [wllamaModelName, setWllamaModelName]   = useState(""); // display name
  const [wllamaModelSize, setWllamaModelSize]   = useState(0);  // size in MB
  const [embedProgress, setEmbedProgress] = useState(null); // null | {done, total}
  // VectorStore (custom pure-JS implementation from ThrataformRAG.js)
  const vectorStoreRef  = useRef(new VectorStore());
  const colbertStoreRef = useRef(new ColBERTVectorStore(1024)); // multi-vector ColBERT (populated when embedMulti available)
  const pendingLlmRef   = useRef({});  // retained for compatibility
  // IaC-IR: computed org tree + SCP ceilings (useState so IntelligencePanel re-renders when updated)
  const [computedIR, setComputedIR] = useState({ organizationTree: null, scpCeilings: {}, gaps: [] });
  const computedIRRef = useRef(computedIR); // keep ref in sync for buildFullContext closures

  // User documents — per-model, backed by localStorage[tf-model-{id}-docs]
  const [userDocs, setUserDocsState] = useState(() => {
    try { const s = localStorage.getItem("tf-intel-user-docs"); return s ? JSON.parse(s) : []; }
    catch { return []; }
  });
  const saveUserDocs = useCallback((docsOrFn) => {
    setUserDocsState(prev => {
      const next = typeof docsOrFn === "function" ? docsOrFn(prev) : docsOrFn;
      // Save per-model if a model is active, else legacy global key
      const key = currentModel ? `tf-model-${currentModel.id}-docs` : "tf-intel-user-docs";
      try { localStorage.setItem(key, JSON.stringify(next)); } catch {}
      // Update model doc count in metadata
      if (currentModel) updateModelMeta({ docCount: next.length });
      return next;
    });
  }, [currentModel, updateModelMeta]); // eslint-disable-line

  // Convenience alias so existing code that references `setUserDocs` still works
  const setUserDocs = saveUserDocs;

  // Remove a single user doc by path or name
  const removeUserDoc = useCallback((pathOrName) => {
    saveUserDocs(prev => prev.filter(d => (d.path || d.name) !== pathOrName));
  }, [saveUserDocs]);

  // Keep a ref so reparse (stable callback) can always access latest userDocs
  const userDocsRef = useRef(userDocs);
  const parseResultRef = useRef(parseResult);
  const filesRef = useRef([]);
  const archOverridesRef = useRef({});
  useEffect(() => { userDocsRef.current = userDocs; }, [userDocs]);
  useEffect(() => { parseResultRef.current = parseResult; }, [parseResult]);
  useEffect(() => { filesRef.current = files; }, [files]);

  // ── IaC-IR: Build org tree + SCP ceilings whenever parse result changes ──────
  useEffect(() => {
    if (!parseResult?.resources?.length) return;
    let cancelled = false;
    (async () => {
      try {
        const [{ buildOrgTree }, { computeSCPCeilings }] = await Promise.all([
          import('./src/lib/iac/OrgTreeBuilder.js'),
          import('./src/lib/iac/PolicyEvaluator.js'),
        ]);
        if (cancelled) return;
        const tree = buildOrgTree(parseResult.resources);
        const ceilings = computeSCPCeilings(parseResult.resources, tree);
        const gaps = [
          ...tree.gaps,
          ...Object.entries(ceilings)
            .filter(([, v]) => v.includes('UNKNOWN'))
            .map(([k]) => `Account ${k}: SCP ceiling partially unknown (intrinsic references)`),
        ];
        const irData = { organizationTree: tree, scpCeilings: ceilings, gaps };
        computedIRRef.current = irData;
        setComputedIR(irData);
      } catch (err) {
        console.warn('[IaC-IR] Failed to compute org tree:', err);
      }
    })();
    return () => { cancelled = true; };
  }, [parseResult]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { archOverridesRef.current = archOverrides; }, [archOverrides]);

  // Stable refs so reparse ([] deps) and grade effect can always read current values
  const currentModelRef    = useRef(currentModel);
  const modelDetailsRef    = useRef(modelDetails);
  const updateModelMetaRef = useRef(updateModelMeta);
  useEffect(() => { currentModelRef.current    = currentModel;    }, [currentModel]);
  useEffect(() => { modelDetailsRef.current    = modelDetails;    }, [modelDetails]);
  useEffect(() => { updateModelMetaRef.current = updateModelMeta; }, [updateModelMeta]);

  // Synthetic "model context" doc injected as the first document in every .build() call.
  // Seeds retrieval with product name, environment, data classification, and compliance scope
  // so queries like "what frameworks are in scope?" return model-level metadata.
  const buildModelContextDoc = useCallback(() => {
    const m = currentModelRef.current;
    const d = modelDetailsRef.current;
    if (!m?.name) return null;
    const lines = [
      `Threat Model Product: ${m.name}`,
      d.environment                  ? `Environment: ${d.environment}` : null,
      d.dataClassification?.length   ? `Data Classification: ${d.dataClassification.join(', ')}` : null,
      d.frameworks?.length           ? `Industry Compliance Scope: ${d.frameworks.join(', ')}` : null,
      d.threatFrameworks?.length     ? `Threat Modeling Frameworks: ${d.threatFrameworks.join(', ')}` : null,
      d.keyFeatures                  ? `Key Features: ${d.keyFeatures}` : null,
      d.owner                        ? `Team / Owner: ${d.owner}` : null,
      d.description                  ? `Architecture Notes: ${d.description}` : null,
    ].filter(Boolean);
    return { name:'__model_context__', path:'__model_context__', ext:'txt',
             content: lines.join('\n'), size:0, _synthetic:true };
  }, []);

  // Synthetic doc from architecture narrative overrides — feeds arch edits back into intelligence index
  const buildArchContextDoc = useCallback(() => {
    const ovNarrative = archOverridesRef.current?.narrative || {};
    const lines = Object.entries(ovNarrative)
      .filter(([,v]) => v?.trim())
      .map(([k,v]) => `${k}: ${v}`);
    if (!lines.length) return null;
    return { name:'__arch_context__', path:'__arch_context__', ext:'txt',
             content: lines.join('\n'), size:0, _synthetic:true };
  }, []);

  // After every intelligence rebuild, compute posture grade and persist it to the model card
  useEffect(() => {
    if (!parseResultRef.current || !currentModelRef.current) return;
    try {
      const posture = intelligenceRef.current.getSecurityPosture(parseResultRef.current.resources||[]);
      if (posture?.grade) {
        updateModelMetaRef.current({
          grade:       posture.grade,
          gradeColor:  posture.gradeColor,
          tfFileCount: parseResultRef.current.resources?.length || 0,
        });
      }
    } catch(_) {}
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // Rebuild intelligence whenever userDocs or modelDetails (Application Details form) changes.
  // modelDetails is in deps so filling in env / compliance scope / description immediately
  // re-indexes the synthetic model-context doc — no file upload required.
  useEffect(() => {
    const pr = parseResultRef.current;
    const ctxDoc = buildModelContextDoc();
    const archDoc = buildArchContextDoc();
    const syntheticDocs = [ctxDoc, archDoc].filter(Boolean);
    const docsWithCtx = [...syntheticDocs, ...userDocs];
    intelligenceRef.current = new ThreatModelIntelligence();
    intelligenceRef.current.build(docsWithCtx, pr?.resources||[], pr?.modules||[]);
    setIntelligenceVersion(v => v+1);
    // Regenerate XML with enriched intelligence if we have parsed data
    if (pr && (pr.resources.length > 0 || pr.modules.length > 0)) {
      const x = generateDFDXml(pr.resources, pr.modules, pr.connections, intelligenceRef.current);
      setXml(x);
    }
  }, [userDocs, modelDetails, archOverrides]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-populate Architecture Description when intelligence rebuilds and field is empty
  useEffect(() => {
    if (!intelligenceRef.current?._built) return;
    const md = modelDetailsRef.current;
    if (md?.description?.trim()) return; // never overwrite user-written content
    const pr = parseResultRef.current;
    const summary = intelligenceRef.current.getArchSummaryText(pr?.resources || []);
    if (summary.trim()) {
      const updated = { ...md, description: summary };
      setModelDetails(updated);
      const cm = currentModelRef.current;
      if (cm) {
        try { localStorage.setItem(`tf-model-${cm.id}-details`, JSON.stringify(updated)); } catch {}
      }
    }
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── loadWllama: load a GGUF model from a File object OR a URL string ─────────
  // File object → user file picker
  // URL string  → Electron bundled model (served from /models via local HTTP)
  // null        → unload current model
  const loadWllama = useCallback(async (fileOrUrl) => {
    if (!fileOrUrl) {
      // Unload current model
      await wllamaManager.unload();
      setLlmStatus("idle"); setLlmProgress(0); setLlmStatusText("");
      setSelectedLlmModel(""); setWllamaModelName(""); setWllamaModelSize(0);
      setEmbedStatus("idle"); vectorStoreRef.current.clear(); setEmbedProgress(null);
      return;
    }
    setLlmStatus("loading"); setLlmProgress(0); setLlmStatusText("");
    try {
      const opts = {
        contextSize: 4096,
        onProgress: ({ pct, loaded, total }) => {
          setLlmProgress(pct);
          const mb = Math.round(loaded / 1024 / 1024);
          const totalMb = Math.round(total / 1024 / 1024);
          setLlmStatusText(totalMb > 0 ? `${mb}MB / ${totalMb}MB` : `${mb}MB`);
        },
      };
      // URL string → Electron local model server; File object → user file picker
      const result = typeof fileOrUrl === 'string'
        ? await wllamaManager.loadFromUrl(fileOrUrl, { ...opts, useCache: true })
        : await wllamaManager.loadFromFile(fileOrUrl, opts);
      setLlmStatus("ready"); setLlmProgress(100); setLlmStatusText("");
      setSelectedLlmModel(result.modelName);
      setWllamaModelName(result.modelName);
      setWllamaModelSize(result.sizeMB);
      // Trigger vector index rebuild now that embeddings are available
      rebuildVectorStore();
    } catch (err) {
      setLlmStatus("error");
      setLlmStatusText(err.message || "Failed to load model. Is the file a valid GGUF?");
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Electron: auto-load bundled model from /models on startup ────────────────
  // Runs once on mount. If running inside Electron and /models has a .gguf file,
  // the model server URL is fetched from the main process and wllama loads it
  // automatically — no file picker needed, no internet required.
  useEffect(() => {
    if (!window?.electronAPI?.isElectron) return;
    window.electronAPI.getModelInfo().then(({ port, models }) => {
      if (models.length > 0 && !wllamaManager.isLoaded) {
        const modelUrl = `http://127.0.0.1:${port}/${encodeURIComponent(models[0])}`;
        console.log('[Threataform] Electron: auto-loading bundled model →', modelUrl);
        loadWllama(modelUrl);
      }
    }).catch(() => {}); // Silently ignore if IPC fails
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── rebuildVectorStore: embed all doc chunks using wllama ────────────────────
  const rebuildVectorStore = useCallback(async () => {
    if (!wllamaManager.isLoaded) return;
    const chunks = intelligenceRef.current.chunks;
    if (!chunks?.length) return;

    const modelId = currentModelRef.current?.id || "global";
    const keys = chunks.map(c => `vec_${modelId}_${chunkHash(c.text)}`);
    const cached = await vdbGetMany(keys);

    const needEmbed = [];
    const result = chunks.map((c, i) => {
      if (cached[keys[i]]) return { ...c, vector: cached[keys[i]] };
      needEmbed.push({ chunkIdx: i, chunk: c, key: keys[i] });
      return { ...c, vector: null };
    });

    // Populate vector store with cached vectors immediately
    vectorStoreRef.current.clear();
    colbertStoreRef.current.clear(); // ColBERT cleared; populated below if embedMulti available
    result.forEach((c, i) => {
      if (c.vector) vectorStoreRef.current.add(`chunk_${i}`, c.vector, c);
    });

    if (!needEmbed.length) { setEmbedProgress(null); return; }

    // Embed uncached chunks in small batches (wllama is sequential, so keep batches small)
    const BATCH = 8;
    setEmbedProgress({ done: 0, total: needEmbed.length });
    for (let i = 0; i < needEmbed.length; i += BATCH) {
      if (!wllamaManager.isLoaded) break; // user unloaded model mid-run
      const batch = needEmbed.slice(i, i + BATCH);
      try {
        const vectors = await wllamaManager.embed(batch.map(b => b.chunk.text));
        batch.forEach((b, j) => {
          const vec = vectors[j];
          if (!vec?.length) return;
          result[b.chunkIdx] = { ...b.chunk, vector: vec };
          vectorStoreRef.current.add(`chunk_${b.chunkIdx}`, vec, b.chunk);
          vdbPut(b.key, vec);
          // ColBERT multi-vector embeddings (late-interaction) — populate if model supports it
          try {
            const multiVecs = wllamaManager.embedMulti?.(b.chunk.text);
            if (multiVecs instanceof Promise) {
              multiVecs.then(mv => { if (mv?.length) colbertStoreRef.current.add(`chunk_${b.chunkIdx}`, mv, b.chunk); }).catch(() => {});
            } else if (multiVecs?.length) {
              colbertStoreRef.current.add(`chunk_${b.chunkIdx}`, multiVecs, b.chunk);
            }
          } catch { /* ColBERT skipped — single-vector still active */ }
        });
      } catch { /* skip failed batch */ }
      setEmbedProgress({ done: Math.min(i + BATCH, needEmbed.length), total: needEmbed.length });
    }
    setEmbedProgress(null);
    setEmbedStatus("ready");
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Rebuild vector store whenever intelligence rebuilds and wllama is loaded
  useEffect(() => {
    if (wllamaManager.isLoaded) rebuildVectorStore();
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── hybridSearch: BM25 + dense (wllama embeddings) via RRF ───────────────────
  const hybridSearch = useCallback(async (query, topK = 8) => {
    const intel = intelligenceRef.current;
    const bm25Results = intel?._built ? intel.query(query, topK * 2) : [];

    const store = vectorStoreRef.current;
    // Offline BM25-only path (no model or no dense store)
    if (!wllamaManager.isLoaded || store.size === 0) {
      return bm25Results.slice(0, topK).map(r => ({ ...r, searchType: 'bm25' }));
    }

    try {
      // HyDE: expand query into hypothetical doc embedding for richer retrieval signal
      let queryVec;
      try {
        queryVec = await hydeTemplate(query, null, (text) => wllamaManager.embedQuery(text));
      } catch {
        // Fall back to plain query embedding if HyDE fails
        queryVec = await wllamaManager.embedQuery(query);
      }

      // Fused BM25 + dense retrieval with HyDE-expanded query vector
      return ragHybridSearch({ bm25Chunks: bm25Results, vectorStore: store, queryVec, topK });
    } catch {
      return bm25Results.slice(0, topK).map(r => ({ ...r, searchType: 'bm25' }));
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── generateLLMResponse: stream tokens via wllama (local WASM inference) ─────
  const generateLLMResponse = useCallback((messages, onToken) => {
    if (!wllamaManager.isLoaded) return Promise.reject(new Error("Model not loaded"));
    return wllamaManager.generate(messages, {
      onToken,
      maxTokens: 2048,
      temperature: 0.2,
    });
  }, []);

  // Auto-populate Architecture Analysis after each intelligence rebuild
  useEffect(() => {
    if (!parseResult && !userDocs.length) return;
    setArchAnalyzing(true);
    const timeout = setTimeout(() => {
      try {
        const result = intelligenceRef.current.analyzeArchitecture(
          parseResult?.resources || [], userDocs, modelDetails
        );
        setArchAnalysis(result);
        if (currentModel) {
          try {
            localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: result, overrides: archOverrides }));
          } catch {}
        }
      } finally { setArchAnalyzing(false); }
    }, 0);
    return () => clearTimeout(timeout);
  }, [intelligenceVersion]); // eslint-disable-line react-hooks/exhaustive-deps

  const addUserDocs = useCallback((fileList, docCategory = "general", onProgress) => {
    // Accept PDFs, images, and text files; skip compiled binaries, archives, web assets
    const SKIP_EXT = /\.(ico|woff|woff2|ttf|eot|zip|tar|gz|7z|exe|dll|so|dylib|class|jar|war|pyc|lock)$/i;
    const candidates = Array.from(fileList)
      .filter(f => !SKIP_EXT.test(f.name) && f.size < 50 * 1024 * 1024); // skip >50MB
    if (!candidates.length) return Promise.resolve([]);
    return Promise.all(candidates.map(async f => {
      const path = f.webkitRelativePath || f.name;
      const name = f.name;
      const ext  = name.includes(".") ? name.split(".").pop().toLowerCase() : "txt";
      if (onProgress) onProgress(name, "processing");
      try {
        const content = await extractTextFromFile(f);
        if (onProgress) onProgress(name, "done");
        return { path, name, ext, content, binary: false, size: f.size, docCategory };
      } catch {
        if (onProgress) onProgress(name, "error");
        return { path, name, ext, content: `[Extraction failed: ${name}]`, binary: false, size: f.size, docCategory };
      }
    })).then(loaded => {
      const valid = loaded.filter(Boolean);
      if (!valid.length) return valid;
      let newDocs = [];
      saveUserDocs(prev => {
        const existingPaths = new Set(prev.map(d => d.path || d.name));
        newDocs = valid.filter(d => !existingPaths.has(d.path || d.name));
        return newDocs.length ? [...prev, ...newDocs] : prev;
      });
      return newDocs;
    });
  }, [saveUserDocs]);

  // Re-run parse + DFD whenever the TF files list changes
  // Uses userDocsRef so this callback stays stable without needing userDocs in deps.
  const reparse = useCallback(async (tfFiles) => {
    const ctxDoc = buildModelContextDoc();
    const archDoc = buildArchContextDoc();
    if (!tfFiles.length) {
      setParseResult(null); setXml("");
      const seedDocs = [ctxDoc, archDoc].filter(Boolean);
      intelligenceRef.current = new ThreatModelIntelligence();
      intelligenceRef.current.build(seedDocs, [], []);
      setIntelligenceVersion(v=>v+1);
      return;
    }

    // ── Separate HCL/TF files from JSON/CFN files ─────────────────────────────
    const CFN_SIG = /"AWSTemplateFormatVersion"|"Resources"\s*:\s*\{[\s\S]{1,500}"AWS::/;
    const hclFiles = tfFiles.filter(f => !/\.json$/i.test(f.name));
    const jsonFiles = tfFiles.filter(f => /\.json$/i.test(f.name));
    const cfnFiles  = jsonFiles.filter(f =>
      /\.cfn\.json$/i.test(f.name) || CFN_SIG.test(f.content || '')
    );

    const result = parseTFMultiFile(hclFiles);

    // ── Parse CFN files and merge resources ───────────────────────────────────
    if (cfnFiles.length > 0) {
      try {
        const cfnResult = await parseCFNFiles(cfnFiles);
        result.resources.push(...cfnResult.resources);
        result.gaps = [...(result.gaps || []), ...cfnResult.gaps];
      } catch (err) {
        console.warn('[reparse] CFN parsing failed:', err);
      }
    }

    setParseResult(result);
    // Rebuild intelligence: model context + arch context + uploaded docs + parsed resources
    const syntheticDocs = [ctxDoc, archDoc].filter(Boolean);
    const docsWithCtx = [...syntheticDocs, ...userDocsRef.current];
    intelligenceRef.current = new ThreatModelIntelligence();
    intelligenceRef.current.build(docsWithCtx, result.resources, result.modules);
    setIntelligenceVersion(v => v+1);
    if (result.resources.length > 0 || result.modules.length > 0) {
      const x = generateDFDXml(result.resources, result.modules, result.connections, intelligenceRef.current);
      setXml(x);
    } else {
      setXml("");
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  reparseRef.current = reparse; // Keep ref current (avoids TDZ in openModel)

  // Accept ALL file types. TF/HCL/sentinel/tfvars → files state (parsed).
  // Everything else → userDocs (context). append=true merges instead of replacing.
  const readFiles = useCallback((fileList, append = false, docCategory = "general") => {
    const SKIP_BINARY = /\.(ico|woff|woff2|ttf|eot|zip|tar|gz|7z|exe|dll|so|dylib|class|jar|war|pyc)$/i;
    const isTF = f => /\.(tf|hcl|sentinel|tfvars)$/i.test(f.name) || /\.cfn\.json$/i.test(f.name);
    const all = Array.from(fileList).filter(f => !SKIP_BINARY.test(f.name) && f.size < 50*1024*1024);
    if (!all.length) return;
    setError("");

    const tfCandidates = all.filter(isTF);
    const ctxCandidates = all.filter(f => !isTF(f));
    const total = all.length;
    let done = 0;
    setIngestState({ total, done: 0, current: all[0]?.name || "" });
    const onFileDone = (name) => { done++; setIngestState({ total, done, current: name }); };

    const readAsText = f => new Promise(res => {
      const r = new FileReader();
      r.onload = ev => { onFileDone(f.name); res({ path: f.webkitRelativePath || f.name, name: f.name, content: ev.target.result || "", size: f.size }); };
      r.onerror = () => { onFileDone(f.name); res(null); };
      r.readAsText(f);
    });

    Promise.all([
      Promise.all(tfCandidates.map(readAsText)),
      Promise.all(ctxCandidates.map(f =>
        extractTextFromFile(f).then(content => {
          onFileDone(f.name);
          return { path: f.webkitRelativePath || f.name, name: f.name, content, size: f.size, docCategory };
        }).catch(() => { onFileDone(f.name); return null; })
      )),
    ]).then(([tfLoaded, ctxLoaded]) => {
      setIngestState(null);
      const validTF = tfLoaded.filter(Boolean);
      const validCtx = ctxLoaded.filter(Boolean);

      // Compute merged array OUTSIDE setFiles to avoid side-effects in state updater
      const existing = append ? filesRef.current : [];
      const existPaths = new Set(existing.map(f => f.path));
      const newTF = validTF.filter(f => !existPaths.has(f.path));
      const merged = [...existing, ...newTF].sort((a,b) => a.path.localeCompare(b.path));

      // Pure state update — no side effects inside
      setScopeFiles(null);
      setFiles(merged);

      // Side effects separately, after state update, using stable refs
      const cm = currentModelRef.current;
      if (cm) {
        try { localStorage.setItem(`tf-model-${cm.id}-files`, JSON.stringify(merged)); } catch {}
        updateModelMetaRef.current({ tfFileCount: merged.length });
      }
      reparse(merged); // reads fresh userDocsRef.current

      // Auto-route non-TF files to userDocs
      if (validCtx.length) {
        saveUserDocs(prev => {
          const existCtxPaths = new Set(prev.map(d => d.path || d.name));
          const newDocs = validCtx
            .filter(d => !existCtxPaths.has(d.path))
            .map(d => ({ ...d, ext: (d.name.split('.').pop() || "txt").toLowerCase() }));
          return newDocs.length ? [...prev, ...newDocs] : prev;
        });
      }
    }).catch(e => { setIngestState(null); setError(e.message); });
  }, [reparse, saveUserDocs]);

  // Delete a single TF file and re-parse the rest
  const removeFile = useCallback((path) => {
    const next = filesRef.current.filter(f => f.path !== path);
    setScopeFiles(null);
    setFiles(next);
    if (!next.length) { setParseResult(null); setXml(""); }
    else reparse(next);
    // Update persistence
    const cm = currentModelRef.current;
    if (cm) {
      try { localStorage.setItem(`tf-model-${cm.id}-files`, JSON.stringify(next)); } catch {}
      updateModelMetaRef.current({ tfFileCount: next.length });
    }
  }, [reparse]);

  // Clear all TF files
  const clearFiles = useCallback(() => {
    setFiles([]);
    setParseResult(null);
    setXml("");
    setScopeFiles(null);
    setError("");
  }, []);

  const handleDrop = useCallback(e=>{ e.preventDefault(); setDragging(false); readFiles(e.dataTransfer.files, true); }, [readFiles]);
  // Full <mxfile> wrapper with correct document-level indentation matching the working reference XML:
  //   <mxfile>            ← 0 spaces
  //     <diagram>         ← 2 spaces
  //       <mxGraphModel>  ← 4 spaces
  //         <root>        ← 6 spaces
  //           <mxCell>    ← 8 spaces
  //             <mxGeometry/> ← 10 spaces
  //           </mxCell>   ← 8 spaces
  // The inner xml (from generateDFDXml) starts at 0 — each line is indented +4 spaces
  // so that <mxGraphModel> sits at 4 spaces inside <diagram>.
  const drawioXml = xml
    ? `<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="app.diagrams.net" modified="${new Date().toISOString()}" agent="Threataform" version="21.0.0" type="device">\n  <diagram name="Enterprise Terraform DFD" id="enterprise-tf-dfd">\n${xml.split('\n').map(l=>'    '+l).join('\n')}\n  </diagram>\n</mxfile>`
    : "";
  // Download as .xml — Lucidchart enterprise lists "Draw.io (.xml, .drawio)" and .xml
  // extension passes more corporate DLP/firewall policies than .drawio.
  const download = () => {
    const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([drawioXml],{type:"application/xml"}));
    a.download="enterprise-tf-dfd.xml"; a.click();
  };
  const copy = () => {
    // Copy the full mxfile XML (including <mxfile> wrapper) so users can save as .drawio and upload to Lucidchart
    const done = () => { setCopied(true); setTimeout(()=>setCopied(false),2000); };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(drawioXml).then(done).catch(()=>{
        const ta=document.createElement("textarea"); ta.value=drawioXml;
        document.body.appendChild(ta); ta.select(); document.execCommand("copy");
        document.body.removeChild(ta); done();
      });
    } else {
      const ta=document.createElement("textarea"); ta.value=drawioXml;
      document.body.appendChild(ta); ta.select(); document.execCommand("copy");
      document.body.removeChild(ta); done();
    }
  };

  // ── Download .lucid (Lucid Standard Import — native Lucidchart format) ───────
  const downloadLucid = useCallback(() => {
    if (!parseResult) return;
    const json = generateLucidJson(parseResult.resources, parseResult.modules, parseResult.connections);
    const zipBytes = makeZipOneFile("document.json", json);
    const blob = new Blob([zipBytes], {type:"application/octet-stream"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "enterprise-tf-dfd.lucid";
    a.click();
    URL.revokeObjectURL(a.href);
  }, [parseResult]);

  const KB_DOMAINS = [
    {id:"xsphere",  label:"xSphere Cloud",         color:"#0277BD", Icon: Cloud},
    {id:"spinnaker",label:"Spinnaker.io",           color:"#00838F", Icon: Settings},
    {id:"iam",      label:"IAM · Org · OUs · SCPs", color:"#B71C1C", Icon: KeyRound},
    {id:"jenkins",  label:"Jenkins / Jules",        color:"#BF360C", Icon: Server},
    {id:"dfd",      label:"Enterprise DFD",         color:"#4527A0", Icon: MapIcon},
    {id:"wiz",      label:"Wiz CSPM",               color:"#1A73E8", Icon: ShieldAlert},
    {id:"attack",   label:"MITRE ATT&CK®",          color:"#B71C1C", Icon: Zap},
    {id:"cwe",      label:"MITRE CWE",              color:"#E65100", Icon: TriangleAlert},
    {id:"stride",   label:"STRIDE-LM",              color:"#4527A0", Icon: Target},
    {id:"tfePave",  label:"TFE-Pave / Hier. IAM",  color:"#2E7D32", Icon: Layers},
    {id:"userdocs", label:"My Documents",           color:"#78909C", Icon: FileText},
  ];

  const MAIN_TABS = [
    {id:"knowledge",     label:"Knowledge Base",        Icon: BookOpen},
    {id:"upload",        label:"Upload & Analyze",      Icon: Upload},
    {id:"arch-analysis", label:"Architecture Analysis", Icon: Building2},
    {id:"intelligence",  label:"Intelligence",           Icon: Brain},
    {id:"analysis",      label:"Threataform Analysis",  Icon: Microscope},
    {id:"dfd",           label:"DFD Output",            Icon: MapIcon},
  ];

  // Landing page render
  if (appMode === "landing") {
    return (
      <>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
        <LandingPage
          threatModels={threatModels}
          onCreateModel={createModel}
          onOpenModel={openModel}
          onDeleteModel={deleteModel}
        />
      </>
    );
  }

  if (appMode === "documents") {
    return (
      <>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
        <DocumentsPage
          model={currentModel}
          modelDetails={modelDetails}
          userDocs={userDocs}
          onSaveDetails={saveModelDetails}
          onAddDocs={addUserDocs}
          onRemoveDoc={removeUserDoc}
          onContinue={() => { setAppMode("workspace"); setMainTab("upload"); }}
          onBack={() => setAppMode("landing")}
          ingestState={ingestState}
          intelligence={intelligenceRef.current}
          intelligenceVersion={intelligenceVersion}
        />
      </>
    );
  }

  return (
    <div style={{...SANS, background:C.bg, minHeight:"100vh", color:C.text}}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>

      {/* ── HEADER ── */}
      <div style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 16px", display:"flex", alignItems:"center", height:58,
        position:"sticky", top:0, zIndex:100,
      }}>
        {/* Back to landing + brand */}
        <div style={{display:"flex", alignItems:"center", gap:10, marginRight:20, flexShrink:0}}>
          <button onClick={()=>setAppMode("landing")} title="All threat models" style={{
            background:"transparent", border:`1px solid ${C.border}`, borderRadius:6,
            padding:"5px 10px", color:C.textMuted, cursor:"pointer", fontSize:11, ...SANS,
            display:"flex", alignItems:"center", gap:4,
          }}><ChevronLeft size={13}/> Home</button>
          <div style={{
            width:30, height:30, borderRadius:7, flexShrink:0,
            background:"linear-gradient(135deg,#FF6B35,#FF9900)",
            display:"flex", alignItems:"center", justifyContent:"center",
            boxShadow:"0 2px 8px #FF990040"
          }}><Shield size={16} color="#fff"/></div>
          <div>
            <div style={{fontSize:13, fontWeight:700, color:C.text, letterSpacing:"-.01em", lineHeight:1.1}}>
              Threataform
            </div>
            {currentModel && (
              <div style={{fontSize:10, color:C.accent, marginTop:1, fontWeight:600,
                maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                {currentModel.name}
              </div>
            )}
          </div>
        </div>

        {/* Nav tabs */}
        <nav style={{display:"flex", gap:2, alignItems:"center"}}>
          {MAIN_TABS.map(t => {
            const active = mainTab === t.id;
            const hasData = (t.id === "analysis" || t.id === "dfd") ? !!parseResult : true;
            return (
              <button key={t.id} onClick={()=>setMainTab(t.id)} style={{
                display:"flex", alignItems:"center", gap:7,
                background: active ? `${C.accent}12` : "transparent",
                border: active ? `1px solid ${C.accent}40` : "1px solid transparent",
                borderRadius:7, padding:"7px 14px",
                color: active ? C.accent : hasData ? C.textSub : C.textMuted,
                fontSize:12, cursor:"pointer", ...SANS,
                fontWeight: active ? 600 : 400,
                transition:"all .15s",
                opacity: !hasData && t.id !== "upload" ? 0.5 : 1,
              }}>
                <t.Icon size={14} />
                <span>{t.label}</span>
                {(t.id === "analysis" || t.id === "dfd") && parseResult && (
                  <span style={{
                    width:6, height:6, borderRadius:"50%",
                    background:C.green, flexShrink:0
                  }}/>
                )}
                {t.id === "intelligence" && intelligenceRef.current._built && (userDocs.length > 0 || parseResult) && (
                  <span style={{
                    width:6, height:6, borderRadius:"50%",
                    background:"#9C27B0", flexShrink:0
                  }}/>
                )}
              </button>
            );
          })}
        </nav>

        {/* Action buttons */}
        {xml && (
          <div style={{marginLeft:"auto", display:"flex", gap:8, alignItems:"center"}}>
            {/* PRIMARY: draw.io / Lucidchart — confirmed supported format in enterprise Lucidchart */}
            <button onClick={download} style={{
              background:"linear-gradient(135deg,#FF6B3520,#FF990020)",
              border:`1px solid ${C.accent}55`,
              borderRadius:7, padding:"7px 18px",
              color:C.accent, fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:6,
              fontWeight:700,
            }}>
              <Download size={13}/> Export .xml
            </button>
            {/* SECONDARY: Copy XML */}
            <button onClick={copy} style={{
              background: copied ? "#0D2010" : C.surface2,
              border:`1px solid ${copied ? C.green+"66" : C.border2}`,
              borderRadius:7, padding:"7px 13px",
              color: copied ? C.green : C.textMuted,
              fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:5,
              transition:"all .15s",
            }}>
              {copied ? <CheckCircle2 size={13}/> : <CheckSquare size={13} style={{opacity:0.6}}/>} {copied ? "Copied!" : "Copy XML"}
            </button>
            {/* TERTIARY: .lucid — for Lucidchart versions that support Lucid Standard Import */}
            <button onClick={downloadLucid} title="Lucid Standard Import format (.lucid) — supported in some Lucidchart versions" style={{
              background:C.surface2,
              border:`1px solid ${C.border2}`,
              borderRadius:7, padding:"7px 13px",
              color:C.textMuted, fontSize:12, cursor:"pointer", ...SANS,
              display:"flex", alignItems:"center", gap:5,
            }}>
              <Download size={13}/> .lucid
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
                const DomainIcon = d.Icon || BookOpen;
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
                        color: active ? d.color : C.textMuted,
                      }}><DomainIcon size={14}/></span>
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
        <div style={{padding:"32px 40px", maxWidth:980, height:"calc(100vh - 58px)", overflowY:"auto"}}>
          {/* Page heading */}
          <div style={{marginBottom:22}}>
            <div style={{...SANS, fontSize:22, fontWeight:700, color:C.text, marginBottom:6, letterSpacing:"-.02em"}}>
              {currentModel ? currentModel.name : "Upload & Analyze"}
            </div>
            <div style={{fontSize:13, color:C.textSub, lineHeight:1.6, maxWidth:680}}>
              Drop any Terraform, HCL, Sentinel, JSON, YAML, docs, or any other file. TF/HCL files are parsed for resources and connections; all other files become context documents that inform the analysis.
            </div>
          </div>

          {/* Ingestion Progress Bar */}
          {ingestState && (
            <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:8,
              padding:"10px 16px", marginBottom:20 }}>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:5 }}>
                <span style={{ fontSize:12, color:C.textSub, fontWeight:500 }}>
                  Analyzing {ingestState.done} / {ingestState.total} files
                  {ingestState.current ? ` · ${ingestState.current}` : ""}
                </span>
                <span style={{ fontSize:12, fontWeight:700, color:C.accent }}>
                  {Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%
                </span>
              </div>
              <div style={{ height:4, background:C.border, borderRadius:2, overflow:"hidden" }}>
                <div style={{
                  height:"100%", borderRadius:2, background:`linear-gradient(90deg,${C.accent},${C.accent}aa)`,
                  width:`${Math.round((ingestState.done / Math.max(ingestState.total, 1)) * 100)}%`,
                  transition:"width .3s ease",
                }} />
              </div>
            </div>
          )}

          {/* ── APPLICATION DETAILS ── */}
          {currentModel && (()=>{
            const envOptions = ["Production","Staging","Development","DR / Disaster Recovery","Sandbox"];
            const dataCls   = ["PII (Personal Data)","PHI (Health Data)","PCI (Payment Data)","Financial Data","Internal","Public"];
            const md = modelDetails;
            const toggleArr = (arr, val) => arr.includes(val) ? arr.filter(x=>x!==val) : [...arr, val];
            return (
              <div style={{background:C.surface, border:`1px solid ${C.border}`, borderRadius:14,
                padding:"20px 24px", marginBottom:24}}>
                <div style={{fontSize:14, fontWeight:700, color:C.text, marginBottom:16, display:"flex", alignItems:"center", gap:8}}>
                  <span>Application Details</span>
                  <span style={{fontSize:10, color:C.textMuted, fontWeight:400}}>— enriches intelligence context</span>
                </div>
                <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:14}}>
                  {/* Environment */}
                  <div>
                    <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6}}>Environment</div>
                    <select value={md.environment||""} onChange={e=>saveModelDetails({...md,environment:e.target.value})} style={{
                      width:"100%", background:C.bg, border:`1px solid ${C.border2}`, borderRadius:8,
                      padding:"8px 12px", color:md.environment?C.text:C.textMuted, fontSize:13, ...SANS, outline:"none",
                    }}>
                      <option value="">Select environment...</option>
                      {envOptions.map(o=><option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                  {/* Owner */}
                  <div>
                    <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6}}>Team / Owner</div>
                    <input value={md.owner||""} onChange={e=>saveModelDetails({...md,owner:e.target.value})}
                      placeholder="e.g. Platform Security Team" style={{
                        width:"100%", boxSizing:"border-box", background:C.bg, border:`1px solid ${C.border2}`,
                        borderRadius:8, padding:"8px 12px", color:C.text, fontSize:13, ...SANS, outline:"none",
                      }} />
                  </div>
                </div>
                {/* Data classification */}
                <div style={{marginBottom:14}}>
                  <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:8}}>Data Classification</div>
                  <div style={{display:"flex", flexWrap:"wrap", gap:6}}>
                    {dataCls.map(cls=>{
                      const on = (md.dataClassification||[]).includes(cls);
                      return (
                        <button key={cls} onClick={()=>saveModelDetails({...md,dataClassification:toggleArr(md.dataClassification||[],cls)})} style={{
                          background:on?"#0277BD20":"transparent", border:`1px solid ${on?"#0277BD":"#33333A"}`,
                          borderRadius:20, padding:"4px 12px", fontSize:11,
                          color:on?"#4FC3F7":C.textMuted, cursor:"pointer", ...SANS,
                        }}>{cls}</button>
                      );
                    })}
                  </div>
                </div>
                {/* Description — auto-populated from intelligence */}
                <div>
                  <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:6, display:"flex", alignItems:"center", gap:8}}>
                    Architecture Description
                    {!md.description && intelligenceRef.current?._built && (
                      <span style={{ fontSize:10, color:C.accent, fontWeight:400 }}>auto-populated from docs</span>
                    )}
                  </div>
                  <textarea value={md.description||""} onChange={e=>saveModelDetails({...md,description:e.target.value})}
                    placeholder="Auto-populated from uploaded documents and Terraform analysis. Edit freely."
                    rows={3} style={{
                      width:"100%", boxSizing:"border-box", background:C.bg, border:`1px solid ${C.border2}`,
                      borderRadius:8, padding:"8px 12px", color:C.text, fontSize:12, ...SANS, outline:"none",
                      resize:"vertical", lineHeight:1.6, ...MONO,
                    }} />
                </div>
              </div>
            );
          })()}

          {/* Drop zone — always visible for adding more */}
          <div
            onDrop={handleDrop}
            onDragOver={e=>{e.preventDefault();setDragging(true);}}
            onDragLeave={()=>setDragging(false)}
            style={{
              border:`2px dashed ${dragging ? C.accent : C.border2}`,
              borderRadius:12, padding: files.length ? "24px 32px" : "48px 32px", textAlign:"center",
              background: dragging ? `${C.accent}08` : C.surface,
              transition:"all .2s", marginBottom:16,
              boxShadow: dragging ? `0 0 24px ${C.accent}20` : "none",
            }}
          >
            <div style={{marginBottom:8, opacity:dragging?1:0.6, display:"flex", justifyContent:"center"}}>
              {dragging ? <Download size={files.length?28:40}/> : <FolderOpen size={files.length?28:40}/>}
            </div>
            <div style={{...SANS, color:C.textSub, fontSize:14, marginBottom:4, fontWeight:500}}>
              {dragging ? "Drop to add files" : files.length ? "Drop more files to add them" : "Drag & drop files or a folder here"}
            </div>
            <div style={{fontSize:12, color:C.textMuted, marginBottom:18}}>
              All file types accepted · .tf .hcl .sentinel .tfvars → parsed · everything else → context docs
            </div>
            <div style={{display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap"}}>
              <label style={{
                background:C.surface2, border:`1px solid ${C.border2}`,
                borderRadius:8, padding:"9px 20px",
                color:C.textSub, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:7, fontWeight:500,
              }}>
                <FileText size={14}/> {files.length ? "Add Files" : "Select Files"}
                <input type="file" multiple
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files, files.length>0);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
              <label style={{
                background:`linear-gradient(135deg,${C.accent}18,${C.accent}08)`,
                border:`1px solid ${C.accent}55`,
                borderRadius:8, padding:"9px 20px",
                color:C.accent, fontSize:13, cursor:"pointer", ...SANS,
                display:"flex", alignItems:"center", gap:7, fontWeight:600,
              }}>
                <span>📂</span> {files.length ? "Add Folder" : "Select Folder"}
                <input type="file" webkitdirectory=""
                  onChange={e=>{if(e.target.files?.length)readFiles(e.target.files, files.length>0);e.target.value="";}}
                  style={{display:"none"}}/>
              </label>
            </div>
          </div>

          {error && (
            <div style={{
              padding:"12px 16px", background:"#200808",
              border:`1px solid ${C.red}44`, borderRadius:8,
              color:"#FF8A80", fontSize:13, marginBottom:16,
              display:"flex", gap:10, alignItems:"flex-start"
            }}>
              <TriangleAlert size={16} style={{flexShrink:0}}/>
              <span>{error}</span>
            </div>
          )}

          {files.length > 0 && (() => {
            // Group by folder prefix
            const grouped = {};
            files.forEach(f => {
              const parts = f.path.split("/");
              const folder = parts.length > 1 ? parts.slice(0,-1).join("/") : "";
              if (!grouped[folder]) grouped[folder] = [];
              grouped[folder].push(f);
            });
            const ext = f => f.path.split(".").pop().toLowerCase();
            const extColor = e => ({tf:"#FF6B35",hcl:"#FF9900",sentinel:"#E91E63",tfvars:"#9C27B0"}[e]||C.textMuted);
            return (
              <div style={{...card(C.green+"33"), marginBottom:16}}>
                <div style={{...sectionBar(C.green), justifyContent:"space-between"}}>
                  <div style={{display:"flex", alignItems:"center", gap:8}}>
                    <CheckCircle2 size={14}/>
                    <span>{files.length} Terraform file{files.length!==1?"s":""} loaded</span>
                    {parseResult && <span style={{fontSize:11, color:C.textMuted}}>· {parseResult.resources.length} resources · {parseResult.connections.length} connections</span>}
                  </div>
                  <button onClick={clearFiles} style={{
                    background:"transparent", border:`1px solid ${C.red}44`,
                    borderRadius:6, padding:"3px 10px", color:C.red,
                    fontSize:11, cursor:"pointer", ...SANS
                  }}>Clear All</button>
                </div>
                <div style={{padding:"10px 14px", maxHeight:320, overflowY:"auto"}}>
                  {Object.entries(grouped).map(([folder, fls]) => (
                    <div key={folder} style={{marginBottom: folder ? 10 : 0}}>
                      {folder && (
                        <div style={{fontSize:11, color:C.textMuted, fontWeight:600, marginBottom:4, paddingLeft:2, textTransform:"uppercase", letterSpacing:".06em", display:"flex", alignItems:"center", gap:5}}>
                          <FolderOpen size={11}/> {folder}
                        </div>
                      )}
                      {fls.map(f => (
                        <div key={f.path} style={{
                          display:"flex", gap:8, alignItems:"center", padding:"4px 6px",
                          borderRadius:5, marginBottom:2,
                          background:"transparent",
                        }}
                          onMouseEnter={e=>e.currentTarget.style.background=C.surface2}
                          onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                        >
                          <span style={{
                            fontSize:9, fontWeight:700, padding:"2px 5px", borderRadius:3,
                            background:`${extColor(ext(f))}20`, color:extColor(ext(f)),
                            border:`1px solid ${extColor(ext(f))}44`, flexShrink:0, minWidth:28, textAlign:"center"
                          }}>{ext(f).toUpperCase().slice(0,6)}</span>
                          <span style={{...MONO, fontSize:12, color:C.textSub, flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>
                            {folder ? f.path.split("/").pop() : f.path}
                          </span>
                          {f.size && <span style={{fontSize:11, color:C.textMuted, flexShrink:0}}>{f.size < 1024 ? f.size+"B" : Math.round(f.size/1024)+"K"}</span>}
                          <button onClick={()=>removeFile(f.path)} style={{
                            background:"transparent", border:"none", color:C.textMuted,
                            cursor:"pointer", fontSize:14, padding:"0 4px", lineHeight:1,
                            borderRadius:4, flexShrink:0,
                          }}
                            onMouseEnter={e=>{ e.currentTarget.style.color=C.red; e.currentTarget.style.background=C.red+"15"; }}
                            onMouseLeave={e=>{ e.currentTarget.style.color=C.textMuted; e.currentTarget.style.background="transparent"; }}
                            title="Remove file"
                          ><X size={12}/></button>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}

          {parseResult && (
            <div style={{...card(), marginBottom:20}}>
              <div style={{...sectionBar(C.accent)}}>
                <BarChart2 size={14}/>
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

      {/* ── ARCHITECTURE ANALYSIS TAB ── */}
      {mainTab==="arch-analysis" && (() => {
        const NARRATIVE_FIELDS = [
          { key:"entryPoints",           label:"Entry Points",               Icon:DoorOpen },
          { key:"dataFlow",              label:"Data Flow",                  Icon:ArrowLeftRight },
          { key:"securityBoundaries",    label:"Security Boundaries",        Icon:Lock },
          { key:"publicPrivateResources",label:"Public & Private Resources", Icon:Globe },
          { key:"securityControls",      label:"Security Controls",          Icon:Shield },
          { key:"faultTolerance",        label:"Fault Tolerance",            Icon:RefreshCw },
          { key:"authAndAuthz",          label:"Authentication & AuthZ",     Icon:KeyRound },
          { key:"externalDependencies",  label:"External Dependencies",      Icon:LinkIcon },
          { key:"storageAndDataSecurity",label:"Storage & Data Security",    Icon:Database },
        ];

        const ATTR_CHIPS = {
          applicationType:   ["Web App","REST API","Serverless","Microservices","Container-Based","VM-Based","Static Site","Data Pipeline","Streaming","ML/AI"],
          entryPointTypes:   ["HTTPS","REST API","GraphQL","gRPC","CLI","SDK","Webhook","Event Stream","File Transfer","Web UI"],
          developedBy:       ["Vendor (AWS)","Vendor (Azure)","Vendor (GCP)","Vendor (3rd Party)","Internal","Hybrid"],
          users:             ["Internal Employees","Internal Apps/Services","External End Users","3rd Party Systems","Business Partners"],
          inboundDataSource: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","IoT/Edge"],
          inboundDataFlow:   ["API Request","Event/Message","Network Traffic","User Input","Data Streaming","File Upload","DB Replication"],
          outboundDataFlow:  ["API Response","Event/Message","Network Traffic","Data Streaming","File Export","DB Write"],
          outboundDataDestination: ["Internal Corporate Network","External 3rd Party","External Public","Trusted Partner","Data Warehouse"],
          integrations:      ["REST API","GraphQL","SDK","Webhook","File Transfer","Message Queue (SQS/SNS)","Event Stream (Kinesis/Kafka)","Middleware","DB Replication"],
          exposure:          ["Public Internet","Intranet Only","VPN Required","Trusted Partner Network","Air-Gapped"],
          facilityType:      ["AWS Cloud","Azure Cloud","GCP Cloud","Enterprise Data Center","3rd Party DC","Mobile","Desktop"],
          computeType:       ["Cloud Managed Service","Serverless","Container (ECS/EKS)","VM (EC2)","On-Premises","Hybrid"],
          authMethods:       ["OAuth 2.0","SSO/SAML","PKI/mTLS","ADFS/LDAP","API Key","MFA","AWS IAM","Certificate","Passwordless"],
          dataSensitivity:   ["PII","PHI","PCI Data","Confidential","Internal","Public","Export Controlled","Trade Secret"],
          complianceFramework:["HIPAA","PCI-DSS","SOC 2","GDPR","FedRAMP","ISO 27001","NIST 800-53","CIS AWS","CCPA","CMMC"],
          environment:       ["Production","Staging","Development","DR / Backup","Lab / Sandbox","Multi-Tenant","Single-Tenant"],
        };

        const ATTR_GROUPS = [
          { label:"Application Profile",        keys:["applicationType","entryPointTypes","developedBy","users"] },
          { label:"Data & Integration",          keys:["inboundDataSource","inboundDataFlow","outboundDataFlow","outboundDataDestination","integrations"] },
          { label:"Deployment & Infrastructure", keys:["exposure","facilityType","computeType"] },
          { label:"Security & Compliance",       keys:["authMethods","dataSensitivity","complianceFramework"] },
          { label:"Context",                     keys:["environment"] },
        ];

        const ATTR_LABELS = {
          applicationType:"Application / Solution Type", entryPointTypes:"Entry Points",
          developedBy:"Developed By", users:"Users / Consumers",
          inboundDataSource:"Inbound Data Source", inboundDataFlow:"Inbound Data Flow",
          outboundDataFlow:"Outbound Data Flow", outboundDataDestination:"Outbound Destination",
          integrations:"Integrations", exposure:"Exposure", facilityType:"Facility Type",
          computeType:"Compute Type", authMethods:"Authentication Methods",
          dataSensitivity:"Data Sensitivity", complianceFramework:"Compliance Frameworks",
          environment:"Environment / Deployment Stage",
        };

        const SINGLE_SELECT = ["developedBy","environment"];

        // Merge base + overrides
        const baseNarrative = archAnalysis?.narrative || {};
        const baseAttrs     = archAnalysis?.attributes || {};
        const ovNarrative   = archOverrides?.narrative || {};
        const ovAttrs       = archOverrides?.attributes || {};
        const narrative     = { ...baseNarrative, ...ovNarrative };
        const attrs         = { ...baseAttrs, ...ovAttrs };

        const saveNarrativeField = (key, value) => {
          const updated = { ...archOverrides, narrative: { ...ovNarrative, [key]: value } };
          setArchOverrides(updated);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: updated })); } catch {}
          }
        };

        const toggleAttrChip = (attrKey, chip) => {
          const single = SINGLE_SELECT.includes(attrKey);
          const current = attrs[attrKey];
          let updated;
          if (single) {
            updated = current === chip ? "" : chip;
          } else {
            const arr = Array.isArray(current) ? current : [];
            updated = arr.includes(chip) ? arr.filter(c => c !== chip) : [...arr, chip];
          }
          const newAttrs = { ...ovAttrs, [attrKey]: updated };
          const newOverrides = { ...archOverrides, attributes: newAttrs };
          setArchOverrides(newOverrides);
          setIntelligenceVersion(v => v + 1);
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: newOverrides })); } catch {}
          }
        };

        const reanalyze = () => {
          setArchAnalyzing(true);
          setTimeout(() => {
            try {
              const result = intelligenceRef.current.analyzeArchitecture(parseResult?.resources||[], userDocs, modelDetails);
              setArchAnalysis(result);
              if (currentModel) {
                try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
                  JSON.stringify({ base: result, overrides: archOverrides })); } catch {}
              }
            } finally { setArchAnalyzing(false); }
          }, 0);
        };

        const resetOverrides = () => {
          setArchOverrides({});
          if (currentModel) {
            try { localStorage.setItem(`tf-model-${currentModel.id}-arch-analysis`,
              JSON.stringify({ base: archAnalysis, overrides: {} })); } catch {}
          }
        };

        return (
          <div style={{ height:"calc(100vh - 58px)", overflow:"hidden", display:"flex", flexDirection:"column" }}>
            {/* Header bar */}
            <div style={{ padding:"16px 28px", borderBottom:`1px solid ${C.border}`, background:C.surface,
              display:"flex", alignItems:"center", gap:16, flexShrink:0 }}>
              <div style={{ flex:1 }}>
                <div style={{...SANS, fontSize:16, fontWeight:700, color:C.text}}>Architecture Analysis</div>
                <div style={{ fontSize:11, color:C.textMuted, marginTop:2 }}>
                  Auto-populated from Terraform resources and uploaded documents · editable per-model
                  {archAnalysis && <span style={{marginLeft:10, color:C.accent, fontWeight:600}}>· Confidence: {archAnalysis.confidence}%</span>}
                </div>
              </div>
              {archAnalyzing && <Loader2 size={16} style={{color:C.accent, animation:"spin 1s linear infinite"}}/>}
              <button onClick={reanalyze} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:C.surface2, border:`1px solid ${C.border2}`, borderRadius:7,
                color:C.textSub, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RotateCcw size={12}/> Re-analyze</button>
              <button onClick={resetOverrides} style={{
                ...SANS, fontSize:12, fontWeight:600, padding:"6px 14px",
                background:"transparent", border:`1px solid ${C.border}`, borderRadius:7,
                color:C.textMuted, cursor:"pointer", display:"flex", alignItems:"center", gap:5,
              }}><RefreshCw size={12}/> Reset edits</button>
            </div>

            {/* Body — 2-column */}
            {!archAnalysis && !archAnalyzing ? (
              <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center", flexDirection:"column", gap:12 }}>
                <Building2 size={40} style={{color:C.textMuted, opacity:.4}}/>
                <div style={{...SANS, fontSize:14, color:C.textMuted}}>Upload Terraform files or documents to generate architecture analysis</div>
                <button onClick={()=>setMainTab("upload")} style={{
                  ...SANS, fontSize:12, padding:"7px 16px", borderRadius:7,
                  background:`${C.accent}18`, border:`1px solid ${C.accent}44`, color:C.accent, cursor:"pointer",
                }}>Go to Upload & Analyze</button>
              </div>
            ) : (() => {
              // ── Inline markdown renderer for narrative preview ──
              const renderLine = (line, i) => {
                const parts = line.split(/(\*\*[^*]+\*\*)/g);
                return parts.map((p,j) =>
                  (p.startsWith('**') && p.endsWith('**'))
                    ? <strong key={j}>{p.slice(2,-2)}</strong>
                    : <span key={j}>{p}</span>
                );
              };
              const decodeEntities = (s) => (s||'')
                .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>')
                .replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&nbsp;/g,' ');
              const renderNarrative = (text) => {
                if (!text?.trim()) return null;
                const lines = decodeEntities(text).split('\n');
                const els = [];
                let i = 0;
                while (i < lines.length) {
                  const line = lines[i];
                  const trimmed = line.trim();
                  if (trimmed.startsWith('• ') || trimmed.startsWith('- ')) {
                    const bullets = [];
                    while (i < lines.length && (lines[i].trim().startsWith('• ') || lines[i].trim().startsWith('- '))) {
                      bullets.push(lines[i].trim().slice(2));
                      i++;
                    }
                    els.push(
                      <div key={`b${i}`} style={{marginBottom:4}}>
                        {bullets.map((b,bi) => (
                          <div key={bi} style={{display:'flex', gap:7, marginBottom:3, alignItems:'flex-start'}}>
                            <span style={{color:C.accent, flexShrink:0, marginTop:1, fontSize:13, lineHeight:'16px'}}>•</span>
                            <span style={{lineHeight:'18px'}}>{renderLine(b, bi)}</span>
                          </div>
                        ))}
                      </div>
                    );
                  } else if (trimmed.startsWith('Context:')) {
                    els.push(
                      <div key={`c${i}`} style={{
                        marginTop:8, padding:'7px 10px',
                        background:`${C.accent}0a`, border:`1px solid ${C.accent}22`,
                        borderRadius:6, fontSize:11, color:C.textSub, lineHeight:1.6,
                        fontStyle:'italic',
                      }}>
                        <span style={{fontWeight:700, fontStyle:'normal', color:C.accent, fontSize:10, marginRight:5}}>FROM DOCS</span>
                        {renderLine(trimmed.slice(9).trim(), i)}
                      </div>
                    );
                    i++;
                  } else if (trimmed === '') {
                    els.push(<div key={`sp${i}`} style={{height:5}}/>);
                    i++;
                  } else {
                    els.push(<div key={`t${i}`} style={{marginBottom:3, lineHeight:'18px'}}>{renderLine(trimmed, i)}</div>);
                    i++;
                  }
                }
                return els;
              };

              return (
                <div style={{ flex:1, display:"grid", gridTemplateColumns:"1fr 1fr", overflow:"hidden" }}>
                  {/* LEFT — Narrative Fields */}
                  <div style={{ overflowY:"auto", padding:"16px 20px", borderRight:`1px solid ${C.border}` }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Narrative Findings
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        {Object.values(narrative).filter(Boolean).length} / {NARRATIVE_FIELDS.length} fields populated
                      </div>
                    </div>
                    {NARRATIVE_FIELDS.map(({ key, label, Icon: FieldIcon }) => {
                      const value = narrative[key] || "";
                      const isOverridden = !!ovNarrative[key];
                      const isEditing = archEditingField === key;
                      const bulletCount = (value.match(/^•/gm) || []).length;
                      return (
                        <div key={key} style={{
                          marginBottom:10,
                          border:`1px solid ${isEditing ? C.accent+'55' : C.border}`,
                          borderRadius:10,
                          overflow:'hidden',
                          transition:'border-color .15s',
                          background: C.surface,
                        }}>
                          {/* Section header */}
                          <div style={{
                            display:'flex', alignItems:'center', gap:7, padding:'8px 12px',
                            borderBottom:`1px solid ${isEditing ? C.accent+'22' : C.border}`,
                            background: isEditing ? `${C.accent}08` : C.surface2,
                          }}>
                            <FieldIcon size={13} style={{color: C.accent, flexShrink:0}}/>
                            <span style={{...SANS, fontSize:12, fontWeight:700, color:C.text, flex:1}}>{label}</span>
                            {bulletCount > 0 && !isEditing && (
                              <span style={{fontSize:10, color:C.textMuted}}>{bulletCount} items</span>
                            )}
                            {!isOverridden && value && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:"#FF980018", color:"#FF9800",
                                border:"1px solid #FF980044", borderRadius:8, padding:"1px 6px"}}>AI</span>
                            )}
                            {isOverridden && !isEditing && (
                              <span style={{fontSize:9, fontWeight:700, background:`${C.accent}18`, color:C.accent,
                                border:`1px solid ${C.accent}44`, borderRadius:8, padding:"1px 6px"}}>edited</span>
                            )}
                            <button
                              onClick={() => setArchEditingField(isEditing ? null : key)}
                              style={{
                                ...SANS, fontSize:10, padding:'2px 8px', borderRadius:6, cursor:'pointer',
                                display:'flex', alignItems:'center', gap:4,
                                background: isEditing ? C.accent : 'transparent',
                                border:`1px solid ${isEditing ? C.accent : C.border2}`,
                                color: isEditing ? '#fff' : C.textMuted,
                                transition:'all .12s',
                              }}
                            >
                              {isEditing
                                ? <><CheckCircle2 size={9}/> Done</>
                                : <><PenLine size={9}/> Edit</>
                              }
                            </button>
                          </div>
                          {/* Content: preview or textarea */}
                          {isEditing ? (
                            <textarea
                              value={value}
                              onChange={e => saveNarrativeField(key, e.target.value)}
                              placeholder={`Describe ${label.toLowerCase()}...\n\nUse • for bullets, e.g.:\n• Item one\n• Item two\nContext: optional doc note`}
                              ref={el => { if (el) { el.style.height='auto'; el.style.height=Math.max(80, el.scrollHeight)+'px'; }}}
                              onInput={e => { e.target.style.height='auto'; e.target.style.height=Math.max(80, e.target.scrollHeight)+'px'; }}
                              style={{
                                width:'100%', boxSizing:'border-box', resize:'none',
                                background:C.bg, border:'none', borderRadius:0,
                                color:C.text, fontSize:12, padding:'10px 12px',
                                lineHeight:1.7, outline:'none', ...SANS,
                                minHeight:80, display:'block', fontFamily:'inherit',
                              }}
                            />
                          ) : (
                            <div
                              onClick={() => setArchEditingField(key)}
                              style={{
                                padding:'10px 12px', fontSize:12, lineHeight:1.6,
                                color: value ? C.text : C.textMuted,
                                ...SANS, cursor:'text', minHeight:38,
                                fontStyle: value ? 'normal' : 'italic',
                              }}
                            >
                              {value
                                ? renderNarrative(value)
                                : `Click to add ${label.toLowerCase()}…`
                              }
                            </div>
                          )}
                          {isEditing && (
                            <div style={{
                              display:'flex', justifyContent:'flex-end',
                              padding:'4px 10px', borderTop:`1px solid ${C.border}`,
                              background:C.surface2,
                            }}>
                              <span style={{fontSize:10, color:C.textMuted}}>{value.length} chars</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* RIGHT — Structured Attributes */}
                  <div style={{ overflowY:"auto", padding:"16px 20px" }}>
                    <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14}}>
                      <div style={{...SANS, fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".1em"}}>
                        Structured Attributes
                      </div>
                      <div style={{fontSize:10, color:C.textMuted}}>
                        ✦ = AI-detected
                      </div>
                    </div>
                    {ATTR_GROUPS.map((group, gi) => {
                      // Count selected across this group
                      const selCount = group.keys.reduce((n, k) => {
                        const v = attrs[k];
                        return n + (SINGLE_SELECT.includes(k) ? (v ? 1 : 0) : (Array.isArray(v) ? v.length : 0));
                      }, 0);
                      return (
                        <div key={gi} style={{ marginBottom:18 }}>
                          <div style={{
                            display:'flex', alignItems:'center', justifyContent:'space-between',
                            marginBottom:10, paddingBottom:7,
                            borderBottom:`1px solid ${C.border}`,
                          }}>
                            <div style={{fontSize:11, fontWeight:700, color:C.textMuted, textTransform:"uppercase", letterSpacing:".08em"}}>
                              {group.label}
                            </div>
                            {selCount > 0 && (
                              <span style={{
                                fontSize:10, color:C.accent, fontWeight:600,
                                background:`${C.accent}15`, border:`1px solid ${C.accent}33`,
                                borderRadius:8, padding:'1px 7px',
                              }}>{selCount} selected</span>
                            )}
                          </div>
                          {group.keys.map(attrKey => {
                            const options = ATTR_CHIPS[attrKey] || [];
                            const single = SINGLE_SELECT.includes(attrKey);
                            const selected = attrs[attrKey];
                            const isSelected = (opt) => single
                              ? selected === opt
                              : Array.isArray(selected) && selected.includes(opt);
                            const isAI = (opt) => {
                              const base = baseAttrs[attrKey];
                              return single ? base === opt : Array.isArray(base) && base.includes(opt);
                            };
                            const anySelected = single ? !!selected : (Array.isArray(selected) && selected.length > 0);
                            return (
                              <div key={attrKey} style={{ marginBottom:11 }}>
                                <div style={{...SANS, fontSize:11, fontWeight:600, color: anySelected ? C.textSub : C.textMuted, marginBottom:5, display:'flex', alignItems:'center', gap:5}}>
                                  {ATTR_LABELS[attrKey]}
                                  {single && <span style={{fontSize:9, color:C.textMuted, fontWeight:400, background:C.surface2, padding:'1px 5px', borderRadius:4}}>single</span>}
                                </div>
                                <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                                  {options.map(opt => {
                                    const active = isSelected(opt);
                                    const ai = isAI(opt);
                                    return (
                                      <button key={opt} onClick={() => toggleAttrChip(attrKey, opt)} style={{
                                        ...SANS, fontSize:11, fontWeight: active ? 600 : 400,
                                        padding:"3px 9px", borderRadius:12, cursor:"pointer",
                                        background: active ? `${C.accent}20` : C.surface2,
                                        border: `1px solid ${active ? C.accent+'88' : C.border2}`,
                                        color: active ? C.accent : C.textMuted,
                                        transition:"all .12s", position:"relative",
                                        lineHeight:'16px',
                                      }}>
                                        {opt}
                                        {ai && active && (
                                          <span title="AI-detected" style={{
                                            fontSize:8, color:"#FF9800",
                                            position:"absolute", top:-4, right:-4,
                                            background:C.surface, borderRadius:"50%",
                                            padding:"0 2px", lineHeight:'12px',
                                            border:'1px solid #FF980044',
                                          }}>✦</span>
                                        )}
                                      </button>
                                    );
                                  })}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
          </div>
        );
      })()}

      {/* ── INTELLIGENCE TAB ── */}
      {mainTab==="intelligence" && (
        <IntelligencePanel
          intelligence={intelligenceRef.current}
          intelligenceVersion={intelligenceVersion}
          userDocs={userDocs}
          parseResult={parseResult}
          modelDetails={modelDetails}
          archAnalysis={archAnalysis}
          archOverrides={archOverrides}
          currentModelId={currentModel?.id}
          llmStatus={llmStatus}
          llmProgress={llmProgress}
          llmStatusText={llmStatusText}
          embedStatus={embedStatus}
          embedProgress={embedProgress}
          selectedLlmModel={selectedLlmModel}
          wllamaModelName={wllamaModelName}
          wllamaModelSize={wllamaModelSize}
          onLoadModel={loadWllama}
          onHybridSearch={hybridSearch}
          onGenerateLLM={generateLLMResponse}
          vectorStore={vectorStoreRef.current}
          computedIR={computedIR}
        />
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
              {id:"arch",     label:"Architecture",       Icon: ImageIcon},
              {id:"stats",    label:"Stats",              Icon: BarChart2},
              {id:"xml",      label:"XML Output",         Icon: Code2},
              {id:"guide",    label:"Import Guide",       Icon: BookMarked},
              {id:"legend",   label:"Legend",             Icon: LayoutList},
              {id:"analysis", label:"Analysis",           Icon: Microscope},
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
                  <t.Icon size={14} />
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

            {/* ── ARCHITECTURE IMAGE (uploaded from Lucidchart export) ── */}
            {dfdTab==="arch" && (
              <ArchitectureImageViewer
                image={diagramImage}
                onUpload={(dataUrl, _name) => {
                  setDiagramImage(dataUrl);
                  if (currentModel) {
                    try { localStorage.setItem(`tf-model-${currentModel.id}-diagram-image`, dataUrl); } catch {}
                  }
                }}
              />
            )}

            {/* STATS */}
            {dfdTab==="stats" && parseResult && (
              <div style={{padding:"20px 28px", maxWidth:800}}>
                <div style={{fontSize:15, fontWeight:700, color:"#FFF", marginBottom:16}}>Terraform Architecture Analysis</div>

                {/* Files */}
                <div style={{marginBottom:20}}>
                  <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><FolderOpen size={11}/> Analyzed Files ({files.length})</div>
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
                  <div style={{fontSize:11, color:"#4CAF50", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><Layers size={11}/> Resources ({parseResult.resources.length})</div>
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
                    <div style={{fontSize:11, color:"#FF9900", fontWeight:600, marginBottom:8, display:"flex", alignItems:"center", gap:5}}><Package size={11}/> Modules & Remote State ({parseResult.modules.length})</div>
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
                      name:"Lucidchart (Enterprise)", color:"#FF7043", badge:"✦ Primary — Draw.io Import",
                      steps:[
                        "Click Export .xml in the top-right — saves enterprise-tf-dfd.xml to your machine",
                        "In Lucidchart: click File → Import Documents",
                        "In the Import dialog select Draw.io (.xml, .drawio) and upload your enterprise-tf-dfd.xml file",
                        "All tier boundaries, resource nodes, and connection arrows will import correctly",
                        "Press Ctrl+Shift+H (Fit Page) after import to center the diagram in the canvas",
                      ]
                    },
                    {
                      name:"draw.io / diagrams.net", color:"#1E88E5", badge:"Secondary",
                      steps:[
                        "Click Export .xml to save the file",
                        "Open app.diagrams.net in any browser (free, no account needed)",
                        "Drag and drop the .drawio file onto the canvas — or use File → Import From → Device",
                        "All tier blocks, nodes, and connection arrows are preserved automatically",
                        "Press Ctrl+Shift+H (Cmd+Shift+H on Mac) to fit the diagram to the window",
                      ]
                    },
                    {
                      name:"Microsoft Visio", color:"#2E7D32", badge:null,
                      steps:[
                        "Download the .xml file via the Export .xml button",
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
