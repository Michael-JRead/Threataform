// src/data/kb-domains.js
// Built-in knowledge base: 8 security/infrastructure domains used in the KBPanel.
// Each domain has: title, icon (string key for KB_DOMAIN_ICONS), sections[],
// where each section has a title and content array of { heading, text } entries.
// Imported by KBPanel and ThreatModelIntelligence.

export const KB = {
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
