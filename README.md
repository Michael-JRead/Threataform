# Threataform

**Enterprise Terraform Threat Intelligence Platform**

A browser-based security analysis tool that parses Terraform infrastructure-as-code, generates STRIDE-LM threat models, identifies security findings, and exports interactive Data Flow Diagrams — all client-side with no data leaving your browser.

---

## Features

### Upload & Analyze
- Drag-and-drop or folder-select `.tf`, `.hcl`, `.sentinel`, and `.tfvars` files
- Parses multi-file Terraform codebases simultaneously with cross-file reference detection
- Detects resources, modules, outputs, variables, remote state data sources, and Sentinel policies
- Scope selector — restrict threat model to specific files/folders within a large codebase

### Security Findings Engine
- 30+ automated security checks modeled after Checkov and tfsec rules
- **Pave-layer-aware IAM analysis** — understands hierarchical TFE-pave patterns; distinguishes safe wildcard policies (bounded by SCPs + permission boundaries) from genuinely dangerous ones
- Findings classified as CRITICAL / HIGH / MEDIUM / LOW with CWE mappings and MITRE ATT&CK technique references
- Checks cover: RDS, S3, Lambda, KMS, Security Groups, EC2, EKS, CloudTrail, ElastiCache, Load Balancers, IAM Roles/Policies, OIDC Providers
- Architecture-level gap detection (missing CloudTrail, GuardDuty, WAF, encryption resources)

### Threat Modeling (STRIDE-LM)
- Per-resource and per-tier STRIDE-LM analysis (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation, Lateral Movement)
- Trust boundary identification across network, compute, storage, IAM, and org layers
- MITRE ATT&CK v18.1 technique mapping for every finding
- Executive summary with severity breakdown and risk score

### DFD Output (draw.io XML)
- Exports tier-swimlane Data Flow Diagrams importable into draw.io, Lucidchart, or Microsoft Visio
- Vertical tier layout with smart orthogonal edge routing (no overlapping arrows)
- Color-coded tiers: xSphere, Org, Security, CI/CD, Spinnaker, Network, Compute, Storage
- Connection types: implicit references (grey), explicit `depends_on` (red dashed), module inputs (green)

### Knowledge Base
Searchable reference covering:
- **xSphere / AWS Hybrid** — xSphere Terraform provider, Direct Connect, cross-provider patterns, FedRAMP/HIPAA compliance
- **Spinnaker.io** — Full microservice architecture, Terraspin integration, Jenkins→Spinnaker→AWS pipeline
- **AWS IAM / Organizations** — 7-layer policy evaluation, SCPs, RCPs, AFT, IAM Identity Center, RVM pattern
- **Jenkins / GitLab CI** — Terraform pipeline patterns, OIDC auth, Vault dynamic secrets, ephemeral agents
- **Enterprise DFD** — Multi-repo topologies, cross-state coupling, Terragrunt dependency patterns
- **TFE-Pave Pattern** — Hierarchical IAM layers (L0→L4), permission boundaries, wildcard safety analysis, OIDC workspace scoping, state file security

---

## Quick Start

### Prerequisites
- Node.js 18+ and npm

### Run Locally

```bash
git clone https://github.com/YOUR_ORG/threataform.git
cd threataform
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### Build for Production

```bash
npm run build
# Output in dist/ — serve with any static file server
```

### Deploy (Static Hosting)

Threataform is a fully static SPA. Deploy the `dist/` folder to:

```bash
# Netlify
netlify deploy --prod --dir=dist

# Vercel
vercel --prod

# AWS S3 + CloudFront
aws s3 sync dist/ s3://your-bucket --delete
aws cloudfront create-invalidation --distribution-id XXXX --paths "/*"

# GitHub Pages (via Actions)
# See .github/workflows/ for example workflow
```

---

## Usage

### 1. Upload Terraform Files

- Click **Upload & Analyze** tab
- Drag-and-drop a folder or click to select individual `.tf` files
- Supports entire directory trees — use your OS folder picker to upload a full Terraform repository

### 2. Set Scope (Optional)

Use the **Threat Model Scope** selector to restrict analysis to specific folders or files within your upload:
- **All** — analyze everything (default)
- **None** — start with nothing selected, then cherry-pick folders/files
- Individual folder and file toggles

### 3. Review Security Analysis

The **Analysis** panel shows:
- Executive summary with risk score
- Severity breakdown (CRITICAL / HIGH / MEDIUM / LOW)
- Per-finding detail with remediation guidance and ATT&CK technique
- STRIDE-LM threat mapping per tier
- Trust boundary identification
- MITRE ATT&CK coverage map

### 4. Export DFD

- Click **DFD Output** tab
- **Copy XML** to clipboard
- Import into [draw.io](https://app.diagrams.net): File → Import From → Device

---

## Supported File Types

| Extension | Description |
|-----------|-------------|
| `.tf` | Terraform HCL resource definitions |
| `.hcl` | HCL configuration files (Terraform / Packer / Nomad) |
| `.sentinel` | HashiCorp Sentinel policy files |
| `.tfvars` | Terraform variable definition files |

Supplemental context documents (`.txt`, `.md`, `.json`, `.pdf`) can be added via the **Add Context Docs** panel to provide additional architectural notes to the analysis engine.

---

## Security & Privacy

- **100% client-side** — no Terraform code is ever uploaded to a server or third party
- All parsing, analysis, and XML generation runs in your browser's JavaScript engine
- No telemetry, no analytics, no external API calls
- Safe to use with sensitive internal infrastructure code

---

## Architecture

```
threataform/
├── terraform-enterprise-intelligence.jsx  # Main application (single file, ~4000 lines)
├── dfd-generator.jsx                      # draw.io XML generator module (standalone export)
├── src/
│   └── main.jsx                           # Vite entry point
├── index.html                             # HTML shell
├── package.json                           # React 18 + Vite 6
└── vite.config.js                         # Vite configuration
```

**Stack:**
- React 18 (functional components, hooks)
- Vite 6 (build tool / dev server)
- Zero external UI dependencies — all styling is inline CSS (no Tailwind, no MUI)
- Fonts: Inter (UI) + JetBrains Mono (code) via Google Fonts CDN

**Key internals:**
- `KB` object — structured knowledge base for 6 enterprise domains
- `RESOURCE_TIERS` — 100+ AWS + xSphere resource type → tier/color/icon mappings
- `parseTFMultiFile()` — multi-file HCL parser with cross-file reference graph construction
- `runSecurityChecks()` — per-resource rule engine (30+ checks, pave-layer-aware IAM)
- `generateAnalysis()` — STRIDE-LM threat model generator with scope filtering
- `generateDFDXml()` / `buildDFDXml()` — draw.io XML generator with vertical tier layout
- `ScopeSelector` — file/folder scope management (null=all, Set([])=none, Set([paths])=subset)
- `AnalysisPanel` — collapsible sections, severity pills, ATT&CK technique mapping

---

## TFE-Pave Pattern Support

Threataform understands enterprise **pave-layer hierarchies**:

| Layer | Name | Description |
|-------|------|-------------|
| L0 | Org/Management | SCPs, OU structure, Control Tower |
| L1 | Account Vending | AFT, account bootstrapping |
| L2 | Account Pave | CloudTrail, GuardDuty, Config, permission boundaries |
| L3 | Product Pave | Platform VPC, TGW, shared SGs, ProductTeamDeployer role |
| L4 | Service | Application workloads, service roles |

**Wildcard IAM analysis is context-aware:**
- `iam:*` at any layer → CRITICAL (permission hierarchy escape)
- `sts:AssumeRole` on `*` → CRITICAL (cross-account pivot)
- `kinesis:*` on `arn:aws:kinesis:...:stream/team-prefix-*` with permission boundary → LOW (standard pave pattern)
- `s3:*` on `*` → HIGH (state file exfiltration risk)
- OIDC sub-claim `*` → CRITICAL (any repo can assume the role)

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-enhancement`
3. Make changes to `terraform-enterprise-intelligence.jsx`
4. Test with `npm run dev`
5. Open a pull request

### Adding Security Rules

Security checks live in `runSecurityChecks()` inside `terraform-enterprise-intelligence.jsx`. Each rule uses the `push(severity, code, resourceId, message, detail, attackTechnique, cwe)` helper.

### Adding Knowledge Base Entries

The `KB` object at the top of the file contains all knowledge base content. Add a new key with `title`, `color`, `sections[]` following the existing pattern.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- MITRE ATT&CK® Enterprise v18.1 — threat technique taxonomy
- HashiCorp Terraform / HCP Terraform documentation
- AWS Security Reference Architecture (SRA)
- CIS AWS Foundations Benchmark
- STRIDE threat modeling methodology (Microsoft)
