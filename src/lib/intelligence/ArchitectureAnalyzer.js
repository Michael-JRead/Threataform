// src/lib/intelligence/ArchitectureAnalyzer.js
// Enterprise Terraform Architecture Analyzer — browser-compatible port.
// Analyzes file arrays for 7-layer enterprise architecture patterns, factory components,
// IAM modules, Sentinel policies, product module auto-detection, and cross-layer recommendations.
// Designed to run in parallel with ThreatModelIntelligence for complementary analysis.
//
// All inputs are in-memory file objects: { path: string, name: string, content: string, size?: number }
// No Node.js APIs (fs, path, readline) are used anywhere in this module.

import {
  TERRAFORM_LAYERS,
  FACTORY_COMPONENTS,
  IAM_MODULES,
  SENTINEL_POLICIES,
  SENTINEL_IMPORT_PATTERNS,
  SENTINEL_POLICY_TYPES,
  PRODUCT_INDICATORS,
  NAMING_CONVENTIONS,
  ABBREVIATION_MAP,
  FILE_PATTERNS,
  SOX_CHECKS,
  PCI_CHECKS,
  GDPR_CHECKS,
  HIPAA_CHECKS,
  ALL_COMPLIANCE_CHECKS,
} from '../../data/architecture-layers.js';

import { RT } from '../../data/resource-types.js';
import { TIERS } from '../../constants/tiers.js';
import { ATTACK_TECHNIQUES, TF_ATTACK_MAP } from '../../data/attack-data.js';

// ── Internal utilities ────────────────────────────────────────────────────────────────────────────

/**
 * Normalise a string for comparison: lowercase, collapse hyphens/underscores/whitespace.
 */
function normalise(str) {
  return String(str || '').toLowerCase().replace(/[-_\s]+/g, '');
}

/**
 * Return true if haystack contains any of the given keyword strings (case-insensitive).
 */
function containsAny(haystack, keywords) {
  const lower = String(haystack || '').toLowerCase();
  return keywords.some(kw => lower.includes(kw.toLowerCase()));
}

/**
 * Extract the directory component from a file path without using Node's path module.
 * Works with both forward and backward slashes.
 */
function dirOf(filePath) {
  const s   = String(filePath || '');
  const fwd = s.lastIndexOf('/');
  const bwd = s.lastIndexOf('\\');
  const sep = Math.max(fwd, bwd);
  return sep === -1 ? '.' : s.slice(0, sep);
}

/**
 * Extract the file extension (including dot, lowercased) from a file name or path.
 */
function extOf(nameOrPath) {
  const s   = String(nameOrPath || '');
  const dot = s.lastIndexOf('.');
  return dot === -1 ? '' : s.slice(dot).toLowerCase();
}

/**
 * Clamp a numeric value to the range [0, 100] and round to integer.
 */
function clamp100(n) {
  return Math.min(100, Math.max(0, Math.round(n)));
}

/**
 * Compute a weighted average from an array of { value, weight } pairs.
 */
function weightedAverage(pairs) {
  const totalWeight = pairs.reduce((sum, p) => sum + p.weight, 0);
  if (totalWeight === 0) return 0;
  return pairs.reduce((sum, p) => sum + p.value * p.weight, 0) / totalWeight;
}

// ── ArchitectureAnalyzer class ────────────────────────────────────────────────────────────────────

export class ArchitectureAnalyzer {
  constructor() {
    // User-confirmed product module selections (set via setProductModules)
    this._productModules = [];
    // Cached result of the last full analyzeArchitecture() call
    this._lastAnalysis = null;
    // Cached file classification from the last call
    this._classifiedFiles = null;
  }

  // ── Main entry point ─────────────────────────────────────────────────────────────────────────

  /**
   * Analyse a set of in-memory file objects and return the full 7-layer architecture report.
   *
   * @param {Array<{path:string, name:string, content:string, size?:number}>} files
   * @returns {object} Full analysis result
   */
  analyzeArchitecture(files = []) {
    const start = Date.now();

    // 1. Classify every file into an architectural category
    const classifiedFiles = this.classifyFiles(files);
    this._classifiedFiles = classifiedFiles;

    const allFiles = files;

    // 2. Assess each of the 7 layers
    const layers = this.identifyLayers(classifiedFiles, allFiles);

    // 3. Factory component inventory (Layer 2 operators)
    const factories = this.analyzeFactories(classifiedFiles, allFiles);

    // 4. IAM module detection (Layer 3)
    const iamModules = this.analyzeIAMModules(classifiedFiles, allFiles);

    // 5. Sentinel / policy-as-code coverage (Layer 5)
    const sentinelPolicies = this.analyzeSentinelPolicies(classifiedFiles, allFiles);

    // 6. Product module auto-detection (Layer 6) + merge user selections
    const detectedProductModules = this.findPotentialProductModules(allFiles);
    const productModules = {
      detected:   detectedProductModules,
      userSelected: this._productModules,
      allModules: [
        ...detectedProductModules,
        ...this._productModules.filter(um => !detectedProductModules.some(d => d.name === um.name)),
      ],
    };

    // 7. Security control scores
    const security = this.analyzeSecurityControls(allFiles);

    // 8. SOX / PCI / GDPR / HIPAA compliance
    const compliance = this.validateCompliance(allFiles);

    // 9. Dependency graph across layers and factories
    const dependencies = this.buildDependencyGraph(layers);

    // 10. File counts by type
    const filesByType = {
      terraform:  allFiles.filter(f => FILE_PATTERNS.terraform.extensions.includes(extOf(f.name || f.path))).length,
      kubernetes: allFiles.filter(f => ['.yaml', '.yml'].includes(extOf(f.name || f.path))).length,
      sentinel:   allFiles.filter(f => extOf(f.name || f.path) === '.sentinel').length,
      python:     allFiles.filter(f => extOf(f.name || f.path) === '.py').length,
      other:      allFiles.filter(f =>
        !['.tf', '.tfvars', '.yaml', '.yml', '.sentinel', '.py'].includes(extOf(f.name || f.path))
      ).length,
    };

    // Assemble the result object
    const result = {
      summary: {
        totalFiles:        allFiles.length,
        analysisTimestamp: new Date().toISOString(),
        platformVersion:   'Enterprise Cloud Platform 2.0',
        filesByType,
        durationMs:        Date.now() - start,
      },
      classification:  classifiedFiles,
      layers,
      factories,
      iamModules,
      sentinelPolicies,
      productModules,
      security,
      compliance,
      dependencies,
      recommendations: [],   // populated below
      architectureGrade: 'F',
    };

    // 11. Prioritised recommendations
    result.recommendations = this.generateRecommendations(result);

    // 12. Architecture grade derived from average layer completeness
    const layerScores    = Object.values(layers).map(l => l.completeness || 0);
    const avgCompleteness = layerScores.length > 0
      ? layerScores.reduce((a, b) => a + b, 0) / layerScores.length
      : 0;
    result.architectureGrade = this.getArchitectureGrade(avgCompleteness);

    // 13. Cache and return
    this._lastAnalysis = result;
    return result;
  }

  // ── File classification ───────────────────────────────────────────────────────────────────────

  /**
   * Classify a single file object using multi-signal confidence scoring.
   *
   * @param {{path:string, name:string, content:string}} file
   * @returns {{ category:string, layer:number|null, type:string, confidence:number }}
   */
  classifyFile(file) {
    const name    = String(file.name || '').toLowerCase();
    const pathStr = String(file.path || '').toLowerCase();
    const content = String(file.content || '');
    const ext     = extOf(name || pathStr);

    let best = { category: 'unknown', layer: null, type: 'unknown', confidence: 0 };

    /**
     * Score a candidate classification.
     * Writes to `best` if this candidate has higher confidence.
     */
    const evaluate = (category, layer, type, signals) => {
      let score = 0;
      let hits  = 0;

      if (signals.namePatterns && signals.namePatterns.some(p => name.includes(p.toLowerCase()))) {
        score += 0.3; hits++;
      }
      if (signals.pathPatterns && signals.pathPatterns.some(p => pathStr.includes(p.toLowerCase()))) {
        score += 0.2; hits++;
      }
      if (signals.contentPatterns && signals.contentPatterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        score += 0.4; hits++;
      }
      if (signals.extensions && signals.extensions.includes(ext)) {
        score += 0.1; hits++;
      }
      // Bonus for multiple corroborating signals
      if (hits >= 3) score += 0.2;
      // Penalty for conflicting signals that suggest a different category
      if (signals.conflictPatterns && signals.conflictPatterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        score -= 0.2;
      }

      if (score > best.confidence) {
        best = { category, layer, type, confidence: Math.min(1, Math.max(0, score)) };
      }
    };

    // ── Layer 1: Foundation / Bootstrap ──────────────────────────────────────
    evaluate('foundation', 1, 'bootstrap', {
      namePatterns:    ['enterprise-aws-bootstrap', 'ou-tree', 'ou-linker', 'bootstrap', 'jenkinsfile'],
      pathPatterns:    ['enterprise-aws-bootstrap', 'bootstrap/', 'automation/', 'templates/scp', 'templates/rcp'],
      contentPatterns: [
        'organizational_units', 'aws_organizations_', 'service_control_policy',
        'AWS Organizations', 'ou-tree', 'ou-linker', 'Jules',
      ],
      extensions: ['.yaml', '.yml', '.groovy', '.py', '.j2', '.sh'],
    });

    // ── Layer 2: Platform Factory Operators ───────────────────────────────────
    evaluate('factories', 2, 'operator', {
      namePatterns: [
        'portfolio-boundary', 'network-boundary', 'base-account',
        'workload-boundary', 'account-factory', '-factory',
      ],
      pathPatterns:    ['-factory/', 'crds/', 'operators/'],
      contentPatterns: [
        'portfolio-boundary-factory', 'network-boundary-factory',
        'base-account-factory', 'workload-boundary-factory',
        'kind: BoundaryResource', 'kind: AccountFactory', 'kind: NetworkBoundary', 'kind: WorkloadBoundary',
        'apiVersion: apiextensions', 'kubernetes_', 'helm_',
        'serviceAccountName:', 'serviceAccount:',
      ],
      extensions: ['.yaml', '.yml', '.tf'],
    });

    // ── Layer 3: IAM Modules ───────────────────────────────────────────────────
    evaluate('modules', 3, 'iam', {
      namePatterns:    ['module-role', 'module-iam', 'role-distribution', 'role-policy-updater', 'iam-policy'],
      pathPatterns:    ['module-role/', 'module-iam', 'role-distribution', 'iam-factory'],
      contentPatterns: [
        'module-role-policy-updater', 'aws_iam_role', 'assume_role_policy',
        'role_distribution', 'permissions_boundary',
      ],
      extensions: ['.tf', '.tfvars'],
    });

    // ── Layer 4: Network ───────────────────────────────────────────────────────
    evaluate('configs', 4, 'network', {
      namePatterns: ['vpc', 'subnet', 'security-group', 'tgw', 'transit-gateway', 'network-boundary', 'route-table'],
      pathPatterns: ['network/', 'vpc/', 'networking/', 'network-boundary'],
      contentPatterns: [
        'aws_vpc', 'aws_subnet', 'aws_security_group',
        'aws_transit_gateway', 'aws_flow_log', 'aws_vpc_endpoint',
      ],
      extensions: ['.tf'],
    });

    // ── Layer 5: Sentinel / Policy-as-Code ────────────────────────────────────
    evaluate('policies', 5, 'sentinel', {
      namePatterns:    ['.sentinel', 'sentinel', 'governance'],
      pathPatterns:    ['sentinel/', 'policies/', 'platform-global', 'governance/'],
      contentPatterns: [
        'import "tfplan"', 'import "tfconfig"', 'import "tfstate"', 'import "tfrun"',
        'main = rule', 'main=rule',
      ],
      extensions: ['.sentinel'],
    });

    // ── CRD detection (sub-category of Layer 2) ───────────────────────────────
    if (
      content.includes('kind: CustomResourceDefinition') ||
      content.includes('apiVersion: apiextensions.k8s.io')
    ) {
      evaluate('crds', 2, 'crd', {
        contentPatterns: ['kind: CustomResourceDefinition', 'apiVersion: apiextensions.k8s.io'],
        extensions:      ['.yaml', '.yml'],
        namePatterns:    ['-crd', 'crd-'],
        pathPatterns:    ['crds/'],
      });
    }

    // ── Layer 6: Product Modules ───────────────────────────────────────────────
    evaluate('modules', 6, 'product', {
      namePatterns: ['module-msk', 'module-kendra', 'module-opensearch', 'module-elasticache', 'module-rds'],
      pathPatterns: ['module-msk', 'module-kendra', 'module-opensearch', 'module-elasticache', 'module-rds'],
      contentPatterns: [
        'aws_msk_', 'aws_kendra', 'aws_opensearch', 'aws_elasticsearch',
        'aws_elasticache', 'aws_rds_', 'aws_kafka',
      ],
      extensions: ['.tf'],
    });

    // Fallback: if still unknown and it's a .tf file, infer layer from content
    if (best.category === 'unknown' && ext === '.tf') {
      const inferredLayer = this.determineTerraformLayer(content);
      best = { category: 'configs', layer: inferredLayer, type: 'terraform', confidence: 0.3 };
    }

    return best;
  }

  /**
   * Classify all files and group them into the classification buckets.
   *
   * @param {Array} files
   * @returns {{ foundation:[], factories:[], modules:[], policies:[], crds:[], configs:[], unknown:[] }}
   */
  classifyFiles(files = []) {
    const result = {
      foundation: [],
      factories:  [],
      modules:    [],
      policies:   [],
      crds:       [],
      configs:    [],
      unknown:    [],
    };

    for (const file of files) {
      const cls       = this.classifyFile(file);
      const enriched  = { ...file, _classification: cls };
      const bucket    = result[cls.category] ?? result.unknown;
      bucket.push(enriched);
    }

    return result;
  }

  /**
   * Determine the most likely architecture layer (1–7) for a Terraform file based on content.
   *
   * @param {string} content  Raw file content
   * @returns {number}
   */
  determineTerraformLayer(content) {
    const c = content.toLowerCase();

    // Layer 1: Organization/Foundation
    if (/aws_organizations_|organizational_unit|service_control_policy/.test(c)) return 1;

    // Layer 2: Kubernetes/Factory operators
    if (/kubernetes_|helm_|\bcrd\b|operator|boundaryresource/.test(c)) return 2;

    // Layer 3: IAM management
    if (/module\.role|aws_iam_role|role_distribution|assume_role_policy/.test(c)) return 3;

    // Layer 4: Networking
    if (/aws_vpc\b|aws_subnet|security_group|aws_transit_gateway/.test(c)) return 4;

    // Layer 5: Policy-as-code / Sentinel
    if (/sentinel|policy_as_code|import "tfplan"|main = rule/.test(c)) return 5;

    // Layer 6: Managed services
    if (/aws_msk_|aws_kendra|aws_opensearch|aws_elasticsearch|aws_elasticache|aws_rds_|aws_kafka/.test(c)) return 6;

    // Default: Application layer
    return 7;
  }

  // ── Layer analysis ────────────────────────────────────────────────────────────────────────────

  /**
   * Assess all 7 layers and build the layers result map.
   *
   * @param {object} classifiedFiles  From classifyFiles()
   * @param {Array}  allFiles         Flat list of all files
   * @returns {Object}  Keyed 1–7
   */
  identifyLayers(classifiedFiles, allFiles = []) {
    const layers = {};

    for (let layerNum = 1; layerNum <= 7; layerNum++) {
      const layerDef   = TERRAFORM_LAYERS[layerNum];
      const assessment = this.assessLayerCompleteness(layerNum, allFiles);

      // Determine status label from completeness score
      let status = 'missing';
      if (assessment.score >= 100)     status = 'complete';
      else if (assessment.score > 0)   status = 'partial';

      // Files whose classification points to this layer
      const layerFiles = allFiles.filter(f => {
        const cls = f._classification || this.classifyFile(f);
        return cls.layer === layerNum;
      });

      layers[layerNum] = {
        name:           layerDef.name,
        status,
        completeness:   assessment.score,
        fileCount:      layerFiles.length,
        presentModules: assessment.present,
        missingModules: assessment.missing,
        files:          layerFiles.map(f => f.name || f.path),
        matchDetails:   assessment.matchDetails,
        alternatives:   assessment.alternatives,
      };
    }

    return layers;
  }

  /**
   * Assess how complete a given layer is by checking whether its expected modules
   * can be found in the provided file list.
   *
   * @param {number} layerNum   1–7
   * @param {Array}  files      All files
   * @returns {{ score:number, missing:string[], present:string[], matchDetails:Object, alternatives:Array }}
   */
  assessLayerCompleteness(layerNum, files) {
    const layer        = TERRAFORM_LAYERS[layerNum];
    const foundModules = [];
    const matchDetails = {};

    layer.modules.forEach(module => {
      const patterns    = this._generateModulePatterns(module, files);
      const matchedFiles = files.filter(f => this._moduleMatchesFile(module, f, patterns));
      if (matchedFiles.length > 0) {
        foundModules.push(module);
        matchDetails[module] = matchedFiles.map(f => f.name || f.path);
      }
    });

    // If the layer has no expected modules defined it is trivially complete
    const score = layer.modules.length > 0
      ? (foundModules.length / layer.modules.length) * 100
      : 100;

    return {
      score:        Math.round(score),
      missing:      layer.modules.filter(m => !foundModules.includes(m)),
      present:      foundModules,
      matchDetails,
      alternatives: layer.modules
        .filter(m => !foundModules.includes(m))
        .map(m => ({ module: m, suggestions: this._suggestAlternativeMatches(m, files) })),
    };
  }

  /**
   * Generate the full set of matching patterns for a canonical module name.
   * Patterns are descriptors used by _moduleMatchesFile().
   *
   * @param {string} module  Canonical module name (e.g. 'network-boundary-factory')
   * @param {Array}  files   All files (unused here but available for extension)
   * @returns {Array<{type:string, value:string}>}
   */
  _generateModulePatterns(module, files) {
    const patterns    = [];
    const moduleLower = module.toLowerCase();

    // Exact name / path contains the module string
    patterns.push({ type: 'exact',     value: moduleLower });
    // Directory path segments
    patterns.push({ type: 'dir',       value: `/${moduleLower}/` });
    patterns.push({ type: 'dir',       value: `\\${moduleLower}\\` });
    // Common module directory layout variations
    patterns.push({ type: 'variation', value: `modules/${moduleLower}` });
    patterns.push({ type: 'variation', value: `module-${moduleLower}` });
    patterns.push({ type: 'variation', value: `${moduleLower}-module` });

    // Wildcard module: match the base without the trailing '*'
    if (module.includes('*')) {
      const base = moduleLower.replace(/\*/g, '').replace(/-$/, '');
      patterns.push({ type: 'wildcard', value: base });
    }

    // Factory variant: also match without the '-factory' suffix
    if (moduleLower.endsWith('-factory')) {
      const base = moduleLower.replace(/-factory$/, '');
      patterns.push({ type: 'factory-base', value: base });
    }

    // Content-based: module name embedded in file text
    patterns.push({ type: 'content', value: moduleLower });
    patterns.push({ type: 'content', value: module }); // original case for exact content match

    // Abbreviation / alias patterns from the map
    for (const alias of (ABBREVIATION_MAP[module] || [])) {
      patterns.push({ type: 'alias', value: alias.toLowerCase() });
    }

    // Detection signals from FACTORY_COMPONENTS if this is a factory
    for (const signal of (FACTORY_COMPONENTS[module]?.detectionSignals || [])) {
      patterns.push({ type: 'signal', value: signal.toLowerCase() });
    }

    // Detection signals from IAM_MODULES if this is an IAM module
    for (const signal of (IAM_MODULES[module]?.detectionSignals || [])) {
      patterns.push({ type: 'signal', value: signal.toLowerCase() });
    }

    return patterns;
  }

  /**
   * Return true if the given file matches any of the patterns generated for a module.
   *
   * @param {string} module    Canonical module name
   * @param {object} file      File object
   * @param {Array}  patterns  From _generateModulePatterns
   * @returns {boolean}
   */
  _moduleMatchesFile(module, file, patterns) {
    const nameLower    = String(file.name    || '').toLowerCase();
    const pathLower    = String(file.path    || '').toLowerCase();
    const contentLower = String(file.content || '').toLowerCase();

    for (const p of patterns) {
      switch (p.type) {
        case 'exact':
        case 'factory-base':
          if (nameLower.includes(p.value) || pathLower.includes(p.value)) return true;
          break;
        case 'dir':
          if (pathLower.includes(p.value)) return true;
          break;
        case 'variation':
          if (pathLower.includes(p.value) || nameLower.includes(p.value)) return true;
          break;
        case 'wildcard':
          if (nameLower.includes(p.value) || pathLower.includes(p.value)) return true;
          break;
        case 'content':
          if (contentLower.includes(p.value)) return true;
          break;
        case 'alias':
        case 'signal':
          if (nameLower.includes(p.value) || pathLower.includes(p.value) || contentLower.includes(p.value)) return true;
          break;
        default:
          break;
      }
    }
    return false;
  }

  /**
   * Find partial / alternative matches for a module that is not present in the file list.
   * Splits the module name on word boundaries and scores files by word overlap.
   *
   * @param {string} module   Canonical module name
   * @param {Array}  files    All files
   * @returns {Array<{file:string, score:number}>}  Top 3 partial matches
   */
  _suggestAlternativeMatches(module, files) {
    const words = module.toLowerCase().split(/[-_]+/).filter(w => w.length > 2);

    const scored = files.map(file => {
      const target = `${file.name || ''} ${file.path || ''}`.toLowerCase();
      const matchCount = words.filter(w => target.includes(w)).length;
      const score      = words.length > 0 ? matchCount / words.length : 0;
      return { file: file.name || file.path, score };
    });

    return scored
      .filter(s => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3);
  }

  // ── Factory analysis ──────────────────────────────────────────────────────────────────────────

  /**
   * Analyse presence and configuration status of each Layer 2 factory component.
   *
   * @param {object} classifiedFiles
   * @param {Array}  allFiles
   * @returns {Object}  Keyed by factory name
   */
  analyzeFactories(classifiedFiles, allFiles = []) {
    const result = {};

    for (const [factoryName, factoryDef] of Object.entries(FACTORY_COMPONENTS)) {
      const signals        = factoryDef.detectionSignals.map(s => s.toLowerCase());
      const crdNames       = factoryDef.crds.map(c => c.toLowerCase());
      const svcAccountKey  = factoryDef.serviceAccount.toLowerCase();
      const iamRoleKey     = factoryDef.iamRole.toLowerCase();

      const matchedFiles     = [];
      let crdDetected        = false;
      let serviceAccountDet  = false;
      let iamRoleDetected    = false;
      const securityFindings = [];

      for (const file of allFiles) {
        const nameLower    = String(file.name    || '').toLowerCase();
        const pathLower    = String(file.path    || '').toLowerCase();
        const contentLower = String(file.content || '').toLowerCase();
        const combined     = `${nameLower} ${pathLower}`;

        const signalMatch = signals.some(s => combined.includes(s) || contentLower.includes(s));
        if (!signalMatch) continue;

        matchedFiles.push(file.name || file.path);

        // CRD: the CRD kind appears in content or 'CustomResourceDefinition' block contains the CRD name
        if (!crdDetected) {
          if (crdNames.some(crd => contentLower.includes(crd))) crdDetected = true;
          if (
            contentLower.includes('kind: customresourcedefinition') &&
            crdNames.some(crd => contentLower.includes(crd))
          ) crdDetected = true;
        }

        // Service account
        if (!serviceAccountDet) {
          if (
            contentLower.includes(`serviceaccountname: ${svcAccountKey}`) ||
            contentLower.includes(`serviceaccount: ${svcAccountKey}`) ||
            contentLower.includes(svcAccountKey)
          ) serviceAccountDet = true;
        }

        // IAM role / IRSA annotation
        if (!iamRoleDetected) {
          if (
            contentLower.includes(iamRoleKey) ||
            (
              contentLower.includes('eks.amazonaws.com/role-arn') &&
              contentLower.includes(iamRoleKey.split('-').slice(-2).join('-'))
            )
          ) iamRoleDetected = true;
        }
      }

      // Determine overall status
      let status = 'missing';
      if (matchedFiles.length > 0) {
        status = (crdDetected && serviceAccountDet && iamRoleDetected) ? 'present' : 'partial';
      }

      // Generate security findings per status
      if (status === 'missing') {
        securityFindings.push(`CRITICAL: ${factoryName} not found — ${factoryDef.purpose}`);
        if (factoryName === 'network-boundary-factory') {
          securityFindings.push('Risk: No automated network micro-segmentation — exposes T1190, T1046, T1133');
        } else if (factoryName === 'base-account-factory') {
          securityFindings.push('Risk: Manual account vending may skip baseline security controls');
        } else if (factoryName === 'portfolio-boundary-factory') {
          securityFindings.push('Risk: OU/SCP boundary management ungoverned — exposes T1580, T1078.004');
        } else if (factoryName === 'workload-boundary-factory') {
          securityFindings.push('Risk: Workload isolation boundaries not enforced programmatically');
        }
      } else if (status === 'partial') {
        if (!crdDetected)       securityFindings.push(`WARNING: ${factoryName} — CRD definition not detected`);
        if (!serviceAccountDet) securityFindings.push(`WARNING: ${factoryName} — Service account not configured`);
        if (!iamRoleDetected)   securityFindings.push(`WARNING: ${factoryName} — IRSA IAM role not detected`);
      }

      result[factoryName] = {
        status,
        fileCount:              matchedFiles.length,
        files:                  matchedFiles,
        securityFindings,
        crdDetected,
        serviceAccountDetected: serviceAccountDet,
        iamRoleDetected,
      };
    }

    return result;
  }

  // ── IAM module analysis ───────────────────────────────────────────────────────────────────────

  /**
   * Detect IAM module presence across the provided file list.
   *
   * @param {object} classifiedFiles
   * @param {Array}  allFiles
   * @returns {Object}  Keyed by IAM module name
   */
  analyzeIAMModules(classifiedFiles, allFiles = []) {
    const result = {};

    for (const [moduleName, moduleDef] of Object.entries(IAM_MODULES)) {
      const signals      = moduleDef.detectionSignals.map(s => s.toLowerCase());
      const matchedFiles = [];
      let keyPatternFound = false;

      for (const file of allFiles) {
        const nameLower    = String(file.name    || '').toLowerCase();
        const pathLower    = String(file.path    || '').toLowerCase();
        const contentLower = String(file.content || '').toLowerCase();
        const combined     = `${nameLower} ${pathLower}`;

        const signalMatch = signals.some(s => combined.includes(s) || contentLower.includes(s));
        if (!signalMatch) continue;

        matchedFiles.push(file.name || file.path);

        // Check for key variable/output names that confirm the module
        if (!keyPatternFound) {
          for (const varName of moduleDef.variables) {
            if (contentLower.includes(varName.toLowerCase())) {
              keyPatternFound = true;
              break;
            }
          }
        }
      }

      result[moduleName] = {
        status:         matchedFiles.length > 0 ? 'present' : 'missing',
        fileCount:      matchedFiles.length,
        files:          matchedFiles,
        keyPatternFound,
        crossAccount:   moduleDef.crossAccount,
      };
    }

    return result;
  }

  // ── Sentinel policy analysis ──────────────────────────────────────────────────────────────────

  /**
   * Analyse Sentinel / policy-as-code coverage from the file set.
   *
   * @param {object} classifiedFiles
   * @param {Array}  allFiles
   * @returns {{ totalCount:number, policyTypes:Object, files:string[], coverage:number }}
   */
  analyzeSentinelPolicies(classifiedFiles, allFiles = []) {
    const sentinelFiles = allFiles.filter(f => {
      const name    = String(f.name || '').toLowerCase();
      const pathStr = String(f.path || '').toLowerCase();
      const content = String(f.content || '');

      return (
        name.endsWith('.sentinel') ||
        pathStr.includes('sentinel/') ||
        pathStr.includes('/policies/') ||
        SENTINEL_IMPORT_PATTERNS.some(p => content.includes(p))
      );
    });

    const totalCount = sentinelFiles.length;
    const fileNames  = sentinelFiles.map(f => f.name || f.path);

    // Categorise each sentinel file by policy domain
    const policyTypes = {
      tagging:    [],
      naming:     [],
      security:   [],
      compliance: [],
      governance: [],
      lifecycle:  [],
    };

    for (const file of sentinelFiles) {
      const combined = `${(file.name || '').toLowerCase()} ${(file.content || '').toLowerCase()}`;
      for (const [typeKey, keywords] of Object.entries(SENTINEL_POLICY_TYPES)) {
        if (keywords.some(kw => combined.includes(kw))) {
          policyTypes[typeKey].push(file.name || file.path);
        }
      }
    }

    // Coverage: percentage of policy type categories that have at least one policy file
    const typeCount    = Object.keys(policyTypes).length;
    const coveredTypes = Object.values(policyTypes).filter(arr => arr.length > 0).length;
    const coverage     = typeCount > 0 ? Math.round((coveredTypes / typeCount) * 100) : 0;

    return { totalCount, policyTypes, files: fileNames, coverage };
  }

  // ── Product module detection ──────────────────────────────────────────────────────────────────

  /**
   * Auto-detect potential Layer 6 product modules from in-memory files.
   * A directory is a candidate if it contains main.tf AND variables.tf or outputs.tf.
   *
   * @param {Array} files
   * @returns {Array<{name:string, path:string, serviceType:string, fileCount:number, awsServices:string[], contentPreview:string}>}
   */
  findPotentialProductModules(files) {
    // Group files by directory path
    const byDir = new Map();
    for (const file of files) {
      const dir = dirOf(file.path || file.name || '');
      if (!byDir.has(dir)) byDir.set(dir, []);
      byDir.get(dir).push(file);
    }

    const potentialModules = [];

    for (const [dir, dirFiles] of byDir.entries()) {
      const names = dirFiles.map(f => (f.name || f.path || '').toLowerCase());

      // Require main.tf
      if (!names.some(n => n.endsWith('main.tf'))) continue;
      // Require variables.tf or outputs.tf
      if (!names.some(n => n.endsWith('variables.tf') || n.endsWith('outputs.tf'))) continue;

      // Skip well-known non-product directories
      const skipDirs = ['environments', 'layers', 'scripts', 'templates', 'automation', 'pipelines'];
      if (skipDirs.some(s => dir.includes(s))) continue;

      const combinedContent = dirFiles.map(f => f.content || '').join('\n').toLowerCase();

      // Detect service type using PRODUCT_INDICATORS
      let serviceType  = 'General Module';
      let bestHitCount = 0;
      for (const [svcType, keywords] of Object.entries(PRODUCT_INDICATORS)) {
        const hitCount = keywords.filter(kw => combinedContent.includes(kw.toLowerCase())).length;
        if (hitCount > bestHitCount) {
          bestHitCount = hitCount;
          serviceType  = svcType;
        }
      }

      // Extract specific AWS resource types from 'resource "aws_xxx" "name"' declarations
      const awsServices = [];
      const seen        = new Set();
      const re          = /resource\s+"(aws_[a-z_]+)"/g;
      let m;
      for (const file of dirFiles) {
        while ((m = re.exec(file.content || '')) !== null) {
          if (!seen.has(m[1])) { seen.add(m[1]); awsServices.push(m[1]); }
        }
      }

      // First meaningful line from main.tf as a content preview
      const mainTf       = dirFiles.find(f => (f.name || '').toLowerCase().endsWith('main.tf'));
      const contentPreview = mainTf
        ? (mainTf.content || '').split('\n').find(l => l.trim() && !l.trim().startsWith('#')) || ''
        : '';

      // Derive the module name from the last directory segment
      const segments   = dir.split(/[/\\]/).filter(s => s.length > 0);
      const moduleName = segments[segments.length - 1] || dir;

      potentialModules.push({
        name:           moduleName,
        path:           dir,
        serviceType:    bestHitCount > 0 ? serviceType : 'General Module',
        fileCount:      dirFiles.length,
        awsServices,
        contentPreview: contentPreview.trim().slice(0, 120),
      });
    }

    return potentialModules;
  }

  /**
   * Accept user-confirmed product module selections and merge them with any existing ones.
   * Invalidates the analysis cache so the next call to analyzeArchitecture() uses fresh data.
   *
   * @param {Array<{name:string, path:string, serviceType?:string}>} productModules
   */
  setProductModules(productModules = []) {
    for (const mod of productModules) {
      if (!this._productModules.some(m => m.name === mod.name)) {
        this._productModules.push(mod);
      }
    }
    this._lastAnalysis    = null;
    this._classifiedFiles = null;
  }

  // ── Resource extraction helper ────────────────────────────────────────────────────────────────

  /**
   * Build a lightweight resources array from .tf file content.
   * Parses 'resource "TYPE" "NAME" { ... }' blocks.
   * Used by compliance check functions.
   *
   * @param {Array} files
   * @returns {Array<{type:string, name:string, body:string}>}
   */
  _extractResourcesFromFiles(files) {
    const resources = [];
    // Regex matches a resource block header and captures up to the next resource block or EOF
    const re = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\nresource\s+"|\nmodule\s+"|\ndata\s+"|$)/g;

    for (const file of files) {
      if (!['.tf', '.tfvars'].includes(extOf(file.name || file.path || ''))) continue;
      let m;
      while ((m = re.exec(file.content || '')) !== null) {
        resources.push({ type: m[1], name: m[2], body: m[3] });
      }
    }

    return resources;
  }

  // ── Security control analysis ─────────────────────────────────────────────────────────────────

  /**
   * Compute security scores across six security domains and produce an overall score.
   *
   * @param {Array} allFiles
   * @returns {{ overall:number, scpInheritance:number, networkSecurity:number, iamGovernance:number,
   *             dataProtection:number, sentinelCoverage:number, auditLogging:number, criticalIssues:string[] }}
   */
  analyzeSecurityControls(allFiles = []) {
    const scpScore       = this._analyzeSCPInheritance(allFiles);
    const netScore       = this._analyzeNetworkSecurity(allFiles);
    const iamScore       = this._analyzeIAMGovernance(allFiles);
    const dataScore      = this._analyzeDataProtection(allFiles);
    const sentinelScore  = this._analyzeSentinelScore(allFiles);
    const auditScore     = this._analyzeAuditLogging(allFiles);

    // Weighted composite: SCP*0.20, Network*0.25, IAM*0.25, Data*0.15, Sentinel*0.10, Audit*0.05
    const overall = clamp100(weightedAverage([
      { value: scpScore,      weight: 0.20 },
      { value: netScore,      weight: 0.25 },
      { value: iamScore,      weight: 0.25 },
      { value: dataScore,     weight: 0.15 },
      { value: sentinelScore, weight: 0.10 },
      { value: auditScore,    weight: 0.05 },
    ]));

    const criticalIssues = [];
    if (scpScore < 40)       criticalIssues.push('SCP inheritance not detected — organization-level controls missing');
    if (netScore < 40)       criticalIssues.push('Network security controls insufficient — no VPC isolation detected');
    if (iamScore < 40)       criticalIssues.push('IAM governance missing — role lifecycle management absent');
    if (dataScore < 40)      criticalIssues.push('Data protection insufficient — no KMS or secrets management detected');
    if (sentinelScore === 0) criticalIssues.push('No Sentinel policies detected — policy-as-code enforcement absent');
    if (auditScore < 40)     criticalIssues.push('Audit logging insufficient — CloudTrail or GuardDuty not found');

    return {
      overall,
      scpInheritance:  scpScore,
      networkSecurity: netScore,
      iamGovernance:   iamScore,
      dataProtection:  dataScore,
      sentinelCoverage: sentinelScore,
      auditLogging:    auditScore,
      criticalIssues,
    };
  }

  /** SCP / organization policy inheritance score. */
  _analyzeSCPInheritance(files) {
    const c = files.map(f => f.content || '').join('\n').toLowerCase();
    let s = 0;
    if (/aws_organizations_policy/.test(c))           s += 30;
    if (/service_control_policy|scp/.test(c))         s += 20;
    if (/deny\s+not\s+action|notaction/.test(c))      s += 20;
    if (/aws_organizations_policy_attachment/.test(c)) s += 15;
    if (/ou-tree|ou_tree|organizational_unit/.test(c)) s += 15;
    return clamp100(s);
  }

  /** VPC-level network security score. */
  _analyzeNetworkSecurity(files) {
    const c = files.map(f => f.content || '').join('\n').toLowerCase();
    let s = 0;
    if (/aws_vpc\b/.test(c))              s += 20;
    if (/aws_subnet\b/.test(c))           s += 10;
    if (/aws_security_group\b/.test(c))   s += 15;
    if (!/0\.0\.0\.0\/0/.test(c))         s += 20;
    else if (/cidr_blocks.*0\.0\.0\.0\/0/.test(c)) s -= 10;
    if (/aws_flow_log/.test(c))           s += 15;
    if (/aws_transit_gateway\b/.test(c))  s += 10;
    if (/aws_vpc_endpoint/.test(c))       s += 10;
    return clamp100(s);
  }

  /** IAM governance and least-privilege score. */
  _analyzeIAMGovernance(files) {
    const c = files.map(f => f.content || '').join('\n').toLowerCase();
    let s = 0;
    if (/module[-_]role/.test(c))              s += 25;
    if (/role[-_]distribution/.test(c))        s += 20;
    if (/permissions_boundary/.test(c))        s += 20;
    if (/"action"\s*:\s*"\*"/.test(c))         s -= 20;  // wildcard IAM is a negative signal
    if (/assume_role_policy/.test(c))          s += 15;
    if (/aws_ssoadmin|aws_iam_openid/.test(c)) s += 20;
    return clamp100(s);
  }

  /** Data protection (KMS, secrets, encryption-at-rest) score. */
  _analyzeDataProtection(files) {
    const c = files.map(f => f.content || '').join('\n').toLowerCase();
    let s = 0;
    if (/aws_kms_key/.test(c))               s += 30;
    if (/aws_secretsmanager_secret/.test(c)) s += 20;
    if (/aws_ssm_parameter/.test(c))         s += 10;
    if (/encryption|encrypted/.test(c))      s += 15;
    if (/server_side_encryption/.test(c))    s += 15;
    if (/kms_key_id|kms_master_key/.test(c)) s += 10;
    return clamp100(s);
  }

  /** Sentinel policy coverage score (delegated to analyzeSentinelPolicies). */
  _analyzeSentinelScore(files) {
    return this.analyzeSentinelPolicies({}, files).coverage;
  }

  /** Audit logging (CloudTrail, GuardDuty, CloudWatch) score. */
  _analyzeAuditLogging(files) {
    const c = files.map(f => f.content || '').join('\n').toLowerCase();
    let s = 0;
    if (/aws_cloudtrail/.test(c))              s += 30;
    if (/aws_flow_log/.test(c))                s += 20;
    if (/aws_cloudwatch_metric_alarm/.test(c)) s += 15;
    if (/aws_guardduty_detector/.test(c))      s += 20;
    if (/aws_securityhub/.test(c))             s += 15;
    return clamp100(s);
  }

  // ── Compliance validation ─────────────────────────────────────────────────────────────────────

  /**
   * Run SOX, PCI, GDPR, and HIPAA compliance checks against resources extracted from files.
   *
   * @param {Array} allFiles
   * @returns {{ overall:number, sox:number, pci:number, gdpr:number, hipaa:number, violations:Array }}
   */
  validateCompliance(allFiles = []) {
    const resources = this._extractResourcesFromFiles(allFiles);

    /**
     * Score a compliance check set.
     * Critical checks count double; returns 0-100.
     */
    const scoreCheckSet = (checks) => {
      let totalWeight = 0;
      let passWeight  = 0;
      for (const check of checks) {
        const weight = check.critical ? 2 : 1;
        totalWeight += weight;
        try {
          if (check.check(resources)) passWeight += weight;
        } catch (_) {
          // Individual check errors do not abort the whole set
        }
      }
      return totalWeight > 0 ? Math.round((passWeight / totalWeight) * 100) : 0;
    };

    const sox   = scoreCheckSet(SOX_CHECKS);
    const pci   = scoreCheckSet(PCI_CHECKS);
    const gdpr  = scoreCheckSet(GDPR_CHECKS);
    const hipaa = scoreCheckSet(HIPAA_CHECKS);
    const overall = Math.round((sox + pci + gdpr + hipaa) / 4);

    // Collect failed critical checks as violations
    const violations = [];
    for (const [framework, checks] of Object.entries(ALL_COMPLIANCE_CHECKS)) {
      for (const check of checks) {
        if (!check.critical) continue;
        try {
          if (!check.check(resources)) {
            violations.push({ framework, id: check.id, category: check.category, desc: check.desc });
          }
        } catch (err) {
          violations.push({ framework, id: check.id, category: check.category, desc: `Check error: ${check.desc}` });
        }
      }
    }

    return { overall, sox, pci, gdpr, hipaa, violations };
  }

  // ── Dependency graph ──────────────────────────────────────────────────────────────────────────

  /**
   * Build a dependency adjacency graph from layer ordering and factory component dependencies.
   *
   * @param {Object} layers  Result from identifyLayers
   * @returns {{ graph:Object, circular:string[][], criticalPath:string[] }}
   */
  buildDependencyGraph(layers) {
    const graph = {};

    // Initialise layer nodes
    for (let i = 1; i <= 7; i++) graph[`layer-${i}`] = [];

    // Factory nodes with their own inter-factory dependencies
    for (const [factoryName, factoryDef] of Object.entries(FACTORY_COMPONENTS)) {
      graph[factoryName] = factoryDef.dependencies.slice();
    }

    // Layer 2 depends on all factories (which individually depend on Layer 1 components)
    for (const factoryName of Object.keys(FACTORY_COMPONENTS)) {
      graph['layer-2'].push(factoryName);
    }

    // Standard layer ordering edges
    graph['layer-2'].push('layer-1');
    graph['layer-3'].push('layer-1');
    graph['layer-4'].push('layer-2');
    graph['layer-5'].push('layer-3');
    graph['layer-5'].push('layer-4');
    graph['layer-6'].push('layer-4');
    graph['layer-6'].push('layer-5');
    graph['layer-7'].push('layer-6');

    return {
      graph,
      circular:     this._detectCircularDependencies(graph),
      criticalPath: this._findCriticalPath(graph),
    };
  }

  /**
   * Depth-first search for cycles in a dependency adjacency list.
   * Returns an array of detected cycles (each cycle is an array of node names).
   *
   * @param {Object} graph  Adjacency list: { node: [dep, dep, ...], ... }
   * @returns {string[][]}
   */
  _detectCircularDependencies(graph) {
    const visited = new Set();
    const inStack = new Set();
    const cycles  = [];

    const dfs = (node, path) => {
      visited.add(node);
      inStack.add(node);
      path.push(node);

      for (const dep of (graph[node] || [])) {
        if (!visited.has(dep)) {
          dfs(dep, path);
        } else if (inStack.has(dep)) {
          const start = path.indexOf(dep);
          if (start !== -1) cycles.push([...path.slice(start), dep]);
        }
      }

      path.pop();
      inStack.delete(node);
    };

    for (const node of Object.keys(graph)) {
      if (!visited.has(node)) dfs(node, []);
    }

    return cycles;
  }

  /**
   * Topological sort to determine the critical path (dependency-first ordering).
   *
   * @param {Object} graph  Adjacency list
   * @returns {string[]}  Nodes ordered from dependencies to dependents
   */
  _findCriticalPath(graph) {
    const visited = new Set();
    const order   = [];

    const visit = (node) => {
      if (visited.has(node)) return;
      visited.add(node);
      for (const dep of (graph[node] || [])) visit(dep);
      order.push(node);
    };

    for (const node of Object.keys(graph)) visit(node);

    // Reverse so foundations come first
    return order.reverse();
  }

  // ── Recommendations ───────────────────────────────────────────────────────────────────────────

  /**
   * Generate a prioritised recommendation list from the assembled analysis result.
   * Priority order: CRITICAL > HIGH > MEDIUM > LOW.
   *
   * @param {object} analysisResult
   * @returns {Array<{priority:string, category:string, title:string, description:string,
   *                  impact:string, action:string, affectedLayer:number|null, attackTechniques:string[]}>}
   */
  generateRecommendations(analysisResult) {
    const recs = [];

    // ── Layer completeness ─────────────────────────────────────────────────────
    for (const [layerNumStr, layer] of Object.entries(analysisResult.layers)) {
      const layerNum = Number(layerNumStr);
      const layerDef = TERRAFORM_LAYERS[layerNum];
      const score    = layer.completeness || 0;

      if (score === 0) {
        recs.push({
          priority:        'CRITICAL',
          category:        'Architecture Completeness',
          title:           `Deploy Layer ${layerNum}: ${layerDef.name}`,
          description:     `Layer ${layerNum} (${layerDef.name}) is entirely absent. ${layerDef.description}`,
          impact:          `Missing: ${layerDef.modules.join(', ')}`,
          action:          `Implement ${layerDef.modules[0] || layerDef.name} as the foundational component of Layer ${layerNum}`,
          affectedLayer:   layerNum,
          attackTechniques: this._layerToAttackTechniques(layerNum),
        });
      } else if (score < 50) {
        recs.push({
          priority:        'HIGH',
          category:        'Architecture Completeness',
          title:           `Complete Layer ${layerNum}: ${layerDef.name} (${score}% done)`,
          description:     `Layer ${layerNum} is only ${score}% complete. Missing modules reduce platform resilience.`,
          impact:          `Missing modules: ${layer.missingModules.join(', ')}`,
          action:          `Implement missing modules: ${layer.missingModules.slice(0, 3).join(', ')}`,
          affectedLayer:   layerNum,
          attackTechniques: this._layerToAttackTechniques(layerNum),
        });
      } else if (score < 80) {
        recs.push({
          priority:        'MEDIUM',
          category:        'Architecture Completeness',
          title:           `Enhance Layer ${layerNum}: ${layerDef.name} (${score}% done)`,
          description:     `Layer ${layerNum} is ${score}% complete. ${layer.missingModules.length} module(s) remaining.`,
          impact:          `Partially missing: ${layer.missingModules.join(', ')}`,
          action:          `Add remaining modules to complete Layer ${layerNum}: ${layer.missingModules.join(', ')}`,
          affectedLayer:   layerNum,
          attackTechniques: [],
        });
      }
    }

    // ── Factory components ─────────────────────────────────────────────────────
    for (const [factoryName, factoryResult] of Object.entries(analysisResult.factories)) {
      const factoryDef    = FACTORY_COMPONENTS[factoryName];
      const hasDependents = Object.values(FACTORY_COMPONENTS).some(f => f.dependencies.includes(factoryName));

      if (factoryResult.status === 'missing') {
        recs.push({
          priority:        hasDependents ? 'CRITICAL' : 'HIGH',
          category:        'Factory Components',
          title:           `Deploy ${factoryName}`,
          description:     `${factoryDef.purpose}. ${hasDependents ? 'Has dependent factories.' : 'Required for platform completeness.'}`,
          impact:          `${factoryDef.security.join(', ')} controls absent`,
          action:          `Implement ${factoryName} operator with CRDs: ${factoryDef.crds.join(', ')}`,
          affectedLayer:   2,
          attackTechniques: factoryName === 'network-boundary-factory'   ? ['T1190', 'T1046', 'T1133'] :
                            factoryName === 'portfolio-boundary-factory' ? ['T1580', 'T1078.004']      : [],
        });
      } else if (factoryResult.status === 'partial') {
        recs.push({
          priority:        'MEDIUM',
          category:        'Factory Components',
          title:           `Complete ${factoryName} configuration`,
          description:     `${factoryName} is partially configured. ${factoryResult.securityFindings.join('; ')}`,
          impact:          'Partial factory configuration may leave security controls incomplete',
          action:          `Ensure CRDs, service accounts, and IRSA roles are all configured for ${factoryName}`,
          affectedLayer:   2,
          attackTechniques: [],
        });
      }
    }

    // ── Security scores ────────────────────────────────────────────────────────
    const sec = analysisResult.security;

    if (sec.overall < 60) {
      recs.push({
        priority:        'CRITICAL',
        category:        'Security Posture',
        title:           `Overall security score critical: ${sec.overall}%`,
        description:     'Overall security posture is critically low. Multiple security domains are deficient.',
        impact:          `Critical issues: ${sec.criticalIssues.slice(0, 3).join('; ')}`,
        action:          'Address critical security issues in each domain before production deployment',
        affectedLayer:   null,
        attackTechniques: ['T1078.004', 'T1562.008', 'T1190'],
      });
    }

    if (sec.sentinelCoverage === 0) {
      recs.push({
        priority:        'HIGH',
        category:        'Policy Enforcement',
        title:           'Implement Sentinel policy-as-code (Layer 5)',
        description:     'No Sentinel policies detected. Policy-as-code is the primary enforcement mechanism for enterprise governance.',
        impact:          'Resources can be deployed without compliance validation — tagging, naming, and encryption controls absent',
        action:          'Deploy sentinel/*.sentinel policies covering tagging, naming, security, and compliance categories',
        affectedLayer:   5,
        attackTechniques: ['T1562.008'],
      });
    }

    if (sec.iamGovernance < 50) {
      recs.push({
        priority:        'HIGH',
        category:        'IAM Governance',
        title:           `IAM governance insufficient: ${sec.iamGovernance}%`,
        description:     'IAM role lifecycle management is weak. Cross-account role distribution and permission boundaries missing.',
        impact:          'Ungoverned IAM enables privilege escalation and lateral movement',
        action:          'Deploy module-role, module-iam-policy, and role-distribution-factory (Layer 3)',
        affectedLayer:   3,
        attackTechniques: ['T1078.004', 'T1548', 'T1098.003'],
      });
    }

    if (sec.networkSecurity < 50) {
      recs.push({
        priority:        'HIGH',
        category:        'Network Security',
        title:           `Network security controls weak: ${sec.networkSecurity}%`,
        description:     'Network isolation patterns are insufficient. VPC isolation, security groups, or flow logs missing.',
        impact:          'Lateral movement and network-based attacks are easier without proper segmentation',
        action:          'Deploy network-boundary-factory and configure VPC isolation, flow logs, and private subnets',
        affectedLayer:   4,
        attackTechniques: ['T1190', 'T1046', 'T1133'],
      });
    }

    // ── Compliance ─────────────────────────────────────────────────────────────
    const comp = analysisResult.compliance;
    if (comp.overall < 70) {
      recs.push({
        priority:        'HIGH',
        category:        'Compliance',
        title:           `Compliance posture below threshold: ${comp.overall}%`,
        description:     `Overall compliance is ${comp.overall}%. SOX:${comp.sox}% PCI:${comp.pci}% GDPR:${comp.gdpr}% HIPAA:${comp.hipaa}%`,
        impact:          `${comp.violations.length} critical compliance violations detected`,
        action:          'Enable CloudTrail, KMS encryption, GuardDuty, and VPC isolation to address critical violations',
        affectedLayer:   null,
        attackTechniques: [],
      });
    }

    // ── Naming conventions (LOW) ───────────────────────────────────────────────
    const allClassified = [
      ...(analysisResult.classification.foundation || []),
      ...(analysisResult.classification.factories  || []),
      ...(analysisResult.classification.modules    || []),
    ];
    const nonCompliant = allClassified.filter(f => {
      const n = String(f.name || '').toLowerCase();
      return n.endsWith('.tf') && !n.startsWith('enterprise-') && !n.startsWith('module-') && !n.startsWith('platform-');
    });
    if (nonCompliant.length > 5) {
      recs.push({
        priority:        'LOW',
        category:        'Naming Conventions',
        title:           'Enforce enterprise naming conventions',
        description:     `${nonCompliant.length} files may not follow the enterprise naming pattern (${NAMING_CONVENTIONS.resources.pattern}).`,
        impact:          'Inconsistent naming complicates automation, search, and governance enforcement',
        action:          `Adopt naming convention: ${NAMING_CONVENTIONS.resources.pattern}`,
        affectedLayer:   null,
        attackTechniques: [],
      });
    }

    // Sort by priority
    const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    recs.sort((a, b) => (priorityOrder[a.priority] ?? 4) - (priorityOrder[b.priority] ?? 4));

    return recs;
  }

  /**
   * Map a layer number to the MITRE ATT&CK technique IDs most relevant to that layer being absent.
   *
   * @param {number} layerNum
   * @returns {string[]}
   */
  _layerToAttackTechniques(layerNum) {
    const map = {
      1: ['T1580', 'T1078.004'],
      2: ['T1190', 'T1046', 'T1580'],
      3: ['T1078.004', 'T1548', 'T1098.003'],
      4: ['T1190', 'T1046', 'T1133'],
      5: ['T1562.008'],
      6: ['T1190', 'T1530'],
      7: ['T1190', 'T1648'],
    };
    return map[layerNum] || [];
  }

  // ── Architecture grade ────────────────────────────────────────────────────────────────────────

  /**
   * Convert an average completeness percentage to a letter grade.
   *
   * @param {number} score  0–100
   * @returns {'A'|'B'|'C'|'D'|'F'}
   */
  getArchitectureGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 50) return 'D';
    return 'F';
  }

  // ── AWS service helper ────────────────────────────────────────────────────────────────────────

  /**
   * Map a Terraform resource type string to a human-readable AWS service category.
   * Uses PRODUCT_INDICATORS keyword arrays for matching.
   *
   * @param {string} resourceType  e.g. 'aws_rds_instance'
   * @returns {string}  e.g. 'Database Service'
   */
  _getAWSServiceFromResource(resourceType) {
    const rt = String(resourceType).toLowerCase();
    for (const [svcType, keywords] of Object.entries(PRODUCT_INDICATORS)) {
      if (keywords.some(kw => rt.includes(kw.toLowerCase()))) return svcType;
    }
    return 'Unknown Service';
  }

  // ── Synthetic document generation ─────────────────────────────────────────────────────────────

  /**
   * Generate a structured plain-text document from the last analysis result.
   * This document is designed to be ingested by ThreatModelIntelligence for BM25 indexing.
   *
   * @returns {string}  Empty string if no analysis has been run yet.
   */
  synthesizeArchDoc() {
    const a = this._lastAnalysis;
    if (!a) return '';

    const lines = [];
    lines.push('Architecture Layer Analysis \u2014 Enterprise Cloud Platform 2.0');
    lines.push(`Generated: ${a.summary.analysisTimestamp}`);
    lines.push('');

    lines.push('LAYER COMPLETENESS:');
    for (const [num, layer] of Object.entries(a.layers)) {
      const pct  = layer.completeness || 0;
      const mark = pct >= 100 ? 'PRESENT' : pct > 0 ? 'PARTIAL' : 'MISSING';
      lines.push(`Layer ${num} (${layer.name}): ${mark} \u2014 ${pct}% complete`);
      if (layer.presentModules.length > 0) lines.push(`  Present: ${layer.presentModules.join(', ')}`);
      if (layer.missingModules.length > 0) {
        lines.push(`  Missing: ${layer.missingModules.join(', ')}`);
        const techniques = this._layerToAttackTechniques(Number(num));
        if (techniques.length > 0) lines.push(`  Risk: Missing modules expose ${techniques.join(', ')}`);
      }
      lines.push(`  Files: ${layer.fileCount}`);
    }

    lines.push('');
    lines.push('FACTORY STATUS:');
    for (const [name, factory] of Object.entries(a.factories)) {
      const crdMark  = factory.crdDetected            ? 'CRD detected'   : 'CRD missing';
      const irsaMark = factory.iamRoleDetected         ? 'IRSA configured' : 'IRSA missing';
      const saMark   = factory.serviceAccountDetected  ? 'SA configured'  : 'SA missing';
      lines.push(`${name}: ${factory.status.toUpperCase()} \u2014 ${crdMark}, ${irsaMark}, ${saMark}`);
      for (const finding of factory.securityFindings) lines.push(`  ${finding}`);
    }

    lines.push('');
    lines.push('IAM MODULE STATUS:');
    for (const [name, mod] of Object.entries(a.iamModules)) {
      const xact = mod.crossAccount ? ' (cross-account)' : '';
      lines.push(`${name}: ${mod.status.toUpperCase()} (${mod.fileCount} files)${xact}`);
      if (mod.status === 'missing') {
        const def = IAM_MODULES[name];
        if (def) lines.push(`  Missing: ${def.purpose}`);
      }
    }

    lines.push('');
    lines.push(`SENTINEL POLICY COVERAGE: ${a.sentinelPolicies.coverage}%`);
    for (const [type, typeFiles] of Object.entries(a.sentinelPolicies.policyTypes)) {
      const mark = typeFiles.length > 0 ? 'PRESENT' : 'MISSING';
      lines.push(`  ${type}: ${mark} (${typeFiles.length} policies)`);
    }

    lines.push('');
    lines.push('SECURITY SCORES:');
    const s = a.security;
    lines.push(`SCP Inheritance: ${s.scpInheritance}% | Network Security: ${s.networkSecurity}% | IAM Governance: ${s.iamGovernance}%`);
    lines.push(`Data Protection: ${s.dataProtection}% | Sentinel Coverage: ${s.sentinelCoverage}% | Audit Logging: ${s.auditLogging}%`);
    lines.push(`Overall Security: ${s.overall}%`);
    if (s.criticalIssues.length > 0) {
      lines.push('Critical Security Issues:');
      for (const issue of s.criticalIssues) lines.push(`  - ${issue}`);
    }

    lines.push('');
    lines.push('COMPLIANCE:');
    const c = a.compliance;
    lines.push(`SOX: ${c.sox}% | PCI: ${c.pci}% | GDPR: ${c.gdpr}% | HIPAA: ${c.hipaa}%`);
    lines.push(`Overall Compliance: ${c.overall}%`);
    if (c.violations.length > 0) {
      lines.push('Compliance Violations:');
      for (const v of c.violations.slice(0, 10)) {
        lines.push(`  [${v.framework} ${v.id}] ${v.category}: ${v.desc}`);
      }
    }

    const critRecs = a.recommendations.filter(r => r.priority === 'CRITICAL');
    if (critRecs.length > 0) {
      lines.push('');
      lines.push('CRITICAL RECOMMENDATIONS:');
      critRecs.forEach((rec, i) => {
        lines.push(`${i + 1}. ${rec.title}`);
        lines.push(`   Impact: ${rec.impact}`);
        lines.push(`   Action: ${rec.action}`);
        if (rec.attackTechniques && rec.attackTechniques.length > 0) {
          lines.push(`   ATT&CK: ${rec.attackTechniques.join(', ')}`);
        }
      });
    }

    return lines.join('\n');
  }

  /**
   * Generate the full integrated TXT report including architecture, security, compliance,
   * and recommendations.  Optionally enriched with threat intelligence context.
   *
   * @param {object|null} threatContext  Optional: threat findings from ThreatModelIntelligence
   * @returns {string}
   */
  generateTXTReport(threatContext = null) {
    const a = this._lastAnalysis;
    if (!a) return 'No analysis available. Call analyzeArchitecture() first.';

    const BAR  = '='.repeat(60);
    const DASH = '\u2500'.repeat(45);
    const lines = [];

    lines.push('THREATAFORM \u2014 ENTERPRISE INFRASTRUCTURE INTELLIGENCE REPORT');
    lines.push(BAR);
    lines.push(`Analysis Date:     ${a.summary.analysisTimestamp}`);
    lines.push(`Platform Version:  ${a.summary.platformVersion}`);
    lines.push(`Total Files:       ${a.summary.totalFiles}`);
    lines.push(`Architecture Grade: ${a.architectureGrade}`);
    lines.push('');

    // ── Architecture Analysis ───────────────────────────────────────────────────
    lines.push('ARCHITECTURE ANALYSIS');
    lines.push(DASH);

    const layerScores     = Object.values(a.layers).map(l => l.completeness || 0);
    const avgScore        = layerScores.length > 0 ? Math.round(layerScores.reduce((s, v) => s + v, 0) / layerScores.length) : 0;
    const layersFound     = layerScores.filter(s => s > 0).length;
    lines.push(`Overall Architecture Grade: ${a.architectureGrade} (${avgScore}%)`);
    lines.push(`Layers Found: ${layersFound}/7`);
    lines.push('');

    for (const [num, layer] of Object.entries(a.layers)) {
      const pct   = layer.completeness || 0;
      const icon  = pct >= 100 ? '\u2705' : pct > 0 ? '\u26A0' : '\u274C';
      const label = pct >= 100 ? 'PRESENT' : pct > 0 ? 'PARTIAL' : 'MISSING';
      const pad   = (str, len) => str + ' '.repeat(Math.max(0, len - str.length));
      let line    = `Layer ${num} - ${pad(layer.name + ':', 35)} ${icon} ${pad(label, 8)} ${pad(pct + '%', 5)} \u2014 ${layer.fileCount} files`;
      if (layer.missingModules.length > 0) line += `   Missing: ${layer.missingModules.slice(0, 2).join(', ')}`;
      lines.push(line);
    }
    lines.push('');

    // ── Factory Status ──────────────────────────────────────────────────────────
    lines.push('FACTORY COMPONENT STATUS');
    lines.push(DASH);

    for (const [name, factory] of Object.entries(a.factories)) {
      const icon   = factory.status === 'present' ? '\u2705' : factory.status === 'partial' ? '\u26A0' : '\u274C';
      const crd    = factory.crdDetected           ? 'CRD:\u2713' : 'CRD:\u2717';
      const irsa   = factory.iamRoleDetected        ? 'IRSA:\u2713' : 'IRSA:\u2717';
      const status = factory.status === 'missing' ? 'MISSING  \u2190 CRITICAL RISK' : factory.status.toUpperCase();
      lines.push(`${icon} ${name}:`);
      lines.push(`    Status: ${status}   Files: ${factory.fileCount}   ${crd}   ${irsa}`);
    }
    lines.push('');

    // ── IAM Module Status ───────────────────────────────────────────────────────
    lines.push('IAM MODULE STATUS');
    lines.push(DASH);

    for (const [name, mod] of Object.entries(a.iamModules)) {
      const icon = mod.status === 'present' ? '\u2705' : '\u274C';
      const xact = mod.crossAccount ? ' [cross-account]' : '';
      lines.push(`${icon} ${name}: ${mod.status.toUpperCase()} (${mod.fileCount} files)${xact}`);
    }
    lines.push('');

    // ── Sentinel Coverage ───────────────────────────────────────────────────────
    lines.push('SENTINEL POLICY COVERAGE');
    lines.push(DASH);
    lines.push(`Total policies: ${a.sentinelPolicies.totalCount}   Coverage: ${a.sentinelPolicies.coverage}%`);
    for (const [type, typeFiles] of Object.entries(a.sentinelPolicies.policyTypes)) {
      const mark = typeFiles.length > 0 ? '\u2705' : '\u274C';
      lines.push(`  ${mark} ${type}: ${typeFiles.length} policy file(s)`);
    }
    lines.push('');

    // ── Security Posture ────────────────────────────────────────────────────────
    lines.push('SECURITY POSTURE');
    lines.push(DASH);

    if (threatContext && Array.isArray(threatContext.findings) && threatContext.findings.length > 0) {
      lines.push('Threat Intelligence Findings:');
      for (const finding of threatContext.findings.slice(0, 5)) lines.push(`  - ${finding}`);
      lines.push('');
    }

    const s = a.security;
    lines.push(`Overall Security Score: ${s.overall}%`);
    lines.push(`  SCP Inheritance:    ${s.scpInheritance}%`);
    lines.push(`  Network Security:   ${s.networkSecurity}%`);
    lines.push(`  IAM Governance:     ${s.iamGovernance}%`);
    lines.push(`  Data Protection:    ${s.dataProtection}%`);
    lines.push(`  Sentinel Coverage:  ${s.sentinelCoverage}%`);
    lines.push(`  Audit Logging:      ${s.auditLogging}%`);

    if (s.criticalIssues.length > 0) {
      lines.push('');
      lines.push('Critical Security Issues:');
      for (const issue of s.criticalIssues) lines.push(`  \u274C ${issue}`);
    }
    lines.push('');

    // ── Compliance Status ───────────────────────────────────────────────────────
    lines.push('COMPLIANCE STATUS');
    lines.push(DASH);
    const c = a.compliance;
    lines.push(`Overall: ${c.overall}%`);
    lines.push(`SOX: ${c.sox}%  |  PCI: ${c.pci}%  |  GDPR: ${c.gdpr}%  |  HIPAA: ${c.hipaa}%`);
    if (c.violations.length > 0) {
      lines.push('');
      lines.push(`Compliance Violations (${c.violations.length} critical):`);
      for (const v of c.violations.slice(0, 8)) {
        lines.push(`  [${v.framework} ${v.id}] ${v.category}: ${v.desc}`);
      }
    }
    lines.push('');

    // ── Recommendations ─────────────────────────────────────────────────────────
    lines.push('CRITICAL RECOMMENDATIONS');
    lines.push(DASH);

    const recs = a.recommendations;
    if (recs.length === 0) {
      lines.push('No critical recommendations \u2014 architecture is well-configured.');
    } else {
      recs.forEach((rec, i) => {
        lines.push(`${i + 1}. [${rec.priority}] ${rec.title}`);
        if (rec.affectedLayer) {
          const lDef = TERRAFORM_LAYERS[rec.affectedLayer];
          lines.push(`   Layer: ${rec.affectedLayer} \u2014 ${lDef ? lDef.name : ''}`);
        }
        lines.push(`   Impact: ${rec.impact}`);
        lines.push(`   Action: ${rec.action}`);
        if (rec.attackTechniques && rec.attackTechniques.length > 0) {
          const details = rec.attackTechniques
            .map(t => `${t} (${ATTACK_TECHNIQUES[t]?.name || t})`)
            .join(', ');
          lines.push(`   ATT&CK: ${details}`);
        }
        lines.push('');
      });
    }

    lines.push(BAR);
    lines.push('END OF REPORT');
    lines.push(BAR);

    return lines.join('\n');
  }
}

// ── Singleton convenience export ──────────────────────────────────────────────────────────────────
// Import `architectureAnalyzer` in components that need a shared instance across the app lifecycle.

export const architectureAnalyzer = new ArchitectureAnalyzer();

export default ArchitectureAnalyzer;
