// src/lib/intelligence/ThreatModelIntelligence.js
import { _STOP, _ENTITY_PATTERNS } from '../../data/entity-patterns.js';
import { ATTACK_TECHNIQUES, TF_ATTACK_MAP, CWE_DETAILS, STRIDE_PER_ELEMENT, getElementType as _getElementType } from '../../data/attack-data.js';
import { CONFIDENCE_BY_METHOD, mkEvidence, CONTROL_DETECTION_MAP, DID_LAYERS, ZT_PILLARS, NIST_CSF_CHECKS } from '../../data/control-detection.js';
import { KB } from '../../data/kb-domains.js';
import { parseHCLBody, inferArchitectureHierarchy } from '../iac/TerraformParser.js';
import { TF_MISCONFIG_CHECKS } from '../../data/misconfig-checks.js';

// ─────────────────────────────────────────────────────────────────────────────
// THREAT MODEL INTELLIGENCE ENGINE v2
// BM25 (Robertson IDF, k1=1.5 b=0.75) + TF-IDF Cosine + RRF Fusion
// Query expansion · Recursive chunking · Contextual compression · Confidence
// Built-in ATT&CK/CWE knowledge · STRIDE-per-element · Misconfig detection
// ─────────────────────────────────────────────────────────────────────────────

// ── Control alias dictionary for flexible doc-based control matching ─────────────────
const _CONTROL_ALIASES = {
  'WAF': ['web application firewall','waf','layer 7','application filter','app firewall'],
  'MFA': ['multi-factor','mfa','two-factor','2fa','multifactor','second factor'],
  'VPN': ['virtual private network','vpn','remote access','site-to-site'],
  'SIEM': ['siem','security information','event management','log aggregation','splunk','sentinel','qradar'],
  'IDS': ['intrusion detection','ids','ips','intrusion prevention','network detection'],
  'DLP': ['data loss prevention','dlp','data leakage','exfiltration prevention'],
  'PKI': ['public key infrastructure','pki','certificate authority','x.509','tls certificate'],
  'IAM': ['identity access management','iam','access control','rbac','role based','identity management'],
  'PAM': ['privileged access','pam','privileged identity','jump server','bastion','cyberark','beyond trust'],
  'SSO': ['single sign on','sso','federated identity','saml','oauth','oidc','identity provider'],
  'ENCRYPTION': ['encryption','encrypted','aes','kms','key management','encrypt at rest','tls','ssl'],
  'BACKUP': ['backup','recovery','rpo','rto','disaster recovery','business continuity','snapshot'],
  'PATCHING': ['patch','patching','vulnerability management','cve remediation','software update'],
  'FIREWALL': ['firewall','network acl','security group','packet filter','stateful inspection'],
  'SEGMENTATION': ['segmentation','network segmentation','microsegmentation','vlan','subnet isolation','zone'],
  'LOGGING': ['logging','audit log','cloudtrail','activity log','log retention','event log'],
  'MONITORING': ['monitoring','alerting','cloudwatch','azure monitor','observability','metrics'],
  'SCANNING': ['scanning','vulnerability scan','pen test','penetration test','sast','dast','code scan'],
  'SCP': ['service control policy','scp','organization policy','guardrail','permission boundary'],
  'ZERO_TRUST': ['zero trust','ztna','never trust','verify explicitly','least privilege access'],
  'INCIDENT_RESPONSE': ['incident response','ir plan','playbook','runbook','escalation','incident management'],
  'ACCESS_REVIEW': ['access review','recertification','entitlement review','quarterly review','user access review'],
  'SECRETS': ['secrets management','vault','hashicorp','aws secrets manager','key vault','credential rotation'],
  'DDOS': ['ddos','distributed denial','shield','cloudflare','denial of service','rate limiting'],
  'CDN': ['cdn','content delivery','cloudfront','edge','waf cdn'],
  'CONTAINER': ['container security','kubernetes','docker','pod security','image scanning','registry'],
  'API_SECURITY': ['api security','api gateway','oauth token','api key','rate limit','api firewall'],
  'NETWORK_FLOW': ['vpc flow','network flow','traffic analysis','packet capture','netflow'],
  'CONFIG_MGMT': ['configuration management','cmdb','asset inventory','configuration baseline','cis benchmark'],
  'CHANGE_MGMT': ['change management','change control','approval workflow','change advisory board','cab']
};

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
    // Prefer explicitly-set category from the upload UI (docCategory or category field)
    const explicit = doc.docCategory || doc.category;
    if (explicit && explicit !== 'general') return explicit;
    const s = ((doc.name||'') + ' ' + (doc.content||'').slice(0,500)).toLowerCase();
    if (/threat|stride|mitre|attack|risk|dread|pasta|threat.model/.test(s)) return 'threat-model';
    if (/architect|design|diagram|infra|topology|data.flow|dfd/.test(s)) return 'architecture';
    if (/security.control|scm|scb|control.baseline|800.53|nist.sp/.test(s)) return 'security-controls';
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
      if (role.isCFN) {
        (attrs.Policies||[]).forEach(p => {
          // _analyzeIAMDocument is defined inline in TerraformParser.js; replicate logic here
          const doc = p.PolicyDocument;
          if (!doc?.Statement) return;
          const stmts2 = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
          stmts2.forEach(stmt => {
            if (stmt.Effect !== 'Allow') return;
            const actions = (Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action]).filter(Boolean);
            const rsrcs   = (Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource]).filter(Boolean);
            if (actions.includes('*') && rsrcs.includes('*'))
              findings.push({
                id:'IAM-ADMIN', severity:'Critical', policyKind:'inline', resourceId:role.id,
                title:'Policy grants AdministratorAccess (Action:* Resource:*)',
                evidence: mkEvidence('policy_parse','Action:* Resource:*', role.id),
                remediation:'Replace wildcard with specific actions following least-privilege principle.',
                cwe:['CWE-269'], attack:['T1078.004'],
              });
            if (actions.some(a => a === 'iam:*' || /^iam:.*\*$/.test(a)))
              findings.push({
                id:'IAM-PRIV-ESC', severity:'Critical', policyKind:'inline', resourceId:role.id,
                title:'Policy allows IAM privilege escalation (iam:*)',
                evidence: mkEvidence('policy_parse','iam:* allows creating roles/policies with any permissions', role.id),
                remediation:'Restrict to specific IAM read actions; never grant iam:PassRole without conditions.',
                cwe:['CWE-269'], attack:['T1078.004','T1548'],
              });
          });
        });
      }
    });
    // Standalone IAM policy resources
    resources.filter(r => ['aws_iam_policy','aws_iam_role_policy','aws_iam_user_policy','AWS::IAM::ManagedPolicy'].includes(r.type)).forEach(pol => {
      const attrs = pol.isCFN ? (pol.cfnProps||{}) : (pol.attrs || parseHCLBody(pol.body||''));
      let doc = null;
      try {
        const raw = pol.isCFN ? attrs.PolicyDocument : (attrs.policy || '');
        doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
      } catch {}
      if (doc?.Statement) {
        const stmts = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
        stmts.forEach(stmt => {
          if (stmt.Effect !== 'Allow') return;
          const actions = (Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action]).filter(Boolean);
          const rsrcs   = (Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource]).filter(Boolean);
          if (actions.includes('*') && rsrcs.includes('*'))
            findings.push({
              id:'IAM-ADMIN', severity:'Critical', policyKind:'standalone', resourceId:pol.id,
              title:'Policy grants AdministratorAccess (Action:* Resource:*)',
              evidence: mkEvidence('policy_parse','Action:* Resource:*', pol.id),
              remediation:'Replace wildcard with specific actions following least-privilege principle.',
              cwe:['CWE-269'], attack:['T1078.004'],
            });
          if (actions.some(a => a === 'iam:*' || /^iam:.*\*$/.test(a)))
            findings.push({
              id:'IAM-PRIV-ESC', severity:'Critical', policyKind:'standalone', resourceId:pol.id,
              title:'Policy allows IAM privilege escalation (iam:*)',
              evidence: mkEvidence('policy_parse','iam:* allows creating roles/policies with any permissions', pol.id),
              remediation:'Restrict to specific IAM read actions; never grant iam:PassRole without conditions.',
              cwe:['CWE-269'], attack:['T1078.004','T1548'],
            });
          const broadSvc = actions.filter(a => /^\w+:\*$/.test(a) && a !== 'iam:*');
          if (broadSvc.length > 0 && rsrcs.includes('*'))
            findings.push({
              id:'IAM-SVC-WILD', severity:'High', policyKind:'standalone', resourceId:pol.id,
              title:`Policy uses broad service wildcard: ${broadSvc.slice(0,3).join(', ')}`,
              evidence: mkEvidence('policy_parse', broadSvc.join(', ') + ' on Resource:*', pol.id),
              remediation:'Scope actions to specific resource ARNs; avoid service-level wildcards on Resource:*.',
              cwe:['CWE-269'], attack:['T1078.004'],
            });
        });
      }
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
  _docHasControl(ctrlName, chunks) {
    const NEGATION = new Set(['not','no','broken','disabled','removed','absent','missing',
      'lacking','without','failed','violation','gap','deficiency','cannot','never']);
    const SEC_CATS = new Set(['security-controls','compliance-guide','cspm','trust-cloud','compliance']);
    const tokens = ctrlName.toLowerCase().split(/\W+/).filter(t => t.length > 3);
    if (!tokens.length) return { found: false, confidence: 0 };

    // Build alias list for this control name (if any key matches)
    const ctrlUpper = ctrlName.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    let aliases = [];
    for (const [key, vals] of Object.entries(_CONTROL_ALIASES)) {
      if (ctrlUpper.includes(key) || vals.some(v => ctrlName.toLowerCase().includes(v))) {
        aliases = aliases.concat(vals);
      }
    }

    // Formal control ID regex: AC-1, SC-28, IA-5(1), CIS-2.3, CTRL-001
    const CTRL_ID_RE = /\b[A-Z]{1,6}-\d{1,3}(?:[.(]\d{1,3}[)]?)?\b/g;

    let best = 0, bestEv = null, bestSrc = null;
    const searchChunks = chunks || this.chunks;
    for (const c of searchChunks.filter(x => x.category !== 'terraform')) {
      const lc = c.text.toLowerCase();
      const words = lc.split(/\W+/);
      const isSecCat = SEC_CATS.has(c.category);
      const threshold = isSecCat ? 0.20 : 0.60;

      const matchCount = tokens.filter(t => lc.includes(t)).length;
      let overlapRatio = tokens.length ? matchCount / tokens.length : 0;

      // Formal control ID bonus: if the chunk contains any control ID pattern, add 0.40 base
      let ctrlIdBonus = 0;
      if (isSecCat) {
        CTRL_ID_RE.lastIndex = 0;
        if (CTRL_ID_RE.test(c.text)) ctrlIdBonus = 0.40;
      }

      // Alias matching for security-controls category: if token overlap < threshold,
      // try matching aliases against chunk text
      let aliasBonus = 0;
      if (isSecCat && overlapRatio < threshold && aliases.length) {
        const aliasHits = aliases.filter(a => lc.includes(a)).length;
        if (aliasHits > 0) aliasBonus = Math.min(0.50, aliasHits * 0.20);
      }

      const effectiveRatio = overlapRatio + ctrlIdBonus + aliasBonus;
      if (effectiveRatio < threshold) continue;

      // Apply negation penalty: -0.25 per negation word found within 5-token window
      let penalty = 0;
      for (const t of tokens) {
        const idx = words.indexOf(t);
        if (idx >= 0) {
          const win = words.slice(Math.max(0, idx - 5), idx + 6);
          if (win.some(w => NEGATION.has(w))) penalty += 0.25;
        }
      }
      const score = Math.max(0, effectiveRatio - penalty) * 100;
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
  build(userDocs, resources, modules, archAnalysis = null) {
    this.chunks=[]; this._tf=[]; this._tfidf=[]; this._docLens=[];
    this._idf={}; this._vocab=new Set(); this._built=false;
    this.indexDocuments(userDocs);
    this.indexResources(resources, modules);
    this._buildIndex();
    this._built=true;
    if (archAnalysis && archAnalysis.layers) {
      const archDoc = this._synthesizeArchDoc(archAnalysis);
      if (archDoc) {
        const synChunks = this._chunkText(archDoc, 'arch-layer-analysis', 'arch-analysis');
        synChunks.forEach(c => { this.chunks.push(c); });
        this._buildIndex(); // rebuild index with arch doc included
      }
    }
    return this;
  }

  // ── Chunk helper for synthesized docs (used by build + archAnalysis path) ────
  _chunkText(text, source, category) {
    return this._splitText(text).map((chunk, ci) => {
      const id = this.chunks.length + ci;
      const trimmed = chunk.trim();
      const entities = this._extractEntities(trimmed);
      const tokens = this._tokenize(trimmed);
      const tfMap = {};
      tokens.forEach(t => { tfMap[t] = (tfMap[t]||0)+1; this._vocab.add(t); });
      this._tf.push(tfMap);
      this._docLens.push(tokens.length);
      return { id, source, text: trimmed, entities, category, docId: source, chunkIdx: ci };
    });
  }

  // ── Synthesize an indexable text document from archAnalysis object ────────────
  _synthesizeArchDoc(archAnalysis) {
    if (!archAnalysis || !archAnalysis.layers) return null;
    const lines = [
      'Architecture Layer Analysis — Enterprise Cloud Platform 2.0',
      `Analysis Date: ${new Date().toISOString()}`,
      '',
      'LAYER COMPLETENESS:',
    ];
    Object.entries(archAnalysis.layers).forEach(([num, layer]) => {
      const icon = layer.completeness >= 90 ? 'PRESENT' : layer.completeness > 0 ? 'PARTIAL' : 'MISSING';
      lines.push(`Layer ${num} (${layer.name}): ${icon} — ${layer.completeness}% complete`);
      if (layer.presentModules?.length) lines.push(`  Present: ${layer.presentModules.join(', ')}`);
      if (layer.missingModules?.length) lines.push(`  Missing: ${layer.missingModules.join(', ')}`);
      if (layer.fileCount) lines.push(`  Files: ${layer.fileCount}`);
    });
    lines.push('', 'FACTORY STATUS:');
    if (archAnalysis.factories) {
      Object.entries(archAnalysis.factories).forEach(([name, factory]) => {
        lines.push(`${name}: ${factory.status?.toUpperCase()} — ${factory.fileCount || 0} files`);
        if (factory.securityFindings?.length) {
          factory.securityFindings.forEach(f => lines.push(`  Risk: ${f}`));
        }
      });
    }
    if (archAnalysis.sentinelPolicies) {
      lines.push('', 'SENTINEL POLICY COVERAGE:');
      lines.push(`Total policies: ${archAnalysis.sentinelPolicies.totalCount}`);
      const types = archAnalysis.sentinelPolicies.policyTypes || {};
      Object.entries(types).forEach(([t, count]) => lines.push(`  ${t}: ${count > 0 ? 'PRESENT' : 'MISSING'} (${count})`));
    }
    if (archAnalysis.security) {
      lines.push('', 'SECURITY SCORES:');
      const s = archAnalysis.security;
      lines.push(`SCP Inheritance: ${s.scpInheritance||0}% | Network: ${s.networkSecurity||0}% | IAM: ${s.iamGovernance||0}%`);
      lines.push(`Data Protection: ${s.dataProtection||0}% | Sentinel: ${s.sentinelCoverage||0}% | Audit: ${s.auditLogging||0}%`);
      lines.push(`Overall Security: ${s.overall||0}%`);
      if (s.criticalIssues?.length) {
        lines.push('', 'CRITICAL SECURITY ISSUES:');
        s.criticalIssues.forEach(i => lines.push(`  - ${i}`));
      }
    }
    if (archAnalysis.compliance) {
      lines.push('', 'COMPLIANCE:');
      const c = archAnalysis.compliance;
      lines.push(`SOX: ${c.sox||0}% | PCI: ${c.pci||0}% | GDPR: ${c.gdpr||0}% | HIPAA: ${c.hipaa||0}%`);
      if (c.violations?.length) {
        lines.push('', 'COMPLIANCE VIOLATIONS:');
        c.violations.slice(0, 10).forEach(v => lines.push(`  - ${v}`));
      }
    }
    if (archAnalysis.recommendations?.length) {
      lines.push('', 'ARCHITECTURE RECOMMENDATIONS:');
      archAnalysis.recommendations.slice(0, 10).forEach((r, i) => {
        lines.push(`${i+1}. [${r.priority||'MEDIUM'}] ${r.title||r.description||''}`);
        if (r.action) lines.push(`   Action: ${r.action}`);
        if (r.attackTechniques?.length) lines.push(`   ATT&CK: ${r.attackTechniques.join(', ')}`);
      });
    }
    return lines.join('\n');
  }

  // ── Architecture gap query convenience method ─────────────────────────────────
  getArchitectureGaps(topK = 5) {
    // Returns top-k chunks specifically about architecture gaps
    return this.query('architecture layer missing factory incomplete governance', topK)
      .filter(c => c.source === 'arch-layer-analysis' ||
                   c.text.toLowerCase().includes('missing') ||
                   c.text.toLowerCase().includes('layer'));
  }

  // ── Legacy: keep _addChunk's old index object intact for any callers ─────────
  // (not needed in v2 but guards against stale refs)
  get index() { return this._idf; }

  // ── Alias: getSummary → getArchitectureSummary (guards against stale call sites) ─
  getSummary(resources, userDocs) { return this.getArchitectureSummary(resources, userDocs); }
}

export { ThreatModelIntelligence };
export default ThreatModelIntelligence;
