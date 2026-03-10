import sys
filepath = "C:/Users/mjrma/Downloads/threataform/src/lib/intelligence/ThreatModelIntelligence.js"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()
print("Loaded", len(content), "chars")
errors = []
NL = chr(10)

# C1: _CONTROL_ALIASES const
CLASS_MARKER = "class ThreatModelIntelligence {"
if "_CONTROL_ALIASES" in content: print("C1-aliases: already applied")
elif CLASS_MARKER not in content: errors.append("ERROR: class marker not found")
else:
    alias_lines = [
        "// ── Control alias dictionary for flexible doc-based control matching ─────────────────",
        "const _CONTROL_ALIASES = {",
        "  'WAF': ['web application firewall','waf','layer 7','application filter','app firewall'],",
        "  'MFA': ['multi-factor','mfa','two-factor','2fa','multifactor','second factor'],",
        "  'VPN': ['virtual private network','vpn','remote access','site-to-site'],",
        "  'SIEM': ['siem','security information','event management','log aggregation','splunk','sentinel','qradar'],",
        "  'IDS': ['intrusion detection','ids','ips','intrusion prevention','network detection'],",
        "  'DLP': ['data loss prevention','dlp','data leakage','exfiltration prevention'],",
        "  'PKI': ['public key infrastructure','pki','certificate authority','x.509','tls certificate'],",
        "  'IAM': ['identity access management','iam','access control','rbac','role based','identity management'],",
        "  'PAM': ['privileged access','pam','privileged identity','jump server','bastion','cyberark','beyond trust'],",
        "  'SSO': ['single sign on','sso','federated identity','saml','oauth','oidc','identity provider'],",
        "  'ENCRYPTION': ['encryption','encrypted','aes','kms','key management','encrypt at rest','tls','ssl'],",
        "  'BACKUP': ['backup','recovery','rpo','rto','disaster recovery','business continuity','snapshot'],",
        "  'PATCHING': ['patch','patching','vulnerability management','cve remediation','software update'],",
        "  'FIREWALL': ['firewall','network acl','security group','packet filter','stateful inspection'],",
        "  'SEGMENTATION': ['segmentation','network segmentation','microsegmentation','vlan','subnet isolation','zone'],",
        "  'LOGGING': ['logging','audit log','cloudtrail','activity log','log retention','event log'],",
        "  'MONITORING': ['monitoring','alerting','cloudwatch','azure monitor','observability','metrics'],",
        "  'SCANNING': ['scanning','vulnerability scan','pen test','penetration test','sast','dast','code scan'],",
        "  'SCP': ['service control policy','scp','organization policy','guardrail','permission boundary'],",
        "  'ZERO_TRUST': ['zero trust','ztna','never trust','verify explicitly','least privilege access'],",
        "  'INCIDENT_RESPONSE': ['incident response','ir plan','playbook','runbook','escalation','incident management'],",
        "  'ACCESS_REVIEW': ['access review','recertification','entitlement review','quarterly review','user access review'],",
        "  'SECRETS': ['secrets management','vault','hashicorp','aws secrets manager','key vault','credential rotation'],",
        "  'DDOS': ['ddos','distributed denial','shield','cloudflare','denial of service','rate limiting'],",
        "  'CDN': ['cdn','content delivery','cloudfront','edge','waf cdn'],",
        "  'CONTAINER': ['container security','kubernetes','docker','pod security','image scanning','registry'],",
        "  'API_SECURITY': ['api security','api gateway','oauth token','api key','rate limit','api firewall'],",
        "  'NETWORK_FLOW': ['vpc flow','network flow','traffic analysis','packet capture','netflow'],",
        "  'CONFIG_MGMT': ['configuration management','cmdb','asset inventory','configuration baseline','cis benchmark'],",
        "  'CHANGE_MGMT': ['change management','change control','approval workflow','change advisory board','cab']",
        "};",
        "",
    ]
    insert_text = NL.join(alias_lines) + NL + CLASS_MARKER
    content = content.replace(CLASS_MARKER, insert_text, 1)
    print("C1-aliases: applied")

# C1: Replace _docHasControl method
meth_start = content.find("  _docHasControl(ctrlName) {")
meth_after = content.find("  // ── Defense-in-Depth", meth_start if meth_start >= 0 else 0)
if "_docHasControl(ctrlName, chunks)" in content: print("C1-method: already applied")
elif meth_start == -1 or meth_after == -1: errors.append("ERROR: _docHasControl bounds not found s=" + str(meth_start) + " a=" + str(meth_after))
else:
    m = [
        "  _docHasControl(ctrlName, chunks) {",
        "    const NEGATION = new Set(['not','no','broken','disabled','removed','absent','missing',",
        "      'lacking','without','failed','violation','gap','deficiency','cannot','never']);",
        "    const SEC_CATS = new Set(['security-controls','compliance-guide','cspm','trust-cloud','compliance']);",
        "    const tokens = ctrlName.toLowerCase().split(/\W+/).filter(t => t.length > 3);",
        "    if (!tokens.length) return { found: false, confidence: 0 };",
        "",
        "    // Build alias list for this control name (if any key matches)",
        "    const ctrlUpper = ctrlName.toUpperCase().replace(/[^A-Z0-9_]/g, '_');",
        "    let aliases = [];",
        "    for (const [key, vals] of Object.entries(_CONTROL_ALIASES)) {",
        "      if (ctrlUpper.includes(key) || vals.some(v => ctrlName.toLowerCase().includes(v))) {",
        "        aliases = aliases.concat(vals);",
        "      }",
        "    }",
        "",
        "    // Formal control ID regex: AC-1, SC-28, IA-5(1), CIS-2.3, CTRL-001",
        "    const CTRL_ID_RE = /[A-Z]{1,6}-\d{1,3}(?:[.(]\d{1,3}[)]?)?/g;",
        "",
        "    let best = 0, bestEv = null, bestSrc = null;",
        "    const searchChunks = chunks || this.chunks;",
        "    for (const c of searchChunks.filter(x => x.category !== 'terraform')) {",
        "      const lc = c.text.toLowerCase();",
        "      const words = lc.split(/\W+/);",
        "      const isSecCat = SEC_CATS.has(c.category);",
        "      const threshold = isSecCat ? 0.20 : 0.60;",
        "",
        "      const matchCount = tokens.filter(t => lc.includes(t)).length;",
        "      let overlapRatio = tokens.length ? matchCount / tokens.length : 0;",
        "",
        "      // Formal control ID bonus: if the chunk contains any control ID pattern, add 0.40 base",
        "      let ctrlIdBonus = 0;",
        "      if (isSecCat) {",
        "        CTRL_ID_RE.lastIndex = 0;",
        "        if (CTRL_ID_RE.test(c.text)) ctrlIdBonus = 0.40;",
        "      }",
        "",
        "      // Alias matching for security-controls category: if token overlap < threshold,",
        "      // try matching aliases against chunk text",
        "      let aliasBonus = 0;",
        "      if (isSecCat && overlapRatio < threshold && aliases.length) {",
        "        const aliasHits = aliases.filter(a => lc.includes(a)).length;",
        "        if (aliasHits > 0) aliasBonus = Math.min(0.50, aliasHits * 0.20);",
        "      }",
        "",
        "      const effectiveRatio = overlapRatio + ctrlIdBonus + aliasBonus;",
        "      if (effectiveRatio < threshold) continue;",
        "",
        "      // Apply negation penalty: -0.25 per negation word found within 5-token window",
        "      let penalty = 0;",
        "      for (const t of tokens) {",
        "        const idx = words.indexOf(t);",
        "        if (idx >= 0) {",
        "          const win = words.slice(Math.max(0, idx - 5), idx + 6);",
        "          if (win.some(w => NEGATION.has(w))) penalty += 0.25;",
        "        }",
        "      }",
        "      const score = Math.max(0, effectiveRatio - penalty) * 100;",
        "      if (score > best) {",
        "        best = Math.round(score);",
        "        bestEv = c.text.slice(0, 130);",
        "        bestSrc = c.source || c.category || 'doc';",
        "      }",
        "    }",
        "    return best >= 30",
        "      ? { found: true, confidence: best, evidence: bestEv, source: bestSrc }",
        "      : { found: false, confidence: 0 };",
        "  }",
        "",
    ]
    new_method = NL.join(m)
    content = content[:meth_start] + new_method + NL + content[meth_after:]
    print("C1-method: applied")

# C2: Fix _categorizeDoc - use line-based search
cat_start = content.find("  _categorizeDoc(doc) {")
if cat_start == -1:
    errors.append("ERROR: _categorizeDoc not found")
elif "doc.docCategory" in content:
    print("C2-categorizeDoc: already applied")
else:
    # Find end of _categorizeDoc method (closing brace)
    # It ends at "  }" after cat_start, followed by empty line then "  // ── Add a single chunk"
    cat_end = content.find("  // ── Add a single chunk", cat_start)
    if cat_end == -1: errors.append("ERROR: _categorizeDoc end not found")
    else:
        old_block = content[cat_start:cat_end]
        # Build new block by injecting the explicit check and security-controls line
        new_lines = [
            "  _categorizeDoc(doc) {",
            "    // Prefer explicitly-set category from the upload UI (docCategory or category field)",
            "    const explicit = doc.docCategory || doc.category;",
            "    if (explicit && explicit \!== 'general') return explicit;",
            "    const s = ((doc.name||'') + ' ' + (doc.content||'').slice(0,500)).toLowerCase();",
            "    if (/threat|stride|mitre|attack|risk|dread|pasta|threat.model/.test(s)) return 'threat-model';",
            "    if (/architect|design|diagram|infra|topology|data.flow|dfd/.test(s)) return 'architecture';",
            "    if (/security.control|scm|scb|control.baseline|800.53|nist.sp/.test(s)) return 'security-controls';",
            "    if (/policy|compliance|hipaa|fedramp|soc2|pci|gdpr|cmmc|iso.?27001/.test(s)) return 'compliance';",
            "    if (/runbook|playbook|incident|procedure|response|sop/.test(s)) return 'runbook';",
            "",
        ]
        tf_line = "    if (/" + chr(92) + ".tf" + chr(36) + "|terraform|provider|resource|module/.test(s)) return " + chr(39) + "terraform" + chr(39) + ";"
        new_lines.append(tf_line)
        new_lines.append("    return " + chr(39) + "general" + chr(39) + ";")
        new_lines.append("  }")
        new_block = NL.join(new_lines)
        content = content.replace(old_block, new_block, 1)
        print("C2-categorizeDoc: applied")

# Write result
if errors:
    for e in errors: print(e)
else:
    with open(filepath, "w", encoding="utf-8") as f: f.write(content)
    print("ThreatModelIntelligence.js written OK, size:", len(content))
