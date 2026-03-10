// src/data/entity-patterns.js
// NLP entity extraction patterns: STRIDE, MITRE ATT&CK, compliance frameworks,
// AWS services, security controls, and architecture scope declarations.
// Used by ThreatModelIntelligence and the BM25 search index.

export const _STOP = new Set([
  "the","a","an","is","are","was","were","be","been","being","have","has","had",
  "do","does","did","will","would","could","should","may","might","must","shall",
  "and","or","but","if","in","on","at","to","for","of","with","by","from","as",
  "this","that","these","those","it","its","we","they","he","she","you","i",
  "not","no","so","then","than","when","where","how","what","which","who","all",
  "also","can","use","used","using","each","other","more","such","well","via",
  "get","set","any","its","our","your","their","been","has","had","one","two",
]);

export const _ENTITY_PATTERNS = {
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
