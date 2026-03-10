// src/data/attack-data.js
// MITRE ATT&CK Cloud technique definitions, Terraform resource → technique mappings,
// CWE weakness definitions, STRIDE applicability per DFD element type, and the
// helper function that maps a resource type to its DFD element category.

// ── MITRE ATT&CK Cloud Techniques ────────────────────────────────────────────
export const ATTACK_TECHNIQUES = {
  'T1078.004':{ name:'Valid Cloud Accounts',            tactic:'Initial Access/Persistence',  severity:'Critical', desc:'Adversaries obtain and abuse credentials of existing cloud accounts to gain access.' },
  'T1530':    { name:'Data from Cloud Storage',         tactic:'Collection',                  severity:'High',     desc:'Adversaries access data from improperly secured cloud storage objects.' },
  'T1537':    { name:'Transfer Data to Cloud Account',  tactic:'Exfiltration',                severity:'High',     desc:'Adversaries exfiltrate data to a different cloud account they control.' },
  'T1098.001':{ name:'Additional Cloud Credentials',    tactic:'Persistence',                 severity:'High',     desc:'Adversaries add adversary-controlled credentials to maintain persistent access.' },
  'T1098.003':{ name:'Additional Cloud Roles',          tactic:'Persistence',                 severity:'High',     desc:'Adversaries attach IAM roles with elevated permissions to cloud services.' },
  'T1580':    { name:'Cloud Infrastructure Discovery',  tactic:'Discovery',                   severity:'Medium',   desc:'Adversaries enumerate cloud infrastructure, services, and configurations.' },
  'T1562.008':{ name:'Disable Cloud Logs',              tactic:'Defense Evasion',             severity:'High',     desc:'Adversaries disable CloudTrail or other logging to evade detection.' },
  'T1552.005':{ name:'Cloud Instance Metadata API',    tactic:'Credential Access',           severity:'High',     desc:'Adversaries query the Instance Metadata Service (IMDS) for credentials.' },
  'T1648':    { name:'Serverless Execution',            tactic:'Execution',                   severity:'Medium',   desc:'Adversaries abuse serverless functions to execute malicious code or commands.' },
  'T1059.009':{ name:'Cloud API',                       tactic:'Execution',                   severity:'Medium',   desc:'Adversaries abuse cloud management APIs to execute commands or access resources.' },
  'T1190':    { name:'Exploit Public-Facing App',       tactic:'Initial Access',              severity:'Critical', desc:'Adversaries exploit vulnerabilities in internet-facing applications or services.' },
  'T1485':    { name:'Data Destruction',                tactic:'Impact',                      severity:'Critical', desc:'Adversaries destroy data and files to interrupt availability of systems.' },
  'T1490':    { name:'Inhibit System Recovery',         tactic:'Impact',                      severity:'High',     desc:'Adversaries delete backups and snapshots to prevent recovery operations.' },
  'T1496':    { name:'Resource Hijacking',              tactic:'Impact',                      severity:'Medium',   desc:'Adversaries leverage compromised systems for cryptomining or other compute abuse.' },
  'T1548':    { name:'Abuse Elevation Control',         tactic:'Privilege Escalation',        severity:'High',     desc:'Adversaries abuse elevated control mechanisms such as IAM policies to gain higher privileges.' },
  'T1555.006':{ name:'Cloud Secrets Management',        tactic:'Credential Access',           severity:'High',     desc:'Adversaries query cloud secrets stores (Secrets Manager, SSM) for credentials.' },
  'T1600':    { name:'Weaken Encryption',               tactic:'Defense Evasion',             severity:'High',     desc:'Adversaries compromise or disable KMS keys to weaken cryptographic protections.' },
  'T1613':    { name:'Container and Resource Discovery',tactic:'Discovery',                   severity:'Medium',   desc:'Adversaries enumerate containers, pods, and cluster resources for lateral movement.' },
  'T1046':    { name:'Network Service Discovery',       tactic:'Discovery',                   severity:'Low',      desc:'Adversaries scan network services to identify attack surface.' },
  'T1133':    { name:'External Remote Services',        tactic:'Initial Access/Persistence',  severity:'High',     desc:'Adversaries leverage VPNs, RDP, or other external remote services for persistent access.' },
};

// ── Terraform / CloudFormation resource type → ATT&CK technique IDs ──────────
export const TF_ATTACK_MAP = {
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
  // ── CloudFormation resource types ──────────────────────────────────────────
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

// ── CWE Weakness Definitions ──────────────────────────────────────────────────
export const CWE_DETAILS = {
  'CWE-284': { name:'Improper Access Control',                    desc:'The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.' },
  'CWE-285': { name:'Improper Authorization',                     desc:'Failure to verify that an actor is authorized to access a resource or perform an action.' },
  'CWE-311': { name:'Missing Encryption of Sensitive Data',       desc:'The software does not encrypt sensitive data, exposing it to unauthorized actors.' },
  'CWE-312': { name:'Cleartext Storage of Sensitive Information', desc:'Sensitive information is stored in plaintext accessible to unauthorized parties.' },
  'CWE-326': { name:'Inadequate Encryption Strength',             desc:'The software stores or transmits data using encryption that is considered too weak.' },
  'CWE-732': { name:'Incorrect Permission Assignment',            desc:'Permissions allow unauthorized actors to access critical resources.' },
  'CWE-778': { name:'Insufficient Logging',                       desc:'The software does not log security-relevant events, impeding detection of attacks.' },
  'CWE-256': { name:'Plaintext Storage of Password',              desc:'Storing passwords in plaintext may result in system compromise if storage is breached.' },
  'CWE-250': { name:'Execution with Unnecessary Privileges',      desc:'The software performs operations using excessively high-privilege accounts or credentials.' },
  'CWE-319': { name:'Cleartext Transmission',                     desc:'Sensitive information is transmitted in plaintext over an unencrypted network channel.' },
  'CWE-306': { name:'Missing Authentication for Critical Function',desc:'The software does not perform any authentication for functionality that requires identity.' },
  'CWE-798': { name:'Use of Hard-coded Credentials',              desc:'Hard-coded credentials used for authentication to external systems or as inbound auth.' },
  'CWE-400': { name:'Uncontrolled Resource Consumption',          desc:'Improper resource control allows an attacker to cause denial of service.' },
  'CWE-269': { name:'Improper Privilege Management',              desc:'The software does not properly assign, modify, track, or check privileges.' },
  'CWE-1104':{ name:'Use of Unmaintained Third-Party Component',  desc:'The product relies on a third-party component that is no longer actively maintained.' },
};

// ── STRIDE applicability by DFD element type ──────────────────────────────────
export const STRIDE_PER_ELEMENT = {
  external_entity: ['spoofing','repudiation'],
  process:         ['spoofing','tampering','repudiation','infoDisclose','dos','elevPriv'],
  data_store:      ['tampering','repudiation','infoDisclose','dos'],
  data_flow:       ['spoofing','tampering','infoDisclose','dos'],
};

/**
 * Map a Terraform/CloudFormation resource type to its DFD element category.
 * Used by STRIDE-per-element analysis.
 */
export function getElementType(resourceType) {
  const rt = resourceType || '';
  if (/s3|rds|dynamodb|elasticache|opensearch|elasticsearch|ebs|efs|ssm_parameter|secrets|AWS::S3::|AWS::RDS::|AWS::DynamoDB::|AWS::ElastiCache::/.test(rt)) return 'data_store';
  if (/security_group|nacl|waf|shield|firewall|acl|route53|nat_gateway|internet_gateway|AWS::EC2::SecurityGroup|AWS::WAF/.test(rt)) return 'data_flow';
  if (/iam_role|iam_user|iam_policy|organizations|cognito|AWS::IAM::|AWS::Organizations::/.test(rt)) return 'external_entity';
  return 'process';
}
