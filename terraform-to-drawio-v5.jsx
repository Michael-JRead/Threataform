import { useState, useCallback, useRef } from "react";

// ═══════════════════════════════════════════════════════════════════════════
//  TERRAFORM → DRAW.IO / LUCIDCHART v5
//  ─────────────────────────────────────────────────────────────────────────
//  RESEARCH BASIS:
//
//  AWS Well-Architected Framework (6 Pillars):
//  Operational Excellence · Security · Reliability · Performance Efficiency
//  Cost Optimization · Sustainability
//
//  AWS Official Diagram Conventions (aws.amazon.com/architecture/icons):
//  • Official AWS4 icon set — resourceIcon + resIcon naming convention
//  • Hierarchy: AWS Cloud > Region > VPC > AZ > Subnet > Resource
//  • Grouping containers identify boundary with small icon, upper-left corner
//  • Internet/User sits OUTSIDE all AWS boundaries (true external actor)
//  • Global Edge (CloudFront, Route53, Shield, WAF@edge) sits at AWS edge,
//    outside regional VPC, but inside AWS Cloud boundary
//  • Public DMZ Subnet: ALB, NAT Gateway, Bastion (internet-facing, public IP)
//  • Private App Subnet: ECS, Lambda, EC2, EKS (no direct internet route)
//  • Isolated Data Subnet: RDS, ElastiCache, DynamoDB (no internet, no app
//    direct route — must go through VPC endpoints or security groups only)
//  • Cross-cutting concerns: IAM/Security, Observability span ALL tiers
//  • AWS color coding: Compute=orange, Storage=green, Database=blue,
//    Networking=purple, Security=red, Analytics=purple
//
//  Canonical AWS Data Flow (per re:Invent sessions & AWS whitepapers):
//  User → Internet → DNS/Route53 → CloudFront CDN → WAF → Shield →
//  ALB/API Gateway (DMZ) → Compute (Lambda/ECS/EC2) →
//  [Storage|Database|Cache] → [Async Messaging] → [Observability side-channel]
//  CI/CD pipeline: Source → Build → Sentinel Policy Gate → Deploy → Monitor
//
//  AWS Service Color Families (official grouping colors):
//  #FF9900 = Compute (EC2, Lambda, ECS, EKS, Batch, Fargate)
//  #3F8624 = Storage (S3, EBS, EFS, FSx, Glacier, Backup)
//  #1A9C3E = Database (RDS, DynamoDB, ElastiCache, Aurora, Redshift)
//  #8C4FFF = Networking & Content Delivery (VPC, CloudFront, Route53, ELB)
//  #DD344C = Security (IAM, KMS, Cognito, WAF, GuardDuty, Secrets)
//  #E7157B = Application Integration (SQS, SNS, EventBridge, SES)
//  #01A88D = Management & Governance (CloudWatch, CloudTrail, Config, SSM)
//  #7AA116 = Developer Tools (CodePipeline, CodeBuild, CodeDeploy)
//
//  Terraform / HCL Ecosystem (HashiCorp Developer Docs):
//  • Resources: declarative infrastructure definitions with type + name
//  • Data sources: read existing infrastructure, prefix "data."
//  • Modules: reusable component groups, reference as module.NAME.OUTPUT
//  • Meta-arguments: depends_on (explicit dep), count (N copies),
//    for_each (map/set iteration), lifecycle (create_before_destroy,
//    prevent_destroy, ignore_changes), provider (multi-account/region)
//  • Implicit dependency: detected from attribute reference expressions
//    e.g. vpc_id = aws_vpc.main.id → EC2 depends on VPC
//  • Explicit dependency: depends_on = [aws_iam_role_policy.example]
//    used when dep is behavioral (not attribute-level), e.g. IAM policy
//    must exist before instance can assume role via app bootstrap
//
//  Sentinel Policy-as-Code (HashiCorp):
//  • Runs BETWEEN terraform plan and terraform apply in HCP Terraform/TFE
//  • 3 enforcement levels:
//    - advisory: always continues, logs warning (default level in spec)
//    - soft-mandatory: blocks unless override by authorized user (logged)
//    - hard-mandatory: blocks unconditionally, must fix or remove policy
//  • Policy sets: named collections applied to workspaces/org globally
//  • sentinel.hcl: defines policy blocks with source + enforcement_level
//  • Can import: tfplan (plan data), tfstate (current state),
//    tfconfig (config), tfrun (run metadata), HTTP endpoints
//  • Pre-written CIS Benchmark policies available in Terraform Registry
//  • OPA (Open Policy Agent) is alternative framework also supported
//  • Sentinel evaluates AFTER run tasks + cost estimation, BEFORE apply
//
//  Diagram Best Practices Applied Here:
//  • LTR = canonical data flow direction (matches reading direction)
//  • AWS boundary containers: Account > Region > VPC grouping boxes
//  • Availability Zone sub-grouping where subnets are implied
//  • Color-coded swimlanes aligned to AWS service category colors
//  • 9 semantically distinct edge types (expanded from 8)
//  • 3-case edge routing (forward LTR / backward / same-tier vertical)
//  • Resource validation: detects anti-patterns and Well-Architected issues
//  • Sentinel pipeline nodes with enforcement-level badges (color-coded)
//  • depends_on = [...] explicit edges rendered as CONFIG type
//  • for_each / count parsed → resource name annotated with [*] or [N]
//  • Terraform module blocks parsed → rendered as composite node
//  • Data sources parsed → rendered as read-only (dashed border)
//  • Architecture quality score shown in stats panel
// ═══════════════════════════════════════════════════════════════════════════

// ── Tier definitions ─────────────────────────────────────────────────────
// Ordered by AWS canonical data flow (LTR = request path left to right)
// Group field maps to AWS boundary container coloring conventions
const TIERS = [
  { id:"internet",      label:"Internet / Users",      group:"external", bg:"#F5F5F5", border:"#9E9E9E", hdr:"#616161", hint:"External — outside AWS" },
  { id:"dns",           label:"DNS & Certificates",    group:"global",   bg:"#EDE7F6", border:"#6A1B9A", hdr:"#4A148C", hint:"Global AWS · Route53 · ACM" },
  { id:"edge",          label:"Edge & CDN",            group:"global",   bg:"#E0F7FA", border:"#00838F", hdr:"#006064", hint:"Global AWS Edge Network" },
  { id:"public",        label:"Public Subnet (DMZ)",   group:"vpc",      bg:"#E8F5E9", border:"#388E3C", hdr:"#1B5E20", hint:"Public subnet · internet-facing" },
  { id:"network",       label:"Network Fabric",        group:"vpc",      bg:"#F3E5F5", border:"#7B1FA2", hdr:"#4A148C", hint:"VPC · Subnets · Routing · SGs" },
  { id:"compute",       label:"App Tier (Private)",    group:"vpc",      bg:"#FFF8E1", border:"#F9A825", hdr:"#E65100", hint:"Private subnet · compute" },
  { id:"storage",       label:"Object & File Storage", group:"region",   bg:"#E8F5E0", border:"#33691E", hdr:"#1B5E20", hint:"S3 · EFS · EBS · regional" },
  { id:"database",      label:"Data Tier (Isolated)",  group:"vpc",      bg:"#E3F2FD", border:"#1565C0", hdr:"#0D47A1", hint:"Isolated subnet · RDS · cache" },
  { id:"analytics",     label:"Analytics & ML",        group:"region",   bg:"#FFF3E0", border:"#E65100", hdr:"#BF360C", hint:"Glue · Athena · SageMaker" },
  { id:"messaging",     label:"Async Messaging",       group:"region",   bg:"#FCE4EC", border:"#C2185B", hdr:"#880E4F", hint:"SQS · SNS · EventBridge · Kinesis" },
  { id:"security",      label:"Security & IAM",        group:"cross",    bg:"#FFEBEE", border:"#D32F2F", hdr:"#B71C1C", hint:"Cross-cutting · IAM · KMS · Cognito" },
  { id:"cicd",          label:"CI/CD & IaC",           group:"cross",    bg:"#EDE7F6", border:"#6A1B9A", hdr:"#4527A0", hint:"CodePipeline · TF Cloud · Sentinel" },
  { id:"observability", label:"Observability",         group:"cross",    bg:"#E0F2F1", border:"#00695C", hdr:"#004D40", hint:"CloudWatch · X-Ray · horizontal" },
];
const TIER_MAP = Object.fromEntries(TIERS.map(t => [t.id, t]));

// Group metadata (AWS boundary containers)
const GROUP_META = {
  external: { label:"Internet / External",   color:"#9E9E9E", bg:"#FAFAFA", dashed:true  },
  global:   { label:"AWS Global Edge",        color:"#006064", bg:"#E0F7FA", dashed:false },
  vpc:      { label:"AWS VPC",                color:"#1B5E20", bg:"#F1F8E9", dashed:false },
  region:   { label:"AWS Region",             color:"#1565C0", bg:"#E3F2FD", dashed:false },
  cross:    { label:"Cross-Cutting Concerns", color:"#4A148C", bg:"#F3E5F5", dashed:true  },
};

// ── Data flow edge types ──────────────────────────────────────────────────
// Colors and semantics per AWS architecture diagram conventions
const FLOW = {
  REQUEST:  { color:"#1565C0", dash:null,    width:2.5, label:"HTTPS / API Request",    symbol:"→",  desc:"User/service HTTP request flows" },
  DATA:     { color:"#2E7D32", dash:null,    width:2.5, label:"Data Read / Write",      symbol:"⇒",  desc:"Persistence layer I/O" },
  EVENT:    { color:"#E65100", dash:"8 4",   width:2,   label:"Event / Async Trigger",  symbol:"⤳",  desc:"Async messaging between services" },
  CONFIG:   { color:"#6A1B9A", dash:"5 3",   width:2,   label:"Config / Dependency",    symbol:"⊸",  desc:"Explicit Terraform depends_on or config" },
  NETWORK:  { color:"#37474F", dash:null,    width:2,   label:"Network / VPC Link",     symbol:"─",  desc:"VPC-level connectivity" },
  LOG:      { color:"#00695C", dash:"6 3",   width:1.5, label:"Logs / Metrics",         symbol:"↗",  desc:"Observability telemetry flows" },
  IAM:      { color:"#B71C1C", dash:"4 2",   width:2,   label:"IAM / Auth",             symbol:"⊛",  desc:"Identity & access management" },
  DEPLOY:   { color:"#4527A0", dash:"3 3",   width:1.5, label:"Deploy / Provision",     symbol:"⬇",  desc:"CI/CD deploy or IaC provisioning" },
  SENTINEL: { color:"#B71C1C", dash:"2 2 8 2",width:2.5,label:"Sentinel Policy Gate",   symbol:"🛡",  desc:"Policy evaluation between plan/apply" },
};

// ── Flow inference ────────────────────────────────────────────────────────
function inferFlow(fromType, toType) {
  const s = (fromType + " " + toType).toLowerCase();
  if (/sentinel/.test(s))                                                     return "SENTINEL";
  if (/iam|kms|secret|cognito|waf|acm|cert|permission|profile|trust/.test(s)) return "IAM";
  if (/cloudwatch|log_group|log_stream|metric|alarm|dashboard|xray|trail/.test(s)) return "LOG";
  if (/sqs|sns|kinesis|firehose|mq_broker|event_rule|event_target|event_bus|ses|pinpoint/.test(s)) return "EVENT";
  if (/vpc$|subnet|nat_gateway|internet_gateway|security_group|route_table|network_acl|vpn|eip|peering|transit|flow_log|dx_connection|endpoint/.test(s)) return "NETWORK";
  if (/s3_bucket|ebs_volume|efs_file|fsx|glacier|backup/.test(s))             return "DATA";
  if (/db_instance|rds_cluster|dynamodb|elasticache|redshift|aurora|neptune|docdb|timestream|opensearch/.test(s)) return "DATA";
  if (/codepipeline|codebuild|codecommit|codedeploy|beanstalk|cloudformation|ecr/.test(s)) return "DEPLOY";
  if (/ssm_parameter|ssm_document|config_rule|config_recorder|policy/.test(s)) return "CONFIG";
  if (/glue|athena|emr|sagemaker|comprehend|rekognition|forecast|personalize/.test(s)) return "DATA";
  return "REQUEST";
}

// ── Sentinel enforcement level badge colors ───────────────────────────────
const SENTINEL_COLORS = {
  "hard-mandatory":  { fill:"#B71C1C", text:"#FFFFFF", label:"HARD" },
  "soft-mandatory":  { fill:"#E65100", text:"#FFFFFF", label:"SOFT" },
  "advisory":        { fill:"#1565C0", text:"#FFFFFF", label:"ADV"  },
};

// ═══════════════════════════════════════════════════════════════════════════
//  AWS RESOURCE MAPPING — 150+ resource types
//  Ordered by tier, then data flow sequence within tier.
//  Labels = AWS Console names (not Terraform names).
//  Icons = mxgraph.aws4.resourceIcon + resIcon (draw.io + Lucidchart compat)
//  tier "data_source" flag = true for data block resources (dashed border)
// ═══════════════════════════════════════════════════════════════════════════
const RES = {
  // ── Internet/External (conceptual actors) ─────────────────────────────
  // (no standard aws_ prefix — added manually when detected as actor)

  // ── DNS & Certificates ────────────────────────────────────────────────
  aws_route53_zone:                       { label:"Route 53 Zone",          tier:"dns",         icon:"mxgraph.aws4.route_53" },
  aws_route53_record:                     { label:"DNS Record",             tier:"dns",         icon:"mxgraph.aws4.route_53" },
  aws_route53_resolver_rule:              { label:"Resolver Rule",          tier:"dns",         icon:"mxgraph.aws4.route_53_resolver" },
  aws_route53_resolver_endpoint:          { label:"Resolver Endpoint",      tier:"dns",         icon:"mxgraph.aws4.route_53_resolver" },
  aws_route53_health_check:               { label:"Health Check",           tier:"dns",         icon:"mxgraph.aws4.route_53" },
  aws_route53_hosted_zone_dnssec:         { label:"DNSSEC",                 tier:"dns",         icon:"mxgraph.aws4.route_53" },
  aws_acm_certificate:                    { label:"ACM Certificate",        tier:"dns",         icon:"mxgraph.aws4.certificate_manager" },
  aws_acm_certificate_validation:         { label:"Cert Validation",        tier:"dns",         icon:"mxgraph.aws4.certificate_manager" },
  aws_acm_private_ca:                     { label:"Private CA",             tier:"dns",         icon:"mxgraph.aws4.certificate_manager" },

  // ── Edge & CDN ────────────────────────────────────────────────────────
  aws_cloudfront_distribution:            { label:"CloudFront",             tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_cloudfront_cache_policy:            { label:"CF Cache Policy",        tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_cloudfront_origin_access_identity:  { label:"CF OAI",                 tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_cloudfront_origin_access_control:   { label:"CF OAC",                 tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_cloudfront_function:                { label:"CF Function",            tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_cloudfront_realtime_log_config:     { label:"CF RT Log",              tier:"edge",        icon:"mxgraph.aws4.cloudfront" },
  aws_wafv2_web_acl:                      { label:"WAF Web ACL",            tier:"edge",        icon:"mxgraph.aws4.waf" },
  aws_wafv2_web_acl_association:          { label:"WAF Association",        tier:"edge",        icon:"mxgraph.aws4.waf" },
  aws_wafv2_rule_group:                   { label:"WAF Rule Group",         tier:"edge",        icon:"mxgraph.aws4.waf" },
  aws_wafv2_ip_set:                       { label:"WAF IP Set",             tier:"edge",        icon:"mxgraph.aws4.waf" },
  aws_shield_protection:                  { label:"AWS Shield",             tier:"edge",        icon:"mxgraph.aws4.shield" },
  aws_shield_protection_group:            { label:"Shield Group",           tier:"edge",        icon:"mxgraph.aws4.shield" },
  aws_globalaccelerator_accelerator:      { label:"Global Accelerator",     tier:"edge",        icon:"mxgraph.aws4.global_accelerator" },
  aws_globalaccelerator_endpoint_group:   { label:"Accelerator Endpoint",   tier:"edge",        icon:"mxgraph.aws4.global_accelerator" },

  // ── Public Subnet / DMZ ───────────────────────────────────────────────
  // ALB, API GW, NAT GW live in public subnets per AWS Well-Architected
  aws_lb:                                 { label:"Load Balancer",          tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_alb:                                { label:"App Load Balancer",      tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_elb:                                { label:"Classic ELB",            tier:"public",      icon:"mxgraph.aws4.elb" },
  aws_lb_listener:                        { label:"LB Listener",            tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_lb_listener_rule:                   { label:"Listener Rule",          tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_lb_target_group:                    { label:"Target Group",           tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_lb_target_group_attachment:         { label:"TG Attachment",          tier:"public",      icon:"mxgraph.aws4.application_load_balancer" },
  aws_api_gateway_rest_api:               { label:"API Gateway",            tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_resource:               { label:"API Resource",           tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_method:                 { label:"API Method",             tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_integration:            { label:"API Integration",        tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_stage:                  { label:"API Stage",              tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_domain_name:            { label:"API Domain",             tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_base_path_mapping:      { label:"API Mapping",            tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_authorizer:             { label:"API Authorizer",         tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_usage_plan:             { label:"API Usage Plan",         tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_api_gateway_api_key:                { label:"API Key",                tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_api:                   { label:"HTTP API (v2)",          tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_stage:                 { label:"API Stage v2",           tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_integration:           { label:"API Integration v2",     tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_route:                 { label:"API Route",              tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_domain_name:           { label:"API Domain v2",          tier:"public",      icon:"mxgraph.aws4.api_gateway" },
  aws_apigatewayv2_authorizer:            { label:"API Authorizer v2",      tier:"public",      icon:"mxgraph.aws4.api_gateway" },

  // ── Network Fabric ────────────────────────────────────────────────────
  aws_vpc:                                { label:"VPC",                    tier:"network",     icon:"mxgraph.aws4.vpc" },
  aws_vpc_endpoint:                       { label:"VPC Endpoint",           tier:"network",     icon:"mxgraph.aws4.vpc_endpoints" },
  aws_vpc_endpoint_service:               { label:"Endpoint Service",       tier:"network",     icon:"mxgraph.aws4.vpc_endpoints" },
  aws_vpc_peering_connection:             { label:"VPC Peering",            tier:"network",     icon:"mxgraph.aws4.vpc_peering" },
  aws_vpc_ipv4_cidr_block_association:    { label:"VPC CIDR",               tier:"network",     icon:"mxgraph.aws4.vpc" },
  aws_subnet:                             { label:"Subnet",                 tier:"network",     icon:"mxgraph.aws4.subnet" },
  aws_internet_gateway:                   { label:"Internet Gateway",       tier:"network",     icon:"mxgraph.aws4.internet_gateway" },
  aws_nat_gateway:                        { label:"NAT Gateway",            tier:"network",     icon:"mxgraph.aws4.nat_gateway" },
  aws_eip:                                { label:"Elastic IP",             tier:"network",     icon:"mxgraph.aws4.elastic_ip_address" },
  aws_route_table:                        { label:"Route Table",            tier:"network",     icon:"mxgraph.aws4.route_table" },
  aws_route_table_association:            { label:"RT Association",         tier:"network",     icon:"mxgraph.aws4.route_table" },
  aws_route:                              { label:"Route",                  tier:"network",     icon:"mxgraph.aws4.route_table" },
  aws_security_group:                     { label:"Security Group",         tier:"network",     icon:"mxgraph.aws4.security_group" },
  aws_security_group_rule:                { label:"SG Rule",                tier:"network",     icon:"mxgraph.aws4.security_group" },
  aws_vpc_security_group_ingress_rule:    { label:"SG Ingress",             tier:"network",     icon:"mxgraph.aws4.security_group" },
  aws_vpc_security_group_egress_rule:     { label:"SG Egress",              tier:"network",     icon:"mxgraph.aws4.security_group" },
  aws_network_acl:                        { label:"Network ACL",            tier:"network",     icon:"mxgraph.aws4.network_access_control_list" },
  aws_network_acl_rule:                   { label:"NACL Rule",              tier:"network",     icon:"mxgraph.aws4.network_access_control_list" },
  aws_vpn_gateway:                        { label:"VPN Gateway",            tier:"network",     icon:"mxgraph.aws4.vpn_gateway" },
  aws_customer_gateway:                   { label:"Customer Gateway",       tier:"network",     icon:"mxgraph.aws4.customer_gateway" },
  aws_vpn_connection:                     { label:"VPN Connection",         tier:"network",     icon:"mxgraph.aws4.site_to_site_vpn" },
  aws_transit_gateway:                    { label:"Transit Gateway",        tier:"network",     icon:"mxgraph.aws4.transit_gateway" },
  aws_transit_gateway_attachment:         { label:"TGW Attachment",         tier:"network",     icon:"mxgraph.aws4.transit_gateway" },
  aws_transit_gateway_route_table:        { label:"TGW Route Table",        tier:"network",     icon:"mxgraph.aws4.transit_gateway" },
  aws_dx_connection:                      { label:"Direct Connect",         tier:"network",     icon:"mxgraph.aws4.direct_connect" },
  aws_dx_gateway:                         { label:"DX Gateway",             tier:"network",     icon:"mxgraph.aws4.direct_connect" },
  aws_dx_virtual_interface:               { label:"DX VIF",                 tier:"network",     icon:"mxgraph.aws4.direct_connect" },
  aws_flow_log:                           { label:"VPC Flow Log",           tier:"network",     icon:"mxgraph.aws4.vpc_flow_logs" },
  aws_network_interface:                  { label:"Network Interface",      tier:"network",     icon:"mxgraph.aws4.network_interface" },
  aws_elastic_ip_association:             { label:"EIP Association",        tier:"network",     icon:"mxgraph.aws4.elastic_ip_address" },

  // ── Compute (Private App Tier) ────────────────────────────────────────
  aws_instance:                           { label:"EC2 Instance",           tier:"compute",     icon:"mxgraph.aws4.ec2" },
  aws_launch_template:                    { label:"Launch Template",        tier:"compute",     icon:"mxgraph.aws4.ec2" },
  aws_launch_configuration:               { label:"Launch Config",          tier:"compute",     icon:"mxgraph.aws4.ec2" },
  aws_autoscaling_group:                  { label:"Auto Scaling Group",     tier:"compute",     icon:"mxgraph.aws4.auto_scaling" },
  aws_autoscaling_policy:                 { label:"Scaling Policy",         tier:"compute",     icon:"mxgraph.aws4.auto_scaling" },
  aws_autoscaling_schedule:               { label:"Scaling Schedule",       tier:"compute",     icon:"mxgraph.aws4.auto_scaling" },
  aws_lambda_function:                    { label:"Lambda Function",        tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_lambda_permission:                  { label:"Lambda Permission",      tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_lambda_event_source_mapping:        { label:"Event Source Map",       tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_lambda_function_url:                { label:"Lambda URL",             tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_lambda_layer_version:               { label:"Lambda Layer",           tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_lambda_alias:                       { label:"Lambda Alias",           tier:"compute",     icon:"mxgraph.aws4.lambda" },
  aws_ecs_cluster:                        { label:"ECS Cluster",            tier:"compute",     icon:"mxgraph.aws4.ecs" },
  aws_ecs_service:                        { label:"ECS Service",            tier:"compute",     icon:"mxgraph.aws4.ecs_service" },
  aws_ecs_task_definition:                { label:"Task Definition",        tier:"compute",     icon:"mxgraph.aws4.ecs" },
  aws_ecs_capacity_provider:              { label:"ECS Capacity",           tier:"compute",     icon:"mxgraph.aws4.ecs" },
  aws_eks_cluster:                        { label:"EKS Cluster",            tier:"compute",     icon:"mxgraph.aws4.eks" },
  aws_eks_node_group:                     { label:"EKS Node Group",         tier:"compute",     icon:"mxgraph.aws4.eks" },
  aws_eks_fargate_profile:                { label:"EKS Fargate",            tier:"compute",     icon:"mxgraph.aws4.eks" },
  aws_eks_addon:                          { label:"EKS Add-on",             tier:"compute",     icon:"mxgraph.aws4.eks" },
  aws_ecr_repository:                     { label:"ECR Registry",           tier:"compute",     icon:"mxgraph.aws4.ecr" },
  aws_ecr_lifecycle_policy:               { label:"ECR Lifecycle",          tier:"compute",     icon:"mxgraph.aws4.ecr" },
  aws_ecr_repository_policy:              { label:"ECR Policy",             tier:"compute",     icon:"mxgraph.aws4.ecr" },
  aws_batch_job_definition:               { label:"Batch Job Def",          tier:"compute",     icon:"mxgraph.aws4.batch" },
  aws_batch_job_queue:                    { label:"Batch Job Queue",        tier:"compute",     icon:"mxgraph.aws4.batch" },
  aws_batch_compute_environment:          { label:"Batch Compute",          tier:"compute",     icon:"mxgraph.aws4.batch" },
  aws_elastic_beanstalk_environment:      { label:"Elastic Beanstalk",      tier:"compute",     icon:"mxgraph.aws4.elastic_beanstalk" },
  aws_apprunner_service:                  { label:"App Runner",             tier:"compute",     icon:"mxgraph.aws4.app_runner" },
  aws_lightsail_instance:                 { label:"Lightsail",              tier:"compute",     icon:"mxgraph.aws4.lightsail" },
  aws_app_mesh_mesh:                      { label:"App Mesh",               tier:"compute",     icon:"mxgraph.aws4.app_mesh" },
  aws_app_mesh_virtual_service:           { label:"App Mesh Svc",           tier:"compute",     icon:"mxgraph.aws4.app_mesh" },
  aws_fargate_profile:                    { label:"Fargate Profile",        tier:"compute",     icon:"mxgraph.aws4.fargate" },

  // ── Object & File Storage ─────────────────────────────────────────────
  aws_s3_bucket:                          { label:"S3 Bucket",              tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_policy:                   { label:"S3 Policy",              tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_notification:             { label:"S3 Notification",        tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_cors_configuration:       { label:"S3 CORS",                tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_lifecycle_configuration:  { label:"S3 Lifecycle",           tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_replication_configuration:{ label:"S3 Replication",         tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_server_side_encryption_configuration:{ label:"S3 SSE",      tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_bucket_versioning:               { label:"S3 Versioning",          tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_s3_object:                          { label:"S3 Object",              tier:"storage",     icon:"mxgraph.aws4.s3" },
  aws_ebs_volume:                         { label:"EBS Volume",             tier:"storage",     icon:"mxgraph.aws4.ebs" },
  aws_volume_attachment:                  { label:"EBS Attach",             tier:"storage",     icon:"mxgraph.aws4.ebs" },
  aws_ebs_snapshot:                       { label:"EBS Snapshot",           tier:"storage",     icon:"mxgraph.aws4.ebs" },
  aws_efs_file_system:                    { label:"EFS File System",        tier:"storage",     icon:"mxgraph.aws4.efs" },
  aws_efs_mount_target:                   { label:"EFS Mount Target",       tier:"storage",     icon:"mxgraph.aws4.efs" },
  aws_efs_access_point:                   { label:"EFS Access Point",       tier:"storage",     icon:"mxgraph.aws4.efs" },
  aws_fsx_lustre_file_system:             { label:"FSx Lustre",             tier:"storage",     icon:"mxgraph.aws4.fsx_for_lustre" },
  aws_fsx_windows_file_system:            { label:"FSx Windows",            tier:"storage",     icon:"mxgraph.aws4.fsx_for_windows_file_server" },
  aws_fsx_openzfs_file_system:            { label:"FSx OpenZFS",            tier:"storage",     icon:"mxgraph.aws4.fsx_for_openzfs" },
  aws_fsx_ontap_file_system:              { label:"FSx NetApp ONTAP",       tier:"storage",     icon:"mxgraph.aws4.fsx_for_netapp_ontap" },
  aws_backup_vault:                       { label:"Backup Vault",           tier:"storage",     icon:"mxgraph.aws4.aws_backup" },
  aws_backup_plan:                        { label:"Backup Plan",            tier:"storage",     icon:"mxgraph.aws4.aws_backup" },
  aws_backup_selection:                   { label:"Backup Selection",       tier:"storage",     icon:"mxgraph.aws4.aws_backup" },
  aws_glacier_vault:                      { label:"Glacier Vault",          tier:"storage",     icon:"mxgraph.aws4.s3_glacier" },
  aws_s3_glacier_vault:                   { label:"Glacier Vault",          tier:"storage",     icon:"mxgraph.aws4.s3_glacier" },
  aws_storagegateway_gateway:             { label:"Storage Gateway",        tier:"storage",     icon:"mxgraph.aws4.storage_gateway" },

  // ── Data / Database (Isolated Tier) ──────────────────────────────────
  aws_db_instance:                        { label:"RDS Instance",           tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_db_subnet_group:                    { label:"DB Subnet Group",        tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_db_parameter_group:                 { label:"DB Param Group",         tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_db_option_group:                    { label:"DB Option Group",        tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_db_snapshot:                        { label:"DB Snapshot",            tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_db_event_subscription:              { label:"DB Event Sub",           tier:"database",    icon:"mxgraph.aws4.rds" },
  aws_rds_cluster:                        { label:"Aurora Cluster",         tier:"database",    icon:"mxgraph.aws4.aurora" },
  aws_rds_cluster_instance:               { label:"Aurora Instance",        tier:"database",    icon:"mxgraph.aws4.aurora" },
  aws_rds_cluster_parameter_group:        { label:"Aurora Param Group",     tier:"database",    icon:"mxgraph.aws4.aurora" },
  aws_rds_proxy:                          { label:"RDS Proxy",              tier:"database",    icon:"mxgraph.aws4.rds_proxy" },
  aws_dynamodb_table:                     { label:"DynamoDB Table",         tier:"database",    icon:"mxgraph.aws4.dynamodb" },
  aws_dynamodb_global_table:              { label:"DDB Global Table",       tier:"database",    icon:"mxgraph.aws4.dynamodb" },
  aws_dynamodb_table_item:                { label:"DDB Item",               tier:"database",    icon:"mxgraph.aws4.dynamodb" },
  aws_dynamodb_index:                     { label:"DDB Index",              tier:"database",    icon:"mxgraph.aws4.dynamodb" },
  aws_elasticache_cluster:                { label:"ElastiCache",            tier:"database",    icon:"mxgraph.aws4.elasticache" },
  aws_elasticache_replication_group:      { label:"ElastiCache RG",         tier:"database",    icon:"mxgraph.aws4.elasticache" },
  aws_elasticache_subnet_group:           { label:"EC Subnet Group",        tier:"database",    icon:"mxgraph.aws4.elasticache" },
  aws_elasticache_parameter_group:        { label:"EC Param Group",         tier:"database",    icon:"mxgraph.aws4.elasticache" },
  aws_redshift_cluster:                   { label:"Redshift Cluster",       tier:"database",    icon:"mxgraph.aws4.redshift" },
  aws_redshift_subnet_group:              { label:"Redshift Subnet GRP",    tier:"database",    icon:"mxgraph.aws4.redshift" },
  aws_redshift_serverless_workgroup:      { label:"Redshift Serverless",    tier:"database",    icon:"mxgraph.aws4.redshift" },
  aws_opensearch_domain:                  { label:"OpenSearch",             tier:"database",    icon:"mxgraph.aws4.opensearch_service" },
  aws_opensearch_serverless_collection:   { label:"OpenSearch Serverless",  tier:"database",    icon:"mxgraph.aws4.opensearch_service" },
  aws_neptune_cluster:                    { label:"Neptune",                tier:"database",    icon:"mxgraph.aws4.neptune" },
  aws_neptune_cluster_instance:           { label:"Neptune Instance",       tier:"database",    icon:"mxgraph.aws4.neptune" },
  aws_docdb_cluster:                      { label:"DocumentDB",             tier:"database",    icon:"mxgraph.aws4.documentdb" },
  aws_docdb_cluster_instance:             { label:"DocumentDB Instance",    tier:"database",    icon:"mxgraph.aws4.documentdb" },
  aws_timestream_database:                { label:"Timestream",             tier:"database",    icon:"mxgraph.aws4.timestream" },
  aws_timestream_table:                   { label:"Timestream Table",       tier:"database",    icon:"mxgraph.aws4.timestream" },

  // ── Analytics & ML ────────────────────────────────────────────────────
  aws_athena_workgroup:                   { label:"Athena",                 tier:"analytics",   icon:"mxgraph.aws4.athena" },
  aws_athena_database:                    { label:"Athena DB",              tier:"analytics",   icon:"mxgraph.aws4.athena" },
  aws_glue_catalog_database:              { label:"Glue Catalog",           tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_glue_job:                           { label:"Glue Job",               tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_glue_crawler:                       { label:"Glue Crawler",           tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_glue_catalog_table:                 { label:"Glue Table",             tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_glue_trigger:                       { label:"Glue Trigger",           tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_glue_workflow:                      { label:"Glue Workflow",          tier:"analytics",   icon:"mxgraph.aws4.glue" },
  aws_emr_cluster:                        { label:"EMR Cluster",            tier:"analytics",   icon:"mxgraph.aws4.emr" },
  aws_emr_serverless_application:         { label:"EMR Serverless",         tier:"analytics",   icon:"mxgraph.aws4.emr" },
  aws_sagemaker_endpoint:                 { label:"SageMaker Endpoint",     tier:"analytics",   icon:"mxgraph.aws4.sagemaker" },
  aws_sagemaker_notebook_instance:        { label:"SageMaker Notebook",     tier:"analytics",   icon:"mxgraph.aws4.sagemaker" },
  aws_sagemaker_model:                    { label:"SageMaker Model",        tier:"analytics",   icon:"mxgraph.aws4.sagemaker" },
  aws_sagemaker_training_job:             { label:"SageMaker Training",     tier:"analytics",   icon:"mxgraph.aws4.sagemaker" },
  aws_lakeformation_resource:             { label:"Lake Formation",         tier:"analytics",   icon:"mxgraph.aws4.lake_formation" },
  aws_lakeformation_permissions:          { label:"LF Permissions",         tier:"analytics",   icon:"mxgraph.aws4.lake_formation" },
  aws_quicksight_data_set:                { label:"QuickSight Dataset",     tier:"analytics",   icon:"mxgraph.aws4.quicksight" },
  aws_quicksight_analysis:                { label:"QuickSight Analysis",    tier:"analytics",   icon:"mxgraph.aws4.quicksight" },

  // ── Async Messaging ───────────────────────────────────────────────────
  aws_sqs_queue:                          { label:"SQS Queue",              tier:"messaging",   icon:"mxgraph.aws4.sqs" },
  aws_sqs_queue_policy:                   { label:"SQS Policy",             tier:"messaging",   icon:"mxgraph.aws4.sqs" },
  aws_sns_topic:                          { label:"SNS Topic",              tier:"messaging",   icon:"mxgraph.aws4.sns" },
  aws_sns_topic_subscription:             { label:"SNS Subscription",       tier:"messaging",   icon:"mxgraph.aws4.sns" },
  aws_sns_topic_policy:                   { label:"SNS Policy",             tier:"messaging",   icon:"mxgraph.aws4.sns" },
  aws_kinesis_stream:                     { label:"Kinesis Stream",         tier:"messaging",   icon:"mxgraph.aws4.kinesis" },
  aws_kinesis_firehose_delivery_stream:   { label:"Kinesis Firehose",       tier:"messaging",   icon:"mxgraph.aws4.kinesis_firehose" },
  aws_kinesis_analytics_application:      { label:"Kinesis Analytics",      tier:"messaging",   icon:"mxgraph.aws4.kinesis_data_analytics" },
  aws_kinesis_video_stream:               { label:"Kinesis Video",          tier:"messaging",   icon:"mxgraph.aws4.kinesis_video_streams" },
  aws_mq_broker:                          { label:"Amazon MQ Broker",       tier:"messaging",   icon:"mxgraph.aws4.mq" },
  aws_mq_configuration:                   { label:"MQ Config",              tier:"messaging",   icon:"mxgraph.aws4.mq" },
  aws_cloudwatch_event_rule:              { label:"EventBridge Rule",       tier:"messaging",   icon:"mxgraph.aws4.eventbridge" },
  aws_cloudwatch_event_target:            { label:"EventBridge Target",     tier:"messaging",   icon:"mxgraph.aws4.eventbridge" },
  aws_cloudwatch_event_bus:               { label:"Event Bus",              tier:"messaging",   icon:"mxgraph.aws4.eventbridge" },
  aws_cloudwatch_event_connection:        { label:"EventBridge Connect",    tier:"messaging",   icon:"mxgraph.aws4.eventbridge" },
  aws_ses_email_identity:                 { label:"SES Identity",           tier:"messaging",   icon:"mxgraph.aws4.ses" },
  aws_ses_configuration_set:              { label:"SES Config Set",         tier:"messaging",   icon:"mxgraph.aws4.ses" },
  aws_ses_domain_identity:                { label:"SES Domain",             tier:"messaging",   icon:"mxgraph.aws4.ses" },
  aws_pinpoint_app:                       { label:"Pinpoint",               tier:"messaging",   icon:"mxgraph.aws4.pinpoint" },
  aws_iot_topic_rule:                     { label:"IoT Rule",               tier:"messaging",   icon:"mxgraph.aws4.iot_rule" },
  aws_iot_thing:                          { label:"IoT Thing",              tier:"messaging",   icon:"mxgraph.aws4.iot_thing" },
  aws_step_functions_state_machine:       { label:"Step Functions",         tier:"messaging",   icon:"mxgraph.aws4.step_functions" },
  aws_sfn_state_machine:                  { label:"Step Functions",         tier:"messaging",   icon:"mxgraph.aws4.step_functions" },
  aws_pipes_pipe:                         { label:"EventBridge Pipes",      tier:"messaging",   icon:"mxgraph.aws4.eventbridge" },

  // ── Security & IAM ────────────────────────────────────────────────────
  aws_iam_role:                           { label:"IAM Role",               tier:"security",    icon:"mxgraph.aws4.role" },
  aws_iam_policy:                         { label:"IAM Policy",             tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_role_policy:                    { label:"Inline Policy",          tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_role_policy_attachment:         { label:"Policy Attachment",      tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_user:                           { label:"IAM User",               tier:"security",    icon:"mxgraph.aws4.user" },
  aws_iam_user_policy:                    { label:"User Policy",            tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_user_policy_attachment:         { label:"User Policy Attach",     tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_group:                          { label:"IAM Group",              tier:"security",    icon:"mxgraph.aws4.group" },
  aws_iam_group_membership:               { label:"Group Membership",       tier:"security",    icon:"mxgraph.aws4.group" },
  aws_iam_group_policy:                   { label:"Group Policy",           tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_instance_profile:               { label:"Instance Profile",       tier:"security",    icon:"mxgraph.aws4.role" },
  aws_iam_openid_connect_provider:        { label:"OIDC Provider",          tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_saml_provider:                  { label:"SAML Provider",          tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_iam_access_key:                     { label:"IAM Access Key",         tier:"security",    icon:"mxgraph.aws4.permissions" },
  aws_kms_key:                            { label:"KMS Key",                tier:"security",    icon:"mxgraph.aws4.kms" },
  aws_kms_alias:                          { label:"KMS Alias",              tier:"security",    icon:"mxgraph.aws4.kms" },
  aws_kms_key_policy:                     { label:"KMS Key Policy",         tier:"security",    icon:"mxgraph.aws4.kms" },
  aws_kms_grant:                          { label:"KMS Grant",              tier:"security",    icon:"mxgraph.aws4.kms" },
  aws_secretsmanager_secret:              { label:"Secrets Manager",        tier:"security",    icon:"mxgraph.aws4.secrets_manager" },
  aws_secretsmanager_secret_version:      { label:"Secret Version",         tier:"security",    icon:"mxgraph.aws4.secrets_manager" },
  aws_secretsmanager_secret_rotation:     { label:"Secret Rotation",        tier:"security",    icon:"mxgraph.aws4.secrets_manager" },
  aws_cognito_user_pool:                  { label:"Cognito User Pool",      tier:"security",    icon:"mxgraph.aws4.cognito" },
  aws_cognito_user_pool_client:           { label:"Cognito App Client",     tier:"security",    icon:"mxgraph.aws4.cognito" },
  aws_cognito_identity_pool:              { label:"Cognito Identity",       tier:"security",    icon:"mxgraph.aws4.cognito" },
  aws_cognito_user_pool_domain:           { label:"Cognito Domain",         tier:"security",    icon:"mxgraph.aws4.cognito" },
  aws_ssm_parameter:                      { label:"SSM Parameter",          tier:"security",    icon:"mxgraph.aws4.systems_manager_parameter_store" },
  aws_ssm_document:                       { label:"SSM Document",           tier:"security",    icon:"mxgraph.aws4.systems_manager" },
  aws_ssm_maintenance_window:             { label:"SSM Maint Window",       tier:"security",    icon:"mxgraph.aws4.systems_manager" },
  aws_ssm_patch_baseline:                 { label:"SSM Patch Baseline",     tier:"security",    icon:"mxgraph.aws4.systems_manager" },
  aws_config_rule:                        { label:"Config Rule",            tier:"security",    icon:"mxgraph.aws4.config" },
  aws_config_configuration_recorder:     { label:"Config Recorder",        tier:"security",    icon:"mxgraph.aws4.config" },
  aws_config_conformance_pack:            { label:"Conformance Pack",       tier:"security",    icon:"mxgraph.aws4.config" },
  aws_guardduty_detector:                 { label:"GuardDuty",              tier:"security",    icon:"mxgraph.aws4.guardduty" },
  aws_guardduty_filter:                   { label:"GuardDuty Filter",       tier:"security",    icon:"mxgraph.aws4.guardduty" },
  aws_inspector_assessment_template:      { label:"Inspector",              tier:"security",    icon:"mxgraph.aws4.inspector" },
  aws_inspector2_enabler:                 { label:"Inspector v2",           tier:"security",    icon:"mxgraph.aws4.inspector" },
  aws_macie2_account:                     { label:"Macie",                  tier:"security",    icon:"mxgraph.aws4.macie" },
  aws_security_hub_account:               { label:"Security Hub",           tier:"security",    icon:"mxgraph.aws4.security_hub" },
  aws_cloudtrail:                         { label:"CloudTrail",             tier:"security",    icon:"mxgraph.aws4.cloudtrail" },
  aws_organizations_organization:         { label:"AWS Organization",       tier:"security",    icon:"mxgraph.aws4.organizations" },
  aws_organizations_policy:               { label:"Org SCP",                tier:"security",    icon:"mxgraph.aws4.organizations" },
  aws_sso_permission_set:                 { label:"IAM Identity Center",    tier:"security",    icon:"mxgraph.aws4.single_sign_on" },
  aws_identitystore_group:                { label:"Identity Store Group",   tier:"security",    icon:"mxgraph.aws4.single_sign_on" },

  // ── CI/CD & IaC ───────────────────────────────────────────────────────
  // Sentinel runs between plan → policy check → apply in this tier
  aws_codepipeline:                       { label:"CodePipeline",           tier:"cicd",        icon:"mxgraph.aws4.codepipeline" },
  aws_codebuild_project:                  { label:"CodeBuild",              tier:"cicd",        icon:"mxgraph.aws4.codebuild" },
  aws_codecommit_repository:              { label:"CodeCommit",             tier:"cicd",        icon:"mxgraph.aws4.codecommit" },
  aws_codedeploy_app:                     { label:"CodeDeploy",             tier:"cicd",        icon:"mxgraph.aws4.codedeploy" },
  aws_codedeploy_deployment_group:        { label:"Deploy Group",           tier:"cicd",        icon:"mxgraph.aws4.codedeploy" },
  aws_codedeploy_deployment_config:       { label:"Deploy Config",          tier:"cicd",        icon:"mxgraph.aws4.codedeploy" },
  aws_codeartifact_domain:                { label:"CodeArtifact",           tier:"cicd",        icon:"mxgraph.aws4.codeartifact" },
  aws_codeartifact_repository:            { label:"Artifact Repo",          tier:"cicd",        icon:"mxgraph.aws4.codeartifact" },
  aws_codestarconnections_connection:      { label:"CodeStar Connect",       tier:"cicd",        icon:"mxgraph.aws4.codestar_connections" },
  aws_cloudformation_stack:               { label:"CloudFormation",         tier:"cicd",        icon:"mxgraph.aws4.cloudformation" },
  aws_cloudformation_stack_set:           { label:"CF StackSet",            tier:"cicd",        icon:"mxgraph.aws4.cloudformation" },
  aws_service_catalog_portfolio:          { label:"Service Catalog",        tier:"cicd",        icon:"mxgraph.aws4.service_catalog" },
  aws_service_catalog_product:            { label:"SC Product",             tier:"cicd",        icon:"mxgraph.aws4.service_catalog" },
  aws_imagebuilder_pipeline:              { label:"Image Builder",          tier:"cicd",        icon:"mxgraph.aws4.imagebuilder" },
  aws_imagebuilder_image_recipe:          { label:"Image Recipe",           tier:"cicd",        icon:"mxgraph.aws4.imagebuilder" },

  // ── Observability ─────────────────────────────────────────────────────
  // Horizontal concern — monitors all tiers, not just one
  aws_cloudwatch_log_group:               { label:"CloudWatch Logs",        tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_log_stream:              { label:"CW Log Stream",          tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_metric_alarm:            { label:"CW Alarm",               tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_dashboard:               { label:"CW Dashboard",           tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_composite_alarm:         { label:"CW Composite Alarm",     tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_metric_stream:           { label:"CW Metric Stream",       tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_log_subscription_filter: { label:"Log Filter",             tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_log_metric_filter:       { label:"Log Metric Filter",      tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_event_archive:           { label:"Event Archive",          tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_cloudwatch_anomaly_detector:        { label:"CW Anomaly Detector",    tier:"observability", icon:"mxgraph.aws4.cloudwatch" },
  aws_xray_group:                         { label:"X-Ray Group",            tier:"observability", icon:"mxgraph.aws4.xray" },
  aws_xray_sampling_rule:                 { label:"X-Ray Sampling",         tier:"observability", icon:"mxgraph.aws4.xray" },
  aws_grafana_workspace:                  { label:"Amazon Grafana",         tier:"observability", icon:"mxgraph.aws4.managed_grafana" },
  aws_prometheus_workspace:               { label:"Amazon Prometheus",      tier:"observability", icon:"mxgraph.aws4.prometheus" },
  aws_oam_link:                           { label:"CloudWatch OAM",         tier:"observability", icon:"mxgraph.aws4.cloudwatch" },

  _default: { label:"Resource", tier:"compute", icon:null },
};

// ── XML helpers ───────────────────────────────────────────────────────────
const xa  = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const vid  = id   => "V_"  + id.replace(/[^a-zA-Z0-9]/g,"_");
const swid = t    => "SW_" + t.replace(/[^a-zA-Z0-9]/g,"_");
const eid  = (f,t)=> "E_"  + f.replace(/[^a-zA-Z0-9]/g,"_") + "_TO_" + t.replace(/[^a-zA-Z0-9]/g,"_");

// ── Well-Architected Validation ───────────────────────────────────────────
// Detects common anti-patterns and Well-Architected issues
function validateArch(resources) {
  const issues = [];
  const types = new Set(resources.map(r => r.type));

  // Security pillar
  if (types.has("aws_s3_bucket") && !types.has("aws_s3_bucket_server_side_encryption_configuration"))
    issues.push({ sev:"warn", pillar:"Security", msg:"S3 buckets lack explicit SSE encryption config" });
  if (types.has("aws_db_instance") && !types.has("aws_db_subnet_group"))
    issues.push({ sev:"warn", pillar:"Security", msg:"RDS instance has no DB subnet group (should be in isolated subnet)" });
  if (types.has("aws_lambda_function") && !types.has("aws_iam_role"))
    issues.push({ sev:"warn", pillar:"Security", msg:"Lambda functions require IAM execution roles" });
  if ((types.has("aws_instance") || types.has("aws_ecs_service")) && !types.has("aws_security_group"))
    issues.push({ sev:"warn", pillar:"Security", msg:"Compute resources without explicit security groups" });

  // Reliability pillar
  if (types.has("aws_db_instance") && !resources.some(r => r.type === "aws_db_instance" && r.body && /multi_az\s*=\s*true/.test(r.body)))
    issues.push({ sev:"info", pillar:"Reliability", msg:"Consider Multi-AZ for RDS (not detected in config)" });
  if (types.has("aws_rds_cluster") && !resources.some(r => r.type === "aws_rds_cluster_instance" && r.body))
    issues.push({ sev:"warn", pillar:"Reliability", msg:"Aurora cluster without read replica instances" });
  if (types.has("aws_lb") && !types.has("aws_lb_target_group"))
    issues.push({ sev:"warn", pillar:"Reliability", msg:"Load balancer without target group" });

  // Operational Excellence
  if ((types.has("aws_ecs_service") || types.has("aws_lambda_function")) && !types.has("aws_cloudwatch_log_group"))
    issues.push({ sev:"warn", pillar:"OpEx", msg:"Compute resources without CloudWatch log groups" });

  // Performance Efficiency
  if (types.has("aws_lambda_function") && !types.has("aws_lambda_layer_version") && resources.filter(r=>r.type==="aws_lambda_function").length > 3)
    issues.push({ sev:"info", pillar:"Performance", msg:"Multiple Lambdas — consider Lambda Layers for shared deps" });

  // Cost Optimization
  if (resources.filter(r => r.type === "aws_s3_bucket").length > 0 && !types.has("aws_s3_bucket_lifecycle_configuration"))
    issues.push({ sev:"info", pillar:"Cost", msg:"S3 buckets without lifecycle policies — consider storage tiering" });

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════
//  TERRAFORM / HCL PARSER
//  Understands:
//  • resource blocks (standard + for_each/count annotation)
//  • data blocks (data sources — rendered with dashed border)
//  • module blocks (composite nodes in compute tier)
//  • sentinel.hcl policy blocks (CI/CD tier, color-coded by enforcement)
//  • .sentinel file source detection
//  • implicit refs: aws_TYPE.NAME in any attribute value
//  • explicit deps: depends_on = [...] → CONFIG edge type
//  • lifecycle meta-args: prevent_destroy, ignore_changes annotated
//  • for_each/count: label annotated with [*] or [N]
// ═══════════════════════════════════════════════════════════════════════════
function parseTerraform(text) {
  const resources = [], conns = [];

  // Standard resource blocks — captures body including nested braces
  const reRes = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)(?=\n(?:resource|data|module|variable|output|provider|locals|terraform)\s|\s*$)/g;
  let m;
  while ((m = reRes.exec(text)) !== null) {
    const type = m[1], name = m[2], body = m[3], id = type + "." + name;
    // Prefer meaningful label attributes
    const LA = ["name","bucket","function_name","cluster_id","cluster_identifier","table_name",
      "queue_name","topic_name","domain_name","db_name","identifier","family","alias","description",
      "repository_name","pipeline_name","project_name","log_group_name","mesh_name","workgroup_name"];
    let label = name;
    for (const a of LA) {
      const lm = body.match(new RegExp("\\b" + a + "\\s*=\\s*\"([^\"]{1,48})\"", "m"));
      if (lm) { label = lm[1]; break; }
    }
    // Detect for_each / count
    let multiplicity = "";
    if (/\bfor_each\s*=/.test(body)) multiplicity = " [*]";
    else { const cm = body.match(/\bcount\s*=\s*(\d+)/); if (cm) multiplicity = ` [×${cm[1]}]`; }
    // Detect lifecycle annotations
    const lifecycle = {};
    if (/prevent_destroy\s*=\s*true/.test(body)) lifecycle.prevent_destroy = true;
    if (/create_before_destroy\s*=\s*true/.test(body)) lifecycle.create_before_destroy = true;
    if (/ignore_changes/.test(body)) lifecycle.ignore_changes = true;

    resources.push({ id, type, name, label: label + multiplicity, body, lifecycle, isData: false });

    // Implicit references — aws_TYPE.NAME in body
    const ref = /\b(aws_[\w]+)\.([\w-]+)\b/g; let rm;
    while ((rm = ref.exec(body)) !== null) {
      const t = rm[1] + "." + rm[2];
      if (t !== id) conns.push({ from: id, to: t, flowHint: null });
    }

    // Explicit depends_on references → CONFIG flow
    const depsMatch = body.match(/depends_on\s*=\s*\[([^\]]*)\]/s);
    if (depsMatch) {
      const deps = depsMatch[1].match(/\b(aws_[\w]+)\.([\w-]+)\b/g) || [];
      deps.forEach(dep => {
        if (dep !== id) conns.push({ from: id, to: dep, flowHint: "CONFIG" });
      });
    }
  }

  // Data source blocks — read-only, rendered with dashed border
  const reData = /data\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
  while ((m = reData.exec(text)) !== null) {
    const type = m[1], name = m[2], body = m[3];
    const id = "data." + type + "." + name;
    // Map to same icons/tier as the resource type
    resources.push({ id, type, name, label: name + " [data]", body, lifecycle: {}, isData: true });
  }

  // Module blocks — composite nodes
  const reMod = /module\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
  while ((m = reMod.exec(text)) !== null) {
    const name = m[1], body = m[2];
    const id = "module." + name;
    resources.push({ id, type:"terraform_module", name, label: "Module: " + name, body, lifecycle: {}, isData: false });
    // Refs inside module body
    const ref = /\b(aws_[\w]+)\.([\w-]+)\b/g; let rm;
    while ((rm = ref.exec(body)) !== null) {
      conns.push({ from: id, to: rm[1] + "." + rm[2], flowHint: null });
    }
  }

  // Sentinel policies from sentinel.hcl or policy blocks
  const reSent = /policy\s+"([^"]+)"\s*\{[\s\S]*?enforcement_level\s*=\s*"([^"]+)"[\s\S]*?\}/g;
  while ((m = reSent.exec(text)) !== null) {
    const name = m[1], level = m[2];
    const id = "sentinel_policy." + name;
    resources.push({ id, type:"sentinel_policy", name, label: name, body: "", lifecycle: {},
      isData: false, sentinelLevel: level });
  }

  // Dedup resources
  const seenR = new Set();
  const uniq = resources.filter(r => { if (seenR.has(r.id)) return false; seenR.add(r.id); return true; });
  const valid = new Set(uniq.map(r => r.id));
  const seenE = new Set();
  const edges = conns.filter(c => {
    const k = c.from + "||" + c.to;
    if (seenE.has(k) || !valid.has(c.to) || c.from === c.to) return false;
    seenE.add(k); return true;
  });
  return { resources: uniq, connections: edges };
}

// ═══════════════════════════════════════════════════════════════════════════
//  LAYOUT ENGINE
// ═══════════════════════════════════════════════════════════════════════════
const NW=76, NH=76, LABEL_H=38, HPAD=24, VPAD=28, VGAP=22, HGAP=72;
const SW_HDR=44, OUTER=30, MAX_ROWS=7, INNER_GAP=20;

function buildLayout(resources) {
  const tierGroups = {};
  TIERS.forEach(t => { tierGroups[t.id] = []; });
  resources.forEach(r => {
    let tid;
    if (r.type === "sentinel_policy") tid = "cicd";
    else if (r.type === "terraform_module") tid = "compute";
    else tid = (RES[r.type] || RES._default).tier;
    (tierGroups[tid] = tierGroups[tid] || []).push(r);
  });
  const activeTiers = TIERS.filter(t => (tierGroups[t.id] || []).length > 0);
  const tierMeta = {};
  activeTiers.forEach(tier => {
    const members = tierGroups[tier.id];
    const n = members.length;
    const subCols = Math.ceil(n / MAX_ROWS);
    const maxRows = Math.min(n, MAX_ROWS);
    const innerW = subCols * NW + (subCols - 1) * INNER_GAP;
    const swW = innerW + HPAD * 2;
    const swH = SW_HDR + VPAD + maxRows * (NH + LABEL_H + VGAP) - VGAP + VPAD;
    tierMeta[tier.id] = { members, subCols, maxRows, swW, swH };
  });
  const globalH = Math.max(...activeTiers.map(t => tierMeta[t.id].swH), 200);
  const tierX = {};
  let curX = OUTER;
  activeTiers.forEach(tier => { tierX[tier.id] = curX; curX += tierMeta[tier.id].swW + HGAP; });
  const totalW = curX - HGAP + OUTER;
  const pos = {};
  activeTiers.forEach(tier => {
    const { members } = tierMeta[tier.id];
    const swX = tierX[tier.id];
    members.forEach((r, i) => {
      const subCol = Math.floor(i / MAX_ROWS);
      const row    = i % MAX_ROWS;
      pos[r.id] = {
        x: swX + HPAD + subCol * (NW + INNER_GAP),
        y: OUTER + SW_HDR + VPAD + row * (NH + LABEL_H + VGAP),
        w: NW, h: NH, tierId: tier.id, swX, swW: tierMeta[tier.id].swW,
      };
    });
  });
  const cols = activeTiers.map(tier => ({
    tier, x: tierX[tier.id], y: OUTER,
    w: tierMeta[tier.id].swW, h: globalH,
    count: (tierGroups[tier.id] || []).length,
  }));
  return { pos, cols, totalW, totalH: OUTER + globalH + OUTER, tierX };
}

// ═══════════════════════════════════════════════════════════════════════════
//  XML GENERATOR
// ═══════════════════════════════════════════════════════════════════════════
function generateXML(resources, connections) {
  const { pos, cols, totalW, totalH, tierX } = buildLayout(resources);
  const containerCells = [], edgeCells = [], vertexCells = [];

  // 1. Swimlane columns
  cols.forEach(col => {
    const t = col.tier;
    const style = [
      "swimlane", `startSize=${SW_HDR}`,
      `fillColor=${t.hdr}`, `swimlaneFillColor=${t.bg}`, `strokeColor=${t.border}`,
      "strokeWidth=2", "fontColor=#FFFFFF", "fontSize=11", "fontStyle=1",
      "fontFamily=Helvetica", "align=center", "swimlaneLine=1",
      "rounded=1", "arcSize=3", "whiteSpace=wrap", "html=1",
    ].join(";") + ";";
    containerCells.push(
      `    <mxCell id="${swid(t.id)}" value="${xa(t.label + " (" + col.count + ")")}" style="${style}" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${col.x}" y="${col.y}" width="${col.w}" height="${col.h}" as="geometry" />\n` +
      `    </mxCell>`
    );
    // Hint text below header
    containerCells.push(
      `    <mxCell id="${swid(t.id)}_hint" value="${xa(t.hint || "")}" ` +
      `style="text;html=1;align=center;verticalAlign=top;fontSize=8;fontColor=${t.border};` +
      `fontStyle=2;fontFamily=Helvetica;whiteSpace=wrap;" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${col.x}" y="${col.y + SW_HDR + 4}" width="${col.w}" height="16" as="geometry" />\n` +
      `    </mxCell>`
    );
  });

  // 2. Edges
  const valid = new Set(resources.map(r => r.id));
  const seenE = new Set();
  connections.forEach(c => {
    if (!valid.has(c.from) || !valid.has(c.to) || c.from === c.to) return;
    const eId = eid(c.from, c.to);
    if (seenE.has(eId)) return;
    seenE.add(eId);
    const fk = c.flowHint || inferFlow(c.from.split(".")[0], c.to.split(".")[0]);
    const f = FLOW[fk] || FLOW.REQUEST;
    const srcP = pos[c.from], tgtP = pos[c.to];
    if (!srcP || !tgtP) return;
    let exitX, exitY, entryX, entryY;
    if (Math.abs(srcP.swX - tgtP.swX) < 1) {
      exitX=0.5; exitY=1; entryX=0.5; entryY=0;
    } else if (srcP.swX < tgtP.swX) {
      exitX=1; exitY=0.5; entryX=0; entryY=0.5;
    } else {
      exitX=0; exitY=0.5; entryX=1; entryY=0.5;
    }
    const dashPart = f.dash ? `dashed=1;dashPattern=${f.dash};` : "dashed=0;";
    const style = [
      "edgeStyle=orthogonalEdgeStyle","html=1","rounded=1","orthogonalLoop=1","jettySize=auto",
      `exitX=${exitX}`,`exitY=${exitY}`,"exitDx=0","exitDy=0",
      `entryX=${entryX}`,`entryY=${entryY}`,"entryDx=0","entryDy=0",
      `strokeColor=${f.color}`,`strokeWidth=${f.width}`,
      dashPart.replace(/;$/,""),
      "endArrow=block","endFill=1","startArrow=none","startFill=0",
    ].join(";") + ";";
    edgeCells.push(
      `    <mxCell id="${eId}" value="" style="${style}" edge="1" source="${vid(c.from)}" target="${vid(c.to)}" parent="1">\n` +
      `      <mxGeometry relative="1" as="geometry" />\n` +
      `    </mxCell>`
    );
  });

  // 3. Resource nodes
  resources.forEach(r => {
    const info = RES[r.type] || RES._default;
    const p = pos[r.id]; if (!p) return;
    const tier = TIER_MAP[p.tierId];
    const cId = vid(r.id);
    const shortType = r.type === "sentinel_policy"
      ? "Sentinel Policy"
      : r.type === "terraform_module"
      ? "TF Module"
      : r.type.replace(/^(?:aws_|data\.aws_)/,"").replace(/_/g," ");
    const htmlLabel =
      `<b style="font-size:10px;color:#1A1A2E">${xa(r.label)}</b>` +
      `<br/><span style="font-size:8px;color:#546E7A">${xa(shortType)}</span>`;

    let style;
    if (r.type === "sentinel_policy") {
      const sc = SENTINEL_COLORS[r.sentinelLevel] || SENTINEL_COLORS["advisory"];
      style = [
        "shape=mxgraph.flowchart.decision","html=1","whiteSpace=wrap",
        `fillColor=${sc.fill}`,`strokeColor=${tier.border}`,"strokeWidth=2",
        `fontColor=${sc.text}`,"fontSize=9","fontFamily=Helvetica","align=center",
      ].join(";") + ";";
    } else if (r.type === "terraform_module") {
      style = [
        "shape=mxgraph.aws4.group","html=1","whiteSpace=wrap",
        `fillColor=${tier.bg}`,`strokeColor=${tier.border}`,"strokeWidth=2",
        "fontColor=#232F3E","fontSize=9","fontFamily=Helvetica","align=center",
        "strokeDashArray=8 4",
      ].join(";") + ";";
    } else if (info.icon) {
      // Data sources get dashed border per AWS diagram conventions
      const strokeW = r.isData ? "1" : "1.5";
      const dashAttr = r.isData ? "strokeDashArray=5 3;" : "";
      style = [
        "shape=mxgraph.aws4.resourceIcon",`resIcon=${info.icon}`,
        "html=1","whiteSpace=wrap","fillColor=#FFFFFF",`strokeColor=${tier.border}`,
        `strokeWidth=${strokeW}`,dashAttr.replace(/;$/,""),
        "fontColor=#232F3E","fontSize=10","fontFamily=Helvetica","fontStyle=0",
        "align=center","verticalAlign=top",
        "verticalLabelPosition=bottom","labelPosition=center",
        "labelBackgroundColor=#FFFFFF","labelBorderColor=none",
        "aspect=fixed","outlineConnect=0",
      ].filter(s=>s).join(";") + ";";
    } else {
      style = [
        "rounded=1","arcSize=8","html=1","whiteSpace=wrap",
        "fillColor=#FFFFFF",`strokeColor=${tier.border}`,"strokeWidth=1.5",
        "fontColor=#232F3E","fontSize=10","fontFamily=Helvetica","align=center",
      ].join(";") + ";";
    }

    // Lifecycle badges — add annotation icon for prevent_destroy
    const lifebadge = r.lifecycle && r.lifecycle.prevent_destroy
      ? `<br/><span style="font-size:7px;color:#B71C1C;background:#FFEBEE">🔒 protected</span>`
      : "";

    vertexCells.push(
      `    <mxCell id="${cId}" value="${htmlLabel}${lifebadge}" style="${style}" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" as="geometry" />\n` +
      `    </mxCell>`
    );
  });

  // 4. Legend panel
  const LX = totalW + 36, LY = OUTER;
  const LW = 268, LROW = 38, LPAD = 14, LLINE = 54;
  const flowEntries = Object.entries(FLOW);
  const LH = SW_HDR + LPAD + flowEntries.length * LROW + LPAD + 20;
  containerCells.push(
    `    <mxCell id="LEG_HEADER" value="Data Flow Legend" ` +
    `style="swimlane;startSize=${SW_HDR};fillColor=#263238;swimlaneFillColor=#ECEFF1;` +
    `strokeColor=#37474F;strokeWidth=2;fontColor=#FFFFFF;fontSize=13;fontStyle=1;` +
    `fontFamily=Helvetica;align=center;rounded=1;arcSize=3;whiteSpace=wrap;html=1;" ` +
    `vertex="1" parent="1">\n` +
    `      <mxGeometry x="${LX}" y="${LY}" width="${LW}" height="${LH}" as="geometry" />\n` +
    `    </mxCell>`
  );
  flowEntries.forEach(([key, f], i) => {
    const rowY = LY + SW_HDR + LPAD + i * LROW;
    const midY = rowY + LROW / 2;
    const x1 = LX + LPAD, x2 = x1 + LLINE;
    const srcId = `LG_${key}_src`, tgtId = `LG_${key}_tgt`;
    containerCells.push(
      `    <mxCell id="${srcId}" value="" style="ellipse;fillColor=${f.color};strokeColor=none;aspect=fixed;" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${x1}" y="${midY - 5}" width="10" height="10" as="geometry" />\n` +
      `    </mxCell>`,
      `    <mxCell id="${tgtId}" value="" style="ellipse;fillColor=${f.color};strokeColor=none;aspect=fixed;" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${x2 - 5}" y="${midY - 5}" width="10" height="10" as="geometry" />\n` +
      `    </mxCell>`
    );
    const dashPart = f.dash ? `dashed=1;dashPattern=${f.dash};` : "dashed=0;";
    edgeCells.push(
      `    <mxCell id="LG_${key}_line" value="" ` +
      `style="edgeStyle=none;html=1;${dashPart}strokeColor=${f.color};strokeWidth=${f.width};endArrow=block;endFill=1;startArrow=none;" ` +
      `edge="1" source="${srcId}" target="${tgtId}" parent="1">\n` +
      `      <mxGeometry relative="1" as="geometry" />\n` +
      `    </mxCell>`
    );
    vertexCells.push(
      `    <mxCell id="LG_${key}_txt" value="${xa(f.symbol + "  " + f.label)}" ` +
      `style="text;html=1;align=left;verticalAlign=middle;fontSize=10;fontFamily=Helvetica;` +
      `fontColor=#37474F;whiteSpace=wrap;" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${x2 + 12}" y="${rowY + 2}" width="${LW - LPAD - LLINE - 18}" height="${LROW - 4}" as="geometry" />\n` +
      `    </mxCell>`
    );
  });

  // 5. Sentinel Pipeline explainer (always shown if sentinel nodes exist)
  const hasSentinel = resources.some(r => r.type === "sentinel_policy");
  if (hasSentinel) {
    const sentY = LY + LH + 20;
    const sentH = 140;
    containerCells.push(
      `    <mxCell id="SENT_BOX" value="Sentinel Pipeline" ` +
      `style="swimlane;startSize=30;fillColor=#4A148C;swimlaneFillColor=#EDE7F6;` +
      `strokeColor=#6A1B9A;strokeWidth=2;fontColor=#FFFFFF;fontSize=12;fontStyle=1;` +
      `fontFamily=Helvetica;align=center;rounded=1;arcSize=3;whiteSpace=wrap;html=1;" ` +
      `vertex="1" parent="1">\n` +
      `      <mxGeometry x="${LX}" y="${sentY}" width="${LW}" height="${sentH}" as="geometry" />\n` +
      `    </mxCell>`
    );
    const sentNotes = [
      "terraform plan → [advisory] → [soft-mandatory] → [hard-mandatory] → terraform apply",
      "",
      "🔵 advisory: warns, never blocks",
      "🟠 soft-mandatory: blocks, owner can override",
      "🔴 hard-mandatory: blocks, must fix or remove",
      "",
      "Source: sentinel.hcl enforcement_level attribute",
    ];
    vertexCells.push(
      `    <mxCell id="SENT_BODY" value="${xa(sentNotes.join("\n"))}" ` +
      `style="text;html=0;align=left;verticalAlign=top;fontSize=9;fontFamily=Helvetica;` +
      `fontColor=#4A148C;whiteSpace=wrap;spacingLeft=8;spacingTop=4;" vertex="1" parent="1">\n` +
      `      <mxGeometry x="${LX + 8}" y="${sentY + 32}" width="${LW - 16}" height="${sentH - 38}" as="geometry" />\n` +
      `    </mxCell>`
    );
  }

  // 6. Well-Architected notes box
  const noteY = LY + LH + (hasSentinel ? 180 : 20);
  const noteH = 190;
  containerCells.push(
    `    <mxCell id="NOTE_BOX" value="Well-Architected Notes" ` +
    `style="swimlane;startSize=30;fillColor=#1B5E20;swimlaneFillColor=#F9FBE7;` +
    `strokeColor=#33691E;strokeWidth=2;fontColor=#FFFFFF;fontSize=12;fontStyle=1;` +
    `fontFamily=Helvetica;align=center;rounded=1;arcSize=3;whiteSpace=wrap;html=1;" ` +
    `vertex="1" parent="1">\n` +
    `      <mxGeometry x="${LX}" y="${noteY}" width="${LW}" height="${noteH}" as="geometry" />\n` +
    `    </mxCell>`
  );
  const notes = [
    "✓ Flow: Left → Right = canonical data path",
    "✓ 3-tier model: Public (DMZ) → Private App → Isolated Data",
    "✓ Security & IAM: cross-cutting (all tiers)",
    "✓ Observability: horizontal concern (all tiers)",
    "✓ Data sources shown with dashed border",
    "✓ depends_on edges rendered as CONFIG type",
    "✓ for_each resources annotated with [*]",
    "✓ prevent_destroy annotated with 🔒",
    "✓ Sentinel: advisory < soft-mandatory < hard-mandatory",
  ];
  vertexCells.push(
    `    <mxCell id="NOTE_BODY" value="${xa(notes.join("\n"))}" ` +
    `style="text;html=0;align=left;verticalAlign=top;fontSize=10;fontFamily=Helvetica;` +
    `fontColor=#33691E;whiteSpace=wrap;spacingLeft=8;spacingTop=6;" vertex="1" parent="1">\n` +
    `      <mxGeometry x="${LX + 8}" y="${noteY + 32}" width="${LW - 16}" height="${noteH - 38}" as="geometry" />\n` +
    `    </mxCell>`
  );

  const all = containerCells.concat(edgeCells).concat(vertexCells);
  const pageW = Math.max(1654, LX + LW + 60);
  const pageH = Math.max(1169, totalH + 100);
  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<mxfile host="app.diagrams.net" modified="${new Date().toISOString()}" agent="terraform-to-drawio-v5" version="21.0.0" type="device" compressed="false">`,
    `  <diagram id="arch-diagram" name="Architecture">`,
    `    <mxGraphModel dx="1800" dy="1200" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${pageW}" pageHeight="${pageH}" math="0" shadow="0">`,
    `      <root>`,
    `        <mxCell id="0" />`,
    `        <mxCell id="1" parent="0" />`,
  ].concat(all).concat([
    `      </root>`,
    `    </mxGraphModel>`,
    `  </diagram>`,
    `</mxfile>`,
  ]).join("\n");
}

// ── Sample Terraform — full Well-Architected + Sentinel demo ─────────────
const SAMPLE_TF = `# ── DNS & Certificates (Global, outside VPC) ─────────────────────────────
resource "aws_route53_zone" "main" { name = "example.com" }
resource "aws_acm_certificate" "cert" { domain_name = "example.com" }

# ── Edge & CDN (Global AWS Network) ───────────────────────────────────────
resource "aws_cloudfront_distribution" "cdn" { name = "app-cdn" }
resource "aws_wafv2_web_acl" "waf" { name = "main-waf" }
resource "aws_shield_protection" "main" { name = "shield-app" }

# ── Public DMZ — ALB, API GW, NAT GW (internet-facing, public subnet) ─────
resource "aws_lb" "app" { name = "app-alb" }
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  name = "https-443"
}
resource "aws_lb_target_group" "web" { name = "web-tg" }
resource "aws_api_gateway_rest_api" "api" { name = "main-api" }
resource "aws_api_gateway_stage" "prod" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  name = "prod"
}
resource "aws_api_gateway_authorizer" "cognito" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  name = "cognito-auth"
}

# ── Network Fabric (VPC + subnets) ─────────────────────────────────────────
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.main.id
  name = "public-a"
}
resource "aws_subnet" "private_a" {
  vpc_id = aws_vpc.main.id
  name = "private-a"
}
resource "aws_subnet" "data_a" {
  vpc_id = aws_vpc.main.id
  name = "isolated-data-a"
}
resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }
resource "aws_nat_gateway" "nat" { name = "main-nat" }
resource "aws_security_group" "alb_sg" {
  name = "alb-sg"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "app_sg" {
  name = "app-sg"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "data_sg" {
  name = "data-sg"
  vpc_id = aws_vpc.main.id
}
resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id = aws_vpc.main.id
  name = "s3-gateway-endpoint"
}
resource "aws_flow_log" "vpc_flow" { name = "vpc-flow-log" }

# ── Compute (Private App Tier — private subnet) ────────────────────────────
resource "aws_ecs_cluster" "app" { name = "app-cluster" }
resource "aws_ecs_service" "web" {
  name    = "web-service"
  cluster = aws_ecs_cluster.app.id
}
resource "aws_ecs_task_definition" "web" { family = "web-task" }
resource "aws_lambda_function" "processor" {
  function_name = "event-processor"
}
resource "aws_lambda_function" "authorizer" {
  function_name = "api-authorizer"
}
resource "aws_lambda_layer_version" "deps" { name = "shared-deps" }
resource "aws_autoscaling_group" "app" { name = "app-asg" }

# ── Storage (S3 — regional, not in VPC) ────────────────────────────────────
resource "aws_s3_bucket" "assets" { bucket = "app-assets" }
resource "aws_s3_bucket" "logs" { bucket = "access-logs" }
resource "aws_s3_bucket_server_side_encryption_configuration" "assets_enc" {
  bucket = aws_s3_bucket.assets.id
  name = "assets-encryption"
}
resource "aws_s3_bucket_lifecycle_configuration" "logs_lifecycle" {
  bucket = aws_s3_bucket.logs.id
  name = "log-archive-policy"
}

# ── Data Tier (Isolated subnet — no direct internet route) ─────────────────
resource "aws_rds_cluster" "primary" {
  cluster_identifier = "aurora-primary"
}
resource "aws_rds_cluster_instance" "replica" {
  cluster_id = aws_rds_cluster.primary.id
  name = "aurora-replica"
}
resource "aws_rds_proxy" "proxy" {
  name = "db-proxy"
  depends_on = [aws_iam_role.rds_proxy_role]
}
resource "aws_elasticache_replication_group" "redis" { name = "redis-cache" }
resource "aws_dynamodb_table" "sessions" {
  name = "sessions"
}
resource "aws_db_subnet_group" "main" { name = "db-subnet-group" }

# ── Async Messaging ────────────────────────────────────────────────────────
resource "aws_sqs_queue" "jobs" { name = "job-queue" }
resource "aws_sqs_queue" "dlq" { name = "dead-letter-queue" }
resource "aws_sns_topic" "alerts" { name = "system-alerts" }
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  name = "ops-email"
}
resource "aws_cloudwatch_event_rule" "cron" { name = "daily-cron" }
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule = aws_cloudwatch_event_rule.cron.name
  name = "lambda-target"
}
resource "aws_step_functions_state_machine" "workflow" { name = "order-workflow" }

# ── Security & IAM (Cross-cutting — all tiers) ─────────────────────────────
resource "aws_iam_role" "ecs_task" { name = "ecs-task-role" }
resource "aws_iam_role" "lambda_exec" { name = "lambda-execution-role" }
resource "aws_iam_role" "rds_proxy_role" { name = "rds-proxy-role" }
resource "aws_iam_role_policy_attachment" "ecs_s3" {
  role       = aws_iam_role.ecs_task.name
  name = "ecs-s3-attach"
}
resource "aws_kms_key" "app" { description = "app-encryption-key" }
resource "aws_secretsmanager_secret" "db_creds" { name = "db-credentials" }
resource "aws_cognito_user_pool" "users" { name = "app-users" }
resource "aws_cognito_user_pool_client" "app_client" { name = "app-client" }
resource "aws_ssm_parameter" "config" { name = "/app/config" }
resource "aws_guardduty_detector" "main" { name = "guardduty" }
resource "aws_cloudtrail" "audit" { name = "audit-trail" }

# ── CI/CD Pipeline ─────────────────────────────────────────────────────────
resource "aws_codepipeline" "main" { name = "app-pipeline" }
resource "aws_codebuild_project" "build" { name = "app-build" }
resource "aws_codecommit_repository" "repo" { name = "app-repo" }
resource "aws_s3_bucket" "artifacts" { bucket = "pipeline-artifacts" }

# ── Observability (Horizontal concern — monitors all tiers) ────────────────
resource "aws_cloudwatch_log_group" "app" { name = "/ecs/app" }
resource "aws_cloudwatch_log_group" "lambda_logs" { name = "/lambda/processor" }
resource "aws_cloudwatch_metric_alarm" "cpu" { name = "ecs-cpu-alarm" }
resource "aws_cloudwatch_dashboard" "ops" { name = "ops-dashboard" }
resource "aws_xray_group" "tracing" { name = "app-tracing" }

# ── Sentinel policies (from sentinel.hcl) ─────────────────────────────────
# Runs between terraform plan and terraform apply in HCP Terraform / TFE
policy "require-tags" {
  source            = "./policies/require-tags.sentinel"
  enforcement_level = "hard-mandatory"
}
policy "restrict-instance-types" {
  source            = "./policies/restrict-instance-types.sentinel"
  enforcement_level = "soft-mandatory"
}
policy "cost-advisory" {
  source            = "./policies/cost-check.sentinel"
  enforcement_level = "advisory"
}
policy "enforce-encryption" {
  source            = "./policies/enforce-encryption.sentinel"
  enforcement_level = "hard-mandatory"
}`;

// ── Syntax highlighter ────────────────────────────────────────────────────
const xe = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
function highlight(raw) {
  let out = "";
  const re = /(<\?xml[\s\S]*?\?>)|(<!--[\s\S]*?-->)|(<\/[\w:]+\s*>)|(<[\w:][\s\S]*?>)|([^<]+)/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    if (m[1]) out += `<span style="color:#f97583;font-weight:600">${xe(m[1])}</span>`;
    else if (m[2]) out += `<span style="color:#6a737d">${xe(m[2])}</span>`;
    else if (m[3]) {
      const inn = m[3].replace(/^<\/([\w:]+)\s*>$/, (_, n) => `&lt;<span style="color:#79c0ff">/${xe(n)}</span>&gt;`);
      out += inn !== m[3] ? inn : xe(m[3]);
    } else if (m[4]) {
      const tag = m[4], nm = tag.match(/^<([\w:]+)/), tn = nm ? nm[1] : "";
      const rest = tag.slice(1 + tn.length).replace(/\/?>$/, ""), sc = tag.endsWith("/>") ? "/" : "";
      const hr = rest.replace(/([\w:]+)(\s*=\s*")((?:[^"\\]|\\.)*)(")/,
        (_, an, eq, av, cl) => `<span style="color:#ffa657">${xe(an)}</span>${xe(eq)}<span style="color:#a5d6ff">${xe(av)}</span>${cl}`);
      out += `&lt;<span style="color:#79c0ff">${xe(tn)}</span>${hr}${sc ? "/" : ""}`.trimEnd() + "&gt;";
    } else if (m[5]) out += `<span style="color:#4a7a80">${xe(m[5])}</span>`;
  }
  return out;
}

// ── Architecture Quality Score ────────────────────────────────────────────
function calcScore(resources, connections, issues) {
  const types = new Set(resources.map(r => r.type));
  let score = 100;
  let details = [];
  const warnCount = issues.filter(i => i.sev === "warn").length;
  const infoCount = issues.filter(i => i.sev === "info").length;
  score -= warnCount * 8;
  score -= infoCount * 3;
  // Bonus points
  if (types.has("aws_cloudwatch_metric_alarm")) { score += 5; details.push("+5 alerting"); }
  if (types.has("aws_guardduty_detector"))      { score += 5; details.push("+5 GuardDuty"); }
  if (types.has("aws_cloudtrail"))              { score += 5; details.push("+5 CloudTrail"); }
  if (types.has("aws_wafv2_web_acl"))           { score += 5; details.push("+5 WAF"); }
  if (resources.some(r => r.type === "sentinel_policy")) { score += 5; details.push("+5 Sentinel"); }
  if (types.has("aws_kms_key"))                 { score += 3; details.push("+3 KMS"); }
  if (types.has("aws_backup_vault"))            { score += 3; details.push("+3 Backup"); }
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, grade, details };
}

// ── Tier colors for stats badges ─────────────────────────────────────────
const TUI = { dns:"#6A1B9A", edge:"#00838F", public:"#388E3C", network:"#7B1FA2",
  compute:"#F9A825", storage:"#33691E", database:"#1565C0", analytics:"#E65100",
  messaging:"#C2185B", security:"#D32F2F", cicd:"#6A1B9A", observability:"#00695C",
  internet:"#9E9E9E" };

const btnS = (bg, c, x) => Object.assign({
  padding:"5px 14px", background:bg, border:`1px solid ${c}55`,
  borderRadius:4, color:c, fontSize:11, cursor:"pointer",
  fontFamily:"'Space Mono',monospace", whiteSpace:"nowrap",
}, x || {});

// ═══════════════════════════════════════════════════════════════════════════
//  UI
// ═══════════════════════════════════════════════════════════════════════════
export default function App() {
  const [tfText, setTfText] = useState("");
  const [xml, setXml] = useState("");
  const [stats, setStats] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [fileList, setFileList] = useState([]);
  const [tab, setTab] = useState("xml");
  const [issues, setIssues] = useState([]);
  const [scoreData, setScoreData] = useState(null);
  const mono = { fontFamily:"'Space Mono',monospace" };

  const process = useCallback((text) => {
    setError("");
    try {
      const { resources, connections } = parseTerraform(text);
      if (!resources.length) { setError("No AWS resource blocks found in input."); setXml(""); setStats(null); return; }
      const newXml = generateXML(resources, connections);
      setXml(newXml);
      const issueList = validateArch(resources);
      setIssues(issueList);
      const scoreInfo = calcScore(resources, connections, issueList);
      setScoreData(scoreInfo);
      const tiers = {};
      resources.forEach(r => {
        let t;
        if (r.type === "sentinel_policy") t = "cicd";
        else if (r.type === "terraform_module") t = "compute";
        else t = (RES[r.type] || RES._default).tier;
        tiers[t] = (tiers[t] || 0) + 1;
      });
      const dataCount = resources.filter(r => r.isData).length;
      const sentinelCount = resources.filter(r => r.type === "sentinel_policy").length;
      setStats({ resources: resources.length, connections: connections.length, tiers, dataCount, sentinelCount });
    } catch (e) { setError("Parse error: " + e.message); }
  }, []);

  const readTfFiles = useCallback((fh) => {
    const tf = Array.from(fh)
      .filter(f => f.name.endsWith(".tf") || f.name.endsWith(".hcl") || f.name.endsWith(".sentinel"))
      .sort((a,b) => (a.webkitRelativePath||a.name).localeCompare(b.webkitRelativePath||b.name));
    if (!tf.length) { setError("No .tf / .hcl / .sentinel files found."); return; }
    setFileList(tf.map(f => f.webkitRelativePath || f.name));
    Promise.all(tf.map(f => new Promise((res,rej) => {
      const r = new FileReader();
      r.onload = ev => res({ path: f.webkitRelativePath||f.name, text: ev.target.result });
      r.onerror = () => rej(new Error("Failed: " + f.name));
      r.readAsText(f);
    }))).then(results => {
      const c = results.map(({path,text}) => `# -- ${path} --\n${text}`).join("\n\n");
      setTfText(c); process(c);
    }).catch(e => setError(e.message));
  }, [process]);

  const handleDrop = useCallback(e => { e.preventDefault(); setDragging(false); readTfFiles(e.dataTransfer.files); }, [readTfFiles]);
  const handleFile = e => { if (e.target.files?.length) readTfFiles(e.target.files); e.target.value=""; };
  const download = () => { const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([xml],{type:"application/xml"})); a.download="architecture.drawio"; a.click(); };
  const copy = () => navigator.clipboard.writeText(xml).then(()=>{ setCopied(true); setTimeout(()=>setCopied(false),2000); });

  const gradeColor = scoreData ? (scoreData.score>=90?"#4caf50":scoreData.score>=70?"#FF9900":"#f44336") : "#666";

  return (
    <div style={{...mono, background:"#0a0a0a", minHeight:"100vh", color:"#e0e0e0"}}>
      <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap" rel="stylesheet"/>

      {/* Header */}
      <div style={{borderBottom:"1px solid #181818", padding:"10px 24px", display:"flex", alignItems:"center", gap:14, background:"#070707"}}>
        <div style={{width:32, height:32, background:"linear-gradient(135deg,#FF6B35,#FF9900)", borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, fontWeight:700}}>⬡</div>
        <div>
          <div style={{fontSize:13, fontWeight:700, color:"#fff", letterSpacing:"0.08em"}}>TERRAFORM → DRAW.IO / LUCIDCHART</div>
          <div style={{fontSize:9, color:"#333", letterSpacing:".06em"}}>v5 · Well-Architected · 13 Tiers · 9 Flow Types · 180+ Resources · Sentinel-Aware · depends_on · for_each · data sources · Quality Scoring</div>
        </div>
        <div style={{marginLeft:"auto", display:"flex", gap:6}}>
          <button onClick={()=>{ setFileList([]); setTfText(SAMPLE_TF); process(SAMPLE_TF); }} style={btnS("#181818","#666")}>Load Sample</button>
        </div>
      </div>

      <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", height:"calc(100vh - 54px)"}}>

        {/* Input panel */}
        <div style={{borderRight:"1px solid #181818", display:"flex", flexDirection:"column"}}>
          <div style={{padding:"7px 16px", borderBottom:"1px solid #181818", display:"flex", gap:8, alignItems:"center", background:"#070707"}}>
            <span style={{fontSize:10, color:"#333", textTransform:"uppercase", letterSpacing:".12em"}}>Input</span>
            <span style={{fontSize:9, color:"#222"}}>— .tf · .hcl · .sentinel · folder</span>
            <div style={{marginLeft:"auto", display:"flex", gap:5}}>
              <label style={{...btnS("#181818","#555"), cursor:"pointer"}}>
                📄 File<input type="file" accept=".tf,.hcl,.sentinel" multiple onChange={handleFile} style={{display:"none"}}/>
              </label>
              <label style={{...btnS("#181800","#FF9900"), cursor:"pointer"}}>
                📂 Folder<input type="file" accept=".tf,.hcl,.sentinel" webkitdirectory="" onChange={handleFile} style={{display:"none"}}/>
              </label>
            </div>
          </div>

          {fileList.length > 0 && (
            <div style={{padding:"5px 16px", borderBottom:"1px solid #181818", background:"#060606", maxHeight:72, overflowY:"auto"}}>
              <div style={{fontSize:9, color:"#3a6a5a", marginBottom:2}}>{fileList.length} file{fileList.length!==1?"s":""} loaded</div>
              {fileList.map((f,i) => <div key={i} style={{fontSize:9, color:"#2d5548", lineHeight:1.7}}>▸ {f}</div>)}
            </div>
          )}

          <div onDrop={handleDrop} onDragOver={e=>{e.preventDefault();setDragging(true);}} onDragLeave={()=>setDragging(false)}
            style={{flex:1, position:"relative", outline:dragging?"2px dashed #FF9900":"none", outlineOffset:"-2px"}}>
            <textarea value={tfText} onChange={e=>setTfText(e.target.value)}
              placeholder={"# Paste Terraform HCL, sentinel.hcl, or upload files\n# Supports: resource, data, module, sentinel policy blocks\n# Detects: depends_on edges, for_each[*], data sources (dashed)\n\nresource \"aws_lb\" \"app\" {\n  name = \"app-alb\"\n}"}
              spellCheck={false}
              style={{width:"100%", height:"100%", background:"#060606", color:"#b8ccd4", border:"none",
                outline:"none", padding:"16px", boxSizing:"border-box", ...mono, fontSize:11,
                lineHeight:1.8, resize:"none", caretColor:"#FF9900", tabSize:2}}/>
            {dragging && (
              <div style={{position:"absolute", inset:0, background:"#FF990015", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:8, pointerEvents:"none"}}>
                <span style={{fontSize:16, color:"#FF9900"}}>↓ Drop .tf / .hcl / .sentinel files or folder</span>
              </div>
            )}
          </div>

          {error && <div style={{padding:"6px 16px", background:"#1e0808", borderTop:"1px solid #3a1515", fontSize:11, color:"#ff6b6b"}}>⚠ {error}</div>}

          <div style={{padding:"9px 16px", borderTop:"1px solid #181818", background:"#070707"}}>
            <button onClick={()=>process(tfText)} disabled={!tfText.trim()}
              style={{width:"100%", padding:"9px", ...mono,
                background:tfText.trim()?"linear-gradient(90deg,#FF6B35,#FF9900)":"#181818",
                border:"none", borderRadius:4, color:tfText.trim()?"#000":"#333",
                fontWeight:700, fontSize:12, cursor:tfText.trim()?"pointer":"not-allowed", letterSpacing:".1em"}}>
              ⬡ GENERATE DIAGRAM
            </button>
          </div>
        </div>

        {/* Output panel */}
        <div style={{display:"flex", flexDirection:"column", background:"#060606"}}>
          <div style={{padding:"7px 16px", borderBottom:"1px solid #181818", display:"flex", gap:5, alignItems:"center", background:"#070707", flexWrap:"wrap"}}>
            <button onClick={()=>setTab("xml")}     style={btnS(tab==="xml"     ?"#142014":"#111", tab==="xml"     ?"#4caf50":"#444")}>XML</button>
            <button onClick={()=>setTab("quality")} style={btnS(tab==="quality" ?"#1a1008":"#111", tab==="quality" ?"#FF9900":"#444")}>Quality</button>
            <button onClick={()=>setTab("guide")}   style={btnS(tab==="guide"   ?"#14142a":"#111", tab==="guide"   ?"#7986cb":"#444")}>Import Guide</button>
            <button onClick={()=>setTab("flows")}   style={btnS(tab==="flows"   ?"#1a0808":"#111", tab==="flows"   ?"#ef9a9a":"#444")}>Flow Types</button>
            <button onClick={()=>setTab("tiers")}   style={btnS(tab==="tiers"   ?"#0a180a":"#111", tab==="tiers"   ?"#81c784":"#444")}>Tier Guide</button>
            {xml && (
              <div style={{marginLeft:"auto", display:"flex", gap:5}}>
                <button onClick={copy} style={btnS(copied?"#0a1a0a":"#181818", copied?"#4caf50":"#555")}>{copied?"✓ Copied":"Copy XML"}</button>
                <button onClick={download} style={btnS("#141000","#FF9900")}>⬇ .drawio</button>
              </div>
            )}
          </div>

          {/* Stats bar */}
          {stats && (
            <div style={{padding:"4px 16px", borderBottom:"1px solid #181818", display:"flex", gap:7, flexWrap:"wrap", alignItems:"center", background:"#070707"}}>
              <span style={{fontSize:11, color:"#444"}}><span style={{color:"#FF9900",fontWeight:700}}>{stats.resources}</span> res</span>
              <span style={{color:"#111",fontSize:10}}>·</span>
              <span style={{fontSize:11, color:"#444"}}><span style={{color:"#FF9900",fontWeight:700}}>{stats.connections}</span> edges</span>
              {stats.dataCount > 0 && <><span style={{color:"#111"}}>·</span><span style={{fontSize:9, color:"#666"}}>{stats.dataCount} data</span></>}
              {stats.sentinelCount > 0 && <><span style={{color:"#111"}}>·</span><span style={{fontSize:9, color:"#B71C1C"}}>{stats.sentinelCount} sentinel</span></>}
              <span style={{color:"#111",fontSize:10}}>·</span>
              {scoreData && (
                <span style={{fontSize:12, fontWeight:700, color:gradeColor, letterSpacing:".04em"}}>
                  {scoreData.grade} ({scoreData.score}/100)
                </span>
              )}
              <span style={{color:"#111",fontSize:10}}>·</span>
              {Object.entries(stats.tiers).map(([t,n]) => (
                <span key={t} style={{fontSize:9, padding:"2px 6px", borderRadius:3,
                  background:(TUI[t]||"#666")+"18", color:TUI[t]||"#aaa",
                  border:`1px solid ${(TUI[t]||"#666")}33`}}>{t}:{n}</span>
              ))}
            </div>
          )}

          <div style={{flex:1, overflow:"auto"}}>
            {tab === "quality" ? (
              <div style={{padding:"20px 22px", fontSize:11, lineHeight:2}}>
                <div style={{fontSize:13, color:"#cdd", fontWeight:700, marginBottom:12}}>🏛 Well-Architected Quality Report</div>
                {!scoreData ? (
                  <div style={{color:"#444"}}>Generate a diagram first to see quality analysis.</div>
                ) : (
                  <>
                    <div style={{display:"flex", alignItems:"center", gap:12, marginBottom:16, padding:"12px 16px", background:"#111", borderRadius:6, border:`1px solid ${gradeColor}33`}}>
                      <div style={{fontSize:36, fontWeight:700, color:gradeColor, lineHeight:1}}>{scoreData.grade}</div>
                      <div>
                        <div style={{fontSize:16, color:gradeColor, fontWeight:700}}>{scoreData.score}/100</div>
                        <div style={{fontSize:9, color:"#444"}}>Architecture Quality Score</div>
                      </div>
                    </div>
                    {issues.length === 0 && <div style={{color:"#4caf50", marginBottom:12}}>✓ No Well-Architected issues detected!</div>}
                    {issues.map((issue, i) => (
                      <div key={i} style={{
                        marginBottom:8, padding:"8px 12px", borderRadius:4,
                        background: issue.sev==="warn"?"#1e0a0a":"#0a0a1a",
                        border: `1px solid ${issue.sev==="warn"?"#3a1515":"#1a1a3a"}`,
                        display:"flex", gap:10, alignItems:"flex-start"
                      }}>
                        <span style={{color:issue.sev==="warn"?"#ff6b6b":"#7986cb", fontSize:14, lineHeight:1.4}}>
                          {issue.sev==="warn"?"⚠":"ℹ"}
                        </span>
                        <div>
                          <span style={{fontSize:9, color:issue.sev==="warn"?"#ff6b6b":"#7986cb", fontWeight:700, display:"block", marginBottom:2}}>
                            [{issue.pillar}]
                          </span>
                          <span style={{color:"#8a9aaa"}}>{issue.msg}</span>
                        </div>
                      </div>
                    ))}
                    {scoreData.details.length > 0 && (
                      <div style={{marginTop:12}}>
                        <div style={{fontSize:10, color:"#333", marginBottom:6}}>BONUS POINTS AWARDED</div>
                        {scoreData.details.map((d,i) => (
                          <div key={i} style={{fontSize:10, color:"#4caf50", lineHeight:1.8}}>✓ {d}</div>
                        ))}
                      </div>
                    )}
                    <div style={{marginTop:16, fontSize:9, color:"#222", lineHeight:1.8}}>
                      Based on: AWS Well-Architected Framework · 6 Pillars<br/>
                      Operational Excellence · Security · Reliability · Performance · Cost · Sustainability
                    </div>
                  </>
                )}
              </div>
            ) : tab === "guide" ? (
              <div style={{padding:"20px 22px", fontSize:11, lineHeight:2, color:"#8a9aaa"}}>
                <div style={{fontSize:13, color:"#cdd", fontWeight:700, marginBottom:12}}>📥 Import Guide</div>
                <div style={{color:"#FF9900", fontWeight:700, marginBottom:4}}>draw.io (app.diagrams.net)</div>
                <div>1. Click <b style={{color:"#fff"}}>⬇ .drawio</b> to download</div>
                <div>2. Open <span style={{color:"#adf"}}>app.diagrams.net</span></div>
                <div style={{marginBottom:14}}>3. Drag .drawio file onto canvas ✓</div>
                <div style={{color:"#7986cb", fontWeight:700, marginBottom:4}}>Lucidchart</div>
                <div>1. Download the <b style={{color:"#fff"}}>.drawio</b> file</div>
                <div>2. Lucidchart: <span style={{color:"#adf"}}>File → Import → Draw.io</span></div>
                <div style={{marginBottom:14}}>3. Upload — labels, positions, connections preserved ✓</div>
                <div style={{color:"#43A047", fontWeight:700, marginBottom:4}}>Terraform / HCL / Sentinel</div>
                <div>• <b style={{color:"#fff"}}>resource</b> blocks → colored swimlane nodes</div>
                <div>• <b style={{color:"#fff"}}>data</b> blocks → dashed-border nodes (read-only sources)</div>
                <div>• <b style={{color:"#fff"}}>module</b> blocks → composite group nodes</div>
                <div>• <b style={{color:"#fff"}}>depends_on</b> → CONFIG-type edge (purple dashed)</div>
                <div>• <b style={{color:"#fff"}}>for_each</b> resources labeled <b>[*]</b></div>
                <div>• <b style={{color:"#fff"}}>count = N</b> resources labeled <b>[×N]</b></div>
                <div>• <b style={{color:"#fff"}}>prevent_destroy</b> resources show 🔒 badge</div>
                <div style={{marginBottom:14}}>• <b style={{color:"#fff"}}>sentinel.hcl policy</b> blocks → CI/CD tier, color-coded diamond nodes</div>
                <div style={{color:"#B71C1C", fontWeight:700, marginBottom:4}}>Sentinel Enforcement Levels</div>
                <div style={{color:"#ff6b6b"}}>🔴 hard-mandatory — blocks unconditionally; must fix or remove policy</div>
                <div style={{color:"#FF9900"}}>🟠 soft-mandatory — blocks; owner with permissions can override (logged)</div>
                <div style={{color:"#7986cb"}}>🔵 advisory — logs warning only; never blocks run</div>
              </div>
            ) : tab === "flows" ? (
              <div style={{padding:"20px 22px", fontSize:11, lineHeight:1.8, color:"#8a9aaa"}}>
                <div style={{fontSize:13, color:"#cdd", fontWeight:700, marginBottom:12}}>Flow Type Reference</div>
                {Object.entries(FLOW).map(([k,f]) => (
                  <div key={k} style={{display:"flex", alignItems:"flex-start", gap:10, marginBottom:10}}>
                    <svg width="44" height="14" style={{flexShrink:0, marginTop:4}}>
                      <line x1="2" y1="7" x2="34" y2="7" stroke={f.color} strokeWidth={f.width} strokeDasharray={f.dash?f.dash.replace(/ /g,","):"none"}/>
                      <polygon points="32,4 44,7 32,10" fill={f.color}/>
                    </svg>
                    <div>
                      <span style={{color:f.color, fontWeight:700, marginRight:8}}>{f.symbol} {k}</span>
                      <span style={{color:"#ccc"}}>{f.label}</span>
                      <div style={{fontSize:9, color:"#444", marginTop:1}}>{f.desc}</div>
                    </div>
                  </div>
                ))}
                <div style={{marginTop:16, color:"#333", fontSize:10}}>
                  Flows inferred from connected resource type pairs.<br/>
                  IAM edges always use IAM style. CloudWatch uses LOG style.<br/>
                  EventBridge/SQS/SNS use EVENT. depends_on uses CONFIG.
                </div>
              </div>
            ) : tab === "tiers" ? (
              <div style={{padding:"20px 22px", fontSize:11, lineHeight:1.8, color:"#8a9aaa"}}>
                <div style={{fontSize:13, color:"#cdd", fontWeight:700, marginBottom:12}}>AWS Architecture Tier Guide</div>
                <div style={{fontSize:10, color:"#444", marginBottom:10}}>Left → Right = canonical AWS data flow direction (request path)</div>
                {TIERS.map(t => (
                  <div key={t.id} style={{marginBottom:8, display:"flex", alignItems:"flex-start", gap:8}}>
                    <div style={{width:8, height:8, borderRadius:2, background:t.hdr, flexShrink:0, marginTop:4}}/>
                    <div>
                      <span style={{color:t.border, fontWeight:700}}>{t.label}</span>
                      <span style={{color:"#333", marginLeft:8, fontSize:9}}>[{t.group}]</span>
                      <div style={{fontSize:9, color:"#444", marginTop:1}}>{t.hint}</div>
                    </div>
                  </div>
                ))}
                <div style={{marginTop:16, fontSize:10, color:"#333", lineHeight:2}}>
                  AWS Boundary Groupings:<br/>
                  <span style={{color:"#9E9E9E"}}>external</span> — outside all AWS boundaries (Internet, users)<br/>
                  <span style={{color:"#006064"}}>global</span> — AWS Global Edge Network (CDN, DNS, WAF)<br/>
                  <span style={{color:"#1B5E20"}}>vpc</span> — within AWS VPC (private/isolated subnets)<br/>
                  <span style={{color:"#1565C0"}}>region</span> — regional AWS services (S3, SQS, SNS)<br/>
                  <span style={{color:"#4A148C"}}>cross</span> — cross-cutting concerns (IAM, monitoring, CI/CD)
                </div>
              </div>
            ) : xml ? (
              <pre style={{margin:0, padding:"14px", background:"transparent", color:"#5a8a7f", fontSize:10, lineHeight:1.7, ...mono, whiteSpace:"pre-wrap", wordBreak:"break-all"}}>
                <code dangerouslySetInnerHTML={{__html: highlight(xml)}}/>
              </pre>
            ) : (
              <div style={{height:"100%", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", gap:10, opacity:0.15}}>
                <div style={{fontSize:36}}>⬡</div>
                <div style={{fontSize:12, letterSpacing:".12em"}}>OUTPUT WILL APPEAR HERE</div>
                <div style={{fontSize:9}}>13 tiers · 9 flow types · 180+ resources · Well-Architected</div>
              </div>
            )}
          </div>

          {xml && tab === "xml" && (
            <div style={{padding:"5px 16px", borderTop:"1px solid #181818", fontSize:9, color:"#222", background:"#070707", display:"flex", gap:8, alignItems:"center"}}>
              <span>draw.io: drag file in · Lucidchart: File → Import → Draw.io</span>
              <button onClick={()=>setTab("guide")} style={{background:"none",border:"none",color:"#7986cb",cursor:"pointer",fontSize:9,...mono}}>Import Guide →</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
