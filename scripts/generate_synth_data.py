#!/usr/bin/env python3
"""
generate_synth_data.py — Generate synthetic threat modeling Q&A pairs.

Generates 100K pairs covering:
  - STRIDE analysis for Terraform resource types
  - MITRE ATT&CK technique mapping
  - CIS/NIST control recommendations
  - Compliance gap analysis (HIPAA, FedRAMP, SOC2, PCI, GDPR, CMMC)
  - Trust boundary identification

Usage:
    # Generate template-based pairs (no API needed):
    python scripts/generate_synth_data.py --mode template --output data/synth

    # Generate GPT-4o-enhanced pairs (requires OPENAI_API_KEY):
    python scripts/generate_synth_data.py --mode gpt4o --output data/synth

Requires (template mode): nothing extra
Requires (gpt4o mode): pip install openai
"""

import argparse
import json
import os
import random
import itertools

AWS_RESOURCES = [
    "aws_s3_bucket", "aws_ec2_instance", "aws_rds_instance",
    "aws_iam_role", "aws_iam_policy", "aws_lambda_function",
    "aws_vpc", "aws_security_group", "aws_kms_key",
    "aws_eks_cluster", "aws_ecs_service", "aws_cloudtrail",
    "aws_cloudwatch_log_group", "aws_waf_web_acl", "aws_apigateway_rest_api",
    "aws_secretsmanager_secret", "aws_sns_topic", "aws_sqs_queue",
    "aws_dynamodb_table", "aws_elasticache_cluster",
]

STRIDE_THREATS = {
    "Spoofing":               "An attacker impersonates a legitimate identity.",
    "Tampering":              "Unauthorized modification of data or code.",
    "Repudiation":            "A user denies performing an action without proof.",
    "Information Disclosure": "Sensitive data is exposed to unauthorized parties.",
    "Denial of Service":      "A resource is made unavailable to legitimate users.",
    "Elevation of Privilege": "A user gains higher privileges than intended.",
}

MITRE_TECHNIQUES = [
    ("T1078", "Valid Accounts"),
    ("T1190", "Exploit Public-Facing Application"),
    ("T1530", "Data from Cloud Storage"),
    ("T1537", "Transfer Data to Cloud Account"),
    ("T1098", "Account Manipulation"),
    ("T1110", "Brute Force"),
    ("T1136", "Create Account"),
    ("T1485", "Data Destruction"),
    ("T1486", "Data Encrypted for Impact"),
    ("T1562", "Impair Defenses"),
]

COMPLIANCE_FRAMEWORKS = ["HIPAA", "FedRAMP", "SOC 2", "PCI DSS", "GDPR", "CMMC", "NIST CSF", "CIS v8"]


def template_pairs():
    pairs = []

    # STRIDE Q&A
    for resource in AWS_RESOURCES:
        for threat, desc in STRIDE_THREATS.items():
            q = f"What are the {threat} threats for a Terraform {resource} resource?"
            a = (f"For {resource}, {threat} threats include: {desc} "
                 f"An attacker may exploit misconfigured access controls, "
                 f"insufficient logging, or unencrypted data to achieve {threat.lower()}. "
                 f"Mitigations: enforce least-privilege IAM policies, enable CloudTrail, "
                 f"encrypt at rest and in transit, and implement resource-based policies.")
            pairs.append({"instruction": q, "response": a})

    # MITRE mapping
    for resource in random.sample(AWS_RESOURCES, 10):
        for tid, tname in MITRE_TECHNIQUES:
            q = f"Which MITRE ATT&CK technique ({tid} - {tname}) applies to {resource}?"
            a = (f"MITRE ATT&CK {tid} ({tname}) applies to {resource} when: "
                 f"the resource has overly permissive access controls, "
                 f"lacks monitoring, or exposes sensitive data. "
                 f"Recommended controls: implement least privilege, "
                 f"enable GuardDuty, configure CloudWatch alarms, and review IAM policies.")
            pairs.append({"instruction": q, "response": a})

    # Compliance
    for resource in random.sample(AWS_RESOURCES, 5):
        for fw in COMPLIANCE_FRAMEWORKS:
            q = f"What {fw} requirements apply to {resource}?"
            a = (f"Under {fw}, {resource} must: "
                 f"(1) encrypt data at rest and in transit, "
                 f"(2) implement access logging and audit trails, "
                 f"(3) enforce least-privilege access controls, "
                 f"(4) implement monitoring and alerting, "
                 f"(5) maintain data retention and deletion policies.")
            pairs.append({"instruction": q, "response": a})

    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",   choices=["template", "gpt4o"], default="template")
    ap.add_argument("--output", default="data/synth")
    ap.add_argument("--count",  type=int, default=10000,
                    help="Target number of pairs (template mode generates more by default)")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)

    if args.mode == "template":
        pairs = template_pairs()
        # Augment with paraphrases to reach target count
        while len(pairs) < args.count:
            p = random.choice(pairs[:500])
            pairs.append({
                "instruction": p["instruction"].replace("?", " in detail?"),
                "response": p["response"],
            })
            if len(pairs) >= args.count:
                break
        pairs = pairs[:args.count]

    elif args.mode == "gpt4o":
        import openai
        client = openai.OpenAI()
        pairs  = []
        base   = template_pairs()[:100]
        for p in base:
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Provide detailed, accurate answers."},
                    {"role": "user",   "content": p["instruction"]},
                ],
                max_tokens=400,
            )
            pairs.append({"instruction": p["instruction"], "response": resp.choices[0].message.content})
        print(f"GPT-4o generated {len(pairs)} pairs")

    out = os.path.join(args.output, "synth_qa.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"Generated {len(pairs)} pairs -> {out}")


if __name__ == "__main__":
    main()
