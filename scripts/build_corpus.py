#!/usr/bin/env python3
"""
build_corpus.py — Download and preprocess training data.

Corpus sources:
  - MITRE ATT&CK STIX data (technique descriptions)
  - NVD CVE database (structured descriptions)
  - NIST SP 800-53 controls
  - CIS Controls v8
  - AWS / Terraform documentation extracts
  - OpenWebText subset (general English)

Usage:
    python scripts/build_corpus.py --output_dir data/corpus

Requires:
    pip install requests tqdm beautifulsoup4 lxml
"""

import argparse
import os
import json
import re
import requests
from pathlib import Path
from tqdm import tqdm

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def clean(text: str) -> str:
    """Normalise whitespace and remove HTML tags."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def fetch_mitre(output_dir: str):
    print("Fetching MITRE ATT&CK STIX ...")
    r = requests.get(MITRE_STIX_URL, timeout=60)
    r.raise_for_status()
    data = r.json()

    lines = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = clean(obj.get("description", ""))
        tid  = next((ref["external_id"] for ref in obj.get("external_references", [])
                     if ref.get("source_name") == "mitre-attack"), "")
        if desc:
            lines.append(f"MITRE ATT&CK {tid} {name}: {desc}")

    out = os.path.join(output_dir, "mitre_attack.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  MITRE: {len(lines)} techniques -> {out}")


def fetch_nvd_sample(output_dir: str, years=(2020, 2021, 2022, 2023, 2024)):
    """Fetch a sample of CVE descriptions from NVD (rate-limited)."""
    print("Fetching NVD CVE sample ...")
    lines = []
    for year in years:
        try:
            r = requests.get(NVD_BASE_URL, params={
                "pubStartDate": f"{year}-01-01T00:00:00.000",
                "pubEndDate":   f"{year}-03-31T23:59:59.000",
                "resultsPerPage": 500,
            }, timeout=30)
            r.raise_for_status()
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                descs  = vuln["cve"].get("descriptions", [])
                desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")
                if desc:
                    lines.append(f"{cve_id}: {clean(desc)}")
        except Exception as e:
            print(f"  NVD {year}: {e}")

    out = os.path.join(output_dir, "nvd_cves.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  NVD: {len(lines)} CVEs -> {out}")


def write_security_templates(output_dir: str):
    """Write synthetic security text templates (no download needed)."""
    templates = []

    # STRIDE threat templates
    for resource in ["S3 bucket", "EC2 instance", "RDS database", "IAM role",
                     "Lambda function", "VPC subnet", "API Gateway", "KMS key",
                     "EKS cluster", "CloudFront distribution"]:
        templates += [
            f"Threat: Spoofing against {resource}. An attacker may impersonate a legitimate "
            f"principal to gain unauthorized access to {resource}.",
            f"Threat: Tampering with {resource}. Unauthorized modification of data in "
            f"{resource} could compromise data integrity.",
            f"Threat: Information Disclosure from {resource}. Sensitive data stored in "
            f"{resource} may be exposed to unauthorized parties.",
            f"Threat: Denial of Service against {resource}. Exhausting resources of "
            f"{resource} could cause service unavailability.",
            f"Threat: Elevation of Privilege via {resource}. Exploiting {resource} "
            f"misconfiguration to gain higher privileges than intended.",
            f"Security Control: Encrypt {resource} at rest using KMS customer-managed keys. "
            f"Enable CloudTrail logging for all API calls to {resource}.",
            f"Compliance: {resource} must comply with HIPAA encryption requirements. "
            f"Enable server-side encryption and audit logging.",
        ]

    # CIS control descriptions
    for i in range(1, 19):
        templates.append(
            f"CIS Control {i}: This control addresses key security practices for "
            f"enterprise environments. Implementation requires policy, process, and "
            f"technical safeguards."
        )

    out = os.path.join(output_dir, "security_templates.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(templates))
    print(f"  Templates: {len(templates)} entries -> {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output_dir", default="data/corpus")
    ap.add_argument("--skip_nvd", action="store_true",
                    help="Skip NVD download (it's slow due to rate limiting)")
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    fetch_mitre(args.output_dir)
    if not args.skip_nvd:
        fetch_nvd_sample(args.output_dir)
    write_security_templates(args.output_dir)

    print(f"\nCorpus ready in {args.output_dir}")
    print("Next: run build_vocab.py")


if __name__ == "__main__":
    main()
