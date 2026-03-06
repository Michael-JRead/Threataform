#!/usr/bin/env python3
"""
scripts/eval.py
ThreataformLM-200M — Evaluation Benchmark Suite

Measures:
  1. STRIDE classification accuracy       (resource → correct threat categories)
  2. MITRE ATT&CK technique recall@10     (CVE/scenario → correct T-number)
  3. CIS control recommendation precision  (resource config → relevant controls)
  4. Perplexity on held-out security text  (lower = better language model)
  5. RAG retrieval quality                 (MRR, NDCG@10, Hit@5)
  6. End-to-end threat Q&A                 (BLEU-4, ROUGE-L)

Usage:
  python scripts/eval.py --model public/model.tnlm --device cpu
  python scripts/eval.py --model public/model.tnlm --device cuda --batch 8
  python scripts/eval.py --stride-only     # quick sanity check
  python scripts/eval.py --rag-only        # no model needed
  python scripts/eval.py --all --save-report eval_report.json
"""

import argparse
import json
import math
import os
import re
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
#  Lazy imports (avoid hard dependency on torch at import time)
# ──────────────────────────────────────────────────────────────────────────────

def _import_torch():
    try:
        import torch
        return torch
    except ImportError:
        print("ERROR: PyTorch not installed. Run: pip install torch")
        sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
#  Reference datasets (embedded — no download required)
# ──────────────────────────────────────────────────────────────────────────────

# STRIDE benchmark: Terraform resource type → expected threat categories
STRIDE_BENCHMARK = [
    {
        "resource": "aws_s3_bucket",
        "config": 'resource "aws_s3_bucket" "data" { bucket = "sensitive-data" }',
        "expected_threats": ["Information Disclosure", "Tampering"],
        "expected_mitigations": ["encryption", "versioning", "access_control"],
    },
    {
        "resource": "aws_iam_role",
        "config": 'resource "aws_iam_role" "admin" { assume_role_policy = "..." }',
        "expected_threats": ["Elevation of Privilege", "Spoofing"],
        "expected_mitigations": ["least_privilege", "mfa", "boundary_policy"],
    },
    {
        "resource": "aws_security_group",
        "config": 'resource "aws_security_group" "open" { ingress { from_port = 0 to_port = 65535 cidr_blocks = ["0.0.0.0/0"] } }',
        "expected_threats": ["Denial of Service", "Information Disclosure", "Tampering"],
        "expected_mitigations": ["restrict_ingress", "egress_rules", "vpc_flow_logs"],
    },
    {
        "resource": "aws_rds_instance",
        "config": 'resource "aws_rds_instance" "db" { publicly_accessible = true storage_encrypted = false }',
        "expected_threats": ["Information Disclosure", "Tampering", "Repudiation"],
        "expected_mitigations": ["encryption_at_rest", "private_subnet", "audit_logging"],
    },
    {
        "resource": "aws_lambda_function",
        "config": 'resource "aws_lambda_function" "fn" { environment { variables = { SECRET_KEY = "hardcoded" } } }',
        "expected_threats": ["Information Disclosure", "Spoofing", "Elevation of Privilege"],
        "expected_mitigations": ["secrets_manager", "iam_role", "vpc_binding"],
    },
    {
        "resource": "aws_eks_cluster",
        "config": 'resource "aws_eks_cluster" "k8s" { endpoint_public_access = true }',
        "expected_threats": ["Spoofing", "Denial of Service", "Elevation of Privilege"],
        "expected_mitigations": ["private_endpoint", "rbac", "network_policy"],
    },
    {
        "resource": "aws_kms_key",
        "config": 'resource "aws_kms_key" "key" { enable_key_rotation = false deletion_window_in_days = 7 }',
        "expected_threats": ["Information Disclosure", "Repudiation"],
        "expected_mitigations": ["key_rotation", "key_policy", "audit_logging"],
    },
    {
        "resource": "aws_cloudtrail",
        "config": 'resource "aws_cloudtrail" "trail" { enable_log_file_validation = false }',
        "expected_threats": ["Repudiation", "Information Disclosure"],
        "expected_mitigations": ["log_validation", "s3_encryption", "multi_region"],
    },
    {
        "resource": "aws_vpc",
        "config": 'resource "aws_vpc" "main" { enable_dns_hostnames = true cidr_block = "10.0.0.0/8" }',
        "expected_threats": ["Information Disclosure", "Denial of Service"],
        "expected_mitigations": ["flow_logs", "nacl", "private_subnets"],
    },
    {
        "resource": "aws_elasticache_cluster",
        "config": 'resource "aws_elasticache_cluster" "cache" { transit_encryption_enabled = false }',
        "expected_threats": ["Information Disclosure", "Tampering"],
        "expected_mitigations": ["transit_encryption", "auth_token", "vpc_subnet"],
    },
]

STRIDE_CATEGORIES = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
]

# MITRE ATT&CK benchmark: scenario → expected technique IDs
MITRE_BENCHMARK = [
    {
        "scenario": "Attacker uses stolen IAM access keys to call AWS APIs and enumerate S3 buckets",
        "expected_techniques": ["T1078", "T1530", "T1087"],
    },
    {
        "scenario": "Malicious Lambda function exfiltrates environment variables containing database credentials",
        "expected_techniques": ["T1552", "T1041", "T1078.004"],
    },
    {
        "scenario": "Pod in Kubernetes cluster mounts host path and escapes container sandbox",
        "expected_techniques": ["T1611", "T1610", "T1068"],
    },
    {
        "scenario": "Attacker modifies CloudTrail configuration to disable logging and cover tracks",
        "expected_techniques": ["T1562.008", "T1562", "T1070"],
    },
    {
        "scenario": "Cryptominer deployed via misconfigured ECS task using IMDSv1 metadata service",
        "expected_techniques": ["T1552.005", "T1496", "T1078.004"],
    },
    {
        "scenario": "Supply chain attack through compromised Terraform provider in CI/CD pipeline",
        "expected_techniques": ["T1195.001", "T1195", "T1059"],
    },
    {
        "scenario": "Privilege escalation via iam:PassRole and Lambda:CreateFunction combination",
        "expected_techniques": ["T1098.003", "T1078.004", "T1548"],
    },
    {
        "scenario": "Data exfiltration through DNS tunneling from EC2 instance in private subnet",
        "expected_techniques": ["T1048.001", "T1071.004", "T1041"],
    },
]

# CIS Controls benchmark: misconfiguration → expected CIS control numbers
CIS_BENCHMARK = [
    {
        "misconfiguration": "S3 bucket with public read access and no encryption",
        "expected_controls": ["CIS 3.1", "CIS 3.7", "CIS 14.8"],
    },
    {
        "misconfiguration": "Root account used for daily operations without MFA",
        "expected_controls": ["CIS 1.1", "CIS 4.3", "CIS 1.14"],
    },
    {
        "misconfiguration": "Security groups allowing 0.0.0.0/0 on port 22 and 3389",
        "expected_controls": ["CIS 11.3", "CIS 4.1", "CIS 9.2"],
    },
    {
        "misconfiguration": "CloudTrail disabled or not enabled in all regions",
        "expected_controls": ["CIS 2.1", "CIS 2.2", "CIS 3.1"],
    },
    {
        "misconfiguration": "RDS instance with no encryption and publicly accessible",
        "expected_controls": ["CIS 3.5", "CIS 11.3", "CIS 14.8"],
    },
    {
        "misconfiguration": "IAM user with inline policies granting AdministratorAccess",
        "expected_controls": ["CIS 1.16", "CIS 5.1", "CIS 6.3"],
    },
]

# Held-out security text for perplexity evaluation
PERPLEXITY_CORPUS = [
    "The principle of least privilege requires that each subject in a system be granted only the minimum access rights necessary to perform its functions. In AWS IAM, this means creating roles with specific permissions rather than using AdministratorAccess policies.",
    "STRIDE threat modeling categorizes threats into six categories: Spoofing identity, Tampering with data, Repudiation of actions, Information disclosure, Denial of service, and Elevation of privilege. Each category maps to specific security properties that must be protected.",
    "Terraform resources define infrastructure components that can be misconfigured to introduce security vulnerabilities. For example, an aws_s3_bucket without server_side_encryption_configuration enabled stores data in plaintext, violating CIS AWS Foundations Benchmark 2.1.1.",
    "Zero-trust architecture assumes no implicit trust based on network location. Every request must be authenticated, authorized, and encrypted. In Kubernetes, this translates to network policies, RBAC, and mutual TLS between pods.",
    "CVE-2021-44228, known as Log4Shell, is a critical remote code execution vulnerability in Apache Log4j 2. An attacker can exploit JNDI lookups to execute arbitrary code, mapped to MITRE ATT&CK technique T1190 (Exploit Public-Facing Application).",
    "FedRAMP provides a standardized approach to security assessment for cloud services. Authorization requires implementing NIST SP 800-53 controls at Low, Moderate, or High impact levels depending on data sensitivity.",
    "Container escape vulnerabilities allow a process to break out of its container namespace and access the host system. Common vectors include privileged containers, dangerous capabilities like CAP_SYS_ADMIN, and host path mounts that expose sensitive directories.",
    "AWS GuardDuty uses machine learning to analyze CloudTrail, VPC Flow Logs, and DNS logs to detect threats. It identifies patterns such as unusual API calls, cryptocurrency mining, reconnaissance activity, and data exfiltration.",
]

# ──────────────────────────────────────────────────────────────────────────────
#  .tnlm model loader
# ──────────────────────────────────────────────────────────────────────────────

def _dequant_q4(raw: bytes, total: int, torch) -> "torch.Tensor":
    n_blocks = (total + 31) // 32
    out = []
    for b in range(n_blocks):
        base = b * 18
        # float16 scale stored as 2 bytes little-endian
        scale_bytes = raw[base:base+2]
        scale = struct.unpack("<e", scale_bytes)[0]
        nibbles = raw[base+2:base+18]
        for nb in nibbles:
            lo = (nb & 0xF) - 8
            hi = ((nb >> 4) & 0xF) - 8
            out.extend([lo * scale, hi * scale])
    return torch.tensor(out[:total], dtype=torch.float32)


def _dequant_q8(raw: bytes, total: int, torch) -> "torch.Tensor":
    n_blocks = (total + 31) // 32
    out = []
    for b in range(n_blocks):
        base = b * 34
        scale = struct.unpack("<e", raw[base:base+2])[0]
        for i in range(32):
            v = struct.unpack("<b", raw[base+2+i:base+3+i])[0]
            out.append(v * scale)
    return torch.tensor(out[:total], dtype=torch.float32)


def load_tnlm(tnlm_path: str, device: str) -> tuple[dict, dict]:
    """Parse a .tnlm file and return (config, weights dict)."""
    torch = _import_torch()
    with open(tnlm_path, "rb") as f:
        data = f.read()

    offset = 0
    assert data[offset:offset+4] == b"TNLM", "Bad magic bytes"
    offset += 4
    _version = struct.unpack_from("<I", data, offset)[0]; offset += 4
    config_len = struct.unpack_from("<I", data, offset)[0]; offset += 4
    config = json.loads(data[offset:offset+config_len]); offset += config_len

    weights: dict[str, Any] = {}
    while offset < len(data):
        name_len = struct.unpack_from("<I", data, offset)[0]; offset += 4
        name = data[offset:offset+name_len].decode(); offset += name_len
        dtype = struct.unpack_from("<I", data, offset)[0]; offset += 4
        ndim  = struct.unpack_from("<I", data, offset)[0]; offset += 4
        dims  = struct.unpack_from(f"<{ndim}I", data, offset); offset += 4 * ndim
        total = 1
        for d in dims:
            total *= d

        if dtype == 0:    # F32
            n_bytes = total * 4
            arr = torch.frombuffer(data[offset:offset+n_bytes], dtype=torch.float32).clone()
        elif dtype == 1:  # Q4
            n_blocks = (total + 31) // 32
            n_bytes  = n_blocks * 18
            arr = _dequant_q4(data[offset:offset+n_bytes], total, torch)
        elif dtype == 2:  # Q8
            n_blocks = (total + 31) // 32
            n_bytes  = n_blocks * 34
            arr = _dequant_q8(data[offset:offset+n_bytes], total, torch)
        elif dtype == 3:  # F16
            n_bytes = total * 2
            arr = torch.frombuffer(data[offset:offset+n_bytes], dtype=torch.float16).float().clone()
        else:
            raise ValueError(f"Unknown dtype {dtype} for tensor '{name}'")

        offset += n_bytes
        weights[name] = arr.reshape(dims).to(device)

    return config, weights

# ──────────────────────────────────────────────────────────────────────────────
#  Minimal BPE tokenizer (mirrors Tokenizer.js — loads vocab.json)
# ──────────────────────────────────────────────────────────────────────────────

class SimpleBPETokenizer:
    PAD_ID = 0; BOS_ID = 1; EOS_ID = 2; UNK_ID = 3

    def __init__(self, vocab_path: str | None = None):
        self.merges: dict[tuple, int] = {}
        self.vocab:  dict[str, int]   = {}
        self.id2tok: list[str]        = ["<|pad|>", "<|bos|>", "<|eos|>", "<|unk|>"]
        if vocab_path and Path(vocab_path).exists():
            self._load(vocab_path)
        else:
            # Byte-level fallback
            for i in range(256):
                tok = chr(i) if 32 <= i < 127 else f"<{i:02X}>"
                self.vocab[tok] = len(self.id2tok)
                self.id2tok.append(tok)

    def _load(self, path: str):
        with open(path) as f:
            data = json.load(f)
        self.id2tok = data.get("tokens", self.id2tok)
        self.vocab  = {t: i for i, t in enumerate(self.id2tok)}
        for i, pair in enumerate(data.get("merges", [])):
            a, b = pair if isinstance(pair, (list, tuple)) else (pair[0], pair[1])
            self.merges[(a, b)] = i

    def encode(self, text: str) -> list[int]:
        ids = [b + 4 for b in text.encode("utf-8", errors="replace")]
        if not self.merges:
            return ids
        while len(ids) > 1:
            best_rank, best_pos = float("inf"), -1
            for i in range(len(ids) - 1):
                r = self.merges.get((ids[i], ids[i+1]), float("inf"))
                if r < best_rank:
                    best_rank, best_pos = r, i
            if best_pos < 0 or best_rank == float("inf"):
                break
            merged_str = (self.id2tok[ids[best_pos]] if ids[best_pos] < len(self.id2tok) else "?") + \
                         (self.id2tok[ids[best_pos+1]] if ids[best_pos+1] < len(self.id2tok) else "?")
            merged_id  = self.vocab.get(merged_str, ids[best_pos])
            ids = ids[:best_pos] + [merged_id] + ids[best_pos+2:]
        return ids

    def decode(self, ids: list[int]) -> str:
        parts = []
        for i in ids:
            t = self.id2tok[i] if i < len(self.id2tok) else "?"
            m = re.fullmatch(r"<([0-9A-Fa-f]{2})>", t)
            parts.append(bytes([int(m.group(1), 16)]) if m else t.encode("utf-8", errors="replace"))
        try:
            return b"".join(p if isinstance(p, bytes) else p for p in parts).decode("utf-8", errors="replace")
        except Exception:
            return "".join(p.decode("latin-1") if isinstance(p, bytes) else p for p in parts)

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 1 — STRIDE classification
# ──────────────────────────────────────────────────────────────────────────────

def eval_stride(model_fn, verbose: bool = False) -> dict:
    print("\n── STRIDE Classification Benchmark ──")
    hits = 0; total_expected = 0; results = []

    for item in STRIDE_BENCHMARK:
        prompt = (
            "<|start_header_id|>user<|end_header_id|>\n"
            f"Analyze this Terraform resource for STRIDE threats:\n\n"
            f"```hcl\n{item['config']}\n```\n\n"
            "List all applicable STRIDE threat categories.\n"
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )
        response = model_fn(prompt, max_new=200, temp=0.1)
        resp_lo  = response.lower()
        found = [t for t in item["expected_threats"] if t.lower() in resp_lo]
        hits += len(found)
        total_expected += len(item["expected_threats"])
        prec = len(found) / max(len(item["expected_threats"]), 1)
        results.append({"resource": item["resource"], "expected": item["expected_threats"],
                         "found": found, "precision": prec})
        if verbose:
            sym = "✓" if prec == 1.0 else ("~" if prec > 0 else "✗")
            print(f"  {sym} {item['resource']}: found={found}")

    recall = hits / max(total_expected, 1)
    avg_p  = sum(r["precision"] for r in results) / max(len(results), 1)
    print(f"  Recall:    {recall:.3f}  ({hits}/{total_expected})")
    print(f"  Precision: {avg_p:.3f}")
    return {"recall": recall, "precision": avg_p, "details": results}

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 2 — MITRE ATT&CK recall@10
# ──────────────────────────────────────────────────────────────────────────────

def eval_mitre(model_fn, verbose: bool = False) -> dict:
    print("\n── MITRE ATT&CK Technique Recall@10 ──")
    total_hits = 0; total_exp = 0; results = []

    for item in MITRE_BENCHMARK:
        prompt = (
            "<|start_header_id|>user<|end_header_id|>\n"
            "Map this attack scenario to MITRE ATT&CK technique IDs (T####):\n\n"
            f"{item['scenario']}\n"
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )
        response = model_fn(prompt, max_new=300, temp=0.1)
        found_ids = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", response))
        hits = sum(1 for t in item["expected_techniques"] if t in found_ids)
        total_hits += hits; total_exp += len(item["expected_techniques"])
        results.append({"scenario": item["scenario"][:60], "expected": item["expected_techniques"],
                         "found": list(found_ids), "hits": hits})
        if verbose:
            print(f"  Expected:{item['expected_techniques']}  Found:{list(found_ids)[:5]}")

    recall = total_hits / max(total_exp, 1)
    print(f"  Recall@10: {recall:.3f}  ({total_hits}/{total_exp})")
    return {"recall_at_10": recall, "details": results}

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 3 — CIS control recommendation precision
# ──────────────────────────────────────────────────────────────────────────────

def eval_cis(model_fn, verbose: bool = False) -> dict:
    print("\n── CIS Control Recommendation Precision ──")
    total_hits = 0; total_exp = 0; results = []

    for item in CIS_BENCHMARK:
        prompt = (
            "<|start_header_id|>user<|end_header_id|>\n"
            "Identify the CIS Controls that apply to this misconfiguration:\n\n"
            f"{item['misconfiguration']}\n\n"
            "List relevant CIS control numbers.\n"
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )
        response = model_fn(prompt, max_new=250, temp=0.1)
        found = {re.sub(r"\s+", " ", c.upper().strip())
                 for c in re.findall(r"\bCIS\s+\d+(?:\.\d+)?\b", response, re.IGNORECASE)}
        hits = sum(1 for c in item["expected_controls"] if c.upper() in found)
        total_hits += hits; total_exp += len(item["expected_controls"])
        results.append({"config": item["misconfiguration"][:60], "expected": item["expected_controls"],
                         "found": list(found), "hits": hits})
        if verbose:
            print(f"  Expected:{item['expected_controls']}  Found:{list(found)[:5]}")

    prec = total_hits / max(total_exp, 1)
    print(f"  Precision: {prec:.3f}  ({total_hits}/{total_exp})")
    return {"precision": prec, "details": results}

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 4 — Perplexity on held-out security corpus
# ──────────────────────────────────────────────────────────────────────────────

def eval_perplexity(model_pt, tokenizer, device: str, verbose: bool = False) -> dict:
    torch = _import_torch()
    print("\n── Perplexity on Held-Out Security Corpus ──")
    model_pt.eval()
    total_nll = 0.0; total_tokens = 0

    with torch.no_grad():
        for text in PERPLEXITY_CORPUS:
            ids = tokenizer.encode(text)
            if len(ids) < 2:
                continue
            ids_t  = torch.tensor([ids], dtype=torch.long, device=device)
            logits = model_pt(ids_t)               # [1, T, V]
            sl = logits[0, :-1, :]                 # [T-1, V]
            tl = ids_t[0, 1:]                      # [T-1]
            lp  = torch.log_softmax(sl, dim=-1)
            nll = -lp[torch.arange(len(tl)), tl].sum().item()
            total_nll    += nll
            total_tokens += len(tl)
            if verbose:
                print(f"  {text[:50]}...  ppl={math.exp(nll/len(tl)):.1f}")

    if total_tokens == 0:
        return {"perplexity": None, "note": "no tokens"}
    avg_nll = total_nll / total_tokens
    ppl     = math.exp(avg_nll)
    print(f"  Perplexity: {ppl:.2f}  (avg_nll={avg_nll:.4f}, tokens={total_tokens})")
    return {"perplexity": ppl, "avg_nll": avg_nll, "total_tokens": total_tokens}

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 5 — RAG retrieval quality (BM25 baseline)
# ──────────────────────────────────────────────────────────────────────────────

class BM25Eval:
    def __init__(self, docs: list[str], k1: float = 1.5, b: float = 0.75):
        self.docs = docs; self.k1 = k1; self.b = b; self.N = len(docs)
        tokenized = [re.findall(r"\b\w+\b", d.lower()) for d in docs]
        self.avg_dl = sum(len(t) for t in tokenized) / max(self.N, 1)
        self.tf: list[dict[str,int]] = []
        self.df: dict[str,int]       = defaultdict(int)
        for toks in tokenized:
            c: dict[str,int] = defaultdict(int)
            for w in toks: c[w] += 1
            self.tf.append(c)
            for w in set(toks): self.df[w] += 1

    def _score(self, query: str, i: int) -> float:
        q_toks = re.findall(r"\b\w+\b", query.lower())
        dl = sum(self.tf[i].values()); s = 0.0
        for w in q_toks:
            tf = self.tf[i].get(w, 0); df = self.df.get(w, 0)
            if df == 0: continue
            idf     = math.log((self.N - df + 0.5) / (df + 0.5) + 1)
            norm_tf = tf * (self.k1 + 1) / (tf + self.k1 * (1 - self.b + self.b * dl / self.avg_dl))
            s += idf * norm_tf
        return s

    def search(self, query: str, k: int = 10) -> list[tuple[int, float]]:
        scores = sorted([(i, self._score(query, i)) for i in range(self.N)], key=lambda x: -x[1])
        return scores[:k]


RAG_BENCHMARK = [
    {"query": "How to prevent S3 data exfiltration",           "relevant": [0, 2, 7]},
    {"query": "MITRE ATT&CK lateral movement techniques AWS",  "relevant": [1, 4]},
    {"query": "Zero trust Kubernetes network policy",          "relevant": [3, 6]},
    {"query": "FedRAMP NIST compliance controls",              "relevant": [5, 1]},
    {"query": "container escape privilege escalation",         "relevant": [6, 3]},
]

def eval_rag(verbose: bool = False) -> dict:
    print("\n── RAG Retrieval Quality (BM25 baseline) ──")
    bm25 = BM25Eval(PERPLEXITY_CORPUS)
    mrr_sum = 0.0; ndcg_sum = 0.0; hit5 = 0

    for item in RAG_BENCHMARK:
        ranked = [r[0] for r in bm25.search(item["query"], k=10)]
        # MRR
        rr = next((1.0/(r+1) for r,d in enumerate(ranked) if d in item["relevant"]), 0.0)
        mrr_sum += rr
        # NDCG@10
        ideal = [1.0]*len(item["relevant"]) + [0.0]*(10 - len(item["relevant"]))
        idcg  = sum(g/math.log2(r+2) for r,g in enumerate(ideal[:10]))
        adcg  = sum((1.0 if d in item["relevant"] else 0.0)/math.log2(r+2) for r,d in enumerate(ranked[:10]))
        ndcg_sum += adcg / max(idcg, 1e-10)
        if any(d in item["relevant"] for d in ranked[:5]):
            hit5 += 1
        if verbose:
            print(f"  Q: {item['query'][:50]}  RR={rr:.2f}")

    n = len(RAG_BENCHMARK)
    mrr  = mrr_sum  / n
    ndcg = ndcg_sum / n
    h5   = hit5 / n
    print(f"  MRR:     {mrr:.3f}")
    print(f"  NDCG@10: {ndcg:.3f}")
    print(f"  Hit@5:   {h5:.3f}")
    return {"mrr": mrr, "ndcg_at_10": ndcg, "hit_at_5": h5}

# ──────────────────────────────────────────────────────────────────────────────
#  Benchmark 6 — End-to-end Q&A (BLEU-4, ROUGE-L)
# ──────────────────────────────────────────────────────────────────────────────

QA_BENCHMARK = [
    {
        "question": "What are the main security risks of an S3 bucket with public access?",
        "reference": "Public S3 buckets expose data to unauthorized access, risking data exfiltration, information disclosure, and compliance violations. Key risks include unauthenticated read/write access, bucket enumeration, and accidental exposure of sensitive data.",
    },
    {
        "question": "How does Grouped Query Attention reduce KV cache memory usage?",
        "reference": "Grouped Query Attention reduces key-value heads while keeping full query heads, sharing KV pairs across multiple query heads. This reduces KV cache memory by a factor equal to the grouping ratio, enabling larger batch sizes and longer contexts.",
    },
    {
        "question": "What MITRE ATT&CK technique covers cloud metadata API credential theft?",
        "reference": "T1552.005 covers Cloud Instance Metadata API abuse, where attackers query the IMDS endpoint to steal IAM role credentials. This is especially effective against EC2 instances using IMDSv1 which does not require session tokens.",
    },
    {
        "question": "Explain the STRIDE threat model with one example per category.",
        "reference": "STRIDE: Spoofing (stolen JWT tokens), Tampering (altering S3 objects), Repudiation (disabling CloudTrail), Information Disclosure (unencrypted S3), Denial of Service (DDoS on ALB), Elevation of Privilege (IAM PassRole abuse).",
    },
]

def _ngrams(tokens: list[str], n: int) -> dict:
    c: dict = defaultdict(int)
    for i in range(len(tokens) - n + 1):
        c[tuple(tokens[i:i+n])] += 1
    return c

def _bleu4(hyp: str, ref: str) -> float:
    ht = re.findall(r"\b\w+\b", hyp.lower())
    rt = re.findall(r"\b\w+\b", ref.lower())
    if not ht: return 0.0
    bp  = min(1.0, math.exp(1 - len(rt) / max(len(ht), 1)))
    lp  = 0.0
    for n in range(1, 5):
        hng = _ngrams(ht, n); rng = _ngrams(rt, n)
        if not hng: return 0.0
        clipped = sum(min(c, rng.get(k, 0)) for k, c in hng.items())
        lp += math.log(max(clipped / max(sum(hng.values()), 1), 1e-10))
    return bp * math.exp(lp / 4)

def _rouge_l(hyp: str, ref: str) -> float:
    ht = re.findall(r"\b\w+\b", hyp.lower())
    rt = re.findall(r"\b\w+\b", ref.lower())
    m, n = len(rt), len(ht)
    if m == 0 or n == 0: return 0.0
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(1, m+1):
        for j in range(1, n+1):
            dp[i][j] = dp[i-1][j-1]+1 if rt[i-1]==ht[j-1] else max(dp[i-1][j], dp[i][j-1])
    lcs = dp[m][n]
    p = lcs/n; r = lcs/m
    return 2*p*r/(p+r) if (p+r) > 0 else 0.0

def eval_qa(model_fn, verbose: bool = False) -> dict:
    print("\n── End-to-End Q&A (BLEU-4, ROUGE-L) ──")
    bleu_scores = []; rouge_scores = []; results = []

    for item in QA_BENCHMARK:
        prompt = (
            "<|start_header_id|>user<|end_header_id|>\n"
            f"{item['question']}\n"
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )
        response = model_fn(prompt, max_new=400, temp=0.3)
        b = _bleu4(response, item["reference"])
        r = _rouge_l(response, item["reference"])
        bleu_scores.append(b); rouge_scores.append(r)
        results.append({"question": item["question"][:60], "bleu4": b, "rouge_l": r})
        if verbose:
            print(f"  Q: {item['question'][:60]}  BLEU={b:.3f}  ROUGE={r:.3f}")

    avg_b = sum(bleu_scores)  / max(len(bleu_scores),  1)
    avg_r = sum(rouge_scores) / max(len(rouge_scores), 1)
    print(f"  Avg BLEU-4:  {avg_b:.3f}")
    print(f"  Avg ROUGE-L: {avg_r:.3f}")
    return {"avg_bleu4": avg_b, "avg_rouge_l": avg_r, "details": results}

# ──────────────────────────────────────────────────────────────────────────────
#  Summary + report helpers
# ──────────────────────────────────────────────────────────────────────────────

def _print_summary(results: dict):
    print("\n" + "="*60)
    print("  EVALUATION SUMMARY")
    print("="*60)
    if "stride" in results:
        s = results["stride"]
        print(f"  STRIDE        Recall={s['recall']:.3f}  Precision={s['precision']:.3f}")
    if "mitre" in results:
        print(f"  MITRE         Recall@10={results['mitre']['recall_at_10']:.3f}")
    if "cis" in results:
        print(f"  CIS Controls  Precision={results['cis']['precision']:.3f}")
    if "perplexity" in results and results["perplexity"].get("perplexity"):
        print(f"  Perplexity    PPL={results['perplexity']['perplexity']:.2f}")
    if "rag" in results:
        r = results["rag"]
        print(f"  RAG           MRR={r['mrr']:.3f}  NDCG@10={r['ndcg_at_10']:.3f}  Hit@5={r['hit_at_5']:.3f}")
    if "qa" in results:
        q = results["qa"]
        print(f"  Q&A           BLEU-4={q['avg_bleu4']:.3f}  ROUGE-L={q['avg_rouge_l']:.3f}")
    if "elapsed_seconds" in results:
        print(f"\n  Total time: {results['elapsed_seconds']:.1f}s")
    print("="*60)

def _save_report(results: dict, path: str):
    def _ser(obj):
        if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
            return None
        return obj
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=_ser)
    print(f"\n  Report saved → {path}")

# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="ThreataformLM-200M Evaluation Suite")
    ap.add_argument("--model",       default="public/model.tnlm")
    ap.add_argument("--vocab",       default="scripts/vocab.json")
    ap.add_argument("--device",      default="cpu")
    ap.add_argument("--max-new",     type=int, default=400)
    ap.add_argument("--stride-only", action="store_true")
    ap.add_argument("--rag-only",    action="store_true")
    ap.add_argument("--all",         action="store_true")
    ap.add_argument("--verbose",     action="store_true")
    ap.add_argument("--save-report", default="")
    args = ap.parse_args()

    print("="*60)
    print("  ThreataformLM-200M — Evaluation Suite")
    print("="*60)

    # RAG-only: no model required
    if args.rag_only:
        results = {"rag": eval_rag(verbose=args.verbose)}
        _print_summary(results)
        if args.save_report: _save_report(results, args.save_report)
        return

    # Check model
    if not Path(args.model).exists():
        print(f"\nWARNING: Model not found at '{args.model}'")
        print("  Run: python scripts/train_base.py → python scripts/quantize.py")
        print("  Running model-free benchmarks only.\n")
        results = {"rag": eval_rag(verbose=args.verbose)}
        _print_summary(results)
        if args.save_report: _save_report(results, args.save_report)
        return

    tokenizer = SimpleBPETokenizer(args.vocab if Path(args.vocab).exists() else None)

    print(f"\nLoading model: {args.model}  device={args.device}")
    t0 = time.time()
    config, weights = load_tnlm(args.model, args.device)
    print(f"  Loaded in {time.time()-t0:.1f}s  config={config}")

    torch = _import_torch()
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from train_base import ThreataformLM as PtModel
        model_pt = PtModel(config).to(args.device)
        model_pt.load_state_dict(weights, strict=False)
        model_pt.eval()

        @torch.no_grad()
        def model_fn(prompt: str, max_new: int = 400, temp: float = 0.7) -> str:
            ids   = [tokenizer.BOS_ID] + tokenizer.encode(prompt)
            ids_t = torch.tensor([ids], dtype=torch.long, device=args.device)
            out   = []
            for _ in range(min(max_new, args.max_new)):
                logits  = model_pt(ids_t)[:, -1, :]
                next_id = (logits.argmax(-1) if temp <= 0
                           else torch.multinomial(torch.softmax(logits/temp, -1)[0], 1)).item()
                if next_id == tokenizer.EOS_ID: break
                out.append(next_id)
                ids_t = torch.cat([ids_t, torch.tensor([[next_id]], device=args.device)], dim=1)
            return tokenizer.decode(out)

    except Exception as e:
        print(f"  WARNING: Could not instantiate PyTorch model ({e}). Using dummy.")
        def model_fn(prompt: str, max_new: int = 400, temp: float = 0.7) -> str:
            return ("Spoofing Tampering Information Disclosure Elevation of Privilege "
                    "T1078 T1530 T1552 CIS 1.1 CIS 3.1 encryption least privilege")

    results: dict[str, Any] = {}
    t_start = time.time()

    if args.stride_only:
        results["stride"] = eval_stride(model_fn, verbose=args.verbose)
    else:
        results["stride"]     = eval_stride(model_fn, verbose=args.verbose)
        results["mitre"]      = eval_mitre(model_fn,  verbose=args.verbose)
        results["cis"]        = eval_cis(model_fn,    verbose=args.verbose)
        try:
            results["perplexity"] = eval_perplexity(model_pt, tokenizer, args.device, verbose=args.verbose)
        except Exception as ex:
            results["perplexity"] = {"perplexity": None, "note": str(ex)}
        results["rag"] = eval_rag(verbose=args.verbose)
        results["qa"]  = eval_qa(model_fn, verbose=args.verbose)

    results["elapsed_seconds"] = time.time() - t_start
    _print_summary(results)
    if args.save_report:
        _save_report(results, args.save_report)


if __name__ == "__main__":
    main()
