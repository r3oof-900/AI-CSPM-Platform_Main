"""
AI-CSPM Prompt Templates & Shared AI Helpers for Contextual Least-Privilege Remediation
"""

import os
import re
import json
from typing import Dict, Any, Tuple


SYSTEM_REMEDIATION_PROMPT = """You are AI-CSPM, an advanced cloud security reasoning agent specializing in Multi-Tier Cloud & Kubernetes architectures.
Your task is to analyze cross-layer attack paths (Kubernetes Workload -> Cloud IAM Role -> KMS CMK -> Storage Vault) and synthesize strictly scoped, least-privilege Infrastructure-as-Code (Terraform HCL) remediations.

Guiding Principles:
1. Eliminate all wildcard '*' grants on high-impact actions like kms:Decrypt, kms:Encrypt, and kms:DescribeKey.
2. Scope the 'Resource' field strictly to the explicit ARN of the authorized Customer Managed Key (CMK).
3. Enforce cryptographic conditions using 'kms:EncryptionContext' to bind decryption exclusively to the authorized S3 bucket.
4. Provide a clear threat narrative explaining why single-layer scanners (like Prowler, Checkov, and Access Analyzer) missed this threat.
5. Format the output with clear 'Original Flawed Code', 'Remediated Scoped Code', and 'Architectural Justification'.
"""


def load_env_secret(var_name: str) -> str:
    """Reads secret from environment or local .env file."""
    val = os.getenv(var_name, "")
    if not val:
        cur = os.path.dirname(os.path.abspath(__file__))
        for _ in range(4):
            env_file = os.path.join(cur, ".env")
            if os.path.exists(env_file):
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and line.startswith(f"{var_name}="):
                            return line.split("=", 1)[1].strip().strip('"').strip("'")
            cur = os.path.dirname(cur)
    return val


def parse_llm_json_response(raw_text: str) -> Dict[str, Any]:
    """Parses JSON from an LLM response, stripping optional markdown code fences."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned).strip()
    return json.loads(cleaned)


def _sanitize_tf_ident(name: str, fallback: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(name or "").strip()).strip("_").lower()
    if cleaned and cleaned[0].isdigit():
        cleaned = f"r_{cleaned}"
    return cleaned or fallback


def detect_attack_path_vector(nodes: list) -> str:
    """Returns 'iam_policy', 'kms_resource_policy', or 's3_resource_policy' based on path nodes."""
    types = {str(n.get("type", "")) for n in (nodes or [])}
    if types & {"IAM_POLICY", "NodeType.IAM_POLICY"}:
        return "iam_policy"
    if types & {"KMS_KEY", "NodeType.KMS_KEY"}:
        return "kms_resource_policy"
    if types & {"S3_BUCKET", "NodeType.S3_BUCKET"}:
        return "s3_resource_policy"
    return "iam_policy"


def extract_target_refs(nodes: list) -> Tuple[str, str, str, str, bool]:
    """
    Extracts (workload_name, policy_name, key_ref_name, bucket_ref_name, is_live_source)
    from attack path node dicts.
    """
    workload_name = "compromised-workload"
    policy_name = "ScopedKmsPolicy"
    key_name = "payment_key"
    bucket_name = "payment_vault"
    is_live = False

    for n in nodes or []:
        ntype = str(n.get("type", ""))
        name = n.get("name", "")
        src = str(n.get("source_file") or "")
        if src.startswith(("aws://", "k8s://", "kubectl://")):
            is_live = True
        if ntype in ("WORKLOAD", "NodeType.WORKLOAD"):
            workload_name = name or workload_name
        elif ntype in ("IAM_POLICY", "NodeType.IAM_POLICY"):
            policy_name = name or policy_name
        elif ntype in ("KMS_KEY", "NodeType.KMS_KEY"):
            key_name = name or key_name
        elif ntype in ("S3_BUCKET", "NodeType.S3_BUCKET"):
            bucket_name = name or bucket_name

    return workload_name, policy_name, key_name, bucket_name, is_live


def build_scoped_kms_policy_hcl(nodes: list) -> str:
    """Builds a valid scoped least-privilege Terraform HCL block matching the path's vector type."""
    vector_type = detect_attack_path_vector(nodes)
    _, policy_name, key_name, bucket_name, is_live = extract_target_refs(nodes)
    key_arn = None
    bucket_arn = None
    role_name = "authorized_role"
    role_arn = None
    has_bucket = False
    for n in nodes or []:
        ntype = str(n.get("type", ""))
        if ntype in ("KMS_KEY", "NodeType.KMS_KEY") and n.get("key_arn"):
            key_arn = n["key_arn"]
        elif ntype in ("S3_BUCKET", "NodeType.S3_BUCKET"):
            has_bucket = True
            if n.get("bucket_arn"):
                bucket_arn = n["bucket_arn"]
        elif ntype in ("IAM_ROLE", "NodeType.IAM_ROLE"):
            role_name = n.get("name") or role_name
            role_arn = n.get("role_arn")

    bucket_tf_ident = _sanitize_tf_ident(bucket_name, "target_vault")
    key_tf_ident = _sanitize_tf_ident(key_name.split("/")[-1], "target_cmk")
    bucket_expr = f'"{bucket_arn}"' if (is_live and bucket_arn) else (f'"arn:aws:s3:::{bucket_name}"' if is_live else f"aws_s3_bucket.{bucket_tf_ident}.arn")

    if vector_type == "s3_resource_policy":
        principal_expr = f'"{role_arn}"' if (is_live and role_arn) else (f'"{role_name}"' if is_live else f"aws_iam_role.{_sanitize_tf_ident(role_name, 'role')}.arn")
        bucket_ref_id = f'"{bucket_name}"' if is_live else f"aws_s3_bucket.{bucket_tf_ident}.id"
        s3_obj_resource = f"{bucket_expr.strip(chr(34))}/*" if is_live else f"${{{bucket_expr}}}/*"
        return f"""resource "aws_s3_bucket_policy" "scoped_{bucket_tf_ident}_policy" {{
  bucket = {bucket_ref_id}

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "ScopedRoleStorageAccessOnly"
        Effect = "Allow"
        Principal = {{
          AWS = {principal_expr}
        }}
        Action   = ["s3:GetObject"]
        Resource = "{s3_obj_resource}"
        Condition = {{
          StringEquals = {{
            "aws:PrincipalArn" = {principal_expr}
          }}
        }}
      }}
    ]
  }})
}}"""

    if vector_type == "kms_resource_policy":
        principal_expr = f'"{role_arn}"' if (is_live and role_arn) else (f'"{role_name}"' if is_live else f"aws_iam_role.{_sanitize_tf_ident(role_name, 'role')}.arn")
        enc_cond_block = (
            f"""
        Condition = {{
          StringEquals = {{
            "kms:EncryptionContext:aws:s3:arn" = {bucket_expr}
          }}
        }}"""
            if has_bucket
            else """
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.amazonaws.com"
          }
        }"""
        )
        return f"""resource "aws_kms_key" "{key_tf_ident}" {{
  enable_key_rotation = true

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "ScopedKeyResourcePolicy"
        Effect = "Allow"
        Principal = {{
          AWS = {principal_expr}
        }}
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"{enc_cond_block}
      }}
    ]
  }})
}}"""

    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", policy_name or "")
    camel_split = re.sub(r"overprivileged", "scoped", camel_split, flags=re.IGNORECASE)
    clean_policy_res = _sanitize_tf_ident(camel_split, "scoped_kms_policy")
    clean_policy_res = re.sub(r"^(?:scoped_?)+", "scoped_", clean_policy_res)
    if not clean_policy_res.startswith("scoped_"):
        clean_policy_res = f"scoped_{clean_policy_res}"

    if is_live:
        if key_arn:
            resource_expr = f'"{key_arn}"'
        elif key_name.startswith("arn:"):
            resource_expr = f'"{key_name}"'
        else:
            resource_expr = f"aws_kms_key.{key_tf_ident}.arn"
    else:
        resource_expr = f"aws_kms_key.{key_tf_ident}.arn"

    remediated_policy_name = policy_name.replace("Overprivileged", "Scoped")
    if remediated_policy_name == policy_name and not remediated_policy_name.startswith("Scoped"):
        remediated_policy_name = f"Scoped{policy_name}"

    return f"""resource "aws_iam_policy" "{clean_policy_res}" {{
  name        = "{remediated_policy_name}"
  description = "Remediated by AI-CSPM: Strictly scoped to {key_name} ARN with S3 EncryptionContext constraint"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "ScopedKeyDecryptionOnly"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        # REMEDIATED: Replaced '*' with explicit Customer Managed Key ARN
        Resource = {resource_expr}

        # REMEDIATED: Cryptographic binding strictly to authorized S3 vault
        Condition = {{
          StringEquals = {{
            "kms:EncryptionContext:aws:s3:arn" = {bucket_expr}
          }}
        }}
      }}
    ]
  }})
}}"""


def generate_remediation_user_prompt(attack_path_dict: dict, vulnerable_code: str) -> str:
    return f"""Analyze the following empirically proven cross-layer attack path and synthesize a least-privilege Terraform patch:

[ATTACK PATH CONTEXT]
- Attack Path ID: {attack_path_dict.get('id')}
- Title: {attack_path_dict.get('title')}
- Severity: {attack_path_dict.get('severity')}
- Root Cause: {attack_path_dict.get('root_cause')}
- Impact: {attack_path_dict.get('impact')}

[ATTACK PATH HOPS]
{chr(10).join(attack_path_dict.get('steps', []))}

[VULNERABLE TERRAFORM CODE]
```hcl
{vulnerable_code}
```

Please synthesize:
1. The exact remediated Terraform HCL block replacing the wildcard with the least-privilege CMK ARN and EncryptionContext condition.
2. An explanation of how this remediation mitigates the multi-tier compromise chain.
3. The quantified blast-radius reduction.
"""
