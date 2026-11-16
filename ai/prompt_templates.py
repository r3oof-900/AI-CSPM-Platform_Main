"""
AI-CSPM Prompt Templates & Shared AI Helpers for Contextual Least-Privilege Remediation
"""

import os
import re
import json
import time
from typing import Dict, Any, Tuple, Optional


SYSTEM_REMEDIATION_PROMPT = """You are AI-CSPM, an advanced cloud security reasoning agent specializing in Multi-Tier Cloud & Kubernetes architectures.
Your task is to analyze cross-layer attack paths (Kubernetes Workload -> Cloud IAM Role -> Policy / KMS / Storage Vault) and synthesize strictly scoped, least-privilege Infrastructure-as-Code (Terraform HCL) remediations.

Guiding Principles:
1. Match the Terraform resource type to the exact attack vector:
   - For 'iam_policy': remediate 'aws_iam_policy', replace wildcard Resource '*' with the exact CMK ARN, and enforce 'kms:EncryptionContext:aws:s3:arn'.
   - For 'kms_resource_policy': remediate 'aws_kms_key', restrict Principal to the exact authorized IAM Role ARN, and enforce 'kms:EncryptionContext' or 'kms:ViaService'.
   - For 's3_resource_policy': remediate 'aws_s3_bucket_policy', replace Principal '*' with the exact authorized IAM Role ARN (do NOT invent KMS keys or aws_iam_policy), and enforce 'aws:PrincipalArn'.
2. Copy every provided ARN, resource name, and bucket name VERBATIM from [VERIFIED GRAPH IDENTIFIERS]. Never invent, truncate, or alter UUIDs or IAM role paths.
3. Eliminate all un-scoped wildcard '*' grants in Resource or Principal.
4. Provide a clear threat narrative explaining why single-layer scanners and siloed linters missed this cross-layer path.
"""


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _parse_dotenv_fallback(path: str) -> Dict[str, str]:
    """Minimal fallback parser for .env files when python-dotenv is absent."""
    result: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if not key:
                    continue
                if len(val) >= 1 and val[0] in ('"', "'"):
                    q = val[0]
                    mq = re.match(rf"^{re.escape(q)}(.*?){re.escape(q)}(?:\s+#.*|\s*)$", val)
                    val = mq.group(1) if mq else val.strip(q)
                else:
                    val = re.sub(r"\s+#.*$", "", val).strip()
                result[key] = val
    except OSError:
        return {}
    return result


def _read_dotenv(path: str) -> Dict[str, str]:
    """Parses a .env file with python-dotenv (handles export, spaces, quotes, comments)."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return _parse_dotenv_fallback(path)
    try:
        return {k: v for k, v in dotenv_values(path).items() if v is not None}
    except OSError:
        return {}


def load_env_secret(var_name: str, default: str = "") -> str:
    """
    Reads a setting from the process environment, then from a .env file.
    The .env lookup is limited to the current working directory and the project root,
    so an unrelated .env in a parent directory is never picked up.
    """
    val = os.getenv(var_name)
    if val:
        return val
    for base in dict.fromkeys([os.getcwd(), _PROJECT_ROOT]):
        env_file = os.path.join(base, ".env")
        if os.path.isfile(env_file):
            found = _read_dotenv(env_file).get(var_name, "")
            if found:
                return found.strip()
    return default


def load_gemini_config() -> Tuple[str, int]:
    """Loads (model_name, timeout_seconds) safely from env/.env with validation."""
    model_name = load_env_secret("GEMINI_MODEL", "gemini-flash-lite-latest") or "gemini-flash-lite-latest"
    raw_timeout = load_env_secret("GEMINI_TIMEOUT", "25")
    try:
        timeout = max(1, int(raw_timeout))
    except (TypeError, ValueError):
        timeout = 25
    return model_name, timeout


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
    """Returns 'iam_policy', 's3_identity_policy', 'kms_resource_policy', or 's3_resource_policy' based on path nodes."""
    types = {str(n.get("type", "")) for n in (nodes or [])}
    has_policy = bool(types & {"IAM_POLICY", "NodeType.IAM_POLICY"})
    has_key = bool(types & {"KMS_KEY", "NodeType.KMS_KEY"})
    has_bucket = bool(types & {"S3_BUCKET", "NodeType.S3_BUCKET"})

    if has_policy:
        if has_bucket and not has_key:
            return "s3_identity_policy"
        return "iam_policy"
    if has_key:
        return "kms_resource_policy"
    if has_bucket:
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


def _pair_from_nodes(member_nodes: list) -> Dict[str, Any]:
    pair: Dict[str, Any] = {"key_name": "", "key_arn": None, "bucket_name": "", "bucket_arn": None}
    for n in member_nodes or []:
        ntype = str(n.get("type", ""))
        if ntype in ("KMS_KEY", "NodeType.KMS_KEY"):
            pair["key_name"] = n.get("name") or pair["key_name"]
            pair["key_arn"] = n.get("key_arn") or pair["key_arn"]
        elif ntype in ("S3_BUCKET", "NodeType.S3_BUCKET"):
            pair["bucket_name"] = n.get("name") or pair["bucket_name"]
            pair["bucket_arn"] = n.get("bucket_arn") or pair["bucket_arn"]
    return pair


def collect_group_pairs(nodes: list, group_members: Optional[list]) -> list:
    members = group_members if group_members else [nodes]
    seen, pairs = set(), []
    for m in members:
        pair = _pair_from_nodes(m)
        sig = (pair["key_name"], pair["bucket_name"])
        if sig not in seen:
            seen.add(sig)
            pairs.append(pair)
    return pairs


def build_scoped_kms_policy_hcl(nodes: list, group_members: Optional[list] = None) -> str:
    """Builds a valid scoped least-privilege Terraform HCL block matching the path's vector type."""
    vector_type = detect_attack_path_vector(nodes)
    _, policy_name, key_name, bucket_name, is_live = extract_target_refs(nodes)
    key_arn = None
    bucket_arn = None
    role_name = "authorized_role"
    role_arn = None
    has_bucket = False
    has_tf_source = False
    has_json_arn_source = False
    for n in nodes or []:
        src = str(n.get("source_file") or "").lower()
        if src.endswith(".tf"):
            has_tf_source = True
        elif src.endswith(".json") and (n.get("key_arn") or n.get("bucket_arn") or n.get("role_arn")):
            has_json_arn_source = True
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

    use_explicit_arns = is_live or (has_json_arn_source and not has_tf_source)
    bucket_tf_ident = _sanitize_tf_ident(bucket_name, "target_vault")
    key_tf_ident = _sanitize_tf_ident(key_name.split("/")[-1], "target_cmk")
    bucket_expr = (
        f'"{bucket_arn}"'
        if (use_explicit_arns and bucket_arn)
        else (f'"arn:aws:s3:::{bucket_name}"' if use_explicit_arns else f"aws_s3_bucket.{bucket_tf_ident}.arn")
    )

    if vector_type == "s3_resource_policy":
        principal_expr = (
            f'"{role_arn}"'
            if (use_explicit_arns and role_arn)
            else (f'"{role_name}"' if use_explicit_arns else f"aws_iam_role.{_sanitize_tf_ident(role_name, 'role')}.arn")
        )
        bucket_ref_id = f'"{bucket_name}"' if use_explicit_arns else f"aws_s3_bucket.{bucket_tf_ident}.id"
        s3_obj_resource = f"{bucket_expr.strip(chr(34))}/*" if use_explicit_arns else f"${{{bucket_expr}}}/*"
        preserved_actions = next(
            (n.get("allowed_actions") for n in (nodes or []) if n.get("allowed_actions")),
            None,
        )
        s3_actions_json = json.dumps(preserved_actions or ["s3:GetObject"])
        return f"""# NOTE: Confirm this IAM role legitimately requires bucket access; otherwise remove the Allow statement instead.
resource "aws_s3_bucket_policy" "scoped_{bucket_tf_ident}_policy" {{
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
        Action   = {s3_actions_json}
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
        principal_expr = (
            f'"{role_arn}"'
            if (use_explicit_arns and role_arn)
            else (f'"{role_name}"' if use_explicit_arns else f"aws_iam_role.{_sanitize_tf_ident(role_name, 'role')}.arn")
        )
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

    remediated_policy_name = policy_name.replace("Overprivileged", "Scoped")
    if remediated_policy_name == policy_name and not remediated_policy_name.startswith("Scoped"):
        remediated_policy_name = f"Scoped-{policy_name}"

    role_tf_ident = _sanitize_tf_ident(role_name, "role")
    role_ref_val = (
        f'"{role_arn}"'
        if (use_explicit_arns and role_arn)
        else (f'"{role_name}"' if use_explicit_arns else f"aws_iam_role.{role_tf_ident}.name")
    )

    pairs = collect_group_pairs(nodes, group_members)
    if len(pairs) > 1 and vector_type in ("iam_policy", "s3_identity_policy"):
        clean_policy_res = f"{clean_policy_res}_{role_tf_ident}"   # اسم فريد لكل دور
        policy_attach = (
            f'\n\nresource "aws_iam_role_policy_attachment" "{clean_policy_res}_attach" {{\n'
            f'  role       = {role_ref_val}\n'
            f'  policy_arn = aws_iam_policy.{clean_policy_res}.arn\n}}'
        )

        def _bucket_arn_expr(pr):
            ident = _sanitize_tf_ident(pr["bucket_name"], "target_vault")
            if use_explicit_arns:
                arn = pr["bucket_arn"] or f"arn:aws:s3:::{pr['bucket_name']}"
                return f'"{arn}"', f'"{arn}/*"'
            return f"aws_s3_bucket.{ident}.arn", f'"${{aws_s3_bucket.{ident}.arn}}/*"'

        stmts = []
        if vector_type == "s3_identity_policy":
            res_items = []
            for pr in pairs:
                a, b = _bucket_arn_expr(pr)
                res_items += [a, b]
            acts = next((n.get("allowed_actions") for n in (nodes or []) if n.get("allowed_actions")), None)
            body = ",\n          ".join(res_items)
            stmts.append(
                '      {\n        Sid    = "ScopedStorageAccessOnly"\n        Effect = "Allow"\n'
                f'        Action   = {json.dumps(acts or ["s3:GetObject"])}\n'
                f'        Resource = [\n          {body}\n        ]\n      }}'
            )
            desc = f"Strictly scoped to {len(pairs)} authorized S3 storage buckets"
        else:
            for i, pr in enumerate(pairs, 1):
                kid = _sanitize_tf_ident(str(pr["key_name"]).split("/")[-1], "target_cmk")
                if use_explicit_arns and pr["key_arn"]:
                    key_expr = f'"{pr["key_arn"]}"'
                elif use_explicit_arns and str(pr["key_name"]).startswith("arn:"):
                    key_expr = f'"{pr["key_name"]}"'
                else:
                    key_expr = f"aws_kms_key.{kid}.arn"
                a, b = _bucket_arn_expr(pr)
                stmts.append(
                    f'      {{\n        Sid    = "ScopedKeyDecryption{i}"\n        Effect = "Allow"\n'
                    '        Action = [\n          "kms:Decrypt",\n          "kms:DescribeKey"\n        ]\n'
                    f'        Resource = {key_expr}\n'
                    '        Condition = {\n          StringLike = {\n            "kms:EncryptionContext:aws:s3:arn" = [\n'
                    f'              {a},\n              {b}\n            ]\n          }}\n        }}\n      }}'
                )
            desc = f"Strictly scoped to {len(pairs)} explicit CMK/S3 vault pairs with S3 EncryptionContext constraint"
        stmts_txt = ",\n".join(stmts)
        return (
            f'resource "aws_iam_policy" "{clean_policy_res}" {{\n'
            f'  name        = "{remediated_policy_name}"\n'
            f'  description = "Remediated by AI-CSPM: {desc}"\n\n'
            '  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [\n'
            f'{stmts_txt}\n    ]\n  }})\n}}' + policy_attach
        )

    if vector_type == "s3_identity_policy":
        if use_explicit_arns and bucket_arn:
            s3_res_list = f'[\n          "{bucket_arn}",\n          "{bucket_arn}/*"\n        ]'
        elif not use_explicit_arns:
            s3_res_list = f'[\n          aws_s3_bucket.{bucket_tf_ident}.arn,\n          "${{aws_s3_bucket.{bucket_tf_ident}.arn}}/*"\n        ]'
        else:
            s3_res_list = f'[\n          "arn:aws:s3:::{bucket_name}",\n          "arn:aws:s3:::{bucket_name}/*"\n        ]'

        preserved_actions = next(
            (n.get("allowed_actions") for n in (nodes or []) if n.get("allowed_actions")),
            None,
        )
        s3_actions_json = json.dumps(preserved_actions or ["s3:GetObject"])

        return f"""resource "aws_iam_policy" "{clean_policy_res}" {{
  name        = "{remediated_policy_name}"
  description = "Remediated by AI-CSPM: Strictly scoped to authorized S3 storage bucket"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "ScopedStorageAccessOnly"
        Effect = "Allow"
        Action   = {s3_actions_json}
        Resource = {s3_res_list}
      }}
    ]
  }})
}}

resource "aws_iam_role_policy_attachment" "{clean_policy_res}_attach" {{
  role       = {role_ref_val}
  policy_arn = aws_iam_policy.{clean_policy_res}.arn
}}"""

    if use_explicit_arns:
        if key_arn:
            resource_expr = f'"{key_arn}"'
        elif key_name.startswith("arn:"):
            resource_expr = f'"{key_name}"'
        else:
            resource_expr = f"aws_kms_key.{key_tf_ident}.arn"
    else:
        resource_expr = f"aws_kms_key.{key_tf_ident}.arn"

    if use_explicit_arns and bucket_arn:
        enc_cond_block = f"""Condition = {{
          StringLike = {{
            "kms:EncryptionContext:aws:s3:arn" = [
              "{bucket_arn}",
              "{bucket_arn}/*"
            ]
          }}
        }}"""
    elif not use_explicit_arns:
        enc_cond_block = f"""Condition = {{
          StringLike = {{
            "kms:EncryptionContext:aws:s3:arn" = [
              aws_s3_bucket.{bucket_tf_ident}.arn,
              "${{aws_s3_bucket.{bucket_tf_ident}.arn}}/*"
            ]
          }}
        }}"""
    else:
        enc_cond_block = f"""Condition = {{
          StringLike = {{
            "kms:EncryptionContext:aws:s3:arn" = [
              "arn:aws:s3:::{bucket_name}",
              "arn:aws:s3:::{bucket_name}/*"
            ]
          }}
        }}"""

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
        {enc_cond_block}
      }}
    ]
  }})
}}

resource "aws_iam_role_policy_attachment" "{clean_policy_res}_attach" {{
  role       = {role_ref_val}
  policy_arn = aws_iam_policy.{clean_policy_res}.arn
}}"""


def extract_verified_refs(nodes: list) -> Dict[str, Any]:
    """Extracts exact verified names, ARNs, and S3 allowed actions from attack path node dicts."""
    refs: Dict[str, Any] = {
        "vector_type": detect_attack_path_vector(nodes),
        "workload_name": "compromised-workload",
        "policy_name": None,
        "role_name": None,
        "role_arn": None,
        "key_name": None,
        "key_arn": None,
        "bucket_name": None,
        "bucket_arn": None,
        "allowed_actions": None,
        "use_explicit_arns": False,
    }
    has_tf = False
    has_live_or_json_arn = False
    for n in nodes or []:
        src = str(n.get("source_file") or "").lower()
        if src.endswith(".tf"):
            has_tf = True
        elif src.startswith(("aws://", "k8s://", "kubectl://")) or (
            src.endswith(".json") and (n.get("key_arn") or n.get("bucket_arn") or n.get("role_arn"))
        ):
            has_live_or_json_arn = True

        ntype = str(n.get("type", ""))
        if ntype in ("WORKLOAD", "NodeType.WORKLOAD"):
            refs["workload_name"] = n.get("name") or refs["workload_name"]
        elif ntype in ("IAM_ROLE", "NodeType.IAM_ROLE"):
            refs["role_name"] = n.get("name") or refs["role_name"]
            refs["role_arn"] = n.get("role_arn") or refs["role_arn"]
        elif ntype in ("IAM_POLICY", "NodeType.IAM_POLICY"):
            refs["policy_name"] = n.get("name") or refs["policy_name"]
        elif ntype in ("KMS_KEY", "NodeType.KMS_KEY"):
            refs["key_name"] = n.get("name") or refs["key_name"]
            refs["key_arn"] = n.get("key_arn") or refs["key_arn"]
        elif ntype in ("S3_BUCKET", "NodeType.S3_BUCKET"):
            refs["bucket_name"] = n.get("bucket_name") or n.get("name") or refs["bucket_name"]
            refs["bucket_arn"] = n.get("bucket_arn") or refs["bucket_arn"]
            if n.get("allowed_actions"):
                refs["allowed_actions"] = list(n["allowed_actions"])
    refs["use_explicit_arns"] = has_live_or_json_arn and not has_tf
    return refs


_VECTOR_GUIDANCE = {
    "s3_resource_policy": (
        "1. Synthesize ONLY an 'aws_s3_bucket_policy' Terraform HCL block (do NOT output aws_iam_policy or KMS keys).\n"
        "2. Replace Principal '*' with the EXACT IAM Role ARN from [VERIFIED GRAPH IDENTIFIERS] and enforce a StringEquals condition on 'aws:PrincipalArn'.\n"
        "3. Explain how scoping the S3 Bucket Policy prevents unauthorized roles/workloads from reading the bucket.\n"
        "4. State the quantified blast-radius reduction.",
        'resource \\"aws_s3_bucket_policy\\" ...',
    ),
    "kms_resource_policy": (
        "1. Synthesize ONLY an 'aws_kms_key' Terraform HCL block restricting the key policy Principal to the EXACT IAM Role ARN.\n"
        "2. Enforce 'kms:EncryptionContext:aws:s3:arn' (when a bucket is present) or 'kms:ViaService'.\n"
        "3. Explain how scoping the KMS Key Resource Policy mitigates direct decryption exposure.\n"
        "4. State the quantified blast-radius reduction.",
        'resource \\"aws_kms_key\\" ...',
    ),
    "iam_policy": (
        "1. Synthesize ONLY an 'aws_iam_policy' Terraform HCL block replacing wildcard Resource '*' with the EXACT CMK ARN (or Terraform reference when .tf) and enforcing 'kms:EncryptionContext:aws:s3:arn' matching the target bucket.\n"
        "2. Explain how this mitigates the multi-tier compromise chain.\n"
        "3. State the quantified blast-radius reduction.",
        'resource \\"aws_iam_policy\\" ...',
    ),
}


def get_vector_remediation_guidance(vector_type: str) -> Tuple[str, str]:
    """Returns (numbered_instructions, schema_example) tailored to the attack path's vector type."""
    return _VECTOR_GUIDANCE.get(vector_type, _VECTOR_GUIDANCE["iam_policy"])


def validate_and_repair_remediated_hcl(remediated_code: str, nodes: list) -> Tuple[str, bool]:
    """
    Verifies LLM-synthesized HCL matches the vector resource type, removes wildcards,
    and preserves verified ARNs without hallucination. Falls back to build_scoped_kms_policy_hcl if invalid.
    """
    code = (remediated_code or "").strip()
    if not code:
        return build_scoped_kms_policy_hcl(nodes), True

    refs = extract_verified_refs(nodes)
    vector_type = refs["vector_type"]

    expected_res = {
        "s3_resource_policy": 'resource "aws_s3_bucket_policy"',
        "kms_resource_policy": 'resource "aws_kms_key"',
        "iam_policy": 'resource "aws_iam_policy"',
    }.get(vector_type, 'resource "aws_iam_policy"')

    if expected_res not in code:
        return build_scoped_kms_policy_hcl(nodes), True

    if vector_type == "s3_resource_policy":
        if re.search(r'(?:Principal\s*=|"Principal"\s*:)\s*["\']\*["\']', code) or re.search(
            r'AWS\s*[:=]\s*["\']\*["\']', code
        ):
            return build_scoped_kms_policy_hcl(nodes), True
        if refs["use_explicit_arns"]:
            if refs["role_arn"] and refs["role_arn"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True
            if refs["bucket_name"] and refs["bucket_name"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True
    elif vector_type == "kms_resource_policy":
        if re.search(r'AWS\s*[:=]\s*["\']\*["\']', code):
            return build_scoped_kms_policy_hcl(nodes), True
        if refs["use_explicit_arns"]:
            if refs["role_arn"] and refs["role_arn"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True
            if refs["bucket_arn"] and refs["bucket_arn"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True
    else:
        if re.search(r'(?:Resource\s*=|"Resource"\s*:)\s*(?:\[\s*)?["\']\*["\']', code):
            return build_scoped_kms_policy_hcl(nodes), True
        if refs["use_explicit_arns"]:
            if refs["key_arn"] and refs["key_arn"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True
            if refs["bucket_arn"] and refs["bucket_arn"] not in code:
                return build_scoped_kms_policy_hcl(nodes), True

    return code, False


def post_gemini_json(
    api_endpoint: str,
    api_key: str,
    prompt: str,
    timeout: int,
    max_attempts: int = 3,
    backoff_sec: float = 1.5,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Posts a deterministic (temperature=0.0) JSON generation request to Gemini with retry
    on transient 429/503 responses. Returns (parsed_dict, error_message).
    """
    import requests

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
        },
    }
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": api_key,
    }

    last_err: Optional[str] = None
    attempts = max(1, int(max_attempts))
    for attempt in range(attempts):
        resp = requests.post(api_endpoint, headers=headers, json=payload, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            return parse_llm_json_response(raw_text), None
        last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
        if resp.status_code in (429, 503) and attempt + 1 < attempts:
            time.sleep(backoff_sec * (attempt + 1))
            continue
        break
    return None, last_err


def generate_remediation_user_prompt(attack_path_dict: dict, vulnerable_code: str) -> str:
    nodes = attack_path_dict.get("nodes") or []
    refs = extract_verified_refs(nodes)
    guidance, _ = get_vector_remediation_guidance(refs["vector_type"])

    verified_lines = [
        f"- Attack Vector Type: {refs['vector_type']}",
        f"- Workload Name: {refs['workload_name']}",
    ]
    if refs["role_name"] or refs["role_arn"]:
        verified_lines.append(f"- IAM Role Name: {refs['role_name']} | Exact Role ARN: {refs['role_arn']}")
    if refs["policy_name"]:
        verified_lines.append(f"- IAM Policy Name: {refs['policy_name']}")
    if refs["key_name"] or refs["key_arn"]:
        verified_lines.append(f"- KMS Key Name: {refs['key_name']} | Exact Key ARN: {refs['key_arn']}")
    if refs["bucket_name"] or refs["bucket_arn"]:
        verified_lines.append(f"- S3 Bucket Name: {refs['bucket_name']} | Exact Bucket ARN: {refs['bucket_arn']}")
    if refs["allowed_actions"]:
        verified_lines.append(f"- Preserved Non-Wildcard Actions: {json.dumps(refs['allowed_actions'])}")

    return f"""Analyze the following empirically proven cross-layer attack path and synthesize a least-privilege Terraform patch:

[VERIFIED GRAPH IDENTIFIERS — USE VERBATIM, DO NOT INVENT OR TRUNCATE ARNS]
{chr(10).join(verified_lines)}

[ATTACK PATH CONTEXT]
- Attack Path ID: {attack_path_dict.get('id')}
- Title: {attack_path_dict.get('title')}
- Severity: {attack_path_dict.get('severity')}
- Root Cause: {attack_path_dict.get('root_cause')}
- Impact: {attack_path_dict.get('impact')}

[ATTACK PATH HOPS]
{chr(10).join(attack_path_dict.get('steps', []))}

[VULNERABLE TERRAFORM / POLICY CODE]
```hcl
{vulnerable_code}
```

Please synthesize:
{guidance}
"""
