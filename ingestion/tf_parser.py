"""
AI-CSPM Dynamic Terraform & Cloud IaC Ingestion Parser
Extracts IAM Roles, IAM Policies, Attachments, KMS Keys, S3 Buckets, and Security Controls from Terraform HCL & JSON files.
"""

import os
import re
import ast
import json
import hcl2
from typing import List, Dict, Any, Tuple, Optional
try:
    from core.models import (
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        NodeType,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )
except (ImportError, ValueError):
    from ..core.models import (
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        NodeType,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )


class TerraformParser:
    def __init__(self):
        self.roles: List[IAMRoleNode] = []
        self.policies: List[IAMPolicyNode] = []
        self.kms_keys: List[KMSKeyNode] = []
        self.s3_buckets: List[S3BucketNode] = []
        self.attachments: List[Dict[str, str]] = []  # [{role: name/arn, policy: arn/name}]

        # Extracted environment variables and context
        self.variables: Dict[str, Any] = {}
        self.locals: Dict[str, Any] = {}
        self.account_id: str = "123456789012"
        self.region: str = "us-east-1"

        # Auxiliary security resources map for dynamic rule verification
        self.s3_public_access_blocks: Dict[str, Dict[str, Any]] = {}
        self.s3_logging_configs: Dict[str, Dict[str, Any]] = {}
        self.s3_lifecycle_configs: Dict[str, Dict[str, Any]] = {}
        self.s3_encryption_configs: Dict[str, Dict[str, Any]] = {}
        self.s3_kms_key_refs: Dict[str, str] = {}
        self.s3_bucket_policies: Dict[str, List[PolicyStatement]] = {}
        self.kms_key_policies: Dict[str, List[PolicyStatement]] = {}
        self.kms_aliases: Dict[str, str] = {}
        self.policy_documents: Dict[str, Dict[str, Any]] = {}
        self.parse_warnings: List[str] = []

    def _resolve_value(self, value: Any) -> Any:
        """Recursively resolves ${var.*} and ${local.*} interpolations across strings, lists, and dicts."""
        if isinstance(value, str):
            return self._resolve_interpolated_string(value)
        if isinstance(value, list):
            return [self._resolve_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve_value(v) for k, v in value.items()}
        return value

    def _extract_embedded_json(self, value: Any) -> Optional[Dict[str, Any]]:
        """Extracts JSON/policy dict from jsonencode(...), data.aws_iam_policy_document.*.json, or raw JSON string."""
        if isinstance(value, list) and len(value) > 0:
            value = value[0]

        if isinstance(value, dict):
            return self._resolve_value(value)

        if not isinstance(value, str):
            return None

        clean_val = value.strip()

        # Resolve data.aws_iam_policy_document.<name>.json references
        doc_ref = clean_val
        if doc_ref.startswith("${") and doc_ref.endswith("}"):
            doc_ref = doc_ref[2:-1].strip()
        if doc_ref.startswith("data.aws_iam_policy_document.") and doc_ref.endswith(".json"):
            parts = doc_ref.split(".")
            if len(parts) >= 3 and parts[2] in self.policy_documents:
                return self._resolve_value(self.policy_documents[parts[2]])

        # Clean terraform wrapper ${jsonencode(...)}
        if clean_val.startswith("${jsonencode(") and clean_val.endswith(")}"):
            inner = clean_val[len("${jsonencode(") : -len(")}")]
            try:
                return self._resolve_value(ast.literal_eval(inner))
            except Exception:
                try:
                    return self._resolve_value(json.loads(inner))
                except Exception as exc:
                    self.parse_warnings.append(f"Failed to parse jsonencode block: {exc}")

        try:
            return self._resolve_value(json.loads(clean_val))
        except Exception:
            resolved_str = self._resolve_interpolated_string(clean_val)
            if resolved_str != clean_val:
                try:
                    return json.loads(resolved_str)
                except Exception as exc:
                    self.parse_warnings.append(f"Failed to parse resolved JSON policy string: {exc}")

        return None

    def _resolve_interpolated_string(self, text: str) -> str:
        """Resolves ${var.*} and ${local.*} based on discovered variables and locals."""
        if not isinstance(text, str):
            return str(text)

        resolved = text
        for _ in range(3):
            prev = resolved
            for var_name, var_val in self.variables.items():
                pattern = re.compile(r"\$\{\s*var\." + re.escape(var_name) + r"\s*\}")
                resolved = pattern.sub(str(var_val), resolved)
            for loc_name, loc_val in self.locals.items():
                pattern = re.compile(r"\$\{\s*local\." + re.escape(loc_name) + r"\s*\}")
                resolved = pattern.sub(str(loc_val), resolved)
            if resolved == prev:
                break

        # Default replace known placeholders
        resolved = resolved.replace("${var.aws_account_id}", self.account_id)
        resolved = resolved.replace("${var.aws_region}", self.region)
        return resolved

    def parse_directory(self, dir_path: str):
        """Scans all .tf, .tfvars, and .json files in the specified directory."""
        if not os.path.exists(dir_path):
            return

        all_tf_files = []
        all_tfvars_files = []
        all_json_files = []

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and "backup" not in d.lower()]
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".tf"):
                    all_tf_files.append(full_path)
                elif file.endswith(".tfvars") or file.endswith(".tfvars.json"):
                    all_tfvars_files.append(full_path)
                elif file.endswith(".json") and "policy" in file.lower():
                    all_json_files.append(full_path)

        # 1. Parse variables, locals, providers, and data policy documents first
        for tf_path in all_tf_files:
            self._parse_variables_and_provider(tf_path)

        # 1b. Override variable defaults with *.tfvars / *.tfvars.json and re-resolve locals
        for tfvars_path in all_tfvars_files:
            self._parse_tfvars(tfvars_path)
        if self.locals:
            for k, v in list(self.locals.items()):
                if isinstance(v, str):
                    self.locals[k] = self._resolve_interpolated_string(v)

        # 2. Parse main resources
        for tf_path in all_tf_files:
            self.parse_tf_file(tf_path)

        # 3. Parse standalone JSON policies
        for json_path in all_json_files:
            self.parse_standalone_json_policy(json_path)

        # 4. Cross-reference aliases and S3 SSE/security bindings regardless of resource order
        self.finalize()

    def _parse_tfvars(self, filepath: str):
        """Loads variable overrides from .tfvars or .tfvars.json."""
        try:
            if filepath.endswith(".json"):
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = hcl2.load(f)
            if isinstance(data, dict):
                for v_name, v_val in data.items():
                    val = self._unwrap_hcl_val(v_val)
                    self.variables[v_name] = val
                    if v_name == "aws_account_id":
                        self.account_id = str(val)
                    elif v_name in ["aws_region", "region"]:
                        self.region = str(val)
        except Exception as exc:
            self.parse_warnings.append(f"Error reading tfvars {filepath}: {exc}")

    def finalize(self):
        """Resolves cross-resource references (KMS aliases and S3 SSE-KMS/security bindings)."""
        for k in self.kms_keys:
            res_id = k.properties.get("res_id") or k.name
            if res_id in self.kms_aliases:
                k.alias = self.kms_aliases[res_id]

        for b in self.s3_buckets:
            res_id = b.properties.get("res_id") or b.name
            keys_to_check = (res_id, b.bucket_name)

            kms_ref = next((self.s3_kms_key_refs[k] for k in keys_to_check if k in self.s3_kms_key_refs), None)
            if kms_ref:
                b.properties["sse_kms_key_ref"] = kms_ref
                if kms_ref.startswith("arn:"):
                    b.kms_key_arn = kms_ref
                else:
                    for k in self.kms_keys:
                        k_res_id = k.properties.get("res_id") or k.name
                        if f"aws_kms_key.{k_res_id}." in kms_ref or k_res_id == self._clean_ref(kms_ref) or k.alias == kms_ref:
                            b.kms_key_arn = k.key_arn
                            break

            pab_entry = next((self.s3_public_access_blocks[k] for k in keys_to_check if k in self.s3_public_access_blocks), None)
            if pab_entry is not None:
                b.properties["has_public_access_block"] = bool(pab_entry.get("_all_blocked", False))
            else:
                b.properties["has_public_access_block"] = False

            b.properties["has_logging"] = any(k in self.s3_logging_configs for k in keys_to_check)
            b.properties["has_lifecycle"] = any(k in self.s3_lifecycle_configs for k in keys_to_check)

            bpol = next((self.s3_bucket_policies[k] for k in keys_to_check if k in self.s3_bucket_policies), None)
            if bpol:
                b.properties["bucket_policy_statements"] = [s.model_dump() for s in bpol]

    @staticmethod
    def _unwrap_hcl_val(val: Any, default: Any = None) -> Any:
        if isinstance(val, list):
            return val[0] if val else default
        return val if val is not None else default

    @staticmethod
    def _flatten_hcl_list(val: Any) -> List[Any]:
        if val is None:
            return []
        if isinstance(val, list):
            if len(val) == 1 and isinstance(val[0], list):
                return val[0]
            return val
        return [val]

    @staticmethod
    def _parse_bool(val: Any, default: bool = False) -> bool:
        """Converts HCL boolean or string ('true'/'false') cleanly."""
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            s = val.strip().lower()
            if s in ("true", "1", "yes"):
                return True
            if s in ("false", "0", "no", ""):
                return False
        return bool(val)

    def _parse_variables_and_provider(self, filepath: str):
        """Extracts declared variables, locals, provider configurations, and IAM policy data sources."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                obj = hcl2.load(f)
        except Exception as exc:
            self.parse_warnings.append(f"Skipping HCL pre-pass for {os.path.basename(filepath)}: {exc}")
            return

        # Variables
        for var_wrapper in obj.get("variable", []):
            for v_name, v_data in var_wrapper.items():
                if "default" in v_data:
                    val = self._unwrap_hcl_val(v_data["default"])
                    self.variables[v_name] = val
                    if v_name == "aws_account_id":
                        self.account_id = str(val)
                    elif v_name in ["aws_region", "region"]:
                        self.region = str(val)

        # Locals
        for loc_wrapper in obj.get("locals", []):
            if isinstance(loc_wrapper, dict):
                for l_name, l_val in loc_wrapper.items():
                    if l_name in ("__start_line__", "__end_line__"):
                        continue
                    self.locals[l_name] = self._unwrap_hcl_val(l_val)

        # Providers
        for p_wrapper in obj.get("provider", []):
            if "aws" in p_wrapper:
                aws_p = p_wrapper["aws"]
                if "region" in aws_p:
                    raw_reg = self._unwrap_hcl_val(aws_p["region"])
                    if isinstance(raw_reg, str) and not raw_reg.startswith("${"):
                        self.region = raw_reg

        # Data sources: aws_iam_policy_document
        for data_wrapper in obj.get("data", []):
            if "aws_iam_policy_document" in data_wrapper:
                for doc_name, doc_body in data_wrapper["aws_iam_policy_document"].items():
                    stmts = []
                    for s in doc_body.get("statement", []):
                        if not isinstance(s, dict):
                            continue
                        stmt_dict: Dict[str, Any] = {
                            "Sid": self._unwrap_hcl_val(s.get("sid")),
                            "Effect": self._unwrap_hcl_val(s.get("effect"), "Allow"),
                            "Condition": self._convert_hcl_conditions(s.get("condition", [])),
                        }
                        if s.get("actions"):
                            stmt_dict["Action"] = self._flatten_hcl_list(s.get("actions"))
                        if s.get("not_actions"):
                            stmt_dict["NotAction"] = self._flatten_hcl_list(s.get("not_actions"))
                        if s.get("resources"):
                            stmt_dict["Resource"] = self._flatten_hcl_list(s.get("resources"))
                        if s.get("not_resources"):
                            stmt_dict["NotResource"] = self._flatten_hcl_list(s.get("not_resources"))
                        principals = self._convert_hcl_principals(s.get("principals", []))
                        if principals:
                            stmt_dict["Principal"] = principals
                        stmts.append(stmt_dict)
                    self.policy_documents[doc_name] = {"Version": "2012-10-17", "Statement": stmts}

    @classmethod
    def _convert_hcl_principals(cls, principal_blocks: Any) -> Dict[str, Any]:
        """Converts `aws_iam_policy_document` HCL `principals` blocks into IAM JSON Principal dict."""
        result: Dict[str, Any] = {}
        if not isinstance(principal_blocks, list):
            return result
        for pb in principal_blocks:
            if not isinstance(pb, dict):
                continue
            ptype = cls._unwrap_hcl_val(pb.get("type"))
            identifiers = cls._flatten_hcl_list(pb.get("identifiers"))
            if ptype and identifiers:
                existing = result.get(ptype)
                if existing is None:
                    result[ptype] = identifiers[0] if len(identifiers) == 1 else identifiers
                else:
                    merged = ([existing] if isinstance(existing, str) else list(existing)) + identifiers
                    result[ptype] = merged
        return result

    @classmethod
    def _convert_hcl_conditions(cls, cond_blocks: Any) -> Dict[str, Any]:
        """Converts `aws_iam_policy_document` HCL `condition` blocks into IAM JSON Condition dict."""
        result: Dict[str, Any] = {}
        if not isinstance(cond_blocks, list):
            return result
        for cb in cond_blocks:
            if not isinstance(cb, dict):
                continue
            test = cls._unwrap_hcl_val(cb.get("test"))
            variable = cls._unwrap_hcl_val(cb.get("variable"))
            values = cls._flatten_hcl_list(cb.get("values"))
            if test and variable:
                result.setdefault(str(test), {})[str(variable)] = values[0] if len(values) == 1 else values
        return result

    def parse_standalone_json_policy(self, filepath: str):
        """Parses standalone IAM policy JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict) or "Statement" not in data:
                return

            statements = self._parse_statements(data.get("Statement", []))
            has_wildcard = any(
                statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                for s in statements
            )

            p_name = os.path.splitext(os.path.basename(filepath))[0]
            node = IAMPolicyNode(
                id=f"iam:policy:{p_name}",
                name=p_name,
                policy_arn=f"arn:aws:iam::{self.account_id}:policy/{p_name}",
                statements=statements,
                has_wildcard_decrypt=has_wildcard,
                source_file=filepath,
                properties={"raw_json": data}
            )
            self.policies.append(node)
        except Exception as e:
            self.parse_warnings.append(f"Error parsing standalone JSON policy {filepath}: {e}")

    def _parse_statements(self, stmts_data: Any) -> List[PolicyStatement]:
        """Normalizes IAM policy statements."""
        return parse_policy_statements(stmts_data)

    def parse_tf_file(self, filepath: str):
        """Parses a Terraform .tf file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                obj = hcl2.load(f)
        except Exception as e:
            self.parse_warnings.append(f"Error reading HCL2 file {filepath}: {e}")
            return

        resources = obj.get("resource", [])
        for res_wrapper in resources:
            for res_type, res_entries in res_wrapper.items():
                for res_id, res_data in res_entries.items():
                    if res_type == "aws_iam_role":
                        self._process_iam_role(res_id, res_data, filepath)
                    elif res_type == "aws_iam_policy":
                        self._process_iam_policy(res_id, res_data, filepath)
                    elif res_type == "aws_iam_role_policy":
                        self._process_inline_role_policy(res_id, res_data, filepath)
                    elif res_type in ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment"):
                        self._process_attachment(res_data)
                    elif res_type == "aws_kms_key":
                        self._process_kms_key(res_id, res_data, filepath)
                    elif res_type == "aws_kms_alias":
                        self._process_kms_alias(res_id, res_data)
                    elif res_type == "aws_s3_bucket":
                        self._process_s3_bucket(res_id, res_data, filepath)
                    elif res_type == "aws_s3_bucket_server_side_encryption_configuration":
                        self._process_s3_sse(res_id, res_data)
                    elif res_type == "aws_s3_bucket_public_access_block":
                        self._process_s3_public_access_block(res_id, res_data)
                    elif res_type == "aws_s3_bucket_logging":
                        self._process_s3_logging(res_id, res_data)
                    elif res_type == "aws_s3_bucket_lifecycle_configuration":
                        self._process_s3_lifecycle(res_id, res_data)
                    elif res_type == "aws_s3_bucket_policy":
                        self._process_s3_bucket_policy(res_id, res_data)

    def _process_iam_role(self, res_id: str, data: Dict[str, Any], filepath: str):
        raw_name = self._unwrap_hcl_val(data.get("name"), res_id)
        name = self._resolve_interpolated_string(raw_name)
        assume_raw = data.get("assume_role_policy")
        assume_dict = self._extract_embedded_json(assume_raw) or {}

        # Detect OIDC federated provider
        oidc_provider = None
        assume_stmts = assume_dict.get("Statement", [])
        if isinstance(assume_stmts, dict):
            assume_stmts = [assume_stmts]
        for stmt in assume_stmts:
            if not isinstance(stmt, dict):
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict) and "Federated" in principal:
                oidc_provider = principal["Federated"]

        role_node = IAMRoleNode(
            id=f"iam:role:{name}",
            name=name,
            role_arn=f"arn:aws:iam::{self.account_id}:role/{name}",
            trust_policy=assume_dict,
            oidc_provider=oidc_provider,
            source_file=filepath,
            properties={"raw": data, "res_id": res_id}
        )
        self.roles.append(role_node)

        # Handle Terraform inline_policy blocks inside aws_iam_role
        for idx, inline in enumerate(data.get("inline_policy", []) or []):
            if not isinstance(inline, dict):
                continue
            inline_name = self._resolve_interpolated_string(self._unwrap_hcl_val(inline.get("name"), f"{res_id}_inline_{idx}"))
            inline_dict = self._extract_embedded_json(inline.get("policy")) or {}
            statements = self._parse_statements(inline_dict.get("Statement", []))
            has_wildcard = any(
                statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                for s in statements
            )
            pol_node = IAMPolicyNode(
                id=f"iam:policy:{name}:{inline_name}",
                name=inline_name,
                policy_arn=f"arn:aws:iam::{self.account_id}:role/{name}/inline/{inline_name}",
                statements=statements,
                has_wildcard_decrypt=has_wildcard,
                source_file=filepath,
                properties={"raw_policy": inline_dict, "res_id": f"{res_id}_{inline_name}", "is_inline": True}
            )
            self.policies.append(pol_node)
            self.attachments.append({"role": name, "policy": pol_node.id})

    def _process_iam_policy(self, res_id: str, data: Dict[str, Any], filepath: str):
        raw_name = self._unwrap_hcl_val(data.get("name"), res_id)
        name = self._resolve_interpolated_string(raw_name)
        policy_raw = data.get("policy")
        policy_dict = self._extract_embedded_json(policy_raw) or {}

        statements = self._parse_statements(policy_dict.get("Statement", []))
        has_wildcard = any(
            statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
            for s in statements
        )

        policy_node = IAMPolicyNode(
            id=f"iam:policy:{name}",
            name=name,
            policy_arn=f"arn:aws:iam::{self.account_id}:policy/{name}",
            statements=statements,
            has_wildcard_decrypt=has_wildcard,
            source_file=filepath,
            properties={"raw_policy": policy_dict, "res_id": res_id}
        )
        self.policies.append(policy_node)

    def _process_inline_role_policy(self, res_id: str, data: Dict[str, Any], filepath: str):
        raw_name = self._unwrap_hcl_val(data.get("name"), res_id)
        name = self._resolve_interpolated_string(raw_name)
        role_raw = self._unwrap_hcl_val(data.get("role"), "")
        role_name = self._clean_ref(role_raw)
        policy_dict = self._extract_embedded_json(data.get("policy")) or {}

        statements = self._parse_statements(policy_dict.get("Statement", []))
        has_wildcard = any(
            statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
            for s in statements
        )
        policy_node = IAMPolicyNode(
            id=f"iam:policy:{role_name}:{name}",
            name=name,
            policy_arn=f"arn:aws:iam::{self.account_id}:role/{role_name}/inline/{name}",
            statements=statements,
            has_wildcard_decrypt=has_wildcard,
            source_file=filepath,
            properties={"raw_policy": policy_dict, "res_id": res_id, "is_inline": True}
        )
        self.policies.append(policy_node)
        if role_name:
            self.attachments.append({"role": role_name, "policy": policy_node.id})

    def _process_attachment(self, data: Dict[str, Any]):
        role_raw = self._unwrap_hcl_val(data.get("role"), "")
        # Also support aws_iam_policy_attachment (roles = [...])
        roles_raw = data.get("roles")
        policy_raw = self._unwrap_hcl_val(data.get("policy_arn"), "")

        def extract_name(raw: str) -> str:
            raw = str(raw).strip()
            if raw.startswith("${") and raw.endswith("}"):
                raw = raw[2:-1].strip()
            if "." in raw and not raw.startswith("arn:"):
                parts = raw.split(".")
                return parts[1] if len(parts) > 1 else parts[0]
            if "/" in raw:
                return raw.split("/")[-1]
            return raw

        policy_name = extract_name(policy_raw)
        if isinstance(roles_raw, list) and roles_raw:
            for r in roles_raw:
                self.attachments.append({"role": extract_name(r), "policy": policy_name})
        elif role_raw:
            self.attachments.append({"role": extract_name(role_raw), "policy": policy_name})

    def _process_kms_key(self, res_id: str, data: Dict[str, Any], filepath: str):
        # Parse KMS Key Policy if embedded
        key_policy_raw = data.get("policy")
        key_policy_dict = self._extract_embedded_json(key_policy_raw) or {}
        statements = self._parse_statements(key_policy_dict.get("Statement", []))
        self.kms_key_policies[res_id] = statements

        rot_raw = self._resolve_value(self._unwrap_hcl_val(data.get("enable_key_rotation"), False))
        desc_raw = self._unwrap_hcl_val(data.get("description"), "")

        key_node = KMSKeyNode(
            id=f"kms:key:{res_id}",
            name=res_id,
            key_arn=f"arn:aws:kms:{self.region}:{self.account_id}:key/{res_id}",
            alias=self.kms_aliases.get(res_id, f"alias/{res_id}"),
            rotation_enabled=self._parse_bool(rot_raw, default=False),
            source_file=filepath,
            properties={
                "res_id": res_id,
                "description": str(desc_raw),
                "has_explicit_policy": bool(key_policy_raw),
                "policy_fetched": True,
                "policy_statements": [s.model_dump() for s in statements]
            }
        )
        self.kms_keys.append(key_node)

    def _process_kms_alias(self, res_id: str, data: Dict[str, Any]):
        name = self._unwrap_hcl_val(data.get("name"), "")
        target_id_raw = self._unwrap_hcl_val(data.get("target_key_id"), "")
        clean_target = self._clean_ref(target_id_raw)
        if clean_target and name:
            self.kms_aliases[clean_target] = name

    def _process_s3_bucket(self, res_id: str, data: Dict[str, Any], filepath: str):
        raw_b_name = self._unwrap_hcl_val(data.get("bucket"), res_id)
        b_name = self._resolve_interpolated_string(raw_b_name)
        tags_raw = self._unwrap_hcl_val(data.get("tags"), {})

        # Support legacy inline server_side_encryption_configuration block inside aws_s3_bucket
        if "server_side_encryption_configuration" in data:
            self._extract_sse_kms_from_block(res_id, data["server_side_encryption_configuration"])

        bucket_node = S3BucketNode(
            id=f"s3:bucket:{res_id}",
            name=res_id,
            bucket_name=b_name,
            bucket_arn=f"arn:aws:s3:::{b_name}",
            source_file=filepath,
            properties={"tags": tags_raw if isinstance(tags_raw, dict) else {}, "res_id": res_id}
        )
        self.s3_buckets.append(bucket_node)

    def _clean_ref(self, val: Any) -> str:
        s = str(val).strip()
        if s.startswith("${") and s.endswith("}"):
            s = s[2:-1].strip()
        if "." in s and not s.startswith("arn:"):
            parts = s.split(".")
            return parts[1] if len(parts) > 1 else parts[0]
        return s

    def _extract_sse_kms_from_block(self, bucket_key: str, block_data: Any):
        """Extracts kms_master_key_id from HCL2 SSE configuration blocks."""
        blocks = block_data if isinstance(block_data, list) else [block_data]
        for blk in blocks:
            if not isinstance(blk, dict):
                continue
            rules = blk.get("rule", [])
            if isinstance(rules, dict):
                rules = [rules]
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                defaults = rule.get("apply_server_side_encryption_by_default", [])
                if isinstance(defaults, dict):
                    defaults = [defaults]
                for d in defaults:
                    if not isinstance(d, dict):
                        continue
                    sse_alg = self._unwrap_hcl_val(d.get("sse_algorithm"), "")
                    kms_id = self._unwrap_hcl_val(d.get("kms_master_key_id"), "")
                    if kms_id and (not sse_alg or sse_alg == "aws:kms"):
                        resolved_kms = self._resolve_interpolated_string(str(kms_id))
                        self.s3_kms_key_refs[bucket_key] = resolved_kms

    def _process_s3_sse(self, res_id: str, data: Dict[str, Any]):
        bucket_raw = self._unwrap_hcl_val(data.get("bucket"), "")
        clean_bucket = self._clean_ref(bucket_raw)
        self.s3_encryption_configs[clean_bucket] = data
        self._extract_sse_kms_from_block(clean_bucket, data)

    def _process_s3_public_access_block(self, res_id: str, data: Dict[str, Any]):
        bucket_raw = self._unwrap_hcl_val(data.get("bucket"), "")
        clean_bucket = self._clean_ref(bucket_raw)
        b_acl = self._parse_bool(self._resolve_value(self._unwrap_hcl_val(data.get("block_public_acls"), False)))
        b_pol = self._parse_bool(self._resolve_value(self._unwrap_hcl_val(data.get("block_public_policy"), False)))
        i_acl = self._parse_bool(self._resolve_value(self._unwrap_hcl_val(data.get("ignore_public_acls"), False)))
        r_pub = self._parse_bool(self._resolve_value(self._unwrap_hcl_val(data.get("restrict_public_buckets"), False)))
        entry = dict(data)
        entry["_all_blocked"] = b_acl and b_pol and i_acl and r_pub
        self.s3_public_access_blocks[clean_bucket] = entry

    def _process_s3_logging(self, res_id: str, data: Dict[str, Any]):
        bucket_raw = self._unwrap_hcl_val(data.get("bucket"), "")
        clean_bucket = self._clean_ref(bucket_raw)
        self.s3_logging_configs[clean_bucket] = data

    def _process_s3_lifecycle(self, res_id: str, data: Dict[str, Any]):
        bucket_raw = self._unwrap_hcl_val(data.get("bucket"), "")
        clean_bucket = self._clean_ref(bucket_raw)
        self.s3_lifecycle_configs[clean_bucket] = data

    def _process_s3_bucket_policy(self, res_id: str, data: Dict[str, Any]):
        bucket_raw = self._unwrap_hcl_val(data.get("bucket"), "")
        clean_bucket = self._clean_ref(bucket_raw)
        pol_dict = self._extract_embedded_json(data.get("policy")) or {}
        stmts = self._parse_statements(pol_dict.get("Statement", []))
        if clean_bucket and stmts:
            self.s3_bucket_policies[clean_bucket] = stmts
