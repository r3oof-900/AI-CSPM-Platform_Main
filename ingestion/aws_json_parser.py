"""
AI-CSPM Exported AWS JSON Snapshot Ingestion Parser
Parses exported AWS IAM, KMS, and S3 JSON snapshots (both structured snapshot bundles
and standard AWS CLI JSON exports) into semantic graph nodes for offline local scans.
"""

import os
import json
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.models import (
        IAMPolicyNode,
        IAMRoleNode,
        KMSKeyNode,
        PolicyStatement,
        S3BucketNode,
        decode_policy_document,
        extract_federated_oidc_provider,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )
except (ImportError, ValueError):
    from ..core.models import (
        IAMPolicyNode,
        IAMRoleNode,
        KMSKeyNode,
        PolicyStatement,
        S3BucketNode,
        decode_policy_document,
        extract_federated_oidc_provider,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )


_AWS_SNAPSHOT_KEYS = frozenset({
    "Roles",
    "Role",
    "RoleDetailList",
    "TrustPolicies",
    "Policies",
    "Policy",
    "PolicyDetailList",
    "Keys",
    "KeyMetadata",
    "KeyPolicies",
    "Buckets",
    "BucketPolicies",
    "BucketEncryptions",
})


class AwsJsonParser:
    """Ingests exported AWS IAM, KMS, and S3 JSON files into AI-CSPM graph nodes."""

    def __init__(self):
        self.roles: List[IAMRoleNode] = []
        self.policies: List[IAMPolicyNode] = []
        self.kms_keys: List[KMSKeyNode] = []
        self.s3_buckets: List[S3BucketNode] = []
        self.attachments: List[Dict[str, str]] = []
        self.parse_warnings: List[str] = []

        self.account_id: str = "123456789012"
        self.region: str = "us-east-1"

        self._roles_by_key: Dict[str, IAMRoleNode] = {}
        self._policies_by_key: Dict[str, IAMPolicyNode] = {}
        self._keys_by_key: Dict[str, KMSKeyNode] = {}
        self._buckets_by_name: Dict[str, S3BucketNode] = {}
        self._attachment_pairs: set = set()
        self._pending_trusts: List[Tuple[Dict[str, Any], str]] = []
        self._pending_key_policies: List[Tuple[Dict[str, Any], str]] = []
        self._pending_bucket_policies: List[Tuple[Dict[str, Any], str]] = []
        self._pending_bucket_encryptions: List[Tuple[Dict[str, Any], str]] = []

    def parse_directory(self, dir_path: str) -> None:
        """Recursively discovers and parses exported AWS JSON snapshot files under `dir_path`."""
        if not dir_path or not os.path.exists(dir_path):
            return

        json_files: List[str] = []
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [
                d for d in sorted(dirs)
                if not d.startswith(".") and "backup" not in d.lower()
            ]
            for fname in sorted(files):
                if not fname.endswith(".json"):
                    continue
                if fname.endswith((".tfvars.json", ".backup")) or fname.startswith("remediated_"):
                    continue
                json_files.append(os.path.join(root, fname))

        for fp in json_files:
            self.parse_file(fp)

        self.finalize()

    def parse_file(self, filepath: str) -> bool:
        """Parses a single JSON file if it matches an AWS snapshot schema. Returns True if consumed."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            self.parse_warnings.append(f"Skipping invalid JSON {os.path.basename(filepath)}: {exc}")
            return False

        if not isinstance(data, dict) or "Statement" in data:
            return False

        is_single_key_policy = "KeyId" in data and ("Policy" in data or "PolicyDocument" in data)
        is_single_bucket_policy = "Bucket" in data and ("Policy" in data or "ServerSideEncryptionConfiguration" in data)
        if not (_AWS_SNAPSHOT_KEYS & set(data.keys()) or is_single_key_policy or is_single_bucket_policy):
            return False

        if data.get("AccountId"):
            self.account_id = str(data["AccountId"])
        if data.get("Region"):
            self.region = str(data["Region"])

        for role_entry in self._collect_entries(data, ("Roles", "RoleDetailList", "Role")):
            self._ingest_role(role_entry, filepath)

        for pol_entry in self._collect_entries(data, ("Policies", "PolicyDetailList")):
            self._ingest_managed_policy(pol_entry, filepath)
        if isinstance(data.get("Policy"), dict) and ("PolicyName" in data["Policy"] or "PolicyVersionList" in data["Policy"]):
            self._ingest_managed_policy(data["Policy"], filepath)

        for trust_entry in self._collect_entries(data, ("TrustPolicies",)):
            self._pending_trusts.append((trust_entry, filepath))

        for key_entry in self._collect_entries(data, ("Keys", "KeyMetadata")):
            self._ingest_kms_key(key_entry, filepath)

        for kp_entry in self._collect_entries(data, ("KeyPolicies",)):
            self._pending_key_policies.append((kp_entry, filepath))
        if is_single_key_policy and "KeyPolicies" not in data:
            self._pending_key_policies.append((data, filepath))

        for bkt_entry in self._collect_entries(data, ("Buckets",)):
            self._ingest_s3_bucket(bkt_entry, filepath)

        for bp_entry in self._collect_entries(data, ("BucketPolicies",)):
            self._pending_bucket_policies.append((bp_entry, filepath))
        if "Bucket" in data and "Policy" in data and "BucketPolicies" not in data:
            self._pending_bucket_policies.append((data, filepath))

        for enc_entry in self._collect_entries(data, ("BucketEncryptions",)):
            self._pending_bucket_encryptions.append((enc_entry, filepath))
        if "Bucket" in data and "ServerSideEncryptionConfiguration" in data and "BucketEncryptions" not in data:
            self._pending_bucket_encryptions.append((data, filepath))

        return True

    def finalize(self) -> None:
        """Applies cross-file trust policies, KMS key policies, S3 policies, and SSE-KMS bindings."""
        for entry, filepath in self._pending_trusts:
            self._apply_trust_policy(entry, filepath)

        for entry, filepath in self._pending_key_policies:
            self._apply_key_policy(entry, filepath)

        for entry, filepath in self._pending_bucket_policies:
            self._apply_bucket_policy(entry, filepath)

        for entry, filepath in self._pending_bucket_encryptions:
            self._apply_bucket_encryption(entry, filepath)

        self._resolve_bucket_kms_arns()

    @staticmethod
    def _collect_entries(data: Dict[str, Any], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for k in keys:
            val = data.get(k)
            if isinstance(val, list):
                entries.extend(item for item in val if isinstance(item, dict))
            elif isinstance(val, dict):
                entries.append(val)
        return entries

    @staticmethod
    def _extract_policy_document(entry: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(entry.get("PolicyVersion"), dict):
            doc = decode_policy_document(entry["PolicyVersion"].get("Document"))
            if doc:
                return doc

        versions = entry.get("PolicyVersionList")
        if isinstance(versions, list) and versions:
            default_id = entry.get("DefaultVersionId")
            chosen = next(
                (v for v in versions if isinstance(v, dict) and (v.get("IsDefaultVersion") or (default_id and v.get("VersionId") == default_id))),
                versions[0],
            )
            if isinstance(chosen, dict):
                doc = decode_policy_document(chosen.get("Document"))
                if doc:
                    return doc

        for key in ("Document", "PolicyDocument", "Policy"):
            if key in entry and entry[key] is not None:
                doc = decode_policy_document(entry[key])
                if doc:
                    return doc
        return {}

    def _add_attachment(self, role_name: str, policy_ref: str) -> None:
        pair = (role_name, policy_ref)
        if role_name and policy_ref and pair not in self._attachment_pairs:
            self._attachment_pairs.add(pair)
            self.attachments.append({"role": role_name, "policy": policy_ref})

    def _register_role(self, role_node: IAMRoleNode) -> IAMRoleNode:
        lookup_keys = [k for k in (role_node.role_arn, role_node.name, role_node.id) if k]
        for k in lookup_keys:
            if k in self._roles_by_key:
                existing = self._roles_by_key[k]
                if role_node.trust_policy and not existing.trust_policy:
                    existing.trust_policy = role_node.trust_policy
                if role_node.oidc_provider and not existing.oidc_provider:
                    existing.oidc_provider = role_node.oidc_provider
                return existing
        self.roles.append(role_node)
        for k in lookup_keys:
            self._roles_by_key[k] = role_node
        return role_node

    def _ingest_role(self, entry: Dict[str, Any], filepath: str) -> None:
        role_name = str(entry.get("RoleName") or entry.get("Name") or "").strip()
        if not role_name:
            return
        role_arn = str(entry.get("Arn") or f"arn:aws:iam::{self.account_id}:role/{role_name}")
        assume_doc = decode_policy_document(entry.get("AssumeRolePolicyDocument"))
        perm_boundary = (entry.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")

        role_node = IAMRoleNode(
            id=f"aws:iam:role:{role_name}",
            name=role_name,
            layer="IAM",
            role_arn=role_arn,
            trust_policy=assume_doc,
            oidc_provider=extract_federated_oidc_provider(assume_doc),
            source_file=filepath,
            properties={
                "res_id": role_name,
                "role_arn": role_arn,
                "permissions_boundary": perm_boundary,
                "path": entry.get("Path", "/"),
                "create_date": str(entry.get("CreateDate", "")),
            },
        )
        self._register_role(role_node)

        for att in entry.get("AttachedManagedPolicies") or []:
            if not isinstance(att, dict):
                continue
            pol_name = att.get("PolicyName")
            pol_arn = att.get("PolicyArn")
            pol_ref = f"aws:iam:policy:{pol_name}" if pol_name else (pol_arn or "")
            self._add_attachment(role_name, pol_ref)

        for inline in (entry.get("RolePolicyList") or entry.get("InlinePolicies") or []):
            if not isinstance(inline, dict):
                continue
            inline_name = str(inline.get("PolicyName") or "inline").strip()
            doc = decode_policy_document(inline.get("PolicyDocument") or inline.get("Document") or inline.get("Policy"))
            stmts = parse_policy_statements(doc)
            pol_id = f"aws:iam:policy:{role_name}:{inline_name}"
            self._register_policy(IAMPolicyNode(
                id=pol_id,
                name=inline_name,
                layer="IAM",
                policy_arn=f"{role_arn}:policy/{inline_name}",
                statements=stmts,
                has_wildcard_decrypt=any(
                    statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                    for s in stmts
                ),
                source_file=filepath,
                properties={"res_id": f"{role_name}:{inline_name}", "is_inline": True},
            ))
            self._add_attachment(role_name, pol_id)

    def _apply_trust_policy(self, entry: Dict[str, Any], filepath: str) -> None:
        role_arn = str(entry.get("RoleArn") or "").strip()
        role_name = str(entry.get("RoleName") or (role_arn.split("/")[-1] if role_arn else "")).strip()
        if not role_name:
            return
        assume_doc = decode_policy_document(entry.get("AssumeRolePolicyDocument"))
        if not assume_doc:
            return
        oidc_provider = extract_federated_oidc_provider(assume_doc)
        existing = self._roles_by_key.get(role_arn) or self._roles_by_key.get(role_name)
        if existing is not None:
            existing.trust_policy = assume_doc
            if oidc_provider:
                existing.oidc_provider = oidc_provider
            return

        self._register_role(IAMRoleNode(
            id=f"aws:iam:role:{role_name}",
            name=role_name,
            layer="IAM",
            role_arn=role_arn or f"arn:aws:iam::{self.account_id}:role/{role_name}",
            trust_policy=assume_doc,
            oidc_provider=oidc_provider,
            source_file=filepath,
            properties={"res_id": role_name, "role_arn": role_arn, "path": "/"},
        ))

    def _register_policy(self, pol_node: IAMPolicyNode) -> IAMPolicyNode:
        lookup_keys = [k for k in (pol_node.policy_arn, pol_node.id) if k]
        for k in lookup_keys:
            if k in self._policies_by_key:
                return self._policies_by_key[k]
        self.policies.append(pol_node)
        for k in lookup_keys:
            self._policies_by_key[k] = pol_node
        return pol_node

    def _ingest_managed_policy(self, entry: Dict[str, Any], filepath: str) -> None:
        pol_name = str(entry.get("PolicyName") or entry.get("Name") or "").strip()
        if not pol_name:
            return
        pol_arn = str(entry.get("Arn") or f"arn:aws:iam::{self.account_id}:policy/{pol_name}")
        doc = self._extract_policy_document(entry)
        stmts = parse_policy_statements(doc)
        self._register_policy(IAMPolicyNode(
            id=f"aws:iam:policy:{pol_name}",
            name=pol_name,
            layer="IAM",
            policy_arn=pol_arn,
            statements=stmts,
            has_wildcard_decrypt=any(
                statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                for s in stmts
            ),
            source_file=filepath,
            properties={"res_id": pol_name, "policy_arn": pol_arn},
        ))

    def _register_kms_key(self, key_node: KMSKeyNode, key_id: str) -> KMSKeyNode:
        lookup_keys = [k for k in (key_node.key_arn, key_id, key_node.alias, key_node.id) if k]
        for k in lookup_keys:
            if k in self._keys_by_key:
                existing = self._keys_by_key[k]
                for lk in lookup_keys:
                    self._keys_by_key[lk] = existing
                return existing
        self.kms_keys.append(key_node)
        for lk in lookup_keys:
            self._keys_by_key[lk] = key_node
        return key_node

    def _ingest_kms_key(self, entry: Dict[str, Any], filepath: str) -> None:
        meta = entry.get("KeyMetadata") if isinstance(entry.get("KeyMetadata"), dict) else entry
        key_manager = str(meta.get("KeyManager", "CUSTOMER")).upper()
        if key_manager == "AWS":
            return

        key_id = str(entry.get("KeyId") or meta.get("KeyId") or "").strip()
        key_arn = str(entry.get("KeyArn") or meta.get("Arn") or "").strip()
        if not key_id and key_arn:
            key_id = key_arn.split("/")[-1]
        if not key_id:
            return
        if not key_arn:
            key_arn = f"arn:aws:kms:{self.region}:{self.account_id}:key/{key_id}"

        alias = entry.get("Alias") or meta.get("Alias")
        if not alias and isinstance(entry.get("Aliases"), list) and entry["Aliases"]:
            first = entry["Aliases"][0]
            alias = first.get("AliasName") if isinstance(first, dict) else str(first)
        display_name = str(alias or key_id)

        rotation = bool(entry.get("KeyRotationEnabled", entry.get("RotationEnabled", False)))
        existing_stmts = parse_policy_statements(entry.get("Policy")) if entry.get("Policy") else []

        key_node = KMSKeyNode(
            id=f"aws:kms:key:{key_id}",
            name=display_name,
            layer="Cryptography",
            key_arn=key_arn,
            alias=str(alias) if alias else None,
            rotation_enabled=rotation,
            source_file=filepath,
            properties={
                "res_id": display_name,
                "key_id": key_id,
                "description": str(meta.get("Description", "")),
                "key_state": str(meta.get("KeyState", "Enabled")),
                "enable_key_rotation": rotation,
                "policy_fetched": bool(existing_stmts),
                "has_explicit_policy": bool(existing_stmts),
                "policy_statements": [s.model_dump() for s in existing_stmts],
            },
        )
        self._register_kms_key(key_node, key_id)

    def _apply_key_policy(self, entry: Dict[str, Any], filepath: str) -> None:
        key_id = str(entry.get("KeyId") or "").strip()
        key_arn = str(entry.get("KeyArn") or "").strip()
        alias = str(entry.get("Alias") or "").strip()
        if not key_id and key_arn:
            key_id = key_arn.split("/")[-1]
        if not (key_id or key_arn or alias):
            return

        doc = decode_policy_document(entry.get("Policy") or entry.get("PolicyDocument"))
        stmts: List[PolicyStatement] = parse_policy_statements(doc)

        target = (
            self._keys_by_key.get(key_arn)
            or self._keys_by_key.get(key_id)
            or self._keys_by_key.get(alias)
        )
        if target is None:
            resolved_id = key_id or alias
            target = self._register_kms_key(
                KMSKeyNode(
                    id=f"aws:kms:key:{resolved_id}",
                    name=alias or resolved_id,
                    layer="Cryptography",
                    key_arn=key_arn or f"arn:aws:kms:{self.region}:{self.account_id}:key/{resolved_id}",
                    alias=alias or None,
                    rotation_enabled=False,
                    source_file=filepath,
                    properties={"res_id": alias or resolved_id, "key_id": resolved_id},
                ),
                resolved_id,
            )

        target.properties["policy_fetched"] = True
        target.properties["has_explicit_policy"] = bool(stmts)
        target.properties["policy_statements"] = [s.model_dump() for s in stmts]

    def _get_or_create_bucket(self, bucket_name: str, filepath: str) -> S3BucketNode:
        existing = self._buckets_by_name.get(bucket_name)
        if existing is not None:
            return existing
        node = S3BucketNode(
            id=f"aws:s3:bucket:{bucket_name}",
            name=bucket_name,
            layer="Storage",
            bucket_name=bucket_name,
            bucket_arn=f"arn:aws:s3:::{bucket_name}",
            source_file=filepath,
            properties={"res_id": bucket_name, "bucket_arn": f"arn:aws:s3:::{bucket_name}"},
        )
        self.s3_buckets.append(node)
        self._buckets_by_name[bucket_name] = node
        return node

    def _ingest_s3_bucket(self, entry: Dict[str, Any], filepath: str) -> None:
        bucket_name = str(entry.get("Name") or entry.get("Bucket") or "").strip()
        if not bucket_name:
            return
        bucket_arn = str(entry.get("Arn") or f"arn:aws:s3:::{bucket_name}")
        node = self._get_or_create_bucket(bucket_name, filepath)
        node.bucket_arn = bucket_arn
        node.source_file = filepath
        node.properties["bucket_arn"] = bucket_arn

        if "PublicAccessBlockConfiguration" in entry:
            pab = entry.get("PublicAccessBlockConfiguration")
            node.properties["has_public_access_block"] = (
                isinstance(pab, dict)
                and bool(pab.get("BlockPublicAcls"))
                and bool(pab.get("BlockPublicPolicy"))
                and bool(pab.get("IgnorePublicAcls"))
                and bool(pab.get("RestrictPublicBuckets"))
            )

        if "Logging" in entry or "LoggingEnabled" in entry:
            log_cfg = entry.get("Logging") if "Logging" in entry else entry.get("LoggingEnabled")
            node.properties["has_logging"] = bool(log_cfg)

        for lc_key in ("Lifecycle", "LifecycleConfiguration", "LifecycleRules"):
            if lc_key in entry:
                lc_val = entry.get(lc_key)
                if isinstance(lc_val, dict):
                    node.properties["has_lifecycle"] = bool(lc_val.get("Rules", lc_val))
                else:
                    node.properties["has_lifecycle"] = bool(lc_val)
                break

        if isinstance(entry.get("Tags"), dict):
            node.properties["tags"] = entry["Tags"]

        if entry.get("ServerSideEncryptionConfiguration"):
            self._apply_bucket_encryption(entry, filepath)

    def _apply_bucket_policy(self, entry: Dict[str, Any], filepath: str) -> None:
        bucket_name = str(entry.get("Bucket") or entry.get("Name") or "").strip()
        if not bucket_name:
            return
        node = self._get_or_create_bucket(bucket_name, filepath)
        raw_pol = entry.get("Policy")
        if raw_pol is None:
            node.properties.setdefault("bucket_policy_statements", [])
            return
        doc = decode_policy_document(raw_pol)
        stmts = parse_policy_statements(doc)
        node.properties["bucket_policy_statements"] = [s.model_dump() for s in stmts]

    def _apply_bucket_encryption(self, entry: Dict[str, Any], filepath: str) -> None:
        bucket_name = str(entry.get("Bucket") or entry.get("Name") or "").strip()
        if not bucket_name:
            return
        node = self._get_or_create_bucket(bucket_name, filepath)
        sse = entry.get("ServerSideEncryptionConfiguration")
        if not isinstance(sse, dict):
            return
        rules = sse.get("Rules") if "Rules" in sse else sse.get("Rule", [])
        if isinstance(rules, dict):
            rules = [rules]
        if not isinstance(rules, list):
            return
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            by_default = rule.get("ApplyServerSideEncryptionByDefault") or {}
            if not isinstance(by_default, dict):
                continue
            alg = str(by_default.get("SSEAlgorithm") or "").strip().lower()
            kms_ref = by_default.get("KMSMasterKeyID") or by_default.get("KMSMasterKeyId")
            if kms_ref and (not alg or alg == "aws:kms"):
                kms_ref_str = str(kms_ref).strip()
                node.properties["sse_kms_key_ref"] = kms_ref_str
                node.properties["kms_master_key_id"] = kms_ref_str
                node.kms_key_arn = kms_ref_str
                break

    def _resolve_bucket_kms_arns(self) -> None:
        for b in self.s3_buckets:
            ref = b.kms_key_arn or b.properties.get("sse_kms_key_ref")
            if not ref or ref.startswith("arn:"):
                continue
            matched = self._keys_by_key.get(ref)
            if matched is not None:
                b.kms_key_arn = matched.key_arn
