"""
AI-CSPM Contextual Graph Synthesizer (DAG Engine)
Builds the end-to-end multi-tier identity & cryptographic access graph using NetworkX.
"""

import fnmatch
import networkx as nx
from typing import Dict, List, Any, Optional
from .models import (
    NodeType,
    EdgeType,
    BaseNode,
    WorkloadNode,
    ServiceAccountNode,
    IAMRoleNode,
    IAMPolicyNode,
    KMSKeyNode,
    S3BucketNode,
    PolicyStatement,
    statement_allows_kms_decrypt,
    statement_denies_kms_decrypt,
    statement_has_encryption_context,
    statement_has_principal_or_source_restriction,
    statement_has_wildcard_kms_resource,
    statement_targets_kms_key,
)


def _extract_aws_account(arn: Optional[str]) -> Optional[str]:
    """Extracts the 12-digit AWS account ID from an ARN if present."""
    if not arn or not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    if len(parts) >= 5 and parts[4].isdigit():
        return parts[4]
    return None


def _exact_ref_matches(
    ref: str,
    name: str,
    node_id: str,
    arn: Optional[str] = None,
    res_id: Optional[str] = None
) -> bool:
    """Matches a resource/ARN reference cleanly without loose substring or cross-account collisions."""
    if not ref:
        return False
    ref_clean = str(ref).strip()

    # Prevent cross-account collisions when both sides specify AWS account IDs
    ref_acct = _extract_aws_account(ref_clean)
    node_acct = _extract_aws_account(arn)
    if ref_acct and node_acct and ref_acct != node_acct:
        return False

    candidates = {c for c in (name, node_id, arn, res_id) if c}
    if ref_clean in candidates:
        return True
    if "/" in ref_clean:
        suffix = ref_clean.split("/")[-1]
        if suffix and suffix in {c for c in (name, res_id) if c}:
            return True
    if ":" in ref_clean and not ref_clean.startswith("arn:"):
        return ref_clean in candidates
    return False


def _principal_matches_role(principal: Any, role: IAMRoleNode) -> Optional[str]:
    """Checks whether a resource policy Principal matches `role` ('explicit') or is public ('wildcard')."""
    if not principal:
        return None
    if principal == "*":
        return "wildcard"
    if isinstance(principal, dict):
        if principal.get("*") == "*":
            return "wildcard"
        for key, val in principal.items():
            if key not in ("AWS", "*"):
                continue
            entries = [val] if isinstance(val, str) else (val if isinstance(val, list) else [])
            for entry in entries:
                if entry == "*":
                    return "wildcard"
            for entry in entries:
                if isinstance(entry, str) and _exact_ref_matches(
                    entry,
                    name=role.name,
                    node_id=role.id,
                    arn=role.role_arn,
                    res_id=role.properties.get("res_id")
                ):
                    return "explicit"
    return None


def _resource_policy_allows_role_account(stmt: PolicyStatement, role: IAMRoleNode) -> bool:
    """Checks whether Principal-restrictive conditions (PrincipalAccount/CallerAccount) exclude `role`."""
    if not stmt.conditions or not isinstance(stmt.conditions, dict):
        return True
    role_acct = _extract_aws_account(role.role_arn)
    for op, cond_dict in stmt.conditions.items():
        if not isinstance(cond_dict, dict):
            continue
        op_l = str(op).lower()
        is_negated = ("notequals" in op_l) or ("notlike" in op_l)
        for ck, cv in cond_dict.items():
            ck_l = str(ck).lower()
            if "principalaccount" in ck_l or "calleraccount" in ck_l:
                vals = [str(cv)] if isinstance(cv, str) else ([str(x) for x in cv] if isinstance(cv, list) else [])
                if is_negated:
                    if role_acct and vals and any(fnmatch.fnmatchcase(role_acct, v) for v in vals):
                        return False
                else:
                    if not role_acct:
                        return False
                    if vals and not any(fnmatch.fnmatchcase(role_acct, v) for v in vals):
                        return False
            if "principalarn" in ck_l:
                vals = [str(cv)] if isinstance(cv, str) else ([str(x) for x in cv] if isinstance(cv, list) else [])
                role_matches_arn = any(
                    _exact_ref_matches(v, name=role.name, node_id=role.id, arn=role.role_arn, res_id=role.properties.get("res_id"))
                    or (role.role_arn and fnmatch.fnmatchcase(role.role_arn, v))
                    for v in vals
                )
                if is_negated:
                    if role_matches_arn:
                        return False
                elif vals and not role_matches_arn:
                    return False
            if "principalorgid" in ck_l:
                if not is_negated:
                    return False
    return True


def _kms_ref_matches_key(ref: str, key: KMSKeyNode) -> bool:
    """Checks whether a KMS key reference (ARN, alias, key ID, or TF interpolation) targets `key`."""
    if not ref:
        return False
    ref_s = str(ref).strip()
    key_res_id = key.properties.get("res_id", "")
    key_id = key.properties.get("key_id", "")
    candidates = {c for c in (key.key_arn, key.name, key.alias, key_res_id, key_id) if c}
    if ref_s in candidates:
        return True
    # Terraform attribute references like aws_kms_key.payment_key.arn
    for ident in {c for c in (key.name, key_res_id) if c}:
        if f"aws_kms_key.{ident}." in ref_s or ref_s == f"aws_kms_key.{ident}":
            return True
    if ":key/" in ref_s and ":key/" in key.key_arn:
        if ref_s.split(":key/")[-1] == key.key_arn.split(":key/")[-1]:
            return True
    if ":alias/" in ref_s and key.alias:
        alias_suffix = ref_s.split(":")[-1]
        if alias_suffix == key.alias:
            return True
    return False


class ContextualGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node: BaseNode):
        """Adds a typed semantic node to the graph."""
        self.graph.add_node(
            node.id,
            name=node.name,
            label=node.name,
            node_type=node.type.value,
            type=node.type.value,
            layer=node.layer,
            source_file=node.source_file,
            obj=node,
            properties=node.properties
        )

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, **kwargs):
        """Adds a directional semantic relationship edge."""
        if self.graph.has_node(source_id) and self.graph.has_node(target_id):
            self.graph.add_edge(
                source_id,
                target_id,
                edge_type=edge_type.value,
                **kwargs
            )

    def build_from_parsed(
        self,
        workloads: List[WorkloadNode],
        service_accounts: List[ServiceAccountNode],
        roles: List[IAMRoleNode],
        policies: List[IAMPolicyNode],
        kms_keys: List[KMSKeyNode],
        s3_buckets: List[S3BucketNode],
        attachments: List[Dict[str, str]]
    ):
        """Synthesizes all multi-tier components into a unified Directed Acyclic Graph."""
        # 1. Add all nodes
        for w in workloads:
            self.add_node(w)
        for sa in service_accounts:
            self.add_node(sa)
        for r in roles:
            self.add_node(r)
        for p in policies:
            self.add_node(p)
        for k in kms_keys:
            self.add_node(k)
        for b in s3_buckets:
            self.add_node(b)

        # 2. Link Workload -> ServiceAccount
        for w in workloads:
            sa_id = f"k8s:sa:{w.namespace}:{w.service_account}"
            if self.graph.has_node(sa_id):
                self.add_edge(w.id, sa_id, EdgeType.USES_SERVICE_ACCOUNT)

        # 3. Link ServiceAccount -> IAM Role (IRSA Bridge)
        for sa in service_accounts:
            # Match via SA annotation
            if sa.role_arn:
                for r in roles:
                    if _exact_ref_matches(
                        sa.role_arn,
                        name=r.name,
                        node_id=r.id,
                        arn=r.role_arn,
                        res_id=r.properties.get("res_id")
                    ):
                        self.add_edge(
                            sa.id,
                            r.id,
                            EdgeType.IRSA_ASSUMES,
                            protocol="OIDC WebIdentityFederation"
                        )

            # Match via Role Trust Policy OIDC Condition
            for r in roles:
                trust_stmts = r.trust_policy.get("Statement", [])
                if isinstance(trust_stmts, dict):
                    trust_stmts = [trust_stmts]
                for stmt in trust_stmts:
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("Effect", "Allow")).strip().lower() != "allow":
                        continue
                    raw_actions = stmt.get("Action", [])
                    actions_list = [raw_actions] if isinstance(raw_actions, str) else (raw_actions if isinstance(raw_actions, list) else [])
                    if not any(
                        str(a).strip().lower() in ("*", "sts:*", "sts:assumerolewithwebidentity")
                        or "assumerolewithwebidentity" in str(a).lower()
                        for a in actions_list
                    ):
                        continue

                    principal = stmt.get("Principal") or {}
                    fed_principal = principal.get("Federated") if isinstance(principal, dict) else None
                    if fed_principal is None and not r.oidc_provider:
                        continue
                    fed_list = (
                        [fed_principal] if isinstance(fed_principal, str)
                        else (fed_principal if isinstance(fed_principal, list) else [])
                    )
                    if not fed_list and isinstance(r.oidc_provider, str):
                        fed_list = [r.oidc_provider]
                    elif not fed_list and isinstance(r.oidc_provider, list):
                        fed_list = r.oidc_provider
                    oidc_hosts = [
                        fp.split("oidc-provider/", 1)[1]
                        for fp in fed_list
                        if isinstance(fp, str) and "oidc-provider/" in fp
                    ]

                    cond = stmt.get("Condition", {}) or {}
                    expected_sub = f"system:serviceaccount:{sa.namespace}:{sa.name}"
                    for op in ("StringEquals", "StringLike"):
                        string_match = cond.get(op, {}) or {}
                        if not isinstance(string_match, dict):
                            continue
                        for cond_key, cond_val in string_match.items():
                            ck_str = str(cond_key)
                            if ":sub" not in ck_str:
                                continue
                            if oidc_hosts and ":" in ck_str:
                                key_host = ck_str.rsplit(":", 1)[0]
                                if key_host and not any(h in key_host or key_host in h for h in oidc_hosts):
                                    continue
                            val_list = [cond_val] if isinstance(cond_val, str) else (cond_val if isinstance(cond_val, list) else [])
                            matched = any(
                                isinstance(v, str)
                                and (
                                    v == expected_sub
                                    or (op == "StringLike" and fnmatch.fnmatchcase(expected_sub, v))
                                )
                                for v in val_list
                            )
                            if matched:
                                self.add_edge(
                                    sa.id,
                                    r.id,
                                    EdgeType.IRSA_ASSUMES,
                                    protocol="OIDC WebIdentityFederation",
                                    sub_claim=cond_val
                                )

        # 4. Link IAM Role -> IAM Policy (Exact Attachment Matching)
        for att in attachments:
            role_ref = att.get("role", "")
            policy_ref = att.get("policy", "")

            matched_roles = [
                r for r in roles
                if _exact_ref_matches(
                    role_ref,
                    name=r.name,
                    node_id=r.id,
                    arn=r.role_arn,
                    res_id=r.properties.get("res_id")
                )
            ]
            matched_policies = [
                p for p in policies
                if _exact_ref_matches(
                    policy_ref,
                    name=p.name,
                    node_id=p.id,
                    arn=p.policy_arn,
                    res_id=p.properties.get("res_id")
                )
            ]

            for r in matched_roles:
                for p in matched_policies:
                    self.add_edge(r.id, p.id, EdgeType.HAS_POLICY)

        # 4b. Compute Role-Level Unconditional Deny across ALL attached policies per IAM Role
        for r in roles:
            r_denied_key_ids = set()
            for p_id in self.graph.successors(r.id):
                p_obj = self.graph.nodes[p_id].get("obj")
                if not p_obj:
                    continue
                for stmt in getattr(p_obj, "statements", []):
                    if statement_denies_kms_decrypt(stmt):
                        for k in kms_keys:
                            if statement_targets_kms_key(stmt, lambda ref, key=k: _kms_ref_matches_key(ref, key)):
                                r_denied_key_ids.add(k.id)
            self.graph.nodes[r.id]["denied_kms_key_ids"] = r_denied_key_ids

        # 5. Link IAM Policy -> KMS Key (Respecting Deny, NotResource, & Merging Multi-Statement Edges)
        for p in policies:
            denied_key_ids = set()
            for stmt in p.statements:
                if statement_denies_kms_decrypt(stmt):
                    for k in kms_keys:
                        if statement_targets_kms_key(stmt, lambda ref, key=k: _kms_ref_matches_key(ref, key)):
                            denied_key_ids.add(k.id)

            for stmt in p.statements:
                if not statement_allows_kms_decrypt(stmt):
                    continue

                is_wildcard = statement_has_wildcard_kms_resource(stmt)
                has_encryption_context = statement_has_encryption_context(stmt)
                is_lethal = is_wildcard and not has_encryption_context

                for k in kms_keys:
                    if k.id in denied_key_ids:
                        continue
                    is_target_key = statement_targets_kms_key(stmt, lambda ref, key=k: _kms_ref_matches_key(ref, key))
                    if not is_target_key:
                        continue

                    if self.graph.has_edge(p.id, k.id):
                        existing = self.graph.get_edge_data(p.id, k.id, default={})
                        merged_actions = list(dict.fromkeys((existing.get("actions") or []) + list(stmt.actions)))
                        self.graph[p.id][k.id]["actions"] = merged_actions
                        self.graph[p.id][k.id]["is_wildcard"] = bool(existing.get("is_wildcard") or is_wildcard)
                        self.graph[p.id][k.id]["lethal_flaw"] = bool(existing.get("lethal_flaw") or is_lethal)
                    else:
                        self.add_edge(
                            p.id,
                            k.id,
                            EdgeType.ALLOWS_DECRYPT,
                            actions=list(stmt.actions),
                            is_wildcard=is_wildcard,
                            lethal_flaw=is_lethal
                        )

        # 5b. Link Direct KMS Key Resource Policy Grants (IAMRole -> KMSKey), respecting resource-policy Denies & CallerAccount
        for k in kms_keys:
            raw_stmts = k.properties.get("policy_statements", [])
            parsed_k_stmts = [s if isinstance(s, PolicyStatement) else PolicyStatement(**s) for s in raw_stmts]
            k_denied_roles = {
                r.id for r in roles
                if any(statement_denies_kms_decrypt(ds) and _principal_matches_role(ds.principal, r) for ds in parsed_k_stmts)
            }
            for stmt in parsed_k_stmts:
                if not statement_allows_kms_decrypt(stmt):
                    continue
                has_enc_ctx = statement_has_encryption_context(stmt)
                for r in roles:
                    if r.id in k_denied_roles:
                        continue
                    r_attrs = self.graph.nodes[r.id]
                    if k.id in r_attrs.get("denied_kms_key_ids", set()):
                        continue
                    match_kind = _principal_matches_role(stmt.principal, r)
                    if not match_kind:
                        continue
                    if match_kind == "wildcard" and not _resource_policy_allows_role_account(stmt, r):
                        continue
                    role_has_iam_policy_to_key = any(
                        self.graph.has_edge(p_id, k.id)
                        for p_id in self.graph.successors(r.id)
                        if self.graph.nodes[p_id].get("node_type") == NodeType.IAM_POLICY.value
                    )
                    if match_kind == "wildcard" or not role_has_iam_policy_to_key:
                        is_lethal = not has_enc_ctx
                        if is_lethal and not self.graph.has_edge(r.id, k.id):
                            self.add_edge(
                                r.id,
                                k.id,
                                EdgeType.ALLOWS_DECRYPT,
                                actions=list(stmt.actions or ["kms:Decrypt"]),
                                is_wildcard=(match_kind == "wildcard"),
                                lethal_flaw=True,
                                via_resource_policy=True
                            )

        # 6. Link KMS Key -> S3 Bucket (Only when Bucket uses that CMK)
        for b in s3_buckets:
            bucket_kms_ref = (
                b.kms_key_arn
                or b.properties.get("kms_master_key_id")
                or b.properties.get("sse_kms_key_ref")
            )
            if not bucket_kms_ref:
                continue
            for k in kms_keys:
                if _kms_ref_matches_key(bucket_kms_ref, k):
                    self.add_edge(k.id, b.id, EdgeType.ENCRYPTS_BUCKET)

        # 6b. Link Direct S3 Bucket Resource Policy Grants (IAMRole -> S3Bucket), respecting Denies & not masked by KMS path
        def _s3_stmt_allows_read(s: PolicyStatement) -> bool:
            if s.actions:
                return any(str(a).strip().lower() in ("*", "s3:*", "s3:getobject", "s3:get*") for a in s.actions)
            if s.not_actions:
                return not any(str(a).strip().lower() in ("*", "s3:*", "s3:getobject") for a in s.not_actions)
            return False

        for b in s3_buckets:
            raw_b_stmts = b.properties.get("bucket_policy_statements", [])
            parsed_b_stmts = [s if isinstance(s, PolicyStatement) else PolicyStatement(**s) for s in raw_b_stmts]
            b_denied_roles = {
                r.id for r in roles
                if any(
                    ds.effect.strip().lower() == "deny"
                    and not ds.conditions
                    and _s3_stmt_allows_read(ds)
                    and _principal_matches_role(ds.principal, r)
                    for ds in parsed_b_stmts
                )
            }
            for stmt in parsed_b_stmts:
                if stmt.effect.strip().lower() != "allow" or not _s3_stmt_allows_read(stmt):
                    continue
                has_conditions = bool(stmt.conditions)
                has_identity_restriction = statement_has_principal_or_source_restriction(stmt.conditions)
                for r in roles:
                    if r.id in b_denied_roles:
                        continue
                    match_kind = _principal_matches_role(stmt.principal, r)
                    if not match_kind:
                        continue
                    if match_kind == "wildcard" and not _resource_policy_allows_role_account(stmt, r):
                        continue
                    wildcard_unrestricted = (match_kind == "wildcard" and not has_identity_restriction)
                    if (wildcard_unrestricted or not has_conditions) and not self.graph.has_edge(r.id, b.id):
                        self.add_edge(
                            r.id,
                            b.id,
                            EdgeType.RESOURCE_POLICY_ALLOWS,
                            actions=list(stmt.actions or ["s3:GetObject"]),
                            is_wildcard=(match_kind == "wildcard"),
                            lethal_flaw=True,
                            via_resource_policy=True
                        )

    def to_dict_format(self) -> Dict[str, Any]:
        """Exports graph to a visual-friendly JSON format for Dashboards (React Flow / Streamlit)."""
        nodes_data = []
        for n, attrs in self.graph.nodes(data=True):
            nodes_data.append({
                "id": n,
                "label": attrs.get("name", n),
                "type": attrs.get("node_type", "UNKNOWN"),
                "layer": attrs.get("layer", "Unknown"),
                "source_file": attrs.get("source_file", "")
            })

        edges_data = []
        for u, v, attrs in self.graph.edges(data=True):
            edges_data.append({
                "source": u,
                "target": v,
                "type": attrs.get("edge_type", ""),
                "is_wildcard": attrs.get("is_wildcard", False),
                "lethal_flaw": attrs.get("lethal_flaw", False)
            })

        return {"nodes": nodes_data, "edges": edges_data}
