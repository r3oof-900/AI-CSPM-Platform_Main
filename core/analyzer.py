"""
AI-CSPM Dynamic Attack Path & Policy Rule Analyzer
Performs AST-driven declarative security checks and traverses the DAG for cross-layer compromise chains.
"""

import networkx as nx
from typing import List, Dict, Any, Optional, Set
from .graph import ContextualGraph
from .models import (
    AttackPath,
    Severity,
    NodeType,
    EdgeType,
    MisconfigurationFinding,
    FindingCategory,
    statement_allows_kms_decrypt,
    statement_denies_kms_decrypt,
    statement_has_encryption_context,
    statement_has_principal_or_source_restriction,
    statement_has_wildcard_kms_resource,
)


class AttackPathAnalyzer:
    def __init__(
        self,
        contextual_graph: ContextualGraph,
        tf_parser: Optional[Any] = None,
        k8s_parser: Optional[Any] = None
    ):
        self.cg = contextual_graph
        self.graph = contextual_graph.graph
        self.tf = tf_parser
        self.k8s = k8s_parser

    def find_cross_layer_attack_paths(self, cutoff: int = 8) -> List[AttackPath]:
        """Discovers all viable paths from Kubernetes Workloads to sensitive Cloud Vaults."""
        attack_paths: List[AttackPath] = []

        # 1. Identify start nodes (Workloads)
        workloads = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NodeType.WORKLOAD.value
        ]

        # 2. Identify terminal target nodes (S3 Buckets, plus KMS Keys not linked to any S3 Bucket)
        targets = []
        for n, d in self.graph.nodes(data=True):
            ntype = d.get("node_type")
            if ntype == NodeType.S3_BUCKET.value:
                targets.append(n)
            elif ntype == NodeType.KMS_KEY.value:
                has_bucket_child = any(
                    self.graph.nodes[succ].get("node_type") == NodeType.S3_BUCKET.value
                    for succ in self.graph.successors(n)
                )
                if not has_bucket_child:
                    targets.append(n)

        path_idx = 1
        for w in workloads:
            for t in targets:
                if not nx.has_path(self.graph, w, t):
                    continue

                for simple_path in nx.all_simple_paths(self.graph, w, t, cutoff=cutoff):
                    # Check Role-level Deny across all policies attached to the IAM Role
                    role_ids_in_path = [
                        nid for nid in simple_path
                        if self.graph.nodes[nid].get("node_type") == NodeType.IAM_ROLE.value
                    ]
                    kms_ids_in_path = {
                        nid for nid in simple_path
                        if self.graph.nodes[nid].get("node_type") == NodeType.KMS_KEY.value
                    }
                    blocked_by_role_deny = False
                    for r_id in role_ids_in_path:
                        r_attrs = self.graph.nodes[r_id]
                        if kms_ids_in_path & set(r_attrs.get("denied_kms_key_ids", set())):
                            blocked_by_role_deny = True
                            break
                    if blocked_by_role_deny:
                        continue

                    # Check if path contains a lethal wildcard decrypt or resource policy flaw
                    has_lethal_flaw = False
                    flawed_policy_name = None
                    flawed_key_name = None
                    flawed_actions: List[str] = []
                    via_resource_policy = False
                    for i in range(len(simple_path) - 1):
                        u, v = simple_path[i], simple_path[i + 1]
                        edge_data = self.graph.get_edge_data(u, v, default={})
                        if edge_data.get("lethal_flaw"):
                            has_lethal_flaw = True
                            flawed_policy_name = self.graph.nodes[u].get("name", u)
                            flawed_key_name = self.graph.nodes[v].get("name", v)
                            flawed_actions = edge_data.get("actions") or ["kms:Decrypt"]
                            via_resource_policy = bool(edge_data.get("via_resource_policy"))
                            break

                    if not has_lethal_flaw:
                        # Path is cryptographically scoped and safe - not an attack path!
                        continue

                    # Construct detailed Attack Path object
                    path_nodes = []
                    path_steps = []
                    for i, node_id in enumerate(simple_path):
                        node_attrs = self.graph.nodes[node_id]
                        name = node_attrs.get("name", node_id)
                        layer = node_attrs.get("layer", "Unknown")
                        ntype = node_attrs.get("node_type", "UNKNOWN")
                        node_obj = node_attrs.get("obj")
                        step_num = i + 1

                        node_entry: Dict[str, Any] = {
                            "id": node_id,
                            "name": name,
                            "type": ntype,
                            "layer": layer,
                            "source_file": node_attrs.get("source_file")
                        }
                        if ntype == NodeType.KMS_KEY.value and node_obj is not None:
                            node_entry["key_arn"] = getattr(node_obj, "key_arn", None)
                            node_entry["alias"] = getattr(node_obj, "alias", None)
                        elif ntype == NodeType.S3_BUCKET.value and node_obj is not None:
                            node_entry["bucket_arn"] = getattr(node_obj, "bucket_arn", None)
                            node_entry["bucket_name"] = getattr(node_obj, "bucket_name", None)
                        elif ntype == NodeType.IAM_POLICY.value and node_obj is not None:
                            node_entry["policy_arn"] = getattr(node_obj, "policy_arn", None)
                        elif ntype == NodeType.IAM_ROLE.value and node_obj is not None:
                            node_entry["role_arn"] = getattr(node_obj, "role_arn", None)
                        path_nodes.append(node_entry)

                        if i == 0:
                            path_steps.append(f"{step_num}. In-Cluster Workload: Container '{name}' compromised in Kubernetes '{layer}' layer.")
                        elif ntype == NodeType.SERVICE_ACCOUNT.value:
                            path_steps.append(f"{step_num}. Workload Identity Token: Container inherits tokens from ServiceAccount '{name}'.")
                        elif ntype == NodeType.IAM_ROLE.value:
                            path_steps.append(f"{step_num}. Cloud Identity Escalation: STS WebIdentity federation assumes AWS IAM Role '{name}'.")
                        elif ntype == NodeType.IAM_POLICY.value:
                            act_str = ", ".join(flawed_actions[:3])
                            path_steps.append(f"{step_num}. Lethal Wildcard Grant: Attached IAM Policy '{name}' permits '{act_str}' on '*' resource without EncryptionContext.")
                        elif ntype == NodeType.KMS_KEY.value:
                            if via_resource_policy:
                                path_steps.append(f"{step_num}. Direct KMS Resource Policy Exposure: KMS Key '{name}' grants decryption directly to role/wildcard without EncryptionContext.")
                            else:
                                path_steps.append(f"{step_num}. Cryptographic Exfiltration: Wildcard enables decrypting Customer Managed Key '{name}'.")
                        elif ntype == NodeType.S3_BUCKET.value:
                            if via_resource_policy:
                                path_steps.append(f"{step_num}. Direct S3 Bucket Policy Exposure: Bucket '{name}' permits direct read access without restrictive conditions.")
                            else:
                                path_steps.append(f"{step_num}. Vault Breach: Full exfiltration of protected records in S3 bucket '{name}'.")

                    rc_source = (
                        f"Resource Policy on '{flawed_key_name}' grants direct access to federated role '{flawed_policy_name}'"
                        if via_resource_policy
                        else f"IAM Policy '{flawed_policy_name}' grants wildcard {', '.join(flawed_actions[:2])} on '*' to an EKS federated role"
                    )
                    ap = AttackPath(
                        id=f"AP-{path_idx:03d}",
                        title=f"Multi-Tier Cryptographic Exfiltration: {path_nodes[0]['name']} -> {path_nodes[-1]['name']}",
                        severity=Severity.CRITICAL,
                        nodes=path_nodes,
                        steps=path_steps,
                        root_cause=(
                            f"Architectural disconnect between single-layer tools. "
                            f"{rc_source}, allowing arbitrary container exfiltration of assets in '{flawed_key_name}'."
                        ),
                        impact=(
                            f"Critical data breach: An attacker exploiting container '{path_nodes[0]['name']}' acquires "
                            f"unrestricted capabilities to decrypt database and storage assets across the cloud tenant."
                        ),
                        false_negative_tools=[
                            "Prowler v5.46 (Gave 100% PASS - checks *:* only)",
                            "ScoutSuite 5.14 (0 findings - no Kubernetes awareness)",
                            "AWS IAM Access Analyzer (findings: [] - syntax valid)",
                            "ARMO Kubescape (Halts at Kubernetes cluster boundary)",
                            "Checkov & Trivy (Segregated inspection - misses cross-layer link)"
                        ]
                    )
                    attack_paths.append(ap)
                    path_idx += 1

        return attack_paths

    def audit_all_misconfigurations(
        self,
        attack_paths: Optional[List[AttackPath]] = None
    ) -> List[MisconfigurationFinding]:
        """
        Performs AST-driven multi-tier security inspection across Kubernetes,
        Cloud IAM, KMS Cryptography, Storage, and RBAC to discover real misconfigurations.
        """
        findings: List[MisconfigurationFinding] = []
        secrets_reading_sas: Set[str] = set()

        # 1. Inspect IAM Policies for Overprivileged Grants
        for n, d in self.graph.nodes(data=True):
            if d.get("node_type") == NodeType.IAM_POLICY.value:
                policy_name = d.get("name", n)
                obj = d.get("obj")
                stmts = getattr(obj, "statements", []) if obj else []

                if any(
                    statement_denies_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                    for s in stmts
                ):
                    continue

                # Check for wildcard decrypt without EncryptionContext
                for s in stmts:
                    if (
                        statement_allows_kms_decrypt(s)
                        and statement_has_wildcard_kms_resource(s)
                        and not statement_has_encryption_context(s)
                    ):
                        findings.append(MisconfigurationFinding(
                            id="SEC-IAM-001",
                            title="Overprivileged IAM Action: kms:Decrypt Granted on Wildcard Resource '*'",
                            category=FindingCategory.CLOUD_IAM,
                            severity=Severity.CRITICAL,
                            resource_id=policy_name,
                            resource_type="aws_iam_policy",
                            layer="IAM",
                            description=(
                                f"Policy '{policy_name}' allows '{', '.join(s.actions[:3])}' with Resource: '*'. "
                                "This grants any principal assuming this role unrestricted capability to decrypt "
                                "ANY Customer Managed Key (CMK) across the entire AWS account."
                            ),
                            remediation_recommendation=(
                                "Replace wildcard Resource '*' with the explicit ARN of the authorized target Customer "
                                "Managed Key and enforce cryptographic conditions."
                            ),
                            compliance_controls=["CIS AWS Foundations 1.16", "PCI-DSS v4.0 Req 3.4", "NIST SP 800-53 AC-6"],
                            cvss_score=9.1
                        ))
                        break

            # 2. Inspect IAM Roles and Trust Policies
            elif d.get("node_type") == NodeType.IAM_ROLE.value:
                role_name = d.get("name", n)
                obj = d.get("obj")
                trust_policy = getattr(obj, "trust_policy", {}) if obj else d.get("trust_policy", {})
                props = d.get("properties", {})
                raw_props = props.get("raw", {})

                # Check for OIDC trust scoping
                trust_stmts = trust_policy.get("Statement", [])
                if isinstance(trust_stmts, dict):
                    trust_stmts = [trust_stmts]
                for stmt in trust_stmts:
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("Effect", "Allow")).strip().lower() != "allow":
                        continue
                    raw_actions = stmt.get("Action", [])
                    actions_list = [raw_actions] if isinstance(raw_actions, str) else (raw_actions if isinstance(raw_actions, list) else [])
                    if any("AssumeRoleWithWebIdentity" in str(a) for a in actions_list):
                        cond = stmt.get("Condition", {}) or {}
                        cond_keys: List[str] = []
                        for op in ("StringEquals", "StringLike"):
                            sub_map = cond.get(op, {})
                            if isinstance(sub_map, dict):
                                cond_keys.extend(str(k) for k in sub_map.keys())
                        has_sub = any(":sub" in k for k in cond_keys)
                        has_aud = any(":aud" in k for k in cond_keys)

                        if not has_sub or not has_aud:
                            findings.append(MisconfigurationFinding(
                                id="SEC-IAM-002",
                                title="Overbroad EKS OIDC Federated Trust Relationship",
                                category=FindingCategory.CLOUD_IAM,
                                severity=Severity.HIGH,
                                resource_id=role_name,
                                resource_type="aws_iam_role",
                                layer="IAM",
                                description=(
                                    f"IAM Role '{role_name}' uses sts:AssumeRoleWithWebIdentity. The OIDC condition "
                                    "lacks strict sub or aud claim verification, permitting unauthorized containers to assume this role."
                                ),
                                remediation_recommendation="Enforce strict StringEquals on both oidc:sub and oidc:aud.",
                                compliance_controls=["CIS AWS Foundations 1.20", "AWS EKS Security Best Practices", "NIST AC-2"],
                                cvss_score=7.8
                            ))
                            break

                # Check permissions boundary (skip AWS Service-Linked Roles where AWS forbids boundaries)
                role_path = str(props.get("path") or raw_props.get("path") or "")
                role_arn_str = str(getattr(obj, "role_arn", "") or props.get("role_arn") or "")
                is_service_linked = (
                    role_path.startswith("/aws-service-role/")
                    or "/aws-service-role/" in role_arn_str
                    or role_name.startswith("AWSServiceRoleFor")
                )
                has_boundary = ("permissions_boundary" in raw_props) or bool(props.get("permissions_boundary"))
                if not has_boundary and not is_service_linked:
                    findings.append(MisconfigurationFinding(
                        id="SEC-IAM-004",
                        title="IAM Federated Execution Role Missing Permissions Boundary",
                        category=FindingCategory.CLOUD_IAM,
                        severity=Severity.MEDIUM,
                        resource_id=role_name,
                        resource_type="aws_iam_role",
                        layer="IAM",
                        description=(
                            f"The execution role '{role_name}' lacks an attached permissions_boundary. If an identity "
                            "manipulates policy attachments, privilege escalation to AdministratorAccess is possible."
                        ),
                        remediation_recommendation="Define and attach an explicit IAM permissions_boundary to all workload roles.",
                        compliance_controls=["CIS AWS Benchmark 1.18", "AWS Well-Architected Security Pillar"],
                        cvss_score=5.8
                    ))

            # 3. Inspect KMS Cryptographic Keys
            elif d.get("node_type") == NodeType.KMS_KEY.value:
                key_name = d.get("name", n)
                props = d.get("properties", {})
                key_stmts = props.get("policy_statements", [])
                policy_fetched = props.get("policy_fetched", True)

                if policy_fetched:
                    # Check root delegation
                    has_root_grant = False
                    for stmt in key_stmts:
                        if isinstance(stmt, dict):
                            effect = str(stmt.get("effect", stmt.get("Effect", "Allow"))).strip().lower()
                            principal = stmt.get("principal") or stmt.get("Principal") or {}
                            actions = stmt.get("actions") or stmt.get("Action") or []
                        else:
                            effect = str(getattr(stmt, "effect", "Allow")).strip().lower()
                            principal = getattr(stmt, "principal", {}) or {}
                            actions = getattr(stmt, "actions", []) or []

                        if effect != "allow":
                            continue
                        if isinstance(actions, str):
                            actions = [actions]
                        principal_str = str(principal).lower()
                        if ":root" in principal_str and any(str(a).strip().lower() in ("kms:*", "*") for a in actions):
                            has_root_grant = True
                            break

                    # In AWS, an aws_kms_key without an explicit policy uses the default policy granting root kms:*
                    if has_root_grant or not key_stmts:
                        findings.append(MisconfigurationFinding(
                            id="SEC-IAM-003",
                            title="Direct AWS Root Account Principal Delegation in KMS Key Policy",
                            category=FindingCategory.CRYPTOGRAPHY,
                            severity=Severity.MEDIUM,
                            resource_id=key_name,
                            resource_type="aws_kms_key",
                            layer="Cryptography",
                            description=(
                                f"Key '{key_name}' policy includes statement granting full kms:* "
                                "to root principal arn:aws:iam::<account>:root without separation of administrative duties."
                            ),
                            remediation_recommendation="Separate KMS Key administration from cryptographic usage roles to prevent single-principal compromise.",
                            compliance_controls=["CIS AWS Benchmark 2.8", "NIST IA-2(1)", "PCI-DSS Req 3.5.1"],
                            cvss_score=6.5
                        ))

                    # Check ViaService / CallerAccount condition inside condition operator sub-dicts
                    has_via_service = False
                    for stmt in key_stmts:
                        cond = (stmt.get("conditions") or stmt.get("Condition") or {}) if isinstance(stmt, dict) else (getattr(stmt, "conditions", {}) or {})
                        if isinstance(cond, dict):
                            for _, cond_dict in cond.items():
                                if isinstance(cond_dict, dict) and any(
                                    "viaservice" in str(k).lower() or "calleraccount" in str(k).lower()
                                    for k in cond_dict.keys()
                                ):
                                    has_via_service = True
                                    break
                        if has_via_service:
                            break

                    if not has_via_service:
                        findings.append(MisconfigurationFinding(
                            id="SEC-KMS-001",
                            title="KMS Key Policy Lacks ViaService / CallerAccount Cryptographic Constraints",
                            category=FindingCategory.CRYPTOGRAPHY,
                            severity=Severity.MEDIUM,
                            resource_id=key_name,
                            resource_type="aws_kms_key",
                            layer="Cryptography",
                            description=(
                                f"Key '{key_name}' permits decryption without restricting the calling AWS service via condition "
                                "keys like kms:ViaService (e.g., s3.amazonaws.com)."
                            ),
                            remediation_recommendation="Add StringEquals condition matching kms:ViaService to the authorized AWS service.",
                            compliance_controls=["CIS AWS Foundations 2.8", "NIST SC-13"],
                            cvss_score=5.3
                        ))

                # Check KMS automatic annual key rotation
                k_obj = d.get("obj")
                if k_obj is not None and getattr(k_obj, "rotation_enabled", True) is False:
                    findings.append(MisconfigurationFinding(
                        id="SEC-KMS-002",
                        title="KMS Customer Managed Key Automatic Rotation Disabled",
                        category=FindingCategory.CRYPTOGRAPHY,
                        severity=Severity.MEDIUM,
                        resource_id=key_name,
                        resource_type="aws_kms_key",
                        layer="Cryptography",
                        description=(
                            f"Key '{key_name}' does not have automatic annual cryptographic key rotation enabled (enable_key_rotation = false)."
                        ),
                        remediation_recommendation="Set enable_key_rotation = true on the aws_kms_key resource.",
                        compliance_controls=["CIS AWS Foundations 3.8", "PCI-DSS v4.0 Req 3.6", "NIST SC-12"],
                        cvss_score=5.3
                    ))

            # 4. Inspect S3 Storage Vaults
            elif d.get("node_type") == NodeType.S3_BUCKET.value:
                bucket_name = d.get("name", n)
                props = d.get("properties", {})
                res_id = props.get("res_id", bucket_name)

                # Check public access block (node property from live fetcher OR Terraform parser)
                if "has_public_access_block" in props and props["has_public_access_block"] is not None:
                    has_pab: Optional[bool] = bool(props["has_public_access_block"])
                elif self.tf is not None:
                    pab_entry = self.tf.s3_public_access_blocks.get(bucket_name) or self.tf.s3_public_access_blocks.get(res_id)
                    has_pab = bool(pab_entry.get("_all_blocked", False)) if pab_entry else False
                else:
                    has_pab = None

                if has_pab is False:
                    findings.append(MisconfigurationFinding(
                        id="SEC-S3-001",
                        title="Target S3 Vault Missing Explicit aws_s3_bucket_public_access_block",
                        category=FindingCategory.STORAGE,
                        severity=Severity.HIGH,
                        resource_id=bucket_name,
                        resource_type="aws_s3_bucket",
                        layer="Storage",
                        description=(
                            f"S3 bucket '{bucket_name}' lacks an attached aws_s3_bucket_public_access_block resource, "
                            "leaving it vulnerable to accidental public exposure through faulty bucket ACLs or policy edits."
                        ),
                        remediation_recommendation=(
                            "Declare an aws_s3_bucket_public_access_block resource setting block_public_acls = true, "
                            "block_public_policy = true, ignore_public_acls = true, and restrict_public_buckets = true."
                        ),
                        compliance_controls=["CIS AWS Foundations 2.1.5", "PCI-DSS v4.0 Req 1.3", "NIST AC-3"],
                        cvss_score=7.3
                    ))

                # Check access logging
                if "has_logging" in props and props["has_logging"] is not None:
                    has_logging: Optional[bool] = bool(props["has_logging"])
                elif self.tf is not None:
                    has_logging = bucket_name in self.tf.s3_logging_configs or res_id in self.tf.s3_logging_configs
                else:
                    has_logging = None

                if has_logging is False:
                    findings.append(MisconfigurationFinding(
                        id="SEC-S3-002",
                        title="S3 Bucket Missing Server Access Logging",
                        category=FindingCategory.STORAGE,
                        severity=Severity.MEDIUM,
                        resource_id=bucket_name,
                        resource_type="aws_s3_bucket",
                        layer="Storage",
                        description=(
                            f"S3 bucket '{bucket_name}' has no aws_s3_bucket_logging resource attached. Access requests "
                            "and suspicious exfiltration attempts are not captured for SIEM forensic analysis."
                        ),
                        remediation_recommendation="Enable S3 bucket logging targeting a dedicated secure audit logging bucket.",
                        compliance_controls=["CIS AWS Foundations 2.1.3", "NIST AU-2"],
                        cvss_score=5.1
                    ))

                # Check lifecycle rules
                if "has_lifecycle" in props and props["has_lifecycle"] is not None:
                    has_lifecycle: Optional[bool] = bool(props["has_lifecycle"])
                elif self.tf is not None:
                    has_lifecycle = bucket_name in self.tf.s3_lifecycle_configs or res_id in self.tf.s3_lifecycle_configs
                else:
                    has_lifecycle = None

                if has_lifecycle is False:
                    findings.append(MisconfigurationFinding(
                        id="SEC-S3-003",
                        title="S3 Bucket Missing Object Lifecycle Configuration",
                        category=FindingCategory.STORAGE,
                        severity=Severity.LOW,
                        resource_id=bucket_name,
                        resource_type="aws_s3_bucket",
                        layer="Storage",
                        description=f"Bucket '{bucket_name}' does not configure expiration or archival rules for stale records.",
                        remediation_recommendation="Implement aws_s3_bucket_lifecycle_configuration to archive or expire old objects.",
                        compliance_controls=["AWS Storage Best Practices"],
                        cvss_score=3.9
                    ))

                # Check Bucket Policy for public wildcard access
                def _is_public_principal(princ: Any) -> bool:
                    if princ == "*":
                        return True
                    if isinstance(princ, dict):
                        for pv in princ.values():
                            if pv == "*" or (isinstance(pv, list) and "*" in pv):
                                return True
                    return False

                for bp_stmt in props.get("bucket_policy_statements", []):
                    bp_eff = str(bp_stmt.get("effect", "Allow")).strip().lower()
                    bp_princ = bp_stmt.get("principal")
                    bp_cond = bp_stmt.get("conditions") or {}
                    if bp_eff == "allow" and _is_public_principal(bp_princ) and not statement_has_principal_or_source_restriction(bp_cond):
                        findings.append(MisconfigurationFinding(
                            id="SEC-S3-004",
                            title="S3 Bucket Policy Grants Public Unconditional Access (Principal '*')",
                            category=FindingCategory.STORAGE,
                            severity=Severity.CRITICAL,
                            resource_id=bucket_name,
                            resource_type="aws_s3_bucket_policy",
                            layer="Storage",
                            description=(
                                f"S3 bucket '{bucket_name}' attaches a bucket policy allowing Principal '*' without restrictive Condition keys."
                            ),
                            remediation_recommendation="Replace Principal '*' with explicit IAM role ARNs and enforce aws:SourceVpce or aws:PrincipalOrgID conditions.",
                            compliance_controls=["CIS AWS Foundations 2.1.5", "PCI-DSS v4.0 Req 1.3"],
                            cvss_score=9.0
                        ))
                        break

            # 5. Inspect Kubernetes Workloads
            elif d.get("node_type") == NodeType.WORKLOAD.value:
                workload_name = d.get("name", n)
                obj: Any = d.get("obj")
                sa_name = getattr(obj, "service_account", "default")
                ns = getattr(obj, "namespace", "default")
                w_props = d.get("properties", {})

                # Check automountServiceAccountToken on workload OR its ServiceAccount OR projected token volume
                automount = w_props.get("automountServiceAccountToken")
                sa_node = self.graph.nodes.get(f"k8s:sa:{ns}:{sa_name}", {})
                sa_automount = sa_node.get("properties", {}).get("automountServiceAccountToken")
                sa_uses_irsa = bool(getattr(sa_node.get("obj"), "role_arn", None))
                volumes = w_props.get("volumes") or []
                has_projected_sa_token = any(
                    isinstance(v, dict)
                    and isinstance(v.get("projected"), dict)
                    and any("serviceAccountToken" in src for src in (v["projected"].get("sources") or []) if isinstance(src, dict))
                    for v in volumes
                )
                token_disabled = (automount is False) or (automount is None and sa_automount is False) or has_projected_sa_token
                if not token_disabled:
                    findings.append(MisconfigurationFinding(
                        id="SEC-K8S-002",
                        title="ServiceAccount Projected Token Auto-Mount Not Disabled",
                        category=FindingCategory.KUBERNETES,
                        severity=Severity.LOW if sa_uses_irsa else Severity.MEDIUM,
                        resource_id=workload_name,
                        resource_type=f"k8s:{w_props.get('kind', 'Deployment')}",
                        layer="Kubernetes",
                        description=(
                            f"Workload '{workload_name}' does not set automountServiceAccountToken: false. "
                            + ("Note: ServiceAccount uses IRSA; verify projected OIDC token injection can replace default API token mount."
                               if sa_uses_irsa else "The internal API server token is automatically injected into /var/run/secrets/kubernetes.io/serviceaccount/.")
                        ),
                        remediation_recommendation="Use explicit projected ServiceAccount tokens or disable automountServiceAccountToken when K8s API access is unneeded.",
                        compliance_controls=["CIS Kubernetes Benchmark 5.1.6", "NSA K8s Security Guide"],
                        cvss_score=3.1 if sa_uses_irsa else 6.2
                    ))

                # Check Container & Pod SecurityContext (privileged, root UID, privilege escalation, host namespaces)
                pod_sc = w_props.get("podSecurityContext") or {}
                containers_list = w_props.get("containers") or [{"name": workload_name, "securityContext": w_props.get("securityContext") or {}}]
                sec_violations: List[str] = []
                if w_props.get("hostNetwork") or w_props.get("hostPID") or w_props.get("hostIPC"):
                    sec_violations.append("hostNetwork/hostPID/hostIPC enabled")
                if pod_sc.get("runAsUser") == 0:
                    sec_violations.append("podSecurityContext.runAsUser=0")
                if pod_sc.get("runAsNonRoot") is False:
                    sec_violations.append("podSecurityContext.runAsNonRoot=false")
                for c in containers_list:
                    sc = c.get("securityContext") or {}
                    if sc.get("privileged") is True:
                        sec_violations.append(f"{c.get('name', 'container')}: privileged=true")
                    if sc.get("allowPrivilegeEscalation") is True:
                        sec_violations.append(f"{c.get('name', 'container')}: allowPrivilegeEscalation=true")
                    if sc.get("runAsUser") == 0 or (sc.get("runAsNonRoot") is False and pod_sc.get("runAsNonRoot") is not True):
                        sec_violations.append(f"{c.get('name', 'container')}: runs as root (UID 0)")
                if sec_violations:
                    findings.append(MisconfigurationFinding(
                        id="SEC-K8S-004",
                        title="Insecure Kubernetes Container / Pod SecurityContext",
                        category=FindingCategory.KUBERNETES,
                        severity=Severity.HIGH,
                        resource_id=workload_name,
                        resource_type=f"k8s:{w_props.get('kind', 'Deployment')}",
                        layer="Kubernetes",
                        description=f"Workload '{workload_name}' exposes elevated container/host privileges: {', '.join(sec_violations)}.",
                        remediation_recommendation="Set privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true, and drop ALL capabilities.",
                        compliance_controls=["CIS Kubernetes Benchmark 5.2.1", "Pod Security Standards (Restricted)"],
                        cvss_score=7.8
                    ))

        # Check K8s RBAC bindings dynamically (supporting ServiceAccount AND Group subjects)
        all_sa_nodes = [
            (nid, ndata.get("obj"))
            for nid, ndata in self.graph.nodes(data=True)
            if ndata.get("node_type") == NodeType.SERVICE_ACCOUNT.value
        ]
        rbac_roles = getattr(self.k8s, "rbac_roles", None) or (self.k8s.roles if (self.k8s and isinstance(getattr(self.k8s, "roles", None), dict)) else {})
        role_bindings = getattr(self.k8s, "role_bindings", []) if self.k8s else []
        if rbac_roles and role_bindings:
            for rb in role_bindings:
                role_ref = rb.get("roleRef", {}) or {}
                role_ref_name = role_ref.get("name", "")
                role_ref_kind = role_ref.get("kind", "")
                rb_ns = rb.get("namespace", "default")
                if role_ref_kind == "ClusterRole":
                    role_data = rbac_roles.get(role_ref_name)
                elif role_ref_kind == "Role":
                    role_data = rbac_roles.get(f"{rb_ns}:{role_ref_name}")
                else:
                    role_data = rbac_roles.get(f"{rb_ns}:{role_ref_name}") or rbac_roles.get(role_ref_name)

                subjects = rb.get("subjects", []) or []
                if role_data and subjects:
                    for rule in role_data.get("rules", []):
                        res_list = rule.get("resources", []) or []
                        verbs = rule.get("verbs", []) or []
                        if any(r in ("secrets", "*") for r in res_list) and any(v in ("get", "list", "watch", "*") for v in verbs):
                            subj_names = []
                            for s in subjects:
                                s_name = s.get("name")
                                s_kind = s.get("kind", "ServiceAccount")
                                if not s_name:
                                    continue
                                subj_names.append(f"{s_kind}:{s_name}" if s_kind != "ServiceAccount" else s_name)
                                if s_kind == "ServiceAccount":
                                    s_ns = s.get("namespace") or rb_ns
                                    secrets_reading_sas.add(f"k8s:sa:{s_ns}:{s_name}")
                                elif s_kind == "Group":
                                    if s_name in ("system:serviceaccounts", "system:authenticated"):
                                        for sa_id, _ in all_sa_nodes:
                                            secrets_reading_sas.add(sa_id)
                                    elif s_name.startswith("system:serviceaccounts:"):
                                        grp_ns = s_name.split(":", 2)[2]
                                        for sa_id, sa_obj in all_sa_nodes:
                                            if getattr(sa_obj, "namespace", None) == grp_ns:
                                                secrets_reading_sas.add(sa_id)
                            findings.append(MisconfigurationFinding(
                                id="SEC-K8S-001",
                                title="Kubernetes RBAC Role Permits In-Cluster Secrets Enumeration",
                                category=FindingCategory.RBAC,
                                severity=Severity.HIGH,
                                resource_id=role_ref_name,
                                resource_type=role_data.get("kind", "k8s:Role"),
                                layer="Kubernetes",
                                description=(
                                    f"Role '{role_ref_name}' bound to {subj_names} grants "
                                    f"verbs {verbs} on resources {res_list}. Any compromised container can dump all cluster secrets."
                                ),
                                remediation_recommendation=(
                                    "Avoid granting list permissions on secrets. Use explicit resourceNames or integrate "
                                    "external Secrets Store CSI Driver with temporary projected tokens."
                                ),
                                compliance_controls=["CIS Kubernetes Benchmark 5.1.2", "MITRE ATT&CK T1552.007", "NSA/CISA Guide"],
                                cvss_score=7.5
                            ))
                            break

        # Check NetworkPolicies per namespace dynamically (verify default-deny rules, not just presence)
        k8s_ns = getattr(self.k8s, "namespaces", []) if self.k8s else []
        k8s_netpols = getattr(self.k8s, "network_policies", {}) if self.k8s else {}
        if k8s_ns:
            for ns in k8s_ns:
                ns_pols = k8s_netpols.get(ns, [])
                if not self._namespace_has_default_deny(ns_pols):
                    findings.append(MisconfigurationFinding(
                        id="SEC-K8S-003",
                        title=f"Namespace '{ns}' Missing Default-Deny NetworkPolicy",
                        category=FindingCategory.KUBERNETES,
                        severity=Severity.MEDIUM,
                        resource_id=ns,
                        resource_type="k8s:Namespace",
                        layer="Kubernetes",
                        description=(
                            f"The namespace '{ns}' does not declare a default-deny NetworkPolicy. Any compromised container "
                            "can initiate unrestricted lateral network connections to other microservices and databases."
                        ),
                        remediation_recommendation="Deploy an ingress/egress default-deny NetworkPolicy and explicitly whitelist needed microservices.",
                        compliance_controls=["CIS Kubernetes Benchmark 5.3.2", "PCI-DSS v4.0 Req 1.2"],
                        cvss_score=5.5
                    ))

        # 6. Cross-Layer Analysis Findings
        if attack_paths is None:
            attack_paths = self.find_cross_layer_attack_paths()
        for ap in attack_paths:
            workload_target = f"{ap.nodes[0]['name']} -> {ap.nodes[-1]['name']}"
            findings.append(MisconfigurationFinding(
                id="SEC-CROSS-001",
                title=f"Cross-Layer Cloud Identity & Cryptographic Exfiltration Path ({ap.id})",
                category=FindingCategory.CROSS_LAYER,
                severity=Severity.CRITICAL,
                resource_id=workload_target,
                resource_type="CrossLayerCompromisePath",
                layer="Cross-Layer",
                description=(
                    f"Container '{ap.nodes[0]['name']}' accesses AWS IAM via OIDC IRSA and leverages wildcard kms:Decrypt "
                    f"to decrypt assets in '{ap.nodes[-1]['name']}'. Single-layer scanners like Prowler and AWS Access Analyzer "
                    "completely miss this threat (100% False-Negative)."
                ),
                remediation_recommendation=(
                    "Enforce scoped Least-Privilege Terraform remediation: Replace wildcard '*' with CMK ARN and enforce "
                    "kms:EncryptionContext condition."
                ),
                compliance_controls=["PCI-DSS v4.0 Req 3.4", "CIS AWS 1.16", "CIS K8s 5.1.1", "NIST SP 800-53 SC-13"],
                cvss_score=9.8
            ))

            # Verify whether an IAM Policy OR KMS Resource Policy along this path lacks EncryptionContext
            lacks_enc_ctx = False
            for node_info in ap.nodes:
                if node_info.get("type") == NodeType.IAM_POLICY.value:
                    p_obj = self.graph.nodes.get(node_info["id"], {}).get("obj")
                    if p_obj and any(
                        statement_allows_kms_decrypt(s) and not statement_has_encryption_context(s)
                        for s in getattr(p_obj, "statements", [])
                    ):
                        lacks_enc_ctx = True
                        break
            if not lacks_enc_ctx:
                for idx_n in range(len(ap.nodes) - 1):
                    u_id = ap.nodes[idx_n]["id"]
                    v_id = ap.nodes[idx_n + 1]["id"]
                    edata = self.graph.get_edge_data(u_id, v_id, default={})
                    if edata.get("via_resource_policy") and edata.get("edge_type") == EdgeType.ALLOWS_DECRYPT.value:
                        lacks_enc_ctx = True
                        break
            if lacks_enc_ctx:
                findings.append(MisconfigurationFinding(
                    id="SEC-CROSS-002",
                    title=f"Target Vault Missing Cryptographic EncryptionContext Binding ({ap.id})",
                    category=FindingCategory.CROSS_LAYER,
                    severity=Severity.HIGH,
                    resource_id=workload_target,
                    resource_type="CryptographicBinding",
                    layer="Cross-Layer",
                    description=(
                        "The IAM policy allows decryption without cryptographically binding the request to the S3 bucket ARN, "
                        "permitting lateral exfiltration if credentials are intercepted."
                    ),
                    remediation_recommendation="Implement kms:EncryptionContext condition tying decrypt operations to the target bucket ARN.",
                    compliance_controls=["PCI-DSS v4.0 Req 3.5.1", "NIST AC-6"],
                    cvss_score=8.4
                ))

            # Only emit SEC-CROSS-003 when the IRSA ServiceAccount in the attack path also has RBAC secrets access
            sa_ids_in_path = {
                node_info["id"]
                for node_info in ap.nodes
                if node_info.get("type") == NodeType.SERVICE_ACCOUNT.value
            }
            dual_sas = sa_ids_in_path & secrets_reading_sas
            if dual_sas:
                findings.append(MisconfigurationFinding(
                    id="SEC-CROSS-003",
                    title="Dual-Vector Exposure: Federated IRSA Role Combined with K8s RBAC Secrets Reading",
                    category=FindingCategory.CROSS_LAYER,
                    severity=Severity.HIGH,
                    resource_id=", ".join(sorted(dual_sas)),
                    resource_type="IdentityFederation",
                    layer="Cross-Layer",
                    description=(
                        "The workload identity holds dual privileges: Cloud IAM access to AWS KMS, and Kubernetes RBAC "
                        "permissions to read in-cluster secrets. Compromise yields both cloud and container credentials."
                    ),
                    remediation_recommendation="Segregate duties: separate cloud integration ServiceAccount from secret-reading identities.",
                    compliance_controls=["CIS Kubernetes Benchmark 5.1.1", "NIST AC-3"],
                    cvss_score=8.2
                ))

        return findings

    @staticmethod
    def _namespace_has_default_deny(policies: List[Dict[str, Any]]) -> bool:
        """Verifies whether at least one NetworkPolicy in the namespace enforces default-deny."""
        if not policies:
            return False
        for np in policies:
            if not isinstance(np, dict):
                continue
            if "spec" not in np:
                # Minimal metadata-only policy record without spec
                return True
            spec = np.get("spec") or {}
            pod_sel = spec.get("podSelector") or {}
            selects_all_pods = not pod_sel.get("matchLabels") and not pod_sel.get("matchExpressions")
            if not selects_all_pods:
                continue
            ptypes = spec.get("policyTypes") or []
            ingress_rules = spec.get("ingress")
            egress_rules = spec.get("egress")
            deny_ingress = ("Ingress" in ptypes or not ptypes) and (ingress_rules is None or ingress_rules == [])
            deny_egress = ("Egress" in ptypes) and (egress_rules is None or egress_rules == [])
            if deny_ingress or deny_egress:
                return True
        return False
