"""
AI-CSPM Core Data Models
Defines semantic graph nodes, edge types, attack path models, and remediation schemas.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class _ValueStrEnum(str, Enum):
    """Preserves Enum value formatting under str() in Python 3.11+ / 3.14."""

    def __str__(self) -> str:
        return str(self.value)


class NodeType(_ValueStrEnum):
    WORKLOAD = "WORKLOAD"                     # Kubernetes Pod / Deployment
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"       # K8s ServiceAccount
    IAM_ROLE = "IAM_ROLE"                     # Cloud IAM Role (AWS/Azure/GCP)
    IAM_POLICY = "IAM_POLICY"                 # Cloud IAM Policy (HCL or JSON)
    KMS_KEY = "KMS_KEY"                       # Cloud KMS Customer Managed Key
    S3_BUCKET = "S3_BUCKET"                   # Cloud Storage Vault / Database
    UNKNOWN = "UNKNOWN"


class EdgeType(_ValueStrEnum):
    USES_SERVICE_ACCOUNT = "USES_SERVICE_ACCOUNT"
    IRSA_ASSUMES = "IRSA_ASSUMES"             # K8s SA assumes Cloud IAM Role via OIDC
    HAS_POLICY = "HAS_POLICY"                 # IAM Role attaches IAM Policy
    ALLOWS_DECRYPT = "ALLOWS_DECRYPT"         # IAM Policy / Resource Policy grants Decrypt on KMS Key
    ENCRYPTS_BUCKET = "ENCRYPTS_BUCKET"       # KMS Key encrypts S3 Bucket
    RESOURCE_POLICY_ALLOWS = "RESOURCE_POLICY_ALLOWS"  # Direct Resource Policy access (KMS/S3)


class Severity(_ValueStrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(_ValueStrEnum):
    CROSS_LAYER = "Cross-Layer Attack Vector"
    CLOUD_IAM = "Cloud IAM & Permissions"
    CRYPTOGRAPHY = "Cryptography & Key Management"
    STORAGE = "Cloud Storage & S3"
    KUBERNETES = "Kubernetes & Workload Security"
    RBAC = "Kubernetes RBAC & Secrets"


class MisconfigurationFinding(BaseModel):
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    resource_id: str
    resource_type: str
    layer: str
    description: str
    remediation_recommendation: str
    compliance_controls: List[str] = Field(default_factory=list)
    cvss_score: float = 5.0


class PolicyStatement(BaseModel):
    sid: Optional[str] = None
    effect: str = "Allow"
    principal: Optional[Any] = None
    actions: List[str] = Field(default_factory=list)
    not_actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    not_resources: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)


_RESTRICTIVE_CONDITION_OPS = {
    "stringequals",
    "stringequalsifexists",
    "stringequalsignorecase",
    "stringequalsignorecaseifexists",
    "stringlike",
    "stringlikeifexists",
    "arnequals",
    "arnequalsifexists",
    "arnlike",
    "arnlikeifexists",
}


def action_matches_kms_decrypt(action: str) -> bool:
    """Returns True if an IAM action string grants kms:Decrypt (directly or via wildcard)."""
    a = str(action).strip().lower()
    if a in ("*", "kms:*", "kms:decrypt", "kms:decrypt*"):
        return True
    if a.startswith("kms:") and a.endswith("*"):
        prefix = a[:-1]
        return "kms:decrypt".startswith(prefix)
    return False


def resource_matches_kms_wildcard(resource: str) -> bool:
    """Returns True if an IAM resource string represents a wildcard across KMS keys."""
    r = str(resource).strip()
    if r == "*":
        return True
    if r.startswith("arn:") and ":kms:" in r:
        return r.endswith(":*") or r.endswith(":key/*") or r.endswith("/*")
    return False


def statement_has_encryption_context(stmt: PolicyStatement) -> bool:
    """Returns True if a PolicyStatement restricts usage via a positive kms:EncryptionContext condition."""
    if not stmt.conditions or not isinstance(stmt.conditions, dict):
        return False
    for cond_op, cond_dict in stmt.conditions.items():
        op_norm = str(cond_op).split(":")[-1].strip().lower()
        if op_norm not in _RESTRICTIVE_CONDITION_OPS:
            continue
        if isinstance(cond_dict, dict):
            for k, v in cond_dict.items():
                if "encryptioncontext" in str(k).lower() and v not in (None, "", []):
                    return True
    return False


_IDENTITY_SOURCE_CONDITION_KEYS = (
    "principalarn",
    "principalaccount",
    "calleraccount",
    "principalorgid",
    "principalorgpaths",
    "sourcearn",
    "sourceaccount",
    "sourcevpc",
    "sourcevpce",
    "sourceip",
)


def statement_has_principal_or_source_restriction(conditions: Any) -> bool:
    """
    Returns True if `conditions` positively constrains caller identity or network/account source
    (e.g. aws:PrincipalOrgID, aws:PrincipalArn, aws:PrincipalAccount, aws:SourceVpce).
    Generic conditions like aws:SecureTransport=true or negated exclusions return False.
    """
    if not conditions or not isinstance(conditions, dict):
        return False
    for cond_op, cond_dict in conditions.items():
        op_norm = str(cond_op).split(":")[-1].strip().lower()
        if op_norm not in _RESTRICTIVE_CONDITION_OPS and not op_norm.startswith("ipaddress"):
            continue
        if isinstance(cond_dict, dict):
            for k, v in cond_dict.items():
                k_l = str(k).lower()
                if any(req in k_l for req in _IDENTITY_SOURCE_CONDITION_KEYS) and v not in (None, "", []):
                    return True
    return False


def _statement_targets_kms_decrypt(stmt: PolicyStatement) -> bool:
    if stmt.actions:
        return any(action_matches_kms_decrypt(a) for a in stmt.actions)
    if stmt.not_actions:
        return not any(action_matches_kms_decrypt(a) for a in stmt.not_actions)
    return False


def statement_allows_kms_decrypt(stmt: PolicyStatement) -> bool:
    """Returns True if an Allow statement grants kms:Decrypt capabilities (supporting Action & NotAction)."""
    return stmt.effect.strip().lower() == "allow" and _statement_targets_kms_decrypt(stmt)


def statement_denies_kms_decrypt(stmt: PolicyStatement) -> bool:
    """Returns True if an unconditional Deny statement blocks kms:Decrypt capabilities."""
    return (
        stmt.effect.strip().lower() == "deny"
        and not stmt.conditions
        and _statement_targets_kms_decrypt(stmt)
    )


def statement_has_wildcard_kms_resource(stmt: PolicyStatement) -> bool:
    """Returns True if any resource in the statement is a KMS wildcard (or NotResource leaves wildcard access)."""
    if stmt.resources:
        return any(resource_matches_kms_wildcard(r) for r in stmt.resources)
    if stmt.not_resources:
        return not any(resource_matches_kms_wildcard(r) for r in stmt.not_resources)
    return False


def statement_targets_kms_key(stmt: PolicyStatement, key_matcher_fn: Any) -> bool:
    """Returns True if a statement applies to the given KMS key (handling Resource & NotResource)."""
    if stmt.resources:
        return any(resource_matches_kms_wildcard(r) or key_matcher_fn(r) for r in stmt.resources)
    if stmt.not_resources:
        if any(resource_matches_kms_wildcard(r) for r in stmt.not_resources):
            return False
        return not any(key_matcher_fn(r) for r in stmt.not_resources)
    return False


class BaseNode(BaseModel):
    id: str
    name: str
    type: NodeType
    layer: str  # "Kubernetes", "IAM", "Cryptography", "Storage"
    source_file: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class WorkloadNode(BaseNode):
    type: NodeType = NodeType.WORKLOAD
    layer: str = "Kubernetes"
    namespace: str = "default"
    service_account: str
    container_name: Optional[str] = None
    image: Optional[str] = None


class ServiceAccountNode(BaseNode):
    type: NodeType = NodeType.SERVICE_ACCOUNT
    layer: str = "Kubernetes"
    namespace: str = "default"
    role_arn: Optional[str] = None  # extracted from IRSA annotation


class IAMRoleNode(BaseNode):
    type: NodeType = NodeType.IAM_ROLE
    layer: str = "IAM"
    role_arn: str
    trust_policy: Dict[str, Any] = Field(default_factory=dict)
    oidc_provider: Optional[str] = None


class IAMPolicyNode(BaseNode):
    type: NodeType = NodeType.IAM_POLICY
    layer: str = "IAM"
    policy_arn: Optional[str] = None
    statements: List[PolicyStatement] = Field(default_factory=list)
    has_wildcard_decrypt: bool = False


class KMSKeyNode(BaseNode):
    type: NodeType = NodeType.KMS_KEY
    layer: str = "Cryptography"
    key_arn: str
    alias: Optional[str] = None
    rotation_enabled: bool = False


class S3BucketNode(BaseNode):
    type: NodeType = NodeType.S3_BUCKET
    layer: str = "Storage"
    bucket_name: str
    bucket_arn: str
    kms_key_arn: Optional[str] = None


class AttackPath(BaseModel):
    id: str
    title: str
    severity: Severity = Severity.CRITICAL
    nodes: List[Dict[str, Any]]
    steps: List[str]
    root_cause: str
    impact: str
    false_negative_tools: List[str] = Field(
        default_factory=lambda: ["Prowler v5.46", "ScoutSuite", "AWS Access Analyzer", "Checkov", "Trivy"]
    )


class RemediationResult(BaseModel):
    attack_path_id: str
    original_code: str
    remediated_code: str
    explanation: str
    least_privilege_changes: List[str]
    risk_reduction: str
