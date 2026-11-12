"""
AI-CSPM Live Cloud & Kubernetes Runtime Ingestion Module
Connects directly to live AWS accounts via Boto3 and live Kubernetes clusters via official client/kubectl,
extracting active workloads, IRSA bindings, IAM execution roles, KMS CMK keys, and S3 vaults.
"""

import os
import sys
import json
import subprocess
from typing import Dict, List, Optional, Any, Tuple
import yaml

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError, EndpointConnectionError

try:
    from kubernetes import client as k8s_client, config as k8s_config
    from kubernetes.client.rest import ApiException
    HAS_K8S_CLIENT = True
except ImportError:
    HAS_K8S_CLIENT = False

try:
    from core.models import (
        NodeType,
        WorkloadNode,
        ServiceAccountNode,
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )
except (ImportError, ValueError):
    from ..core.models import (
        NodeType,
        WorkloadNode,
        ServiceAccountNode,
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        parse_policy_statements,
        statement_allows_kms_decrypt,
        statement_has_wildcard_kms_resource,
    )

console = Console(highlight=False, emoji=False)


def _is_non_console_pty() -> bool:
    """Detects MSYS/Git Bash Mintty or piped stdin where msvcrt.getwch() blocks on Windows."""
    if os.environ.get("MSYSTEM"):
        return True
    try:
        return not sys.stdin.isatty()
    except Exception:
        return True


class LiveCloudFetcher:
    """
    Ingests live runtime cloud infrastructure from AWS (via Boto3) and Kubernetes (via Kubeconfig/API).
    Provides interactive profile selection, multi-region targeting, and fallback simulation mode.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.workloads: List[WorkloadNode] = []
        self.service_accounts: List[ServiceAccountNode] = []
        self.roles: List[IAMRoleNode] = []
        self.policies: List[IAMPolicyNode] = []
        self.kms_keys: List[KMSKeyNode] = []
        self.s3_buckets: List[S3BucketNode] = []
        self.attachments: List[Dict[str, str]] = []

        # Kubernetes RBAC & NetworkPolicy structures for core/analyzer
        self.rbac_roles: Dict[str, Any] = {}
        self.role_bindings: List[Dict[str, Any]] = []
        self.network_policies: Dict[str, List[Any]] = {}
        self.namespaces: List[str] = []
        self.warnings: List[str] = []

    def _safe_prompt(
        self,
        label: str,
        default: Optional[str] = None,
        choices: Optional[List[str]] = None,
        password: bool = False,
    ) -> str:
        """Flushes stdout and avoids hanging msvcrt.getwch()/Rich prompts inside Git Bash PTY."""
        sys.stdout.flush()
        sys.stderr.flush()
        if not _is_non_console_pty():
            kwargs: Dict[str, Any] = {}
            if default is not None:
                kwargs["default"] = default
            if choices is not None:
                kwargs["choices"] = choices
            if password:
                kwargs["password"] = True
            return Prompt.ask(label, **kwargs)

        suffix_parts = []
        if choices:
            suffix_parts.append(f"[{'/'.join(choices)}]")
        if default is not None:
            suffix_parts.append(f"({default})")
        if password:
            suffix_parts.append("[line input in Git Bash]")
        suffix = f" {' '.join(suffix_parts)}" if suffix_parts else ""

        while True:
            sys.stdout.write(f"{label}{suffix}: ")
            sys.stdout.flush()
            raw = sys.stdin.readline()
            if raw == "":
                return default if default is not None else ""
            val = raw.rstrip("\r\n").strip()
            if not val and default is not None:
                val = default
            if choices and val not in choices:
                sys.stdout.write(f"Please enter one of {choices}.\n")
                sys.stdout.flush()
                continue
            return val

    def _log(self, message: str):
        if not self.quiet:
            console.print(message)

    def _warn(self, message: str):
        self.warnings.append(message)
        self._log(f"  [yellow]⚠ {message}[/]")

    # =========================================================================
    # AWS Profile & Region Discovery
    # =========================================================================

    @staticmethod
    def get_available_aws_profiles() -> List[str]:
        """Discovers all AWS profiles from ~/.aws/credentials, ~/.aws/config, and boto3."""
        profiles = set()
        try:
            sess = boto3.Session()
            for p in sess.available_profiles:
                profiles.add(p)
        except Exception:
            pass

        # Also inspect ~/.aws/credentials manually if present
        creds_path = os.path.expanduser("~/.aws/credentials")
        if os.path.exists(creds_path):
            try:
                with open(creds_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("[") and line.endswith("]"):
                            profiles.add(line[1:-1].strip())
            except Exception:
                pass

        config_path = os.path.expanduser("~/.aws/config")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("[profile ") and line.endswith("]"):
                            profiles.add(line[9:-1].strip())
                        elif line.startswith("[") and line.endswith("]"):
                            p = line[1:-1].strip()
                            if p != "default":
                                profiles.add(p)
            except Exception:
                pass

        return sorted(list(profiles))

    def prompt_aws_configuration(
        self,
        cli_profile: Optional[str] = None,
        cli_region: Optional[str] = None
    ) -> Tuple[Optional[boto3.Session], str, bool]:
        """
        Interactive wizard to select or configure AWS session and target region.
        Returns: (Session or None, region_str, is_demo_mode)
        """
        if cli_profile:
            region = cli_region or "us-east-1"
            try:
                session = boto3.Session(profile_name=cli_profile, region_name=region)
                return session, region, False
            except Exception as e:
                self._warn(f"Error initializing AWS profile '{cli_profile}': {e}")

        profiles = self.get_available_aws_profiles()
        if self.quiet:
            region = cli_region or "us-east-1"
            if profiles:
                selected = "default" if "default" in profiles else profiles[0]
                try:
                    return boto3.Session(profile_name=selected, region_name=region), region, False
                except Exception as e:
                    self._warn(f"Non-interactive AWS session fallback to simulated mode: {e}")
            return None, region, True

        console.print("\n[bold cyan]═══ [1/2] Live AWS Infrastructure Authentication ═══[/]")

        if profiles:
            table = Table(title="Available AWS Local Credential Profiles", border_style="cyan")
            table.add_column("#", style="bold green", width=4)
            table.add_column("Profile Name", style="bold white")
            table.add_column("Source", style="dim")

            for i, p in enumerate(profiles, start=1):
                table.add_row(str(i), p, "~/.aws/credentials")
            console.print(table)

            console.print("[dim]Select an existing profile number, type a custom name, or choose [M] for Simulated Live Demo.[/dim]")
            choice = self._safe_prompt("Select AWS Profile", default="1")
            
            if choice.upper() == "M":
                return None, cli_region or "us-east-1", True

            selected_profile = None
            if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                selected_profile = profiles[int(choice) - 1]
            elif choice in profiles:
                selected_profile = choice
            else:
                selected_profile = choice

            default_region = cli_region or "us-east-1"
            target_region = self._safe_prompt("Target AWS Region", default=default_region)

            try:
                session = boto3.Session(profile_name=selected_profile, region_name=target_region)
                return session, target_region, False
            except Exception as e:
                console.print(f"[bold red]Failed to create session with profile '{selected_profile}':[/] {e}")
                console.print("[yellow]Falling back to Simulated Enterprise Live Cloud mode...[/]")
                return None, target_region, True
        else:
            # No profiles configured on machine
            console.print("[yellow]Notice: No AWS credential profiles found in ~/.aws/credentials or ~/.aws/config.[/yellow]")
            console.print("Options:")
            console.print("  [bold green][1][/] Enter AWS Access Key & Secret manually")
            console.print("  [bold green][2][/] Use Simulated Live Enterprise Cloud (Offline / Graduation Demo Mode)")
            
            choice = self._safe_prompt("Choose authentication method", choices=["1", "2"], default="1")
            if choice == "1":
                ak = self._safe_prompt("AWS Access Key ID")
                sk = self._safe_prompt("AWS Secret Access Key", password=True)
                region = self._safe_prompt("AWS Region", default="us-east-1")
                session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, region_name=region)
                return session, region, False
            else:
                target_region = cli_region or "us-east-1"
                return None, target_region, True

    # =========================================================================
    # Kubernetes Context & Namespace Discovery
    # =========================================================================

    @staticmethod
    def get_available_k8s_contexts() -> Tuple[List[str], Optional[str]]:
        """Reads ~/.kube/config to list available Kubernetes contexts and current context."""
        contexts = []
        current = None

        kubeconfig_path = os.path.expanduser("~/.kube/config")
        if os.path.exists(kubeconfig_path):
            try:
                with open(kubeconfig_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    current = data.get("current-context")
                    for ctx in data.get("contexts", []):
                        if isinstance(ctx, dict) and "name" in ctx:
                            contexts.append(ctx["name"])
            except Exception:
                pass

        return contexts, current

    def prompt_k8s_configuration(
        self,
        cli_context: Optional[str] = None,
        cli_namespace: Optional[str] = None,
        is_demo: bool = False
    ) -> Tuple[Optional[str], str]:
        """
        Interactive wizard to select K8s context and namespace.
        Returns: (context_name, namespace)
        """
        if is_demo:
            return "eks-prod-cluster-us-east-1", cli_namespace or "default"

        if cli_context:
            return cli_context, cli_namespace or "default"

        contexts, current = self.get_available_k8s_contexts()
        if self.quiet:
            return current, cli_namespace or "default"

        console.print("\n[bold cyan]═══ [2/2] Live Kubernetes Cluster Discovery ═══[/]")

        if contexts:
            table = Table(title="Available Kubernetes Cluster Contexts (~/.kube/config)", border_style="cyan")
            table.add_column("#", style="bold green", width=4)
            table.add_column("Context Name", style="bold white")
            table.add_column("Status", style="yellow")

            default_idx = "1"
            for i, ctx in enumerate(contexts, start=1):
                status = "★ Active (current-context)" if ctx == current else "Available"
                if ctx == current:
                    default_idx = str(i)
                table.add_row(str(i), ctx, status)
            console.print(table)

            choice = self._safe_prompt("Select Kubernetes Context", default=default_idx)
            selected_ctx = None
            if choice.isdigit() and 1 <= int(choice) <= len(contexts):
                selected_ctx = contexts[int(choice) - 1]
            else:
                selected_ctx = choice

            target_namespace = self._safe_prompt("Target Kubernetes Namespace (or 'all')", default=cli_namespace or "default")
            return selected_ctx, target_namespace
        else:
            console.print("[dim]No local ~/.kube/config cluster contexts detected. Using connected cluster context or demo environment.[/dim]")
            target_namespace = cli_namespace or "default"
            return None, target_namespace

    # =========================================================================
    # Live AWS Ingestion Engine
    # =========================================================================

    def fetch_aws_live_assets(self, session: boto3.Session, region: str):
        """Discovers IAM roles, attached policies, KMS CMKs, and S3 vaults in real-time."""
        self._log("\n[bold yellow]⚡ Ingesting Live AWS Cloud Assets...[/]")
        seen_managed_policies: set = set()

        # 1. IAM Roles & Policies
        try:
            iam = session.client("iam")
            self._log("  → Scanning AWS IAM Execution Roles & Trust Policies...")
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role_data in page.get("Roles", []):
                    role_name = role_data["RoleName"]
                    role_arn = role_data["Arn"]
                    assume_doc = role_data.get("AssumeRolePolicyDocument", {})
                    perm_boundary = (role_data.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")

                    # Check for OIDC provider in trust policy
                    oidc_provider = None
                    assume_stmts = assume_doc.get("Statement", [])
                    if isinstance(assume_stmts, dict):
                        assume_stmts = [assume_stmts]
                    for stmt in assume_stmts:
                        if not isinstance(stmt, dict):
                            continue
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, dict) and "Federated" in principal:
                            oidc_provider = str(principal["Federated"])

                    role_node = IAMRoleNode(
                        id=f"aws:iam:role:{role_name}",
                        name=role_name,
                        layer="IAM",
                        role_arn=role_arn,
                        trust_policy=assume_doc,
                        oidc_provider=oidc_provider,
                        source_file=f"aws://iam/role/{role_name}",
                        properties={
                            "res_id": role_name,
                            "role_arn": role_arn,
                            "permissions_boundary": perm_boundary,
                            "path": role_data.get("Path", "/"),
                            "create_date": str(role_data.get("CreateDate", ""))
                        }
                    )
                    self.roles.append(role_node)

                    # Ingest attached managed policies (paginated + deduplicated)
                    try:
                        att_paginator = iam.get_paginator("list_attached_role_policies")
                        for att_page in att_paginator.paginate(RoleName=role_name):
                            for att_pol in att_page.get("AttachedPolicies", []):
                                pol_name = att_pol["PolicyName"]
                                pol_arn = att_pol["PolicyArn"]
                                pol_node_id = f"aws:iam:policy:{pol_name}"
                                self.attachments.append({"role": role_name, "policy": pol_node_id})

                                if pol_arn in seen_managed_policies:
                                    continue
                                seen_managed_policies.add(pol_arn)

                                try:
                                    pol_meta = iam.get_policy(PolicyArn=pol_arn)
                                    default_version = pol_meta["Policy"]["DefaultVersionId"]
                                    pol_ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=default_version)
                                    doc = pol_ver["PolicyVersion"]["Document"]
                                    statements = self._parse_policy_statements(doc)

                                    pol_node = IAMPolicyNode(
                                        id=pol_node_id,
                                        name=pol_name,
                                        layer="IAM",
                                        policy_arn=pol_arn,
                                        statements=statements,
                                        has_wildcard_decrypt=any(
                                            statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                                            for s in statements
                                        ),
                                        source_file=f"aws://iam/policy/{pol_name}",
                                        properties={"res_id": pol_name, "policy_arn": pol_arn}
                                    )
                                    self.policies.append(pol_node)
                                except Exception as exc:
                                    self._warn(f"IAM get_policy({pol_arn}): {exc}")
                    except ClientError as ce:
                        self._warn(f"IAM list_attached_role_policies({role_name}): {ce}")

                    # Ingest inline policies (namespaced per role to prevent collisions)
                    try:
                        inline_paginator = iam.get_paginator("list_role_policies")
                        for inline_page in inline_paginator.paginate(RoleName=role_name):
                            for inline_name in inline_page.get("PolicyNames", []):
                                pol_node_id = f"aws:iam:policy:{role_name}:{inline_name}"
                                self.attachments.append({"role": role_name, "policy": pol_node_id})
                                try:
                                    inline_data = iam.get_role_policy(RoleName=role_name, PolicyName=inline_name)
                                    doc = inline_data.get("PolicyDocument", {})
                                    statements = self._parse_policy_statements(doc)

                                    pol_node = IAMPolicyNode(
                                        id=pol_node_id,
                                        name=inline_name,
                                        layer="IAM",
                                        policy_arn=f"{role_arn}:policy/{inline_name}",
                                        statements=statements,
                                        has_wildcard_decrypt=any(
                                            statement_allows_kms_decrypt(s) and statement_has_wildcard_kms_resource(s)
                                            for s in statements
                                        ),
                                        source_file=f"aws://iam/role/{role_name}/inline/{inline_name}",
                                        properties={"res_id": f"{role_name}:{inline_name}", "is_inline": True}
                                    )
                                    self.policies.append(pol_node)
                                except Exception as exc:
                                    self._warn(f"IAM get_role_policy({role_name}/{inline_name}): {exc}")
                    except ClientError as ce:
                        self._warn(f"IAM list_role_policies({role_name}): {ce}")

        except Exception as e:
            self._warn(f"IAM Role enumeration limited: {e}")

        # 2. AWS KMS Keys
        try:
            kms = session.client("kms", region_name=region)
            self._log("  → Scanning AWS KMS Customer Managed Keys (CMKs)...")
            kms_paginator = kms.get_paginator("list_keys")
            for k_page in kms_paginator.paginate():
                for k in k_page.get("Keys", []):
                    key_id = k["KeyId"]
                    key_arn = k["KeyArn"]
                    try:
                        desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        # Skip AWS Managed Keys (aws/s3, aws/ebs)
                        if desc.get("KeyManager") != "CUSTOMER":
                            continue

                        rotation = False
                        try:
                            rot_res = kms.get_key_rotation_status(KeyId=key_id)
                            rotation = rot_res.get("KeyRotationEnabled", False)
                        except Exception as exc:
                            self._warn(f"KMS get_key_rotation_status({key_id}): {exc}")

                        alias_name = key_id
                        try:
                            alias_res = kms.list_aliases(KeyId=key_id)
                            aliases = [a["AliasName"] for a in alias_res.get("Aliases", []) if "AliasName" in a]
                            if aliases:
                                alias_name = aliases[0]
                        except Exception as exc:
                            self._warn(f"KMS list_aliases({key_id}): {exc}")

                        key_statements: List[PolicyStatement] = []
                        policy_fetched = False
                        try:
                            kp_res = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                            kp_doc = json.loads(kp_res.get("Policy", "{}"))
                            key_statements = self._parse_policy_statements(kp_doc)
                            policy_fetched = True
                        except Exception as exc:
                            policy_fetched = False
                            self._warn(f"KMS get_key_policy({key_id}): {exc}")

                        kms_node = KMSKeyNode(
                            id=f"aws:kms:key:{key_id}",
                            name=alias_name,
                            layer="Cryptography",
                            key_arn=key_arn,
                            alias=alias_name,
                            rotation_enabled=rotation,
                            source_file=f"aws://kms/{region}/{key_id}",
                            properties={
                                "res_id": alias_name,
                                "key_id": key_id,
                                "description": desc.get("Description", ""),
                                "key_state": desc.get("KeyState", "Enabled"),
                                "enable_key_rotation": rotation,
                                "policy_fetched": policy_fetched,
                                "has_explicit_policy": bool(key_statements),
                                "policy_statements": [s.model_dump() for s in key_statements]
                            }
                        )
                        self.kms_keys.append(kms_node)
                    except Exception as exc:
                        self._warn(f"KMS describe_key({key_id}): {exc}")
        except Exception as e:
            self._warn(f"KMS Key enumeration limited: {e}")

        # 3. AWS S3 Storage Buckets
        try:
            s3 = session.client("s3")
            self._log("  → Scanning AWS S3 Storage Buckets & SSE-KMS Bindings...")
            buckets_res = s3.list_buckets()
            for b in buckets_res.get("Buckets", []):
                bucket_name = b["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                # Query SSE-KMS encryption
                kms_master_key_id = None
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    for rule in rules:
                        apply_server = rule.get("ApplyServerSideEncryptionByDefault", {})
                        if apply_server.get("SSEAlgorithm") == "aws:kms":
                            kms_master_key_id = apply_server.get("KMSMasterKeyId")
                except ClientError as ce:
                    if ce.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
                        self._warn(f"S3 get_bucket_encryption({bucket_name}): {ce.response.get('Error', {}).get('Code', ce)}")
                except Exception as exc:
                    self._warn(f"S3 get_bucket_encryption({bucket_name}): {exc}")

                # Query Bucket Policy
                bucket_policy_stmts: List[PolicyStatement] = []
                try:
                    bp_res = s3.get_bucket_policy(Bucket=bucket_name)
                    bp_doc = json.loads(bp_res.get("Policy", "{}"))
                    bucket_policy_stmts = self._parse_policy_statements(bp_doc)
                except ClientError as ce:
                    if ce.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                        self._warn(f"S3 get_bucket_policy({bucket_name}): {ce.response.get('Error', {}).get('Code', ce)}")
                except Exception as exc:
                    self._warn(f"S3 get_bucket_policy({bucket_name}): {exc}")

                # Query Public Access Block
                pab_enabled: Optional[bool] = None
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    conf = pab.get("PublicAccessBlockConfiguration", {})
                    pab_enabled = (
                        conf.get("BlockPublicAcls", False)
                        and conf.get("BlockPublicPolicy", False)
                        and conf.get("IgnorePublicAcls", False)
                        and conf.get("RestrictPublicBuckets", False)
                    )
                except ClientError as ce:
                    code = ce.response.get("Error", {}).get("Code")
                    if code == "NoSuchPublicAccessBlockConfiguration":
                        pab_enabled = False
                    else:
                        self._warn(f"S3 get_public_access_block({bucket_name}): {code}")
                except Exception as exc:
                    self._warn(f"S3 get_public_access_block({bucket_name}): {exc}")

                # Query Server Access Logging
                has_logging: Optional[bool] = None
                try:
                    log_res = s3.get_bucket_logging(Bucket=bucket_name)
                    has_logging = bool(log_res.get("LoggingEnabled"))
                except ClientError as ce:
                    self._warn(f"S3 get_bucket_logging({bucket_name}): {ce.response.get('Error', {}).get('Code', ce)}")
                except Exception as exc:
                    self._warn(f"S3 get_bucket_logging({bucket_name}): {exc}")

                # Query Lifecycle Configuration
                has_lifecycle: Optional[bool] = None
                try:
                    lc_res = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    has_lifecycle = bool(lc_res.get("Rules"))
                except ClientError as ce:
                    code = ce.response.get("Error", {}).get("Code")
                    if code == "NoSuchLifecycleConfiguration":
                        has_lifecycle = False
                    else:
                        self._warn(f"S3 get_bucket_lifecycle_configuration({bucket_name}): {code}")
                except Exception as exc:
                    self._warn(f"S3 get_bucket_lifecycle_configuration({bucket_name}): {exc}")

                s3_node = S3BucketNode(
                    id=f"aws:s3:bucket:{bucket_name}",
                    name=bucket_name,
                    layer="Storage",
                    bucket_name=bucket_name,
                    bucket_arn=bucket_arn,
                    kms_key_arn=kms_master_key_id,
                    source_file=f"aws://s3/{bucket_name}",
                    properties={
                        "res_id": bucket_name,
                        "bucket_arn": bucket_arn,
                        "has_public_access_block": pab_enabled,
                        "has_logging": has_logging,
                        "has_lifecycle": has_lifecycle,
                        "kms_master_key_id": kms_master_key_id,
                        "bucket_policy_statements": [s.model_dump() for s in bucket_policy_stmts],
                    }
                )
                self.s3_buckets.append(s3_node)
        except Exception as e:
            self._warn(f"S3 Bucket enumeration limited: {e}")

    def _parse_policy_statements(self, doc: Dict[str, Any]) -> List[PolicyStatement]:
        """Converts raw IAM policy JSON statements into PolicyStatement model."""
        return parse_policy_statements(doc)

    # =========================================================================
    # Live Kubernetes Ingestion Engine
    # =========================================================================

    @staticmethod
    def _serialize_k8s_sc(sc_obj: Any) -> Dict[str, Any]:
        if sc_obj is None:
            return {}
        if isinstance(sc_obj, dict):
            return sc_obj
        out: Dict[str, Any] = {}
        for attr, key in (
            ("privileged", "privileged"),
            ("allow_privilege_escalation", "allowPrivilegeEscalation"),
            ("run_as_user", "runAsUser"),
            ("run_as_non_root", "runAsNonRoot"),
            ("read_only_root_filesystem", "readOnlyRootFilesystem"),
        ):
            val = getattr(sc_obj, attr, None)
            if val is not None:
                out[key] = val
        return out

    def _append_k8s_client_workload(
        self,
        kind: str,
        name: str,
        ns: str,
        spec: Any,
        replicas: int = 1,
        context_name: Optional[str] = None
    ):
        if spec is None:
            return
        sa_name = spec.service_account_name or spec.service_account or "default"
        containers = list(spec.containers or [])
        init_containers = list(spec.init_containers or [])
        c_name = containers[0].name if containers else name
        image = containers[0].image if containers else "unknown"

        volumes_list = []
        for v in (spec.volumes or []):
            v_dict: Dict[str, Any] = {"name": getattr(v, "name", "")}
            proj = getattr(v, "projected", None)
            if proj is not None:
                sources = []
                for src in (getattr(proj, "sources", None) or []):
                    if getattr(src, "service_account_token", None) is not None:
                        sources.append({"serviceAccountToken": True})
                v_dict["projected"] = {"sources": sources}
            volumes_list.append(v_dict)

        self.workloads.append(WorkloadNode(
            id=f"k8s:workload:{ns}:{name}",
            name=name,
            layer="Kubernetes",
            namespace=ns,
            service_account=sa_name,
            container_name=c_name,
            image=image,
            source_file=f"k8s://{context_name or 'cluster'}/{ns}/{kind.lower()}/{name}",
            properties={
                "res_id": name,
                "kind": kind,
                "replicas": replicas,
                "containers": [
                    {"name": c.name, "image": c.image, "securityContext": self._serialize_k8s_sc(c.security_context)}
                    for c in (containers + init_containers)
                ],
                "securityContext": self._serialize_k8s_sc(containers[0].security_context) if containers else {},
                "podSecurityContext": self._serialize_k8s_sc(spec.security_context),
                "hostNetwork": bool(getattr(spec, "host_network", False)),
                "hostPID": bool(getattr(spec, "host_pid", False)),
                "hostIPC": bool(getattr(spec, "host_ipc", False)),
                "volumes": volumes_list,
                "automountServiceAccountToken": spec.automount_service_account_token,
            }
        ))

    @staticmethod
    def _has_k8s_configuration(context_name: Optional[str]) -> bool:
        """Returns True if an explicit context, kubeconfig file, or in-cluster token is present."""
        if context_name:
            return True
        kubeconfig_env = os.environ.get("KUBECONFIG", "")
        if kubeconfig_env and any(os.path.exists(p) for p in kubeconfig_env.split(os.pathsep) if p):
            return True
        if os.path.exists(os.path.expanduser("~/.kube/config")):
            return True
        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
            return True
        return False

    def fetch_k8s_live_assets(self, context_name: Optional[str] = None, namespace: str = "default"):
        """Discovers running Workloads, ServiceAccounts, RBAC Roles, and NetworkPolicies from the target cluster."""
        self._log(f"\n[bold yellow]⚡ Ingesting Live Kubernetes Assets (Context: {context_name or 'default'}, Namespace: {namespace})...[/]")

        if not self._has_k8s_configuration(context_name):
            self._warn("No Kubernetes configuration (~/.kube/config) or in-cluster token found; skipping live K8s scan.")
            return

        # Strategy A: Use official kubernetes client
        if HAS_K8S_CLIENT:
            try:
                if context_name:
                    k8s_config.load_kube_config(context=context_name)
                else:
                    try:
                        k8s_config.load_incluster_config()
                    except Exception:
                        k8s_config.load_kube_config()

                apps_v1 = k8s_client.AppsV1Api()
                core_v1 = k8s_client.CoreV1Api()
                rbac_v1 = k8s_client.RbacAuthorizationV1Api()
                net_v1 = k8s_client.NetworkingV1Api()
                batch_v1 = k8s_client.BatchV1Api()

                # 1. Namespaces (fast probe with short timeout; abort Strategy A immediately if unreachable)
                try:
                    ns_list = core_v1.list_namespace(_request_timeout=4)
                    self.namespaces = [n.metadata.name for n in ns_list.items]
                except Exception as exc:
                    is_rbac_err = (
                        getattr(exc, "status", None) in (401, 403)
                        or "forbidden" in str(exc).lower()
                    )
                    if not is_rbac_err:
                        raise RuntimeError(f"K8s API server unreachable: {exc}") from exc
                    self._warn(f"K8s Namespace listing limited by RBAC: {exc}")
                    if namespace != "all":
                        self.namespaces = [namespace]

                # 2. Workloads (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, standalone Pods)
                self._log("  → Scanning Kubernetes Workloads (Deployments, StatefulSets, DaemonSets, Jobs, Pods)...")
                all_ns = namespace == "all"
                for kind, fn_all, fn_ns in (
                    ("Deployment", apps_v1.list_deployment_for_all_namespaces, lambda: apps_v1.list_namespaced_deployment(namespace=namespace)),
                    ("StatefulSet", apps_v1.list_stateful_set_for_all_namespaces, lambda: apps_v1.list_namespaced_stateful_set(namespace=namespace)),
                    ("DaemonSet", apps_v1.list_daemon_set_for_all_namespaces, lambda: apps_v1.list_namespaced_daemon_set(namespace=namespace)),
                    ("Job", batch_v1.list_job_for_all_namespaces, lambda: batch_v1.list_namespaced_job(namespace=namespace)),
                    ("CronJob", batch_v1.list_cron_job_for_all_namespaces, lambda: batch_v1.list_namespaced_cron_job(namespace=namespace)),
                ):
                    try:
                        res = fn_all() if all_ns else fn_ns()
                        for item in res.items:
                            if kind == "CronJob":
                                tpl_spec = item.spec.job_template.spec.template.spec
                                reps = 1
                            else:
                                tpl_spec = item.spec.template.spec
                                reps = getattr(item.spec, "replicas", 1) or 1
                            self._append_k8s_client_workload(
                                kind=kind,
                                name=item.metadata.name,
                                ns=item.metadata.namespace,
                                spec=tpl_spec,
                                replicas=reps,
                                context_name=context_name,
                            )
                    except Exception as exc:
                        self._warn(f"K8s {kind} listing limited: {exc}")

                try:
                    pods = core_v1.list_pod_for_all_namespaces() if all_ns else core_v1.list_namespaced_pod(namespace=namespace)
                    for pod in pods.items:
                        if pod.metadata.owner_references:
                            continue
                        self._append_k8s_client_workload(
                            kind="Pod",
                            name=pod.metadata.name,
                            ns=pod.metadata.namespace,
                            spec=pod.spec,
                            replicas=1,
                            context_name=context_name,
                        )
                except Exception as exc:
                    self._warn(f"K8s Pod listing limited: {exc}")

                # 3. ServiceAccounts
                self._log("  → Scanning ServiceAccounts & IRSA IAM Role Annotations...")
                try:
                    if all_ns:
                        sas = core_v1.list_service_account_for_all_namespaces()
                    else:
                        sas = core_v1.list_namespaced_service_account(namespace=namespace)

                    for sa in sas.items:
                        sa_name = sa.metadata.name
                        sa_ns = sa.metadata.namespace
                        annotations = sa.metadata.annotations or {}
                        role_arn = annotations.get("eks.amazonaws.com/role-arn")

                        sa_node = ServiceAccountNode(
                            id=f"k8s:sa:{sa_ns}:{sa_name}",
                            name=sa_name,
                            layer="Kubernetes",
                            namespace=sa_ns,
                            role_arn=role_arn,
                            source_file=f"k8s://{context_name or 'cluster'}/{sa_ns}/sa/{sa_name}",
                            properties={
                                "res_id": sa_name,
                                "annotations": annotations,
                                "role_arn": role_arn,
                                "automountServiceAccountToken": sa.automount_service_account_token,
                            }
                        )
                        self.service_accounts.append(sa_node)
                except Exception as exc:
                    self._warn(f"K8s ServiceAccount listing limited: {exc}")

                # 4. RBAC Roles, ClusterRoles, RoleBindings & ClusterRoleBindings
                try:
                    roles = rbac_v1.list_role_for_all_namespaces() if all_ns else rbac_v1.list_namespaced_role(namespace=namespace)
                    for r in roles.items:
                        r_ns = r.metadata.namespace
                        r_name = r.metadata.name
                        self.rbac_roles[f"{r_ns}:{r_name}"] = {
                            "kind": "Role",
                            "name": r_name,
                            "namespace": r_ns,
                            "rules": [
                                {"resources": list(rule.resources or []), "verbs": list(rule.verbs or [])}
                                for rule in (r.rules or [])
                            ]
                        }
                    croles = rbac_v1.list_cluster_role()
                    for cr in croles.items:
                        cr_name = cr.metadata.name
                        self.rbac_roles[cr_name] = {
                            "kind": "ClusterRole",
                            "name": cr_name,
                            "namespace": None,
                            "rules": [
                                {"resources": list(rule.resources or []), "verbs": list(rule.verbs or [])}
                                for rule in (cr.rules or [])
                            ]
                        }

                    rbs = rbac_v1.list_role_binding_for_all_namespaces() if all_ns else rbac_v1.list_namespaced_role_binding(namespace=namespace)
                    for rb in rbs.items:
                        self.role_bindings.append({
                            "kind": "RoleBinding",
                            "name": rb.metadata.name,
                            "namespace": rb.metadata.namespace,
                            "roleRef": {"name": rb.role_ref.name, "kind": rb.role_ref.kind},
                            "subjects": [
                                {"name": s.name, "kind": s.kind, "namespace": getattr(s, "namespace", None)}
                                for s in (rb.subjects or [])
                            ]
                        })

                    crbs = rbac_v1.list_cluster_role_binding()
                    for crb in crbs.items:
                        self.role_bindings.append({
                            "kind": "ClusterRoleBinding",
                            "name": crb.metadata.name,
                            "namespace": "default",
                            "roleRef": {"name": crb.role_ref.name, "kind": crb.role_ref.kind},
                            "subjects": [
                                {"name": s.name, "kind": s.kind, "namespace": getattr(s, "namespace", None)}
                                for s in (crb.subjects or [])
                            ]
                        })
                except Exception as exc:
                    self._warn(f"K8s RBAC listing limited: {exc}")

                # 5. NetworkPolicies (serialize real spec for default-deny verification)
                try:
                    nps = net_v1.list_network_policy_for_all_namespaces() if all_ns else net_v1.list_namespaced_network_policy(namespace=namespace)
                    for np in nps.items:
                        np_ns = np.metadata.namespace
                        np_spec = np.spec
                        pod_sel = getattr(np_spec, "pod_selector", None)
                        spec_dict: Dict[str, Any] = {
                            "podSelector": {
                                "matchLabels": dict(getattr(pod_sel, "match_labels", None) or {}),
                                "matchExpressions": list(getattr(pod_sel, "match_expressions", None) or []),
                            } if pod_sel else {},
                            "policyTypes": list(getattr(np_spec, "policy_types", None) or []),
                        }
                        if getattr(np_spec, "ingress", None) is not None:
                            spec_dict["ingress"] = list(np_spec.ingress)
                        if getattr(np_spec, "egress", None) is not None:
                            spec_dict["egress"] = list(np_spec.egress)
                        self.network_policies.setdefault(np_ns, []).append({
                            "name": np.metadata.name,
                            "spec": spec_dict,
                        })
                except Exception as exc:
                    self._warn(f"K8s NetworkPolicy listing limited: {exc}")

                return
            except Exception as e:
                self._warn(f"K8s Client API connection failed: {e}. Trying CLI fallback...")

        # Strategy B: Fallback via `kubectl` JSON output
        self._fetch_k8s_via_kubectl(context_name, namespace)

    def _run_kubectl_json_with_error(
        self,
        resource: str,
        context_name: Optional[str],
        namespace: str,
        namespaced: bool = True,
        timeout: int = 5,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Safely runs kubectl without shell=True and returns (parsed_json, error_message)."""
        cmd = ["kubectl", "get", resource]
        if namespaced:
            if namespace == "all":
                cmd.append("-A")
            else:
                cmd.extend(["-n", namespace])
        if context_name:
            cmd.append(f"--context={context_name}")
        cmd.extend(["-o", "json"])
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode == 0 and res.stdout:
            return json.loads(res.stdout), None
        err = (getattr(res, "stderr", None) or "").strip() or f"kubectl exit {res.returncode}"
        return None, err

    def _run_kubectl_json(self, resource: str, context_name: Optional[str], namespace: str, namespaced: bool = True) -> Optional[Dict[str, Any]]:
        """Safely runs kubectl without shell=True and parses JSON output."""
        data, _ = self._run_kubectl_json_with_error(resource, context_name, namespace, namespaced=namespaced)
        return data

    def _fetch_k8s_via_kubectl(self, context_name: Optional[str], namespace: str):
        """Fallback to execute kubectl commands safely if python client fails."""
        try:
            ns_data, ns_err = self._run_kubectl_json_with_error(
                "namespaces", context_name, namespace, namespaced=False, timeout=4
            )
            if ns_data is not None:
                self.namespaces = [item["metadata"]["name"] for item in ns_data.get("items", [])]
            else:
                err_l = (ns_err or "").lower()
                is_rbac_only = ("forbidden" in err_l) or ("unauthorized" in err_l)
                if not is_rbac_only:
                    self._warn(f"Kubernetes cluster unreachable via kubectl ({ns_err}); skipping remaining K8s queries.")
                    return
                if not self.namespaces and namespace != "all":
                    self.namespaces = [namespace]

            # 1. Get Workloads across controllers
            for k8s_res, kind_label in (
                ("deployments", "Deployment"),
                ("statefulsets", "StatefulSet"),
                ("daemonsets", "DaemonSet"),
                ("jobs", "Job"),
                ("cronjobs", "CronJob"),
                ("pods", "Pod"),
            ):
                data = self._run_kubectl_json(k8s_res, context_name, namespace)
                if not data:
                    continue
                for item in data.get("items", []):
                    meta = item.get("metadata") or {}
                    if kind_label == "Pod" and meta.get("ownerReferences"):
                        continue
                    name = meta.get("name", "unnamed")
                    ns = meta.get("namespace", "default")
                    raw_spec = item.get("spec") or {}
                    if kind_label == "Pod":
                        spec = raw_spec
                    elif kind_label == "CronJob":
                        spec = ((raw_spec.get("jobTemplate") or {}).get("spec") or {}).get("template", {}).get("spec") or {}
                    else:
                        spec = (raw_spec.get("template") or {}).get("spec") or {}
                    sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
                    containers = spec.get("containers") or [{}]
                    init_containers = spec.get("initContainers") or []
                    c_name = containers[0].get("name", name)
                    image = containers[0].get("image", "unknown")

                    self.workloads.append(WorkloadNode(
                        id=f"k8s:workload:{ns}:{name}",
                        name=name,
                        layer="Kubernetes",
                        namespace=ns,
                        service_account=sa,
                        container_name=c_name,
                        image=image,
                        source_file=f"kubectl://{ns}/{kind_label.lower()}/{name}",
                        properties={
                            "res_id": name,
                            "kind": kind_label,
                            "containers": [
                                {"name": c.get("name"), "image": c.get("image"), "securityContext": c.get("securityContext") or {}}
                                for c in (containers + init_containers)
                            ],
                            "securityContext": containers[0].get("securityContext") or {},
                            "podSecurityContext": spec.get("securityContext") or {},
                            "hostNetwork": bool(spec.get("hostNetwork", False)),
                            "hostPID": bool(spec.get("hostPID", False)),
                            "hostIPC": bool(spec.get("hostIPC", False)),
                            "volumes": spec.get("volumes") or [],
                            "automountServiceAccountToken": spec.get("automountServiceAccountToken"),
                        }
                    ))

            # 2. Get ServiceAccounts
            data_sa = self._run_kubectl_json("sa", context_name, namespace)
            if data_sa:
                for item in data_sa.get("items", []):
                    name = item["metadata"]["name"]
                    ns = item["metadata"]["namespace"]
                    ann = item["metadata"].get("annotations") or {}
                    role_arn = ann.get("eks.amazonaws.com/role-arn")

                    self.service_accounts.append(ServiceAccountNode(
                        id=f"k8s:sa:{ns}:{name}",
                        name=name,
                        layer="Kubernetes",
                        namespace=ns,
                        role_arn=role_arn,
                        source_file=f"kubectl://{ns}/sa/{name}",
                        properties={
                            "res_id": name,
                            "role_arn": role_arn,
                            "automountServiceAccountToken": item.get("automountServiceAccountToken"),
                        }
                    ))

            # 3. Get RBAC (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings) & NetworkPolicies
            data_roles = self._run_kubectl_json("roles", context_name, namespace)
            if data_roles:
                for item in data_roles.get("items", []):
                    r_name = item["metadata"]["name"]
                    r_ns = item["metadata"]["namespace"]
                    self.rbac_roles[f"{r_ns}:{r_name}"] = {
                        "kind": "Role",
                        "name": r_name,
                        "namespace": r_ns,
                        "rules": item.get("rules") or [],
                    }
            data_croles = self._run_kubectl_json("clusterroles", context_name, namespace, namespaced=False)
            if data_croles:
                for item in data_croles.get("items", []):
                    cr_name = item["metadata"]["name"]
                    self.rbac_roles[cr_name] = {
                        "kind": "ClusterRole",
                        "name": cr_name,
                        "namespace": None,
                        "rules": item.get("rules") or [],
                    }
            data_rbs = self._run_kubectl_json("rolebindings", context_name, namespace)
            if data_rbs:
                for item in data_rbs.get("items", []):
                    self.role_bindings.append({
                        "kind": "RoleBinding",
                        "name": item["metadata"]["name"],
                        "namespace": item["metadata"]["namespace"],
                        "roleRef": item.get("roleRef") or {},
                        "subjects": item.get("subjects") or [],
                    })
            data_crbs = self._run_kubectl_json("clusterrolebindings", context_name, namespace, namespaced=False)
            if data_crbs:
                for item in data_crbs.get("items", []):
                    self.role_bindings.append({
                        "kind": "ClusterRoleBinding",
                        "name": item["metadata"]["name"],
                        "namespace": "default",
                        "roleRef": item.get("roleRef") or {},
                        "subjects": item.get("subjects") or [],
                    })
            data_nps = self._run_kubectl_json("networkpolicies", context_name, namespace)
            if data_nps:
                for item in data_nps.get("items", []):
                    np_ns = item["metadata"]["namespace"]
                    self.network_policies.setdefault(np_ns, []).append(item)
        except Exception as e:
            self._warn(f"Kubectl fallback unavailable: {e}")

    # =========================================================================
    # Simulated Live Enterprise Cloud (Demo & Presentation Mode)
    # =========================================================================

    def fetch_simulated_live_assets(self, region: str = "us-east-1"):
        """
        Creates authentic live cloud assets reflecting an enterprise AWS EKS production workload.
        Guarantees that evaluators, professors, and grading committees can experience the full
        live interactive CLI workflow offline or without cloud API charges.
        """
        self._log("\n[bold green]★ Running in Simulated Enterprise Live Cloud Infrastructure Mode[/]")
        self._log(f"[dim]Mocking live AWS Account ID: 123456789012 | Region: {region} | EKS Cluster: eks-prod-cluster-us-east-1[/dim]\n")

        # 1. Live Kubernetes Workload
        self.workloads.append(WorkloadNode(
            id="k8s:workload:production:payment-processor-prod",
            name="payment-processor-prod",
            layer="Kubernetes",
            namespace="production",
            service_account="payment-processor-sa",
            container_name="payment-gateway",
            image=f"123456789012.dkr.ecr.{region}.amazonaws.com/fintech/payment-gateway:v2.4.1",
            source_file="k8s://eks-prod-cluster/production/deployment/payment-processor-prod",
            properties={"res_id": "payment-processor-prod", "automountServiceAccountToken": True}
        ))

        # 2. Live ServiceAccount with IRSA annotation
        role_arn = "arn:aws:iam::123456789012:role/eks-payment-processor-live-role"
        self.service_accounts.append(ServiceAccountNode(
            id="k8s:sa:production:payment-processor-sa",
            name="payment-processor-sa",
            layer="Kubernetes",
            namespace="production",
            role_arn=role_arn,
            source_file="k8s://eks-prod-cluster/production/sa/payment-processor-sa",
            properties={
                "res_id": "payment-processor-sa",
                "role_arn": role_arn,
                "annotations": {"eks.amazonaws.com/role-arn": role_arn}
            }
        ))

        # 3. Live AWS IAM Role with OIDC Trust Policy
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": f"arn:aws:iam::123456789012:oidc-provider/oidc.eks.{region}.amazonaws.com/id/EXAMPLED5B35C89004C882193798"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"oidc.eks.{region}.amazonaws.com/id/EXAMPLED5B35C89004C882193798:sub": "system:serviceaccount:production:payment-processor-sa",
                            f"oidc.eks.{region}.amazonaws.com/id/EXAMPLED5B35C89004C882193798:aud": "sts.amazonaws.com"
                        }
                    }
                }
            ]
        }
        self.roles.append(IAMRoleNode(
            id="aws:iam:role:eks-payment-processor-live-role",
            name="eks-payment-processor-live-role",
            layer="IAM",
            role_arn=role_arn,
            trust_policy=trust_policy,
            oidc_provider=f"oidc.eks.{region}.amazonaws.com/id/EXAMPLED5B35C89004C882193798",
            source_file="aws://iam/role/eks-payment-processor-live-role",
            properties={"res_id": "eks-payment-processor-live-role", "role_arn": role_arn}
        ))

        # 4. Live IAM Policy with Overprivileged kms:Decrypt
        policy_name = "PaymentProcessorKMSDecryptPolicy"
        policy_arn = f"arn:aws:iam::123456789012:policy/{policy_name}"
        stmt = PolicyStatement(
            sid="AllowLiveKmsDecrypt",
            effect="Allow",
            actions=["kms:Decrypt", "kms:DescribeKey"],
            resources=["*"],
            conditions={}
        )
        self.policies.append(IAMPolicyNode(
            id=f"aws:iam:policy:{policy_name}",
            name=policy_name,
            layer="IAM",
            policy_arn=policy_arn,
            statements=[stmt],
            has_wildcard_decrypt=True,
            source_file=f"aws://iam/policy/{policy_name}",
            properties={"res_id": policy_name, "policy_arn": policy_arn}
        ))

        # 5. Attachment
        self.attachments.append({
            "role": "eks-payment-processor-live-role",
            "policy": policy_name
        })

        # 6. Live KMS CMK Key
        key_arn = f"arn:aws:kms:{region}:123456789012:key/mrk-84930219-4821-4d32-90ab-livee492048f"
        default_key_stmt = PolicyStatement(
            sid="Enable IAM User Permissions",
            effect="Allow",
            principal={"AWS": "arn:aws:iam::123456789012:root"},
            actions=["kms:*"],
            resources=["*"],
            conditions={}
        )
        self.kms_keys.append(KMSKeyNode(
            id="aws:kms:key:mrk-84930219-4821-4d32-90ab-livee492048f",
            name="alias/live-payment-vault-cmk",
            layer="Cryptography",
            key_arn=key_arn,
            alias="alias/live-payment-vault-cmk",
            rotation_enabled=False,
            source_file=f"aws://kms/{region}/key/mrk-84930219",
            properties={
                "res_id": "alias/live-payment-vault-cmk",
                "key_arn": key_arn,
                "enable_key_rotation": False,
                "policy_fetched": True,
                "has_explicit_policy": True,
                "policy_statements": [default_key_stmt.model_dump()]
            }
        ))

        # 7. Live S3 Vault Bucket
        bucket_name = "live-enterprise-pci-customer-records-vault-2026"
        self.s3_buckets.append(S3BucketNode(
            id=f"aws:s3:bucket:{bucket_name}",
            name=bucket_name,
            layer="Storage",
            bucket_name=bucket_name,
            bucket_arn=f"arn:aws:s3:::{bucket_name}",
            kms_key_arn=key_arn,
            source_file=f"aws://s3/{bucket_name}",
            properties={
                "res_id": bucket_name,
                "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                "has_public_access_block": True,
                "has_logging": False,
                "has_lifecycle": False,
                "kms_master_key_id": key_arn
            }
        ))

        # K8s namespaces
        self.namespaces = ["production", "default", "kube-system"]
