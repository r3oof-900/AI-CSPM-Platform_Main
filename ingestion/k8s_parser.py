"""
AI-CSPM Kubernetes Ingestion Parser
Extracts Workloads, ServiceAccounts, RBAC Roles, RoleBindings, NetworkPolicies, and Cloud Workload Identity bindings (e.g. AWS IRSA).
"""

import os
import yaml
from typing import List, Tuple, Dict, Any, Set
try:
    from core.models import WorkloadNode, ServiceAccountNode, NodeType
except (ImportError, ValueError):
    from ..core.models import WorkloadNode, ServiceAccountNode, NodeType


class K8sParser:
    def __init__(self):
        self.workloads: List[WorkloadNode] = []
        self.service_accounts: List[ServiceAccountNode] = []
        self.namespaces: Set[str] = set()
        self.network_policies: Dict[str, List[Dict[str, Any]]] = {}  # namespace -> list of policies
        self.roles: Dict[str, Dict[str, Any]] = {}                    # "namespace:name" -> role data
        self.role_bindings: List[Dict[str, Any]] = []

    def parse_file(self, filepath: str) -> Tuple[List[WorkloadNode], List[ServiceAccountNode]]:
        """Parses a Kubernetes multi-document YAML file."""
        if not os.path.exists(filepath):
            return [], []

        with open(filepath, "r", encoding="utf-8") as f:
            try:
                documents = list(yaml.safe_load_all(f))
            except Exception as e:
                print(f"[!] Error parsing K8s YAML {filepath}: {e}")
                return [], []

        file_workloads = []
        file_sas = []

        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            metadata = doc.get("metadata") or {}
            name = metadata.get("name", "unnamed")
            namespace = metadata.get("namespace", "default")
            self.namespaces.add(namespace)

            if kind == "Namespace":
                self.namespaces.add(name)

            elif kind == "NetworkPolicy":
                if namespace not in self.network_policies:
                    self.network_policies[namespace] = []
                self.network_policies[namespace].append(doc)

            elif kind in ["Role", "ClusterRole"]:
                role_key = f"{namespace}:{name}" if kind == "Role" else name
                self.roles[role_key] = {
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "rules": doc.get("rules") or [],
                    "source_file": filepath
                }

            elif kind in ["RoleBinding", "ClusterRoleBinding"]:
                self.role_bindings.append({
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "roleRef": doc.get("roleRef") or {},
                    "subjects": doc.get("subjects") or [],
                    "source_file": filepath
                })

            elif kind == "ServiceAccount":
                annotations = metadata.get("annotations") or {}
                # AWS EKS IRSA or Azure Workload Identity annotation
                role_arn = (
                    annotations.get("eks.amazonaws.com/role-arn")
                    or annotations.get("azure.workload.identity/client-id")
                )
                automount = doc.get("automountServiceAccountToken", True)

                sa_node = ServiceAccountNode(
                    id=f"k8s:sa:{namespace}:{name}",
                    name=name,
                    namespace=namespace,
                    role_arn=role_arn,
                    source_file=filepath,
                    properties={
                        "annotations": annotations,
                        "labels": metadata.get("labels") or {},
                        "automountServiceAccountToken": automount
                    }
                )
                file_sas.append(sa_node)

            elif kind in ["Deployment", "Pod", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
                spec = doc.get("spec") or {}
                if kind == "Pod":
                    template_spec = spec
                elif kind == "CronJob":
                    job_template = (spec.get("jobTemplate") or {}).get("spec") or {}
                    template_spec = (job_template.get("template") or {}).get("spec") or {}
                else:
                    template_spec = (spec.get("template") or {}).get("spec") or {}

                sa_name = template_spec.get("serviceAccountName") or template_spec.get("serviceAccount") or "default"
                containers = template_spec.get("containers") or []
                init_containers = template_spec.get("initContainers") or []
                primary_container = containers[0] if containers else {}
                automount = template_spec.get("automountServiceAccountToken", None)

                workload_node = WorkloadNode(
                    id=f"k8s:workload:{namespace}:{name}",
                    name=name,
                    namespace=namespace,
                    service_account=sa_name,
                    container_name=primary_container.get("name"),
                    image=primary_container.get("image"),
                    source_file=filepath,
                    properties={
                        "kind": kind,
                        "replicas": spec.get("replicas", 1),
                        "containers": [
                            {"name": c.get("name"), "image": c.get("image"), "securityContext": c.get("securityContext") or {}}
                            for c in (containers + init_containers)
                        ],
                        "securityContext": primary_container.get("securityContext") or {},
                        "podSecurityContext": template_spec.get("securityContext") or {},
                        "hostNetwork": bool(template_spec.get("hostNetwork", False)),
                        "hostPID": bool(template_spec.get("hostPID", False)),
                        "hostIPC": bool(template_spec.get("hostIPC", False)),
                        "automountServiceAccountToken": automount,
                        "volumes": template_spec.get("volumes") or [],
                        "env": primary_container.get("env") or []
                    }
                )
                file_workloads.append(workload_node)

        self.workloads.extend(file_workloads)
        self.service_accounts.extend(file_sas)
        return file_workloads, file_sas
