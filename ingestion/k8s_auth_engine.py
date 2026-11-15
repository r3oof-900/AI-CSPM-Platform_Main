"""
AI-CSPM In-Memory Kubernetes Authentication Engine
Provides zero-external-CLI authentication for AWS EKS, External K8s (Bearer Token), and Local Kubeconfig.
"""

import os
import atexit
import base64
import tempfile
from typing import Optional, Any
import boto3
from botocore.signers import RequestSigner

try:
    from kubernetes import client, config
    HAS_K8S = True
except ImportError:
    HAS_K8S = False
    client = None
    config = None


class K8sAuthEngine:
    """
    محرك توثيق كوبرنيتس مستقل بالكامل في الذاكرة بدون استدعاء أي برامج خارجية (Zero Subprocess / Zero CLI).
    """

    @staticmethod
    def generate_eks_token(cluster_name: str, session: boto3.Session) -> str:
        """
        توليد EKS Bearer Token في الذاكرة عبر AWS STS Presigned URL
        بدون الحاجة لبرنامج 'aws' الخارجي.
        """
        if not cluster_name or not isinstance(cluster_name, str):
            raise ValueError("Cluster name must be a valid non-empty string.")

        credentials = session.get_credentials()
        if not credentials:
            raise ValueError("AWS credentials not found in session; cannot generate EKS token.")

        sts_client = session.client("sts")
        service_id = sts_client.meta.service_model.service_id
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
        domain = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"

        signer = RequestSigner(
            service_id,
            region,
            "sts",
            "v4",
            credentials,
            sts_client.meta.events
        )

        params = {
            "method": "GET",
            "url": f"https://sts.{region}.{domain}/?Action=GetCallerIdentity&Version=2011-06-15",
            "body": {},
            "headers": {"x-k8s-aws-id": cluster_name},
            "context": {}
        }

        # operation_name is required in botocore RequestSigner.generate_presigned_url
        signed_url = signer.generate_presigned_url(params, "GetCallerIdentity", expires_in=60)
        base64_url = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8").rstrip("=")
        token = f"k8s-aws-v1.{base64_url}"

        if not token or not isinstance(token, str):
            raise ValueError("Failed to generate a valid STS Bearer token.")

        return token.strip()

    @classmethod
    def get_eks_client(cls, cluster_name: str, session: boto3.Session) -> Any:
        """
        اكتشاف إعدادات EKS والاتصال به برمجياً في الذاكرة بالكامل.
        """
        if not HAS_K8S:
            raise ImportError("The 'kubernetes' package is required to connect to Kubernetes.")

        eks_client = session.client("eks")
        desc = eks_client.describe_cluster(name=cluster_name)["cluster"]

        endpoint = desc["endpoint"]
        ca_data = desc["certificateAuthority"]["data"]
        token = cls.generate_eks_token(cluster_name, session)

        ca_cert_bytes = base64.b64decode(ca_data)
        temp_ca = tempfile.NamedTemporaryFile(delete=False)
        temp_ca.write(ca_cert_bytes)
        temp_ca.close()
        atexit.register(lambda: os.path.exists(temp_ca.name) and os.remove(temp_ca.name))

        k8s_conf = client.Configuration()
        k8s_conf.host = endpoint
        k8s_conf.verify_ssl = True
        k8s_conf.ssl_ca_cert = temp_ca.name
        k8s_conf.api_key["authorization"] = token
        k8s_conf.api_key_prefix["authorization"] = "Bearer"

        return client.ApiClient(k8s_conf)

    @classmethod
    def get_external_k8s_client(
        cls,
        endpoint: str,
        token: str,
        ca_cert_base64: Optional[str] = None,
        verify_ssl: bool = True
    ) -> Any:
        """
        الاتصال بأي كوبرنيتس خارجي (K3s, On-Prem, EC2 Self-hosted, VPS).
        """
        if not HAS_K8S:
            raise ImportError("The 'kubernetes' package is required to connect to Kubernetes.")

        if not endpoint or not isinstance(endpoint, str):
            raise ValueError("Endpoint must be a valid non-empty URL string.")
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a valid non-empty string.")

        k8s_conf = client.Configuration()
        k8s_conf.host = endpoint.rstrip("/")
        k8s_conf.api_key["authorization"] = token.strip()
        k8s_conf.api_key_prefix["authorization"] = "Bearer"
        k8s_conf.verify_ssl = verify_ssl

        if verify_ssl and ca_cert_base64:
            ca_bytes = base64.b64decode(ca_cert_base64)
            temp_ca = tempfile.NamedTemporaryFile(delete=False)
            temp_ca.write(ca_bytes)
            temp_ca.close()
            atexit.register(lambda: os.path.exists(temp_ca.name) and os.remove(temp_ca.name))
            k8s_conf.ssl_ca_cert = temp_ca.name

        return client.ApiClient(k8s_conf)

    @classmethod
    def auto_connect(
        cls,
        # خيار AWS EKS
        aws_session: Optional[boto3.Session] = None,
        cluster_name: Optional[str] = None,
        # خيار خارجي
        k8s_endpoint: Optional[str] = None,
        k8s_token: Optional[str] = None,
        k8s_ca_cert: Optional[str] = None,
        verify_ssl: bool = True,
        # خيار Kubeconfig محلي
        kube_context: Optional[str] = None,
        use_kubeconfig: bool = False
    ) -> Any:
        """
        الموزع الذكي: يختار طريقة التوثيق تلقائياً بناءً على المدخلات المتاحة.
        """
        if not HAS_K8S:
            raise ImportError("The 'kubernetes' package is required to connect to Kubernetes.")

        # 1. كوبرنيتس خارجي مباشر
        if k8s_endpoint and k8s_token:
            return cls.get_external_k8s_client(
                endpoint=k8s_endpoint,
                token=k8s_token,
                ca_cert_base64=k8s_ca_cert,
                verify_ssl=verify_ssl and (bool(k8s_ca_cert) or verify_ssl)
            )

        # 2. AWS EKS تلقائي عبر boto3 في الذاكرة
        if aws_session and cluster_name:
            return cls.get_eks_client(cluster_name=cluster_name, session=aws_session)

        # 3. Kubeconfig محلي كـ Fallback
        if use_kubeconfig or kube_context:
            k8s_conf = client.Configuration()
            config.load_kube_config(context=kube_context, client_configuration=k8s_conf)
            return client.ApiClient(k8s_conf)

        # 4. In-cluster Token (إذا كان الفاحص يعمل داخل حاوية في Pod)
        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
            k8s_conf = client.Configuration()
            config.load_incluster_config(client_configuration=k8s_conf)
            return client.ApiClient(k8s_conf)

        raise RuntimeError("No valid Kubernetes connection parameters provided.")
