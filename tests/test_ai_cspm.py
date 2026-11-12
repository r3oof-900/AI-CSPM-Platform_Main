import json
import os
import shutil
import sys
from unittest.mock import MagicMock, patch

import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ai.engine import AIRemediationEngine
from ai.multi_agent_consensus import MultiAgentConsensusEngine
from ai_cspm import run_scan
from core.analyzer import AttackPathAnalyzer
from core.graph import ContextualGraph
from core.models import (
    IAMPolicyNode,
    IAMRoleNode,
    KMSKeyNode,
    PolicyStatement,
    S3BucketNode,
    ServiceAccountNode,
    WorkloadNode,
)
from core.reporter import (
    apply_auto_remediation,
    generate_html_report,
    generate_interactive_graph_html,
)
from ingestion.k8s_parser import K8sParser
from ingestion.live_cloud_parser import LiveCloudFetcher
from ingestion.tf_parser import TerraformParser


def test_graph_links_only_matching_kms_and_s3_buckets():
    cg = ContextualGraph()
    w = WorkloadNode(id="k8s:workload:prod:app", name="app", namespace="prod", service_account="sa")
    sa = ServiceAccountNode(id="k8s:sa:prod:sa", name="sa", namespace="prod", role_arn="arn:aws:iam::123:role/app-role")
    r = IAMRoleNode(id="iam:role:app-role", name="app-role", role_arn="arn:aws:iam::123:role/app-role")
    p = IAMPolicyNode(
        id="iam:policy:p",
        name="p",
        statements=[PolicyStatement(effect="Allow", actions=["*"], resources=["*"])],
    )
    k1 = KMSKeyNode(id="kms:key:k1", name="k1", key_arn="arn:aws:kms:us-east-1:123:key/k1")
    k2 = KMSKeyNode(id="kms:key:k2", name="k2", key_arn="arn:aws:kms:us-east-1:123:key/k2")
    b1 = S3BucketNode(id="s3:bucket:b1", name="b1", bucket_name="b1", bucket_arn="arn:aws:s3:::b1", kms_key_arn=k1.key_arn)
    b_unencrypted = S3BucketNode(id="s3:bucket:b2", name="b2", bucket_name="b2", bucket_arn="arn:aws:s3:::b2")

    cg.build_from_parsed(
        workloads=[w],
        service_accounts=[sa],
        roles=[r],
        policies=[p],
        kms_keys=[k1, k2],
        s3_buckets=[b1, b_unencrypted],
        attachments=[{"role": "app-role", "policy": "p"}],
    )

    assert cg.graph.has_edge(k1.id, b1.id)
    assert not cg.graph.has_edge(k1.id, b_unencrypted.id)
    assert not cg.graph.has_edge(k2.id, b1.id)
    assert cg.graph.get_edge_data(p.id, k1.id)["lethal_flaw"] is True


def test_graph_merges_multi_statement_edges_and_respects_deny():
    cg = ContextualGraph()
    k = KMSKeyNode(id="kms:key:k1", name="k1", key_arn="arn:aws:kms:us-east-1:123:key/k1")
    # Statement 1 is lethal wildcard; Statement 2 is scoped safe. Edge must stay lethal!
    p_multi = IAMPolicyNode(
        id="iam:policy:multi",
        name="multi",
        statements=[
            PolicyStatement(effect="Allow", actions=["kms:Decrypt"], resources=["*"]),
            PolicyStatement(
                effect="Allow",
                actions=["kms:DescribeKey"],
                resources=[k.key_arn],
                conditions={"StringEquals": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::b1"}},
            ),
        ],
    )
    # Explicit Deny must block ALLOWS_DECRYPT edge
    p_denied = IAMPolicyNode(
        id="iam:policy:denied",
        name="denied",
        statements=[
            PolicyStatement(effect="Allow", actions=["kms:Decrypt"], resources=["*"]),
            PolicyStatement(effect="Deny", actions=["kms:Decrypt"], resources=["*"]),
        ],
    )
    cg.build_from_parsed([], [], [], [p_multi, p_denied], [k], [], [])
    assert cg.graph.get_edge_data(p_multi.id, k.id)["lethal_flaw"] is True
    assert not cg.graph.has_edge(p_denied.id, k.id)


def test_exact_matching_prevents_substring_collisions():
    cg = ContextualGraph()
    sa = ServiceAccountNode(
        id="k8s:sa:prod:sa",
        name="sa",
        namespace="prod",
        role_arn="arn:aws:iam::123:role/app-admin",
    )
    r_short = IAMRoleNode(id="iam:role:app", name="app", role_arn="arn:aws:iam::123:role/app")
    r_admin = IAMRoleNode(id="iam:role:app-admin", name="app-admin", role_arn="arn:aws:iam::123:role/app-admin")
    p_short = IAMPolicyNode(id="iam:policy:pol", name="pol")
    p_other = IAMPolicyNode(id="iam:policy:pol-readonly", name="pol-readonly")

    cg.build_from_parsed(
        [],
        [sa],
        [r_short, r_admin],
        [p_short, p_other],
        [],
        [],
        [{"role": "app", "policy": "pol"}],
    )
    assert cg.graph.has_edge(sa.id, r_admin.id)
    assert not cg.graph.has_edge(sa.id, r_short.id)
    assert cg.graph.has_edge(r_short.id, p_short.id)
    assert not cg.graph.has_edge(r_short.id, p_other.id)


def test_analyzer_kms_viaservice_root_principal_and_action_list():
    cg = ContextualGraph()
    r = IAMRoleNode(
        id="iam:role:r",
        name="r",
        role_arn="arn:aws:iam::123:role/r",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRoleWithWebIdentity"],  # list form!
                    "Condition": {"StringEquals": {"oidc:aud": "sts.amazonaws.com"}},  # missing :sub
                }
            ]
        },
        properties={"raw": {"permissions_boundary": "arn:aws:iam::123:policy/bound"}},
    )
    k = KMSKeyNode(
        id="kms:key:k",
        name="k",
        key_arn="arn:aws:kms:us-east-1:123:key/k",
        properties={
            "policy_fetched": True,
            "has_explicit_policy": True,
            "policy_statements": [
                {
                    "effect": "Allow",
                    "principal": {"AWS": "arn:aws:iam::123:role/kms-admin"},
                    "actions": ["kms:Decrypt"],
                    "resources": ["*"],
                    "conditions": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}},
                }
            ],
        },
    )
    b_live_safe = S3BucketNode(
        id="aws:s3:bucket:safe",
        name="safe",
        bucket_name="safe",
        bucket_arn="arn:aws:s3:::safe",
        properties={"has_public_access_block": True, "has_logging": True, "has_lifecycle": True},
    )
    cg.build_from_parsed([], [], [r], [], [k], [b_live_safe], [])
    analyzer = AttackPathAnalyzer(cg, tf_parser=None, k8s_parser=None)
    findings = analyzer.audit_all_misconfigurations()
    ids = {f.id for f in findings}

    assert "SEC-IAM-002" in ids
    assert "SEC-IAM-004" not in ids
    assert "SEC-IAM-003" not in ids
    assert "SEC-KMS-001" not in ids
    assert "SEC-S3-001" not in ids
    assert "SEC-S3-002" not in ids
    assert "SEC-S3-003" not in ids


def test_offline_mode_blocks_live_gemini_and_contained_skips_gemini():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key-for-test"}):
        with patch("requests.post") as mock_post:
            engine = AIRemediationEngine(offline_mode=True)
            from core.models import AttackPath
            ap = AttackPath(
                id="AP-001",
                title="Test",
                nodes=[
                    {"id": "w", "name": "app", "type": "WORKLOAD", "layer": "Kubernetes"},
                    {"id": "p", "name": "OverprivilegedPol", "type": "IAM_POLICY", "layer": "IAM"},
                    {"id": "k", "name": "payment_key", "type": "KMS_KEY", "layer": "Cryptography"},
                    {"id": "b", "name": "payment_vault", "type": "S3_BUCKET", "layer": "Storage"},
                ],
                steps=["1. test"],
                root_cause="test",
                impact="test",
            )
            rem = engine.synthesize_remediation(ap)
            assert "aws_kms_key.payment_key.arn" in rem.remediated_code
            mock_post.assert_not_called()

            consensus = MultiAgentConsensusEngine(offline_mode=False)
            res = consensus.run_consensus_evaluation({"id": "AP-CONTAINED"})
            assert res["arbiter"]["cvss_v4_score"] == 0.0
            mock_post.assert_not_called()


def test_tf_parser_rotation_and_cross_resource_order(tmp_path):
    tf_file = tmp_path / "infra.tf"
    tf_file.write_text(
        '''
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.mykey.arn
    }
  }
}

resource "aws_s3_bucket" "vault" {
  bucket = "my-vault-bucket"
}

resource "aws_kms_key" "mykey" {
  enable_key_rotation = false
}

resource "aws_kms_alias" "myalias" {
  name          = "alias/my-key"
  target_key_id = aws_kms_key.mykey.key_id
}
''',
        encoding="utf-8",
    )
    tf = TerraformParser()
    tf.parse_directory(str(tmp_path))
    assert len(tf.kms_keys) == 1
    assert tf.kms_keys[0].rotation_enabled is False
    assert tf.kms_keys[0].alias == "alias/my-key"
    assert len(tf.s3_buckets) == 1
    assert tf.s3_buckets[0].kms_key_arn == tf.kms_keys[0].key_arn


def test_end_to_end_json_apply_fix_and_rescan(tmp_path, capsys):
    baseline_src = os.path.join(ROOT_DIR, "samples", "vulnerable_baseline")
    work_dir = tmp_path / "baseline"
    shutil.copytree(baseline_src, work_dir)

    # 1. Scan in JSON format with --offline and --apply-fix
    exit_code = run_scan(
        target_dir=str(work_dir),
        offline_mode=True,
        format_type="json",
        apply_fix=True,
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metrics"]["critical_attack_paths"] == 1
    assert data["remediation"] is not None
    assert "kms:EncryptionContext" in data["remediation"]["remediated_code"]

    # Check HTML report uses real target_source
    html_out = generate_html_report(data)
    assert "Unknown" not in html_out.split("</header>")[0]

    # 2. Re-scan after --apply-fix: cross-layer path is 0, while standalone HIGH/MED findings reflect real CVSS (not 0.0)
    json_out_path = tmp_path / "post_fix.json"
    exit_code_after = run_scan(
        target_dir=str(work_dir),
        output_path=str(json_out_path),
        offline_mode=True,
        format_type="json",
        apply_fix=False,
    )
    assert exit_code_after == 0
    captured_after = capsys.readouterr()
    data_after = json.loads(captured_after.out)
    assert data_after["metrics"]["critical_attack_paths"] == 0
    assert data_after["metrics"]["containment_score"] == "100%"
    assert data_after["consensus"]["arbiter"]["cvss_v4_score"] == 7.5
    assert "POSTURE REMEDIATION REQUIRED" in data_after["consensus"]["consensus_status"]

    html_after = generate_html_report(data_after)
    assert "7.5 HIGH" in html_after
    assert "100% CONTAINED & SECURE" not in html_after
    assert "0.0 Critical" not in html_after


def test_clean_baseline_vs_posture_findings_consensus_and_real_live_arns():
    consensus = MultiAgentConsensusEngine(offline_mode=True)
    truly_clean = consensus.run_consensus_evaluation(
        {"id": "AP-CONTAINED", "total_misconfigs": 0, "severity_counts": {}, "max_misconfig_cvss": 0.0}
    )
    assert truly_clean["arbiter"]["cvss_v4_score"] == 0.0
    assert "CERTIFIED SECURE" in truly_clean["consensus_status"]

    from ai.prompt_templates import build_scoped_kms_policy_hcl
    hcl_live = build_scoped_kms_policy_hcl([
        {"id": "p", "name": "LiveKmsPol", "type": "IAM_POLICY", "source_file": "aws://iam/policy/LiveKmsPol"},
        {"id": "k", "name": "alias/prod-cmk", "type": "KMS_KEY", "source_file": "aws://kms/eu-west-1/k1", "key_arn": "arn:aws:kms:eu-west-1:555666777888:key/k1"},
        {"id": "b", "name": "eu-vault", "type": "S3_BUCKET", "source_file": "aws://s3/eu-vault", "bucket_arn": "arn:aws:s3:::eu-vault"},
    ])
    assert "arn:aws:kms:eu-west-1:555666777888:key/k1" in hcl_live
    assert "123456789012" not in hcl_live
    assert "us-east-1" not in hcl_live


def test_ai_fallback_error_is_surfaced_in_diagnostics(capsys):
    with patch.dict(os.environ, {"GEMINI_API_KEY": "bad-key"}):
        with patch("requests.post", side_effect=RuntimeError("Quota exceeded")):
            rc = run_scan(live_demo=True, offline_mode=False, format_type="json")
            assert rc == 1
            data = json.loads(capsys.readouterr().out)
            warnings = data["ai_diagnostics"]["warnings"]
            assert any("Quota exceeded" in w for w in warnings)


def test_live_demo_json_stdout_is_clean(capsys):
    exit_code = run_scan(live_demo=True, offline_mode=True, format_type="json")
    assert exit_code == 1
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["metrics"]["critical_attack_paths"] == 1
    assert parsed["remediation"] is not None


def test_interactive_graph_scales_height_for_many_nodes():
    nodes = [
        {"id": f"n{i}", "label": f"node-{i}", "type": "WORKLOAD", "layer": "Kubernetes"}
        for i in range(6)
    ]
    svg_html = generate_interactive_graph_html({"nodes": nodes, "edges": []})
    assert 'height="780"' in svg_html


def test_role_level_deny_blocks_only_role_with_deny_policy():
    cg = ContextualGraph()
    w1 = WorkloadNode(id="k8s:workload:ns:w1", name="w1", namespace="ns", service_account="sa1")
    w2 = WorkloadNode(id="k8s:workload:ns:w2", name="w2", namespace="ns", service_account="sa2")
    sa1 = ServiceAccountNode(id="k8s:sa:ns:sa1", name="sa1", namespace="ns", role_arn="arn:aws:iam::111122223333:role/r-denied")
    sa2 = ServiceAccountNode(id="k8s:sa:ns:sa2", name="sa2", namespace="ns", role_arn="arn:aws:iam::111122223333:role/r-open")
    r_denied = IAMRoleNode(id="iam:role:r-denied", name="r-denied", role_arn="arn:aws:iam::111122223333:role/r-denied")
    r_open = IAMRoleNode(id="iam:role:r-open", name="r-open", role_arn="arn:aws:iam::111122223333:role/r-open")
    p_allow = IAMPolicyNode(
        id="iam:policy:allow",
        name="allow",
        statements=[PolicyStatement(effect="Allow", actions=["kms:Decrypt"], resources=["*"])],
    )
    p_deny = IAMPolicyNode(
        id="iam:policy:deny",
        name="deny",
        statements=[PolicyStatement(effect="Deny", actions=["kms:Decrypt"], resources=["*"])],
    )
    k = KMSKeyNode(id="kms:key:k1", name="k1", key_arn="arn:aws:kms:us-east-1:111122223333:key/k1", rotation_enabled=False)

    cg.build_from_parsed(
        workloads=[w1, w2],
        service_accounts=[sa1, sa2],
        roles=[r_denied, r_open],
        policies=[p_allow, p_deny],
        kms_keys=[k],
        s3_buckets=[],
        attachments=[
            {"role": "r-denied", "policy": "allow"},
            {"role": "r-denied", "policy": "deny"},
            {"role": "r-open", "policy": "allow"},
        ],
    )
    analyzer = AttackPathAnalyzer(cg)
    paths = analyzer.find_cross_layer_attack_paths()
    assert len(paths) == 1
    assert paths[0].nodes[0]["name"] == "w2"
    findings = analyzer.audit_all_misconfigurations(attack_paths=paths)
    assert any(f.id == "SEC-KMS-002" for f in findings)


def test_cross_account_collision_and_oidc_glob_patterns():
    cg = ContextualGraph()
    sa = ServiceAccountNode(
        id="k8s:sa:payments:payment-sa",
        name="payment-sa",
        namespace="payments",
        role_arn="arn:aws:iam::111111111111:role/shared-app",
    )
    r_acct1 = IAMRoleNode(
        id="iam:role:shared-app-1",
        name="shared-app",
        role_arn="arn:aws:iam::111111111111:role/shared-app",
        oidc_provider="arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/AAA",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/AAA"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringLike": {"oidc.eks.us-east-1.amazonaws.com/id/AAA:sub": "system:serviceaccount:*:payment-sa"}},
                }
            ]
        },
    )
    r_acct2 = IAMRoleNode(
        id="iam:role:shared-app-2",
        name="shared-app",
        role_arn="arn:aws:iam::999999999999:role/shared-app",
    )
    cg.build_from_parsed([], [sa], [r_acct1, r_acct2], [], [], [], [])
    assert cg.graph.has_edge(sa.id, r_acct1.id)
    assert not cg.graph.has_edge(sa.id, r_acct2.id)


def test_tf_data_doc_principals_locals_tfvars_resource_policies_and_pab_flags(tmp_path):
    (tmp_path / "terraform.tfvars").write_text('env_suffix = "prod"\n', encoding="utf-8")
    (tmp_path / "infra.tf").write_text(
        '''
variable "env_suffix" {
  default = "dev"
}

locals {
  vault_name = "vault-${var.env_suffix}"
}

data "aws_iam_policy_document" "irsa_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/XYZ"]
    }
    condition {
      test     = "StringLike"
      variable = "oidc.eks.us-east-1.amazonaws.com/id/XYZ:sub"
      values   = ["system:serviceaccount:*:worker-sa"]
    }
  }
}

resource "aws_iam_role" "worker_role" {
  name               = "worker-role"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_kms_key" "direct_key" {
  enable_key_rotation = false
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/worker-role" }
      Action    = ["kms:Decrypt"]
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "vault" {
  bucket = local.vault_name
}

resource "aws_s3_bucket_public_access_block" "vault_pab" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "vault_pol" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::vault-prod/*"
    }]
  })
}
''',
        encoding="utf-8",
    )
    (tmp_path / "k8s.yaml").write_text(
        '''
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: apps
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: apps
spec:
  template:
    spec:
      serviceAccountName: worker-sa
      containers:
        - name: app
          image: python:3.12
          securityContext:
            privileged: true
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: apps
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - {}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sec-reader
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sec-bind
  namespace: apps
subjects:
  - kind: Group
    name: system:serviceaccounts:apps
roleRef:
  kind: Role
  name: sec-reader
''',
        encoding="utf-8",
    )

    k8s = K8sParser()
    k8s.parse_file(str(tmp_path / "k8s.yaml"))
    tf = TerraformParser()
    tf.parse_directory(str(tmp_path))
    assert tf.s3_buckets[0].bucket_name == "vault-prod"
    assert tf.roles[0].oidc_provider is not None

    cg = ContextualGraph()
    cg.build_from_parsed(k8s.workloads, k8s.service_accounts, tf.roles, tf.policies, tf.kms_keys, tf.s3_buckets, tf.attachments)
    analyzer = AttackPathAnalyzer(cg, tf_parser=tf, k8s_parser=k8s)
    paths = analyzer.find_cross_layer_attack_paths()
    assert len(paths) == 2  # direct KMS key policy path AND direct S3 bucket policy path!

    findings = analyzer.audit_all_misconfigurations(attack_paths=paths)
    ids = {f.id for f in findings}
    assert "SEC-S3-001" in ids  # PAB had block_public_acls=false!
    assert "SEC-S3-004" in ids  # Public S3 bucket policy!
    assert "SEC-KMS-002" in ids # rotation_enabled=false!
    assert "SEC-K8S-003" in ids # allow-all NetworkPolicy is NOT default-deny!
    assert "SEC-K8S-004" in ids # privileged=true!
    assert "SEC-CROSS-003" in ids  # Group subject system:serviceaccounts:apps matched!


def test_phase1_followup_edge_cases_and_fail_on_threshold(tmp_path, capsys):
    # 1. INFO-only AP-CONTAINED must NOT jump to 5.5 MEDIUM
    consensus = MultiAgentConsensusEngine(offline_mode=True)
    info_res = consensus.run_consensus_evaluation({
        "id": "AP-CONTAINED",
        "total_misconfigs": 2,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 2},
        "max_misconfig_cvss": 0.0,
    })
    assert info_res["arbiter"]["cvss_v4_score"] == 0.0
    assert info_res["arbiter"]["cvss_rating"] == "INFO"

    # 2. MEDIUM/LOW-only console scan shows HARDENING ADVISED + Posture Summary
    med_dir = tmp_path / "med_only"
    med_dir.mkdir()
    (med_dir / "k8s.yaml").write_text(
        '''
apiVersion: v1
kind: Namespace
metadata:
  name: dev
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: dev
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
''',
        encoding="utf-8",
    )
    rc_med = run_scan(target_dir=str(med_dir), offline_mode=True, format_type="console")
    assert rc_med == 0
    console_out = capsys.readouterr().out
    assert "HARDENING ADVISED" in console_out
    assert "Security Posture Score" in console_out
    assert "FULLY REMEDIATED & CONTAINED" not in console_out

    # 3. fail_on="high" returns 1 on remediated_baseline (which has HIGH findings), while default returns 0
    rem_dir = os.path.join(ROOT_DIR, "samples", "remediated_baseline")
    assert run_scan(target_dir=rem_dir, offline_mode=True, format_type="json", fail_on="critical") == 0
    capsys.readouterr()
    assert run_scan(target_dir=rem_dir, offline_mode=True, format_type="json", fail_on="high") == 1
    rem_json = json.loads(capsys.readouterr().out)
    html_rem = generate_html_report(rem_json)
    assert "Security Posture Score" in html_rem
    assert "Address 10 standalone posture finding(s)" in html_rem
    assert "Environment baseline already hardened" not in html_rem

    # 4. Empty remediated_code from live Gemini sets last_error in diagnostics
    class _FakeResp:
        status_code = 200
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": '{"remediated_code": "   ", "explanation": "x"}'}]}}]}

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with patch("requests.post", return_value=_FakeResp()):
            run_scan(live_demo=True, offline_mode=False, format_type="json")
            diag_data = json.loads(capsys.readouterr().out)
            assert any("empty remediated_code" in w for w in diag_data["ai_diagnostics"]["warnings"])

    # 5. HTML KPI containment card uses kpi-danger when 0%
    html_vuln = generate_html_report(diag_data)
    assert "kpi-card kpi-danger" in html_vuln
    assert "Security Posture Score" in html_vuln


def test_phase2_followup_graph_resource_policies_notresource_and_tf_bools(tmp_path, capsys):
    # 1. Open S3 Bucket Policy must NOT be hidden when a safe scoped IAM->KMS->S3 path exists
    #    Also test Federated as list, NotResource exclusion, PrincipalAccount condition, and resource-policy Deny
    cg = ContextualGraph()
    w = WorkloadNode(id="k8s:workload:prod:app", name="app", namespace="prod", service_account="sa")
    sa = ServiceAccountNode(id="k8s:sa:prod:sa", name="sa", namespace="prod", role_arn="arn:aws:iam::111122223333:role/r1")
    r = IAMRoleNode(
        id="iam:role:r1",
        name="r1",
        role_arn="arn:aws:iam::111122223333:role/r1",
        trust_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": ["arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/MULTI"]},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"oidc.eks.us-east-1.amazonaws.com/id/MULTI:sub": "system:serviceaccount:prod:sa"}},
            }]
        },
    )
    k_safe = KMSKeyNode(
        id="kms:key:ksafe",
        name="ksafe",
        key_arn="arn:aws:kms:us-east-1:111122223333:key/ksafe",
        properties={
            "policy_statements": [
                {
                    "effect": "Allow",
                    "principal": "*",
                    "actions": ["kms:Decrypt"],
                    "resources": ["*"],
                    "conditions": {"StringEquals": {"aws:PrincipalAccount": "999988887777"}},
                },
                {
                    "effect": "Deny",
                    "principal": {"AWS": "arn:aws:iam::111122223333:role/r1"},
                    "actions": ["kms:Decrypt"],
                    "resources": ["*"],
                },
            ]
        },
    )
    k_other = KMSKeyNode(id="kms:key:kother", name="kother", key_arn="arn:aws:kms:us-east-1:111122223333:key/kother")
    # Allow with NotResource excluding ksafe must NOT link ksafe, only kother
    p_notres = IAMPolicyNode(
        id="iam:policy:notres",
        name="notres",
        statements=[PolicyStatement(effect="Allow", actions=["kms:Decrypt"], not_resources=[k_safe.key_arn])],
    )
    # Safe scoped IAM policy to ksafe + bucket encrypted by ksafe, BUT bucket also has open Principal: {"AWS": ["*"]}!
    p_scoped = IAMPolicyNode(
        id="iam:policy:scoped",
        name="scoped",
        statements=[
            PolicyStatement(
                effect="Allow",
                actions=["kms:Decrypt"],
                resources=[k_safe.key_arn],
                conditions={"StringEquals": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::b-open"}},
            )
        ],
    )
    b_open = S3BucketNode(
        id="s3:bucket:b-open",
        name="b-open",
        bucket_name="b-open",
        bucket_arn="arn:aws:s3:::b-open",
        kms_key_arn=k_safe.key_arn,
        properties={
            "bucket_policy_statements": [
                {"effect": "Allow", "principal": {"AWS": ["arn:aws:iam::111122223333:role/other", "*"]}, "actions": ["s3:GetObject"], "resources": ["*"]}
            ]
        },
    )
    cg.build_from_parsed(
        [w], [sa], [r], [p_scoped, p_notres], [k_safe, k_other], [b_open],
        [{"role": "r1", "policy": "scoped"}, {"role": "r1", "policy": "notres"}],
    )
    assert not cg.graph.has_edge(p_notres.id, k_safe.id)
    assert cg.graph.has_edge(p_notres.id, k_other.id)
    assert not cg.graph.has_edge(r.id, k_safe.id)  # PrincipalAccount excluded & Deny matched!
    assert cg.graph.has_edge(r.id, b_open.id)  # Open S3 Bucket Policy NOT masked by safe path!

    analyzer = AttackPathAnalyzer(cg)
    paths = analyzer.find_cross_layer_attack_paths()
    assert any(ap.nodes[-1]["id"] == b_open.id for ap in paths)
    findings = analyzer.audit_all_misconfigurations(attack_paths=paths)
    assert any(f.id == "SEC-S3-004" for f in findings)

    # 2. Direct KMS & S3 remediation templates generate matching resource types (not fake aws_iam_policy)
    from ai.prompt_templates import build_scoped_kms_policy_hcl
    hcl_s3 = build_scoped_kms_policy_hcl([
        {"id": "w", "name": "app", "type": "WORKLOAD"},
        {"id": "r", "name": "worker_role", "type": "IAM_ROLE", "role_arn": "arn:aws:iam::1:role/worker_role"},
        {"id": "b", "name": "vault", "type": "S3_BUCKET", "bucket_arn": "arn:aws:s3:::vault"},
    ])
    assert 'resource "aws_s3_bucket_policy"' in hcl_s3
    assert "payment_key" not in hcl_s3

    hcl_kms = build_scoped_kms_policy_hcl([
        {"id": "w", "name": "app", "type": "WORKLOAD"},
        {"id": "r", "name": "worker_role", "type": "IAM_ROLE", "role_arn": "arn:aws:iam::1:role/worker_role"},
        {"id": "k", "name": "direct_key", "type": "KMS_KEY", "key_arn": "arn:aws:kms:eu-west-1:1:key/k1"},
    ])
    assert 'resource "aws_kms_key"' in hcl_kms

    # 3. TerraformParser string "false" booleans + parse_warnings without stdout pollution + pod runAsNonRoot: false
    (tmp_path / "broken.tf").write_text("resource { invalid hcl !!!", encoding="utf-8")
    (tmp_path / "strbool.tf").write_text(
        '''
variable "rotate_flag" {
  default = "false"
}
resource "aws_kms_key" "kstr" {
  enable_key_rotation = var.rotate_flag
}
resource "aws_s3_bucket" "bstr" {
  bucket = "bstr"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.bstr.id
  block_public_acls       = "false"
  block_public_policy     = "true"
  ignore_public_acls      = "true"
  restrict_public_buckets = "true"
}
''',
        encoding="utf-8",
    )
    (tmp_path / "pod.yaml").write_text(
        '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rootpod
  namespace: default
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: false
      containers:
        - name: c
          image: alpine
''',
        encoding="utf-8",
    )
    rc = run_scan(target_dir=str(tmp_path), offline_mode=True, format_type="json")
    out_json = json.loads(capsys.readouterr().out)
    assert rc in (0, 1)
    assert len(out_json["parse_warnings"]) >= 1
    f_ids = {f["id"] for f in out_json["misconfigurations"]}
    assert "SEC-KMS-002" in f_ids
    assert "SEC-S3-001" in f_ids
    assert "SEC-K8S-004" in f_ids


def test_phase3_apply_fix_condition_merge_json_data_doc_and_resource_policies(tmp_path):
    # A. Existing Condition block in aws_iam_policy must merge without duplicate Condition key
    d_cond = tmp_path / "existing_cond"
    d_cond.mkdir()
    (d_cond / "k8s.yaml").write_text(
        '''
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa
  namespace: ns
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/r
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: ns
spec:
  template:
    spec:
      serviceAccountName: sa
      containers:
        - name: c
          image: alpine
''',
        encoding="utf-8",
    )
    (d_cond / "main.tf").write_text(
        '''
resource "aws_kms_key" "cmk" {
  enable_key_rotation = true
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bkt.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_iam_policy" "pol" {
  name = "pol"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = "*"
      Condition = {
        StringEquals = {
          "aws:RequestedRegion" = "us-east-1"
        }
      }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "att" {
  role       = aws_iam_role.r.name
  policy_arn = aws_iam_policy.pol.arn
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_cond), offline_mode=True, format_type="json", apply_fix=True) == 1
    patched_tf = (d_cond / "main.tf").read_text(encoding="utf-8")
    assert patched_tf.count("Condition =") == 1
    assert '"aws:RequestedRegion"' in patched_tf
    assert '"kms:EncryptionContext:aws:s3:arn"' in patched_tf
    assert run_scan(target_dir=str(d_cond), offline_mode=True, format_type="json", apply_fix=False) == 0

    # B. Standalone JSON policy patching + data.aws_iam_policy_document patching
    d_json = tmp_path / "json_pol"
    d_json.mkdir()
    j_file = d_json / "kms_policy.json"
    j_file.write_text(
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}],
        }),
        encoding="utf-8",
    )
    from core.models import AttackPath, RemediationResult
    ap_json = AttackPath(
        id="AP-001",
        title="t",
        nodes=[
            {"id": "p", "name": "kms_policy", "type": "IAM_POLICY", "source_file": str(j_file)},
            {"id": "k", "name": "cmk", "type": "KMS_KEY", "key_arn": "arn:aws:kms:eu-west-1:111:key/cmk"},
            {"id": "b", "name": "bkt", "type": "S3_BUCKET", "bucket_arn": "arn:aws:s3:::bkt"},
        ],
        steps=["1"],
        root_cause="rc",
        impact="imp",
    )
    rem_json = RemediationResult(
        attack_path_id="AP-001", original_code="", remediated_code="", explanation="", least_privilege_changes=[], risk_reduction=""
    )
    apply_auto_remediation(str(d_json), rem_json, attack_path=ap_json)
    patched_j = json.loads(j_file.read_text(encoding="utf-8"))
    assert patched_j["Statement"][0]["Resource"] == "arn:aws:kms:eu-west-1:111:key/cmk"
    assert patched_j["Statement"][0]["Condition"]["StringEquals"]["aws:RequestedRegion"] == "us-east-1"
    assert patched_j["Statement"][0]["Condition"]["StringEquals"]["kms:EncryptionContext:aws:s3:arn"] == "arn:aws:s3:::bkt"

    # C. data.aws_iam_policy_document patching
    d_data = tmp_path / "data_doc"
    d_data.mkdir()
    (d_data / "k8s.yaml").write_text((d_cond / "k8s.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    (d_data / "main.tf").write_text(
        '''
resource "aws_kms_key" "cmk" {
  enable_key_rotation = true
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bkt.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
data "aws_iam_policy_document" "doc" {
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "pol" {
  name   = "pol"
  policy = data.aws_iam_policy_document.doc.json
}
resource "aws_iam_role_policy_attachment" "att" {
  role       = aws_iam_role.r.name
  policy_arn = aws_iam_policy.pol.arn
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_data), offline_mode=True, format_type="json", apply_fix=True) == 1
    assert run_scan(target_dir=str(d_data), offline_mode=True, format_type="json", apply_fix=False) == 0


def test_phase3_multi_path_html_and_svg_curves_labels_tooltips():
    scan_data = {
        "target_source": "multi-test",
        "metrics": {
            "total_assets": 4,
            "total_relationships": 3,
            "critical_attack_paths": 2,
            "total_misconfigurations": 2,
            "containment_score": "0%",
            "posture_score": "50%",
            "severity_counts": {"CRITICAL": 2},
        },
        "attack_paths": [
            {"id": "AP-001", "title": "Path 1", "severity": "CRITICAL", "root_cause": "rc1", "impact": "imp1", "steps": ["s1"]},
            {"id": "AP-002", "title": "Path 2", "severity": "HIGH", "root_cause": "rc2", "impact": "imp2", "steps": ["s2"]},
        ],
        "misconfigurations": [],
        "remediation": {"attack_path_id": "AP-001", "remediated_code": "code_1"},
        "remediations": [
            {"attack_path_id": "AP-001", "explanation": "exp 1", "remediated_code": "code_1", "risk_reduction": "99%"},
            {"attack_path_id": "AP-002", "explanation": "exp 2", "remediated_code": "code_2", "risk_reduction": "95%"},
        ],
        "consensus": {
            "red_team": {"agent_name": "R", "attack_vector_en": "v", "blast_radius": "b"},
            "blue_team": {"agent_name": "B", "defense_strategy_en": "d", "status": "s"},
            "arbiter": {"agent_name": "A", "consensus_verdict_en": "c", "cvss_v4_score": 9.8, "cvss_rating": "CRITICAL"},
        },
    }
    html_out = generate_html_report(scan_data)
    assert "Patch for AP-001" in html_out
    assert "Patch for AP-002" in html_out
    assert "code_2" in html_out

    svg = generate_interactive_graph_html({
        "nodes": [
            {"id": "w", "label": "very-long-kubernetes-deployment-name-exceeding-22-chars", "type": "WORKLOAD", "layer": "Kubernetes", "source_file": "k8s.yaml"},
            {"id": "r", "label": "iam-role", "type": "IAM_ROLE", "layer": "IAM", "source_file": "main.tf"},
            {"id": "b", "label": "target-bucket", "type": "S3_BUCKET", "layer": "Storage", "source_file": "main.tf"},
        ],
        "edges": [
            {"source": "w", "target": "r", "type": "IRSA_ASSUMES", "lethal_flaw": False},
            {"source": "r", "target": "b", "type": "RESOURCE_POLICY_ALLOWS", "lethal_flaw": True},
        ],
    })
    assert "<path d=\"M " in svg
    assert "RESOURCE POLICY ALLOWS" in svg
    assert "<title>very-long-kubernetes-deployment-name-exceeding-22-chars" in svg


def test_phase3_json_heredoc_kms_policy_and_s3_bucket_policy_apply_fix(tmp_path):
    base_k8s = '''
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-p3
  namespace: apps
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/r-p3
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-p3
  namespace: apps
spec:
  template:
    spec:
      serviceAccountName: sa-p3
      containers:
        - name: app
          image: python:3.12
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: apps
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
'''
    # (a) JSON heredoc inside aws_iam_policy: <<EOF { ... "Resource": "*" ... } EOF
    d_heredoc = tmp_path / "heredoc_iam"
    d_heredoc.mkdir()
    (d_heredoc / "k8s.yaml").write_text(base_k8s, encoding="utf-8")
    (d_heredoc / "main.tf").write_text(
        '''
resource "aws_kms_key" "cmk" {
  enable_key_rotation = true
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt-p3"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.bkt.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bkt.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}
resource "aws_iam_role" "r_p3" {
  name               = "r-p3"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_iam_policy" "pol_p3" {
  name   = "pol-p3"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "*"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "att" {
  role       = aws_iam_role.r_p3.name
  policy_arn = aws_iam_policy.pol_p3.arn
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_heredoc), offline_mode=True, format_type="json", apply_fix=True) == 1
    assert run_scan(target_dir=str(d_heredoc), offline_mode=True, format_type="json", apply_fix=False) == 0

    # (b) Direct aws_kms_key.policy attack path (no aws_iam_policy, Action = "kms:*")
    d_kms = tmp_path / "direct_kms"
    d_kms.mkdir()
    (d_kms / "k8s.yaml").write_text(base_k8s, encoding="utf-8")
    (d_kms / "main.tf").write_text(
        '''
resource "aws_iam_role" "r_p3" {
  name               = "r-p3"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_kms_key" "cmk" {
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/r-p3" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt-kms-p3"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.bkt.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bkt.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_kms), offline_mode=True, format_type="json", apply_fix=True) == 1
    assert run_scan(target_dir=str(d_kms), offline_mode=True, format_type="json", apply_fix=False) == 0

    # (c) Direct aws_s3_bucket_policy (Principal = "*" HCL + JSON heredoc)
    for variant, pol_expr in [
        ("hcl", 'jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::bkt-s3-p3/*" }] })'),
        ("heredoc", '<<EOF\n{\n  "Version": "2012-10-17",\n  "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bkt-s3-p3/*"}]\n}\nEOF'),
    ]:
        d_s3 = tmp_path / f"direct_s3_{variant}"
        d_s3.mkdir()
        (d_s3 / "k8s.yaml").write_text(base_k8s, encoding="utf-8")
        (d_s3 / "main.tf").write_text(
            f'''
resource "aws_iam_role" "r_p3" {{
  name               = "r-p3"
  assume_role_policy = jsonencode({{ Version = "2012-10-17", Statement = [] }})
}}
resource "aws_s3_bucket" "bkt" {{
  bucket = "bkt-s3-p3"
}}
resource "aws_s3_bucket_public_access_block" "pab" {{
  bucket                  = aws_s3_bucket.bkt.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
resource "aws_s3_bucket_policy" "bkt_pol" {{
  bucket = aws_s3_bucket.bkt.id
  policy = {pol_expr}
}}
''',
            encoding="utf-8",
        )
        assert run_scan(target_dir=str(d_s3), offline_mode=True, format_type="json", apply_fix=True) == 1
        assert run_scan(target_dir=str(d_s3), offline_mode=True, format_type="json", apply_fix=False) == 0


def test_phase3_consensus_total_paths_evaluated():
    consensus = MultiAgentConsensusEngine(offline_mode=True)
    res = consensus.run_consensus_evaluation({
        "id": "AP-001",
        "source_node": "pod-a",
        "destination": "bucket-a",
        "pivot_node": "role-a",
        "nodes": [{"type": "WORKLOAD", "name": "pod-a"}],
        "all_attack_paths": [
            {"id": "AP-001", "title": "Path 1"},
            {"id": "AP-002", "title": "Path 2"},
        ],
    })
    assert res["total_paths_evaluated"] == 2
    assert "(+1 more attack path(s))" in res["red_team"]["attack_vector_en"]


def test_followup_read_original_code_data_doc_nested_cond_and_s3_mixed_principal_roles(tmp_path):
    from core.models import AttackPath

    # 1. _read_original_policy_code should adapt to kms_resource_policy and s3_resource_policy
    ai = AIRemediationEngine(offline_mode=True)
    kms_ap = AttackPath(
        id="AP-KMS",
        title="Direct KMS",
        severity="CRITICAL",
        source_node="pod",
        target_node="bkt",
        nodes=[
            {"type": "WORKLOAD", "name": "pod"},
            {"type": "IAM_ROLE", "name": "worker"},
            {"type": "KMS_KEY", "name": "cmk_direct", "key_arn": "arn:aws:kms:us-east-1:123456789012:key/k1", "source_file": "aws://kms/us-east-1/k1"},
            {"type": "S3_BUCKET", "name": "vault_direct", "bucket_arn": "arn:aws:s3:::vault-direct"},
        ],
        edges=[{"via_resource_policy": True}],
        root_cause="Direct KMS key policy",
        impact="Decrypt",
        steps=["s1"],
    )
    assert 'resource "aws_kms_key"' in ai._read_original_policy_code(kms_ap)

    s3_ap = AttackPath(
        id="AP-S3",
        title="Direct S3",
        severity="CRITICAL",
        source_node="pod",
        target_node="bkt",
        nodes=[
            {"type": "WORKLOAD", "name": "pod"},
            {"type": "IAM_ROLE", "name": "worker"},
            {"type": "S3_BUCKET", "name": "vault_direct", "bucket_arn": "arn:aws:s3:::vault-direct", "source_file": "aws://s3/vault-direct"},
        ],
        edges=[{"type": "RESOURCE_POLICY_ALLOWS", "via_resource_policy": True}],
        root_cause="Direct S3 policy",
        impact="Read",
        steps=["s1"],
    )
    assert 'resource "aws_s3_bucket_policy"' in ai._read_original_policy_code(s3_ap)

    # 2. data.aws_iam_policy_document with an EXISTING condition {} block inside statement {}
    base_k8s = '''
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-f
  namespace: apps
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/target-worker
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-f
  namespace: apps
spec:
  template:
    spec:
      serviceAccountName: sa-f
      containers:
        - name: app
          image: python:3.12
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: apps
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
'''
    d_doc = tmp_path / "data_nested_cond"
    d_doc.mkdir()
    (d_doc / "k8s.yaml").write_text(base_k8s, encoding="utf-8")
    (d_doc / "main.tf").write_text(
        '''
resource "aws_kms_key" "cmk" {
  enable_key_rotation = true
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt-doc"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.bkt.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bkt.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cmk.arn
    }
  }
}
resource "aws_iam_role" "target_worker" {
  name               = "target-worker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
data "aws_iam_policy_document" "doc" {
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["us-east-1"]
    }
  }
}
resource "aws_iam_policy" "pol" {
  name   = "pol"
  policy = data.aws_iam_policy_document.doc.json
}
resource "aws_iam_role_policy_attachment" "att" {
  role       = aws_iam_role.target_worker.name
  policy_arn = aws_iam_policy.pol.arn
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_doc), offline_mode=True, format_type="json", apply_fix=True) == 1
    assert run_scan(target_dir=str(d_doc), offline_mode=True, format_type="json", apply_fix=False) == 0

    # 3. aws_s3_bucket_policy with multiple roles & mixed AWS = ["arn:...", "*"]
    d_mix = tmp_path / "s3_mixed_roles"
    d_mix.mkdir()
    (d_mix / "k8s.yaml").write_text(base_k8s, encoding="utf-8")
    (d_mix / "main.tf").write_text(
        '''
resource "aws_iam_role" "decoy_role" {
  name               = "decoy-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_iam_role" "target_worker" {
  name               = "target-worker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt-mixed"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.bkt.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "bkt_pol" {
  bucket = aws_s3_bucket.bkt.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = ["arn:aws:iam::123456789012:role/decoy-role", "*"] }
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::bkt-mixed/*"
    }]
  })
}
''',
        encoding="utf-8",
    )
    assert run_scan(target_dir=str(d_mix), offline_mode=True, format_type="json", apply_fix=True) == 1
    patched_tf = (d_mix / "main.tf").read_text(encoding="utf-8")
    assert "aws_iam_role.target_worker.arn" in patched_tf
    assert "arn:aws:iam::123456789012:role/decoy-role" in patched_tf
    assert run_scan(target_dir=str(d_mix), offline_mode=True, format_type="json", apply_fix=False) == 0


def test_followup_negated_account_condition_in_resource_policy():
    cg = ContextualGraph()
    r_blocked = IAMRoleNode(id="r1", name="blocked", role_arn="arn:aws:iam::111122223333:role/blocked")
    r_allowed = IAMRoleNode(id="r2", name="allowed", role_arn="arn:aws:iam::999988887777:role/allowed")
    k = KMSKeyNode(
        id="k1",
        name="k1",
        key_arn="arn:aws:kms:us-east-1:123456789012:key/k1",
        properties={
            "policy_statements": [{
                "sid": "ExcludeAcct",
                "effect": "Allow",
                "principal": "*",
                "actions": ["kms:Decrypt"],
                "resources": ["*"],
                "conditions": {"StringNotEquals": {"aws:PrincipalAccount": "111122223333"}},
            }]
        },
    )
    cg.build_from_parsed([], [], [r_blocked, r_allowed], [], [k], [], [])
    assert not cg.graph.has_edge("r1", "k1")
    assert cg.graph.has_edge("r2", "k1")


def test_live_cloud_fetcher_mocked_aws_k8s_and_warnings():
    fetcher = LiveCloudFetcher(quiet=True)

    # Mock boto3 session clients
    iam_mock = MagicMock()
    role_paginator = MagicMock()
    role_paginator.paginate.return_value = [{
        "Roles": [{
            "RoleName": "app-role",
            "Arn": "arn:aws:iam::123456789012:role/app-role",
            "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Federated": ["arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"]}}]},
            "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/Boundary"},
        }]
    }]
    att_paginator = MagicMock()
    att_paginator.paginate.return_value = [{"AttachedPolicies": [{"PolicyName": "GoodPol", "PolicyArn": "arn:aws:iam::123456789012:policy/GoodPol"}, {"PolicyName": "ErrPol", "PolicyArn": "arn:aws:iam::123456789012:policy/ErrPol"}]}]
    inl_paginator = MagicMock()
    inl_paginator.paginate.return_value = [{"PolicyNames": ["inline-notaction"]}]
    iam_mock.get_paginator.side_effect = lambda op: {"list_roles": role_paginator, "list_attached_role_policies": att_paginator, "list_role_policies": inl_paginator}[op]

    def _get_pol(PolicyArn):
        if "ErrPol" in PolicyArn:
            raise RuntimeError("AccessDenied on ErrPol")
        return {"Policy": {"DefaultVersionId": "v1"}}
    iam_mock.get_policy.side_effect = _get_pol
    iam_mock.get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]}}}
    iam_mock.get_role_policy.return_value = {"PolicyDocument": {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:kms:us-east-1:123456789012:key/safe"}]}}

    kms_mock = MagicMock()
    kms_pag = MagicMock()
    kms_pag.paginate.return_value = [{"Keys": [{"KeyId": "k1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/k1"}]}]
    kms_mock.get_paginator.return_value = kms_pag
    kms_mock.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}
    kms_mock.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    kms_mock.list_aliases.return_value = {"Aliases": [{"AliasName": "alias/cmk"}]}
    kms_mock.get_key_policy.side_effect = RuntimeError("KMS GetKeyPolicy denied")

    s3_mock = MagicMock()
    s3_mock.list_buckets.return_value = {"Buckets": [{"Name": "vault-live"}]}
    s3_mock.get_bucket_encryption.side_effect = RuntimeError("No encryption")
    s3_mock.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}}
    s3_mock.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::vault-live/*"}]})}
    s3_mock.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}
    s3_mock.get_bucket_lifecycle_configuration.return_value = {"Rules": [{"ID": "r1"}]}

    sess_mock = MagicMock()
    sess_mock.client.side_effect = lambda svc, **kw: {"iam": iam_mock, "kms": kms_mock, "s3": s3_mock}[svc]
    fetcher.fetch_aws_live_assets(sess_mock, "us-east-1")

    assert len(fetcher.roles) == 1
    assert fetcher.roles[0].properties["permissions_boundary"].endswith("Boundary")
    assert len(fetcher.policies) == 2
    assert any(p.statements and p.statements[0].not_actions for p in fetcher.policies)
    assert fetcher.kms_keys[0].rotation_enabled is False
    assert len(fetcher.s3_buckets[0].properties["bucket_policy_statements"]) == 1
    assert fetcher.s3_buckets[0].properties["has_logging"] is True
    assert fetcher.s3_buckets[0].properties["has_lifecycle"] is True
    assert any("ErrPol" in w for w in fetcher.warnings)
    assert any("GetKeyPolicy denied" in w for w in fetcher.warnings)

    # Mock kubectl JSON fallback for K8s workloads, RBAC ClusterRoleBindings, and NetworkPolicy
    k8s_payloads = {
        "namespaces": {"items": [{"metadata": {"name": "prod"}}]},
        "statefulsets": {"items": [{"metadata": {"name": "sts-app", "namespace": "prod"}, "spec": {"template": {"spec": {"serviceAccountName": "sa-app", "containers": [{"name": "c", "image": "app:1", "securityContext": {"privileged": True}}]}}}}]},
        "sa": {"items": [{"metadata": {"name": "sa-app", "namespace": "prod", "annotations": {"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/app-role"}}}]},
        "clusterrolebindings": {"items": [{"metadata": {"name": "crb"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}]},
        "networkpolicies": {"items": [{"metadata": {"name": "allow-all", "namespace": "prod"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]}}]},
    }
    def _fake_kubectl(cmd, **kw):
        res_name = cmd[2]
        out = k8s_payloads.get(res_name, {"items": []})
        return MagicMock(returncode=0, stdout=json.dumps(out))

    with patch("ingestion.live_cloud_parser.subprocess.run", side_effect=_fake_kubectl):
        fetcher._fetch_k8s_via_kubectl(None, "prod")

    assert any(w.name == "sts-app" for w in fetcher.workloads)
    assert any(s.name == "sa-app" for s in fetcher.service_accounts)
    assert len(fetcher.role_bindings) == 1
    assert fetcher.role_bindings[0]["kind"] == "ClusterRoleBinding"
    assert len(fetcher.network_policies["prod"]) == 1


def test_marginal_notes_ident_sanitization_sibling_kms_and_stmt_scoped_apply_fix(tmp_path):
    from core.models import AttackPath

    # 1. _read_original_policy_code sanitizes alias/ and hyphens AND checks sibling .tf for aws_kms_key
    ai = AIRemediationEngine(offline_mode=True)
    alias_dir = tmp_path / "sibling_kms"
    alias_dir.mkdir()
    alias_tf = alias_dir / "alias_only.tf"
    kms_tf = alias_dir / "kms_key.tf"
    alias_tf.write_text('resource "aws_kms_alias" "a" { name = "alias/payment-cmk" }', encoding="utf-8")
    kms_tf.write_text('resource "aws_kms_key" "cmk" { enable_key_rotation = true }', encoding="utf-8")

    ap_sibling = AttackPath(
        id="AP-SIB",
        title="Sibling KMS",
        severity="CRITICAL",
        source_node="pod",
        target_node="bkt",
        nodes=[
            {"type": "WORKLOAD", "name": "pod"},
            {"type": "IAM_ROLE", "name": "role"},
            {"type": "KMS_KEY", "name": "alias/payment-cmk", "source_file": str(alias_tf)},
            {"type": "S3_BUCKET", "name": "vault-01-prod"},
        ],
        edges=[{"via_resource_policy": True}],
        root_cause="Direct KMS",
        impact="Decrypt",
        steps=["s1"],
    )
    assert "aws_kms_key" in ai._read_original_policy_code(ap_sibling)

    ap_live_alias = AttackPath(
        id="AP-LIVE-IDENT",
        title="Live Ident",
        severity="CRITICAL",
        source_node="pod",
        target_node="bkt",
        nodes=[
            {"type": "WORKLOAD", "name": "pod"},
            {"type": "IAM_ROLE", "name": "role"},
            {"type": "KMS_KEY", "name": "alias/payment-cmk", "source_file": "aws://kms/us-east-1/k1"},
            {"type": "S3_BUCKET", "name": "01-vault-prod"},
        ],
        edges=[{"via_resource_policy": True}],
        root_cause="Direct KMS",
        impact="Decrypt",
        steps=["s1"],
    )
    kms_code = ai._read_original_policy_code(ap_live_alias)
    assert 'resource "aws_kms_key" "payment_cmk"' in kms_code

    ap_live_s3 = AttackPath(
        id="AP-LIVE-S3",
        title="Live S3 Ident",
        severity="CRITICAL",
        source_node="pod",
        target_node="bkt",
        nodes=[
            {"type": "WORKLOAD", "name": "pod"},
            {"type": "IAM_ROLE", "name": "role"},
            {"type": "S3_BUCKET", "name": "01-vault-prod", "source_file": "aws://s3/01-vault-prod"},
        ],
        edges=[{"type": "RESOURCE_POLICY_ALLOWS", "via_resource_policy": True}],
        root_cause="Direct S3",
        impact="Read",
        steps=["s1"],
    )
    s3_code = ai._read_original_policy_code(ap_live_s3)
    assert 'resource "aws_s3_bucket_policy" "r_01_vault_prod_policy"' in s3_code

    # 2. Multi-statement aws_s3_bucket_policy with EXTERNAL role & earlier Condition in Statement[0]
    ext_dir = tmp_path / "ext_role_s3"
    ext_dir.mkdir()
    main_tf = ext_dir / "main.tf"
    main_tf.write_text(
        '''
resource "aws_iam_role" "unrelated_local" {
  name               = "unrelated-local"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_s3_bucket" "bkt" {
  bucket = "bkt-ext"
}
resource "aws_s3_bucket_policy" "pol" {
  bucket = aws_s3_bucket.bkt.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::bkt-ext/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "PublicAllow",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bkt-ext/*"
    }
  ]
}
EOF
}
''',
        encoding="utf-8",
    )
    ext_ap = {
        "nodes": [
            {"type": "IAM_ROLE", "name": "external-reader", "role_arn": "arn:aws:iam::999988887777:role/external-reader"},
            {"type": "S3_BUCKET", "name": "bkt-ext", "bucket_arn": "arn:aws:s3:::bkt-ext", "source_file": str(main_tf)},
        ]
    }
    apply_auto_remediation(str(ext_dir), {"remediated_code": ""}, attack_path=ext_ap)
    res_tf = main_tf.read_text(encoding="utf-8")
    assert "arn:aws:iam::999988887777:role/external-reader" in res_tf
    assert "unrelated_local" not in res_tf.split('"PublicAllow"')[1]
    assert '"aws:PrincipalArn": "arn:aws:iam::999988887777:role/external-reader"' in res_tf.split('"PublicAllow"')[1]
    assert '"aws:PrincipalArn"' not in res_tf.split('"PublicAllow"')[0]

    # 3. Multi-statement JSON heredoc aws_iam_policy where Statement[0] is harmless + has Condition
    iam_dir = tmp_path / "multi_stmt_json_iam"
    iam_dir.mkdir()
    iam_tf = iam_dir / "main.tf"
    iam_tf.write_text(
        '''
resource "aws_kms_key" "cmk" { enable_key_rotation = true }
resource "aws_s3_bucket" "bkt" { bucket = "bkt-iam" }
resource "aws_iam_policy" "pol" {
  name = "pol"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOwn",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:RequestedRegion": "us-east-1"}
      }
    },
    {
      "Sid": "DecryptWildcard",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "*"
    }
  ]
}
EOF
}
''',
        encoding="utf-8",
    )
    iam_ap = {
        "nodes": [
            {"type": "IAM_POLICY", "name": "pol", "source_file": str(iam_tf)},
            {"type": "KMS_KEY", "name": "cmk"},
            {"type": "S3_BUCKET", "name": "bkt"},
        ]
    }
    apply_auto_remediation(str(iam_dir), {"remediated_code": ""}, attack_path=iam_ap)
    iam_out = iam_tf.read_text(encoding="utf-8")
    stmt0, stmt1 = iam_out.split('"DecryptWildcard"')
    assert '"kms:EncryptionContext:aws:s3:arn"' not in stmt0
    assert '"kms:EncryptionContext:aws:s3:arn"' in stmt1
    assert '"Resource": "${aws_kms_key.cmk.arn}"' in stmt1


def test_field_fixes_gitbash_k8s_fast_abort_servicerole_enum_svg_s3_and_samples(tmp_path, capsys):
    import io
    import re
    from core.models import Severity

    # 1. Severity Enum str() on Python 3.14 + HTML badge rendering
    assert str(Severity.CRITICAL) == "CRITICAL"
    html_enum = generate_html_report({
        "target_source": "enum-test",
        "metrics": {"total_assets": 1, "total_relationships": 0, "critical_attack_paths": 1, "total_misconfigurations": 1, "containment_score": "0%", "posture_score": "75%", "severity_counts": {"CRITICAL": 1}},
        "attack_paths": [{"id": "AP-E", "title": "Enum Path", "severity": Severity.CRITICAL, "root_cause": "r", "impact": "i", "steps": ["s1"]}],
        "misconfigurations": [{"id": "SEC-X", "severity": Severity.CRITICAL, "layer": "IAM", "title": "Defect", "resource_id": "res", "compliance_controls": ["CIS"]}],
        "consensus": {"red_team": {}, "blue_team": {}, "arbiter": {"cvss_v4_score": 9.8}},
    })
    assert '<span class="badge badge-danger">CRITICAL SEVERITY</span>' in html_enum
    assert "SEVERITY.CRITICAL" not in html_enum

    # 2. Git Bash PTY _safe_prompt never invokes Prompt.ask/msvcrt when MSYSTEM is set
    fetcher_pty = LiveCloudFetcher(quiet=False)
    fake_stdin = io.StringIO("AKIAFAKE\nSECRETFAKE\nus-west-2\n")
    with patch.dict(os.environ, {"MSYSTEM": "MINGW64"}):
        with patch("ingestion.live_cloud_parser.sys.stdin", fake_stdin):
            with patch("ingestion.live_cloud_parser.Prompt.ask", side_effect=AssertionError("Must not call Prompt.ask in MSYS PTY")):
                ak = fetcher_pty._safe_prompt("AWS Access Key ID")
                sk = fetcher_pty._safe_prompt("AWS Secret Access Key", password=True)
                reg = fetcher_pty._safe_prompt("AWS Region", default="us-east-1")
    assert (ak, sk, reg) == ("AKIAFAKE", "SECRETFAKE", "us-west-2")

    # 3. K8s absent kubeconfig skips without fake 'default' namespace; unreachable kubectl stops after 1 call
    fetcher_nok8s = LiveCloudFetcher(quiet=True)
    with patch.object(LiveCloudFetcher, "_has_k8s_configuration", return_value=False):
        fetcher_nok8s.fetch_k8s_live_assets(None, "default")
    assert fetcher_nok8s.namespaces == []
    assert any("No Kubernetes configuration" in w for w in fetcher_nok8s.warnings)

    fetcher_down = LiveCloudFetcher(quiet=True)
    down_res = MagicMock(returncode=1, stdout="", stderr="Unable to connect to the server: dial tcp 127.0.0.1:8080: connectex: No connection")
    with patch("ingestion.live_cloud_parser.subprocess.run", return_value=down_res) as mock_sub:
        fetcher_down._fetch_k8s_via_kubectl(None, "default")
    assert mock_sub.call_count == 1
    assert fetcher_down.namespaces == []
    assert any("unreachable" in w.lower() for w in fetcher_down.warnings)

    # 4. Client API ServiceAccount failure preserves RBAC & NetworkPolicy discovery
    fetcher_sa_err = LiveCloudFetcher(quiet=True)
    fake_k8s_client = MagicMock()
    fake_k8s_client.CoreV1Api.return_value.list_namespace.return_value.items = [MagicMock(metadata=MagicMock(name="ns1"))]
    # MagicMock(name=...) sets mock name; set metadata.name explicitly
    ns_obj = MagicMock()
    ns_obj.metadata.name = "ns1"
    fake_k8s_client.CoreV1Api.return_value.list_namespace.return_value.items = [ns_obj]
    for list_attr in ("list_deployment_for_all_namespaces", "list_namespaced_deployment", "list_stateful_set_for_all_namespaces", "list_namespaced_stateful_set", "list_daemon_set_for_all_namespaces", "list_namespaced_daemon_set"):
        setattr(fake_k8s_client.AppsV1Api.return_value, list_attr, MagicMock(return_value=MagicMock(items=[])))
    for list_attr in ("list_job_for_all_namespaces", "list_namespaced_job", "list_cron_job_for_all_namespaces", "list_namespaced_cron_job"):
        setattr(fake_k8s_client.BatchV1Api.return_value, list_attr, MagicMock(return_value=MagicMock(items=[])))
    fake_k8s_client.CoreV1Api.return_value.list_pod_for_all_namespaces.return_value.items = []
    fake_k8s_client.CoreV1Api.return_value.list_namespaced_pod.return_value.items = []
    fake_k8s_client.CoreV1Api.return_value.list_service_account_for_all_namespaces.side_effect = RuntimeError("SA Forbidden")
    fake_k8s_client.CoreV1Api.return_value.list_namespaced_service_account.side_effect = RuntimeError("SA Forbidden")
    for rb_attr in ("list_role_for_all_namespaces", "list_namespaced_role", "list_cluster_role", "list_role_binding_for_all_namespaces", "list_namespaced_role_binding", "list_cluster_role_binding"):
        setattr(fake_k8s_client.RbacAuthorizationV1Api.return_value, rb_attr, MagicMock(return_value=MagicMock(items=[])))
    np_item = MagicMock()
    np_item.metadata.name = "deny-all"
    np_item.metadata.namespace = "ns1"
    np_item.spec.pod_selector.match_labels = {}
    np_item.spec.pod_selector.match_expressions = []
    np_item.spec.policy_types = ["Ingress", "Egress"]
    np_item.spec.ingress = None
    np_item.spec.egress = None
    fake_k8s_client.NetworkingV1Api.return_value.list_namespaced_network_policy.return_value.items = [np_item]
    with patch.object(LiveCloudFetcher, "_has_k8s_configuration", return_value=True):
        with patch("ingestion.live_cloud_parser.HAS_K8S_CLIENT", True):
            with patch("ingestion.live_cloud_parser.k8s_client", fake_k8s_client, create=True):
                with patch("ingestion.live_cloud_parser.k8s_config", MagicMock(), create=True):
                    fetcher_sa_err.fetch_k8s_live_assets(None, "ns1")
    assert any("ServiceAccount listing limited" in w for w in fetcher_sa_err.warnings)
    assert "ns1" in fetcher_sa_err.network_policies

    # 5. SEC-IAM-004 ignores AWS Service-Linked Roles
    slr_role = IAMRoleNode(
        id="aws:iam:role:AWSServiceRoleForSupport",
        name="AWSServiceRoleForSupport",
        role_arn="arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
        properties={"path": "/aws-service-role/support.amazonaws.com/"},
    )
    reg_role = IAMRoleNode(id="aws:iam:role:RegularAppRole", name="RegularAppRole", role_arn="arn:aws:iam::123456789012:role/RegularAppRole")
    cg_slr = ContextualGraph()
    cg_slr.build_from_parsed([], [], [slr_role, reg_role], [], [], [], [])
    slr_findings = AttackPathAnalyzer(cg_slr).audit_all_misconfigurations(attack_paths=[])
    iam004_res = {f.resource_id for f in slr_findings if f.id == "SEC-IAM-004"}
    assert "AWSServiceRoleForSupport" not in iam004_res
    assert "RegularAppRole" in iam004_res

    # 6. SEC-S3-004 & ContextualGraph symmetry on non-restrictive Condition (SecureTransport=true) vs PrincipalOrgID
    cg_s3 = ContextualGraph()
    r_s3 = IAMRoleNode(id="r", name="r", role_arn="arn:aws:iam::111122223333:role/r")
    b_tls = S3BucketNode(
        id="b_tls", name="b-tls", bucket_name="b-tls", bucket_arn="arn:aws:s3:::b-tls",
        properties={"bucket_policy_statements": [{"effect": "Allow", "principal": "*", "actions": ["s3:GetObject"], "resources": ["*"], "conditions": {"Bool": {"aws:SecureTransport": "true"}}}]},
    )
    b_org = S3BucketNode(
        id="b_org", name="b-org", bucket_name="b-org", bucket_arn="arn:aws:s3:::b-org",
        properties={"bucket_policy_statements": [{"effect": "Allow", "principal": "*", "actions": ["s3:GetObject"], "resources": ["*"], "conditions": {"StringEquals": {"aws:PrincipalOrgID": "o-12345"}}}]},
    )
    cg_s3.build_from_parsed([], [], [r_s3], [], [], [b_tls, b_org], [])
    assert cg_s3.graph.has_edge("r", "b_tls")
    assert not cg_s3.graph.has_edge("r", "b_org")
    s3_findings = AttackPathAnalyzer(cg_s3).audit_all_misconfigurations(attack_paths=[])
    s3_004_res = {f.resource_id for f in s3_findings if f.id == "SEC-S3-004"}
    assert "b-tls" in s3_004_res and "b-org" not in s3_004_res

    # 7. SVG edge label pills must not collide across column/intra-column edges
    svg_full = generate_interactive_graph_html({
        "nodes": [
            {"id": "w1", "label": "pod", "type": "WORKLOAD", "layer": "Kubernetes"},
            {"id": "sa1", "label": "sa", "type": "SERVICE_ACCOUNT", "layer": "Kubernetes"},
            {"id": "r1", "label": "role", "type": "IAM_ROLE", "layer": "IAM"},
            {"id": "p1", "label": "pol", "type": "IAM_POLICY", "layer": "IAM"},
            {"id": "k1", "label": "cmk", "type": "KMS_KEY", "layer": "Cryptography"},
            {"id": "b1", "label": "bkt", "type": "S3_BUCKET", "layer": "Storage"},
        ],
        "edges": [
            {"source": "w1", "target": "sa1", "type": "USES_SERVICE_ACCOUNT", "lethal_flaw": False},
            {"source": "sa1", "target": "r1", "type": "IRSA_ASSUMES", "lethal_flaw": False},
            {"source": "r1", "target": "p1", "type": "HAS_POLICY", "lethal_flaw": False},
            {"source": "p1", "target": "k1", "type": "ALLOWS_DECRYPT", "lethal_flaw": True},
            {"source": "k1", "target": "b1", "type": "ENCRYPTS_BUCKET", "lethal_flaw": False},
        ],
    })
    pill_boxes = [(float(x), float(y), float(w), float(h)) for x, y, w, h in re.findall(r'<rect x="([^"]+)" y="([^"]+)" width="([^"]+)" height="(15)" rx="4"', svg_full)]
    assert len(pill_boxes) == 5
    for idx_i in range(len(pill_boxes)):
        ax, ay, aw, ah = pill_boxes[idx_i]
        for idx_j in range(idx_i + 1, len(pill_boxes)):
            bx, by, bw, bh = pill_boxes[idx_j]
            assert not ((ax < bx + bw and ax + aw > bx) and (ay < by + bh and ay + ah > by))

    # 8. apply_auto_remediation preserves LF line endings & checks per-statement cond_key & data Deny skip
    lf_dir = tmp_path / "lf_preserve"
    lf_dir.mkdir()
    lf_tf = lf_dir / "main.tf"
    lf_bytes = (
        b'resource "aws_kms_key" "cmk" {\n'
        b'  policy = jsonencode({\n'
        b'    Version = "2012-10-17"\n'
        b'    Statement = [\n'
        b'      {\n'
        b'        Effect = "Allow"\n'
        b'        Principal = { AWS = "arn:aws:iam::111122223333:root" }\n'
        b'        Action = "kms:*"\n'
        b'        Resource = "*"\n'
        b'        Condition = { StringEquals = { "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::other" } }\n'
        b'      },\n'
        b'      {\n'
        b'        Sid = "TargetDecrypt"\n'
        b'        Effect = "Allow"\n'
        b'        Principal = { AWS = "arn:aws:iam::111122223333:role/r" }\n'
        b'        Action = ["kms:Decrypt"]\n'
        b'        Resource = "*"\n'
        b'      }\n'
        b'    ]\n'
        b'  })\n'
        b'}\n'
        b'resource "aws_s3_bucket" "bkt" { bucket = "bkt" }\n'
    )
    lf_tf.write_bytes(lf_bytes)
    apply_auto_remediation(str(lf_dir), {"remediated_code": ""}, attack_path={"nodes": [{"type": "KMS_KEY", "name": "cmk", "source_file": str(lf_tf)}, {"type": "S3_BUCKET", "name": "bkt"}]})
    out_bytes = lf_tf.read_bytes()
    assert b"\r\n" not in out_bytes
    assert b'aws_s3_bucket.bkt.arn' in out_bytes.split(b"TargetDecrypt")[1]

    doc_dir = tmp_path / "doc_deny_skip"
    doc_dir.mkdir()
    doc_tf = doc_dir / "main.tf"
    doc_tf.write_text(
        '''
resource "aws_kms_key" "cmk" { enable_key_rotation = true }
resource "aws_s3_bucket" "bkt" { bucket = "bkt" }
data "aws_iam_policy_document" "doc" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "pol" {
  name   = "pol"
  policy = data.aws_iam_policy_document.doc.json
}
''',
        encoding="utf-8",
    )
    apply_auto_remediation(str(doc_dir), {"remediated_code": ""}, attack_path={"nodes": [{"type": "IAM_POLICY", "name": "pol", "source_file": str(doc_tf)}, {"type": "KMS_KEY", "name": "cmk"}, {"type": "S3_BUCKET", "name": "bkt"}]})
    doc_out = doc_tf.read_text(encoding="utf-8")
    deny_half, allow_half = doc_out.split('effect    = "Allow"')
    assert 'resources = ["*"]' in deny_half
    assert 'resources = [aws_kms_key.cmk.arn]' in allow_half

    # 9. Prompt template no double 'scoped_' prefix + samples consistency + console ':sa:' not turned into emoji
    from ai.prompt_templates import build_scoped_kms_policy_hcl
    scoped_hcl = build_scoped_kms_policy_hcl([
        {"type": "IAM_POLICY", "name": "ScopedPaymentKmsPolicy"},
        {"type": "KMS_KEY", "name": "cmk"},
        {"type": "S3_BUCKET", "name": "bkt"},
    ])
    assert "scoped_scoped" not in scoped_hcl

    rem_dir = os.path.join(ROOT_DIR, "samples", "remediated_baseline")
    capsys.readouterr()
    assert run_scan(target_dir=rem_dir, offline_mode=True, format_type="json", fail_on="critical") == 0
    rem_json = json.loads(capsys.readouterr().out)
    assert any(e.get("type") == "IRSA_ASSUMES" for e in rem_json["graph_summary"]["edges"])

    fraud_dir = os.path.join(ROOT_DIR, "samples", "fraud_detection_ai_engine")
    assert run_scan(target_dir=fraud_dir, offline_mode=True, format_type="console", fail_on="critical") == 1
    console_text = capsys.readouterr().out
    assert "\U0001f202" not in console_text


# --- Env loader hardening -----------------------------------------------------
def test_load_env_secret_dotenv_syntax_and_no_parent_leak(tmp_path, monkeypatch):
    from ai.prompt_templates import load_env_secret

    monkeypatch.delenv("CSPM_TEST_KEY", raising=False)
    (tmp_path / ".env").write_text('# c\nexport CSPM_TEST_KEY = "abc123"  # inline\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert load_env_secret("CSPM_TEST_KEY") == "abc123"

    # real environment variable wins over .env
    monkeypatch.setenv("CSPM_TEST_KEY", "from-env")
    assert load_env_secret("CSPM_TEST_KEY") == "from-env"

    # a .env in a PARENT directory must not be picked up
    monkeypatch.delenv("CSPM_TEST_KEY", raising=False)
    child = tmp_path / "child"
    child.mkdir()
    monkeypatch.chdir(child)
    assert load_env_secret("CSPM_TEST_KEY", "dflt") == "dflt"


# --- Live-mode safety: a failed scan must never be reported as secure ----------
def test_live_mode_fails_closed_on_bad_credentials(monkeypatch):
    import ai_cspm

    class BadSession:
        def client(self, name):
            raise RuntimeError("endpoint unreachable")

    monkeypatch.setattr(ai_cspm, "_resolve_aws_session", lambda f, p, r: (BadSession(), "eu-north-1", False))
    assert ai_cspm.run_scan(live_mode=True, offline_mode=True, format_type="json") == 2


def test_live_mode_uses_env_credentials_without_wizard(monkeypatch):
    import ai_cspm

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKEFAKEFAKEFAKE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x" * 40)

    class Boom:
        def prompt_aws_configuration(self, **kw):
            raise AssertionError("interactive wizard must not run when env credentials exist")

    sess, region, is_demo = ai_cspm._resolve_aws_session(Boom(), None, "eu-north-1")
    assert sess is not None and region == "eu-north-1" and is_demo is False


def test_live_json_stdout_clean_and_gemini_timeout_fallback(tmp_path, monkeypatch, capsys):
    import ai_cspm
    from ai.prompt_templates import load_gemini_config, _parse_dotenv_fallback

    # 0. Fallback .env parser works even if python-dotenv is absent
    env_p = tmp_path / ".env"
    env_p.write_text('# comment\nexport FOO = "bar"  # inline\nBAZ=qux # tail\n', encoding="utf-8")
    assert _parse_dotenv_fallback(str(env_p)) == {"FOO": "bar", "BAZ": "qux"}

    # 1. Invalid GEMINI_TIMEOUT does not crash engine construction
    monkeypatch.setenv("GEMINI_TIMEOUT", "invalid-number")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    model, tout = load_gemini_config()
    assert model == "gemini-2.5-flash" and tout == 25

    # 2. Live mode with -f json keeps stdout strictly parseable JSON (no Authenticated banner)
    class FakeSTS:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:iam::111122223333:user/auditor"}

    class FakeSession:
        def client(self, name, **kw):
            return FakeSTS()

    def fake_aws_fetch(self, sess, region):
        self.roles.append(IAMRoleNode(id="r1", name="AppRole", role_arn="arn:aws:iam::111122223333:role/AppRole"))

    monkeypatch.setattr(ai_cspm, "_resolve_aws_session", lambda f, p, r: (FakeSession(), "eu-north-1", False))
    monkeypatch.setattr(LiveCloudFetcher, "fetch_aws_live_assets", fake_aws_fetch)
    monkeypatch.setattr(LiveCloudFetcher, "fetch_k8s_live_assets", lambda self, context_name=None, namespace="default": None)
    capsys.readouterr()
    rc = ai_cspm.run_scan(live_mode=True, offline_mode=True, format_type="json", fail_on="attack-path")
    assert rc == 0
    captured = capsys.readouterr()
    assert "Authenticated to AWS" not in captured.out
    parsed = json.loads(captured.out)
    assert parsed["metrics"]["total_assets"] == 1


def test_aws_json_snapshot_ingestion_and_cross_layer_scan(tmp_path, capsys):
    import urllib.parse
    import ai_cspm
    from ingestion.aws_json_parser import AwsJsonParser

    k8s_dir = tmp_path / "k8s"
    aws_dir = tmp_path / "aws"
    k8s_dir.mkdir()
    aws_dir.mkdir()

    (k8s_dir / "workloads.yaml").write_text(
        """apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-etl
  namespace: data
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/eks/etl-role
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: etl-worker
  namespace: data
spec:
  template:
    spec:
      serviceAccountName: sa-etl
      containers:
        - name: etl
          image: python:3.12
""",
        encoding="utf-8",
    )

    # Write trust/encryption/policies BEFORE roles/keys/buckets to also verify order independence
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OIDC123"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"oidc.eks.us-east-1.amazonaws.com/id/OIDC123:aud": "sts.amazonaws.com"}},
        }],
    }
    (aws_dir / "01_trust-policies.json").write_text(json.dumps({
        "TrustPolicies": [{
            "RoleName": "etl-role",
            "RoleArn": "arn:aws:iam::123456789012:role/eks/etl-role",
            "AssumeRolePolicyDocument": urllib.parse.quote(json.dumps(trust_doc)),
        }]
    }), encoding="utf-8")

    (aws_dir / "02_encryption.json").write_text(json.dumps({
        "BucketEncryptions": [{
            "Bucket": "pii-vault",
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "key-uuid-1"}}]
            },
        }]
    }), encoding="utf-8")

    (aws_dir / "03_key-policies.json").write_text(json.dumps({
        "KeyPolicies": [{
            "KeyId": "key-uuid-1",
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}],
            }),
        }]
    }), encoding="utf-8")

    (aws_dir / "04_policies.json").write_text(json.dumps({
        "Policies": [{
            "PolicyName": "BroadKmsPol",
            "Arn": "arn:aws:iam::123456789012:policy/BroadKmsPol",
            "DefaultVersionId": "v2",
            "PolicyVersionList": [{
                "VersionId": "v2",
                "IsDefaultVersion": True,
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"}],
                },
            }],
        }]
    }), encoding="utf-8")

    (aws_dir / "05_roles.json").write_text(json.dumps({
        "Roles": [{
            "RoleName": "etl-role",
            "Arn": "arn:aws:iam::123456789012:role/eks/etl-role",
            "AssumeRolePolicyDocument": trust_doc,
            "AttachedManagedPolicies": [{"PolicyName": "BroadKmsPol", "PolicyArn": "arn:aws:iam::123456789012:policy/BroadKmsPol"}],
        }]
    }), encoding="utf-8")

    (aws_dir / "06_keys.json").write_text(json.dumps({
        "Region": "us-east-1",
        "Keys": [
            {"KeyId": "aws-managed-s3", "KeyMetadata": {"KeyManager": "AWS", "Arn": "arn:aws:kms:us-east-1:123456789012:key/aws-managed-s3"}},
            {"KeyId": "key-uuid-1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-uuid-1", "Alias": "alias/pii-cmk", "KeyManager": "CUSTOMER", "KeyRotationEnabled": False},
        ],
    }), encoding="utf-8")

    (aws_dir / "07_buckets.json").write_text(json.dumps({
        "Buckets": [{
            "Name": "pii-vault",
            "Arn": "arn:aws:s3:::pii-vault",
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            "Logging": None,
        }]
    }), encoding="utf-8")

    parser = AwsJsonParser()
    parser.parse_directory(str(tmp_path))
    assert len(parser.roles) == 1
    assert len(parser.policies) == 1
    assert len(parser.kms_keys) == 1  # AWS-managed key skipped
    assert len(parser.s3_buckets) == 1
    assert parser.s3_buckets[0].kms_key_arn == "arn:aws:kms:us-east-1:123456789012:key/key-uuid-1"
    assert parser.s3_buckets[0].properties.get("has_lifecycle") is None

    capsys.readouterr()
    rc = ai_cspm.run_scan(target_dir=str(tmp_path), offline_mode=True, format_type="json", apply_fix=True)
    assert rc == 1
    res = json.loads(capsys.readouterr().out)
    assert res["metrics"]["critical_attack_paths"] == 1
    finding_ids = {m["id"] for m in res["misconfigurations"]}
    assert {"SEC-IAM-001", "SEC-IAM-002", "SEC-KMS-001", "SEC-KMS-002", "SEC-S3-002", "SEC-CROSS-001", "SEC-CROSS-002"} <= finding_ids
    assert "SEC-S3-003" not in finding_ids
    assert '"arn:aws:kms:us-east-1:123456789012:key/key-uuid-1"' in res["remediation"]["remediated_code"]
    assert '"arn:aws:s3:::pii-vault"' in res["remediation"]["remediated_code"]
    # Snapshot policies JSON must not be clobbered by --apply-fix; TF patch is emitted instead
    assert "Policies" in json.loads((aws_dir / "04_policies.json").read_text(encoding="utf-8"))
    assert (tmp_path / "remediated_snapshot_least_privilege.tf").is_file()


def test_explicit_s3_principal_wildcard_enc_ctx_actions_and_consensus_vector():
    from core.models import statement_has_encryption_context
    from ai.prompt_templates import build_scoped_kms_policy_hcl

    # 1. Wildcard EncryptionContext values ('*' or mixed '*') must not pass validation
    assert statement_has_encryption_context(PolicyStatement(
        effect="Allow",
        actions=["kms:Decrypt"],
        resources=["*"],
        conditions={"StringEquals": {"kms:EncryptionContext:aws:s3:arn": "*"}},
    )) is False
    assert statement_has_encryption_context(PolicyStatement(
        effect="Allow",
        actions=["kms:Decrypt"],
        resources=["*"],
        conditions={"StringEquals": {"kms:EncryptionContext:aws:s3:arn": ["arn:aws:s3:::ok", "*"]}},
    )) is False
    assert statement_has_encryption_context(PolicyStatement(
        effect="Allow",
        actions=["kms:Decrypt"],
        resources=["*"],
        conditions={"StringEquals": {"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::ok"}},
    )) is True

    # 2. Explicit IAM Role Principal on S3 Bucket Policy (no wildcard '*') must NOT trigger attack edge
    cg = ContextualGraph()
    r = IAMRoleNode(id="r1", name="pay-role", role_arn="arn:aws:iam::123456789012:role/pay-role")
    b_scoped = S3BucketNode(
        id="b1",
        name="pay-vault",
        bucket_name="pay-vault",
        bucket_arn="arn:aws:s3:::pay-vault",
        properties={
            "bucket_policy_statements": [{
                "effect": "Allow",
                "principal": {"AWS": "arn:aws:iam::123456789012:role/pay-role"},
                "actions": ["s3:GetObject", "s3:PutObject"],
                "resources": ["arn:aws:s3:::pay-vault/*"],
            }]
        },
    )
    cg.build_from_parsed([], [], [r], [], [], [b_scoped], [])
    assert not cg.graph.has_edge("r1", "b1")

    # 3. S3 remediation preserves non-wildcard edge actions & consensus aligns with vector_type
    s3_nodes = [
        {"id": "w", "name": "api", "type": "WORKLOAD"},
        {"id": "sa", "name": "sa", "type": "SERVICE_ACCOUNT"},
        {"id": "r1", "name": "pay-role", "type": "IAM_ROLE", "role_arn": "arn:aws:iam::123456789012:role/pay-role"},
        {"id": "b1", "name": "staging", "type": "S3_BUCKET", "bucket_arn": "arn:aws:s3:::staging", "allowed_actions": ["s3:GetObject", "s3:ListBucket"]},
    ]
    hcl = build_scoped_kms_policy_hcl(s3_nodes)
    assert '["s3:GetObject", "s3:ListBucket"]' in hcl
    assert "NOTE:" in hcl

    consensus = MultiAgentConsensusEngine(offline_mode=True)
    res_s3 = consensus.run_consensus_evaluation({
        "id": "AP-001",
        "title": "S3 exposure",
        "nodes": s3_nodes,
    })
    assert "kms:Decrypt on wildcard '*'" not in res_s3["red_team"]["attack_vector_en"]
    assert "S3 Bucket Policy" in res_s3["red_team"]["attack_vector_en"]

    kms_nodes = [
        {"id": "w", "name": "api", "type": "WORKLOAD"},
        {"id": "sa", "name": "sa", "type": "SERVICE_ACCOUNT"},
        {"id": "r1", "name": "pay-role", "type": "IAM_ROLE", "role_arn": "arn:aws:iam::123456789012:role/pay-role"},
        {"id": "k1", "name": "cmk", "type": "KMS_KEY", "key_arn": "arn:aws:kms:us-east-1:123456789012:key/k1"},
    ]
    res_kms = consensus.run_consensus_evaluation({"id": "AP-002", "title": "KMS key policy", "nodes": kms_nodes})
    assert "KMS Key Resource Policy" in res_kms["red_team"]["attack_vector_en"]


def test_gemini_prompt_grounding_retry_and_post_llm_guardrail():
    from core.models import AttackPath
    from ai.prompt_templates import (
        generate_remediation_user_prompt,
        validate_and_repair_remediated_hcl,
        post_gemini_json,
    )

    s3_nodes = [
        {"id": "w", "name": "payment-api", "type": "WORKLOAD", "source_file": "k8s.yaml"},
        {"id": "sa", "name": "sa-pay", "type": "SERVICE_ACCOUNT", "source_file": "k8s.yaml"},
        {"id": "r", "name": "eks-payment-processor-role", "type": "IAM_ROLE", "role_arn": "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role", "source_file": "roles.json"},
        {"id": "b", "name": "acme-public-assets-staging", "type": "S3_BUCKET", "bucket_name": "acme-public-assets-staging", "bucket_arn": "arn:aws:s3:::acme-public-assets-staging", "source_file": "buckets.json"},
    ]
    prompt = generate_remediation_user_prompt({"id": "AP-001", "nodes": s3_nodes, "steps": ["1. step"]}, "code")
    assert "Attack Vector Type: s3_resource_policy" in prompt
    assert "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role" in prompt
    assert "aws_s3_bucket_policy" in prompt

    # Guardrail rejects hallucinated aws_iam_policy or truncated role ARN for s3_resource_policy
    bad_hcl, repaired_wrong_type = validate_and_repair_remediated_hcl('resource "aws_iam_policy" "fake" {}', s3_nodes)
    assert repaired_wrong_type is True
    assert 'resource "aws_s3_bucket_policy"' in bad_hcl
    assert "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role" in bad_hcl

    bad_role, repaired_trunc_arn = validate_and_repair_remediated_hcl(
        'resource "aws_s3_bucket_policy" "p" { bucket = "acme-public-assets-staging", Principal = "arn:aws:iam::123456789012:role/eks-payment-processor-role" }',
        s3_nodes,
    )
    assert repaired_trunc_arn is True
    assert "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role" in bad_role

    valid_s3 = (
        'resource "aws_s3_bucket_policy" "p" { bucket = "acme-public-assets-staging" '
        'Principal = { AWS = "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role" } }'
    )
    kept_hcl, repaired_valid = validate_and_repair_remediated_hcl(valid_s3, s3_nodes)
    assert repaired_valid is False
    assert kept_hcl == valid_s3

    # Retry on HTTP 503 succeeds on 2nd attempt with temperature=0.0, and AIRemediationEngine applies guardrail
    resp_503 = MagicMock(status_code=503, text="overloaded")
    resp_200 = MagicMock(status_code=200)
    resp_200.json.return_value = {
        "candidates": [{
            "content": {
                "parts": [{
                    "text": json.dumps({
                        "remediated_code": 'resource "aws_iam_policy" "hallucinated_kms" { Resource = "arn:aws:kms:us-east-1:123456789012:key/12345678-fake" }',
                        "explanation": "Grounded explanation from Gemini.",
                        "least_privilege_changes": ["Scoped bucket policy"],
                        "risk_reduction": "99.9%",
                    })
                }]
            }
        }]
    }
    with patch("time.sleep") as mock_sleep:
        with patch("requests.post", side_effect=[resp_503, resp_200]) as mock_post:
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
                engine = AIRemediationEngine(offline_mode=False)
                ap = AttackPath(id="AP-001", title="T", nodes=s3_nodes, steps=["s1"], root_cause="rc", impact="imp")
                rem = engine.synthesize_remediation(ap)
                assert mock_post.call_count == 2
                mock_sleep.assert_called_once()
                sent_payload = mock_post.call_args_list[0].kwargs["json"]
                assert sent_payload["generationConfig"]["temperature"] == 0.0
                assert "Google Gemini Live" in engine.last_provider
                assert rem.explanation == "Grounded explanation from Gemini."
                assert 'resource "aws_s3_bucket_policy"' in rem.remediated_code
                assert "arn:aws:iam::123456789012:role/eks-irsa/eks-payment-processor-role" in rem.remediated_code
                assert any("Guardrail" in c for c in rem.least_privilege_changes)

    # Direct post_gemini_json exhaustion returns clean HTTP 503 error
    with patch("time.sleep"):
        with patch("requests.post", return_value=resp_503):
            parsed, err = post_gemini_json("https://example.invalid", "k", "p", 5, max_attempts=2, backoff_sec=0.1)
            assert parsed is None and "HTTP 503" in err
