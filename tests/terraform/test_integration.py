"""End-to-end Terraform integration tests.

Drives a synthetic ``terraform show -json`` plan through the full
Scanner via ``--pipeline terraform`` and asserts every rule from the
runtime AWS provider's Phase 1-3 checks has a parity Terraform rule
that fires (or passes) on the expected resource shape.

Covers the three Terraform extension modules:
  - checks/terraform/extended.py    (CB-008..010, CT-*, CWL-*, SM-*, IAM-008)
  - checks/terraform/services.py    (CA-*, CCM-*, LMB-*, KMS-*, SSM-*)
  - checks/terraform/phase3.py      (ECR-006, PBAC-003/005, CP-005/007, EB-001)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline_check.core.scanner import Scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _r(addr: str, rtype: str, name: str, values: dict) -> dict:
    return {
        "address": addr,
        "mode": "managed",
        "type": rtype,
        "name": name,
        "values": values,
    }


def _plan(resources: list[dict]) -> dict:
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {"resources": resources, "child_modules": []},
        },
    }


@pytest.fixture()
def plan_file(tmp_path: Path):
    """Factory that writes a plan JSON to tmp_path and returns its path."""
    def _write(resources: list[dict]) -> str:
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(_plan(resources)), encoding="utf-8")
        return str(path)
    return _write


def _scan(plan_path: str):
    """Run the full Scanner against *plan_path* using the terraform provider."""
    scanner = Scanner(pipeline="terraform", tf_plan=plan_path)
    return scanner.run()


def _failed_ids(findings) -> set[str]:
    return {f.check_id for f in findings if not f.passed}


def _passed_ids(findings) -> set[str]:
    return {f.check_id for f in findings if f.passed}


# ---------------------------------------------------------------------------
# Fixtures: insecure + secure plan resource lists
# ---------------------------------------------------------------------------

_GH_OIDC_PROVIDER = (
    "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
)

_WILDCARD_POLICY = json.dumps({
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]
})

_SCOPED_POLICY = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111111111111:role/r"},
        "Action": "secretsmanager:GetSecretValue",
    }]
})

_GOOD_OIDC_TRUST = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_PROVIDER},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:corp/*:ref:refs/heads/main"},
        },
    }]
})

_BAD_OIDC_TRUST = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_PROVIDER},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }]
})

_FAILED_PATTERN = json.dumps({
    "detail-type": ["CodePipeline Pipeline Execution State Change"],
    "detail": {"state": ["FAILED"]},
})


def _insecure_plan() -> list[dict]:
    """Every Terraform-mirror rule should fire on this plan."""
    return [
        # CodeBuild — inline buildspec + tag-only image + PR webhook without actor
        _r("aws_codebuild_project.bad", "aws_codebuild_project", "bad", {
            "name": "bad",
            "source": [{"type": "GITHUB", "buildspec": "version: 0.2\nphases:\n  build:\n    commands: echo"}],
            "environment": [{"image": "ghcr.io/corp/builder:latest"}],
        }),
        _r("aws_codebuild_webhook.bad", "aws_codebuild_webhook", "bad", {
            "project_name": "bad",
            "filter_group": [{"filter": [{"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"}]}],
        }),
        # CloudTrail with validation + multi-region both off — satisfies CT-002/003.
        # (CT-001 passes because the trail exists in the plan.)
        _r("aws_cloudtrail.t", "aws_cloudtrail", "t", {
            "enable_log_file_validation": False,
            "is_multi_region_trail": False,
        }),
        # CloudWatch log group with no retention and no KMS.
        _r("aws_cloudwatch_log_group.bad_lg", "aws_cloudwatch_log_group", "bad_lg", {
            "name": "/aws/codebuild/bad",
        }),
        # Secrets Manager — secret without rotation + wildcard policy.
        _r("aws_secretsmanager_secret.s", "aws_secretsmanager_secret", "s", {"name": "prod-db"}),
        _r("aws_secretsmanager_secret_policy.p", "aws_secretsmanager_secret_policy", "p", {
            "policy": _WILDCARD_POLICY,
        }),
        # IAM role with under-scoped OIDC trust.
        _r("aws_iam_role.gh", "aws_iam_role", "gh", {"assume_role_policy": _BAD_OIDC_TRUST}),
        # CodeArtifact
        _r("aws_codeartifact_domain.d", "aws_codeartifact_domain", "d", {"domain": "corp"}),
        _r("aws_codeartifact_repository.r", "aws_codeartifact_repository", "r", {
            "external_connections": ["public:npmjs"],
        }),
        _r("aws_codeartifact_domain_permissions_policy.dp",
           "aws_codeartifact_domain_permissions_policy", "dp",
           {"policy_document": _WILDCARD_POLICY}),
        _r("aws_codeartifact_repository_permissions_policy.rp",
           "aws_codeartifact_repository_permissions_policy", "rp",
           {"policy_document": json.dumps({"Statement": [{
               "Effect": "Allow",
               "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
               "Action": "codeartifact:*",
               "Resource": "*",
           }]})}),
        # CodeCommit — no template attached, AWS-owned KMS.
        _r("aws_codecommit_repository.app", "aws_codecommit_repository", "app", {
            "repository_name": "app",
            "kms_key_id": "alias/aws/codecommit",
        }),
        # Lambda — no signing, public URL, secret env, wildcard permission.
        _r("aws_lambda_function.fn", "aws_lambda_function", "fn", {
            "function_name": "fn",
            "environment": [{"variables": {"DB_PASSWORD": "leaked"}}],
        }),
        _r("aws_lambda_function_url.u", "aws_lambda_function_url", "u", {
            "function_name": "fn",
            "authorization_type": "NONE",
        }),
        _r("aws_lambda_permission.p", "aws_lambda_permission", "p", {
            "principal": "*",
        }),
        # KMS key with rotation off + wildcard action grant.
        _r("aws_kms_key.k", "aws_kms_key", "k", {
            "enable_key_rotation": False,
            "policy": json.dumps({"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/r"},
                "Action": "kms:*",
            }]}),
        }),
        # SSM parameters
        _r("aws_ssm_parameter.pw", "aws_ssm_parameter", "pw", {
            "name": "/app/DB_PASSWORD", "type": "String",
        }),
        _r("aws_ssm_parameter.scd", "aws_ssm_parameter", "scd", {
            "name": "/app/other", "type": "SecureString", "key_id": "alias/aws/ssm",
        }),
        # ECR pull-through cache pointing at Docker Hub.
        _r("aws_ecr_pull_through_cache_rule.d", "aws_ecr_pull_through_cache_rule", "d", {
            "upstream_registry_url": "registry-1.docker.io",
        }),
        # Open SG egress.
        _r("aws_security_group.open", "aws_security_group", "open", {
            "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0,
                         "cidr_blocks": ["0.0.0.0/0"]}],
        }),
        # CodePipeline v2 with shared role + prod deploy + wildcard PR trigger.
        _r("aws_codepipeline.ship", "aws_codepipeline", "ship", {
            "name": "ship",
            "role_arn": "arn:aws:iam::111111111111:role/pipeline",
            "pipeline_type": "V2",
            "trigger": [{
                "provider_type": "CodeStarSourceConnection",
                "git_configuration": [{"pull_request": [{"branches": [{"includes": ["*"]}]}]}],
            }],
            "stage": [
                {"name": "Source", "action": [{"name": "s",
                                                "role_arn": "arn:aws:iam::111111111111:role/pipeline"}]},
                {"name": "DeployProd", "action": [{"name": "d", "category": "Deploy",
                                                     "role_arn": "arn:aws:iam::111111111111:role/pipeline"}]},
            ],
        }),
        # EventBridge rule that does NOT match CodePipeline FAILED
        # (triggers EB-001 because the plan manages event rules but lacks one).
        _r("aws_cloudwatch_event_rule.noise", "aws_cloudwatch_event_rule", "noise", {
            "event_pattern": json.dumps({"detail-type": ["EC2 Instance State-change Notification"]}),
        }),
    ]


def _secure_plan() -> list[dict]:
    """Plan where every extension rule should pass (or skip)."""
    return [
        # CodeBuild with repo-sourced buildspec + digest-pinned image, no webhook.
        _r("aws_codebuild_project.ok", "aws_codebuild_project", "ok", {
            "name": "ok",
            "source": [{"type": "GITHUB", "buildspec": "ci/build.yml"}],
            "environment": [{"image": "ghcr.io/corp/builder@sha256:" + "a" * 64}],
        }),
        _r("aws_cloudtrail.t", "aws_cloudtrail", "t", {
            "enable_log_file_validation": True,
            "is_multi_region_trail": True,
        }),
        _r("aws_cloudwatch_log_group.cb", "aws_cloudwatch_log_group", "cb", {
            "name": "/aws/codebuild/ok",
            "retention_in_days": 30,
            "kms_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc",
        }),
        _r("aws_secretsmanager_secret.s", "aws_secretsmanager_secret", "s", {"name": "prod-db"}),
        _r("aws_secretsmanager_secret_rotation.r",
           "aws_secretsmanager_secret_rotation", "r", {"secret_id": "prod-db"}),
        _r("aws_secretsmanager_secret_policy.p",
           "aws_secretsmanager_secret_policy", "p", {"policy": _SCOPED_POLICY}),
        _r("aws_iam_role.gh", "aws_iam_role", "gh", {"assume_role_policy": _GOOD_OIDC_TRUST}),
        _r("aws_codeartifact_domain.d", "aws_codeartifact_domain", "d", {
            "domain": "corp",
            "encryption_key": "arn:aws:kms:us-east-1:111111111111:key/ca",
        }),
        _r("aws_codecommit_repository.app", "aws_codecommit_repository", "app", {
            "repository_name": "app",
            "kms_key_id": "arn:aws:kms:us-east-1:111111111111:key/cc",
        }),
        _r("aws_codecommit_approval_rule_template_association.a",
           "aws_codecommit_approval_rule_template_association", "a",
           {"repository_name": "app", "approval_rule_template_name": "pr-review"}),
        _r("aws_lambda_function.fn", "aws_lambda_function", "fn", {
            "function_name": "fn",
            "code_signing_config_arn": "arn:aws:lambda:us-east-1:111111111111:code-signing-config:x",
        }),
        _r("aws_kms_key.k", "aws_kms_key", "k", {
            "enable_key_rotation": True,
            "policy": json.dumps({"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/r"},
                "Action": "kms:Decrypt",
            }]}),
        }),
        _r("aws_ssm_parameter.p", "aws_ssm_parameter", "p", {
            "name": "/app/token",
            "type": "SecureString",
            "key_id": "arn:aws:kms:us-east-1:111111111111:key/ssm",
        }),
        _r("aws_ecr_pull_through_cache_rule.k8s", "aws_ecr_pull_through_cache_rule", "k8s", {
            "upstream_registry_url": "registry.k8s.io",
        }),
        _r("aws_security_group.ok", "aws_security_group", "ok", {
            "egress": [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                         "cidr_blocks": ["10.0.0.0/8"]}],
        }),
        _r("aws_codepipeline.ship", "aws_codepipeline", "ship", {
            "name": "ship",
            "role_arn": "arn:aws:iam::111111111111:role/pipeline",
            "pipeline_type": "V2",
            "trigger": [{
                "provider_type": "CodeStarSourceConnection",
                "git_configuration": [{"pull_request": [{"branches": [{"includes": ["main"]}]}]}],
            }],
            "stage": [
                {"name": "Source", "action": [{"name": "s",
                                                "role_arn": "arn:aws:iam::111111111111:role/source"}]},
                {"name": "Approve", "action": [{"name": "a", "category": "Approval",
                                                  "provider": "Manual"}]},
                {"name": "DeployProd", "action": [{"name": "d", "category": "Deploy",
                                                     "role_arn": "arn:aws:iam::111111111111:role/deploy"}]},
            ],
        }),
        _r("aws_cloudwatch_event_rule.pipe_fail", "aws_cloudwatch_event_rule", "pipe_fail", {
            "event_pattern": _FAILED_PATTERN,
        }),
    ]


# ---------------------------------------------------------------------------
# Test: insecure plan — every mirror rule fires
# ---------------------------------------------------------------------------

class TestTerraformInsecurePlan:
    """The insecure plan exercises every Phase 1-3 Terraform-mirror rule."""

    @pytest.fixture()
    def findings(self, plan_file):
        return _scan(plan_file(_insecure_plan()))

    # --- Phase 1 mirrors
    @pytest.mark.parametrize("check_id", [
        "CB-008", "CB-009", "CB-010",
        "CT-002", "CT-003",
        "CWL-001", "CWL-002",
        "SM-001", "SM-002",
        "IAM-008",
    ])
    def test_phase1_mirror_fires(self, findings, check_id):
        assert check_id in _failed_ids(findings), (
            f"{check_id} not in failed set. Failures: "
            f"{sorted(_failed_ids(findings))}"
        )

    # --- Phase 2 mirrors
    @pytest.mark.parametrize("check_id", [
        "CA-001", "CA-002", "CA-003", "CA-004",
        "CCM-001", "CCM-002",
        "LMB-001", "LMB-002", "LMB-003", "LMB-004",
        "KMS-001", "KMS-002",
        "SSM-001", "SSM-002",
    ])
    def test_phase2_mirror_fires(self, findings, check_id):
        assert check_id in _failed_ids(findings), (
            f"{check_id} not in failed set. Failures: "
            f"{sorted(_failed_ids(findings))}"
        )

    # --- Phase 3 mirrors
    @pytest.mark.parametrize("check_id", [
        "ECR-006",
        "PBAC-003", "PBAC-005",
        "CP-005", "CP-007",
        "EB-001",
    ])
    def test_phase3_mirror_fires(self, findings, check_id):
        assert check_id in _failed_ids(findings), (
            f"{check_id} not in failed set. Failures: "
            f"{sorted(_failed_ids(findings))}"
        )

    def test_findings_have_owasp_controls(self, findings):
        """Scanner must annotate every finding with OWASP controls
        (the mirror rules should all have mappings in the registry)."""
        unmapped = [
            f.check_id for f in findings
            if not f.passed and not any(
                c.standard == "owasp_cicd_top_10" for c in f.controls
            )
        ]
        assert not unmapped, f"Terraform findings without OWASP mapping: {unmapped}"


# ---------------------------------------------------------------------------
# Test: secure plan — no mirror rule fails
# ---------------------------------------------------------------------------

class TestTerraformSecurePlan:
    @pytest.fixture()
    def findings(self, plan_file):
        return _scan(plan_file(_secure_plan()))

    def test_no_phase_1_3_rule_fails(self, findings):
        """Every Phase 1-3 rule-ID should either pass or not emit a finding
        for this plan. None should fail."""
        new_rule_prefixes = {
            "CB", "CP", "CT", "CWL", "SM", "IAM",
            "CA", "CCM", "LMB", "KMS", "SSM",
            "ECR", "PBAC", "EB",
        }
        failed = [
            f for f in findings
            if not f.passed and f.check_id.split("-")[0] in new_rule_prefixes
        ]
        # CB-* and IAM-* have class-based legacy checks that may still flag
        # the plan (e.g. CB-001/003/etc). Filter to only the Phase 1-3
        # rule IDs introduced by this expansion.
        new_rule_ids = {
            "CB-008", "CB-009", "CB-010",
            "CT-001", "CT-002", "CT-003",
            "CWL-001", "CWL-002",
            "SM-001", "SM-002",
            "IAM-007", "IAM-008",
            "CA-001", "CA-002", "CA-003", "CA-004",
            "CCM-001", "CCM-002", "CCM-003",
            "LMB-001", "LMB-002", "LMB-003", "LMB-004",
            "KMS-001", "KMS-002",
            "SSM-001", "SSM-002",
            "ECR-006",
            "PBAC-003", "PBAC-005",
            "CP-005", "CP-007",
            "EB-001",
        }
        offenders = [f.check_id for f in failed if f.check_id in new_rule_ids]
        assert not offenders, (
            f"Secure plan tripped Phase 1-3 rules it should not: {offenders}"
        )

    def test_secure_plan_marks_expected_rules_as_passed(self, findings):
        """A few high-signal rules should explicitly emit passing findings
        on the secure plan (not just absent ones). This catches the case
        where a rule silently returns [] for both the passing and failing
        shapes."""
        must_pass = {
            "CB-008", "CB-009",
            "CT-002", "CT-003",
            "SM-001", "SM-002",
            "KMS-001", "KMS-002",
            "CA-001",
            "IAM-008",
        }
        passed = _passed_ids(findings)
        missing = must_pass - passed
        assert not missing, (
            f"Expected these rules to emit passing findings on the secure "
            f"plan but they didn't: {missing}. Passed: {sorted(passed)}"
        )


# ---------------------------------------------------------------------------
# Test: CLI-style check filtering still works
# ---------------------------------------------------------------------------

class TestTerraformCheckFiltering:
    def test_glob_filter_scopes_run(self, plan_file):
        """``--checks 'CT-*'`` should restrict output to CloudTrail findings."""
        findings = Scanner(
            pipeline="terraform", tf_plan=plan_file(_insecure_plan()),
        ).run(checks=["CT-*"])
        ids = {f.check_id for f in findings}
        assert ids, "Filter produced no output"
        assert all(cid.startswith("CT-") for cid in ids), (
            f"Expected only CT-* findings, got: {sorted(ids)}"
        )

    def test_exact_id_filter(self, plan_file):
        findings = Scanner(
            pipeline="terraform", tf_plan=plan_file(_insecure_plan()),
        ).run(checks=["SM-002"])
        ids = {f.check_id for f in findings}
        assert ids == {"SM-002"}, f"Expected exactly SM-002, got: {ids}"
