"""End-to-end integration tests against LocalStack.

These tests create real AWS resources via boto3 (routed to LocalStack by
AWS_ENDPOINT_URL), run the pipeline_check check classes against them, and
assert the scanner produces the expected findings. Every fixture tears down
what it creates, so the tests are safe to run repeatedly.

Coverage here is focused on the check modules that can be exercised without a
full CodePipeline/CodeDeploy chain: IAM, ECR, CodeBuild, and PBAC. The fuller
end-to-end pipeline (all 22+ checks) is still covered by the Terraform-driven
GitHub Actions workflow at .github/workflows/localstack-test.yml.
"""

from __future__ import annotations

import json
from contextlib import suppress

import boto3
import pytest
from botocore.exceptions import ClientError

from pipeline_check.core import providers as _providers
from pipeline_check.core.checks.aws.codebuild import CodeBuildChecks
from pipeline_check.core.checks.aws.ecr import ECRChecks
from pipeline_check.core.checks.aws.iam import IAMChecks
from pipeline_check.core.checks.aws.pbac import PBACChecks
from pipeline_check.core.scanner import Scanner

_CB_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _safe(fn, *args, **kwargs):
    """Call a teardown function, swallowing ClientError so cleanup continues."""
    with suppress(ClientError):
        fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# IAM integration
# ---------------------------------------------------------------------------

class TestIAMIntegration:
    @pytest.fixture(scope="class")
    def secure_role(self, ls_session: boto3.Session, run_id: str):
        iam = ls_session.client("iam")
        boundary_name = f"pc-boundary-{run_id}"
        role_name = f"pc-cb-secure-{run_id}"
        boundary = None

        try:
            boundary = iam.create_policy(
                PolicyName=boundary_name,
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "logs:*"],
                        "Resource": "*",
                    }],
                }),
            )["Policy"]["Arn"]

            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(_CB_TRUST),
                PermissionsBoundary=boundary,
            )
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="ScopedInline",
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }],
                }),
            )

            yield role_name
        finally:
            _safe(iam.delete_role_policy, RoleName=role_name, PolicyName="ScopedInline")
            _safe(iam.delete_role, RoleName=role_name)
            if boundary:
                _safe(iam.delete_policy, PolicyArn=boundary)

    def _findings_for(self, ls_session, role_name):
        all_findings = IAMChecks(ls_session).run()
        return [f for f in all_findings if f.resource == role_name]

    def test_secure_role_passes_iam001_and_iam002(self, ls_session, secure_role):
        findings = self._findings_for(ls_session, secure_role)
        by_id = {f.check_id: f for f in findings}
        # IAM-001: no AdministratorAccess attached
        assert by_id["IAM-001"].passed
        # IAM-002: no wildcard Action in inline policy
        assert by_id["IAM-002"].passed
        # IAM-003 is intentionally not asserted here: LocalStack's list_roles
        # pagination does not reliably echo PermissionsBoundary back, which
        # causes false negatives. The Terraform-based GH Actions workflow
        # covers IAM-003 end-to-end instead.

    def test_insecure_role_fails_iam002(self, ls_session, insecure_role):
        findings = self._findings_for(ls_session, insecure_role)
        by_id = {f.check_id: f for f in findings}
        assert not by_id["IAM-002"].passed
        # See note above: IAM-003 is not asserted against LocalStack.


# ---------------------------------------------------------------------------
# ECR integration
# ---------------------------------------------------------------------------

class TestECRIntegration:
    @pytest.fixture(scope="class")
    def secure_repo(self, ls_session: boto3.Session, run_id: str):
        ecr = ls_session.client("ecr")
        name = f"pc-secure-{run_id}"
        try:
            ecr.create_repository(
                repositoryName=name,
                imageTagMutability="IMMUTABLE",
                imageScanningConfiguration={"scanOnPush": True},
            )
            ecr.put_lifecycle_policy(
                repositoryName=name,
                lifecyclePolicyText=json.dumps({
                    "rules": [{
                        "rulePriority": 1,
                        "selection": {
                            "tagStatus": "untagged",
                            "countType": "sinceImagePushed",
                            "countUnit": "days",
                            "countNumber": 7,
                        },
                        "action": {"type": "expire"},
                    }],
                }),
            )
            yield name
        finally:
            _safe(ecr.delete_repository, repositoryName=name, force=True)

    def _findings_for(self, ls_session, repo_name):
        all_findings = ECRChecks(ls_session).run()
        return [f for f in all_findings if f.resource == repo_name]

    def test_secure_repo_passes_scan_mutability_lifecycle(self, ls_session, secure_repo):
        by_id = {f.check_id: f for f in self._findings_for(ls_session, secure_repo)}
        assert by_id["ECR-001"].passed
        assert by_id["ECR-002"].passed
        assert by_id["ECR-004"].passed

    def test_insecure_repo_fails_scan_mutability_lifecycle(self, ls_session, insecure_repo):
        by_id = {f.check_id: f for f in self._findings_for(ls_session, insecure_repo)}
        assert not by_id["ECR-001"].passed
        assert not by_id["ECR-002"].passed
        assert not by_id["ECR-004"].passed


# ---------------------------------------------------------------------------
# CodeBuild + PBAC integration
# ---------------------------------------------------------------------------

class TestCodeBuildAndPBACIntegration:
    def test_codebuild_bad_project_fails_expected_checks(
        self, ls_session, bad_project, shared_role_project,
    ):
        findings = CodeBuildChecks(ls_session).run()
        by_id = {
            f.check_id: f for f in findings if f.resource == bad_project
        }
        assert not by_id["CB-001"].passed, "plaintext secret should fail CB-001"
        assert not by_id["CB-002"].passed, "privileged mode should fail CB-002"
        assert not by_id["CB-003"].passed, "logging disabled should fail CB-003"
        assert not by_id["CB-004"].passed, "max timeout should fail CB-004"
        assert not by_id["CB-005"].passed, "outdated image should fail CB-005"

    def test_pbac001_detects_missing_vpc(
        self, ls_session, bad_project, shared_role_project,
    ):
        findings = PBACChecks(ls_session).run()
        pbac001 = {f.resource: f for f in findings if f.check_id == "PBAC-001"}
        assert bad_project in pbac001
        assert not pbac001[bad_project].passed

    def test_pbac002_detects_shared_service_role(
        self, ls_session, bad_project, shared_role_project,
    ):
        findings = PBACChecks(ls_session).run()
        pbac002 = {f.resource: f for f in findings if f.check_id == "PBAC-002"}
        assert not pbac002[bad_project].passed
        assert not pbac002[shared_role_project].passed
        assert bad_project in pbac002[shared_role_project].description \
            or shared_role_project in pbac002[bad_project].description


# ---------------------------------------------------------------------------
# End-to-end Scanner orchestration
# ---------------------------------------------------------------------------

class TestScannerEndToEnd:
    """Exercises the full Scanner.run() orchestration, provider wiring, and
    report assembly — not just individual check classes.
    """

    def _make_scanner(self, ls_session: boto3.Session) -> Scanner:
        """Inject the pre-built LocalStack session into a Scanner without
        touching boto3's default credential chain."""
        scanner = Scanner.__new__(Scanner)
        scanner.pipeline = "aws"
        scanner._context = ls_session
        scanner._check_classes = _providers.get("aws").check_classes
        return scanner

    def test_scanner_produces_findings_across_all_check_prefixes(
        self, ls_session, bad_project, shared_role_project, insecure_repo, insecure_role,
    ):
        """Run the full orchestration — every wired check class should contribute."""
        findings = self._make_scanner(ls_session).run()
        prefixes = {f.check_id.split("-")[0] for f in findings}
        # Services that exercise resources we created in other fixtures.
        # CP/CD/S3 may or may not appear depending on unrelated state in
        # LocalStack, so we only require that the services we actively set
        # up are present.
        assert {"CB", "ECR", "IAM", "PBAC"} <= prefixes, (
            f"Expected CB/ECR/IAM/PBAC in prefixes, got: {sorted(prefixes)}"
        )

    def test_scanner_detects_our_bad_codebuild_project(
        self, ls_session, bad_project, shared_role_project,
    ):
        findings = self._make_scanner(ls_session).run()
        failed_for_bad = {
            f.check_id for f in findings
            if f.resource == bad_project and not f.passed
        }
        # Every CodeBuild misconfiguration plus PBAC-001/002 should surface.
        assert {
            "CB-001", "CB-002", "CB-003", "CB-004", "CB-005",
            "PBAC-001", "PBAC-002",
        } <= failed_for_bad, f"Missing expected failures: {failed_for_bad}"

    def test_scanner_check_filter_works(
        self, ls_session, bad_project, shared_role_project,
    ):
        """Scanner.run(checks=...) should only return findings for the allowlist."""
        findings = self._make_scanner(ls_session).run(checks=["CB-001", "PBAC-001"])
        ids = {f.check_id for f in findings}
        assert ids <= {"CB-001", "PBAC-001"}
        assert ids, "Expected at least one finding for the allowlisted checks"
