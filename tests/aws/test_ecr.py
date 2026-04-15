"""Unit tests for ECR checks."""

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.ecr import ECRChecks
from tests.aws.conftest import make_paginator


def _repo(name="my-repo", scan_on_push=True, mutability="IMMUTABLE", encryption=None):
    repo = {
        "repositoryName": name,
        "repositoryArn": f"arn:aws:ecr:us-east-1:123:{name}",
        "imageScanningConfiguration": {"scanOnPush": scan_on_push},
        "imageTagMutability": mutability,
    }
    if encryption is not None:
        repo["encryptionConfiguration"] = encryption
    return repo


def _client_error(code):
    err = ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")
    return err


def _make_check(repos, policy_error=None, lifecycle_error=None):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"repositories": repos}])
    client.get_paginator.return_value = paginator

    if policy_error:
        client.get_repository_policy.side_effect = _client_error(policy_error)
    else:
        client.get_repository_policy.return_value = {"policyText": "{}"}

    if lifecycle_error:
        client.get_lifecycle_policy.side_effect = _client_error(lifecycle_error)
    else:
        client.get_lifecycle_policy.return_value = {}

    return ECRChecks(session)


class TestECR001ScanOnPush:
    def test_no_scan_fails(self):
        findings = _make_check([_repo(scan_on_push=False)]).run()
        ecr001 = next(f for f in findings if f.check_id == "ECR-001")
        assert not ecr001.passed
        assert ecr001.severity == Severity.HIGH

    def test_scan_enabled_passes(self):
        findings = _make_check([_repo(scan_on_push=True)]).run()
        assert next(f for f in findings if f.check_id == "ECR-001").passed


class TestECR002TagMutability:
    def test_mutable_tags_fail(self):
        findings = _make_check([_repo(mutability="MUTABLE")]).run()
        ecr002 = next(f for f in findings if f.check_id == "ECR-002")
        assert not ecr002.passed
        assert ecr002.severity == Severity.HIGH

    def test_immutable_tags_pass(self):
        findings = _make_check([_repo(mutability="IMMUTABLE")]).run()
        assert next(f for f in findings if f.check_id == "ECR-002").passed


class TestECR003PublicPolicy:
    def test_no_policy_passes(self):
        findings = _make_check([_repo()], policy_error="RepositoryPolicyNotFoundException").run()
        assert next(f for f in findings if f.check_id == "ECR-003").passed

    def test_empty_policy_passes(self):
        findings = _make_check([_repo()]).run()
        assert next(f for f in findings if f.check_id == "ECR-003").passed

    def test_wildcard_principal_fails(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client

        paginator = make_paginator([{"repositories": [_repo()]}])
        client.get_paginator.return_value = paginator
        public_policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:GetDownloadUrlForLayer"}]
        })
        client.get_repository_policy.return_value = {"policyText": public_policy}
        client.get_lifecycle_policy.return_value = {}

        findings = ECRChecks(session).run()
        ecr003 = next(f for f in findings if f.check_id == "ECR-003")
        assert not ecr003.passed
        assert ecr003.severity == Severity.CRITICAL


class TestECR004LifecyclePolicy:
    def test_no_lifecycle_policy_fails(self):
        findings = _make_check([_repo()], lifecycle_error="LifecyclePolicyNotFoundException").run()
        ecr004 = next(f for f in findings if f.check_id == "ECR-004")
        assert not ecr004.passed
        assert ecr004.severity == Severity.LOW

    def test_lifecycle_policy_present_passes(self):
        findings = _make_check([_repo()]).run()
        assert next(f for f in findings if f.check_id == "ECR-004").passed


class TestECR005KmsEncryption:
    def test_aes256_fails(self):
        findings = _make_check([_repo(encryption={"encryptionType": "AES256"})]).run()
        ecr005 = next(f for f in findings if f.check_id == "ECR-005")
        assert not ecr005.passed
        assert ecr005.severity == Severity.MEDIUM

    def test_missing_config_fails(self):
        findings = _make_check([_repo()]).run()
        assert not next(f for f in findings if f.check_id == "ECR-005").passed

    def test_kms_without_key_fails(self):
        findings = _make_check([_repo(encryption={"encryptionType": "KMS"})]).run()
        assert not next(f for f in findings if f.check_id == "ECR-005").passed

    def test_kms_with_cmk_passes(self):
        findings = _make_check([_repo(encryption={
            "encryptionType": "KMS",
            "kmsKey": "arn:aws:kms:us-east-1:123:key/abc",
        })]).run()
        assert next(f for f in findings if f.check_id == "ECR-005").passed


class TestNoRepositories:
    def test_no_repos_returns_empty(self):
        findings = _make_check([]).run()
        assert findings == []


class TestErrorHandling:
    def test_list_repositories_access_denied_returns_ecr000(self):
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        paginator = MagicMock()
        paginator.paginate.side_effect = _client_error("AccessDeniedException")
        client.get_paginator.return_value = paginator

        findings = ECRChecks(session).run()
        assert len(findings) == 1
        assert findings[0].check_id == "ECR-000"
        assert not findings[0].passed

    def test_policy_other_error_fails_ecr003(self):
        """A non-RepositoryPolicyNotFoundException error should produce a failed ECR-003."""
        findings = _make_check([_repo()], policy_error="InternalServerError").run()
        ecr003 = next(f for f in findings if f.check_id == "ECR-003")
        assert not ecr003.passed
