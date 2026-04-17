"""Unit tests for ECR ECR-001..ECR-005 rule modules."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    ecr001_scan_on_push as ecr001,
    ecr002_tag_mutability as ecr002,
    ecr003_public_policy as ecr003,
    ecr004_lifecycle_policy as ecr004,
    ecr005_kms_encryption as ecr005,
)
from pipeline_check.core.checks.aws.workflows import AWSRuleChecks
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
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


def _catalog(repos, policy_error=None, lifecycle_error=None, policy_text="{}"):
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = make_paginator([{"repositories": repos}])
    client.get_paginator.return_value = paginator

    if policy_error:
        client.get_repository_policy.side_effect = _client_error(policy_error)
    else:
        client.get_repository_policy.return_value = {"policyText": policy_text}

    if lifecycle_error:
        client.get_lifecycle_policy.side_effect = _client_error(lifecycle_error)
    else:
        client.get_lifecycle_policy.return_value = {}

    return ResourceCatalog(session)


class TestECR001ScanOnPush:
    def test_no_scan_fails(self):
        f = ecr001.check(_catalog([_repo(scan_on_push=False)]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_scan_enabled_passes(self):
        assert ecr001.check(_catalog([_repo(scan_on_push=True)]))[0].passed


class TestECR002TagMutability:
    def test_mutable_tags_fail(self):
        f = ecr002.check(_catalog([_repo(mutability="MUTABLE")]))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_immutable_tags_pass(self):
        assert ecr002.check(_catalog([_repo(mutability="IMMUTABLE")]))[0].passed


class TestECR003PublicPolicy:
    def test_no_policy_passes(self):
        cat = _catalog([_repo()], policy_error="RepositoryPolicyNotFoundException")
        assert ecr003.check(cat)[0].passed

    def test_empty_policy_passes(self):
        assert ecr003.check(_catalog([_repo()]))[0].passed

    def test_wildcard_principal_fails(self):
        public_policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:GetDownloadUrlForLayer"}]
        })
        cat = _catalog([_repo()], policy_text=public_policy)
        f = ecr003.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_policy_other_error_fails(self):
        cat = _catalog([_repo()], policy_error="InternalServerError")
        assert not ecr003.check(cat)[0].passed


class TestECR004LifecyclePolicy:
    def test_no_lifecycle_policy_fails(self):
        cat = _catalog([_repo()], lifecycle_error="LifecyclePolicyNotFoundException")
        f = ecr004.check(cat)[0]
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_lifecycle_policy_present_passes(self):
        assert ecr004.check(_catalog([_repo()]))[0].passed


class TestECR005KmsEncryption:
    def test_aes256_fails(self):
        f = ecr005.check(_catalog([_repo(encryption={"encryptionType": "AES256"})]))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_missing_config_fails(self):
        assert not ecr005.check(_catalog([_repo()]))[0].passed

    def test_kms_without_key_fails(self):
        assert not ecr005.check(_catalog([_repo(encryption={"encryptionType": "KMS"})]))[0].passed

    def test_kms_with_cmk_passes(self):
        cat = _catalog([_repo(encryption={
            "encryptionType": "KMS",
            "kmsKey": "arn:aws:kms:us-east-1:123:key/abc",
        })])
        assert ecr005.check(cat)[0].passed


class TestNoRepositories:
    def test_no_repos_returns_empty(self):
        cat = _catalog([])
        for rule in (ecr001, ecr002, ecr005):
            assert rule.check(cat) == []


class TestOrchestratorDegraded:
    def test_list_repositories_access_denied_yields_single_ecr000(self):
        """When ECR enumeration errors, exactly one ``ECR-000`` INFO should be
        emitted regardless of how many ECR rules depend on the catalog."""
        session = MagicMock()
        def _pick(svc, **_):
            if svc == "ecr":
                c = MagicMock()
                p = MagicMock()
                p.paginate.side_effect = _client_error("AccessDeniedException")
                c.get_paginator.return_value = p
                return c
            c = MagicMock()
            empty = MagicMock()
            empty.paginate.return_value = iter([])
            c.get_paginator.return_value = empty
            return c
        session.client.side_effect = _pick

        findings = AWSRuleChecks(session).run()
        ecr_000 = [f for f in findings if f.check_id == "ECR-000"]
        assert len(ecr_000) == 1
        assert not ecr_000[0].passed
        assert not any(
            f.check_id.startswith("ECR-") and f.check_id != "ECR-000"
            for f in findings
        )
