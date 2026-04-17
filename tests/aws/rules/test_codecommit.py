"""CCM-001..003 — CodeCommit rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.aws.rules import (
    ccm001_approval_rule,
    ccm002_repo_encryption,
    ccm003_trigger_cross_account,
)
from tests.aws.rules.conftest import FakeClient


def _cc_client(repos=None, approval_templates=None, metadata=None, triggers=None):
    client = FakeClient()
    client.set_paginator("list_repositories", [{"repositories": repos or []}])
    client._responses["list_associated_approval_rule_templates_for_repository"] = {
        "approvalRuleTemplateNames": approval_templates or []
    }
    client._responses["get_repository"] = {"repositoryMetadata": metadata or {}}
    client._responses["get_repository_triggers"] = {"triggers": triggers or []}
    return client


def _sts_client(account="123456789012"):
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": account}
    return client


def test_ccm001_no_template_fails(make_catalog):
    cat = make_catalog(codecommit=_cc_client(repos=[{"repositoryName": "r"}]))
    assert ccm001_approval_rule.check(cat)[0].passed is False


def test_ccm001_with_template_passes(make_catalog):
    cat = make_catalog(codecommit=_cc_client(
        repos=[{"repositoryName": "r"}], approval_templates=["PR-Review"],
    ))
    assert ccm001_approval_rule.check(cat)[0].passed is True


def test_ccm002_default_encryption_fails(make_catalog):
    cat = make_catalog(codecommit=_cc_client(
        repos=[{"repositoryName": "r"}],
        metadata={"kmsKeyId": "alias/aws/codecommit"},
    ))
    assert ccm002_repo_encryption.check(cat)[0].passed is False


def test_ccm002_cmk_passes(make_catalog):
    cat = make_catalog(codecommit=_cc_client(
        repos=[{"repositoryName": "r"}],
        metadata={"kmsKeyId": "arn:aws:kms:us-east-1:1:key/abc"},
    ))
    assert ccm002_repo_encryption.check(cat)[0].passed is True


def test_ccm003_same_account_passes(make_catalog):
    triggers = [{"destinationArn": "arn:aws:sns:us-east-1:123456789012:topic"}]
    cat = make_catalog(
        codecommit=_cc_client(repos=[{"repositoryName": "r"}], triggers=triggers),
        sts=_sts_client(),
    )
    assert ccm003_trigger_cross_account.check(cat)[0].passed is True


def test_ccm003_cross_account_fails(make_catalog):
    triggers = [{"destinationArn": "arn:aws:sns:us-east-1:999999999999:topic"}]
    cat = make_catalog(
        codecommit=_cc_client(repos=[{"repositoryName": "r"}], triggers=triggers),
        sts=_sts_client(),
    )
    f = ccm003_trigger_cross_account.check(cat)[0]
    assert f.passed is False
    assert "999999999999" in f.description
