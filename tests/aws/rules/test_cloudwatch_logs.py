"""CWL-001/002 — CodeBuild log group retention and KMS."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import (
    cwl001_codebuild_retention,
    cwl002_codebuild_kms,
)
from tests.aws.rules.conftest import FakeClient


def _logs_client(groups):
    client = FakeClient()
    client.set_paginator("describe_log_groups", [{"logGroups": groups}])
    return client


def test_cwl001_retention_set_passes(make_catalog):
    groups = [{"logGroupName": "/aws/codebuild/foo", "retentionInDays": 30}]
    cat = make_catalog(logs=_logs_client(groups))
    assert cwl001_codebuild_retention.check(cat)[0].passed is True


def test_cwl001_no_retention_fails(make_catalog):
    groups = [{"logGroupName": "/aws/codebuild/foo"}]
    cat = make_catalog(logs=_logs_client(groups))
    assert cwl001_codebuild_retention.check(cat)[0].passed is False


def test_cwl002_kms_passes(make_catalog):
    groups = [{
        "logGroupName": "/aws/codebuild/foo",
        "kmsKeyId": "arn:aws:kms:us-east-1:1:key/abc",
    }]
    cat = make_catalog(logs=_logs_client(groups))
    assert cwl002_codebuild_kms.check(cat)[0].passed is True


def test_cwl002_no_kms_fails(make_catalog):
    groups = [{"logGroupName": "/aws/codebuild/foo"}]
    cat = make_catalog(logs=_logs_client(groups))
    assert cwl002_codebuild_kms.check(cat)[0].passed is False
