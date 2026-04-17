"""Unit tests for S3 S3-001..S3-005 rule modules."""
from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.rules import (
    s3001_public_access_block as s3001,
    s3002_encryption as s3002,
    s3003_versioning as s3003,
    s3004_access_logging as s3004,
    s3005_secure_transport as s3005,
)
from tests.aws.conftest import make_paginator


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


_SECURE_TRANSPORT_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*",'
    '"Resource":"arn:aws:s3:::b/*","Principal":"*",'
    '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
)


def _catalog(
    buckets=("artifact-bucket",),
    pub_block=None,
    encryption=None,
    versioning_status="Enabled",
    logging_enabled=True,
    bucket_policy=_SECURE_TRANSPORT_POLICY,
    s3_mutator=None,
):
    session = MagicMock()

    # CodePipeline client — used by catalog.codepipeline_pipelines() to
    # populate s3_artifact_buckets().
    cp_client = MagicMock()
    cp_paginator = make_paginator([{"pipelines": [{"name": "my-pipe"}]}])
    cp_client.get_paginator.return_value = cp_paginator
    cp_client.get_pipeline.return_value = {
        "pipeline": {
            "name": "my-pipe",
            "stages": [],
            "artifactStore": {"type": "S3", "location": buckets[0]},
        }
    }

    # S3 client
    s3_client = MagicMock()

    if pub_block is None:
        pub_block = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": pub_block
    }

    if encryption is None:
        encryption = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": encryption
    }

    s3_client.get_bucket_versioning.return_value = {"Status": versioning_status}

    if logging_enabled:
        s3_client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    else:
        s3_client.get_bucket_logging.return_value = {}

    if bucket_policy is None:
        s3_client.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    else:
        s3_client.get_bucket_policy.return_value = {"Policy": bucket_policy}

    if s3_mutator is not None:
        s3_mutator(s3_client)

    def client_factory(service, **kwargs):
        if service == "codepipeline":
            return cp_client
        return s3_client

    session.client.side_effect = client_factory
    return ResourceCatalog(session)


class TestS3001PublicAccessBlock:
    def test_missing_block_fails(self):
        partial = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        }
        f = s3001.check(_catalog(pub_block=partial))[0]
        assert not f.passed
        assert f.severity == Severity.CRITICAL

    def test_all_block_enabled_passes(self):
        assert s3001.check(_catalog())[0].passed


class TestS3002Encryption:
    def test_no_encryption_fails(self):
        f = s3002.check(_catalog(encryption={"Rules": []}))[0]
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_encryption_configured_passes(self):
        assert s3002.check(_catalog())[0].passed


class TestS3003Versioning:
    def test_versioning_disabled_fails(self):
        f = s3003.check(_catalog(versioning_status="Suspended"))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_versioning_enabled_passes(self):
        assert s3003.check(_catalog(versioning_status="Enabled"))[0].passed


class TestS3004Logging:
    def test_logging_disabled_fails(self):
        f = s3004.check(_catalog(logging_enabled=False))[0]
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_logging_enabled_passes(self):
        assert s3004.check(_catalog(logging_enabled=True))[0].passed


class TestS3005SecureTransport:
    def test_no_policy_fails(self):
        f = s3005.check(_catalog(bucket_policy=None))[0]
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_deny_on_insecure_passes(self):
        assert s3005.check(_catalog())[0].passed

    def test_policy_without_secure_transport_deny_fails(self):
        other = '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":"*"}]}'
        assert not s3005.check(_catalog(bucket_policy=other))[0].passed

    def test_string_equals_condition_recognised(self):
        policy = (
            '{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::b/*",'
            '"Principal":"*","Condition":{"StringEquals":{"aws:SecureTransport":"false"}}}]}'
        )
        assert s3005.check(_catalog(bucket_policy=policy))[0].passed

    def test_invalid_json_fails(self):
        assert not s3005.check(_catalog(bucket_policy="not json"))[0].passed


class TestNoPipelines:
    def test_no_artifact_buckets_returns_no_findings(self):
        session = MagicMock()
        cp_client = MagicMock()
        cp_paginator = make_paginator([{"pipelines": []}])
        cp_client.get_paginator.return_value = cp_paginator
        session.client.return_value = cp_client
        catalog = ResourceCatalog(session)
        for rule in (s3001, s3002, s3003, s3004, s3005):
            assert rule.check(catalog) == []


class TestApiErrorBranches:
    """Non-recoverable ClientErrors should surface as failed findings."""

    def test_s3001_arbitrary_client_error_fails(self):
        def m(s3):
            s3.get_public_access_block.side_effect = _client_error("AccessDenied")
        assert not s3001.check(_catalog(s3_mutator=m))[0].passed

    def test_s3002_arbitrary_client_error_fails(self):
        def m(s3):
            s3.get_bucket_encryption.side_effect = _client_error("AccessDenied")
        assert not s3002.check(_catalog(s3_mutator=m))[0].passed

    def test_s3003_client_error_fails(self):
        def m(s3):
            s3.get_bucket_versioning.side_effect = _client_error("AccessDenied")
        assert not s3003.check(_catalog(s3_mutator=m))[0].passed

    def test_s3004_client_error_fails(self):
        def m(s3):
            s3.get_bucket_logging.side_effect = _client_error("AccessDenied")
        assert not s3004.check(_catalog(s3_mutator=m))[0].passed

    def test_s3005_arbitrary_error_fails(self):
        def m(s3):
            s3.get_bucket_policy.side_effect = _client_error("AccessDenied")
        assert not s3005.check(_catalog(s3_mutator=m))[0].passed

    def test_s3001_no_public_access_block_config_fails(self):
        def m(s3):
            s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
        assert not s3001.check(_catalog(s3_mutator=m))[0].passed

    def test_s3002_missing_encryption_config_fails(self):
        def m(s3):
            s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        assert not s3002.check(_catalog(s3_mutator=m))[0].passed
