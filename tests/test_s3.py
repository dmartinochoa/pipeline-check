"""Unit tests for S3 checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipelineguard.core.checks.base import Severity
from pipelineguard.core.checks.s3 import S3Checks
from tests.conftest import make_paginator


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


def _make_check(
    buckets=("artifact-bucket",),
    pub_block=None,
    encryption=None,
    versioning_status="Enabled",
    logging_enabled=True,
):
    session = MagicMock()

    # CodePipeline client (used to discover buckets)
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

    # Public access block
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

    # Encryption
    if encryption is None:
        encryption = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": encryption
    }

    # Versioning
    s3_client.get_bucket_versioning.return_value = {"Status": versioning_status}

    # Logging
    if logging_enabled:
        s3_client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    else:
        s3_client.get_bucket_logging.return_value = {}

    def client_factory(service, **kwargs):
        if service == "codepipeline":
            return cp_client
        return s3_client

    session.client.side_effect = client_factory
    return S3Checks(session)


class TestS3001PublicAccessBlock:
    def test_missing_block_fails(self):
        partial = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        }
        findings = _make_check(pub_block=partial).run()
        s3001 = next(f for f in findings if f.check_id == "S3-001")
        assert not s3001.passed
        assert s3001.severity == Severity.CRITICAL

    def test_all_block_enabled_passes(self):
        findings = _make_check().run()
        assert next(f for f in findings if f.check_id == "S3-001").passed


class TestS3002Encryption:
    def test_no_encryption_fails(self):
        findings = _make_check(encryption={"Rules": []}).run()
        s3002 = next(f for f in findings if f.check_id == "S3-002")
        assert not s3002.passed
        assert s3002.severity == Severity.HIGH

    def test_encryption_configured_passes(self):
        findings = _make_check().run()
        assert next(f for f in findings if f.check_id == "S3-002").passed


class TestS3003Versioning:
    def test_versioning_disabled_fails(self):
        findings = _make_check(versioning_status="Suspended").run()
        s3003 = next(f for f in findings if f.check_id == "S3-003")
        assert not s3003.passed
        assert s3003.severity == Severity.MEDIUM

    def test_versioning_enabled_passes(self):
        findings = _make_check(versioning_status="Enabled").run()
        assert next(f for f in findings if f.check_id == "S3-003").passed


class TestS3004Logging:
    def test_logging_disabled_fails(self):
        findings = _make_check(logging_enabled=False).run()
        s3004 = next(f for f in findings if f.check_id == "S3-004")
        assert not s3004.passed
        assert s3004.severity == Severity.LOW

    def test_logging_enabled_passes(self):
        findings = _make_check(logging_enabled=True).run()
        assert next(f for f in findings if f.check_id == "S3-004").passed


class TestNoPipelines:
    def test_no_artifact_buckets_returns_no_findings(self):
        session = MagicMock()
        cp_client = MagicMock()
        cp_paginator = make_paginator([{"pipelines": []}])
        cp_client.get_paginator.return_value = cp_paginator
        session.client.return_value = cp_client
        findings = S3Checks(session).run()
        assert findings == []
