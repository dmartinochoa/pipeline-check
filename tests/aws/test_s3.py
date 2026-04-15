"""Unit tests for S3 checks."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.base import Severity
from pipeline_check.core.checks.aws.s3 import S3Checks
from tests.aws.conftest import make_paginator


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "op")


_SECURE_TRANSPORT_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*",'
    '"Resource":"arn:aws:s3:::b/*","Principal":"*",'
    '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
)


def _make_check(
    buckets=("artifact-bucket",),
    pub_block=None,
    encryption=None,
    versioning_status="Enabled",
    logging_enabled=True,
    bucket_policy=_SECURE_TRANSPORT_POLICY,
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

    # Bucket policy — SecureTransport check
    if bucket_policy is None:
        s3_client.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    else:
        s3_client.get_bucket_policy.return_value = {"Policy": bucket_policy}

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


class TestS3005SecureTransport:
    def test_no_policy_fails(self):
        findings = _make_check(bucket_policy=None).run()
        f = next(x for x in findings if x.check_id == "S3-005")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_deny_on_insecure_passes(self):
        findings = _make_check().run()
        assert next(f for f in findings if f.check_id == "S3-005").passed

    def test_policy_without_secure_transport_deny_fails(self):
        other = '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":"*"}]}'
        findings = _make_check(bucket_policy=other).run()
        assert not next(f for f in findings if f.check_id == "S3-005").passed

    def test_string_equals_condition_recognised(self):
        policy = (
            '{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::b/*",'
            '"Principal":"*","Condition":{"StringEquals":{"aws:SecureTransport":"false"}}}]}'
        )
        findings = _make_check(bucket_policy=policy).run()
        assert next(f for f in findings if f.check_id == "S3-005").passed

    def test_invalid_json_fails(self):
        findings = _make_check(bucket_policy="not json").run()
        assert not next(f for f in findings if f.check_id == "S3-005").passed


class TestNoPipelines:
    def test_no_artifact_buckets_returns_no_findings(self):
        session = MagicMock()
        cp_client = MagicMock()
        cp_paginator = make_paginator([{"pipelines": []}])
        cp_client.get_paginator.return_value = cp_paginator
        session.client.return_value = cp_client
        findings = S3Checks(session).run()
        assert findings == []


class TestApiErrorBranches:
    """Non-recoverable ClientErrors should surface as failed findings."""

    def _check(self, mutator):
        """Build a check with a standard session, then apply `mutator(s3_client)`."""
        check = _make_check()
        # The S3 client was created as the non-codepipeline mock inside _make_check's
        # factory. Re-fetch via the same session.
        s3 = check.session.client("s3")
        mutator(s3)
        return check

    def test_s3001_arbitrary_client_error_fails(self):
        def m(s3):
            s3.get_public_access_block.side_effect = _client_error("AccessDenied")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-001").passed

    def test_s3002_arbitrary_client_error_fails(self):
        def m(s3):
            s3.get_bucket_encryption.side_effect = _client_error("AccessDenied")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-002").passed

    def test_s3003_client_error_fails(self):
        def m(s3):
            s3.get_bucket_versioning.side_effect = _client_error("AccessDenied")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-003").passed

    def test_s3004_client_error_fails(self):
        def m(s3):
            s3.get_bucket_logging.side_effect = _client_error("AccessDenied")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-004").passed

    def test_s3005_arbitrary_error_fails(self):
        def m(s3):
            s3.get_bucket_policy.side_effect = _client_error("AccessDenied")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-005").passed

    def test_s3001_no_public_access_block_config_fails(self):
        def m(s3):
            s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-001").passed

    def test_s3002_missing_encryption_config_fails(self):
        def m(s3):
            s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
        assert not next(f for f in self._check(m).run() if f.check_id == "S3-002").passed
