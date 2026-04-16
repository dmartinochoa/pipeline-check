"""Tests for the AWS Lambda entry point.

The handler composes Scanner + score + report_json + optional S3 upload
+ optional SNS alert. These tests mock the Scanner and boto3 clients
and verify:

- region resolution (event > AWS_REGION env > default)
- return payload shape
- S3 persistence enabled/disabled
- SNS alerting on CRITICAL findings
- Graceful handling of S3 / SNS boto3 errors
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from pipeline_check import lambda_handler as lh
from pipeline_check.core.checks.base import Finding, Severity


def _f(check_id="CB-001", severity=Severity.HIGH, passed=False):
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        resource="r",
        description="d",
        recommendation="rec",
        passed=passed,
    )


def _patch_scanner(findings):
    """Patch Scanner so handler tests don't touch AWS."""
    scanner_inst = MagicMock()
    scanner_inst.run.return_value = findings
    return patch.object(lh, "Scanner", return_value=scanner_inst)


class TestRegionResolution:
    def test_event_region_wins(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        with _patch_scanner([]) as MockScanner:
            lh.handler({"region": "ap-south-1"}, None)
        # First positional kwarg to Scanner() is pipeline; region is keyword.
        args, kwargs = MockScanner.call_args
        assert kwargs.get("region") == "ap-south-1"

    def test_env_region_used_when_event_omits(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        with _patch_scanner([]) as MockScanner:
            lh.handler({}, None)
        assert MockScanner.call_args.kwargs["region"] == "eu-west-1"

    def test_default_region_when_nothing_set(self, monkeypatch):
        monkeypatch.delenv("AWS_REGION", raising=False)
        with _patch_scanner([]) as MockScanner:
            lh.handler({}, None)
        assert MockScanner.call_args.kwargs["region"] == "us-east-1"


class TestReturnPayload:
    def test_basic_shape(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        findings = [_f(severity=Severity.CRITICAL), _f(severity=Severity.HIGH, passed=True)]
        with _patch_scanner(findings):
            result = lh.handler({}, None)
        assert result["statusCode"] == 200
        assert result["grade"] in ("A", "B", "C", "D")
        assert result["total_findings"] == 2
        assert result["critical_failures"] == 1
        assert result["report_s3_key"] is None  # no bucket configured

    def test_no_findings_returns_grade_a(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        with _patch_scanner([]):
            result = lh.handler({}, None)
        assert result["grade"] == "A"
        assert result["total_findings"] == 0
        assert result["critical_failures"] == 0


class TestS3Persistence:
    def test_s3_put_called_when_bucket_configured(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_CHECK_RESULTS_BUCKET", "my-reports")
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        s3 = MagicMock()
        with _patch_scanner([_f()]), patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.return_value = s3
            result = lh.handler({"region": "eu-west-2"}, None)
        # Constructor called with the resolved region — not the default.
        mock_boto3.client.assert_called_once_with("s3", region_name="eu-west-2")
        s3.put_object.assert_called_once()
        kwargs = s3.put_object.call_args.kwargs
        assert kwargs["Bucket"] == "my-reports"
        assert kwargs["Key"].startswith("reports/")
        assert kwargs["Key"].endswith("/pipeline_check-report.json")
        assert kwargs["ServerSideEncryption"] == "AES256"
        # Body should be the JSON report we built.
        body = kwargs["Body"].decode()
        payload = json.loads(body)
        assert "findings" in payload
        assert result["report_s3_key"] == kwargs["Key"]

    def test_s3_put_failure_resets_key_and_returns_200(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_CHECK_RESULTS_BUCKET", "my-reports")
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        s3 = MagicMock()
        s3.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "nope"}},
            "PutObject",
        )
        with _patch_scanner([_f()]), patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.return_value = s3
            result = lh.handler({}, None)
        assert result["statusCode"] == 200
        assert result["report_s3_key"] is None

    def test_s3_skipped_when_bucket_unset(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        with _patch_scanner([_f()]), patch.object(lh, "boto3") as mock_boto3:
            result = lh.handler({}, None)
        mock_boto3.client.assert_not_called()
        assert result["report_s3_key"] is None


class TestSNSAlerts:
    def test_sns_published_on_critical(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.setenv("PIPELINE_CHECK_SNS_TOPIC_ARN",
                           "arn:aws:sns:us-east-1:123:alerts")
        sns = MagicMock()
        with _patch_scanner([_f(severity=Severity.CRITICAL)]), \
             patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.return_value = sns
            lh.handler({"region": "ap-south-1"}, None)
        # Constructor must receive the resolved region.
        mock_boto3.client.assert_called_once_with("sns", region_name="ap-south-1")
        sns.publish.assert_called_once()
        kwargs = sns.publish.call_args.kwargs
        assert kwargs["TopicArn"].endswith(":alerts")
        assert "CRITICAL" in kwargs["Subject"]
        assert "[CB-001]" in kwargs["Message"]

    def test_sns_skipped_when_no_critical(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.setenv("PIPELINE_CHECK_SNS_TOPIC_ARN",
                           "arn:aws:sns:us-east-1:123:alerts")
        with _patch_scanner([_f(severity=Severity.HIGH)]), \
             patch.object(lh, "boto3") as mock_boto3:
            lh.handler({}, None)
        mock_boto3.client.assert_not_called()  # no boto3 calls at all

    def test_sns_skipped_when_arn_unset(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        with _patch_scanner([_f(severity=Severity.CRITICAL)]), \
             patch.object(lh, "boto3") as mock_boto3:
            lh.handler({}, None)
        mock_boto3.client.assert_not_called()

    def test_sns_failure_does_not_affect_return(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.setenv("PIPELINE_CHECK_SNS_TOPIC_ARN",
                           "arn:aws:sns:us-east-1:123:alerts")
        sns = MagicMock()
        sns.publish.side_effect = ClientError(
            {"Error": {"Code": "Throttling", "Message": "slow down"}},
            "Publish",
        )
        with _patch_scanner([_f(severity=Severity.CRITICAL)]), \
             patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.return_value = sns
            result = lh.handler({}, None)
        assert result["statusCode"] == 200

    def test_sns_message_includes_s3_link_when_persisted(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_CHECK_RESULTS_BUCKET", "my-reports")
        monkeypatch.setenv("PIPELINE_CHECK_SNS_TOPIC_ARN",
                           "arn:aws:sns:us-east-1:123:alerts")
        s3 = MagicMock()
        sns = MagicMock()

        def pick_client(name, **_):
            return s3 if name == "s3" else sns

        with _patch_scanner([_f(severity=Severity.CRITICAL)]), \
             patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.side_effect = pick_client
            lh.handler({}, None)

        msg = sns.publish.call_args.kwargs["Message"]
        assert "s3://my-reports/reports/" in msg

    def test_sns_message_omits_s3_link_when_put_object_fails(self, monkeypatch):
        """When S3 write fails, the SNS alert must not reference a key
        that was never written — and ``report_s3_status`` distinguishes
        the failure from the "unconfigured" case."""
        monkeypatch.setenv("PIPELINE_CHECK_RESULTS_BUCKET", "my-reports")
        monkeypatch.setenv("PIPELINE_CHECK_SNS_TOPIC_ARN",
                           "arn:aws:sns:us-east-1:123:alerts")
        s3 = MagicMock()
        s3.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "PutObject"
        )
        sns = MagicMock()

        def pick_client(name, **_):
            return s3 if name == "s3" else sns

        with _patch_scanner([_f(severity=Severity.CRITICAL)]), \
             patch.object(lh, "boto3") as mock_boto3:
            mock_boto3.client.side_effect = pick_client
            result = lh.handler({}, None)

        # SNS is still published, but the S3 link is absent from the message.
        msg = sns.publish.call_args.kwargs["Message"]
        assert "s3://" not in msg
        # Return payload distinguishes 'error' from 'unconfigured'.
        assert result["report_s3_key"] is None
        assert result["report_s3_status"] == "error"

    def test_report_s3_status_unconfigured_when_bucket_env_unset(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
        monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)
        with _patch_scanner([_f()]), patch.object(lh, "boto3"):
            result = lh.handler({}, None)
        assert result["report_s3_key"] is None
        assert result["report_s3_status"] == "unconfigured"
