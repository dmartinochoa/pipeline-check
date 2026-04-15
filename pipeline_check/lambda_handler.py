"""AWS Lambda entry point.

Wraps the ``Scanner`` + ``score`` + ``report_json`` pipeline so the same
scan logic runs from CLI and Lambda without duplication.

Environment variables
---------------------
PIPELINE_CHECK_RESULTS_BUCKET
    S3 bucket where JSON reports are stored.
    Reports are written to: ``reports/<timestamp>/pipeline_check-report.json``
    If unset, the report is not persisted to S3 and ``report_s3_key`` is
    ``null`` in the return payload.

PIPELINE_CHECK_SNS_TOPIC_ARN
    SNS topic ARN to notify when CRITICAL findings are detected.
    If unset, no SNS alert is sent. When set *and* CRITICAL findings exist,
    one message is published per invocation listing each critical finding
    and linking to the S3 report (if persisted).

Event payload (optional)
------------------------
    {
        "region": "eu-west-1"   // single-region scan (legacy shape)
    }

    // Fan-out shape:
    {
        "regions":   ["us-east-1", "eu-west-1"],
        "providers": ["aws"]         // defaults to ["aws"] if omitted
    }

Return value
------------
    // Single-scan shape (legacy path — one region, one provider):
    {
        "statusCode": 200,
        "grade": "B",
        "score": 78,
        ...
    }

    // Fan-out shape:
    {
        "statusCode": 200,
        "scans": [ {region, provider, grade, score, ...}, ... ],
        "worst_grade": "D",
        "total_critical_failures": 3
    }

Failure handling
----------------
- S3 ``put_object`` failures are logged and ``report_s3_key`` is reset to
  ``null`` so downstream consumers can't reference a key that was never
  written. The function still returns 200 so Lambda does not retry.
- SNS ``publish`` failures are logged but do not affect the return value.
- Any error inside the scan itself propagates — Lambda retry behaviour
  applies per the function's configured event source.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .core.checks.base import Severity
from .core.reporter import report_json
from .core.scanner import Scanner
from .core.scorer import score

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    # Fan-out path: when ``regions`` or ``providers`` is set, run one
    # scan per combination and aggregate. Otherwise fall through to
    # the legacy single-scan shape so existing callers keep working.
    regions_list = event.get("regions")
    providers_list = event.get("providers")
    if isinstance(regions_list, list) or isinstance(providers_list, list):
        return _fan_out(
            regions=regions_list or [
                event.get("region") or os.environ.get("AWS_REGION") or "us-east-1"
            ],
            providers=providers_list or ["aws"],
        )

    region = (
        event.get("region")
        or os.environ.get("AWS_REGION")
        or "us-east-1"
    )
    # ``provider`` on the legacy event defaults to ``aws`` — fan-out
    # sets this when iterating across providers. Forwarding it lets
    # a single handler scan multiple pipeline types per invocation
    # without silently collapsing everything to AWS.
    provider = str(event.get("provider") or "aws").lower()
    provider_kwargs = {
        k: v for k, v in event.items()
        if k in {
            "tf_plan", "gha_path", "gitlab_path",
            "bitbucket_path", "azure_path", "target", "profile",
        }
    }
    results_bucket: str | None = os.environ.get("PIPELINE_CHECK_RESULTS_BUCKET")
    sns_topic_arn: str | None = os.environ.get("PIPELINE_CHECK_SNS_TOPIC_ARN")

    logger.info(
        "Starting PipelineCheck scan: provider=%s region=%s", provider, region
    )

    # Run scan
    scanner = Scanner(pipeline=provider, region=region, **provider_kwargs)
    findings = scanner.run()
    score_result = score(findings)

    logger.info(
        "Scan complete: grade=%s score=%s total_findings=%s",
        score_result["grade"],
        score_result["score"],
        len(findings),
    )

    report = report_json(findings, score_result, tool_version=__version__)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"reports/{timestamp}/pipeline_check-report.json"

    # Persist to S3. ``report_s3_status`` lets downstream consumers
    # distinguish three outcomes that a plain None can't express:
    #   "ok"           — bucket configured, put_object succeeded
    #   "unconfigured" — no PIPELINE_CHECK_RESULTS_BUCKET env var
    #   "error"        — put_object failed; details in CloudWatch logs
    report_s3_status = "unconfigured"
    if results_bucket:
        try:
            s3 = boto3.client("s3", region_name=region)
            s3.put_object(
                Bucket=results_bucket,
                Key=s3_key,
                Body=report.encode(),
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
            logger.info("Report stored at s3://%s/%s", results_bucket, s3_key)
            report_s3_status = "ok"
        except (ClientError, BotoCoreError):
            logger.exception("Failed to write report to S3")
            s3_key = None
            report_s3_status = "error"
    else:
        s3_key = None

    # SNS alert on critical failures
    critical_failures = [
        f for f in findings if not f.passed and f.severity is Severity.CRITICAL
    ]

    if sns_topic_arn and critical_failures:
        lines = "\n".join(
            f"  - [{f.check_id}] {f.title}  (resource: {f.resource})"
            for f in critical_failures
        )
        message = (
            f"PipelineCheck detected {len(critical_failures)} CRITICAL finding(s) "
            f"in region {region}.\n\n"
            f"Grade : {score_result['grade']}\n"
            f"Score : {score_result['score']}/100\n\n"
            f"Critical findings:\n{lines}\n"
        )
        if s3_key and results_bucket:
            message += f"\nFull report: s3://{results_bucket}/{s3_key}\n"

        try:
            sns = boto3.client("sns", region_name=region)
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject=(
                    f"[PipelineCheck] CRITICAL alert -- "
                    f"Grade {score_result['grade']} in {region}"
                ),
                Message=message,
            )
            logger.info("SNS alert sent to %s", sns_topic_arn)
        except (ClientError, BotoCoreError):
            logger.exception("Failed to send SNS alert")

    return {
        "statusCode": 200,
        "grade": score_result["grade"],
        "score": score_result["score"],
        "total_findings": len(findings),
        "critical_failures": len(critical_failures),
        "report_s3_key": s3_key,
        "report_s3_status": report_s3_status,
    }


_GRADE_ORDER = ("A", "B", "C", "D")


def _fan_out(regions: list[str], providers: list[str]) -> dict[str, Any]:
    """Run one scan per (region, provider) pair and aggregate results.

    Each sub-scan calls ``handler`` recursively with a single-region,
    single-provider event so the per-scan reporting (S3 persist, SNS
    alert) stays identical to the legacy code path. Exceptions inside
    one scan produce a per-scan error entry rather than aborting the
    whole invocation.
    """
    scans: list[dict[str, Any]] = []
    worst_grade = "A"
    total_criticals = 0
    for provider in providers:
        for region in regions:
            try:
                result = handler(
                    {"region": region, "provider": provider},
                    None,
                )
            except Exception as exc:
                logger.exception("Fan-out scan failed for %s/%s", provider, region)
                scans.append({
                    "region": region,
                    "provider": provider,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                worst_grade = "D"
                continue
            result["region"] = region
            result["provider"] = provider
            scans.append(result)
            grade = result.get("grade", "D")
            if _GRADE_ORDER.index(grade) > _GRADE_ORDER.index(worst_grade):
                worst_grade = grade
            total_criticals += int(result.get("critical_failures", 0))
    return {
        "statusCode": 200,
        "scans": scans,
        "worst_grade": worst_grade,
        "total_critical_failures": total_criticals,
    }
