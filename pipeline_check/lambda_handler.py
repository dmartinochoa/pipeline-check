"""AWS Lambda entry point.

Environment variables
---------------------
PIPELINEGUARD_RESULTS_BUCKET
    S3 bucket where JSON reports are stored.
    Reports are written to: reports/<timestamp>/pipeline_check-report.json
    If unset, the report is not persisted to S3.

PIPELINEGUARD_SNS_TOPIC_ARN
    SNS topic ARN to notify when CRITICAL findings are detected.
    If unset, no SNS alert is sent.

Event payload (optional)
------------------------
    {
        "region": "eu-west-1"   // overrides AWS_REGION; defaults to us-east-1
    }

Return value
------------
    {
        "statusCode": 200,
        "grade": "B",
        "score": 78,
        "total_findings": 12,
        "critical_failures": 0,
        "report_s3_key": "reports/20240501T120000Z/pipeline_check-report.json"
    }
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3

from .core.reporter import report_json
from .core.scanner import Scanner
from .core.scorer import score

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    region = (
        event.get("region")
        or os.environ.get("AWS_REGION")
        or "us-east-1"
    )
    results_bucket: str | None = os.environ.get("PIPELINEGUARD_RESULTS_BUCKET")
    sns_topic_arn: str | None = os.environ.get("PIPELINEGUARD_SNS_TOPIC_ARN")

    logger.info("Starting PipelineGuard scan in region %s", region)

    # Run scan
    scanner = Scanner(region=region)
    findings = scanner.run()
    score_result = score(findings)

    logger.info(
        "Scan complete: grade=%s score=%s total_findings=%s",
        score_result["grade"],
        score_result["score"],
        len(findings),
    )

    report = report_json(findings, score_result)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"reports/{timestamp}/pipeline_check-report.json"

    # Persist to S3
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
        except Exception:
            logger.exception("Failed to write report to S3")
    else:
        s3_key = None  # type: ignore[assignment]

    # SNS alert on critical failures
    critical_failures = [
        f for f in findings if not f.passed and f.severity.value == "CRITICAL"
    ]

    if sns_topic_arn and critical_failures:
        lines = "\n".join(
            f"  - [{f.check_id}] {f.title}  (resource: {f.resource})"
            for f in critical_failures
        )
        message = (
            f"PipelineGuard detected {len(critical_failures)} CRITICAL finding(s) "
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
                    f"[PipelineGuard] CRITICAL alert -- "
                    f"Grade {score_result['grade']} in {region}"
                ),
                Message=message,
            )
            logger.info("SNS alert sent to %s", sns_topic_arn)
        except Exception:
            logger.exception("Failed to send SNS alert")

    return {
        "statusCode": 200,
        "grade": score_result["grade"],
        "score": score_result["score"],
        "total_findings": len(findings),
        "critical_failures": len(critical_failures),
        "report_s3_key": s3_key,
    }
