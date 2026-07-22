"""EB-001. No EventBridge rule for CodePipeline failure notifications."""
from __future__ import annotations

import json

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="EB-001",
    title="No EventBridge rule for CodePipeline failure notifications",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Create an EventBridge rule matching "
        "``detail-type: 'CodePipeline Pipeline Execution State Change'`` "
        "and ``state: FAILED``, and point it at an SNS topic or chat "
        "webhook. Without it, pipeline failures during an incident "
        "(a compromise triggering rollback, for example) go unnoticed."
    ),
    docs_note=(
        "Pipeline failure events are emitted to EventBridge "
        "automatically; the missing piece is a rule that pipes them "
        "to somewhere a human reads (SNS, Slack, PagerDuty). "
        "Without it, failures only surface via the CodePipeline "
        "console, which no one watches."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    rules = catalog.eventbridge_rules()
    has_failure_rule = False
    for rule_row in rules:
        pattern = rule_row.get("EventPattern")
        if not pattern:
            continue
        try:
            doc = json.loads(pattern) if isinstance(pattern, str) else pattern
        except (TypeError, json.JSONDecodeError):
            continue
        detail_types = doc.get("detail-type") or []
        if isinstance(detail_types, str):
            detail_types = [detail_types]
        sources = doc.get("source") or []
        if isinstance(sources, str):
            sources = [sources]
        # A pattern covers CodePipeline executions either via the
        # detail-type (``CodePipeline Pipeline Execution State Change``)
        # or a source-only pattern (``source: ["aws.codepipeline"]``).
        covers_pipeline = any(
            "CodePipeline Pipeline Execution State Change" in dt
            for dt in detail_types
        ) or "aws.codepipeline" in sources
        if covers_pipeline:
            states = (doc.get("detail") or {}).get("state") or []
            if isinstance(states, str):
                states = [states]
            # An empty (absent) state filter matches ALL execution states,
            # including FAILED, so it satisfies the coverage requirement.
            if not states or "FAILED" in states:
                has_failure_rule = True
                break
    return [Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="eventbridge",
        description=(
            "At least one EventBridge rule matches CodePipeline FAILED events."
            if has_failure_rule else
            "No EventBridge rule matches CodePipeline FAILED state change."
        ),
        recommendation=RULE.recommendation,
        passed=has_failure_rule,
    )]
