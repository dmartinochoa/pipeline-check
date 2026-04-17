"""EB-001 — No EventBridge rule for CodePipeline failure notifications."""
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
        if any("CodePipeline Pipeline Execution State Change" in dt for dt in detail_types):
            states = (doc.get("detail") or {}).get("state") or []
            if isinstance(states, str):
                states = [states]
            if "FAILED" in states:
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
