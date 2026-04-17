"""LMB-004 — Lambda function resource policy grants wildcard principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from ..._iam_policy import iter_allow, public_principal
from .._catalog import ResourceCatalog

RULE = Rule(
    id="LMB-004",
    title="Lambda resource policy allows wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove Allow statements with ``Principal: '*'`` from every "
        "Lambda function resource policy, or scope them with a "
        "``SourceArn`` / ``SourceAccount`` condition. Service principals "
        "(e.g. ``apigateway.amazonaws.com``) are the common legitimate "
        "case — ensure they carry a condition."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("lambda")
    for fn in catalog.lambda_functions():
        name = fn.get("FunctionName", "<unnamed>")
        try:
            resp = client.get_policy(FunctionName=name)
        except ClientError:
            continue  # no policy = no exposure
        raw = resp.get("Policy")
        if not raw:
            continue
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            continue
        offenders: list[int] = []
        for idx, stmt in enumerate(iter_allow(doc)):
            if not public_principal(stmt):
                continue
            # If the statement has a SourceArn / SourceAccount condition,
            # the wildcard is effectively scoped.
            conditions = stmt.get("Condition", {}) or {}
            scoped = any(
                any(
                    isinstance(key, str) and key.lower() in ("aws:sourcearn", "aws:sourceaccount")
                    for key in (inner or {})
                )
                for inner in conditions.values()
                if isinstance(inner, dict)
            )
            if not scoped:
                offenders.append(idx)
        passed = not offenders
        desc = (
            f"Function '{name}' policy has no unscoped wildcard Allow."
            if passed else
            f"Function '{name}' policy Allow statement(s) {offenders} "
            "grant Principal: '*' without a SourceArn/SourceAccount condition."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
