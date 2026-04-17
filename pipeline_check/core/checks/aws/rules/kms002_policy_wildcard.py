"""KMS-002 — KMS key policy grants kms:* with Resource '*' to CI/CD principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..._iam_policy import as_list, iter_allow
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="KMS-002",
    title="KMS key policy grants wildcard KMS actions",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Replace ``kms:*`` grants with specific actions needed by the "
        "caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy "
        "wildcard grants let any holder of the principal re-key, schedule "
        "deletion, or export material at will."
    ),
)


def _wildcard_kms(doc: dict) -> list[str]:
    offenders: list[str] = []
    for stmt in iter_allow(doc):
        actions = as_list(stmt.get("Action"))
        if any(a in ("*", "kms:*") for a in actions if isinstance(a, str)):
            offenders.append(stmt.get("Sid") or "<unsid>")
    return offenders


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("kms")
    for key in catalog.kms_keys():
        key_id = key.get("KeyId")
        arn = key.get("Arn", key_id or "<unknown>")
        try:
            resp = client.get_key_policy(KeyId=key_id, PolicyName="default")
        except ClientError:
            continue
        raw = resp.get("Policy")
        try:
            doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except (TypeError, json.JSONDecodeError):
            continue
        offenders = _wildcard_kms(doc)
        passed = not offenders
        desc = (
            f"Key {arn} policy has no wildcard kms:* grants."
            if passed else
            f"Key {arn} policy grants wildcard KMS actions in statement(s) "
            f"{offenders}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=arn, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
