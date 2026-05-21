"""KMS-002. KMS key policy grants kms:* with Resource '*' to CI/CD principal."""
from __future__ import annotations

import json
from typing import Any

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
    docs_note=(
        "``kms:*`` on a key policy is administrative authority over "
        "the cipher boundary: ``CancelKeyDeletion``, "
        "``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, "
        "and the data-plane decrypt actions all collapse into one "
        "grant. A CI/CD principal almost never needs more than the "
        "data-plane subset (``Decrypt`` / ``GenerateDataKey`` / "
        "``Encrypt``)."
    ),
    exploit_example=(
        "# Vulnerable: a KMS key policy with ``Action: kms:*``\n"
        "# (or ``Action: '*'``) on ``Resource: '*'`` granted to\n"
        "# an IAM principal. The principal can ScheduleKeyDeletion\n"
        "# (effective key destruction in 7 days minimum) and\n"
        "# PutKeyPolicy (rewrite the trust on the key itself).\n"
        "# A compromise of that principal collapses every secret\n"
        "# encrypted with the key.\n"
        "{\n"
        "  \"Effect\": \"Allow\",\n"
        "  \"Principal\": {\"AWS\": \"arn:aws:iam::123:role/CI\"},\n"
        "  \"Action\": \"kms:*\",\n"
        "  \"Resource\": \"*\"\n"
        "}\n"
        "\n"
        "# Safe: enumerate the verbs the workload actually needs\n"
        "# (typically Encrypt / Decrypt / GenerateDataKey for\n"
        "# app workloads; CreateGrant if needed). Key-admin verbs\n"
        "# (PutKeyPolicy, ScheduleKeyDeletion) stay scoped to a\n"
        "# separate, narrowly-bound admin role.\n"
        "{\n"
        "  \"Effect\": \"Allow\",\n"
        "  \"Principal\": {\"AWS\": \"arn:aws:iam::123:role/CI\"},\n"
        "  \"Action\": [\n"
        "    \"kms:Encrypt\",\n"
        "    \"kms:Decrypt\",\n"
        "    \"kms:GenerateDataKey\",\n"
        "    \"kms:DescribeKey\"\n"
        "  ],\n"
        "  \"Resource\": \"*\"\n"
        "}"
    ),
)


def _wildcard_kms(doc: dict[str, Any]) -> list[str]:
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
