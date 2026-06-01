"""IAM-005. CI/CD role trust allows external AWS principal w/o sts:ExternalId."""
from __future__ import annotations

import json
import re

from ..._iam_policy import iter_allow
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

# Account id (12 digits) from any-partition ARN: aws / aws-cn / aws-us-gov.
_ARN_ACCOUNT_RE = re.compile(r"arn:aws[a-z-]*:[^:]*:[^:]*:(\d{12}):")


def _account_of(arn: object) -> str | None:
    if not isinstance(arn, str):
        return None
    m = _ARN_ACCOUNT_RE.search(arn)
    return m.group(1) if m else None

RULE = Rule(
    id="IAM-005",
    title="CI/CD role trust policy missing sts:ExternalId",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-441",),
    recommendation=(
        "Add a Condition requiring sts:ExternalId for external principals."
    ),
    docs_note=(
        "A trust policy that lets an external AWS account assume "
        "the role without an ``sts:ExternalId`` condition is "
        "vulnerable to the confused-deputy pattern: a third-party "
        "SaaS configured with your role ARN can also be used by "
        "another customer of that SaaS to assume your role (if "
        "they know the ARN). ``sts:ExternalId`` ties the role to a "
        "specific tenancy."
    ),
    exploit_example=(
        "# Vulnerable: a role with a cross-account trust policy\n"
        "# missing ``sts:ExternalId`` in its Condition. The\n"
        "# Confused Deputy problem: a third-party SaaS (or\n"
        "# another team in another org) that AWS uses your\n"
        "# ARN with can be tricked into using it on the wrong\n"
        "# customer's behalf.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": {\"AWS\": \"arn:aws:iam::999999999999:root\"},\n"
        "    \"Action\": \"sts:AssumeRole\"\n"
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: require ``sts:ExternalId`` matching a value\n"
        "# the third party shares only with your tenant. Even\n"
        "# if the third-party SaaS is tricked into assuming\n"
        "# your role on a different customer's behalf, the\n"
        "# AssumeRole fails without the matching ExternalId.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": {\"AWS\": \"arn:aws:iam::999999999999:root\"},\n"
        "    \"Action\": \"sts:AssumeRole\",\n"
        "    \"Condition\": {\n"
        "      \"StringEquals\": {\"sts:ExternalId\": \"e7c1a0b3-abc-tenant-id\"}\n"
        "    }\n"
        "  }]\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        role_account = _account_of(role.get("Arn", ""))
        doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                doc = {}
        bad: list[str] = []
        for idx, stmt in enumerate(iter_allow(doc)):
            principal = stmt.get("Principal", {}) or {}
            if not (isinstance(principal, dict) and principal.get("AWS")):
                continue
            # sts:ExternalId guards the confused-deputy risk for EXTERNAL
            # accounts only. A same-account principal (the role's own
            # account root) is not a confused-deputy vector, don't flag it.
            aws_principal = principal.get("AWS")
            aws_values = (
                aws_principal if isinstance(aws_principal, list)
                else [aws_principal]
            )
            # A principal is external when it is a wildcard, or its account
            # differs from the role's own. When the role's account can't be
            # parsed we can't prove same-account, so flag conservatively
            # (no worse than the pre-fix behavior). Only a CONFIRMED
            # same-account principal is skipped.
            has_external = any(
                v == "*"
                or role_account is None
                or _account_of(v) != role_account
                for v in aws_values
            )
            if not has_external:
                continue
            conditions = stmt.get("Condition", {}) or {}
            has_external_id = any(
                "sts:ExternalId" in (inner or {})
                for inner in conditions.values()
                if isinstance(inner, dict)
            )
            if not has_external_id:
                bad.append(f"stmt[{idx}]")
        passed = not bad
        desc = (
            f"Trust policy on '{role_name}' has no external AWS principal, or "
            f"every external principal requires sts:ExternalId."
            if passed else
            f"Trust policy on '{role_name}' allows assumption by an AWS "
            f"principal in {bad} without sts:ExternalId (confused-deputy risk)."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
