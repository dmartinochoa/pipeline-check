"""BB-011, pipeline should not embed long-lived AWS access keys."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps
from ._helpers import aws_key_in

_AWS_CONFIGURE_RE = re.compile(
    r"aws\s+configure\s+set\s+"
    r"aws_(?:access_key_id|secret_access_key)\s+(\S+)"
)


def _is_literal_value(token: str) -> bool:
    """True when *token* is an embedded literal, not a ``$``-reference.

    ``aws configure set aws_access_key_id "$SECURED_VAR"`` sources the
    key from a secured Bitbucket variable (the recommended shape) and
    must not fire; only a literal value embedded in the file does.
    """
    t = token.strip().strip("\"'").strip()
    return bool(t) and not t.startswith("$")

RULE = Rule(
    id="BB-011",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Use Bitbucket OIDC with `oidc: true` on the AWS pipe, or "
        "store credentials as secured Bitbucket variables rather than "
        "inline values. Remove static AWS_ACCESS_KEY_ID / "
        "AWS_SECRET_ACCESS_KEY from the pipeline file."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "values embedded in the pipeline file can't be rotated on a "
        "fine-grained schedule. Prefer OIDC or Bitbucket secured "
        "variables for cross-cloud access."
    ),
    exploit_example=(
        "# Vulnerable: long-lived AWS keys baked into the pipeline.\n"
        "# The keys are present in the build environment and in the\n"
        "# checked-in file; a leaked log or malicious dependency\n"
        "# exfiltrates them and they stay valid until rotated by hand.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - export AWS_ACCESS_KEY_ID=AKIAZ3MHALF2TESTHIJK\n"
        "          - export AWS_SECRET_ACCESS_KEY=wJalrXUtn/K7MDENG/bPxRfiCYSAMPLEKEY\n"
        "          - aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Safe: OIDC via the AWS pipe's `oidc: true` (short-lived role\n"
        "# credentials per build), or secured repo variables.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        oidc: true\n"
        "        script:\n"
        "          - pipe: atlassian/aws-s3-deploy:1.7.0\n"
        "            variables:\n"
        "              AWS_OIDC_ROLE_ARN: arn:aws:iam::123456789012:role/ci-deploy"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    # Scan step-level variables and script lines.
    for _, step in iter_steps(doc):
        for script_line in (step.get("script") or []):
            if isinstance(script_line, str):
                if aws_key_in(script_line):
                    static_keys = True
                m = _AWS_CONFIGURE_RE.search(script_line)
                if m and _is_literal_value(m.group(1)):
                    static_keys = True
        # Also check step-level variables (definitions.variables).
        for v in (step.get("variables") or {}).values() if isinstance(step.get("variables"), dict) else []:
            if isinstance(v, str) and aws_key_in(v):
                static_keys = True
    # Scan top-level definitions variables.
    defs = doc.get("definitions") or {}
    if isinstance(defs, dict):
        for v in (defs.get("variables") or {}).values() if isinstance(defs.get("variables"), dict) else []:
            if isinstance(v, str) and aws_key_in(v):
                static_keys = True
    if not static_keys:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not reference long-lived AWS keys.",
            recommendation="No action required.", passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "Pipeline references long-lived AWS access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) in variables "
            "or script blocks."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
