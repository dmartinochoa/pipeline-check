"""BB-011 — pipeline should not embed long-lived AWS access keys."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps
from ._helpers import AWS_KEY_RE

_AWS_CONFIGURE_RE = re.compile(
    r"aws\s+configure\s+set\s+aws_access_key_id\b"
    r"|aws\s+configure\s+set\s+aws_secret_access_key\b"
)

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
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    # Scan step-level variables and script lines.
    for _, step in iter_steps(doc):
        for script_line in (step.get("script") or []):
            if isinstance(script_line, str):
                if AWS_KEY_RE.search(script_line):
                    static_keys = True
                if _AWS_CONFIGURE_RE.search(script_line):
                    static_keys = True
        # Also check step-level variables (definitions.variables).
        for v in (step.get("variables") or {}).values() if isinstance(step.get("variables"), dict) else []:
            if isinstance(v, str) and AWS_KEY_RE.search(v):
                static_keys = True
    # Scan top-level definitions variables.
    defs = doc.get("definitions") or {}
    if isinstance(defs, dict):
        for v in (defs.get("variables") or {}).values() if isinstance(defs.get("variables"), dict) else []:
            if isinstance(v, str) and AWS_KEY_RE.search(v):
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
