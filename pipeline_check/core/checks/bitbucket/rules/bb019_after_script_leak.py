"""BB-019 — after-script accessing secrets may leak credentials on failure."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

_SECRET_REF_RE = re.compile(
    r"\$\{?(?:BITBUCKET_TOKEN|REPOSITORY_OAUTH_ACCESS_TOKEN)\}?"
    r"|\$\{?[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY)[A-Z_]*\}?"
)

RULE = Rule(
    id="BB-019",
    title="after-script references secrets",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Move secret-dependent operations into the main `script:` "
        "block. `after-script` runs even when the step fails and "
        "executes in a separate shell context — credential exposure "
        "here is harder to audit and more likely to persist in logs."
    ),
    docs_note=(
        "Bitbucket's `after-script` runs unconditionally after the "
        "main `script` block (including on failure). If the "
        "`after-script` references secrets or tokens, those values "
        "may leak into build logs or artifacts even when the step "
        "fails unexpectedly. This check detects secret-like variable "
        "references in `after-script` blocks."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        after = step.get("after-script")
        if not isinstance(after, list):
            continue
        for line in after:
            if isinstance(line, str) and _SECRET_REF_RE.search(line):
                offenders.append(loc)
                break
    passed = not offenders
    desc = (
        "No after-script blocks reference secrets."
        if passed
        else f"after-script references secret-like variables in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
