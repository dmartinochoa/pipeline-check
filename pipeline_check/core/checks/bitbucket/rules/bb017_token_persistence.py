"""BB-017 — repository token written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts

_TOKEN_PERSIST_RE = re.compile(
    r"BITBUCKET_TOKEN.*(?:>>?\s|tee\s)"
    r"|REPOSITORY_OAUTH_ACCESS_TOKEN.*(?:>>?\s|tee\s)"
    r"|>>?\s*.*BITBUCKET_TOKEN"
    r"|>>?\s*.*REPOSITORY_OAUTH_ACCESS_TOKEN"
)

RULE = Rule(
    id="BB-017",
    title="Repository token written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN "
        "to files or artifacts. Use the token inline in the command "
        "that needs it and let Bitbucket revoke it after the build."
    ),
    docs_note=(
        "Detects patterns where Bitbucket pipeline tokens are "
        "redirected to files or piped through `tee`. Persisted tokens "
        "survive the step boundary and can be exfiltrated by later "
        "steps, artifacts, or cache entries."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        for line in step_scripts(step):
            if _TOKEN_PERSIST_RE.search(line):
                offenders.append(loc)
                break
    passed = not offenders
    desc = (
        "No repository token persistence patterns detected."
        if passed
        else f"Repository token written to persistent storage in: "
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
