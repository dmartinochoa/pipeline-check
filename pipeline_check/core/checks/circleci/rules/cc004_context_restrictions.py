"""CC-004. Jobs with secret-like env vars should use contexts, not inline values."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="CC-004",
    title="Secret-like environment variable not managed via context",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-284",),
    recommendation=(
        "Move secret-like variables (PASSWORD, TOKEN, SECRET, API_KEY) "
        "into a CircleCI context and reference the context in the "
        "workflow job configuration. Contexts support security groups "
        "and audit logging that inline `environment:` blocks lack."
    ),
    docs_note=(
        "Jobs that declare environment variables with secret-looking "
        "names (containing PASSWORD, TOKEN, SECRET, or API_KEY) in "
        "inline `environment:` blocks bypass CircleCI's context "
        "restrictions, security groups, OIDC claims, and audit logs "
        "are only enforced when secrets live in contexts."
    ),
)

# Match a secret-like keyword as a complete underscore-delimited segment.
# To reduce false positives on names like ``SECRET_SCANNING_ENABLED`` or
# ``TOKEN_TYPE`` (where the keyword is a non-secret prefix), require the
# keyword to either:
#   - be preceded by ``_`` (never the first segment), OR
#   - be the entire variable name (standalone, no underscores).
# This keeps ``NPM_TOKEN``, ``DATABASE_PASSWORD``, ``GH_TOKEN``,
# ``MY_SECRET``, ``APP_API_KEY`` while dropping ``SECRET_SCANNING_ENABLED``.
# ``APIKEY`` (no underscore) is matched as a substring because it has no
# known non-secret homographs.
_SECRET_NAME_RE = re.compile(
    r"_(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)(?:_|$)"
    r"|^(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)$"
    r"|APIKEY",
    re.IGNORECASE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending_jobs: list[str] = []
    for job_id, job in iter_jobs(doc):
        env = job.get("environment")
        if not isinstance(env, dict):
            continue
        for var_name in env:
            if isinstance(var_name, str) and _SECRET_NAME_RE.search(var_name):
                offending_jobs.append(job_id)
                break
    passed = not offending_jobs
    desc = (
        "No job declares secret-like variables in inline `environment:` "
        "blocks."
        if passed else
        f"{len(offending_jobs)} job(s) declare secret-like environment "
        f"variables (PASSWORD, TOKEN, SECRET, API_KEY) inline rather "
        f"than via a context: {', '.join(offending_jobs)}. Inline env "
        f"blocks bypass context-level security groups and audit logging."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
