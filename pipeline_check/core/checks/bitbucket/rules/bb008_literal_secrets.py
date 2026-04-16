"""BB-008 — whole-document credential-shaped literal scan."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="BB-008",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Rotate the exposed credential. Move the value to a Secured "
        "Repository or Deployment Variable and reference it by name."
    ),
    docs_note=(
        "Complements BB-003 (variable-name scan). BB-008 checks "
        "every string in the pipeline against the cross-provider "
        "credential-pattern catalogue — catches secrets pasted into "
        "script bodies or environment blocks."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the pipeline matches a known credential pattern."
        if passed else
        f"Pipeline contains {len(hits)} literal value(s) matching "
        f"known credential patterns (AWS keys, GitHub tokens, Slack "
        f"tokens, JWTs): {', '.join(hits[:5])}"
        f"{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
