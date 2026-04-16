"""BB-003 — definitions / step variables must not hold literal credentials."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps
from ._helpers import AWS_KEY_RE, SECRETISH_KEY_RE


RULE = Rule(
    id="BB-003",
    title="Variables contain literal secret values",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Store credentials as Repository / Deployment Variables in "
        "Bitbucket's Pipelines settings with the 'Secured' flag, and "
        "reference them by name. Prefer short-lived OIDC tokens for "
        "cloud access."
    ),
    docs_note=(
        "Scans `definitions.variables` and each step's `variables:` "
        "for entries whose KEY looks credential-shaped and whose "
        "VALUE is a literal string. AWS access keys are detected by "
        "value shape regardless of key name."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan(varmap: Any, where: str) -> None:
        if not isinstance(varmap, dict):
            return
        for key, value in varmap.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if AWS_KEY_RE.search(value):
                offenders.append(f"{where}.{key} (AWS access key)")
            elif SECRETISH_KEY_RE.search(key) and value and "$" not in value:
                offenders.append(f"{where}.{key}")

    defs = doc.get("definitions")
    if isinstance(defs, dict):
        _scan(defs.get("variables"), "definitions.variables")
    for loc, step in iter_steps(doc):
        _scan(step.get("variables"), loc)

    passed = not offenders
    desc = (
        "No YAML-declared variable holds a literal credential-shaped value."
        if passed else
        f"{len(offenders)} variable(s) contain literal credential "
        f"values: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    severity = Severity.CRITICAL if any("AWS" in o for o in offenders) else Severity.HIGH
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
