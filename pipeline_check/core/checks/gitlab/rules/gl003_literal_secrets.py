"""GL-003 — `variables:` blocks must not hold literal credential values."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import AWS_KEY_RE, SECRETISH_KEY_RE


RULE = Rule(
    id="GL-003",
    title="Variables contain literal secret values",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Store credentials as protected + masked CI/CD variables in "
        "project or group settings, and reference them by name from "
        "the YAML. For cloud access prefer short-lived OIDC tokens."
    ),
    docs_note=(
        "Scans `variables:` at the top level and on each job for "
        "entries whose KEY looks credential-shaped and whose VALUE "
        "is a literal string (not a `$VAR` reference). AWS access "
        "keys are detected by value pattern regardless of key name."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan(varmap: Any, where: str) -> None:
        if not isinstance(varmap, dict):
            return
        for key, value in varmap.items():
            if not isinstance(key, str):
                continue
            raw = value.get("value") if isinstance(value, dict) else value
            if not isinstance(raw, str):
                continue
            if AWS_KEY_RE.search(raw):
                offenders.append(f"{where}.{key} (AWS access key)")
                continue
            if SECRETISH_KEY_RE.search(key) and raw and "$" not in raw:
                offenders.append(f"{where}.{key}")

    _scan(doc.get("variables"), "<top>")
    for name, job in iter_jobs(doc):
        _scan(job.get("variables"), name)

    passed = not offenders
    desc = (
        "No `variables:` entry holds a literal credential-shaped value."
        if passed else
        f"{len(offenders)} variable(s) contain literal credential values: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}. "
        f"Secrets committed to CI YAML are visible in every fork and "
        f"every pipeline run log."
    )
    severity = Severity.CRITICAL if any("AWS" in o for o in offenders) else Severity.HIGH
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
