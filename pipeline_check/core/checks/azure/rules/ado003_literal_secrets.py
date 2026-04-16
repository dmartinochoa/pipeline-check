"""ADO-003 — `variables:` must not hold literal credential values."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import AWS_KEY_RE, SECRETISH_KEY_RE

RULE = Rule(
    id="ADO-003",
    title="Variables contain literal secret values",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    recommendation=(
        "Store secrets in an Azure Key Vault or a Library variable "
        "group with the secret flag set; reference them via "
        "`$(SECRET_NAME)` at runtime. For cloud access prefer Azure "
        "workload identity federation."
    ),
    docs_note=(
        "Scans `variables:` in both the mapping form (`{KEY: VAL}`) "
        "and the list form (`[{name: X, value: Y}]`) that ADO "
        "supports. AWS keys are detected by value shape regardless "
        "of variable name."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan(mapping: Any, where: str) -> None:
        if isinstance(mapping, dict):
            for key, value in mapping.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                if AWS_KEY_RE.search(value):
                    offenders.append(f"{where}.{key} (AWS access key)")
                elif SECRETISH_KEY_RE.search(key) and value and "$" not in value:
                    offenders.append(f"{where}.{key}")
        elif isinstance(mapping, list):
            for entry in mapping:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                value = entry.get("value")
                if not isinstance(name, str) or not isinstance(value, str):
                    continue
                if AWS_KEY_RE.search(value):
                    offenders.append(f"{where}.{name} (AWS access key)")
                elif SECRETISH_KEY_RE.search(name) and value and "$" not in value:
                    offenders.append(f"{where}.{name}")

    _scan(doc.get("variables"), "<top>")
    for job_loc, job in iter_jobs(doc):
        _scan(job.get("variables"), job_loc)

    passed = not offenders
    desc = (
        "No `variables:` entry holds a literal credential-shaped value."
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
