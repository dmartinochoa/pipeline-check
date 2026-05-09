"""ADO-008, whole-document credential-shaped literal scan."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="ADO-008",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential. Move the value to Azure Key "
        "Vault or a secret variable group and reference it via "
        "`$(SECRET_NAME)`."
    ),
    docs_note=(
        "Complements ADO-003 (which looks at `variables:` keys). "
        "ADO-008 scans every string in the pipeline against the "
        "cross-provider credential-pattern catalog."
    ),
    known_fp=(
        "Test fixtures and documentation blobs sometimes embed "
        "credential-shaped strings (JWT samples, AKIAI... examples). "
        "The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is "
        "deliberately NOT suppressed, if it appears in a real "
        "pipeline it almost always means a copy-paste from docs was "
        "never substituted. Defaults to LOW confidence.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the pipeline matches a known credential pattern."
        if passed else
        f"Pipeline contains {len(hits)} literal value(s) matching "
        f"known credential patterns: {', '.join(hits[:5])}"
        f"{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
