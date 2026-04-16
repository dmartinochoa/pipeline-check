"""JF-010 — environment block must not expose long-lived AWS keys."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import ENV_AWS_KEY_RE

RULE = Rule(
    id="JF-010",
    title="Long-lived AWS keys exposed via environment {} block",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS", "ESF-D-TOKEN-HYGIENE"),
    recommendation=(
        "Replace the literal with a credentials-store reference: "
        "`AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: "
        "switch to the AWS plugin's role binding (`withAWS(role: "
        "'arn:…')`) so the build assumes a short-lived role per run."
    ),
    docs_note=(
        "Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the "
        "value is a literal or plain variable reference. Skips "
        "`credentials('id')` helpers and `${env.X}` that resolve at "
        "runtime. Matches both multiline and inline `environment { "
        "... }` forms."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    for m in ENV_AWS_KEY_RE.finditer(jf.text):
        name, value = m.group(1), m.group(2)
        if value.startswith("${") and "credentials" in value:
            continue
        if "credentials(" in value:
            continue
        offenders.append(name)
    passed = not offenders
    desc = (
        "No long-lived AWS credentials are bound in `environment { … }`."
        if passed else
        f"`environment {{ … }}` block declares AWS credential "
        f"variable(s) with literal or non-credentials-store values: "
        f"{', '.join(sorted(set(offenders)))}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
