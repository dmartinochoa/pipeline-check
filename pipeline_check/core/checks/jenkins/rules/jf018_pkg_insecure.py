"""JF-018 — package install from insecure source."""
from __future__ import annotations

from ...base import PKG_INSECURE_RE, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-018",
    title="Package install from insecure source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Use HTTPS registry URLs. Remove --trusted-host and "
        "--no-verify flags. Pin to a private registry with TLS."
    ),
    docs_note=(
        "Detects package-manager invocations that use plain HTTP "
        "registries (`--index-url http://`, `--registry=http://`) or "
        "disable TLS verification (`--trusted-host`, `--no-verify`) "
        "in a Jenkinsfile. These patterns allow man-in-the-middle "
        "injection of malicious packages."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    matches = PKG_INSECURE_RE.findall(jf.text.lower())
    passed = not matches
    desc = (
        "No insecure package install patterns detected in this Jenkinsfile."
        if passed else
        f"Insecure package install detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
