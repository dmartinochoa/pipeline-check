"""BB-014 — package install from insecure source."""
from __future__ import annotations

from typing import Any

from ...base import PKG_INSECURE_RE, Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BB-014",
    title="Package install from insecure source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    recommendation=(
        "Use HTTPS registry URLs. Remove --trusted-host and "
        "--no-verify flags. Pin to a private registry with TLS."
    ),
    docs_note=(
        "Detects package-manager invocations that use plain HTTP "
        "registries (`--index-url http://`, `--registry=http://`) or "
        "disable TLS verification (`--trusted-host`, `--no-verify`) "
        "in a pipeline. These patterns allow man-in-the-middle "
        "injection of malicious packages."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    matches = PKG_INSECURE_RE.findall(blob)
    passed = not matches
    desc = (
        "No insecure package install patterns detected in this pipeline."
        if passed else
        f"Insecure package install detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
