"""BB-023 — TLS / certificate verification bypass."""
from __future__ import annotations
from typing import Any
from ...base import TLS_BYPASS_RE, Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BB-023",
    title="TLS / certificate verification bypass",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-295",),
    recommendation=(
        "Remove TLS verification bypasses. Fix certificate issues at "
        "the source (install CA certificates, configure proper trust "
        "stores) instead of disabling verification."
    ),
    docs_note=(
        "Detects patterns that disable TLS certificate verification: "
        "`git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, "
        "`npm config set strict-ssl false`, `curl -k`, "
        "`wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and "
        "`GOINSECURE=`. Disabling TLS verification allows MITM injection "
        "of malicious packages, repositories, or build tools."
    ),
)

def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    matches = TLS_BYPASS_RE.findall(blob)
    passed = not matches
    desc = (
        "No TLS verification bypass patterns detected."
        if passed else
        f"TLS verification bypass detected: "
        f"{', '.join(m.strip() for m in matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
