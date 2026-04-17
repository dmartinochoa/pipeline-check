"""ADO-023 — TLS / certificate verification bypass."""
from __future__ import annotations

from typing import Any

from ..._primitives import tls_bypass
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="ADO-023",
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
    hits = tls_bypass.scan(blob_lower(doc))
    passed = not hits
    desc = (
        "No TLS verification bypass patterns detected."
        if passed else
        f"TLS verification bypass detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
