"""GCB-011. TLS / certificate verification bypass.

Cloud Build steps that disable TLS verification (``curl -k``,
``wget --no-check-certificate``, ``git config http.sslVerify false``,
``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``PYTHONHTTPSVERIFY=0``) open the
build up to MITM injection of malicious packages, tooling, or
repositories. Reuses the cross-provider ``_primitives.tls_bypass``
detector so the idiom catalog stays aligned with GHA-023 / GL-023
/ BB-023 / ADO-023 / CC-023 / JF-023.
"""
from __future__ import annotations

from ..._primitives import tls_bypass
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-011",
    title="TLS / certificate verification bypass",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-295",),
    recommendation=(
        "Fix the underlying certificate issue, install the correct CA "
        "bundle into the step image, or point the tool at a mirror that "
        "presents a valid chain. Disabling verification trades a build "
        "error for a silent MITM window."
    ),
    docs_note=(
        "Covers ``curl -k`` / ``wget --no-check-certificate``, "
        "``git config http.sslVerify false``, "
        "``NODE_TLS_REJECT_UNAUTHORIZED=0``, "
        "``npm config set strict-ssl false``, ``PYTHONHTTPSVERIFY=0``, "
        "``GOINSECURE=``, ``helm --insecure-skip-tls-verify``, "
        "``kubectl --insecure-skip-tls-verify``, and "
        "``ssh -o StrictHostKeyChecking=no``."
    ),
)


def _fail_desc(hits: list[tls_bypass.TlsBypassFinding]) -> str:
    snippets = sorted({h.snippet for h in hits})
    return (
        f"{len(hits)} TLS verification bypass(es) detected: "
        f"{', '.join(snippets[:3])}"
        f"{'…' if len(snippets) > 3 else ''}."
    )


check = yaml_blob_check(
    RULE,
    scanner=tls_bypass.scan,
    pass_desc="No TLS verification bypass patterns detected in this pipeline.",
    fail_desc=_fail_desc,
)
