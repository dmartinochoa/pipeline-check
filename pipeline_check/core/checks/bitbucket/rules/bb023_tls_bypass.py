"""BB-023. TLS / certificate verification bypass."""
from __future__ import annotations

from typing import Any

from ..._primitives import tls_bypass
from ...base import Finding, Severity
from ...blob import blob_raw
from ...rule import Rule
from ..base import iter_steps

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
        "of malicious packages, repositories, or build tools.\n\n"
        "Also flags Bitbucket's structural clone bypass, a step-level "
        "`clone: { skip-ssl-verify: true }`, which turns off certificate "
        "verification on the repository clone itself so a MITM can inject "
        "source into the build before any script runs."
    ),
    exploit_example=(
        "# Vulnerable: ``npm config set strict-ssl false`` (or\n"
        "# ``git config http.sslverify false`` / ``NODE_TLS_\n"
        "# REJECT_UNAUTHORIZED=0``) disables certificate\n"
        "# verification for the duration. A network attacker MITMs\n"
        "# the registry and ships substituted tarballs.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        image: node:20@sha256:abc123...\n"
        "        script:\n"
        "          - npm config set strict-ssl false\n"
        "          - npm install\n"
        "\n"
        "# Safe: install the missing CA into the image's trust\n"
        "# store; keep strict-ssl on.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        image: node:20@sha256:abc123...\n"
        "        script:\n"
        "          - cp /etc/ssl/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "          - update-ca-certificates\n"
        "          - npm install"
    ),
)


_TRUTHY = frozenset({"true", "1", "yes", "on"})


def _clone_skips_ssl(clone: Any) -> bool:
    """True when a ``clone:`` block sets ``skip-ssl-verify`` truthy."""
    if not isinstance(clone, dict):
        return False
    v = clone.get("skip-ssl-verify")
    return v is True or (isinstance(v, str) and v.strip().lower() in _TRUTHY)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Shell-level bypass idioms (curl -k, git http.sslVerify=false, ...)
    # live in script text, which blob_raw flattens. The Bitbucket
    # ``clone: { skip-ssl-verify: true }`` bypass is structural (a YAML
    # key + bool), which never reaches the blob, so it's walked here.
    hits = tls_bypass.scan(blob_raw(doc))
    structural: list[str] = []
    if _clone_skips_ssl(doc.get("clone")):
        structural.append("global clone: skip-ssl-verify")
    for loc, step in iter_steps(doc):
        if _clone_skips_ssl(step.get("clone")):
            structural.append(f"{loc}: clone skip-ssl-verify")
    passed = not hits and not structural
    if passed:
        desc = "No TLS verification bypass patterns detected."
    else:
        parts: list[str] = []
        if hits:
            parts.append(
                "TLS verification bypass detected: "
                + ", ".join(h.snippet for h in hits[:3])
            )
        if structural:
            parts.append(
                "clone TLS verification disabled: "
                + ", ".join(structural[:3])
            )
        desc = ". ".join(parts) + "."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
