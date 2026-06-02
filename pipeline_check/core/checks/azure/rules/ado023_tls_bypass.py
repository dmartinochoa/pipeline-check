"""ADO-023. TLS / certificate verification bypass."""
from __future__ import annotations

from ..._primitives import tls_bypass
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
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
    exploit_example=(
        "# Vulnerable: ``npm config set strict-ssl false`` disables\n"
        "# certificate verification for every subsequent npm call.\n"
        "# A network attacker MITMs the registry and ships\n"
        "# substituted tarballs that npm installs unverified.\n"
        "steps:\n"
        "  - bash: |\n"
        "      npm config set strict-ssl false\n"
        "      npm install\n"
        "\n"
        "# Safe: install the missing CA into the agent's trust\n"
        "# store and keep strict-ssl on.\n"
        "steps:\n"
        "  - bash: |\n"
        "      sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "      sudo update-ca-certificates\n"
        "      npm install"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=tls_bypass.scan,
    pass_desc="No TLS verification bypass patterns detected.",
    fail_desc=lambda hits: (
        f"TLS verification bypass detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    ),
    lowercase=False,
)
