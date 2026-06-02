"""GHA-023. TLS / certificate verification bypass."""
from __future__ import annotations

from ..._primitives import tls_bypass
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-023",
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
        "# Vulnerable: every git fetch in the job ignores certificate\n"
        "# validity. An attacker on the same network (corporate proxy,\n"
        "# hostile WiFi at a remote-dev's home, compromised mirror)\n"
        "# returns a MITM-substituted clone of the dependency. The\n"
        "# downstream build runs the attacker's code with the\n"
        "# workflow's full secret + token set in scope.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: git config --global http.sslVerify false\n"
        "      - run: git clone https://internal.example.com/lib.git\n"
        "      - run: ./build\n"
        "\n"
        "# Safe: install the missing CA chain so verification succeeds.\n"
        "# If the upstream really uses a private CA, ship its root in\n"
        "# the runner image rather than disabling verification for\n"
        "# every host the job talks to.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "          sudo update-ca-certificates\n"
        "      - run: git clone https://internal.example.com/lib.git\n"
        "      - run: ./build"
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
