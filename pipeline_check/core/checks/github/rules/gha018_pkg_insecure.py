"""GHA-018, package install from insecure source."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import PKG_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-018",
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
        "in a workflow. These patterns allow man-in-the-middle "
        "injection of malicious packages.\n\n"
        "Carve-out: third-party binary installers that download over "
        "HTTPS (no insecure registry, no TLS bypass) are GHA-016's "
        "trusted-installer shape, not GHA-018's. "
        "``greylag-ci/cicd-goat`` scenario 19 fetches a Codecov-style "
        "uploader from a non-vendor HTTPS endpoint, verifies a SHA256 "
        "checksum and GPG signature, and runs the binary; GHA-018 "
        "deliberately doesn't fire (the source is HTTPS), GHA-016 "
        "does (the Codecov-2021 lesson)."
    ),
    exploit_example=(
        "# Vulnerable: pip resolves and downloads packages over\n"
        "# plaintext HTTP, so any network attacker between the\n"
        "# runner and the registry (compromised proxy, malicious\n"
        "# VPN exit, BGP hijack on an internal mirror) can swap a\n"
        "# wheel for a malicious one whose ``setup.py`` runs at\n"
        "# install time. ``--trusted-host`` then silences the very\n"
        "# error that would have caught the swap.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          pip install \\\n"
        "            --index-url http://internal-pypi.example.com/simple \\\n"
        "            --trusted-host internal-pypi.example.com \\\n"
        "            -r requirements.txt\n"
        "\n"
        "# Safe: HTTPS with the registry's certificate validated.\n"
        "# If the internal index uses a private CA, install the CA\n"
        "# into the runner trust store, never ``--trusted-host`` or\n"
        "# ``--no-verify``.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "          sudo update-ca-certificates\n"
        "      - run: |\n"
        "          pip install \\\n"
        "            --index-url https://internal-pypi.example.com/simple \\\n"
        "            --require-hashes -r requirements.txt"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=PKG_INSECURE_RE.findall,
    pass_desc="No insecure package install patterns detected in this workflow.",
    fail_desc=lambda matches: (
        f"Insecure package install detected: {', '.join(matches[:3])}"
    ),
)
