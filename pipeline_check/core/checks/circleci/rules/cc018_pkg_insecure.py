"""CC-018, package install from insecure source."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import PKG_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-018",
    title="Package install from insecure source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Use HTTPS registry URLs. Remove --trusted-host and "
        "--no-verify flags. Pin to a private registry with TLS."
    ),
    docs_note=(
        "Detects package-manager invocations that use plain HTTP "
        "registries (`--index-url http://`, `--registry=http://`) or "
        "disable TLS verification (`--trusted-host`, `--no-verify`) "
        "in a CircleCI config. These patterns allow man-in-the-middle "
        "injection of malicious packages."
    ),
    exploit_example=(
        "# Vulnerable: pip resolves and downloads packages over\n"
        "# plaintext HTTP, so a network attacker between the\n"
        "# runner and the registry can substitute the wheel.\n"
        "# ``--trusted-host`` silences the very error that would\n"
        "# have caught the swap.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  install:\n"
        "    docker:\n"
        "      - image: cimg/python@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          pip install --index-url http://internal-pypi.example.com/simple \\\n"
        "                      --trusted-host internal-pypi.example.com \\\n"
        "                      -r requirements.txt\n"
        "\n"
        "# Safe: HTTPS with the index's certificate validated.\n"
        "# Internal CA installed into the image trust store.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  install:\n"
        "    docker:\n"
        "      - image: cimg/python@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          pip install --index-url https://internal-pypi.example.com/simple \\\n"
        "                      --require-hashes -r requirements.txt"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=PKG_INSECURE_RE.findall,
    pass_desc="No insecure package install patterns detected in this config.",
    fail_desc=lambda matches: (
        f"Insecure package install detected: {', '.join(matches[:3])}"
    ),
)
