"""GL-018, package install from insecure source."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import PKG_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="GL-018",
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
        "in a pipeline. These patterns allow man-in-the-middle "
        "injection of malicious packages."
    ),
    exploit_example=(
        "# Vulnerable: pip uses a plaintext-HTTP index and\n"
        "# ``--trusted-host`` silences hash verification.\n"
        "install:\n"
        "  image: python@sha256:abc123...\n"
        "  script:\n"
        "    - pip install --index-url http://internal-pypi.example.com/simple\n"
        "        --trusted-host internal-pypi.example.com -r requirements.txt\n"
        "\n"
        "# Safe: HTTPS + ``--require-hashes``. Internal CA\n"
        "# installed into the image's trust store.\n"
        "install:\n"
        "  image: python@sha256:abc123...\n"
        "  script:\n"
        "    - pip install --index-url https://internal-pypi.example.com/simple\n"
        "        --require-hashes -r requirements.txt"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=PKG_INSECURE_RE.findall,
    pass_desc="No insecure package install patterns detected in this pipeline.",
    fail_desc=lambda matches: (
        f"Insecure package install detected: {', '.join(matches[:3])}"
    ),
)
