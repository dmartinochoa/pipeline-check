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
)


check = yaml_blob_check(
    RULE,
    scanner=PKG_INSECURE_RE.findall,
    pass_desc="No insecure package install patterns detected in this config.",
    fail_desc=lambda matches: (
        f"Insecure package install detected: {', '.join(matches[:3])}"
    ),
)
