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
)


check = yaml_blob_check(
    RULE,
    scanner=PKG_INSECURE_RE.findall,
    pass_desc="No insecure package install patterns detected in this workflow.",
    fail_desc=lambda matches: (
        f"Insecure package install detected: {', '.join(matches[:3])}"
    ),
)
