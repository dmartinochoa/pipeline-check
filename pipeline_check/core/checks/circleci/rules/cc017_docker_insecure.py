"""CC-017, docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import DOCKER_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-017",
    title="Docker run with insecure flags (privileged/host mount)",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250",),
    recommendation=(
        "Remove --privileged and --cap-add flags. Use minimal volume "
        "mounts. Prefer rootless containers."
    ),
    docs_note=(
        "Flags like `--privileged`, `--cap-add`, `--net=host`, or "
        "host-root volume mounts (`-v /:/`) in a CircleCI config give "
        "the container full access to the runner, enabling container "
        "escape and lateral movement."
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=DOCKER_INSECURE_RE.findall,
    pass_desc="No insecure docker run flags detected in this config.",
    fail_desc=lambda matches: (
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    ),
)
