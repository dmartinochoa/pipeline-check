"""GHA-017 — docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from typing import Any

from ...base import DOCKER_INSECURE_RE, Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-017",
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
        "host-root volume mounts (`-v /:/`) in a workflow give the "
        "container full access to the runner, enabling container "
        "escape and lateral movement."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    matches = DOCKER_INSECURE_RE.findall(blob)
    passed = not matches
    desc = (
        "No insecure docker run flags detected in this workflow."
        if passed else
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
