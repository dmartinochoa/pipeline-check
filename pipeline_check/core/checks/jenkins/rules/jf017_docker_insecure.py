"""JF-017 — docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from ...base import DOCKER_INSECURE_RE, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-017",
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
        "host-root volume mounts (`-v /:/`) in a Jenkinsfile give the "
        "container full access to the build agent, enabling container "
        "escape and lateral movement."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    matches = DOCKER_INSECURE_RE.findall(jf.text.lower())
    passed = not matches
    desc = (
        "No insecure docker run flags detected in this Jenkinsfile."
        if passed else
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
