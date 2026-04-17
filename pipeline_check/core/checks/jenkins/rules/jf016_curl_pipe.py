"""JF-016 — remote script piped to shell interpreter."""
from __future__ import annotations

from ...base import Finding, Severity
from ..._primitives import remote_script_exec
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-016",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository."
    ),
    docs_note=(
        "Detects `curl | bash`, `wget | sh`, and similar patterns "
        "that pipe remote content directly into a shell interpreter "
        "inside a Jenkinsfile. An attacker who controls the remote "
        "endpoint (or poisons DNS / CDN) gains arbitrary code "
        "execution in the build agent."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    hits = remote_script_exec.scan(jf.text.lower())
    passed = not hits
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this Jenkinsfile."
        if passed else
        f"Remote script piped to interpreter detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
