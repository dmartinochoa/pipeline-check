"""GHA-016 — remote script piped to shell interpreter."""
from __future__ import annotations

from typing import Any

from ...base import CURL_PIPE_RE, Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-016",
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
        "inside a workflow. An attacker who controls the remote "
        "endpoint (or poisons DNS / CDN) gains arbitrary code "
        "execution in the CI runner."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    matches = CURL_PIPE_RE.findall(blob)
    passed = not matches
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this workflow."
        if passed else
        f"Remote script piped to interpreter detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
