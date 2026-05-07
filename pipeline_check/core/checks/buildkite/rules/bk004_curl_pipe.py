"""BK-004 — ``curl <url> | sh`` and equivalents in step commands."""
from __future__ import annotations

from typing import Any

from ...base import CURL_PIPE_RE, Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-004",
    title="Remote script piped into shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Download the installer to disk, verify a checksum or "
        "signature, then execute it. ``curl ... | sh`` lets the "
        "remote host change what runs in your pipeline at any time, "
        "and any TLS / DNS error during download silently feeds a "
        "partial script to the shell."
    ),
    docs_note=(
        "The detection fires on ``curl|bash``, ``curl|sh``, ``wget|"
        "bash``, ``iex (iwr ...)``, and the corresponding "
        "``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. "
        "Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; "
        "bash install.sh`` instead."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            m = CURL_PIPE_RE.search(cmd)
            if m:
                snippet = cmd[max(0, m.start() - 10):m.end() + 20].strip()
                offenders.append(
                    f"{step_label(step, idx)}: {snippet[:80]}"
                )
                break
    passed = not offenders
    desc = (
        "No curl-pipe-shell idioms in step commands."
        if passed else
        f"{len(offenders)} step(s) pipe a remote script into a shell: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Download, verify, then "
        f"execute."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
