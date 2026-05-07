"""BK-008 — TLS verification disabled in step commands."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, TLS_BYPASS_RE
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-008",
    title="TLS verification disabled in step command",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-D-COMMS-INTEGRITY",),
    cwe=("CWE-295",),
    recommendation=(
        "Drop ``curl -k`` / ``--insecure``, ``wget --no-check-"
        "certificate``, ``git -c http.sslVerify=false``, and ``pip "
        "install --trusted-host``. If a CA isn't trusted, install it "
        "into the agent's trust store (``update-ca-certificates``) "
        "rather than disabling validation pipeline-wide. A "
        "compromised intermediate that strips TLS gets a free hand "
        "with every fetch the step performs."
    ),
    docs_note=(
        "Detection fires on the canonical bypass flags across curl, "
        "wget, git, npm, pip, gcloud, and openssl. The check is "
        "deliberately conservative — partial-word matches "
        "(``--insecure-protocols``) are excluded."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            m = TLS_BYPASS_RE.search(cmd)
            if m:
                offenders.append(
                    f"{step_label(step, idx)}: {m.group(0)}"
                )
                break
    passed = not offenders
    desc = (
        "No TLS bypass flags detected in step commands."
        if passed else
        f"{len(offenders)} step(s) disable TLS verification: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Install the missing CA "
        f"into the agent's trust store instead of bypassing."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
