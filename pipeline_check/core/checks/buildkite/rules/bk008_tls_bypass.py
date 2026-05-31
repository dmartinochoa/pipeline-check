"""BK-008. TLS verification disabled in step commands."""
from __future__ import annotations

from typing import Any

from ..._primitives import tls_bypass
from ...base import Finding, Severity
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
        "Uses the cross-provider ``_primitives.tls_bypass`` detector "
        "so detection stays aligned with GHA-027 / GL-023 / JF-022 / "
        "ADO-026 / CC-024 / GCB-011 / DR-006. Covers curl / wget / "
        "git / npm / yarn / pip / helm / kubectl / ssh / docker / "
        "maven / gradle / aws bypasses. Partial-word matches "
        "(``--insecure-protocols``) are excluded."
    ),
    exploit_example=(
        "# Vulnerable: TLS verification disabled mid-pipeline.\n"
        "steps:\n"
        "  - command: \"curl -k https://artifacts.internal/app.tar.gz | tar xz\"\n"
        "\n"
        "# Attack: `curl -k` skips certificate validation. An on-path\n"
        "# attacker (a compromised proxy, a poisoned DNS entry, a\n"
        "# hostile network) presents any certificate and serves a\n"
        "# backdoored app.tar.gz, which the step unpacks and runs with\n"
        "# the agent's credentials.\n"
        "\n"
        "# Safe: keep verification on; install the CA into the agent\n"
        "# trust store if it's a private root.\n"
        "  - command: \"curl https://artifacts.internal/app.tar.gz | tar xz\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            hits = tls_bypass.scan(cmd)
            if hits:
                offenders.append(
                    f"{step_label(step, idx)}: {hits[0].snippet}"
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
