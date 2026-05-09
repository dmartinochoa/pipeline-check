"""DR-006. TLS verification disabled in step commands."""
from __future__ import annotations

from ...base import TLS_BYPASS_RE, Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_steps,
    step_commands,
    step_label,
)

RULE = Rule(
    id="DR-006",
    title="TLS verification disabled in step commands",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-295", "CWE-494"),
    recommendation=(
        "Remove TLS-bypass flags from build commands. The most "
        "common offenders are ``curl --insecure`` / ``-k`` / "
        "``wget --no-check-certificate``, ``pip config set "
        "global.trusted-host``, ``npm config set strict-ssl "
        "false``, and ``git -c http.sslverify=false``. Each "
        "exposes the build to TLS-MITM injection of a "
        "registry-served payload, which is a textbook supply-"
        "chain attack vector. If a registry's certificate is "
        "genuinely broken, fix the registry rather than "
        "permanently disabling verification, the bypass tends "
        "to outlive the broken cert and become a permanent "
        "weakness."
    ),
    docs_note=(
        "Detection is the same blob-regex used by GHA-027, "
        "BK-008, JF-022, ADO-026, CC-024, and the CFN/Terraform "
        "rule packs. Matches: ``curl --insecure`` / ``-k``, "
        "``wget --no-check-certificate``, ``pip config set "
        "global.trusted-host``, ``npm config set strict-ssl "
        "false``, ``yarn config set strict-ssl false``, ``git "
        "config http.sslverify false``, ``GIT_SSL_NO_VERIFY=1``, "
        "``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``PYTHONHTTPSVERIFY=0``, "
        "and ``GOINSECURE=...``. The rule scans every "
        "``commands:`` entry on every step."
    ),
)


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored, no "
                "shell command surface to scan."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        for cmd in step_commands(step):
            m = TLS_BYPASS_RE.search(cmd)
            if m:
                offenders.append(
                    f"steps.{step_label(step, idx)}: "
                    f"{m.group(0).strip()[:80]}"
                )
                break
    passed = not offenders
    desc = (
        "No step disables TLS verification."
        if passed else
        f"{len(offenders)} step(s) disable TLS verification: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
