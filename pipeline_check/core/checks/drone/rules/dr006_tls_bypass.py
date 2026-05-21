"""DR-006. TLS verification disabled in step commands."""
from __future__ import annotations

from ..._primitives import tls_bypass
from ...base import Finding, Severity
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
        "Uses the cross-provider ``_primitives.tls_bypass`` detector "
        "shared with GHA-027, BK-008, JF-022, ADO-026, CC-024, "
        "GCB-011, and the CFN / Terraform rule packs. Covers curl / "
        "wget / git / npm / yarn / pip / helm / kubectl / ssh / "
        "docker / maven / gradle / aws bypasses. The rule scans every "
        "``commands:`` entry on every step."
    ),
    exploit_example=(
        "# Vulnerable: every npm install in the build skips strict-\n"
        "# ssl validation. An attacker on the network path (corp\n"
        "# proxy, malicious mirror, BGP hijack) MITMs the registry\n"
        "# and ships malicious tarballs that npm installs without\n"
        "# any signal.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: install\n"
        "    image: node:20@sha256:abc123...\n"
        "    commands:\n"
        "      - npm config set strict-ssl false\n"
        "      - npm install\n"
        "\n"
        "# Safe: install the missing CA into the image (or use the\n"
        "# default trust store). Never disable TLS verification\n"
        "# pipeline-wide; if a registry's cert is broken, fix the\n"
        "# registry rather than papering over with a bypass that\n"
        "# outlives the broken cert.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: install\n"
        "    image: node:20@sha256:abc123...\n"
        "    commands:\n"
        "      - cp /etc/ssl/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "      - update-ca-certificates\n"
        "      - npm install"
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
            hits = tls_bypass.scan(cmd)
            if hits:
                offenders.append(
                    f"steps.{step_label(step, idx)}: "
                    f"{hits[0].snippet[:80]}"
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
