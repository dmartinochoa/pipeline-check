"""HARNESS-006. TLS verification disabled in step commands."""
from __future__ import annotations

from ..._primitives import tls_bypass
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text, step_label

RULE = Rule(
    id="HARNESS-006",
    title="TLS verification disabled in step commands",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-295", "CWE-494"),
    recommendation=(
        "Remove TLS-bypass flags from the step command. The common "
        "offenders are ``curl --insecure`` / ``-k``, ``wget "
        "--no-check-certificate``, ``pip config set global.trusted-host``, "
        "``npm config set strict-ssl false``, and ``git -c "
        "http.sslVerify=false``. Each exposes the build to a TLS-MITM "
        "injection of a registry-served payload, a textbook supply-chain "
        "vector. If a registry's certificate is genuinely broken, install "
        "the missing CA into the build image and fix the registry rather "
        "than disabling verification, which tends to outlive the broken "
        "cert and become a permanent weakness."
    ),
    docs_note=(
        "Reuses the cross-provider ``_primitives.tls_bypass`` detector "
        "shared with DR-006 / GHA-027 / BK-008 / JF-022 / ADO-026 / CC-024 "
        "/ GCB-011 and the IaC packs (covers curl / wget / git / npm / yarn "
        "/ pip / helm / kubectl / ssh / docker / maven / gradle / aws "
        "bypasses). The rule scans every step's ``spec.command`` text "
        "across CI and CD stages, through ``parallel`` / ``stepGroup`` "
        "nesting."
    ),
    exploit_example=(
        "# Vulnerable: every npm install skips strict-ssl validation. An\n"
        "# attacker on the network path (corp proxy, malicious mirror, BGP\n"
        "# hijack) MITMs the registry and ships malicious tarballs that npm\n"
        "# installs with no signal.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: install\n"
        "    spec:\n"
        "      image: node@sha256:...\n"
        "      command: |\n"
        "        npm config set strict-ssl false\n"
        "        npm install\n"
        "\n"
        "# Safe: install the missing CA into the image; never disable TLS\n"
        "# verification build-wide.\n"
        "      command: |\n"
        "        cp internal-ca.crt /usr/local/share/ca-certificates/\n"
        "        update-ca-certificates\n"
        "        npm install"
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if not text:
            continue
        hits = tls_bypass.scan(text)
        if hits:
            offenders.append(f"{step_label(stage_id, step)}: {hits[0].snippet[:80]}")
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
