"""HARNESS-005. Step pipes a remote download into a shell interpreter."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text, step_label

RULE = Rule(
    id="HARNESS-005",
    title="Step pipes a remote download into a shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-78"),
    recommendation=(
        "Replace every ``curl ... | sh`` / ``wget ... | bash`` pattern in "
        "a Run step ``command`` with a download-verify-execute flow: "
        "download the artifact to disk (``curl -fsSL -o installer.sh "
        "<url>``), verify a known-good checksum against the file "
        "(``echo \"<sha256>  installer.sh\" | sha256sum -c -``), and only "
        "then run it (``sh installer.sh``). The pipe-to-shell pattern "
        "executes whatever bytes the URL serves at run time with the step "
        "container's privileges and secrets, so a network MITM, a "
        "compromised mirror, or a brief upstream takeover injects arbitrary "
        "code into the build with no verification step."
    ),
    docs_note=(
        "Walks every step's ``spec.command`` text and fires on the "
        "canonical pipe-to-shell shapes (``curl ... | sh`` / ``| bash``, "
        "``wget ... -O - | sh``, ``fetch ... | sh``), allowing arbitrary "
        "intermediate flags so ``curl -fsSL <url> | sh -s -- --foo`` still "
        "matches. The download-then-execute form (``curl <url> -o f && sh "
        "f``) is NOT caught: the file lands on disk first, leaving room for "
        "a checksum-verify step. Same model as DR-014 / GHA-016 / BK-017 / "
        "TKN-008 across providers."
    ),
    known_fp=(
        "Some vendor install scripts (rustup, nvm) ship pipe-to-shell as "
        "the canonical path. The rule fires anyway, since upstream "
        "reputation doesn't remove the MITM / compromised-domain risk. "
        "Suppress per step with a rationale naming the upstream.",
    ),
    incident_refs=(
        "Codecov bash uploader (April 2021): downstream builds using "
        "``curl -fsSL https://codecov.io/bash | bash`` shipped a tampered "
        "uploader for two months. https://about.codecov.io/security-update/",
    ),
    exploit_example=(
        "# Vulnerable: the install script is executed as it downloads.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: install\n"
        "    spec:\n"
        "      image: alpine@sha256:...\n"
        "      command: curl -fsSL https://example.com/install.sh | sh\n"
        "\n"
        "# Safe: download, verify a pinned checksum, then execute.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: install\n"
        "    spec:\n"
        "      image: alpine@sha256:...\n"
        "      command: |\n"
        "        curl -fsSL -o installer.sh https://example.com/install.sh\n"
        "        echo \"a3f2...  installer.sh\" | sha256sum -c -\n"
        "        sh installer.sh"
    ),
)

# ``curl|sh`` / ``wget|bash`` with arbitrary intermediate flags; mirrors
# DR-014's pattern. Requires a pipe directly into ``sh`` / ``bash``.
_PIPE_RE = re.compile(
    r"(?:curl|wget|fetch)\s+[^|]+\|\s*(?:sh|bash)(?:\s|$)",
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if text and _PIPE_RE.search(text):
            offenders.append(step_label(stage_id, step))
    passed = not offenders
    desc = (
        "No step pipes a remote download into a shell."
        if passed else
        f"{len(offenders)} step(s) pipe a remote download into a shell "
        f"(curl|sh / wget|bash): {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. The pattern runs whatever "
        f"bytes the URL serves; download, verify a checksum, then execute."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
