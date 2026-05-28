"""DR-014. Step pipes a remote download into a shell interpreter."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_steps,
    step_commands,
    step_label,
    step_location,
)

RULE = Rule(
    id="DR-014",
    title="Step pipes a remote download into a shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-78"),
    recommendation=(
        "Replace every ``curl ... | sh`` / ``wget ... | bash`` "
        "pattern with a two-step download-and-verify flow:\n\n"
        "1. Download the artifact to disk:\n"
        "   ``curl -fsSL -o installer.sh https://example.com/install.sh``\n"
        "2. Verify a known-good checksum or signature against the "
        "downloaded file:\n"
        "   ``echo \"<expected-sha256>  installer.sh\" | sha256sum -c -``\n"
        "3. Only then execute: ``sh installer.sh``.\n\n"
        "The pipe-to-shell pattern executes whatever bytes the "
        "URL serves at download time, with the step container's "
        "privileges. A network MITM, a compromised mirror, or "
        "an attacker who briefly takes over the upstream domain "
        "drops arbitrary code into the build with no verification "
        "step. Pinning the download to an exact version + "
        "checksum closes the gap. Mirrors GHA-016 / BK-017 / "
        "TKN-008 across providers."
    ),
    docs_note=(
        "Walks every ``commands:`` array on every step and "
        "fires on shell snippets matching one of the canonical "
        "pipe-to-shell shapes:\n\n"
        "* ``curl ... | sh``\n"
        "* ``curl ... | bash``\n"
        "* ``wget ... -O - | sh``\n"
        "* ``wget ... | bash``\n"
        "* ``fetch ... | sh`` (BSD variant)\n\n"
        "Pattern recognition allows arbitrary intermediate "
        "flags so ``curl -fsSL <url> | sh -s -- --version=foo`` "
        "still matches. Plain ``curl <url> > installer.sh && "
        "sh installer.sh`` is NOT caught — the file lands on "
        "disk first, which means a checksum-verify step can be "
        "inserted between download and execution."
    ),
    known_fp=(
        "Some vendor-published install scripts (rustup, nvm, "
        "brew install scripts) ship pipe-to-shell as the "
        "canonical install path. The rule fires anyway because "
        "the upstream's reputation doesn't eliminate the "
        "MITM / compromised-domain class of risk. Suppress per "
        "step with a one-line rationale naming the upstream "
        "and the operator's awareness of the unverified-pull "
        "posture.",
    ),
    incident_refs=(
        "Codecov bash uploader (April 2021): downstream builds "
        "using ``curl -fsSL https://codecov.io/bash | bash`` "
        "shipped a tampered uploader for two months. Every CI "
        "system without pipe-to-shell detection inherited the "
        "compromise; the audit trail relied on the bash "
        "scripts' own logging, which the malicious modification "
        "could and did suppress. "
        "https://about.codecov.io/security-update/",
    ),
    exploit_example=(
        "# Vulnerable: pipe-to-shell.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: install-tooling\n"
        "    image: alpine:3.19@sha256:abc...\n"
        "    commands:\n"
        "      - curl -fsSL https://example.com/install.sh | sh\n"
        "\n"
        "# Attack: example.com is compromised. The install.sh\n"
        "# served on the next build is a backdoored version; it\n"
        "# runs with the step container's privileges and any\n"
        "# secrets the step has access to.\n"
        "\n"
        "# Safe: download, verify, then execute.\n"
        "steps:\n"
        "  - name: install-tooling\n"
        "    image: alpine:3.19@sha256:abc...\n"
        "    commands:\n"
        "      - curl -fsSL -o installer.sh https://example.com/install.sh\n"
        "      - echo \"a3f2c5e3b8e0d4a5...installer.sh\" | sha256sum -c -\n"
        "      - sh installer.sh\n"
    ),
)


# Match ``curl ... | sh`` and ``wget ... | bash`` patterns. The
# regex allows arbitrary intermediate flags / arguments after curl
# or wget but requires a pipe directly into ``sh`` or ``bash``
# (with optional trailing args).
_PIPE_RE = re.compile(
    r"(?:curl|wget|fetch)\s+[^|]+\|\s*(?:sh|bash)(?:\s|$)",
)


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline type {pipeline.data.get('type')!r} has no "
                f"shell commands to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations = []
    for idx, step in iter_steps(pipeline):
        for cmd in step_commands(step):
            if _PIPE_RE.search(cmd):
                name = step_label(step, idx)
                offenders.append(f"{name}: {cmd.strip()[:60]}")
                locations.append(step_location(pipeline.path, step))
                break
    passed = not offenders
    desc = (
        f"No pipe-to-shell patterns across {pipeline.path}."
        if passed else
        f"{len(offenders)} step(s) pipe a remote download into "
        f"a shell: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. The pattern "
        f"executes whatever bytes the URL serves; a network MITM "
        f"or a compromised upstream drops arbitrary code into "
        f"the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
