"""DR-005. Plugin step uses a floating image tag."""
from __future__ import annotations

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    is_plugin_step,
    iter_steps,
    step_label,
)

RULE = Rule(
    id="DR-005",
    title="Plugin step uses a floating image tag",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-IMMUTABLE", "ESF-D-RUNTIME-HARDENING"),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every plugin step's ``image:`` to ``@sha256:"
        "<digest>`` or, at minimum, a specific version tag "
        "(``plugins/docker:20.13.0`` rather than ``plugins/"
        "docker:latest`` or ``plugins/docker``). Plugin steps "
        "are a sharper attack surface than ordinary steps "
        "because Drone passes every ``settings:`` key to the "
        "plugin as an environment variable, including any "
        "secret references; a malicious plugin replacement can "
        "exfiltrate the entire credential set the step was "
        "trusted with."
    ),
    docs_note=(
        "Drone treats a step as a plugin when it has a "
        "``settings:`` block. The ``image:`` field still names "
        "the container that runs, and the same supply-chain "
        "argument as DR-001 applies; this rule fires "
        "specifically on plugin steps using a floating tag "
        "(``:latest``, no tag, or a non-version-shaped tag) "
        "rather than every unpinned image, so a maintainer "
        "weighing trade-offs can ratchet plugin pinning up "
        "first. A pinned-version tag (``plugins/docker:20.13.0``) "
        "passes this rule but still trips DR-001 for the wider "
        "supply-chain hardening."
    ),
    known_fp=(
        "Internal-registry plugins built and pushed by the "
        "same pipeline (``image: my-org/internal-plugin:dev`` "
        "produced upstream) sometimes can't be exact-pinned. "
        "Suppress via ignore-file scoped to the specific step "
        "name when this is the deliberate shape.",
    ),
    exploit_example=(
        "# Vulnerable: ``plugins/docker:latest`` resolves at runner\n"
        "# start to whatever Docker Hub currently serves under the\n"
        "# ``latest`` tag. Whoever controls the plugin repo (or\n"
        "# anyone with publisher access) ships code into every\n"
        "# pipeline that uses the plugin.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: publish\n"
        "steps:\n"
        "  - name: push-image\n"
        "    image: plugins/docker:latest\n"
        "    settings:\n"
        "      repo: myorg/app\n"
        "      tags: latest\n"
        "\n"
        "# Safe: pin the plugin image to a content-addressable\n"
        "# digest. The plugin can't be repointed without changing\n"
        "# the pipeline file (and a reviewable PR with it).\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: publish\n"
        "steps:\n"
        "  - name: push-image\n"
        "    image: plugins/docker@sha256:abc123...\n"
        "    settings:\n"
        "      repo: myorg/app\n"
        "      tags: ${DRONE_TAG}"
    ),
)


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored; "
                "plugin pinning does not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        if not is_plugin_step(step):
            continue
        image = step.get("image")
        if not isinstance(image, str) or not image.strip():
            continue
        kind = classify(image.strip())
        # Acceptable for this rule: digest or pinned version tag.
        # Floating / no-tag is a finding.
        if kind in (PinKind.FLOATING, PinKind.NO_TAG):
            offenders.append(
                f"steps.{step_label(step, idx)}={image}"
            )
    passed = not offenders
    desc = (
        "Every plugin step uses a pinned version tag or digest."
        if passed else
        f"{len(offenders)} plugin step(s) use a floating image "
        f"tag: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
