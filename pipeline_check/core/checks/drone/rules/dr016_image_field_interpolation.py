"""DR-016. Step image: field carries a Drone template substitution."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_services,
    iter_steps,
    step_label,
    step_location,
)

RULE = Rule(
    id="DR-016",
    title="Step image: field carries a Drone template substitution",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Replace the templated ``image:`` value with a literal "
        "digest-pinned reference. Drone expands "
        "``${DRONE_BUILD_*}``, ``${DRONE_COMMIT_*}``, and other "
        "build-context variables before the runner pulls the "
        "image — including variables that PR authors or "
        "promotion-script operators can influence "
        "(``DRONE_TAG``, ``DRONE_TARGET_BRANCH``, "
        "``DRONE_DEPLOY_TO``, custom promotion parameters). A "
        "contributor who controls one of those values can "
        "redirect the image fetch to an attacker-controlled "
        "registry / tag combination.\n\n"
        "If the build genuinely needs to swap images per "
        "environment, pin each variant explicitly and select "
        "via ``when:`` predicates:\n\n"
        "    steps:\n"
        "      - name: deploy-staging\n"
        "        image: myregistry/deploy:1.2.3@sha256:abc...\n"
        "        when: { branch: [staging] }\n"
        "      - name: deploy-prod\n"
        "        image: myregistry/deploy:1.2.3@sha256:def...\n"
        "        when: { branch: [main] }\n\n"
        "The literal image references are immutable; the "
        "``when:`` block controls execution without exposing "
        "the image identity to PR-controllable input."
    ),
    docs_note=(
        "Walks every ``image:`` field (steps + services) and "
        "fires when the value contains a ``${...}`` template "
        "expression. Drone resolves these against the pipeline's "
        "environment + build-context table before image pull, "
        "so any variable that's caller-controllable becomes an "
        "image-name injection primitive.\n\n"
        "Distinct from DR-001 (image not digest-pinned), which "
        "audits the immutability shape of the *resolved* image "
        "reference. This rule fires before that resolution can "
        "happen: a templated image is unauditable at scan time "
        "regardless of whether the resolution happens to land "
        "on a digest-pinned shape."
    ),
    known_fp=(
        "Some monorepo layouts use Drone template substitution "
        "to pick service-team-specific images "
        "(``image: ${SERVICE_TEAM}-base:1.0``). The rule fires "
        "regardless because the resolution-time substitution "
        "isn't auditable. Suppress per step / service with a "
        "rationale naming the substitution variable's "
        "trust source.",
    ),
    incident_refs=(
        "Image-name injection pattern: a Drone pipeline with "
        "``image: ${DRONE_DEPLOY_TO}-runner:latest`` is "
        "triggered via the Drone API with "
        "``DRONE_DEPLOY_TO=attacker.registry.example.com/`` — "
        "the resolved image is pulled from the attacker's "
        "registry and the runner executes attacker-controlled "
        "code. Documented as a real attack surface in audits "
        "of self-hosted Drone deployments with public API "
        "exposure.",
    ),
    exploit_example=(
        "# Vulnerable: image field templated against deploy-to.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: deploy\n"
        "steps:\n"
        "  - name: deploy\n"
        "    image: ${DRONE_DEPLOY_TO}-runner:latest\n"
        "    commands: [./deploy.sh]\n"
        "\n"
        "# Attack: someone who can trigger a deploy promotion\n"
        "# (any user with promotion permissions, or anyone who\n"
        "# can hit the Drone API) sets DRONE_DEPLOY_TO to a\n"
        "# value that resolves to an attacker registry. The next\n"
        "# build pulls and runs that image; the runner inherits\n"
        "# the build's secrets and write access.\n"
        "\n"
        "# Safe: pinned image, per-environment selection via\n"
        "# ``when:``.\n"
        "steps:\n"
        "  - name: deploy-staging\n"
        "    image: myregistry/deploy:1.2.3@sha256:abc...\n"
        "    when: { target: [staging] }\n"
        "  - name: deploy-prod\n"
        "    image: myregistry/deploy:1.2.3@sha256:def...\n"
        "    when: { target: [prod] }\n"
    ),
)


_TEMPLATE_RE = re.compile(r"\$\{[^}]+\}")


def _scan_container(
    name: str, container: dict[str, Any], offenders: list[str],
) -> None:
    image = container.get("image")
    if not isinstance(image, str):
        return
    if _TEMPLATE_RE.search(image):
        offenders.append(f"{name}: image={image!r}")


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline type {pipeline.data.get('type')!r} has "
                f"no image: fields to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations = []
    for idx, step in iter_steps(pipeline):
        before = len(offenders)
        _scan_container(step_label(step, idx), step, offenders)
        if len(offenders) > before:
            locations.append(step_location(pipeline.path, step))
    for idx, svc in iter_services(pipeline):
        before = len(offenders)
        _scan_container(
            step_label(svc, idx, kind="services"), svc, offenders,
        )
        if len(offenders) > before:
            locations.append(step_location(pipeline.path, svc))
    passed = not offenders
    desc = (
        f"No image: fields carry template substitutions across "
        f"{pipeline.path}."
        if passed else
        f"{len(offenders)} container(s) reference template-"
        f"expanded image names: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Caller-influenced "
        f"variables become image-name injection primitives at "
        f"pull time."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
