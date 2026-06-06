"""DR-001. Step image not pinned to a digest."""
from __future__ import annotations

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_services,
    iter_steps,
    step_label,
)

RULE = Rule(
    id="DR-001",
    title="Step image not pinned to a digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-IMMUTABLE",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin every step ``image:`` (and every ``services:`` "
        "image) to ``@sha256:<digest>``. Drone resolves the image "
        "ref at run time, so a tag like ``golang:1.21`` resolves "
        "against whatever the registry currently serves and a "
        "compromised registry can swap content under a fixed "
        "tag. Capture the digest once with ``docker buildx "
        "imagetools inspect golang:1.21`` (or "
        "``crane digest golang:1.21``) and update the digest "
        "deliberately when the upstream version moves."
    ),
    docs_note=(
        "Detection mirrors the GL-001 / JF-009 / ADO-009 / "
        "CC-003 family: any container ``image:`` whose ref "
        "doesn't end "
        "in ``@sha256:<64 hex>`` fires. ``:latest`` and missing-"
        "tag references emit the strongest message; a "
        "specific-version tag (``golang:1.21.5``) still fires "
        "but can be fixed with a one-line digest swap. The rule "
        "scopes itself to ``type: docker`` / ``kubernetes`` "
        "pipelines (the container-flavored ones); ``ssh`` / "
        "``exec`` / ``digitalocean`` pipelines have no "
        "``image:`` field and pass-by-default."
    ),
    known_fp=(
        "Local-build images (``image: my-org/build-tools:dev`` "
        "produced upstream in the same pipeline) sometimes "
        "can't be digest-pinned because the digest depends on "
        "the build. Suppress via ignore-file scoped to the "
        "specific step name when this is the deliberate shape; "
        "the floating-tag risk still applies to every public-"
        "registry pull.",
    ),
    exploit_example=(
        "# Vulnerable: ``golang:1.21`` is a mutable tag. Docker Hub\n"
        "# (or any compromise of the publisher's account) repoints\n"
        "# the tag at a new image on the next 1.21.x patch release\n"
        "# and the next pipeline run pulls the swap silently.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: test\n"
        "    image: golang:1.21\n"
        "    commands:\n"
        "      - go test ./...\n"
        "\n"
        "# Safe: pin to the content-addressable digest. Renovate /\n"
        "# Dependabot bump the digest in reviewable PRs.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: test\n"
        "    image: golang@sha256:abc123...\n"
        "    commands:\n"
        "      - go test ./..."
    ),
)


def _classify_image(image: str) -> PinKind:
    """Defensive wrapper, tolerate non-string image fields gracefully."""
    if not isinstance(image, str) or not image.strip():
        # An entirely missing ``image:`` is its own bug, but it
        # isn't this rule's bug, treat as pinned (NO finding) so
        # we don't double-fire with whatever later rule catches
        # the missing-image case.
        return PinKind.DIGEST
    return classify(image.strip())


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored "
                "(docker/kubernetes); image pinning does not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        kind = _classify_image(step.get("image", ""))
        if kind != PinKind.DIGEST:
            offenders.append(
                f"steps.{step_label(step, idx)}={step.get('image', '<missing>')}"
            )
    for idx, svc in iter_services(pipeline):
        kind = _classify_image(svc.get("image", ""))
        if kind != PinKind.DIGEST:
            offenders.append(
                f"services.{step_label(svc, idx, kind='services')}"
                f"={svc.get('image', '<missing>')}"
            )
    passed = not offenders
    desc = (
        "Every step / service image is pinned to ``@sha256:<digest>``."
        if passed else
        f"{len(offenders)} step(s) / service(s) reference an "
        f"unpinned image: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
