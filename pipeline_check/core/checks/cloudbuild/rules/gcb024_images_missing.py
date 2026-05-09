"""GCB-024. Build pushes Docker images but the top-level ``images:`` is empty.

Cloud Build's image-attestation flow (and the build-result UI's
"Images" column) only tracks images that are declared in the
top-level ``images:`` array. When a step does ``docker build`` +
``docker push`` but the build doesn't list the resulting image in
``images:``, the push still happens, the image lands in the
target registry, but Cloud Build records no provenance edge from
the build to the image. The Cloud Build → Cloud Logging
``image_url`` field stays empty, Binary Authorization can't
attest the image to this specific build, and the
``builds.list --image`` query returns nothing for the image.

Declaring the image in ``images:`` also tells Cloud Build to
verify the push completed successfully before marking the build
as SUCCESS. Without it, a step's ``docker push`` failure may not
fail the build.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="GCB-024",
    title="Build pushes Docker images but top-level images: is empty",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"),
    cwe=("CWE-1059",),
    recommendation=(
        "Add every image the build produces to the top-level "
        "``images:`` array (e.g. ``images: ['gcr.io/$PROJECT_ID/"
        "myapp:$COMMIT_SHA']``). Cloud Build then verifies the "
        "push succeeded before marking the build SUCCESS, records "
        "the image in the build's metadata for provenance / Binary "
        "Authorization attestation, and surfaces the image in the "
        "``builds.list --image`` query. Without it, a push that "
        "happens inside a step is invisible to Cloud Build's "
        "tracking layer even though the image still lands in the "
        "registry."
    ),
    docs_note=(
        "Walks step args / entrypoint / cmd looking for ``docker "
        "push`` (or the ``buildx imagetools push`` variant) "
        "invocations. When the build has at least one such step "
        "but the top-level ``images:`` field is missing or "
        "empty, fires. Steps that build *and* push via the "
        "``gcr.io/cloud-builders/docker`` builder image are the "
        "common case; ``--push`` flags on ``buildx build`` are "
        "also detected. ``kaniko`` and ``buildah`` push idioms "
        "aren't currently detected. Those are different builder "
        "images entirely."
    ),
    known_fp=(
        "Multi-stage builds where one step pushes an intermediate "
        "image to a private cache registry and the final stage "
        "pushes the production artifact (which IS in ``images:``) "
        "would trip this rule on the cache push. Suppress with "
        "``--ignore-file`` when this matches.",
    ),
)


#: Cloud Build's official docker builder. A step whose ``name:``
#: starts with this and whose first ``args:`` entry is ``push`` /
#: ``buildx`` is pushing an image.
_DOCKER_BUILDER_PREFIX = "gcr.io/cloud-builders/docker"

#: Fallback for shell-builder steps (``ubuntu``, ``alpine``) that
#: invoke docker via an inline script. ``step_strings`` returns
#: each arg individually, so the pattern needs to match a joined
#: string for the multi-token form.
_DOCKER_PUSH_BLOB_RE = re.compile(
    r"\bdocker(?:\s+buildx(?:\s+imagetools)?)?\s+push\b"
    r"|\bdocker\s+buildx\s+build\b[^|]*--push\b",
)


def _step_pushes_image(step: dict[str, Any]) -> bool:
    name = step.get("name")
    args = step.get("args")
    # Fast path: docker builder + ``push`` subcommand.
    if (
        isinstance(name, str)
        and name.startswith(_DOCKER_BUILDER_PREFIX)
        and isinstance(args, list)
        and len(args) >= 1
    ):
        first = args[0] if isinstance(args[0], str) else ""
        if first == "push":
            return True
        if first == "buildx":
            tail = [a for a in args[1:] if isinstance(a, str)]
            if "--push" in tail:
                return True
            if tail and tail[0] == "imagetools" and "push" in tail:
                return True
    # Shell-builder fallback: rejoin args and run the blob regex
    # over the combined text. Catches ``ubuntu`` / ``alpine``
    # builders whose script invokes docker.
    if isinstance(args, list):
        joined = " ".join(a for a in args if isinstance(a, str))
        if _DOCKER_PUSH_BLOB_RE.search(joined):
            return True
    return False


def _has_images_declared(doc: dict[str, Any]) -> bool:
    images = doc.get("images")
    if not isinstance(images, list):
        return False
    return any(isinstance(x, str) and x.strip() for x in images)


def check(path: str, doc: dict[str, Any]) -> Finding:
    pushers: list[str] = []
    for idx, step in iter_steps(doc):
        if _step_pushes_image(step):
            pushers.append(f"step[{idx}]")
    if not pushers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No step pushes a Docker image, nothing to declare.",
            recommendation=RULE.recommendation, passed=True,
        )
    if _has_images_declared(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Build pushes images and declares them in the "
                "top-level ``images:`` array."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            f"{len(pushers)} step(s) push Docker image(s) "
            f"({', '.join(pushers[:3])}{'…' if len(pushers) > 3 else ''}) "
            f"but the build's top-level ``images:`` array is empty / "
            f"missing. Cloud Build's image attestation only tracks "
            f"images declared there."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
