"""HARNESS-001. Step image not pinned to a digest."""
from __future__ import annotations

from ..._primitives.image_pinning import PinKind, classify
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_label, step_spec

RULE = Rule(
    id="HARNESS-001",
    title="Step image not pinned to a digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-IMMUTABLE",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin every step ``image:`` to ``@sha256:<digest>``. Harness "
        "resolves the image ref at run time, so a tag like ``node:18`` "
        "resolves against whatever the registry currently serves, and a "
        "compromised registry (or a moved tag) can swap content under a "
        "fixed tag. Capture the digest once with ``crane digest node:18`` "
        "(or ``docker buildx imagetools inspect node:18``) and bump it "
        "deliberately when the upstream version moves."
    ),
    docs_note=(
        "Detection mirrors the DR-001 / GL-001 / CC-003 family over "
        "Harness's nested step model: every ``Run`` / ``Plugin`` / "
        "``Background`` (and any custom) step that declares a "
        "``spec.image`` whose ref does not end in ``@sha256:<64 hex>`` "
        "fires, across CI and CD stages and through ``parallel`` / "
        "``stepGroup`` nesting. Steps with no ``spec.image`` (built-in "
        "steps like ``BuildAndPushDockerRegistry`` / ``RestoreCacheS3``) "
        "pass-by-default. ``:latest`` and missing-tag refs emit the "
        "strongest message; a version tag (``node:18.19.0``) still fires "
        "but is a one-line digest swap."
    ),
    known_fp=(
        "An image built earlier in the same pipeline and referenced by a "
        "deliberately-floating internal tag can't always be digest-pinned. "
        "Suppress via an ignore-file scoped to that step; the floating-tag "
        "risk still applies to every public-registry pull.",
    ),
    exploit_example=(
        "# Vulnerable: ``node:18`` is a mutable tag. The registry (or a\n"
        "# compromise of the publisher) repoints it on the next 18.x patch\n"
        "# and the next pipeline run pulls the swap silently.\n"
        "pipeline:\n"
        "  identifier: build\n"
        "  stages:\n"
        "    - stage:\n"
        "        identifier: ci\n"
        "        type: CI\n"
        "        spec:\n"
        "          execution:\n"
        "            steps:\n"
        "              - step:\n"
        "                  type: Run\n"
        "                  identifier: test\n"
        "                  spec:\n"
        "                    image: node:18\n"
        "                    command: npm test\n"
        "\n"
        "# Safe: pin to the content-addressable digest.\n"
        "                    image: node@sha256:abc123..."
    ),
)


def _classify_image(image: object) -> PinKind:
    if not isinstance(image, str) or not image.strip():
        # No image declared on this step: not this rule's concern.
        return PinKind.DIGEST
    return classify(image.strip())


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        image = step_spec(step).get("image")
        if _classify_image(image) != PinKind.DIGEST:
            offenders.append(f"{step_label(stage_id, step)}={image}")
    passed = not offenders
    desc = (
        "Every step image is pinned to ``@sha256:<digest>``."
        if passed else
        f"{len(offenders)} step(s) reference an unpinned image: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
