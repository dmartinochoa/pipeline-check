"""Extract canonical :class:`ResourceAnchor` ``oci_image`` entries from rule input.

The cross-provider chain engine (AC-005) intersects findings on
the ``oci_image`` kind so a build-side workflow that pushes an
image and a deploy-side workflow that consumes one can match when
they name the same canonical identity. This module concentrates
the extraction logic so every rule that contributes to AC-005
goes through one helper and the producer / consumer sides
mechanically agree on what counts as an image reference.

Two extraction strategies, in priority order:

1. **Structured**: walk every ``uses: docker/build-push-action`` /
   ``uses: docker/metadata-action`` step in a workflow and read its
   ``with.tags`` input directly. That's the canonical GHA build /
   tag-management pattern.
2. **Text scan**: walk every string in the doc and pull tokens that
   look like image references out of common deploy-tooling shell
   shapes (``docker push X``, ``docker pull X``, ``kubectl set image
   ...=X``, ``helm upgrade --set image=X``, ``--image=X`` on
   ``gcloud run deploy`` / ``az containerapp``).

Every candidate string is run through
:func:`pipeline_check.core.checks._primitives.anchors.oci_image`,
which validates the shape and applies the canonical form (strips
the tag / digest, normalizes implicit Docker Hub registries to
``docker.io/<repo>``, etc.). Tokens the canonicalizer rejects
drop on the floor — better than emitting a half-formed anchor
that silently misses a chain intersection.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..base import ResourceAnchor, walk_strings
from .anchors import oci_image

# ── Step-level structured extraction ──────────────────────────────

#: Build / metadata actions whose ``tags:`` input names the
#: image(s) the workflow pushes. Pinned at the prefix so the
#: action ref's ``@<sha>`` / ``@<tag>`` suffix doesn't matter.
_BUILD_ACTIONS: tuple[str, ...] = (
    "docker/build-push-action",
    "docker/metadata-action",
)


def _iter_action_tags(step: dict[str, Any]) -> Iterable[str]:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return ()
    action = uses.split("@", 1)[0].lower()
    if not any(action.startswith(prefix) for prefix in _BUILD_ACTIONS):
        return ()
    with_block = step.get("with") or {}
    if not isinstance(with_block, dict):
        return ()
    tags = with_block.get("tags")
    out: list[str] = []
    if isinstance(tags, str):
        # Multi-line strings are how docker/build-push-action
        # advertises multiple tags — one tag per non-empty line.
        for line in tags.splitlines():
            line = line.strip()
            if line:
                out.append(line)
    elif isinstance(tags, list):
        for item in tags:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
    return out


# ── Text-scan deploy / runtime mentions ───────────────────────────

# Token shape: <host?>[/<path>]*[<repo>][:<tag>][@<digest>]. We
# require either a "." in the first component (registry hostname),
# a registry-port shape, or a "/" in the path so we don't match
# bare words like ``latest``. Tokens captured here are validated
# by oci_image() so the regex only needs to be a coarse pre-filter.
_IMAGE_TOKEN_RE = re.compile(
    r"\b("
    r"(?:[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\.[a-zA-Z0-9._-]+|:\d+))"
    r"(?:/[a-zA-Z0-9._-]+)+"
    r"(?::[a-zA-Z0-9._-]+)?"
    r"(?:@sha[0-9]+:[a-fA-F0-9]+)?"
    r")"
)

# Shell verbs that name an image in their argument list. We pull
# the image token that appears right after the verb (not in the
# tag/build flags), letting ``_IMAGE_TOKEN_RE`` narrow it.
_DEPLOY_CMD_RE = re.compile(
    r"\b(?:"
    r"docker\s+(?:push|pull|tag)"
    r"|kubectl\s+set\s+image"
    r"|helm\s+(?:upgrade|install)"
    r"|gcloud\s+run\s+deploy"
    r"|az\s+containerapp"
    r"|aws\s+ecs\s+update-service"
    r")\b[^\n]*",
    re.IGNORECASE,
)


def _candidates_from_text(text: str) -> list[str]:
    """Pull image-ref-shaped tokens out of *text* — coarse filter."""
    out: list[str] = []
    for line_match in _DEPLOY_CMD_RE.finditer(text):
        line = line_match.group(0)
        for m in _IMAGE_TOKEN_RE.finditer(line):
            out.append(m.group(1))
    return out


# ── Public API ────────────────────────────────────────────────────


def extract_image_anchors_from_workflow(
    doc: dict[str, Any],
) -> tuple[ResourceAnchor, ...]:
    """Walk a GHA workflow doc and return canonical ``oci_image`` anchors.

    Captures images named by:

    - ``docker/build-push-action`` / ``docker/metadata-action`` step
      ``with.tags`` inputs (structured form).
    - Deploy-shaped shell commands inside ``run:`` blocks
      (``docker push``, ``kubectl set image``, ``helm upgrade``,
      ``gcloud run deploy``, ``az containerapp``, ``aws ecs
      update-service``).

    De-duplicates by canonical identity, returns in insertion order.
    """
    from ..github.base import iter_jobs, iter_steps
    seen: dict[str, ResourceAnchor] = {}
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            # Structured: docker/build-push-action tags
            for raw in _iter_action_tags(step):
                built = oci_image(raw)
                if built is not None:
                    seen[built.identity] = built
            # Text scan over the step's ``run:`` body, where deploy
            # commands typically live.
            run = step.get("run")
            if isinstance(run, str):
                for raw in _candidates_from_text(run):
                    built = oci_image(raw)
                    if built is not None:
                        seen[built.identity] = built
    return tuple(seen.values())


def extract_image_anchors_from_strings(
    doc: Any,
) -> tuple[ResourceAnchor, ...]:
    """Generic fallback for non-GHA shapes — walks every string in *doc*.

    Used by leg rules whose context isn't a GHA workflow dict and
    so can't use the structured extractor (Cloud Build, Helm
    chart, GitLab CI, etc.). Same canonicalization pipeline.
    """
    seen: dict[str, ResourceAnchor] = {}
    for s in walk_strings(doc):
        for raw in _candidates_from_text(s):
            built = oci_image(raw)
            if built is not None:
                seen[built.identity] = built
    return tuple(seen.values())


__all__ = [
    "extract_image_anchors_from_workflow",
    "extract_image_anchors_from_strings",
]
