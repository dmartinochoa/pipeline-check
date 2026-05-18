"""Container-image pin-classification primitive.

Several providers (GitLab, Azure DevOps, CircleCI, Jenkins) ship a
near-identical pair of regexes for deciding whether an ``image:``
reference is pinned to a digest, a specific tag, or a floating
tag. The shape of that decision is provider-independent, only the
*display* of the unpinned reason differs, so the regexes and the
classifier live here, and per-provider rules adapt the resulting
:class:`PinKind` into their own prose.

This is a stricter classifier than ``container_image.classify()``.
That primitive is targeted at AWS-managed / digest / trusted-registry
detection (used by AWS / Terraform / CloudFormation rules), where a
plain version tag is treated as ``pinned``. Here a tag like ``:3``
or ``:latest`` is a finding, so the two callers serve different
checks and shouldn't be conflated.

Structural decomposition (registry / repo / tag / digest) lives in
:mod:`image_ref`. The module-level ``DIGEST_RE`` / ``VERSION_TAG_RE``
regexes are kept as a stable export — four provider ``_helpers.py``
modules re-export them by identity (``is``) and a test in
``tests/test_primitives.py`` locks that contract — but the classifier
itself reads from :class:`ImageRef`.
"""
from __future__ import annotations

import re
from enum import Enum

from .image_ref import parse_image_ref

#: Trailing ``@sha256:<64 hex>`` digest pin. Kept as a public regex
#: so the four provider ``_helpers.py`` modules can re-export the
#: identical object. New code should call :func:`classify` directly.
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

#: Final ``:tag`` segment that contains at least one digit. Used to
#: distinguish version-shaped tags (``:3.12.1``) from floating ones
#: (``:latest``, ``:stable``).
VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")


class PinKind(str, Enum):
    """How tightly an image reference is pinned."""
    #: ``…@sha256:<hex>``, fully immutable.
    DIGEST = "digest"
    #: ``:3.12.1-slim``, specific version tag, no digest.
    PINNED_TAG = "pinned_tag"
    #: Bare reference, no ``:tag`` suffix.
    NO_TAG = "no_tag"
    #: ``:latest``, ``:3``, ``:stable``, mutable tag.
    FLOATING = "floating"


def classify(ref: str) -> PinKind:
    """Classify an image reference's pin tightness.

    The algorithm matches the duplicated provider logic exactly:

    1. ``@sha256:<hex>`` → :attr:`PinKind.DIGEST`
    2. last path segment has no ``:`` → :attr:`PinKind.NO_TAG`
    3. tag is ``latest`` or contains no digit → :attr:`PinKind.FLOATING`
    4. otherwise → :attr:`PinKind.PINNED_TAG`
    """
    parsed = parse_image_ref(ref)
    if parsed is None:
        # Empty / non-string. The legacy behavior returned NO_TAG
        # (the first conditional would fall through), so preserve
        # that — calling rules treat it as unpinned without
        # downgrading severity for a malformed empty value.
        return PinKind.NO_TAG
    if parsed.is_digest_pinned:
        return PinKind.DIGEST
    if not parsed.tag:
        return PinKind.NO_TAG
    if parsed.is_floating_tag:
        return PinKind.FLOATING
    return PinKind.PINNED_TAG
