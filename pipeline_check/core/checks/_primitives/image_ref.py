"""Canonical parser for OCI / Docker image references.

A container image reference can name several distinct things,
spelled with overlapping punctuation:

  - ``alpine``                              implicit Docker Hub, implicit ``library/``
  - ``library/alpine:3.20``                 implicit Docker Hub, explicit namespace
  - ``ghcr.io/corp/builder:v1``             explicit registry, two-segment repo
  - ``registry.internal:5000/team/app:v1``  registry with port
  - ``python:3.11@sha256:<64 hex>``         tag and digest both present
  - ``aws/codebuild/standard:7.0``          AWS-managed shortform (no registry)

Three primitives previously decomposed this string for partial,
overlapping reasons:

  - ``anchors.oci_image()`` strips tag/digest to build the chain
    identity, with Docker Hub normalization.
  - ``container_image.classify()`` decides AWS-managed / digest /
    trusted-registry for AWS rules.
  - ``image_pinning.classify()`` decides pin tightness (digest /
    pinned_tag / no_tag / floating) for workflow rules.

Each carried its own ``@sha256:`` regex, its own registry heuristic,
and its own ``rpartition('/')`` dance. ``image_ref`` is the single
structural decomposition the three classifiers (and any rule that
needs raw fields like ``namespace``) build on. Domain verdicts stay
with their classifier; only the grammar lives here.

The parser is conservative. It returns ``None`` for input that
isn't string-shaped or is empty after a strip. It never raises.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ``@<algo>:<hex>`` boundary detector, case-insensitive on the hex
# so we can find the boundary even when the digest is malformed
# (uppercase). Validity of the digest is decided separately in
# :attr:`ImageRef.is_digest_pinned` — finding the boundary lets us
# strip the suffix from the repository path cleanly even when the
# digest itself is rejected.
_DIGEST_BOUNDARY_RE = re.compile(
    r"@(?P<algo>[a-z][a-z0-9]+):(?P<hex>[a-fA-F0-9]+)$"
)

# OCI spec mandates lowercase hex; uppercase is rejected per the
# engine invariant. Width is the algorithm's natural digest length
# (sha256 → 64, sha512 → 128).
_VALID_DIGEST_WIDTHS: dict[str, int] = {"sha256": 64, "sha512": 128}

# A version-shaped tag contains at least one digit somewhere. ``:3``,
# ``:3.12.1-slim``, ``:v1.2.3-rc.1`` all match. ``:latest``,
# ``:stable``, ``:edge`` do not, so :attr:`ImageRef.is_floating_tag`
# can flag them.
_VERSION_TAG_RE = re.compile(r"\d")

# Hostname heuristic: the first ``/``-separated component is treated
# as a registry IFF it contains a ``.`` or a ``:`` (port), or is the
# literal ``localhost``. Matches Docker's own parser, so
# ``library/redis`` stays a repo and ``registry.example.com/redis``
# becomes a registry host.
def _looks_like_host(component: str) -> bool:
    return "." in component or ":" in component or component == "localhost"


@dataclass(frozen=True, slots=True)
class ImageRef:
    """Structured form of an OCI / Docker image reference.

    Fields preserve the surface form, no Docker Hub injection.
    Use :attr:`canonical_registry` / :attr:`canonical_repository` when
    a consumer needs the normalized ``docker.io/library/...`` shape
    (chain anchoring, dedup across surface variants).

    ``digest_algo`` / ``digest_hex`` are filled when the input ends
    in ``@<algo>:<hex>``. ``is_digest_pinned`` further requires the
    algorithm to be one we trust (sha256 / sha512) and the hex to be
    lowercase and the correct width per OCI spec.
    """

    raw: str
    registry: str        # "" when no explicit registry (implicit Docker Hub or shortform)
    repository: str      # everything between registry and ``:tag``/``@digest``; may contain ``/``
    tag: str             # tag without the leading ``:``; "" when absent
    digest_algo: str     # "" when no ``@<algo>:<hex>`` suffix
    digest_hex: str      # "" when no ``@<algo>:<hex>`` suffix

    @property
    def is_digest_pinned(self) -> bool:
        """True iff the ref ends in a valid OCI digest.

        OCI spec: digest hex must be lowercase and exactly the
        algorithm's natural width (64 for sha256, 128 for sha512).
        Uppercase or wrong-width values are rejected — they're how
        a malformed pin sneaks past a casual regex match.
        """
        expected = _VALID_DIGEST_WIDTHS.get(self.digest_algo)
        if expected is None:
            return False
        return (
            len(self.digest_hex) == expected
            and self.digest_hex == self.digest_hex.lower()
        )

    @property
    def is_floating_tag(self) -> bool:
        """True iff the ref has a mutable tag (``latest`` / no digit).

        Used by the strict pin-tightness classifier. A bare ref
        (no tag) is not floating — it's a separate state. A
        digit-bearing tag (``:3.12.1``) is not floating either.
        """
        if not self.tag:
            return False
        if self.tag == "latest":
            return True
        return not _VERSION_TAG_RE.search(self.tag)

    @property
    def canonical_registry(self) -> str:
        """Docker Hub default injected when no explicit registry."""
        return self.registry or "docker.io"

    @property
    def canonical_repository(self) -> str:
        """``library/<name>`` injected for Docker Hub single-component repos."""
        if self.registry:
            return self.repository
        if "/" in self.repository:
            return self.repository
        return f"library/{self.repository}"


def parse_image_ref(value: Any) -> ImageRef | None:
    """Parse *value* into an :class:`ImageRef`, or ``None``.

    Accepts ``Any`` because callers fish image strings out of YAML
    mappings where the static type is ``Any | None``. Non-string
    input returns ``None``. Empty / whitespace-only input returns
    ``None``; classifiers handle the empty-ref case in their own
    domain (e.g. ``container_image`` treats it as ``pinned=True``
    because the rule has nothing to score against).
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    # Strip the ``@<algo>:<hex>`` suffix first. Digests contain both
    # ``@`` and ``:``, so they have to be peeled before any tag
    # splitting, otherwise a tag-split would chop in the wrong place.
    digest_algo = ""
    digest_hex = ""
    body = raw
    if (m := _DIGEST_BOUNDARY_RE.search(raw)) is not None:
        digest_algo = m.group("algo")
        digest_hex = m.group("hex")
        body = raw[: m.start()]

    # Distinguish registry from repository. The first component is a
    # registry only when it looks like a hostname (``.``, ``:``, or
    # ``localhost``). Single-component refs and Docker Hub shortforms
    # (``library/alpine``, ``aws/codebuild/standard``) leave registry
    # empty.
    first, sep, rest = body.partition("/")
    if sep and _looks_like_host(first):
        registry = first
        repo_and_tag = rest
    else:
        registry = ""
        repo_and_tag = body

    # The tag lives in the final path component (everything after the
    # last ``/``) so a registry-with-port (``registry.x:5000/repo``)
    # doesn't get mis-split here — the registry was already peeled.
    if not repo_and_tag:
        # ``host/`` with no repo, or empty after a digest strip. Treat
        # as malformed.
        return None
    last_slash = repo_and_tag.rfind("/")
    head, tail = (
        (repo_and_tag[: last_slash + 1], repo_and_tag[last_slash + 1:])
        if last_slash >= 0
        else ("", repo_and_tag)
    )
    if ":" in tail:
        name, _, tag = tail.partition(":")
        repository = f"{head}{name}"
    else:
        tag = ""
        repository = repo_and_tag

    if not repository:
        return None

    return ImageRef(
        raw=raw,
        registry=registry,
        repository=repository,
        tag=tag,
        digest_algo=digest_algo,
        digest_hex=digest_hex,
    )


__all__ = ["ImageRef", "parse_image_ref"]
