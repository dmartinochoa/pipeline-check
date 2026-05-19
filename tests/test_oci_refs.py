"""Unit tests for the OCI image-token pre-filter.

The cross-provider chain engine pre-filters strings with
``_IMAGE_TOKEN_RE`` before handing them to
:func:`pipeline_check.core.checks._primitives.anchors.oci_image`.
These tests pin both ends of the trade-off the pre-filter has to
make: it must accept the implicit-registry forms Docker Hub
publishes against (``myorg/app:1.2``, ``library/redis:7.0``) and
the explicit-host forms every other registry uses, while still
rejecting bare words that happen to appear inside ``run:`` blocks.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._primitives.anchors import oci_image
from pipeline_check.core.checks._primitives.oci_refs import (
    _IMAGE_TOKEN_RE,
    _candidates_from_text,
)


class TestImageTokenRegex:
    @pytest.mark.parametrize(
        "ref,expected_canonical",
        [
            # Implicit-registry (Docker Hub) forms.
            ("myorg/app:1.2", "docker.io/myorg/app"),
            ("library/redis:7.0", "docker.io/library/redis"),
            ("myorg/app/sub:1.0", "docker.io/myorg/app/sub"),
            # Explicit-registry forms.
            ("docker.io/myorg/app:1.0", "docker.io/myorg/app"),
            ("gcr.io/foo:1.0", "gcr.io/foo"),
            ("gcr.io/foo/bar:1.0", "gcr.io/foo/bar"),
            ("localhost:5000/foo:1.0", "localhost:5000/foo"),
            (
                "123.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
                "123.dkr.ecr.us-east-1.amazonaws.com/repo",
            ),
            # Digest forms.
            ("gcr.io/team/svc@sha256:abc123def456", "gcr.io/team/svc"),
        ],
    )
    def test_matched_tokens_canonicalize(self, ref: str, expected_canonical: str) -> None:
        m = _IMAGE_TOKEN_RE.search(ref)
        assert m is not None, ref
        assert m.group(0) == ref
        anchor = oci_image(m.group(0))
        assert anchor is not None
        assert anchor.identity == expected_canonical

    @pytest.mark.parametrize(
        "noise",
        [
            # Bare words must stay out — pre-filter avoids
            # treating tag-like or env-like tokens as image refs.
            "latest",
            "python",
            "redis",
            "$IMAGE",
            "FROM",
        ],
    )
    def test_bare_words_do_not_match(self, noise: str) -> None:
        assert _IMAGE_TOKEN_RE.search(noise) is None

    def test_implicit_ref_in_docker_push_line(self) -> None:
        # Real-world shape: ``docker push myorg/app:1.2`` in a
        # workflow's ``run:`` block. Before the regex relaxation
        # the implicit-registry ref was silently dropped, costing
        # AC-005 match accuracy.
        cands = _candidates_from_text("docker push myorg/app:1.2")
        assert cands == ["myorg/app:1.2"]
        anchor = oci_image(cands[0])
        assert anchor is not None
        assert anchor.identity == "docker.io/myorg/app"
