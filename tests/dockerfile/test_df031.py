"""Tests for DF-031 (COPY --from external image not digest-pinned)."""
from __future__ import annotations

from .conftest import run_check

_DIGEST = "@sha256:0000000000000000000000000000000000000000000000000000000000000001"


class TestDF031CopyFromExternalImageUnpinned:
    def test_fails_on_tagged_external_image(self):
        f = run_check(
            f"FROM gcr.io/distroless/static{_DIGEST}\n"
            "COPY --from=sigstore/cosign:latest /ko-app/cosign /usr/local/bin/cosign\n",
            "DF-031",
        )
        assert not f.passed
        assert "cosign" in f.description

    def test_fails_on_floating_external_image(self):
        f = run_check(
            f"FROM alpine{_DIGEST}\n"
            "COPY --from=ghcr.io/org/tools /t /t\n",
            "DF-031",
        )
        assert not f.passed

    def test_passes_on_named_stage(self):
        f = run_check(
            f"FROM alpine{_DIGEST} AS builder\n"
            "RUN echo hi\n"
            f"FROM alpine{_DIGEST}\n"
            "COPY --from=builder /app /app\n",
            "DF-031",
        )
        assert f.passed

    def test_passes_on_numeric_stage_index(self):
        f = run_check(
            f"FROM alpine{_DIGEST}\n"
            "COPY --from=0 /app /app\n",
            "DF-031",
        )
        assert f.passed

    def test_passes_on_digest_pinned_external_image(self):
        f = run_check(
            f"FROM alpine{_DIGEST}\n"
            f"COPY --from=sigstore/cosign{_DIGEST} /c /c\n",
            "DF-031",
        )
        assert f.passed

    def test_passes_on_bare_build_context_name(self):
        # A bare name (no registry / tag / digest separator) is a build
        # stage or a --build-context name, not an external image ref.
        f = run_check(
            f"FROM alpine{_DIGEST}\n"
            "COPY --from=mycontext /a /a\n",
            "DF-031",
        )
        assert f.passed

    def test_passes_without_copy_from(self):
        f = run_check(
            f"FROM alpine{_DIGEST}\n"
            "COPY . /app\n",
            "DF-031",
        )
        assert f.passed
