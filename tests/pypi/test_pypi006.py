"""Per-rule tests for PYPI-006 (compromised-package registry lookup)."""

from pipeline_check.core.checks.pypi._compromised_packages import (
    known_names,
    lookup,
    registry_size,
)

from .conftest import run_check

# ── Registry data layer ───────────────────────────────────────────────


class TestCompromisedRegistry:
    def test_registry_is_non_empty(self):
        assert registry_size() >= 2

    def test_known_names_include_canonical_incidents(self):
        names = known_names()
        assert "ctx" in names
        assert "requests-darwin-lite" in names

    def test_lookup_hits_ctx(self):
        hit = lookup("ctx", "0.2.2")
        assert hit is not None
        assert "ctx" in hit.advisory

    def test_lookup_misses_clean_ctx_version(self):
        # The clean republish (if any) — registry should not flag
        # arbitrary later versions.
        assert lookup("ctx", "0.3.0") is None

    def test_lookup_is_pep503_normalized(self):
        # ``Requests-Darwin-Lite`` and ``requests_darwin_lite`` and
        # ``requests.darwin.lite`` all normalize to the same name.
        assert lookup("Requests-Darwin-Lite", "2.27.1") is not None
        assert lookup("requests_darwin_lite", "2.27.1") is not None
        assert lookup("requests.darwin.lite", "2.27.1") is not None

    def test_lookup_misses_unknown_package(self):
        assert lookup("requests", "2.31.0") is None


# ── Rule behavior ─────────────────────────────────────────────────────


class TestPYPI006:
    def test_fails_on_pinned_ctx(self):
        text = "ctx==0.2.2\n"
        f = run_check(text, "PYPI-006")
        assert not f.passed
        assert "ctx==0.2.2" in f.description

    def test_fails_with_pep503_variant_in_file(self):
        # The file writes ``CTX_PKG`` (silly but valid) — wait, no:
        # ctx is a literal name. The PEP 503 normalization is for the
        # lookup side. Let's exercise it with an underscore.
        text = "requests_darwin_lite==2.27.1\n"
        f = run_check(text, "PYPI-006")
        assert not f.passed

    def test_passes_on_clean_versions(self):
        text = "requests==2.31.0\ndjango==4.2.7\n"
        f = run_check(text, "PYPI-006")
        assert f.passed

    def test_skips_unpinned_lines(self):
        # Without ``==``, the line has no decidable version. PYPI-006
        # passes (PYPI-001 catches unpinned lines).
        text = "ctx\n"
        f = run_check(text, "PYPI-006")
        assert f.passed

    def test_skips_vcs_url(self):
        text = "ctx @ git+https://github.com/o/r.git@deadbeef\n"
        f = run_check(text, "PYPI-006")
        assert f.passed

    def test_handles_extras_and_markers(self):
        text = (
            "ctx[extra]==0.2.2; python_version >= '3.10'\n"
        )
        f = run_check(text, "PYPI-006")
        assert not f.passed
        assert "Advisory:" in f.description
