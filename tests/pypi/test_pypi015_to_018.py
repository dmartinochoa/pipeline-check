"""Per-rule tests for PYPI-015..018.

PYPI-015 (direct artifact URL install),
PYPI-016 (primary --index-url repointed at a non-PyPI host),
PYPI-017 (remote --find-links source),
PYPI-018 (--no-binary forces the sdist build path).
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check

# ── PYPI-015 direct artifact URL ──────────────────────────────────────


class TestPYPI015:
    def test_fails_on_named_direct_url(self):
        text = (
            "mypkg @ https://downloads.example.com/"
            "mypkg-1.0-py3-none-any.whl\n"
        )
        f = run_check(text, "PYPI-015")
        assert not f.passed
        # The finding echoes the offending artifact so a reviewer can
        # find it. Assert on the wheel filename, not the host substring
        # (a host-in-string check trips CodeQL's url-sanitization query).
        assert "mypkg-1.0-py3-none-any.whl" in f.description

    def test_fails_on_bare_tarball_url(self):
        text = "https://files.example.org/foo-2.0.tar.gz\n"
        f = run_check(text, "PYPI-015")
        assert not f.passed

    def test_passes_with_inline_hash(self):
        text = (
            "mypkg @ https://downloads.example.com/mypkg-1.0.whl "
            "--hash=sha256:" + "a" * 64 + "\n"
        )
        f = run_check(text, "PYPI-015")
        assert f.passed

    def test_passes_on_pythonhosted_host(self):
        text = (
            "foo @ https://files.pythonhosted.org/packages/foo-1.0.whl\n"
        )
        f = run_check(text, "PYPI-015")
        assert f.passed

    def test_skips_vcs_url(self):
        # VCS direct URLs are PYPI-004's surface, not PYPI-015's.
        text = "foo @ git+https://github.com/o/r.git@main\n"
        f = run_check(text, "PYPI-015")
        assert f.passed

    def test_passes_on_plain_pinned_requirement(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-015")
        assert f.passed


# ── PYPI-016 primary index repointed ──────────────────────────────────


class TestPYPI016:
    def test_fails_on_repointed_index(self):
        text = "--index-url https://pypi.evil.example/simple\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-016")
        assert not f.passed
        # Assert the index option is echoed via its flag, not a host
        # substring (which trips CodeQL's url-sanitization query).
        assert "--index-url" in f.description

    def test_fails_on_short_flag(self):
        text = "-i https://mirror.evil.example/simple\n"
        f = run_check(text, "PYPI-016")
        assert not f.passed

    def test_passes_on_canonical_pypi(self):
        text = "--index-url https://pypi.org/simple\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-016")
        assert f.passed

    def test_passes_on_internal_mirror(self):
        text = "--index-url https://pypi.internal/simple\n"
        f = run_check(text, "PYPI-016")
        assert f.passed

    def test_passes_on_artifactory_host(self):
        text = "--index-url https://artifactory.example.com/api/pypi/simple\n"
        f = run_check(text, "PYPI-016")
        assert f.passed

    def test_does_not_fire_on_extra_index_url(self):
        # The additive vector is PYPI-005, not PYPI-016.
        text = "--extra-index-url https://other.example/simple\n"
        f = run_check(text, "PYPI-016")
        assert f.passed


# ── PYPI-017 remote find-links ────────────────────────────────────────


class TestPYPI017:
    def test_fails_medium_on_remote_https(self):
        text = "--find-links https://wheels.example.com/\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-017")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_escalates_high_with_no_index(self):
        text = (
            "--no-index\n--find-links https://wheels.example.com/\n"
            "requests==2.31.0\n"
        )
        f = run_check(text, "PYPI-017")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_escalates_high_on_http(self):
        text = "--find-links http://wheels.example.com/\n"
        f = run_check(text, "PYPI-017")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_passes_on_local_dir(self):
        text = "--find-links ./vendor/wheels\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-017")
        assert f.passed

    def test_passes_when_absent(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-017")
        assert f.passed


# ── PYPI-018 --no-binary sdist build ──────────────────────────────────


class TestPYPI018:
    def test_fails_on_no_binary_all(self):
        text = "--no-binary :all:\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-018")
        assert not f.passed

    def test_fails_on_no_binary_named(self):
        text = "--no-binary numpy\nnumpy==1.26.0\n"
        f = run_check(text, "PYPI-018")
        assert not f.passed
        assert "numpy" in f.description

    def test_passes_on_only_binary(self):
        # The safer direction must not fire.
        text = "--only-binary :all:\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-018")
        assert f.passed

    def test_passes_when_absent(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-018")
        assert f.passed
