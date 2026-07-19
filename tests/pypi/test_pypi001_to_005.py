"""Per-rule tests for PYPI-001..005.

PYPI-001 (requirements line missing exact version pin),
PYPI-002 (requirements file missing hash pinning),
PYPI-003 (HTTP index / --trusted-host),
PYPI-004 (VCS dep without commit SHA),
PYPI-005 (--extra-index-url dependency-confusion).
"""
from __future__ import annotations

from .conftest import run_check

# ── PYPI-001 missing version pin ───────────────────────────────────────


class TestPYPI001:
    def test_fails_on_unpinned(self):
        text = "requests\n"
        f = run_check(text, "PYPI-001")
        assert not f.passed
        assert "requests" in f.description

    def test_fails_on_range(self):
        text = "django>=4,<5\n"
        f = run_check(text, "PYPI-001")
        assert not f.passed

    def test_fails_on_compatible(self):
        text = "urllib3~=2.0\n"
        f = run_check(text, "PYPI-001")
        assert not f.passed

    def test_passes_on_exact_pin(self):
        text = "requests==2.31.0\ndjango==4.2.7\n"
        f = run_check(text, "PYPI-001")
        assert f.passed

    def test_passes_on_exact_pin_with_whitespace(self):
        # PEP 440 permits whitespace between the operator and the
        # version (``pkg == 1.2.3``). The regex must consume it.
        text = "requests == 2.31.0\ndjango ==4.2.7\n"
        f = run_check(text, "PYPI-001")
        assert f.passed

    def test_passes_on_arbitrary_equality(self):
        # ``===`` is PEP 440 "arbitrary equality" — still a pin.
        text = "requests===2.31.0+local\n"
        f = run_check(text, "PYPI-001")
        assert f.passed

    def test_skips_vcs_url(self):
        text = "git+https://github.com/o/r.git@deadbeef\n"
        f = run_check(text, "PYPI-001")
        # No version-pin violation: VCS surface belongs to PYPI-004.
        assert f.passed

    def test_skips_editable_local(self):
        text = "-e .\n"
        f = run_check(text, "PYPI-001")
        assert f.passed

    def test_in_file_is_exempt(self):
        text = "requests\n"
        f = run_check(text, "PYPI-001", path="requirements.in")
        # pip-tools input is declarative; ranges are expected.
        assert f.passed


# ── PYPI-002 missing hash pin ──────────────────────────────────────────


    # Regression (2026-07 audit, PYPI-001): a `-r`/`-c` nested-include
    # directive is not a requirement and carries no `==` pin.
    def test_r_include_line_not_flagged(self):
        text = "-r base.txt\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-001")
        assert f.passed

    def test_c_constraint_line_not_flagged(self):
        text = "-c constraints.txt\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-001")
        assert f.passed


class TestPYPI002:
    def test_fails_without_hashes(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-002")
        assert not f.passed

    def test_fails_when_require_hashes_missing_even_if_lines_have_hashes(self):
        # Every line has ``--hash=`` but no top-level ``--require-hashes``,
        # so a single unhashed addition silently downgrades the file.
        text = "requests==2.31.0 --hash=sha256:abc\n"
        f = run_check(text, "PYPI-002")
        assert not f.passed
        assert "--require-hashes" in f.description

    def test_passes_with_require_hashes_and_per_line_hashes(self):
        text = (
            "--require-hashes\n"
            "requests==2.31.0 --hash=sha256:abc\n"
        )
        f = run_check(text, "PYPI-002")
        assert f.passed

    def test_in_file_is_exempt(self):
        text = "requests\n"
        f = run_check(text, "PYPI-002", path="requirements.in")
        assert f.passed

    # Regression (2026-07 audit, PYPI-002): nested-include and
    # editable/local lines can't carry a `--hash=` and must not be flagged.
    def test_r_include_not_flagged(self):
        text = (
            "--require-hashes\n"
            "requests==2.31.0 --hash=sha256:abc\n"
            "-r base.txt\n"
        )
        f = run_check(text, "PYPI-002")
        assert f.passed

    def test_editable_local_not_flagged(self):
        text = (
            "--require-hashes\n"
            "requests==2.31.0 --hash=sha256:abc\n"
            "-e .\n"
        )
        f = run_check(text, "PYPI-002")
        assert f.passed


# ── PYPI-003 HTTP index / trusted-host ─────────────────────────────────


class TestPYPI003:
    def test_fails_on_http_index(self):
        text = "--index-url http://internal/pypi/simple\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-003")
        assert not f.passed

    def test_fails_on_trusted_host(self):
        text = "--trusted-host internal.example.com\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-003")
        assert not f.passed

    def test_fails_on_http_extra_index(self):
        text = "--extra-index-url http://mirror/pypi\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-003")
        assert not f.passed

    def test_passes_on_https_index(self):
        text = "--index-url https://pypi.org/simple\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-003")
        assert f.passed


# ── PYPI-004 VCS dep mutable ref ───────────────────────────────────────


class TestPYPI004:
    def test_fails_on_branch_ref(self):
        text = "foo @ git+https://github.com/o/r.git@main\n"
        f = run_check(text, "PYPI-004")
        assert not f.passed

    def test_fails_on_tag_ref(self):
        text = "foo @ git+https://github.com/o/r.git@v1.2.3\n"
        f = run_check(text, "PYPI-004")
        assert not f.passed

    def test_fails_without_ref(self):
        text = "foo @ git+https://github.com/o/r.git\n"
        f = run_check(text, "PYPI-004")
        assert not f.passed

    def test_fails_on_editable_vcs_branch(self):
        text = "-e git+https://github.com/o/r.git@main#egg=foo\n"
        f = run_check(text, "PYPI-004")
        assert not f.passed

    def test_passes_with_40char_sha(self):
        text = (
            "foo @ git+https://github.com/o/r.git@"
            "0123456789abcdef0123456789abcdef01234567\n"
        )
        f = run_check(text, "PYPI-004")
        assert f.passed

    def test_skips_registry_spec(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-004")
        assert f.passed


# ── PYPI-005 extra-index-url dependency confusion ──────────────────────


class TestPYPI005:
    def test_fails_when_extra_index_declared(self):
        text = "--extra-index-url https://internal.example.com/pypi\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-005")
        assert not f.passed
        assert "internal.example.com" in f.description

    def test_fails_with_equals_form(self):
        text = "--extra-index-url=https://internal.example.com/pypi\n"
        f = run_check(text, "PYPI-005")
        assert not f.passed

    def test_passes_with_single_index(self):
        text = "--index-url https://internal.example.com/pypi\nrequests==2.31.0\n"
        f = run_check(text, "PYPI-005")
        assert f.passed

    def test_passes_without_index_options(self):
        text = "requests==2.31.0\n"
        f = run_check(text, "PYPI-005")
        assert f.passed
