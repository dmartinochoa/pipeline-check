"""Per-rule tests for PYPI-010..014 (extended PyPI pack).

PYPI-010 / 011 read from ``requirements.txt`` options;
PYPI-012 / 013 / 014 re-parse ``pyproject.toml`` text. Each test
constructs the minimum manifest needed to exercise the rule and
asserts pass / fail / edge-case behavior.
"""
from __future__ import annotations

from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    RequirementsFile,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks

from .conftest import run_check


def _toml_ctx(body: str) -> PypiContext:
    """Build a PypiContext from a single pyproject.toml body (no
    parser dispatch — the rules re-parse the TOML themselves)."""
    return PypiContext([RequirementsFile(
        path="pyproject.toml", text=body, lines=(), options=(),
    )])


def _toml_check(body: str, check_id: str):
    ctx = _toml_ctx(body)
    for f in PypiChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(f"check_id {check_id!r} not produced")


# ── PYPI-010 ────────────────────────────────────────────────────


class TestPypi010:
    def test_fires_on_credential_in_extra_index_url(self):
        body = (
            "--extra-index-url https://user:pw@nexus.corp/simple/\n"
            "foo==1.0.0\n"
        )
        f = run_check(body, "PYPI-010")
        assert not f.passed
        assert "user@nexus.corp" in f.description

    def test_passes_when_no_credentials_in_url(self):
        body = (
            "--extra-index-url https://nexus.corp/simple/\n"
            "foo==1.0.0\n"
        )
        f = run_check(body, "PYPI-010")
        assert f.passed

    def test_passes_on_env_var_placeholder(self):
        body = (
            "--extra-index-url https://${TOKEN}@nexus.corp/simple/\n"
            "foo==1.0.0\n"
        )
        f = run_check(body, "PYPI-010")
        assert f.passed


# ── PYPI-011 ────────────────────────────────────────────────────


class TestPypi011:
    def test_fires_on_trusted_host_declaration(self):
        body = (
            "--extra-index-url https://nexus.corp/simple/\n"
            "--trusted-host nexus.corp\n"
            "foo==1.0.0\n"
        )
        f = run_check(body, "PYPI-011")
        assert not f.passed
        assert "nexus.corp" in f.description

    def test_passes_when_no_trusted_host(self):
        body = "foo==1.0.0\n"
        f = run_check(body, "PYPI-011")
        assert f.passed


# ── PYPI-012 ────────────────────────────────────────────────────


class TestPypi012:
    def test_fires_on_unpinned_build_system_requires(self):
        body = (
            '[build-system]\n'
            'requires = ["setuptools", "wheel"]\n'
            'build-backend = "setuptools.build_meta"\n'
        )
        f = _toml_check(body, "PYPI-012")
        assert not f.passed
        assert "setuptools" in f.description

    def test_passes_on_pinned_build_system_requires(self):
        body = (
            '[build-system]\n'
            'requires = ["setuptools==69.0.2", "wheel==0.42.0"]\n'
            'build-backend = "setuptools.build_meta"\n'
        )
        f = _toml_check(body, "PYPI-012")
        assert f.passed

    def test_passes_when_no_build_system(self):
        body = '[project]\nname = "x"\nversion = "0.1.0"\n'
        f = _toml_check(body, "PYPI-012")
        assert f.passed

    def test_skips_non_pyproject_files(self):
        # Non-pyproject path should pass silently.
        ctx = PypiContext([RequirementsFile(
            path="requirements.txt",
            text="setuptools\n", lines=(), options=(),
        )])
        for f in PypiChecks(ctx).run():
            if f.check_id == "PYPI-012":
                assert f.passed
                break


# ── PYPI-013 ────────────────────────────────────────────────────


class TestPypi013:
    def test_fires_on_dynamic_dependencies(self):
        body = (
            '[project]\n'
            'name = "x"\n'
            'version = "0.1.0"\n'
            'dynamic = ["dependencies"]\n'
        )
        f = _toml_check(body, "PYPI-013")
        assert not f.passed

    def test_passes_on_static_dependencies(self):
        body = (
            '[project]\n'
            'name = "x"\n'
            'version = "0.1.0"\n'
            'dependencies = ["urllib3==2.1.0"]\n'
        )
        f = _toml_check(body, "PYPI-013")
        assert f.passed

    def test_passes_on_dynamic_version_only(self):
        """``dynamic = [\"version\"]`` doesn't affect dep resolution
        and is a low-impact alternative; the rule scopes to
        ``dependencies`` / ``optional-dependencies``."""
        body = (
            '[project]\n'
            'name = "x"\n'
            'dynamic = ["version"]\n'
        )
        f = _toml_check(body, "PYPI-013")
        assert f.passed


# ── PYPI-014 ────────────────────────────────────────────────────


class TestPypi014:
    def test_fires_on_poetry_http_source(self):
        body = (
            '[[tool.poetry.source]]\n'
            'name = "corp"\n'
            'url = "http://nexus.corp/simple"\n'
        )
        f = _toml_check(body, "PYPI-014")
        assert not f.passed

    def test_passes_on_poetry_https_source(self):
        body = (
            '[[tool.poetry.source]]\n'
            'name = "corp"\n'
            'url = "https://nexus.corp/simple"\n'
        )
        f = _toml_check(body, "PYPI-014")
        assert f.passed

    def test_fires_on_uv_extra_index_http(self):
        body = (
            '[tool.uv]\n'
            'extra-index-url = ["http://nexus.corp/simple"]\n'
        )
        f = _toml_check(body, "PYPI-014")
        assert not f.passed

    def test_fires_on_pdm_http_source(self):
        body = (
            '[[tool.pdm.source]]\n'
            'name = "corp"\n'
            'url = "http://nexus.corp/simple"\n'
        )
        f = _toml_check(body, "PYPI-014")
        assert not f.passed
