"""pyproject.toml parser tests.

Three layers:

1. ``_parse_pyproject_toml`` unit tests: PEP 621 / Poetry / build-
   system shapes, classic vs. group dev-deps, Poetry table form
   (version / git / url / path), bare-numeric pin shorthand.
2. End-to-end through :class:`PypiContext.from_path`: a real
   pyproject.toml on disk produces a :class:`RequirementsFile`
   whose synthesized lines flow through PYPI-004 / PYPI-006
   without per-rule changes.
3. Rule-exemption locks: PYPI-001 and PYPI-002 silent-pass on
   pyproject.toml because the resolved lockfile is what pins.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    _parse_pyproject_toml,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks

# ── _parse_pyproject_toml ───────────────────────────────────────────


class TestParsePyprojectToml:
    def test_pep621_dependencies_array(self) -> None:
        body = textwrap.dedent(
            """\
            [project]
            name = "myproj"
            version = "1.0.0"
            dependencies = [
              "requests>=2.28",
              "click==8.1.0",
              "ua-parser-js",
            ]
            """
        )
        lines, options = _parse_pyproject_toml(body)
        bodies = [rl.body for rl in lines]
        assert "requests>=2.28" in bodies
        assert "click==8.1.0" in bodies
        assert "ua-parser-js" in bodies
        assert options == ()

    def test_pep621_optional_dependencies_table_of_arrays(self) -> None:
        body = textwrap.dedent(
            """\
            [project]
            name = "myproj"
            version = "1.0.0"

            [project.optional-dependencies]
            test = ["pytest>=7", "pytest-cov"]
            dev  = ["ruff", "mypy"]
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert {"pytest>=7", "pytest-cov", "ruff", "mypy"}.issubset(bodies)

    def test_pep621_direct_url_pep508(self) -> None:
        body = textwrap.dedent(
            """\
            [project]
            name = "myproj"
            version = "1.0.0"
            dependencies = [
              "myfork @ git+https://github.com/user/repo.git@main",
            ]
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        assert any("git+" in rl.body for rl in lines)

    def test_poetry_classic_dependencies_caret(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry]
            name = "myproj"
            version = "1.0.0"

            [tool.poetry.dependencies]
            python = "^3.10"
            requests = "^2.28"
            click = "==8.1.0"
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        # python entry is dropped (runtime requirement, not a dep)
        assert not any("python" in b for b in bodies)
        # Caret stays as range so PYPI-001 will see a non-== body
        assert "requests ^2.28" in bodies
        # Explicit == stays a pin
        assert "click==8.1.0" in bodies

    def test_poetry_bare_numeric_treated_as_exact(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            requests = "2.28.1"
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "requests==2.28.1" in bodies

    def test_poetry_table_form_with_version(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            requests = { version = "^2.28", extras = ["security"] }
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "requests ^2.28" in bodies

    def test_poetry_git_dependency_with_rev(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            mylib = { git = "https://github.com/owner/repo.git", rev = "abc123" }
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "mylib @ git+https://github.com/owner/repo.git@abc123" in bodies

    def test_poetry_git_dependency_with_branch_is_mutable(self) -> None:
        # A branch ref synthesizes the same direct-URL shape; PYPI-004
        # then fires because the ref isn't a 40-char SHA.
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            mylib = { git = "https://github.com/owner/repo.git", branch = "main" }
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "mylib @ git+https://github.com/owner/repo.git@main" in bodies

    def test_poetry_url_dependency(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            wheels = { url = "https://example.com/wheels/foo.whl" }
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "wheels @ https://example.com/wheels/foo.whl" in bodies

    def test_poetry_path_dependency_is_dropped(self) -> None:
        # Local sources aren't a supply-chain surface.
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            mylib = { path = "./packages/mylib" }
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        assert lines == ()

    def test_poetry_classic_dev_dependencies(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            requests = "^2.28"

            [tool.poetry.dev-dependencies]
            pytest = "^7.0"
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "requests ^2.28" in bodies
        assert "pytest ^7.0" in bodies

    def test_poetry_groups_dependencies(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            requests = "^2.28"

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.0"

            [tool.poetry.group.docs.dependencies]
            sphinx = "^6.0"
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "requests ^2.28" in bodies
        assert "pytest ^7.0" in bodies
        assert "sphinx ^6.0" in bodies

    def test_poetry_multiple_constraints_list_form(self) -> None:
        body = textwrap.dedent(
            """\
            [tool.poetry.dependencies]
            sphinx = [
              { version = "^6.0", python = "<3.10" },
              { version = "^7.0", python = ">=3.10" },
            ]
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "sphinx ^6.0" in bodies
        assert "sphinx ^7.0" in bodies

    def test_build_system_requires(self) -> None:
        body = textwrap.dedent(
            """\
            [build-system]
            requires = ["setuptools>=61", "wheel"]
            build-backend = "setuptools.build_meta"
            """
        )
        lines, _ = _parse_pyproject_toml(body)
        bodies = {rl.body for rl in lines}
        assert "setuptools>=61" in bodies
        assert "wheel" in bodies

    def test_empty_pyproject_yields_no_lines(self) -> None:
        body = '[project]\nname = "x"\nversion = "1.0"\n'
        lines, options = _parse_pyproject_toml(body)
        assert lines == ()
        assert options == ()

    def test_no_top_level_require_hashes_emitted(self) -> None:
        # Manifests don't carry hashes; the resolved lockfile is what
        # does. PYPI-002 exempts pyproject.toml directly so the empty
        # options stay correct.
        body = textwrap.dedent(
            """\
            [project]
            name = "myproj"
            version = "1.0.0"
            dependencies = ["requests==2.28.1"]
            """
        )
        _, options = _parse_pyproject_toml(body)
        assert options == ()


# ── End-to-end via PypiContext.from_path ────────────────────────────


_PYPROJECT_BODY = textwrap.dedent(
    """\
    [project]
    name = "myproj"
    version = "1.0.0"
    dependencies = [
      "requests>=2.28",
      "ctx==0.2.2",
    ]

    [tool.poetry.dependencies]
    mylib = { git = "https://github.com/owner/repo.git", branch = "main" }
    """
)


def _write_pyproject(tmp_path: Path) -> Path:
    target = tmp_path / "pyproject.toml"
    target.write_text(_PYPROJECT_BODY, encoding="utf-8")
    return target


def test_pyproject_picked_up_by_loader(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    rf = ctx.files[0]
    assert rf.path.endswith("pyproject.toml")
    bodies = {rl.body for rl in rf.lines}
    assert "requests>=2.28" in bodies
    assert "ctx==0.2.2" in bodies
    assert "mylib @ git+https://github.com/owner/repo.git@main" in bodies


def test_pyproject_pypi001_exempted(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    pypi001 = [f for f in findings if f.check_id == "PYPI-001"]
    assert pypi001 and all(f.passed for f in pypi001)
    assert "manifest" in pypi001[0].description.lower()


def test_pyproject_pypi002_exempted(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    pypi002 = [f for f in findings if f.check_id == "PYPI-002"]
    assert pypi002 and all(f.passed for f in pypi002)


def test_pyproject_pypi004_fires_on_branch_ref(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    pypi004 = [f for f in findings if f.check_id == "PYPI-004"]
    assert pypi004 and not pypi004[0].passed
    assert "main" in pypi004[0].description.lower() or "ref" in pypi004[0].description.lower()


def test_pyproject_pypi006_flags_compromised_version(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)  # body pins ctx==0.2.2 (compromised)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    pypi006 = [f for f in findings if f.check_id == "PYPI-006"]
    assert pypi006 and not pypi006[0].passed
    assert "ctx" in pypi006[0].description
