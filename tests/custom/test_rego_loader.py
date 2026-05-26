"""Tests for the Rego rule loader (metadata extraction and validation)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pipeline_check.core.checks.custom.rego_errors import (
    OpaNotFoundError,
    RegoRuleError,
)
from pipeline_check.core.checks.custom.rego_loader import (
    find_rego_files,
    load_rego_rules,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "rego"
_HAS_OPA = shutil.which("opa") is not None
_SKIP_NO_OPA = pytest.mark.skipif(
    not _HAS_OPA, reason="opa binary not on PATH"
)


class TestFindRegoFiles:
    def test_directory_discovery(self) -> None:
        files = find_rego_files([str(_FIXTURES)])
        names = {f.name for f in files}
        assert "gha_pin.rego" in names
        assert "gl_privileged.rego" in names

    def test_single_file(self) -> None:
        files = find_rego_files([str(_FIXTURES / "gha_pin.rego")])
        assert len(files) == 1
        assert files[0].name == "gha_pin.rego"

    def test_missing_path_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="does not exist"):
            find_rego_files(["/nonexistent/path"])

    def test_non_rego_file_raises(self) -> None:
        init_file = Path(__file__).parent / "__init__.py"
        with pytest.raises(RegoRuleError, match="not a .rego file"):
            find_rego_files([str(init_file)])

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RegoRuleError, match="no .rego files"):
            find_rego_files([str(tmp_path)])


class TestLoadRegoRulesNoOpa:
    def test_no_paths_returns_empty(self) -> None:
        result = load_rego_rules(None)
        assert result.rules == []
        assert result.by_provider == {}


@_SKIP_NO_OPA
class TestLoadRegoRules:
    def test_load_valid_policies(self, tmp_path: Path) -> None:
        _copy_fixture(tmp_path, "gha_pin.rego")
        result = load_rego_rules([str(tmp_path)])
        assert len(result.rules) == 1
        rule = result.rules[0]
        assert rule.id == "TEST-001"
        assert rule.title == "Actions must be pinned to commit SHA"
        assert rule.severity.value == "HIGH"
        assert "github" in result.by_provider
        meta = result.by_provider["github"][0]
        assert meta.provider == "github"
        assert meta.rule.cwe == ("CWE-829",)
        assert meta.rule.owasp == ("CICD-SEC-3",)

    def test_load_multiple_providers(self, tmp_path: Path) -> None:
        _copy_fixture(tmp_path, "gha_pin.rego")
        _copy_fixture(tmp_path, "gl_privileged.rego")
        result = load_rego_rules([str(tmp_path)])
        assert len(result.rules) == 2
        providers = set(result.by_provider.keys())
        assert providers == {"github", "gitlab"}

    def test_builtin_id_collision_raises(self, tmp_path: Path) -> None:
        _copy_fixture(tmp_path, "collision.rego")
        with pytest.raises(RegoRuleError, match="collides with a built-in"):
            load_rego_rules([str(tmp_path)], builtin_ids={"GHA-001"})

    def test_yaml_custom_id_collision_raises(self, tmp_path: Path) -> None:
        _copy_fixture(tmp_path, "gha_pin.rego")
        with pytest.raises(RegoRuleError, match="collides with a YAML custom rule"):
            load_rego_rules(
                [str(tmp_path)],
                yaml_custom_ids={"TEST-001"},
            )

    def test_missing_severity_raises(self, tmp_path: Path) -> None:
        _copy_fixture(tmp_path, "bad_metadata.rego")
        with pytest.raises(RegoRuleError, match="severity"):
            load_rego_rules([str(tmp_path)])


@_SKIP_NO_OPA
class TestOpaNotFound:
    def test_raises_when_opa_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _copy_fixture(tmp_path, "gha_pin.rego")
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        with pytest.raises(OpaNotFoundError, match="opa binary not found"):
            load_rego_rules([str(tmp_path)])


def _copy_fixture(dest: Path, name: str) -> Path:
    src = _FIXTURES / name
    dst = dest / name
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return dst
