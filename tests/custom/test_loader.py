"""Tests for the YAML rule loader."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.custom.loader import (
    CustomRuleError,
    load_custom_rules,
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


VALID_RULE = """
rules:
  - id: ACME-001
    title: Action must be pinned to a SHA
    severity: HIGH
    provider: github
    description: 'step {{uses}} not pinned'
    recommendation: Pin to a 40-char SHA.
    for_each: $.jobs.*.steps[*]
    assert:
      regex:
        path: uses
        pattern: '^[^@]+@[0-9a-f]{40}$'
"""


class TestHappyPath:

    def test_load_one_rule(self, tmp_path):
        f = _write(tmp_path, "rules.yml", VALID_RULE)
        loaded = load_custom_rules([str(f)])
        assert [r.id for r in loaded.rules] == ["ACME-001"]
        assert "github" in loaded.by_provider
        assert len(loaded.by_provider["github"]) == 1
        compiled = loaded.by_provider["github"][0]
        assert compiled.rule.title.startswith("Action must")
        assert compiled.source.endswith("rules.yml")

    def test_load_directory(self, tmp_path):
        sub = tmp_path / "rules"
        sub.mkdir()
        _write(sub, "a.yml", VALID_RULE)
        loaded = load_custom_rules([str(sub)])
        assert len(loaded.rules) == 1

    def test_empty_paths_returns_empty(self):
        loaded = load_custom_rules([])
        assert loaded.rules == []
        assert loaded.by_provider == {}


class TestIdValidation:

    def test_id_format_required(self, tmp_path):
        bad = VALID_RULE.replace("ACME-001", "acme-001")
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="must match"):
            load_custom_rules([str(f)])

    def test_collides_with_builtin(self, tmp_path):
        bad = VALID_RULE.replace("ACME-001", "GHA-001")
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="collides with a built-in"):
            load_custom_rules([str(f)], builtin_ids={"GHA-001"})

    def test_duplicate_id_across_files(self, tmp_path):
        _write(tmp_path, "a.yml", VALID_RULE)
        _write(tmp_path, "b.yml", VALID_RULE)
        with pytest.raises(CustomRuleError, match="already defined"):
            load_custom_rules([str(tmp_path)])


class TestSchemaErrors:

    def test_missing_required_field(self, tmp_path):
        bad = VALID_RULE.replace("    severity: HIGH\n", "")
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="missing required"):
            load_custom_rules([str(f)])

    def test_unknown_provider(self, tmp_path):
        bad = VALID_RULE.replace("provider: github", "provider: ftp")
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="provider 'ftp'"):
            load_custom_rules([str(f)])

    def test_invalid_severity(self, tmp_path):
        bad = VALID_RULE.replace("severity: HIGH", "severity: BIG")
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="severity 'BIG'"):
            load_custom_rules([str(f)])

    def test_bad_jsonpath_in_for_each(self, tmp_path):
        bad = VALID_RULE.replace(
            "for_each: $.jobs.*.steps[*]",
            "for_each: '..no-dollar'",
        )
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="for_each"):
            load_custom_rules([str(f)])

    def test_bad_predicate_op(self, tmp_path):
        bad = VALID_RULE.replace(
            "assert:\n      regex:\n        path: uses\n        pattern: '^[^@]+@[0-9a-f]{40}$'",
            "assert:\n      weird: { path: uses }",
        )
        f = _write(tmp_path, "rules.yml", bad)
        with pytest.raises(CustomRuleError, match="unknown operator"):
            load_custom_rules([str(f)])

    def test_yaml_parse_error(self, tmp_path):
        f = _write(tmp_path, "bad.yml", "rules: [{:::]")
        with pytest.raises(CustomRuleError, match="YAML parse error"):
            load_custom_rules([str(f)])


class TestPathErrors:

    def test_path_does_not_exist(self):
        with pytest.raises(CustomRuleError, match="does not exist"):
            load_custom_rules(["/nonexistent/rules.yml"])

    def test_directory_with_no_yaml_files(self, tmp_path):
        sub = tmp_path / "empty"
        sub.mkdir()
        with pytest.raises(CustomRuleError, match="no .yml/.yaml"):
            load_custom_rules([str(sub)])
