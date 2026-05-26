"""Tests for the Rego rule evaluation runner."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.custom.rego_loader import (
    load_rego_rules,
)
from pipeline_check.core.checks.custom.rego_runner import (
    evaluate_rego_rules,
    make_passing_findings,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "rego"
_HAS_OPA = shutil.which("opa") is not None
_SKIP_NO_OPA = pytest.mark.skipif(
    not _HAS_OPA, reason="opa binary not on PATH"
)


def _load_test_rules(
    tmp_path: Path, *filenames: str,
) -> Any:
    for name in filenames:
        src = _FIXTURES / name
        dst = tmp_path / name
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return load_rego_rules([str(tmp_path)])


@_SKIP_NO_OPA
class TestEvaluateRegoRules:
    def test_unpinned_action_denied(self, tmp_path: Path) -> None:
        loaded = _load_test_rules(tmp_path, "gha_pin.rego")
        rules = loaded.by_provider["github"]
        input_data: dict[str, Any] = {
            "path": ".github/workflows/ci.yml",
            "doc": {
                "jobs": {
                    "build": {
                        "steps": [
                            {"uses": "actions/checkout@v4"},
                            {"run": "echo hello"},
                        ]
                    }
                }
            },
            "provider": "github",
        }
        findings = evaluate_rego_rules(rules, input_data)
        assert len(findings) >= 1
        failing = [f for f in findings if not f.passed]
        assert len(failing) >= 1
        assert failing[0].check_id == "TEST-001"
        assert "unpinned action" in failing[0].description.lower()
        assert failing[0].severity == Severity.HIGH

    def test_pinned_action_passes(self, tmp_path: Path) -> None:
        loaded = _load_test_rules(tmp_path, "gha_pin.rego")
        rules = loaded.by_provider["github"]
        input_data: dict[str, Any] = {
            "path": ".github/workflows/ci.yml",
            "doc": {
                "jobs": {
                    "build": {
                        "steps": [
                            {
                                "uses": "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"
                            },
                        ]
                    }
                }
            },
            "provider": "github",
        }
        findings = evaluate_rego_rules(rules, input_data)
        failing = [f for f in findings if not f.passed]
        assert len(failing) == 0

    def test_gitlab_privileged_denied(self, tmp_path: Path) -> None:
        loaded = _load_test_rules(tmp_path, "gl_privileged.rego")
        rules = loaded.by_provider["gitlab"]
        input_data: dict[str, Any] = {
            "path": ".gitlab-ci.yml",
            "doc": {
                "stages": ["build"],
                "build_job": {
                    "stage": "build",
                    "tags": ["privileged"],
                    "script": ["make build"],
                },
            },
            "provider": "gitlab",
        }
        findings = evaluate_rego_rules(rules, input_data)
        failing = [f for f in findings if not f.passed]
        assert len(failing) >= 1
        assert failing[0].check_id == "TEST-002"
        assert failing[0].severity == Severity.CRITICAL

    def test_empty_rules_returns_empty(self) -> None:
        findings = evaluate_rego_rules([], {"doc": {}})
        assert findings == []


class TestMakePassingFindings:
    def test_generates_passing_for_non_denied(self, tmp_path: Path) -> None:
        if not _HAS_OPA:
            pytest.skip("opa binary not on PATH")
        loaded = _load_test_rules(tmp_path, "gha_pin.rego")
        rules = loaded.by_provider["github"]
        passing = make_passing_findings(rules, set(), ".github/workflows/ci.yml")
        assert len(passing) == 1
        assert passing[0].passed is True
        assert passing[0].check_id == "TEST-001"

    def test_skips_already_denied(self, tmp_path: Path) -> None:
        if not _HAS_OPA:
            pytest.skip("opa binary not on PATH")
        loaded = _load_test_rules(tmp_path, "gha_pin.rego")
        rules = loaded.by_provider["github"]
        passing = make_passing_findings(
            rules, {"TEST-001"}, ".github/workflows/ci.yml",
        )
        assert len(passing) == 0
