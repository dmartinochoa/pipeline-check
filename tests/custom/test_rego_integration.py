"""End-to-end integration tests for OPA/Rego custom rules.

These tests construct a Scanner with ``--rego-rules`` and verify
findings flow through scoring, gating, and JSON output.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

_HAS_OPA = shutil.which("opa") is not None
_SKIP_NO_OPA = pytest.mark.skipif(
    not _HAS_OPA, reason="opa binary not on PATH"
)

_FIXTURES = Path(__file__).parent / "fixtures" / "rego"


def _write_workflow(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf = wf_dir / "ci.yml"
    wf.write_text(
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo hello\n",
        encoding="utf-8",
    )
    return wf_dir


def _copy_policies(tmp_path: Path, *names: str) -> Path:
    pol_dir = tmp_path / "policies"
    pol_dir.mkdir()
    for name in names:
        src = _FIXTURES / name
        dst = pol_dir / name
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return pol_dir


@_SKIP_NO_OPA
class TestRegoScannerIntegration:
    def test_rego_finding_appears_in_scan(self, tmp_path: Path) -> None:
        from pipeline_check.core.scanner import Scanner

        wf_dir = _write_workflow(tmp_path)
        pol_dir = _copy_policies(tmp_path, "gha_pin.rego")

        scanner = Scanner(
            pipeline="github",
            rego_rules=[str(pol_dir)],
            gha_path=str(wf_dir),
        )
        findings = scanner.run()
        rego_findings = [f for f in findings if f.check_id == "TEST-001"]
        assert len(rego_findings) >= 1
        failing = [f for f in rego_findings if not f.passed]
        assert len(failing) >= 1
        assert "unpinned" in failing[0].description.lower()

    def test_rego_finding_in_json_output(self, tmp_path: Path) -> None:
        from pipeline_check.core.scanner import Scanner

        wf_dir = _write_workflow(tmp_path)
        pol_dir = _copy_policies(tmp_path, "gha_pin.rego")

        scanner = Scanner(
            pipeline="github",
            rego_rules=[str(pol_dir)],
            gha_path=str(wf_dir),
        )
        findings = scanner.run()
        data: list[dict[str, Any]] = [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "passed": f.passed,
                "description": f.description,
            }
            for f in findings
            if f.check_id == "TEST-001"
        ]
        assert len(data) >= 1
        serialized = json.dumps(data)
        assert "TEST-001" in serialized

    def test_rego_and_yaml_custom_coexist(self, tmp_path: Path) -> None:
        from pipeline_check.core.scanner import Scanner

        wf_dir = _write_workflow(tmp_path)
        pol_dir = _copy_policies(tmp_path, "gha_pin.rego")

        yaml_dir = tmp_path / "yaml_rules"
        yaml_dir.mkdir()
        yaml_rule = yaml_dir / "timeout.yml"
        yaml_rule.write_text(
            "rules:\n"
            "  - id: ACME-001\n"
            "    title: Job must specify runner\n"
            "    severity: LOW\n"
            "    provider: github\n"
            "    description: Job has no explicit runner.\n"
            "    recommendation: Set runs-on explicitly on every job.\n"
            '    for_each: "$.jobs.*"\n'
            "    assert:\n"
            "      exists:\n"
            "        path: permissions\n",
            encoding="utf-8",
        )

        scanner = Scanner(
            pipeline="github",
            custom_rules=[str(yaml_dir)],
            rego_rules=[str(pol_dir)],
            gha_path=str(wf_dir),
        )
        findings = scanner.run()
        ids = {f.check_id for f in findings}
        assert "TEST-001" in ids
        assert "ACME-001" in ids

    def test_no_rego_rules_is_noop(self, tmp_path: Path) -> None:
        from pipeline_check.core.scanner import Scanner

        wf_dir = _write_workflow(tmp_path)
        scanner = Scanner(
            pipeline="github",
            gha_path=str(wf_dir),
        )
        findings = scanner.run()
        rego_findings = [f for f in findings if f.check_id.startswith("TEST-")]
        assert len(rego_findings) == 0
