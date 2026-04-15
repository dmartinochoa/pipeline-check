"""Tests for the SARIF 2.1.0 reporter."""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.sarif_reporter import report_sarif
from pipeline_check.core.standards.base import ControlRef


def _f(check_id="CB-001", passed=False, severity=Severity.HIGH, controls=None, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Plaintext secret in CodeBuild env"),
        severity=severity,
        resource=kw.get("resource", "my-project"),
        description=kw.get("description", "A secret was found."),
        recommendation=kw.get("recommendation", "Use Secrets Manager."),
        passed=passed,
        controls=controls or [],
    )


def _score():
    return {"grade": "C", "total": 10, "failed": 3, "passed": 7}


class TestSarifEnvelope:
    def test_top_level_schema_and_version(self):
        out = json.loads(report_sarif([_f()], _score()))
        assert out["version"] == "2.1.0"
        assert out["$schema"].endswith("sarif-2.1.0.json")
        assert len(out["runs"]) == 1

    def test_driver_metadata(self):
        out = json.loads(report_sarif([_f()], _score(), tool_version="1.2.3"))
        driver = out["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pipeline_check"
        assert driver["version"] == "1.2.3"
        assert driver["informationUri"].startswith("http")

    def test_run_level_score_embedded(self):
        out = json.loads(report_sarif([_f()], _score()))
        assert out["runs"][0]["properties"]["score"]["grade"] == "C"


class TestResultsVsRules:
    def test_passing_findings_produce_no_results(self):
        out = json.loads(report_sarif([_f(passed=True)], _score()))
        assert out["runs"][0]["results"] == []

    def test_passing_findings_still_populate_rule_catalogue(self):
        out = json.loads(report_sarif([_f(passed=True)], _score()))
        rules = out["runs"][0]["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["CB-001"]

    def test_failed_findings_become_results(self):
        out = json.loads(report_sarif([_f(passed=False)], _score()))
        results = out["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CB-001"

    def test_duplicate_check_id_creates_single_rule_multiple_results(self):
        findings = [
            _f(resource="project-a"),
            _f(resource="project-b"),
            _f(resource="project-c"),
        ]
        out = json.loads(report_sarif(findings, _score()))
        rules = out["runs"][0]["tool"]["driver"]["rules"]
        results = out["runs"][0]["results"]
        assert len(rules) == 1
        assert len(results) == 3
        # All results index into the single rule.
        assert {r["ruleIndex"] for r in results} == {0}

    def test_rule_index_matches_rule_position(self):
        findings = [
            _f(check_id="CB-001"),
            _f(check_id="IAM-001", title="Admin access"),
            _f(check_id="CB-001", resource="other"),
        ]
        out = json.loads(report_sarif(findings, _score()))
        rules = out["runs"][0]["tool"]["driver"]["rules"]
        results = out["runs"][0]["results"]
        idx = {r["id"]: i for i, r in enumerate(rules)}
        for r in results:
            assert r["ruleIndex"] == idx[r["ruleId"]]


class TestSeverityMapping:
    @pytest.mark.parametrize("sev,expected_level,expected_score_prefix", [
        (Severity.CRITICAL, "error", "9"),
        (Severity.HIGH, "error", "7"),
        (Severity.MEDIUM, "warning", "5"),
        (Severity.LOW, "warning", "3"),
        (Severity.INFO, "note", "1"),
    ])
    def test_level_and_security_severity(self, sev, expected_level, expected_score_prefix):
        out = json.loads(report_sarif([_f(severity=sev)], _score()))
        rule = out["runs"][0]["tool"]["driver"]["rules"][0]
        result = out["runs"][0]["results"][0]
        assert rule["defaultConfiguration"]["level"] == expected_level
        assert result["level"] == expected_level
        assert rule["properties"]["security-severity"].startswith(expected_score_prefix)


class TestLocations:
    def test_file_path_resource_is_file_uri(self):
        out = json.loads(report_sarif([_f(resource=".github/workflows/ci.yml")], _score()))
        loc = out["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/ci.yml"

    def test_windows_path_normalised_to_forward_slashes(self):
        out = json.loads(report_sarif([_f(resource="C:\\repo\\.gitlab-ci.yml")], _score()))
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert uri.endswith(".gitlab-ci.yml")

    def test_aws_resource_name_uses_resource_scheme(self):
        out = json.loads(report_sarif([_f(resource="my-codebuild-project")], _score()))
        uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("resource:///")
        assert uri.endswith("my-codebuild-project")

    def test_logical_location_carries_resource(self):
        out = json.loads(report_sarif([_f(resource="my-codebuild-project")], _score()))
        loc = out["runs"][0]["results"][0]["locations"][0]
        assert loc["logicalLocations"][0]["name"] == "my-codebuild-project"


class TestControlsPropagation:
    def _finding_with_controls(self):
        return _f(controls=[
            ControlRef(
                standard="owasp_cicd_top_10",
                standard_title="OWASP Top 10 CI/CD Security Risks",
                control_id="CICD-SEC-6",
                control_title="Insufficient Credential Hygiene",
            ),
            ControlRef(
                standard="nist_800_53",
                standard_title="NIST SP 800-53 Rev. 5",
                control_id="IA-5",
                control_title="Authenticator Management",
            ),
        ])

    def test_control_ids_appear_in_rule_tags(self):
        out = json.loads(report_sarif([self._finding_with_controls()], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert "security" in tags
        assert "CICD-SEC-6" in tags
        assert "IA-5" in tags
        assert "owasp_cicd_top_10" in tags

    def test_controls_in_result_properties(self):
        out = json.loads(report_sarif([self._finding_with_controls()], _score()))
        controls = out["runs"][0]["results"][0]["properties"]["controls"]
        assert len(controls) == 2
        assert controls[0]["control_id"] == "CICD-SEC-6"


class TestRuleContent:
    def test_rule_help_has_text_and_markdown(self):
        out = json.loads(report_sarif([_f(recommendation="Rotate the secret.")], _score()))
        help_ = out["runs"][0]["tool"]["driver"]["rules"][0]["help"]
        assert help_["text"] == "Rotate the secret."
        assert "Rotate the secret" in help_["markdown"]

    def test_rule_name_is_camel_case_identifier(self):
        out = json.loads(report_sarif(
            [_f(title="Plaintext secret in CodeBuild env")],
            _score(),
        ))
        name = out["runs"][0]["tool"]["driver"]["rules"][0]["name"]
        # CamelCase derivation: no spaces, starts with capital
        assert " " not in name
        assert name[0].isupper()

    def test_result_message_is_the_finding_description(self):
        out = json.loads(report_sarif(
            [_f(description="CB-001: my-project has plaintext secrets.")],
            _score(),
        ))
        assert out["runs"][0]["results"][0]["message"]["text"].startswith("CB-001:")


class TestIntegrationWithCli:
    """Exercise the actual CLI --output sarif path end-to-end."""

    def test_cli_sarif_output(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from pipeline_check.cli import scan

        # Use the GitHub provider with a trivial fixture so the CLI actually
        # runs a scan and produces SARIF.
        wf_dir = tmp_path / "wf"
        wf_dir.mkdir()
        (wf_dir / "c.yml").write_text(
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        runner = CliRunner()
        result = runner.invoke(scan, [
            "--pipeline", "github",
            "--gha-path", str(wf_dir),
            "--output", "sarif",
        ])
        # Grade D causes exit 1; sarif payload still on stdout.
        assert result.exit_code in (0, 1)
        payload = json.loads(result.stdout)
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["tool"]["driver"]["name"] == "pipeline_check"
