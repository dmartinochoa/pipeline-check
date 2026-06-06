"""Tests for the SARIF 2.1.0 reporter."""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.sarif_reporter import report_sarif
from pipeline_check.core.standards.base import ControlRef

from ._chain_helpers import make_reach_chain


def _f(check_id="CB-001", passed=False, severity=Severity.HIGH, controls=None, cwe=None, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Plaintext secret in CodeBuild env"),
        severity=severity,
        resource=kw.get("resource", "my-project"),
        description=kw.get("description", "A secret was found."),
        recommendation=kw.get("recommendation", "Use Secrets Manager."),
        passed=passed,
        controls=controls or [],
        cwe=cwe or [],
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

    def test_standard_slugs_appear_in_rule_tags(self):
        # GitHub code-scanning caps tags per rule at 20. We keep only
        # "security" + the standard slugs here; individual control IDs
        # live in ``properties.controls`` on each result.
        out = json.loads(report_sarif([self._finding_with_controls()], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert "security" in tags
        assert "owasp_cicd_top_10" in tags
        assert "nist_800_53" in tags
        assert len(tags) <= 20

    def test_controls_in_result_properties(self):
        out = json.loads(report_sarif([self._finding_with_controls()], _score()))
        controls = out["runs"][0]["results"][0]["properties"]["controls"]
        assert len(controls) == 2
        assert controls[0]["control_id"] == "CICD-SEC-6"

    def test_kebab_case_control_ids_pass_through(self):
        """OpenSSF Scorecard uses kebab-case IDs (``Dangerous-Workflow``)
        rather than the numeric IDs other standards use. SARIF allows any
        string for ``properties.controls[].control_id``, but downstream
        consumers (GitHub Advanced Security) have historically been
        picky about special characters — this test guards the round-trip.
        """
        finding = _f(controls=[
            ControlRef(
                standard="openssf_scorecard",
                standard_title="OpenSSF Scorecard",
                control_id="Dangerous-Workflow",
                control_title="No dangerous patterns in CI workflows",
            ),
            ControlRef(
                standard="soc2",
                standard_title="SOC 2 Trust Services Criteria",
                control_id="CC6.8",
                control_title="Controls prevent or detect malicious software",
            ),
        ])
        out = json.loads(report_sarif([finding], _score()))

        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert "openssf_scorecard" in tags
        assert "soc2" in tags
        # Control IDs themselves must NOT appear in tags — they only
        # live in properties.controls. Guards against a regression
        # where someone "helpfully" adds them to tags and pushes past
        # the 20-tag cap.
        assert "Dangerous-Workflow" not in tags
        assert "CC6.8" not in tags

        controls = out["runs"][0]["results"][0]["properties"]["controls"]
        ids = {c["control_id"] for c in controls}
        assert ids == {"Dangerous-Workflow", "CC6.8"}
        # SARIF JSON must round-trip without escape mangling of the hyphen.
        assert json.loads(json.dumps(out))["runs"][0]["results"][0][
            "properties"
        ]["controls"][0]["control_id"] in ids


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


class TestRuleTagsCap:
    """GitHub Code Scanning rejects rules whose ``properties.tags``
    list exceeds 10 entries. Pipeline-check maps a single check to up
    to 13 standards (one tag each, plus ``security`` itself), so the
    SARIF emitter has to cap and prioritize.
    """

    _ALL_STANDARDS = (
        "cis_aws_foundations", "cis_supply_chain", "esf_supply_chain",
        "nist_800_190", "nist_800_53", "nist_csf_2", "nist_ssdf",
        "openssf_scorecard", "owasp_cicd_top_10", "pci_dss_v4",
        "s2c2f", "slsa", "soc2",
    )

    def _finding_with_n_standards(self, n: int) -> Finding:
        controls = [
            ControlRef(standard=s, standard_title=s,
                       control_id="X", control_title="Y")
            for s in self._ALL_STANDARDS[:n]
        ]
        return _f(controls=controls)

    def test_tags_capped_at_ten_when_all_standards_apply(self):
        f = self._finding_with_n_standards(len(self._ALL_STANDARDS))
        out = json.loads(report_sarif([f], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert len(tags) == 10, (
            f"GitHub caps SARIF rule tags at 10; emitter produced "
            f"{len(tags)} — uploads will warn and silently drop "
            f"the overflow"
        )

    def test_tags_uncapped_when_under_limit(self):
        f = self._finding_with_n_standards(3)
        out = json.loads(report_sarif([f], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        # ``security`` + 3 standards = 4
        assert len(tags) == 4

    def test_security_tag_always_first(self):
        f = self._finding_with_n_standards(0)  # no standards mapped
        out = json.loads(report_sarif([f], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert tags == ["security"]

    def test_priority_standards_survive_truncation(self):
        """When the cap kicks in, the most user-facing frameworks
        (OWASP CICD Top 10, NIST SSDF, SLSA, CIS Supply Chain,
        OpenSSF Scorecard) must remain in the tag list — those are
        what users filter the GitHub Code Scanning UI by."""
        f = self._finding_with_n_standards(len(self._ALL_STANDARDS))
        out = json.loads(report_sarif([f], _score()))
        tags = out["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        for must_keep in (
            "owasp_cicd_top_10", "nist_ssdf", "slsa",
            "cis_supply_chain", "openssf_scorecard",
        ):
            assert must_keep in tags, (
                f"{must_keep!r} dropped by truncation; got {tags}"
            )

    def test_overflowed_standards_still_visible_on_result(self):
        """Standards truncated from the rule's ``tags`` must still
        appear in full on the per-result ``properties.controls`` so
        no audit information is lost — only the UI-filter convenience
        is."""
        f = self._finding_with_n_standards(len(self._ALL_STANDARDS))
        out = json.loads(report_sarif([f], _score()))
        result_controls = out["runs"][0]["results"][0]["properties"]["controls"]
        emitted_standards = {c["standard"] for c in result_controls}
        assert emitted_standards == set(self._ALL_STANDARDS)


class TestCweEnrichment:
    def test_cwe_appears_in_rule_properties(self):
        f = _f(cwe=["CWE-798"])
        out = json.loads(report_sarif([f], _score()))
        rule = out["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == ["CWE-798"]

    def test_cwe_appears_in_result_properties(self):
        f = _f(cwe=["CWE-78", "CWE-94"])
        out = json.loads(report_sarif([f], _score()))
        result = out["runs"][0]["results"][0]
        assert result["properties"]["cwe"] == ["CWE-78", "CWE-94"]

    def test_cwe_omitted_when_empty(self):
        f = _f()  # no cwe
        out = json.loads(report_sarif([f], _score()))
        rule = out["runs"][0]["tool"]["driver"]["rules"][0]
        assert "cwe" not in rule["properties"]
        result = out["runs"][0]["results"][0]
        assert "cwe" not in result["properties"]


class TestPartialFingerprints:
    """Stable cross-run fingerprints so GHCS dedupes findings."""

    def test_every_result_carries_a_fingerprint(self):
        out = json.loads(report_sarif([_f()], _score()))
        result = out["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        fps = result["partialFingerprints"]
        assert "pipelineCheckV1" in fps
        # SHA-256 -> 64 hex chars.
        assert len(fps["pipelineCheckV1"]) == 64
        assert all(c in "0123456789abcdef" for c in fps["pipelineCheckV1"])

    def test_fingerprint_stable_across_two_runs(self):
        a = json.loads(report_sarif([_f()], _score()))
        b = json.loads(report_sarif([_f()], _score()))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]
            == b["runs"][0]["results"][0]["partialFingerprints"]
        )

    def test_fingerprint_differs_across_check_ids(self):
        a = json.loads(report_sarif([_f(check_id="CB-001")], _score()))
        b = json.loads(report_sarif([_f(check_id="CB-002")], _score()))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]["pipelineCheckV1"]
            != b["runs"][0]["results"][0]["partialFingerprints"]["pipelineCheckV1"]
        )

    def test_fingerprint_differs_across_resources(self):
        a = json.loads(report_sarif([_f(resource="proj-a")], _score()))
        b = json.loads(report_sarif([_f(resource="proj-b")], _score()))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]["pipelineCheckV1"]
            != b["runs"][0]["results"][0]["partialFingerprints"]["pipelineCheckV1"]
        )

    def test_fingerprint_uses_snippet_when_file_readable(self, tmp_path):
        # Two findings on the same file, same line content, different
        # surrounding lines -> same fingerprint (content drives the hash,
        # not unrelated line additions).
        from pipeline_check.core.checks.base import Location

        a_path = tmp_path / "a.yml"
        a_path.write_text("uses: actions/checkout@v4\nname: build\n")
        f1 = _f(resource=str(a_path))
        f1.locations = [Location(path=str(a_path), start_line=1, end_line=1)]

        b_path = tmp_path / "b.yml"
        b_path.write_text(
            "name: build\nname: test\nuses: actions/checkout@v4\n"
        )
        f2 = _f(resource=str(b_path))
        f2.locations = [Location(path=str(b_path), start_line=3, end_line=3)]

        out_a = json.loads(report_sarif([f1], _score()))
        out_b = json.loads(report_sarif([f2], _score()))
        # Same line content but different paths -> different fingerprints
        # (path is part of the hash inputs).
        assert (
            out_a["runs"][0]["results"][0]["partialFingerprints"]
                ["pipelineCheckV1"]
            != out_b["runs"][0]["results"][0]["partialFingerprints"]
                ["pipelineCheckV1"]
        )

    def test_fingerprint_changes_when_offending_line_changes(self, tmp_path):
        from pipeline_check.core.checks.base import Location

        path = tmp_path / "wf.yml"
        # Pre-fix offending line.
        path.write_text("uses: actions/checkout@v4\n")
        f_before = _f(resource=str(path))
        f_before.locations = [Location(path=str(path), start_line=1, end_line=1)]
        before = json.loads(report_sarif([f_before], _score()))
        before_fp = before["runs"][0]["results"][0]["partialFingerprints"]

        # Post-fix offending line (digest pin).
        path.write_text("uses: actions/checkout@a1b2c3d4e5f6...\n")
        f_after = _f(resource=str(path))
        f_after.locations = [Location(path=str(path), start_line=1, end_line=1)]
        after = json.loads(report_sarif([f_after], _score()))
        after_fp = after["runs"][0]["results"][0]["partialFingerprints"]

        assert before_fp != after_fp, (
            "Editing the offending line must produce a new fingerprint "
            "so GHCS resolves the prior alert."
        )

    def test_fingerprint_stable_when_unrelated_line_changes(self, tmp_path):
        from pipeline_check.core.checks.base import Location

        path = tmp_path / "wf.yml"
        path.write_text(
            "name: build\n"
            "uses: actions/checkout@v4\n"
            "run: pytest\n"
        )
        f1 = _f(resource=str(path))
        f1.locations = [Location(path=str(path), start_line=2, end_line=2)]
        first = json.loads(report_sarif([f1], _score()))
        first_fp = first["runs"][0]["results"][0]["partialFingerprints"]

        # Swap an unrelated line. Offending line content is unchanged.
        path.write_text(
            "name: build\n"
            "uses: actions/checkout@v4\n"
            "run: pytest -v\n"
        )
        f2 = _f(resource=str(path))
        f2.locations = [Location(path=str(path), start_line=2, end_line=2)]
        second = json.loads(report_sarif([f2], _score()))
        second_fp = second["runs"][0]["results"][0]["partialFingerprints"]

        assert first_fp == second_fp, (
            "An unrelated edit must not invalidate the fingerprint."
        )

    def test_fingerprint_falls_back_for_non_file_resource(self):
        # AWS-style resources (no Location, no readable file) still
        # need a stable fingerprint based on (id, resource).
        a = json.loads(report_sarif(
            [_f(resource="arn:aws:lambda:us-east-1:1234:function:foo")],
            _score(),
        ))
        b = json.loads(report_sarif(
            [_f(resource="arn:aws:lambda:us-east-1:1234:function:foo")],
            _score(),
        ))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]
            == b["runs"][0]["results"][0]["partialFingerprints"]
        )

    def test_arn_fingerprint_is_cross_platform_stable(self, monkeypatch):
        # Resource-only findings (no Location) carry AWS ARNs / IAM
        # role names whose case is meaningful. The Windows branch of
        # _normalize_path lowercases its input, so passing an ARN
        # through it would produce a Windows-only fingerprint that
        # disagrees with the Linux scan and breaks GHCS dedup.
        # Drive the os.name switch directly so the assertion runs the
        # same way on every CI runner.
        from pipeline_check.core import sarif_reporter as sr

        arn = "arn:aws:lambda:US-EAST-1:1234:function:Foo"

        monkeypatch.setattr(sr.os, "name", "posix")
        linux = json.loads(report_sarif([_f(resource=arn)], _score()))

        monkeypatch.setattr(sr.os, "name", "nt")
        windows = json.loads(report_sarif([_f(resource=arn)], _score()))

        assert (
            linux["runs"][0]["results"][0]["partialFingerprints"]
            == windows["runs"][0]["results"][0]["partialFingerprints"]
        ), (
            "ARN fingerprints must not depend on os.name — Windows "
            "case-folding would otherwise diverge from Linux scans of "
            "the same AWS account and break GHCS dedup."
        )


class TestChainFingerprints:
    """Same dedup behavior for attack-chain results."""

    def test_chain_result_carries_a_fingerprint(self):
        from pipeline_check.core.chains import Chain
        from pipeline_check.core.checks.base import Confidence

        chain = Chain(
            chain_id="AC-001",
            title="Test chain",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            summary="s", narrative="n",
            mitre_attack=["T1078"],
            kill_chain_phase="initial-access",
            triggering_check_ids=["GHA-002", "GHA-005"],
            triggering_findings=[],
            resources=["wf.yml"],
            references=[], recommendation="r",
        )
        out = json.loads(report_sarif([_f()], _score(), chains=[chain]))
        # Chain result is appended after finding results.
        chain_result = out["runs"][0]["results"][-1]
        assert chain_result["ruleId"] == "AC-001"
        assert "partialFingerprints" in chain_result
        assert "pipelineCheckV1" in chain_result["partialFingerprints"]

    def test_chain_fingerprint_stable_for_same_resource_set(self):
        from pipeline_check.core.chains import Chain
        from pipeline_check.core.checks.base import Confidence

        def make_chain(resources):
            return Chain(
                chain_id="AC-001",
                title="t", severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="s", narrative="n",
                mitre_attack=[],
                kill_chain_phase="",
                triggering_check_ids=["GHA-002", "GHA-005"],
                triggering_findings=[],
                resources=resources,
                references=[], recommendation="",
            )

        # Same resources, different list ordering -> same fingerprint.
        a = json.loads(report_sarif(
            [], _score(), chains=[make_chain(["a.yml", "b.yml"])],
        ))
        b = json.loads(report_sarif(
            [], _score(), chains=[make_chain(["b.yml", "a.yml"])],
        ))
        assert (
            a["runs"][0]["results"][0]["partialFingerprints"]
            == b["runs"][0]["results"][0]["partialFingerprints"]
        )


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


class TestScanStatus:
    """The run carries scan_status so a SARIF consumer can detect an
    incomplete scan."""

    def test_in_run_properties(self):
        status = {
            "complete": False, "files_scanned": 1,
            "files_unparsed": 1, "degraded_modules": 0, "reason": "x",
        }
        out = json.loads(report_sarif([_f()], _score(), scan_status=status))
        assert out["runs"][0]["properties"]["scan_status"] == status

    def test_omitted_when_none(self):
        out = json.loads(report_sarif([_f()], _score()))
        assert "scan_status" not in out["runs"][0]["properties"]


class TestReachabilityProperties:
    """The chain result carries via_dataflow so machine consumers can
    tell the proven dataflow tier from the shared-job co-location tier."""

    def _props(self, *, via_dataflow):
        out = json.loads(report_sarif(
            [_f()], _score(),
            chains=[make_reach_chain(via_dataflow=via_dataflow)],
        ))
        return out["runs"][0]["results"][-1]["properties"]

    def test_dataflow_tier(self):
        props = self._props(via_dataflow=True)
        assert props["confirmed_reachable"] is True
        assert props["via_dataflow"] is True

    def test_shared_job_tier(self):
        props = self._props(via_dataflow=False)
        assert props["confirmed_reachable"] is True
        assert props["via_dataflow"] is False
