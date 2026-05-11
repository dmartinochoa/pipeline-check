"""Unit tests for the external SARIF ingest parser
(``pipeline_check.core.sarif_ingest``).

Covers the synthetic-rule-id format, severity mapping (level +
security-severity override), locations, prose extraction, error
modes (malformed JSON, missing fields, oversized files), and the
caps that prevent runaway loads.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.sarif_ingest import (
    IngestResult,
    parse_sarif_file,
    parse_sarif_text,
)

# ── Helpers ─────────────────────────────────────────────────────────


def _trivy_sarif(rule_id: str = "AVD-AWS-0028", **overrides) -> dict:
    """Synthesize a minimal Trivy-shaped SARIF document."""
    base = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Trivy",
                "version": "0.50.0",
                "rules": [{
                    "id": rule_id,
                    "shortDescription": {
                        "text": "S3 bucket has no logging",
                    },
                    "fullDescription": {
                        "text": "Enable access logging on the bucket.",
                    },
                }],
            }},
            "results": [{
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"Bucket my-app-data triggered {rule_id}"},
                "properties": {"security-severity": "5.5"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "terraform/s3.tf"},
                    "region": {"startLine": 14, "endLine": 16},
                }}],
            }],
        }],
    }
    base.update(overrides)
    return base


def _checkov_sarif(rule_id: str = "CKV_AWS_61") -> dict:
    """Synthesize a Checkov-shaped SARIF document. Differences from
    Trivy: lowercase tool name, no security-severity override,
    fullDescription as the main prose."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "checkov",
                "rules": [{
                    "id": rule_id,
                    "fullDescription": {
                        "text": (
                            "IAM role has wildcard in trust policy. "
                            "Restrict the principal to specific accounts."
                        ),
                    },
                }],
            }},
            "results": [{
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": "IAM role 'admin-cross-account' has * in trust",
                },
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "iam.tf"},
                    "region": {"startLine": 42},
                }}],
            }],
        }],
    }


# ── Happy path: typical Trivy / Checkov shapes ────────────────────


class TestHappyPath:
    def test_parses_trivy_sarif_into_one_finding(self):
        r = parse_sarif_text(json.dumps(_trivy_sarif()))
        assert r.warnings == []
        assert r.source == "trivy"
        assert r.source_version == "0.50.0"
        assert len(r.findings) == 1
        f = r.findings[0]
        assert f.check_id == "INGEST-trivy-AVD-AWS-0028"
        assert f.severity == Severity.MEDIUM  # security-severity 5.5
        assert f.resource == "terraform/s3.tf"
        assert "Bucket my-app-data" in f.description
        assert f.recommendation == "Enable access logging on the bucket."
        assert not f.passed
        assert f.confidence == Confidence.MEDIUM
        assert len(f.locations) == 1
        assert f.locations[0].start_line == 14
        assert f.locations[0].end_line == 16

    def test_parses_checkov_sarif(self):
        r = parse_sarif_text(json.dumps(_checkov_sarif()))
        assert r.warnings == []
        assert r.source == "checkov"
        assert r.findings[0].check_id == "INGEST-checkov-CKV_AWS_61"
        # No security-severity override, level=warning -> MEDIUM.
        assert r.findings[0].severity == Severity.MEDIUM

    def test_check_id_preserves_tool_provenance(self):
        """Two SARIF feeds with overlapping rule IDs must produce
        distinct check_ids so the chain engine doesn't merge them."""
        r_trivy = parse_sarif_text(
            json.dumps(_trivy_sarif(rule_id="CKV_AWS_61")),
        )
        r_checkov = parse_sarif_text(
            json.dumps(_checkov_sarif(rule_id="CKV_AWS_61")),
        )
        assert r_trivy.findings[0].check_id == "INGEST-trivy-CKV_AWS_61"
        assert r_checkov.findings[0].check_id == "INGEST-checkov-CKV_AWS_61"


# ── Severity mapping ────────────────────────────────────────────────


class TestSeverityMapping:
    def test_security_severity_critical_band(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["properties"]["security-severity"] = "9.5"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.CRITICAL

    def test_security_severity_high_band(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["properties"]["security-severity"] = "7.2"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.HIGH

    def test_security_severity_low_band(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["properties"]["security-severity"] = "1.5"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.LOW

    def test_security_severity_info_band(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["properties"]["security-severity"] = "0.0"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.INFO

    def test_falls_back_to_level_when_no_security_severity(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("properties", None)
        # level=error in fixture -> HIGH per the level mapping.
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.HIGH

    def test_falls_back_to_info_when_neither_present(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("properties", None)
        sarif["runs"][0]["results"][0].pop("level", None)
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.INFO

    def test_invalid_security_severity_falls_back_to_level(self):
        """A non-numeric security-severity (some scanners ship the
        string 'high' instead of a number) should drop through to
        level-based mapping rather than crash."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["properties"]["security-severity"] = "high"
        sarif["runs"][0]["results"][0]["level"] = "warning"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].severity == Severity.MEDIUM

    def test_each_level_maps_predictably(self):
        for level, expected in [
            ("error", Severity.HIGH),
            ("warning", Severity.MEDIUM),
            ("note", Severity.LOW),
            ("none", Severity.INFO),
        ]:
            sarif = _trivy_sarif()
            sarif["runs"][0]["results"][0].pop("properties", None)
            sarif["runs"][0]["results"][0]["level"] = level
            r = parse_sarif_text(json.dumps(sarif))
            assert r.findings[0].severity == expected, (
                f"level={level} should map to {expected}"
            )


# ── Locations ──────────────────────────────────────────────────────


class TestLocations:
    def test_multiple_locations_become_multiple_location_rows(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["locations"] = [
            {"physicalLocation": {
                "artifactLocation": {"uri": "a.tf"},
                "region": {"startLine": 1},
            }},
            {"physicalLocation": {
                "artifactLocation": {"uri": "b.tf"},
                "region": {"startLine": 5},
            }},
        ]
        r = parse_sarif_text(json.dumps(sarif))
        assert len(r.findings[0].locations) == 2
        # Resource handle = first location's URI.
        assert r.findings[0].resource == "a.tf"

    def test_missing_locations_falls_back_to_source_path(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("locations", None)
        r = parse_sarif_text(json.dumps(sarif), file_path="trivy.sarif")
        assert r.findings[0].locations == []
        assert r.findings[0].resource == "trivy.sarif"

    def test_logical_only_locations_dropped(self):
        """SARIF allows logical-only locations (function name
        without a file). These can't anchor a Location and should
        be dropped silently."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0]["locations"] = [
            {"logicalLocations": [{"name": "some_function"}]},
        ]
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].locations == []


# ── Rule-id resolution and provenance ─────────────────────────────


class TestRuleIdResolution:
    def test_rule_id_from_top_level(self):
        r = parse_sarif_text(json.dumps(_trivy_sarif()))
        assert r.findings[0].check_id.endswith("AVD-AWS-0028")

    def test_rule_id_from_nested_rule_block(self):
        """Some tools omit the top-level ``ruleId`` and use the
        ``rule.id`` shape instead. Both should resolve."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("ruleId")
        sarif["runs"][0]["results"][0]["rule"] = {"id": "AVD-AWS-0028"}
        r = parse_sarif_text(json.dumps(sarif))
        assert len(r.findings) == 1
        assert "AVD-AWS-0028" in r.findings[0].check_id

    def test_result_with_no_rule_id_but_message_kept_with_synthetic_id(self):
        """SARIF results missing ``ruleId`` (and ``rule.id``) are
        salvaged when a non-empty ``message.text`` survives — the
        ingest contract is best-effort, and free-form tools that
        skip rule metadata still produce a finding under a
        ``message-only-<hash>`` synthetic id. Documented on
        ``_convert_result``."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("ruleId")
        r = parse_sarif_text(json.dumps(sarif))
        assert len(r.findings) == 1
        cid = r.findings[0].check_id
        # ``INGEST-<tool>-message-only-<10-char-hash>`` form.
        assert "message-only-" in cid

    def test_result_with_no_rule_id_and_no_message_dropped(self):
        """The truly-empty case (no ruleId and no message) yields
        nothing — there's no salvageable identifier left."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("ruleId")
        sarif["runs"][0]["results"][0].pop("message", None)
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings == []

    def test_double_prefix_avoided(self):
        """If a SARIF source already prefixes its rule with
        INGEST-, don't double-stuff it."""
        sarif = _trivy_sarif(rule_id="INGEST-cosign-attestation")
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].check_id == "INGEST-cosign-attestation"

    def test_tool_name_normalization(self):
        """Mixed-case + spaces in the driver name should slug
        to a stable lowercase identifier."""
        sarif = _trivy_sarif()
        sarif["runs"][0]["tool"]["driver"]["name"] = "CodeQL CLI"
        r = parse_sarif_text(json.dumps(sarif))
        assert r.source == "codeql-cli"
        assert r.findings[0].check_id.startswith("INGEST-codeql-cli-")


# ── Prose extraction ──────────────────────────────────────────────


class TestProseExtraction:
    def test_recommendation_from_full_description(self):
        r = parse_sarif_text(json.dumps(_trivy_sarif()))
        assert r.findings[0].recommendation == (
            "Enable access logging on the bucket."
        )

    def test_recommendation_from_help_text_when_no_full_description(self):
        sarif = _trivy_sarif()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rules[0].pop("fullDescription", None)
        rules[0]["help"] = {"text": "See vendor docs at example.com"}
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].recommendation == "See vendor docs at example.com"

    def test_title_falls_back_to_rule_id_when_no_short_description(self):
        sarif = _trivy_sarif()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rules[0].pop("shortDescription", None)
        r = parse_sarif_text(json.dumps(sarif))
        assert r.findings[0].title == "AVD-AWS-0028"

    def test_description_falls_back_when_no_message(self):
        sarif = _trivy_sarif()
        sarif["runs"][0]["results"][0].pop("message", None)
        r = parse_sarif_text(json.dumps(sarif))
        # Falls back to a generic note pointing at the source.
        assert "trivy" in r.findings[0].description.lower()
        assert "AVD-AWS-0028" in r.findings[0].description


# ── Error modes ───────────────────────────────────────────────────


class TestErrorModes:
    def test_malformed_json_returns_warning_no_findings(self):
        r = parse_sarif_text("{ this is not :: valid")
        assert r.findings == []
        assert any("JSON parse error" in w for w in r.warnings)

    def test_top_level_array_returns_warning(self):
        r = parse_sarif_text(json.dumps([1, 2, 3]))
        assert r.findings == []
        assert any("not a JSON object" in w for w in r.warnings)

    def test_missing_runs_array_returns_warning(self):
        r = parse_sarif_text(json.dumps({"version": "2.1.0"}))
        assert r.findings == []
        assert any("missing ``runs``" in w for w in r.warnings)

    def test_missing_version_warns_but_still_parses(self):
        sarif = _trivy_sarif()
        sarif.pop("version")
        r = parse_sarif_text(json.dumps(sarif))
        assert any("version" in w for w in r.warnings)
        # Best-effort: still parses.
        assert len(r.findings) == 1

    def test_v1_sarif_warns_but_attempts_parse(self):
        sarif = _trivy_sarif()
        sarif["version"] = "1.0.0"
        r = parse_sarif_text(json.dumps(sarif))
        assert any("non-2.x" in w for w in r.warnings)


# ── Disk-loading + caps ────────────────────────────────────────────


class TestFileLoading:
    def test_parse_sarif_file_round_trip(self, tmp_path: Path):
        path = tmp_path / "trivy.sarif"
        path.write_text(json.dumps(_trivy_sarif()))
        r = parse_sarif_file(path)
        assert r.warnings == []
        assert len(r.findings) == 1

    def test_missing_file_returns_warning(self, tmp_path: Path):
        r = parse_sarif_file(tmp_path / "nope.sarif")
        assert r.findings == []
        assert any("does not exist" in w for w in r.warnings)

    def test_non_utf8_file_returns_warning(self, tmp_path: Path):
        path = tmp_path / "bad.sarif"
        path.write_bytes(b"\xff\xfe not utf-8")
        r = parse_sarif_file(path)
        assert r.findings == []
        assert any("read failed" in w for w in r.warnings)

    def test_max_results_cap_truncates_and_warns(self):
        sarif = _trivy_sarif()
        # Inflate to 5 results, cap at 2.
        result_template = sarif["runs"][0]["results"][0]
        sarif["runs"][0]["results"] = [
            dict(result_template) for _ in range(5)
        ]
        r = parse_sarif_text(json.dumps(sarif), max_results=2)
        assert len(r.findings) == 2
        assert any("max_results cap" in w for w in r.warnings)


# ── IngestResult dataclass shape ──────────────────────────────────


class TestIngestResultShape:
    def test_default_construction(self):
        r = IngestResult()
        assert r.findings == []
        assert r.warnings == []
        assert r.source == ""
        assert r.source_version == ""
        assert r.file_path == ""
