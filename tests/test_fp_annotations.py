"""Tests for the per-repo false-positive annotation store + CLI surface."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import fp_stats_cmd, scan
from pipeline_check.core.checks.base import Confidence, Finding, Severity
from pipeline_check.core.fp_annotations import (
    FPAnnotation,
    annotation_index,
    append_annotation,
    demote_one_rung,
    fp_stats,
    load_annotations,
)
from pipeline_check.core.scanner import ScanMetadata

# ── Demotion math ──────────────────────────────────────────────────


class TestDemoteOneRung:
    def test_high_demotes_to_medium(self):
        assert demote_one_rung(Confidence.HIGH) == Confidence.MEDIUM

    def test_medium_demotes_to_low(self):
        assert demote_one_rung(Confidence.MEDIUM) == Confidence.LOW

    def test_low_saturates(self):
        assert demote_one_rung(Confidence.LOW) == Confidence.LOW


# ── File I/O ───────────────────────────────────────────────────────


class TestLoadAnnotations:
    def test_missing_file_returns_empty(self, tmp_path: Path):
        assert load_annotations(tmp_path / "missing.json") == []

    def test_corrupt_json_returns_empty(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        p.write_text("{not valid json")
        assert load_annotations(p) == []

    def test_wrong_root_type_returns_empty(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        p.write_text("[]")  # array, not object
        assert load_annotations(p) == []

    def test_skips_malformed_entries(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        p.write_text(json.dumps({
            "version": 1,
            "annotations": [
                {"check_id": "GHA-001", "resource": "wf.yml"},
                {"check_id": 42, "resource": "wf.yml"},  # bad type
                {"resource": "wf.yml"},  # missing check_id
                "not-a-dict",
            ],
        }))
        loaded = load_annotations(p)
        assert len(loaded) == 1
        assert loaded[0].check_id == "GHA-001"

    def test_uppercases_check_id_on_load(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        p.write_text(json.dumps({
            "version": 1,
            "annotations": [{"check_id": "gha-001", "resource": "wf.yml"}],
        }))
        loaded = load_annotations(p)
        assert loaded[0].check_id == "GHA-001"


class TestAppendAnnotation:
    def test_creates_file_when_missing(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        wrote = append_annotation("GHA-016", ".github/workflows/ci.yml", path=p)
        assert wrote is True
        assert p.is_file()
        loaded = load_annotations(p)
        assert len(loaded) == 1
        assert loaded[0].check_id == "GHA-016"
        assert loaded[0].resource == ".github/workflows/ci.yml"
        assert loaded[0].annotated_at  # ISO timestamp populated

    def test_idempotent_on_duplicate(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        append_annotation("GHA-016", "wf.yml", path=p)
        wrote_again = append_annotation("GHA-016", "wf.yml", path=p)
        assert wrote_again is False
        # Still one entry; no duplicate appended.
        assert len(load_annotations(p)) == 1

    def test_appends_distinct_pair(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        append_annotation("GHA-016", "wf.yml", path=p)
        append_annotation("GHA-016", "other.yml", path=p)
        append_annotation("GHA-008", "wf.yml", path=p)
        assert len(load_annotations(p)) == 3

    def test_uppercases_on_write(self, tmp_path: Path):
        p = tmp_path / "fp.json"
        append_annotation("gha-001", "wf.yml", path=p)
        loaded = load_annotations(p)
        assert loaded[0].check_id == "GHA-001"

    def test_rejects_empty_check_id(self, tmp_path: Path):
        with pytest.raises(ValueError):
            append_annotation("", "wf.yml", path=tmp_path / "fp.json")

    def test_rejects_empty_resource(self, tmp_path: Path):
        with pytest.raises(ValueError):
            append_annotation("GHA-001", "  ", path=tmp_path / "fp.json")


# ── Stats + index ──────────────────────────────────────────────────


class TestFPStats:
    def test_sorted_by_count_desc_then_id_asc(self):
        annotations = [
            FPAnnotation(check_id="GHA-016", resource="a"),
            FPAnnotation(check_id="GHA-016", resource="b"),
            FPAnnotation(check_id="GHA-008", resource="a"),
            FPAnnotation(check_id="GHA-001", resource="a"),
            FPAnnotation(check_id="GHA-001", resource="b"),
        ]
        stats = fp_stats(annotations)
        assert stats == [
            ("GHA-001", 2),  # tied with GHA-016 at 2; lexically smaller wins
            ("GHA-016", 2),
            ("GHA-008", 1),
        ]

    def test_empty_annotations(self):
        assert fp_stats([]) == []


def test_annotation_index_keys_uppercase():
    """The Scanner looks up ``(check_id_upper, resource)`` so the
    index keys must already be upper-cased."""
    annotations = [
        FPAnnotation(check_id="GHA-001", resource="wf.yml"),
    ]
    idx = annotation_index(annotations)
    assert ("GHA-001", "wf.yml") in idx


# ── CLI: fp-stats subcommand ───────────────────────────────────────


@pytest.fixture
def runner():
    return CliRunner()


class TestFPStatsCommand:
    def test_no_annotations(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(fp_stats_cmd, [])
        assert result.exit_code == 0
        assert "no annotations found" in result.stderr

    def test_renders_stats(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        append_annotation("GHA-001", "wf.yml")
        append_annotation("GHA-001", "other.yml")
        append_annotation("GHA-016", "wf.yml")
        result = runner.invoke(fp_stats_cmd, [])
        assert result.exit_code == 0
        assert "3 annotation(s)" in result.output
        assert "GHA-001" in result.output
        assert "2 votes" in result.output  # GHA-001 has 2 votes
        assert "1 vote" in result.output and "1 votes" not in result.output


# ── CLI: --annotate-fp early-exit ──────────────────────────────────


def _mock_meta():
    return ScanMetadata(provider="aws")


class TestAnnotateFPFlag:
    def test_writes_entry_and_exits(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # No Scanner mock needed: --annotate-fp short-circuits before
        # any scan starts.
        result = runner.invoke(scan, [
            "--annotate-fp", "GHA-001", ".github/workflows/ci.yml",
        ])
        assert result.exit_code == 0
        assert "recorded GHA-001:" in result.output
        loaded = load_annotations(tmp_path / ".pipeline-check-fp.json")
        assert len(loaded) == 1
        assert loaded[0].check_id == "GHA-001"

    def test_idempotent_via_cli(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner.invoke(scan, ["--annotate-fp", "GHA-001", "wf.yml"])
        result = runner.invoke(scan, ["--annotate-fp", "GHA-001", "wf.yml"])
        assert result.exit_code == 0
        assert "already present" in result.output


# ── Scanner integration: confidence demotion at scan time ──────────


class TestScannerDemotion:
    """The Scanner reads the annotation file once per run and demotes
    matching findings one confidence rung. Findings at MEDIUM go to
    LOW; HIGH rules with no matching annotation stay HIGH."""

    def _ran_finding(
        self, check_id: str, resource: str, base: Confidence,
    ) -> Finding:
        return Finding(
            check_id=check_id, title="t", severity=Severity.HIGH,
            resource=resource, description="d",
            recommendation="r", passed=False,
            confidence=base,
        )

    def test_matching_annotation_demotes_high_to_medium(
        self, tmp_path, monkeypatch,
    ):
        # Set up an annotation file at cwd's default path.
        monkeypatch.chdir(tmp_path)
        append_annotation("CB-001", "pipeline-x")

        # Drive the Scanner directly with a pre-built finding list.
        # We run the per-finding loop's demotion manually, mirroring
        # the scanner.run() block. The Scanner's run() flow is
        # exercised end-to-end in the broader suite; here we focus
        # on the (fp_index, finding) interaction.
        f = self._ran_finding("CB-001", "pipeline-x", Confidence.HIGH)
        annotations = load_annotations(".pipeline-check-fp.json")
        idx = annotation_index(annotations)
        if (f.check_id.upper(), f.resource) in idx:
            f.confidence = demote_one_rung(f.confidence)
        assert f.confidence == Confidence.MEDIUM

    def test_non_matching_annotation_leaves_finding_alone(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        append_annotation("CB-001", "other-pipeline")
        f = self._ran_finding("CB-001", "pipeline-x", Confidence.HIGH)
        annotations = load_annotations(".pipeline-check-fp.json")
        idx = annotation_index(annotations)
        if (f.check_id.upper(), f.resource) in idx:
            f.confidence = demote_one_rung(f.confidence)
        assert f.confidence == Confidence.HIGH

    def test_scanner_constructor_accepts_fp_path(self, tmp_path):
        """Smoke test the constructor accepts the new kwarg without
        error. Real demotion behavior is exercised end-to-end below."""
        from pipeline_check.core.scanner import Scanner
        scanner = Scanner(
            pipeline="aws", region="us-east-1",
            fp_annotations_path=str(tmp_path / "missing.json"),
        )
        assert scanner._fp_annotations_path == str(
            tmp_path / "missing.json"
        )

    def test_end_to_end_demotion_via_run(self, tmp_path, monkeypatch):
        """Real Scanner.run path: build a fake provider returning a
        single HIGH-confidence finding, write an annotation matching
        it, run the scanner, confirm the finding came back at MEDIUM."""
        monkeypatch.chdir(tmp_path)
        append_annotation("FAKE-1", "fake-resource")

        from pipeline_check.core import providers as _providers
        from pipeline_check.core.checks.base import (
            BaseCheck,
        )
        from pipeline_check.core.checks.base import (
            Confidence as Cf,
        )
        from pipeline_check.core.checks.base import (
            Severity as Sv,
        )
        from pipeline_check.core.providers.base import BaseProvider

        class _FakeCheck(BaseCheck):
            PROVIDER = "fake-provider-fp"

            def run(self):
                return [Finding(
                    check_id="FAKE-1", title="t", severity=Sv.HIGH,
                    resource="fake-resource", description="d",
                    recommendation="r", passed=False,
                    confidence=Cf.HIGH,
                )]

        class _FakeProvider(BaseProvider):
            NAME = "fake-provider-fp"

            def build_context(self, **_):
                return object()

            @property
            def check_classes(self):
                return [_FakeCheck]

        _providers.register(_FakeProvider())
        try:
            from pipeline_check.core.scanner import Scanner
            scanner = Scanner(pipeline="fake-provider-fp", chains_enabled=False)
            findings = scanner.run()
            assert len(findings) == 1
            assert findings[0].confidence == Cf.MEDIUM, (
                "FP-annotated finding should be demoted from HIGH to "
                "MEDIUM by the Scanner"
            )
        finally:
            _providers._REGISTRY.pop("fake-provider-fp", None)
