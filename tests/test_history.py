"""Tests for the findings-history dashboard."""
from __future__ import annotations

import datetime as _dt
import json
import time
from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import history_cmd
from pipeline_check.core.history import (
    HistoryReport,
    HistorySnapshot,
    _parse_timestamp_from_name,
    load_history,
    render_html,
)

# ── Timestamp parsing ──────────────────────────────────────────────


class TestParseTimestampFromName:
    def test_compact_with_separator(self) -> None:
        ts = _parse_timestamp_from_name("scan-20260519-120000.json")
        assert ts == _dt.datetime(2026, 5, 19, 12, 0, 0)

    def test_compact_without_separator(self) -> None:
        ts = _parse_timestamp_from_name("20260519120000.json")
        assert ts == _dt.datetime(2026, 5, 19, 12, 0, 0)

    def test_iso_date_only(self) -> None:
        ts = _parse_timestamp_from_name("2026-05-19.json")
        assert ts == _dt.datetime(2026, 5, 19, 0, 0, 0)

    def test_iso_with_time(self) -> None:
        ts = _parse_timestamp_from_name("scan-2026-05-19T12-30-45.json")
        assert ts == _dt.datetime(2026, 5, 19, 12, 30, 45)

    def test_no_recognizable_pattern(self) -> None:
        assert _parse_timestamp_from_name("latest.json") is None


# ── load_history ──────────────────────────────────────────────────


def _scan_doc(
    *,
    score: int = 90,
    grade: str = "A",
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    extra_findings: list[dict] | None = None,
) -> dict:
    findings = []
    for sev, count in (
        ("CRITICAL", critical), ("HIGH", high),
        ("MEDIUM", medium), ("LOW", low),
    ):
        for i in range(count):
            findings.append({
                "check_id": f"{sev[:3]}-{i:03d}",
                "title": "synthetic",
                "severity": sev,
                "resource": "synthetic.yaml",
                "passed": False,
            })
    if extra_findings:
        findings.extend(extra_findings)
    return {
        "schema_version": 1,
        "tool_version": "test",
        "score": {
            "grade": grade,
            "score": score,
            "summary": {
                "CRITICAL": {"failed": critical, "passed": 0},
                "HIGH":     {"failed": high,     "passed": 0},
                "MEDIUM":   {"failed": medium,   "passed": 0},
                "LOW":      {"failed": low,      "passed": 0},
            },
        },
        "findings": findings,
    }


def _write_scan(
    dir_path: Path, name: str, doc: dict, *,
    mtime: float | None = None,
) -> Path:
    p = dir_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    if mtime is not None:
        import os
        os.utime(p, (mtime, mtime))
    return p


class TestLoadHistory:
    def test_load_sorts_chronologically_by_filename_timestamp(
        self, tmp_path: Path,
    ) -> None:
        # Write three scans out of chronological order; loader must
        # sort by parsed filename timestamp, not directory walk order.
        _write_scan(
            tmp_path, "scan-20260519-120000.json",
            _scan_doc(score=85, grade="B", high=3),
        )
        _write_scan(
            tmp_path, "scan-20260517-080000.json",
            _scan_doc(score=70, grade="C", high=8),
        )
        _write_scan(
            tmp_path, "scan-20260518-100000.json",
            _scan_doc(score=80, grade="B", high=5),
        )
        report = load_history(tmp_path)
        timestamps = [s.timestamp for s in report.snapshots]
        assert timestamps == sorted(timestamps)
        assert report.snapshots[0].score == 70
        assert report.snapshots[-1].score == 85
        assert report.warnings == ()

    def test_falls_back_to_mtime_for_unrecognized_names(
        self, tmp_path: Path,
    ) -> None:
        # File with no recognizable timestamp pattern → mtime
        # determines ordering.
        old = time.time() - 3600
        new = time.time()
        _write_scan(
            tmp_path, "latest.json",
            _scan_doc(score=95), mtime=new,
        )
        _write_scan(
            tmp_path, "previous.json",
            _scan_doc(score=70), mtime=old,
        )
        report = load_history(tmp_path)
        scores = [s.score for s in report.snapshots]
        assert scores == [70, 95]

    def test_malformed_json_skipped_with_warning(
        self, tmp_path: Path,
    ) -> None:
        _write_scan(
            tmp_path, "good-20260519-120000.json", _scan_doc(score=80),
        )
        (tmp_path / "bad-20260520-120000.json").write_text(
            "{not json", encoding="utf-8",
        )
        report = load_history(tmp_path)
        assert len(report.snapshots) == 1
        assert len(report.warnings) == 1
        assert "bad-20260520-120000.json" in report.warnings[0]

    def test_non_dict_top_level_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "20260519-120000.json").write_text(
            "[]", encoding="utf-8",
        )
        report = load_history(tmp_path)
        assert report.snapshots == ()
        assert report.warnings and "not an object" in report.warnings[0]

    def test_rule_counts_extracted_from_findings(
        self, tmp_path: Path,
    ) -> None:
        doc = _scan_doc(score=80, extra_findings=[
            {"check_id": "GHA-001", "passed": False},
            {"check_id": "GHA-001", "passed": False},
            {"check_id": "GHA-014", "passed": False},
            {"check_id": "GHA-014", "passed": True},  # excluded
        ])
        _write_scan(tmp_path, "20260519-120000.json", doc)
        report = load_history(tmp_path)
        assert report.snapshots[0].rule_counts == Counter({
            "GHA-001": 2, "GHA-014": 1,
        })

    def test_missing_dir_raises_value_error(
        self, tmp_path: Path,
    ) -> None:
        with pytest.raises(ValueError):
            load_history(tmp_path / "does-not-exist")

    def test_file_not_dir_raises_value_error(
        self, tmp_path: Path,
    ) -> None:
        f = tmp_path / "a.json"
        f.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError):
            load_history(f)


# ── render_html ────────────────────────────────────────────────────


class TestRenderHtml:
    def test_empty_report_renders_friendly_placeholder(self) -> None:
        out = render_html(HistoryReport(snapshots=()))
        assert out.startswith("<!DOCTYPE html>")
        assert "No scan-output JSON files found" in out
        assert "</html>" in out.rstrip()

    def test_snapshots_render_severity_chart_and_score_chart(
        self, tmp_path: Path,
    ) -> None:
        _write_scan(
            tmp_path, "scan-20260518-080000.json",
            _scan_doc(score=80, grade="B", high=5, medium=2),
        )
        _write_scan(
            tmp_path, "scan-20260519-120000.json",
            _scan_doc(score=95, grade="A", high=1),
        )
        report = load_history(tmp_path)
        out = render_html(report)
        assert "Failed findings by severity" in out
        assert "Score over time" in out
        # Inline SVG should render two polylines (severity chart
        # carries HIGH + MEDIUM lines).
        assert out.count("<polyline") >= 2
        # Top rules table renders even with synthesized check_ids.
        assert "Top 15 firing rules" in out

    def test_warnings_rendered_in_html(self) -> None:
        report = HistoryReport(
            snapshots=(HistorySnapshot(
                path="x.json",
                timestamp=_dt.datetime(2026, 5, 19, 12, 0, 0),
                score=90, grade="A",
                failed_by_severity={
                    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0,
                },
                total_failed=1,
                rule_counts=Counter({"GHA-001": 1}),
            ),),
            warnings=("bad.json: JSON decode error",),
        )
        out = render_html(report)
        assert "Skipped files" in out
        assert "bad.json: JSON decode error" in out

    def test_top_n_parameter_caps_rules_table(
        self, tmp_path: Path,
    ) -> None:
        # Twenty distinct firing rules in one snapshot; top_n=3
        # should clamp the table to 3 rows.
        findings = [
            {"check_id": f"RUL-{i:03d}", "passed": False}
            for i in range(20)
        ]
        _write_scan(
            tmp_path, "scan-20260519-120000.json",
            _scan_doc(score=50, extra_findings=findings),
        )
        report = load_history(tmp_path)
        out = render_html(report, top_n=3)
        rule_rows = sum(out.count(f"RUL-{i:03d}") for i in range(20))
        assert rule_rows == 3


# ── CLI integration ───────────────────────────────────────────────


class TestHistoryCli:
    def test_history_cli_writes_html_file(self, tmp_path: Path) -> None:
        history_dir = tmp_path / ".pipeline-check-history"
        history_dir.mkdir()
        _write_scan(
            history_dir, "scan-20260519-120000.json",
            _scan_doc(score=90, high=2),
        )
        out = tmp_path / "out.html"
        result = CliRunner().invoke(
            history_cmd,
            ["--dir", str(history_dir), "--output", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in body
        assert "Failed findings by severity" in body
        assert "1 snapshot(s)" in result.output

    def test_history_cli_errors_on_missing_dir(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            history_cmd,
            ["--dir", str(tmp_path / "nope"), "--output", "x.html"],
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output
