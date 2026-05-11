"""CLI integration tests for ``--write-baseline``.

The flag snapshots the current findings to a JSON file so subsequent
runs can suppress them via ``--baseline PATH``. These tests verify the
file is written, the shape matches what ``--baseline`` accepts, and
the round-trip suppresses prior findings on the next scan.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from click.testing import CliRunner

from pipeline_check.cli import scan


def _gha_repo_with_unpinned_action(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(textwrap.dedent("""
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: echo hi
    """).strip() + "\n")
    return tmp_path


class TestWriteBaseline:
    def test_writes_findings_to_path(self, tmp_path: Path) -> None:
        repo = _gha_repo_with_unpinned_action(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--write-baseline", str(baseline_path),
                "--no-chains",
                "--quiet",
            ],
        )
        # GHA-001 fires HIGH -> default gate (fail_on=CRITICAL) passes,
        # but exit code may be 0 or 1 depending on what else trips. The
        # baseline file should exist either way.
        assert baseline_path.exists(), result.output
        doc = json.loads(baseline_path.read_text(encoding="utf-8"))
        # Same shape as --output json.
        assert "findings" in doc
        assert any(
            f["check_id"] == "GHA-001" and not f["passed"]
            for f in doc["findings"]
        )

    def test_baseline_round_trip_suppresses_findings(
        self, tmp_path: Path,
    ) -> None:
        """Write a baseline, then pass it on the next scan, gate passes."""
        repo = _gha_repo_with_unpinned_action(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        runner = CliRunner()

        # Step 1: write the baseline.
        result1 = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--write-baseline", str(baseline_path),
                "--no-chains",
                "--quiet",
            ],
        )
        assert baseline_path.exists(), result1.output

        # Step 2: re-scan with --baseline + --fail-on HIGH. Without
        # the baseline this would trip on GHA-001 (HIGH); with it,
        # the gate should pass.
        result2 = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--baseline", str(baseline_path),
                "--fail-on", "HIGH",
                "--no-chains",
                "--quiet",
            ],
        )
        assert result2.exit_code == 0, result2.output

    def test_baseline_announces_to_stderr_when_not_quiet(
        self, tmp_path: Path,
    ) -> None:
        repo = _gha_repo_with_unpinned_action(tmp_path)
        baseline_path = tmp_path / "baseline.json"
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--write-baseline", str(baseline_path),
                "--no-chains",
            ],
        )
        # The announce line goes to stderr, but the test runner merges
        # them into ``result.output`` on this click version.
        assert "[baseline] wrote" in result.output, result.output
        assert str(baseline_path) in result.output

    def test_unwritable_path_raises_usage_error(
        self, tmp_path: Path,
    ) -> None:
        repo = _gha_repo_with_unpinned_action(tmp_path)
        # A nested directory that doesn't exist makes the open() fail.
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--write-baseline", str(tmp_path / "missing-dir" / "b.json"),
                "--no-chains",
                "--quiet",
            ],
        )
        assert result.exit_code != 0
        assert "--write-baseline" in result.output
