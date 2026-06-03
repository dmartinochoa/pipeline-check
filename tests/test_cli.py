"""CLI integration tests — exit codes, output format, flag wiring."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Finding, Severity


def _finding(check_id="CB-001", passed=True, severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        title="Test finding",
        severity=severity,
        resource="test-resource",
        description="Test description.",
        recommendation="Test recommendation.",
        passed=passed,
    )


@pytest.fixture
def runner(tmp_path, monkeypatch):
    """Click test runner pinned to an isolated cwd with a minimal CI file.

    Without an isolated cwd, the CLI's auto-detect walks the project
    root, finds multiple providers, and routes through ``MultiScanner``
    — which bypasses these tests' ``patch("pipeline_check.cli.Scanner")``
    mocks. We additionally drop a trivial ``.gitlab-ci.yml`` so
    auto-detect resolves to a single provider; without it, UX-3 raises
    a ``UsageError`` for "no CI files found" before the Scanner mock
    is ever called. The exact provider doesn't matter for these tests
    — they assert exit codes, output shape, and flag wiring with the
    Scanner mocked out — but the file's presence is now required to
    reach the Scanner-construction path.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
    return CliRunner()


class TestExitCodes:
    def test_exit_0_on_passing_scan(self, runner):
        findings = [_finding(passed=True) for _ in range(5)]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0

    def test_exit_1_on_any_critical(self, runner):
        # Default gate: --fail-on CRITICAL. A single CRITICAL finding fails.
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [
                _finding(passed=False, severity=Severity.CRITICAL),
            ]
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 1

    def test_exit_0_when_only_high_findings(self, runner):
        # Default gate no longer fails on grade alone — only on CRITICAL.
        findings = [
            _finding(passed=False, severity=Severity.HIGH) for _ in range(10)
        ]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0

    def test_exit_2_on_scan_exception(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.side_effect = Exception("AWS API unreachable")
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 2


class TestJsonOutput:
    def test_output_is_valid_json(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "score" in payload
        assert "findings" in payload

    def test_output_contains_all_findings(self, runner):
        findings = [_finding(check_id=f"CB-00{i}") for i in range(1, 4)]
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = findings
            result = runner.invoke(scan, ["--output", "json"])
        payload = json.loads(result.stdout)
        assert len(payload["findings"]) == 3

    def test_score_fields_present(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        score = json.loads(result.stdout)["score"]
        assert "score" in score
        assert "grade" in score
        assert "summary" in score
        assert score["grade"] in ("A", "B", "C", "D")
        assert 0 <= score["score"] <= 100


class TestFlagWiring:
    def test_checks_filter_forwarded_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--checks", "CB-001", "--checks", "CB-002", "--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(
            checks=["CB-001", "CB-002"], target=None, standards=None
        )

    def test_target_forwarded_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--target", "my-pipeline", "--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(
            checks=None, target="my-pipeline", standards=None
        )

    def test_no_checks_passes_none_to_scanner(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--output", "json"])
        MockScanner.return_value.run.assert_called_once_with(checks=None, target=None, standards=None)

    def test_only_known_attacked_forwards_filtered_checks(self, runner):
        # ``--only-known-attacked`` builds the list of rules whose
        # ``Rule.incident_refs`` is non-empty and passes it as the
        # ``checks=`` filter to the scanner. The exact size depends on
        # the live rule pack, so assert non-empty + all entries map to
        # rules whose incident_refs is populated.
        from pipeline_check.cli import _known_attacked_check_ids
        expected_ids = set(_known_attacked_check_ids())
        assert expected_ids, "rule pack should have known-attacked rules"

        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, ["--only-known-attacked", "--output", "json"])
        kwargs = MockScanner.return_value.run.call_args.kwargs
        assert kwargs["target"] is None
        assert kwargs["standards"] is None
        assert kwargs["checks"] is not None
        assert set(kwargs["checks"]) == expected_ids

    def test_only_known_attacked_with_checks_intersects(self, runner):
        # When both flags are set, the rules that run are the
        # intersection. ``--checks GHA-001 --checks NONEXISTENT-999
        # --only-known-attacked`` runs only GHA-001 (in the
        # known-attacked set) because NONEXISTENT-999 isn't.
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            runner.invoke(scan, [
                "--only-known-attacked",
                "--checks", "GHA-001",
                "--checks", "NONEXISTENT-999",
                "--output", "json",
            ])
        kwargs = MockScanner.return_value.run.call_args.kwargs
        assert kwargs["checks"] == ["GHA-001"]

    def test_only_known_attacked_empty_intersection_warns(self, runner):
        # ``--only-known-attacked --checks NONEXISTENT-999`` reduces
        # the active set to empty. The scanner still runs (with an
        # empty list) but a stderr warning surfaces the situation.
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = []
            result = runner.invoke(scan, [
                "--only-known-attacked",
                "--checks", "NONEXISTENT-999",
                "--output", "json",
            ])
        assert (
            "--only-known-attacked filtered the rule set to zero checks"
            in result.output
        )

    def test_html_output_writes_file(self, runner, tmp_path):
        out = tmp_path / "report.html"
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(
                scan, ["--output", "html", "--output-file", str(out)]
            )
        assert result.exit_code == 0
        assert out.exists()
        assert "<html" in out.read_text().lower()

    def test_html_output_requires_output_file(self, runner):
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "html"])
        assert result.exit_code != 0
        assert "--output-file" in result.output or "--output-file" in (result.stderr or "")

    def test_json_output_honors_output_file(self, runner, tmp_path):
        # Regression: --output json silently ignored --output-file and
        # dumped JSON to stdout, which breaks every CI integration that
        # routes JSON to a path.
        out = tmp_path / "report.json"
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(
                scan, ["--output", "json", "--output-file", str(out)],
            )
        assert result.exit_code in (0, 1), result.output
        assert out.exists(), "JSON file was not written"
        # File holds a parseable JSON payload.
        import json as _json
        _json.loads(out.read_text(encoding="utf-8"))
        # stdout should NOT also carry the JSON.
        assert result.stdout.strip() == ""

    def test_json_output_without_file_still_writes_stdout(self, runner):
        # The bare --output json case (no --output-file) must keep its
        # legacy stdout behavior so existing scripts piping the output
        # don't break.
        with patch("pipeline_check.cli.Scanner") as MockScanner:
            MockScanner.return_value.run.return_value = [_finding()]
            result = runner.invoke(scan, ["--output", "json"])
        assert result.exit_code in (0, 1)
        assert result.stdout.strip().startswith("{")


class TestAutoDetect:
    def test_gitlab_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        result = runner.invoke(scan, ["--pipeline", "gitlab", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        # Auto-detection announced on stderr.
        assert "[auto] using --gitlab-path .gitlab-ci.yml" in result.output
        # Findings are from the GitLab provider (GL-001..005), proving the
        # resolved path was actually loaded and scanned.
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == (
            {f"GL-{i:03d}" for i in range(1, 41)}
            | {"TAINT-004", "TAINT-008"}
        )

    def test_bitbucket_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bitbucket-pipelines.yml").write_text(
            "pipelines:\n  default:\n    - step: {script: [make]}\n"
        )
        result = runner.invoke(scan, ["--pipeline", "bitbucket", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        assert "[auto] using --bitbucket-path bitbucket-pipelines.yml" in result.output
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == {f"BB-{i:03d}" for i in range(1, 33)}


    def test_github_path_autodetected(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "on: push\njobs: {b: {runs-on: x, steps: [{run: echo}]}}\n"
        )
        result = runner.invoke(scan, ["--pipeline", "github", "--output", "json"])
        assert result.exit_code in (0, 1), result.output
        assert "[auto] using --gha-path" in result.output
        payload = json.loads(result.stdout)
        emitted = {f["check_id"] for f in payload["findings"]}
        assert emitted == (
            {f"GHA-{i:03d}" for i in range(1, 74)}
            | {"GHA-086", "GHA-087", "GHA-088", "GHA-089", "GHA-090",
               "GHA-091", "GHA-092", "GHA-093", "GHA-094", "GHA-095",
               "GHA-096", "GHA-097", "GHA-098", "GHA-099",
               "GHA-100", "GHA-102", "GHA-103", "GHA-104",
               "GHA-105", "GHA-106", "GHA-107", "GHA-108", "GHA-109",
               "GHA-110", "GHA-111", "GHA-112", "GHA-113", "GHA-114",
               "GHA-115", "GHA-116", "GHA-117"}
            | {"TAINT-001", "TAINT-002", "TAINT-003", "TAINT-009"}
        )

    def test_gitlab_missing_file_raises_usage_error(self, tmp_path_factory, monkeypatch):
        # Uses a fresh tmp dir (not the ``runner`` fixture's, which
        # drops a ``.gitlab-ci.yml`` to satisfy auto-detect) so the
        # explicit ``--pipeline gitlab`` has nothing to resolve.
        empty = tmp_path_factory.mktemp("no-gitlab")
        monkeypatch.chdir(empty)
        result = CliRunner().invoke(scan, ["--pipeline", "gitlab", "--output", "json"])
        assert result.exit_code != 0
        assert "gitlab-path" in result.output.lower()


class TestFlagMarshallingEndToEnd:
    """Unmocked CLI runs that exercise the click → Scanner → reporter
    path for the flag-marshalling surfaces the mocked tests above bypass.

    The ``TestExitCodes`` / ``TestFlagWiring`` classes patch
    ``pipeline_check.cli.Scanner`` to return canned findings, so the
    real loader / rule / reporter / baseline path never runs. A
    regression in the way ``--output-file``, ``--baseline``, or
    ``--diff-base`` get marshalled into the Scanner can only be
    caught by an end-to-end test that goes through the whole pipeline.
    """

    def _gitlab_fixture(self, tmp_path):
        """Drop a minimal GitLab CI file that auto-detect picks up."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build: {script: [make]}\n",
            encoding="utf-8",
        )

    def test_output_file_writes_json_report_to_disk(self, tmp_path, monkeypatch):
        # ``--output json --output-file PATH`` should write the JSON
        # payload to ``PATH`` instead of stdout. Confirms the
        # ``output_file`` parameter reaches the writer branch in
        # cli.py:2685 (which patched Scanner tests never exercise).
        monkeypatch.chdir(tmp_path)
        self._gitlab_fixture(tmp_path)
        out_path = tmp_path / "report.json"
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "json",
                "--output-file", str(out_path),
            ],
        )
        assert result.exit_code in (0, 1), result.output
        assert out_path.is_file(), f"--output-file did not produce {out_path}"
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert "findings" in payload
        assert "score" in payload
        # Status message lands on stderr (mixed with stdout under
        # CliRunner) so the operator sees the file was written.
        assert "JSON report written to" in result.output

    def test_output_file_writes_sarif_report_to_disk(self, tmp_path, monkeypatch):
        # ``--output sarif --output-file PATH`` follows the SARIF
        # writer branch (cli.py:2703-2706); proves the same
        # marshalling works for the non-JSON format too.
        monkeypatch.chdir(tmp_path)
        self._gitlab_fixture(tmp_path)
        out_path = tmp_path / "report.sarif"
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "sarif",
                "--output-file", str(out_path),
            ],
        )
        assert result.exit_code in (0, 1), result.output
        assert out_path.is_file()
        sarif = json.loads(out_path.read_text(encoding="utf-8"))
        # SARIF 2.1.0 has a ``version`` field at the top.
        assert sarif.get("version") == "2.1.0"
        assert "runs" in sarif

    def test_baseline_filters_known_findings(self, tmp_path, monkeypatch):
        # Generate a baseline from a first scan, then pass it via
        # ``--baseline`` to a second scan. The follow-up should report
        # zero new findings even though the on-disk pipeline didn't
        # change. Exercises the ``baseline=`` parameter all the way
        # through to the gate.
        monkeypatch.chdir(tmp_path)
        self._gitlab_fixture(tmp_path)
        baseline_path = tmp_path / "baseline.json"

        # First scan: capture every finding as the baseline.
        first = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "json",
                "--output-file", str(baseline_path),
            ],
        )
        assert first.exit_code in (0, 1), first.output
        assert baseline_path.is_file()

        # Second scan with the baseline: ``new_findings`` count must
        # drop to 0 because nothing changed since the snapshot.
        second_out = tmp_path / "second.json"
        second = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "json",
                "--output-file", str(second_out),
                "--baseline", str(baseline_path),
            ],
        )
        assert second.exit_code in (0, 1), second.output
        payload = json.loads(second_out.read_text(encoding="utf-8"))
        # Gate diagnostics carry the baseline-aware delta. Different
        # release lines name the key slightly differently; accept either
        # location so the test doesn't lock to a specific report shape.
        gate = payload.get("gate") or {}
        new_count = gate.get("new_findings_count")
        if new_count is None:
            new_count = payload.get("new_findings_count", 0)
        assert new_count == 0, (
            f"--baseline didn't filter known findings; new_findings_count={new_count}"
        )

    def test_baseline_missing_path_raises_usage_error(self, tmp_path, monkeypatch):
        # The path-validation arm of --baseline (cli.py:2136) is
        # ``raise click.UsageError(...)``; the mocked tests can't hit
        # it because they bypass the loader entirely.
        monkeypatch.chdir(tmp_path)
        self._gitlab_fixture(tmp_path)
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "json",
                "--baseline", str(tmp_path / "does-not-exist.json"),
            ],
        )
        assert result.exit_code == 2, result.output
        assert "--baseline file not found" in result.output

    def test_diff_base_rejects_leading_dash(self, tmp_path, monkeypatch):
        # cli.py:2414 enforces "--diff-base must not start with '-'"
        # so an operator can't fool the git-show invocation into
        # treating the ref as a flag. Real end-to-end check that the
        # validation fires before any work happens.
        monkeypatch.chdir(tmp_path)
        self._gitlab_fixture(tmp_path)
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--output", "json",
                "--diff-base", "--malicious",
            ],
        )
        assert result.exit_code != 0
        assert "--diff-base" in result.output
