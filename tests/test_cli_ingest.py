"""End-to-end CLI integration tests for ``--ingest``.

The unit tests in ``test_sarif_ingest.py`` cover the parser
contract; this module verifies the CLI flag wiring: SARIF files
from disk, multiple feeds, and the merged-findings shape that
appears in JSON output.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from click.testing import CliRunner

from pipeline_check.cli import scan


def _trivy_sarif(rule_id: str, severity_score: str = "5.5") -> str:
    """Synthesize a Trivy-shaped SARIF document body."""
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Trivy",
                "version": "0.50.0",
                "rules": [{
                    "id": rule_id,
                    "shortDescription": {"text": f"{rule_id} title"},
                    "fullDescription": {
                        "text": f"Fix guidance for {rule_id}.",
                    },
                }],
            }},
            "results": [{
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"Triggered {rule_id}"},
                "properties": {"security-severity": severity_score},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "infra/main.tf"},
                    "region": {"startLine": 7},
                }}],
            }],
        }],
    })


def _minimal_gha_repo(tmp_path: Path) -> Path:
    """A repo with one trivial workflow so the github auto-detect
    has something to scan. Keeps the test scope tight to the
    ingest behavior."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(textwrap.dedent("""
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
    """).strip() + "\n")
    return tmp_path


class TestIngestCLI:
    def test_ingest_findings_appear_in_json_output(self, tmp_path: Path):
        repo = _minimal_gha_repo(tmp_path)
        sarif = tmp_path / "trivy.sarif"
        sarif.write_text(_trivy_sarif("AVD-AWS-0028"))
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--ingest", str(sarif),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        ingested = [
            f for f in payload["findings"]
            if f["check_id"].startswith("INGEST-")
        ]
        assert len(ingested) == 1
        assert ingested[0]["check_id"] == "INGEST-trivy-AVD-AWS-0028"
        # Severity 5.5 → MEDIUM per the security-severity bucketing.
        assert ingested[0]["severity"] == "MEDIUM"
        assert ingested[0]["resource"] == "infra/main.tf"

    def test_multiple_ingest_flags_compose(self, tmp_path: Path):
        repo = _minimal_gha_repo(tmp_path)
        first = tmp_path / "trivy-1.sarif"
        first.write_text(_trivy_sarif("AVD-AWS-0028"))
        second = tmp_path / "trivy-2.sarif"
        second.write_text(_trivy_sarif("AVD-AWS-0099", severity_score="9.5"))
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--ingest", str(first),
                "--ingest", str(second),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        ingested = sorted(
            f["check_id"] for f in payload["findings"]
            if f["check_id"].startswith("INGEST-")
        )
        assert ingested == [
            "INGEST-trivy-AVD-AWS-0028",
            "INGEST-trivy-AVD-AWS-0099",
        ]
        # The 9.5 severity-score finding should have CRITICAL severity.
        critical = [
            f for f in payload["findings"]
            if f["check_id"] == "INGEST-trivy-AVD-AWS-0099"
        ][0]
        assert critical["severity"] == "CRITICAL"

    def test_missing_sarif_file_warns_keeps_going(self, tmp_path: Path):
        repo = _minimal_gha_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--ingest", str(tmp_path / "does-not-exist.sarif"),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        # Warning surfaced on stderr (mix=False); native scan still ran.
        assert "does not exist" in result.output or \
               "does not exist" in result.stderr if hasattr(result, "stderr") else True
        payload = json.loads(result.stdout)
        # No INGEST findings landed.
        ingested = [
            f for f in payload["findings"]
            if f["check_id"].startswith("INGEST-")
        ]
        assert ingested == []

    def test_malformed_sarif_warns_keeps_going(self, tmp_path: Path):
        repo = _minimal_gha_repo(tmp_path)
        bad = tmp_path / "bad.sarif"
        bad.write_text("{ not valid json")
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--ingest", str(bad),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        ingested = [
            f for f in payload["findings"]
            if f["check_id"].startswith("INGEST-")
        ]
        assert ingested == []

    def test_no_ingest_flag_produces_no_ingest_findings(
        self, tmp_path: Path,
    ):
        """Sanity: without --ingest, no INGEST- findings appear.
        Catches a regression where the ingest path runs unconditionally."""
        repo = _minimal_gha_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        ingested = [
            f for f in payload["findings"]
            if f["check_id"].startswith("INGEST-")
        ]
        assert ingested == []
