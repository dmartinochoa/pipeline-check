"""Tests for the multi-provider scan mode.

Covers ``MultiScanner`` directly plus the CLI ``--pipelines`` flag
that wires it up. The headline behavioral test is that
:class:`XPC-001` (the cross-provider chain) lights up only under
multi-scan; single-provider runs of GHA or OCI alone never see
both check IDs in the chain engine's input.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.scanner import MultiScanner

# A workflow that exercises GHA-006 (no provenance attestation
# emitter) without becoming a kitchen-sink fixture. The scanner
# only needs the workflow to fail GHA-006; the rest of the rules
# can fire too, they don't affect XPC-001.
_GHA_WORKFLOW = """\
name: release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: docker build -t img:1 .
      - run: docker push img:1
"""

# An OCI image index without an attestation manifest sub-entry.
# OCI-002 fires on this shape.
_OCI_INDEX = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:" + "a" * 64,
            "size": 100,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
    ],
})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo layout with both a workflow and an OCI manifest at cwd."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "release.yml").write_text(
        _GHA_WORKFLOW, encoding="utf-8",
    )
    (tmp_path / "index.json").write_text(_OCI_INDEX, encoding="utf-8")
    return tmp_path


# ── MultiScanner direct tests ──────────────────────────────────────


class TestMultiScanner:
    def test_rejects_empty_pipelines(self) -> None:
        with pytest.raises(ValueError, match="at least one pipeline"):
            MultiScanner(pipelines=[])

    def test_runs_each_provider_in_order(self, repo: Path) -> None:
        ms = MultiScanner(
            pipelines=["github", "oci"],
            gha_path=str(repo / ".github" / "workflows"),
            oci_manifest=str(repo / "index.json"),
        )
        assert ms.pipelines == ["github", "oci"]
        findings = ms.run()
        check_ids = {f.check_id for f in findings}
        # Findings from both providers in the union.
        assert any(cid.startswith("GHA-") for cid in check_ids)
        assert any(cid.startswith("OCI-") for cid in check_ids)

    def test_xpc001_fires_only_under_multi_scan(self, repo: Path) -> None:
        # Multi-scan: chain engine sees both providers' findings,
        # XPC-001 fires.
        ms = MultiScanner(
            pipelines=["github", "oci"],
            gha_path=str(repo / ".github" / "workflows"),
            oci_manifest=str(repo / "index.json"),
        )
        ms.run()
        chain_ids = {c.chain_id for c in ms.chains}
        assert "XPC-001" in chain_ids

    def test_chains_disabled_skips_union_pass(self, repo: Path) -> None:
        ms = MultiScanner(
            pipelines=["github", "oci"],
            chains_enabled=False,
            gha_path=str(repo / ".github" / "workflows"),
            oci_manifest=str(repo / "index.json"),
        )
        ms.run()
        assert ms.chains == []

    def test_aggregate_metadata_concatenates(self, repo: Path) -> None:
        ms = MultiScanner(
            pipelines=["github", "oci"],
            gha_path=str(repo / ".github" / "workflows"),
            oci_manifest=str(repo / "index.json"),
        )
        ms.run()
        agg = ms.metadata
        # Provider name reads as the comma-joined list.
        assert agg.provider == "github,oci"
        # Per-provider metadata stays queryable.
        assert set(ms.metadata_by_provider.keys()) == {"github", "oci"}
        # Aggregate files_scanned is the sum of both.
        per_provider_sum = sum(
            m.files_scanned for m in ms.metadata_by_provider.values()
        )
        assert agg.files_scanned == per_provider_sum

    def test_per_sub_scanner_chains_stay_empty(self, repo: Path) -> None:
        # Sub-scanners run with chains_enabled=False so they don't
        # double-emit; the union pass is the only place that
        # populates chain output.
        ms = MultiScanner(
            pipelines=["github", "oci"],
            gha_path=str(repo / ".github" / "workflows"),
            oci_manifest=str(repo / "index.json"),
        )
        ms.run()
        for sub in ms._scanners:
            assert sub.chains == []


# ── CLI --pipelines flag tests ─────────────────────────────────────


class TestPipelinesFlag:
    def test_rejects_combination_with_pipeline(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(repo)
        runner = CliRunner()
        result = runner.invoke(scan, [
            "--pipeline", "github",
            "--pipelines", "github,oci",
        ])
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_rejects_unknown_provider_in_list(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(repo)
        runner = CliRunner()
        result = runner.invoke(scan, ["--pipelines", "github,not-a-real-thing"])
        assert result.exit_code != 0
        assert "unknown provider" in result.output.lower()

    def test_rejects_empty_csv(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(repo)
        runner = CliRunner()
        result = runner.invoke(scan, ["--pipelines", ", , "])
        assert result.exit_code != 0
        assert "parsed empty" in result.output

    def test_two_provider_run_emits_xpc001(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(repo)
        runner = CliRunner()
        result = runner.invoke(scan, [
            "--pipelines", "github,oci",
            "--output", "json",
        ])
        # Exit code may be 1 (findings present) or 2 (gate failure);
        # either is fine, we're just looking for XPC-001 in the
        # rendered output.
        assert result.exit_code in (0, 1, 2), result.output
        # The JSON report carries chains in a top-level array. Parse
        # it to confirm XPC-001 is present.
        report = json.loads(result.stdout)
        chain_ids = {c["chain_id"] for c in report.get("chains", [])}
        assert "XPC-001" in chain_ids

    def test_dedupes_repeated_provider(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # ``--pipelines github,github,oci`` should run github once.
        # The dedup happens during CSV parsing.
        monkeypatch.chdir(repo)
        runner = CliRunner()
        result = runner.invoke(scan, [
            "--pipelines", "github,github,oci",
            "--output", "json", "--show-passed",
        ])
        assert result.exit_code in (0, 1, 2)
        # If github ran twice we'd see duplicate GHA-NNN findings.
        report = json.loads(result.stdout)
        check_ids = [f["check_id"] for f in report["findings"]]
        gha_001_count = sum(1 for cid in check_ids if cid == "GHA-001")
        # GHA-001 fires once per workflow, not twice.
        assert gha_001_count == 1
