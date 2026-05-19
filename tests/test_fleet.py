"""Tests for the org-wide fleet runner."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import fleet_cmd
from pipeline_check.core import fleet as fleet_mod
from pipeline_check.core.fleet import (
    FleetDigest,
    FleetSnapshot,
    RepoCoordinate,
    load_repo_list,
    render_markdown,
    run_fleet,
)

# ── Repo-list parser ──────────────────────────────────────────────


class TestLoadRepoList:
    def test_flat_list(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text(
            "- dmartinochoa/pipeline-check\n"
            "- greylag-ci/pipeline-check-vscode\n",
            encoding="utf-8",
        )
        repos = load_repo_list(p)
        assert [r.coord for r in repos] == [
            "dmartinochoa/pipeline-check",
            "greylag-ci/pipeline-check-vscode",
        ]
        assert repos[0].clone_url == (
            "https://github.com/dmartinochoa/pipeline-check.git"
        )
        assert (repos[0].owner, repos[0].repo) == (
            "dmartinochoa", "pipeline-check",
        )

    def test_mapping_with_repos_key(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text(
            textwrap.dedent(
                """\
                repos:
                  - dmartinochoa/pipeline-check
                """
            ),
            encoding="utf-8",
        )
        repos = load_repo_list(p)
        assert len(repos) == 1
        assert repos[0].coord == "dmartinochoa/pipeline-check"

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("", encoding="utf-8")
        assert load_repo_list(p) == []

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            load_repo_list(tmp_path / "nope.yml")

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("[unclosed", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML parse error"):
            load_repo_list(p)

    def test_non_list_top_level_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("foo: bar\n", encoding="utf-8")
        with pytest.raises(ValueError, match="top-level must be a list"):
            load_repo_list(p)

    def test_non_string_entry_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- 42\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must be a string"):
            load_repo_list(p)

    def test_malformed_coordinate_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- not-a-coordinate\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not the 'owner/repo' shape"):
            load_repo_list(p)

    def test_gitlab_style_subgroup_rejected(self, tmp_path: Path) -> None:
        # ``group/subgroup/project`` has two slashes — phase 1
        # rejects so the user gets an explicit error rather than a
        # silently-misparsed clone URL.
        p = tmp_path / "repos.yml"
        p.write_text("- group/sub/project\n", encoding="utf-8")
        with pytest.raises(ValueError, match="GitLab"):
            load_repo_list(p)


# ── render_markdown ───────────────────────────────────────────────


class TestRenderMarkdown:
    def test_empty_digest(self) -> None:
        out = render_markdown(FleetDigest())
        assert "Scanned **0**" in out
        assert "Per-repo posture" in out

    def test_ranks_by_score_ascending(self) -> None:
        digest = FleetDigest(snapshots=[
            FleetSnapshot(
                coord="o/a", grade="A", score=95,
                failed_by_severity={
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0,
                },
                total_failed=1,
            ),
            FleetSnapshot(
                coord="o/b", grade="D", score=40,
                failed_by_severity={
                    "CRITICAL": 3, "HIGH": 5, "MEDIUM": 0, "LOW": 0,
                },
                total_failed=8,
            ),
        ])
        out = render_markdown(digest)
        # b (worst) appears before a in the per-repo table.
        b_pos = out.find("| o/b ")
        a_pos = out.find("| o/a ")
        assert 0 < b_pos < a_pos

    def test_warnings_rendered(self) -> None:
        digest = FleetDigest(
            snapshots=[],
            warnings=["o/r: git clone exit 128: not found"],
        )
        out = render_markdown(digest)
        assert "Warnings" in out
        assert "not found" in out

    def test_errored_snapshot_status_truncated(self) -> None:
        long = "x" * 200
        digest = FleetDigest(snapshots=[
            FleetSnapshot(
                coord="o/r", grade="?", score=0,
                failed_by_severity={s: 0 for s in (
                    "CRITICAL", "HIGH", "MEDIUM", "LOW",
                )},
                total_failed=0,
                error=long,
            ),
        ])
        out = render_markdown(digest)
        # Status cell caps the error at 60 chars so the table stays readable.
        assert "x" * 60 in out
        assert "x" * 200 not in out


# ── run_fleet (orchestrator with monkeypatched clone + scan) ─────


def _fake_findings_doc(score: int = 90, high: int = 0) -> dict:
    findings = [
        {"check_id": f"HIGH-{i:03d}", "severity": "HIGH", "passed": False}
        for i in range(high)
    ]
    return {
        "schema_version": 1,
        "tool_version": "test",
        "score": {
            "grade": "A" if score >= 90 else "B",
            "score": score,
            "summary": {
                "CRITICAL": {"failed": 0, "passed": 0},
                "HIGH":     {"failed": high, "passed": 0},
                "MEDIUM":   {"failed": 0, "passed": 0},
                "LOW":      {"failed": 0, "passed": 0},
            },
        },
        "findings": findings,
    }


class TestRunFleet:
    def test_happy_path_two_repos(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Stub clone + scan: clone is a no-op (tmpdir already exists);
        # scan writes a synthetic findings.json so the orchestrator
        # can walk the rest of the pipeline.
        def fake_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            dest.mkdir(parents=True, exist_ok=True)
            return ""

        def fake_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
        ):
            score = 95 if coord.repo == "alpha" else 60
            high = 0 if coord.repo == "alpha" else 7
            findings_path.write_text(
                json.dumps(_fake_findings_doc(score=score, high=high)),
                encoding="utf-8",
            )
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", fake_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", fake_scan)

        out_dir = tmp_path / "fleet-out"
        repos = [
            RepoCoordinate(
                coord="acme/alpha",
                clone_url="https://github.com/acme/alpha.git",
                owner="acme", repo="alpha",
            ),
            RepoCoordinate(
                coord="acme/beta",
                clone_url="https://github.com/acme/beta.git",
                owner="acme", repo="beta",
            ),
        ]
        digest = run_fleet(repos, out_dir)
        assert len(digest.snapshots) == 2
        assert all(s.ok for s in digest.snapshots)
        assert digest.warnings == []
        # Per-repo findings.json files landed.
        assert (out_dir / "acme/alpha/findings.json").exists()
        assert (out_dir / "acme/beta/findings.json").exists()
        # Top-level digest written.
        assert (out_dir / "fleet.json").exists()
        assert (out_dir / "fleet.md").exists()
        # JSON digest carries both snapshots.
        fleet_json = json.loads(
            (out_dir / "fleet.json").read_text(encoding="utf-8"),
        )
        assert {s["coord"] for s in fleet_json["snapshots"]} == {
            "acme/alpha", "acme/beta",
        }

    def test_clone_failure_surfaces_as_warning(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        def fake_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            return "git clone exit 128: Repository not found"

        # Scan should never be reached for the failing clone — if it
        # is, the orchestrator broke the early-return contract.
        def fake_scan(*a, **kw):  # type: ignore[no-untyped-def]
            raise AssertionError("scan should not run after clone failure")

        monkeypatch.setattr(fleet_mod, "_clone_repo", fake_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", fake_scan)

        repos = [RepoCoordinate(
            coord="acme/missing",
            clone_url="https://github.com/acme/missing.git",
            owner="acme", repo="missing",
        )]
        digest = run_fleet(repos, tmp_path / "fleet-out")
        assert len(digest.snapshots) == 1
        assert not digest.snapshots[0].ok
        assert "Repository not found" in digest.snapshots[0].error
        assert len(digest.warnings) == 1

    def test_scan_failure_surfaces_as_warning(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        def fake_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            dest.mkdir(parents=True, exist_ok=True)
            return ""

        def fake_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
        ):
            return "pipeline_check produced no findings.json: exit code 2"

        monkeypatch.setattr(fleet_mod, "_clone_repo", fake_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", fake_scan)

        repos = [RepoCoordinate(
            coord="acme/broken",
            clone_url="https://github.com/acme/broken.git",
            owner="acme", repo="broken",
        )]
        digest = run_fleet(repos, tmp_path / "fleet-out")
        assert len(digest.snapshots) == 1
        snap = digest.snapshots[0]
        assert not snap.ok
        assert "exit code 2" in snap.error

    def test_corrupt_findings_file_yields_error_snapshot(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Clone succeeds, scan reports success, but findings.json is
        # not valid JSON — the snapshot stays in the digest with an
        # explicit error rather than crashing the run.
        def fake_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            dest.mkdir(parents=True, exist_ok=True)
            return ""

        def fake_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
        ):
            findings_path.write_text("{not json", encoding="utf-8")
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", fake_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", fake_scan)

        repos = [RepoCoordinate(
            coord="acme/corrupt",
            clone_url="https://github.com/acme/corrupt.git",
            owner="acme", repo="corrupt",
        )]
        digest = run_fleet(repos, tmp_path / "fleet-out")
        assert not digest.snapshots[0].ok
        assert "parse error" in digest.snapshots[0].error.lower()


# ── CLI integration ──────────────────────────────────────────────


class TestFleetCli:
    def test_fleet_cli_runs_end_to_end(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        def fake_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            dest.mkdir(parents=True, exist_ok=True)
            return ""

        def fake_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
        ):
            findings_path.write_text(
                json.dumps(_fake_findings_doc(score=88, high=1)),
                encoding="utf-8",
            )
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", fake_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", fake_scan)

        repos_yml = tmp_path / "repos.yml"
        repos_yml.write_text("- acme/alpha\n", encoding="utf-8")
        out_dir = tmp_path / "fleet-out"

        result = CliRunner().invoke(
            fleet_cmd,
            ["--repos", str(repos_yml), "--output-dir", str(out_dir)],
        )
        assert result.exit_code == 0, result.output
        assert "1 OK" in result.output
        assert (out_dir / "fleet.json").exists()
        assert (out_dir / "acme/alpha/findings.json").exists()

    def test_fleet_cli_errors_on_missing_repos_file(
        self, tmp_path: Path,
    ) -> None:
        result = CliRunner().invoke(
            fleet_cmd,
            ["--repos", str(tmp_path / "nope.yml")],
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_fleet_cli_errors_on_empty_repo_list(
        self, tmp_path: Path,
    ) -> None:
        repos_yml = tmp_path / "repos.yml"
        repos_yml.write_text("[]\n", encoding="utf-8")
        result = CliRunner().invoke(
            fleet_cmd, ["--repos", str(repos_yml)],
        )
        assert result.exit_code != 0
        assert "no repo coordinates" in result.output
