"""Tests for the org-wide fleet runner."""
from __future__ import annotations

import json
import textwrap
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pipeline_check.cli import fleet_cmd
from pipeline_check.core import fleet as fleet_mod
from pipeline_check.core.fleet import (
    FleetDigest,
    FleetSnapshot,
    RepoCoordinate,
    _parse_coord_string,
    _resolve_coord,
    apply_filters,
    default_worker_count,
    enumerate_org_repos,
    load_repo_list,
    render_markdown,
    run_fleet,
)

# ── Shared helpers ───────────────────────────────────────────────


def _fake_findings_doc(score: int = 90, high: int = 0) -> dict[str, Any]:
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


def _noop_clone(  # type: ignore[no-untyped-def]
    coord, dest, *, timeout_sec,
):
    dest.mkdir(parents=True, exist_ok=True)
    return ""


def _make_scan(  # type: ignore[no-untyped-def]
    score: int = 90, high: int = 0,
):
    """Return a fake ``_scan_repo`` that writes a synthetic findings doc."""
    def _scan(  # type: ignore[no-untyped-def]
        coord, src, findings_path, stderr_path, *, timeout_sec,
        extra_flags=None,
    ):
        findings_path.write_text(
            json.dumps(_fake_findings_doc(score=score, high=high)),
            encoding="utf-8",
        )
        return ""
    return _scan


def _make_capturing_scan(  # type: ignore[no-untyped-def]
    captured: list[list[str] | None], score: int = 90,
):
    """Fake ``_scan_repo`` that records *extra_flags* into *captured*.

    Thread-safe: appends are guarded by a lock so the list is safe
    to read back after joining all workers.
    """
    lock = threading.Lock()

    def _scan(  # type: ignore[no-untyped-def]
        coord, src, findings_path, stderr_path, *, timeout_sec,
        extra_flags=None,
    ):
        with lock:
            captured.append(extra_flags)
        findings_path.write_text(
            json.dumps(_fake_findings_doc(score=score)),
            encoding="utf-8",
        )
        return ""
    return _scan


def _make_coord(name: str) -> RepoCoordinate:
    owner, repo = name.split("/", 1)
    return RepoCoordinate(
        coord=name,
        clone_url=f"https://github.com/{name}.git",
        owner=owner,
        repo=repo,
    )


# ── Coordinate parsing ───────────────────────────────────────────


class TestParseCoordString:
    def test_bare_coord_defaults_github(self) -> None:
        assert _parse_coord_string("owner/repo") == ("github", "owner/repo")

    def test_github_prefix(self) -> None:
        assert _parse_coord_string("github:o/r") == ("github", "o/r")

    def test_gitlab_prefix(self) -> None:
        assert _parse_coord_string("gitlab:g/s/p") == ("gitlab", "g/s/p")

    def test_bitbucket_prefix(self) -> None:
        assert _parse_coord_string("bitbucket:ws/slug") == (
            "bitbucket", "ws/slug",
        )

    def test_unknown_alpha_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown platform"):
            _parse_coord_string("foobar:owner/repo")

    def test_non_alpha_prefix_passes_through(self) -> None:
        platform, coord = _parse_coord_string("123:owner/repo")
        assert platform == "github"
        assert coord == "123:owner/repo"


class TestResolveCoord:
    def test_github_valid(self) -> None:
        owner, repo, url = _resolve_coord("github", "acme/tool")
        assert owner == "acme"
        assert repo == "tool"
        assert url == "https://github.com/acme/tool.git"

    def test_gitlab_subgroup(self) -> None:
        owner, repo, url = _resolve_coord("gitlab", "group/sub/proj")
        assert owner == "group/sub"
        assert repo == "proj"
        assert url == "https://gitlab.com/group/sub/proj.git"

    def test_bitbucket_valid(self) -> None:
        owner, repo, url = _resolve_coord("bitbucket", "ws/slug")
        assert owner == "ws"
        assert repo == "slug"
        assert url == "https://bitbucket.org/ws/slug.git"

    def test_github_multi_slash_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a valid github"):
            _resolve_coord("github", "a/b/c")

    def test_unknown_platform_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unknown platform"):
            _resolve_coord("nope", "owner/repo")


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
        with pytest.raises(ValueError, match="not a valid github"):
            load_repo_list(p)

    def test_bare_multi_slash_rejected_as_github(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- group/sub/project\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not a valid github"):
            load_repo_list(p)

    def test_gitlab_prefixed_string(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- gitlab:group/sub/project\n", encoding="utf-8")
        repos = load_repo_list(p)
        assert len(repos) == 1
        r = repos[0]
        assert r.platform == "gitlab"
        assert r.owner == "group/sub"
        assert r.repo == "project"
        assert r.clone_url == "https://gitlab.com/group/sub/project.git"

    def test_bitbucket_prefixed_string(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- bitbucket:workspace/slug\n", encoding="utf-8")
        repos = load_repo_list(p)
        assert len(repos) == 1
        r = repos[0]
        assert r.platform == "bitbucket"
        assert r.owner == "workspace"
        assert r.repo == "slug"
        assert r.clone_url == "https://bitbucket.org/workspace/slug.git"

    def test_mapping_entry_with_platform(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text(
            textwrap.dedent("""\
                - coord: mygroup/sub/project
                  platform: gitlab
            """),
            encoding="utf-8",
        )
        repos = load_repo_list(p)
        assert len(repos) == 1
        assert repos[0].platform == "gitlab"
        assert repos[0].owner == "mygroup/sub"
        assert repos[0].repo == "project"

    def test_bare_string_remains_github(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- acme/tool\n", encoding="utf-8")
        repos = load_repo_list(p)
        assert repos[0].platform == "github"
        assert repos[0].clone_url == "https://github.com/acme/tool.git"

    def test_unknown_platform_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text("- foobar:owner/repo\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unknown platform"):
            load_repo_list(p)

    def test_mixed_platforms_in_list(self, tmp_path: Path) -> None:
        p = tmp_path / "repos.yml"
        p.write_text(
            "- acme/gh-repo\n"
            "- gitlab:org/sub/proj\n"
            "- bitbucket:ws/bb-repo\n",
            encoding="utf-8",
        )
        repos = load_repo_list(p)
        assert len(repos) == 3
        assert repos[0].platform == "github"
        assert repos[1].platform == "gitlab"
        assert repos[2].platform == "bitbucket"


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
        assert "x" * 60 in out
        assert "x" * 200 not in out


# ── run_fleet (orchestrator with monkeypatched clone + scan) ─────


class TestRunFleet:
    def test_happy_path_two_repos(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def per_repo_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
            extra_flags=None,
        ):
            score = 95 if coord.repo == "alpha" else 60
            high = 0 if coord.repo == "alpha" else 7
            findings_path.write_text(
                json.dumps(_fake_findings_doc(score=score, high=high)),
                encoding="utf-8",
            )
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", per_repo_scan)

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
        assert (out_dir / "github/acme/alpha/findings.json").exists()
        assert (out_dir / "github/acme/beta/findings.json").exists()
        assert (out_dir / "fleet.json").exists()
        assert (out_dir / "fleet.md").exists()
        fleet_json = json.loads(
            (out_dir / "fleet.json").read_text(encoding="utf-8"),
        )
        assert {s["coord"] for s in fleet_json["snapshots"]} == {
            "acme/alpha", "acme/beta",
        }

    def test_clone_failure_surfaces_as_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def failing_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            return "git clone exit 128: Repository not found"

        def unreachable_scan(*a: object, **kw: object) -> str:
            raise AssertionError("scan should not run after clone failure")

        monkeypatch.setattr(fleet_mod, "_clone_repo", failing_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", unreachable_scan)

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
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def failing_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
            extra_flags=None,
        ):
            return "pipeline_check produced no findings.json: exit code 2"

        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", failing_scan)

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
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def corrupt_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
            extra_flags=None,
        ):
            findings_path.write_text("{not json", encoding="utf-8")
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", corrupt_scan)

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
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", _make_scan(88, 1))

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
        assert (out_dir / "github/acme/alpha/findings.json").exists()

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

    def test_fleet_cli_with_jobs_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", _make_scan(88, 1))

        repos_yml = tmp_path / "repos.yml"
        repos_yml.write_text("- acme/alpha\n", encoding="utf-8")
        out_dir = tmp_path / "fleet-out"

        result = CliRunner().invoke(
            fleet_cmd,
            [
                "--repos", str(repos_yml),
                "--output-dir", str(out_dir),
                "--jobs", "2",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "1 OK" in result.output

    def test_fleet_cli_with_scan_flags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured_flags: list[list[str] | None] = []
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(
            fleet_mod, "_scan_repo",
            _make_capturing_scan(captured_flags, score=95),
        )

        repos_yml = tmp_path / "repos.yml"
        repos_yml.write_text("- acme/alpha\n", encoding="utf-8")
        out_dir = tmp_path / "fleet-out"

        result = CliRunner().invoke(
            fleet_cmd,
            [
                "--repos", str(repos_yml),
                "--output-dir", str(out_dir),
                "--jobs", "0",
                "--scan-flags", "--standard owasp_cicd_top_10 --resolve-remote",
            ],
        )
        assert result.exit_code == 0, result.output
        assert len(captured_flags) == 1
        assert captured_flags[0] == [
            "--standard", "owasp_cicd_top_10", "--resolve-remote",
        ]


# ── Parallel execution ──────────────────────────────────────────


class TestParallelExecution:
    def test_parallel_two_repos(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def per_repo_scan(  # type: ignore[no-untyped-def]
            coord, src, findings_path, stderr_path, *, timeout_sec,
            extra_flags=None,
        ):
            score = 95 if coord.repo == "alpha" else 60
            high = 0 if coord.repo == "alpha" else 7
            findings_path.write_text(
                json.dumps(_fake_findings_doc(score=score, high=high)),
                encoding="utf-8",
            )
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", per_repo_scan)

        repos = [_make_coord("acme/alpha"), _make_coord("acme/beta")]
        out_dir = tmp_path / "fleet-out"
        digest = run_fleet(repos, out_dir, jobs=2)

        assert len(digest.snapshots) == 2
        assert all(s.ok for s in digest.snapshots)
        assert digest.warnings == []
        assert (out_dir / "github/acme/alpha/findings.json").exists()
        assert (out_dir / "github/acme/beta/findings.json").exists()
        assert (out_dir / "fleet.json").exists()

    def test_parallel_preserves_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", _make_scan(80))

        names = [f"org/repo-{i}" for i in range(5)]
        repos = [_make_coord(n) for n in names]
        out_dir = tmp_path / "fleet-out"
        digest = run_fleet(repos, out_dir, jobs=3)

        assert [s.coord for s in digest.snapshots] == names

    def test_sequential_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", _make_scan(90))

        repos = [_make_coord("acme/alpha")]
        out_dir = tmp_path / "fleet-out"
        digest = run_fleet(repos, out_dir, jobs=0)

        assert len(digest.snapshots) == 1
        assert digest.snapshots[0].ok

    def test_parallel_clone_failure_isolated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def selective_clone(coord, dest, *, timeout_sec):  # type: ignore[no-untyped-def]
            if coord.repo == "broken":
                return "git clone exit 128: Repository not found"
            dest.mkdir(parents=True, exist_ok=True)
            return ""

        monkeypatch.setattr(fleet_mod, "_clone_repo", selective_clone)
        monkeypatch.setattr(fleet_mod, "_scan_repo", _make_scan(90))

        repos = [
            _make_coord("acme/good1"),
            _make_coord("acme/broken"),
            _make_coord("acme/good2"),
        ]
        out_dir = tmp_path / "fleet-out"
        digest = run_fleet(repos, out_dir, jobs=2)

        assert len(digest.snapshots) == 3
        ok_snaps = [s for s in digest.snapshots if s.ok]
        err_snaps = [s for s in digest.snapshots if not s.ok]
        assert len(ok_snaps) == 2
        assert len(err_snaps) == 1
        assert err_snaps[0].coord == "acme/broken"
        assert len(digest.warnings) == 1


# ── Flag forwarding ─────────────────────────────────────────────


class TestFlagForwarding:
    def test_scan_flags_forwarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: list[list[str] | None] = []
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(
            fleet_mod, "_scan_repo", _make_capturing_scan(captured),
        )

        flags = ["--standard", "owasp_cicd_top_10", "--resolve-remote"]
        run_fleet(
            [_make_coord("acme/alpha")], tmp_path / "out",
            jobs=0, scan_flags=flags,
        )

        assert len(captured) == 1
        assert captured[0] == flags

    def test_scan_flags_none_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: list[list[str] | None] = []
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(
            fleet_mod, "_scan_repo", _make_capturing_scan(captured),
        )

        run_fleet([_make_coord("acme/alpha")], tmp_path / "out", jobs=0)

        assert len(captured) == 1
        assert captured[0] is None

    def test_scan_flags_forwarded_parallel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: list[list[str] | None] = []
        monkeypatch.setattr(fleet_mod, "_clone_repo", _noop_clone)
        monkeypatch.setattr(
            fleet_mod, "_scan_repo", _make_capturing_scan(captured),
        )

        flags = ["--resolve-remote"]
        run_fleet(
            [_make_coord("acme/alpha"), _make_coord("acme/beta")],
            tmp_path / "out", jobs=2, scan_flags=flags,
        )

        assert len(captured) == 2
        assert all(f == flags for f in captured)


# ── default_worker_count ────────────────────────────────────────


class TestDefaultWorkerCount:
    def test_single_repo(self) -> None:
        assert default_worker_count(1) == 1

    def test_capped_at_max(self) -> None:
        with patch("pipeline_check.core.fleet.os.cpu_count", return_value=16):
            assert default_worker_count(100) == 8

    def test_capped_at_repo_count(self) -> None:
        with patch("pipeline_check.core.fleet.os.cpu_count", return_value=8):
            assert default_worker_count(3) == 3

    def test_capped_at_cpu_count(self) -> None:
        with patch("pipeline_check.core.fleet.os.cpu_count", return_value=2):
            assert default_worker_count(10) == 2

    def test_none_cpu_count(self) -> None:
        with patch("pipeline_check.core.fleet.os.cpu_count", return_value=None):
            assert default_worker_count(10) == 4


# ── Org enumeration and filtering ───────────────────────────────


class TestApplyFilters:
    def test_include_filter(self) -> None:
        coords = [
            _make_coord("org/pipeline-check"),
            _make_coord("org/pipeline-deploy"),
            _make_coord("org/docs"),
        ]
        result = apply_filters(coords, include=["pipeline-*"])
        assert [c.repo for c in result] == [
            "pipeline-check", "pipeline-deploy",
        ]

    def test_exclude_filter(self) -> None:
        coords = [
            _make_coord("org/public"),
            _make_coord("org/internal"),
            _make_coord("org/internal-tools"),
        ]
        result = apply_filters(coords, exclude=["internal*"])
        assert [c.repo for c in result] == ["public"]

    def test_include_and_exclude(self) -> None:
        coords = [
            _make_coord("org/api"),
            _make_coord("org/api-internal"),
            _make_coord("org/web"),
        ]
        result = apply_filters(
            coords, include=["api*"], exclude=["*-internal"],
        )
        assert [c.repo for c in result] == ["api"]

    def test_no_filters_passes_all(self) -> None:
        coords = [_make_coord("org/a"), _make_coord("org/b")]
        assert apply_filters(coords) == coords


_FAKE_GITHUB_REPOS: list[dict[str, object]] = [
    {
        "full_name": "acme/alpha",
        "clone_url": "https://github.com/acme/alpha.git",
        "archived": False,
    },
    {
        "full_name": "acme/beta",
        "clone_url": "https://github.com/acme/beta.git",
        "archived": False,
    },
    {
        "full_name": "acme/archived",
        "clone_url": "https://github.com/acme/archived.git",
        "archived": True,
    },
]


def _fake_github_fetch(
    self: object, path: str,
) -> list[dict[str, object]]:
    if "page=1" in path:
        return _FAKE_GITHUB_REPOS
    return []


class TestEnumerateOrgRepos:
    def test_github_enumerate(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from pipeline_check.core.checks.scm.base import HttpSCMFetcher

        monkeypatch.setattr(HttpSCMFetcher, "fetch", _fake_github_fetch)
        coords = enumerate_org_repos("acme", "github")
        assert len(coords) == 2
        assert {c.coord for c in coords} == {"acme/alpha", "acme/beta"}
        assert all(c.platform == "github" for c in coords)

    def test_github_archived_repos_skipped(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from pipeline_check.core.checks.scm.base import HttpSCMFetcher

        monkeypatch.setattr(HttpSCMFetcher, "fetch", _fake_github_fetch)
        coords = enumerate_org_repos("acme", "github")
        names = {c.repo for c in coords}
        assert "archived" not in names

    def test_github_pagination(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        page1 = [
            {"full_name": f"org/repo-{i}", "archived": False}
            for i in range(100)
        ]
        page2 = [
            {"full_name": f"org/repo-{100 + i}", "archived": False}
            for i in range(20)
        ]

        def fake_fetch(self: object, path: str) -> list[dict[str, object]]:
            if "page=1" in path:
                return page1
            if "page=2" in path:
                return page2
            return []

        from pipeline_check.core.checks.scm.base import HttpSCMFetcher

        monkeypatch.setattr(HttpSCMFetcher, "fetch", fake_fetch)
        coords = enumerate_org_repos("org", "github")
        assert len(coords) == 120

    def test_include_filter_applied(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from pipeline_check.core.checks.scm.base import HttpSCMFetcher

        monkeypatch.setattr(HttpSCMFetcher, "fetch", _fake_github_fetch)
        coords = enumerate_org_repos("acme", "github")
        filtered = apply_filters(coords, include=["alpha"])
        assert len(filtered) == 1
        assert filtered[0].repo == "alpha"

    def test_exclude_filter_applied(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from pipeline_check.core.checks.scm.base import HttpSCMFetcher

        monkeypatch.setattr(HttpSCMFetcher, "fetch", _fake_github_fetch)
        coords = enumerate_org_repos("acme", "github")
        filtered = apply_filters(coords, exclude=["beta"])
        assert len(filtered) == 1
        assert filtered[0].repo == "alpha"

    def test_gitlab_enumerate(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_projects = [
            {
                "path_with_namespace": "mygroup/sub/project",
                "http_url_to_repo": "https://gitlab.com/mygroup/sub/project.git",
                "archived": False,
            },
        ]

        def fake_fetch(
            self: object, path: str,
        ) -> list[dict[str, object]] | None:
            if "page=1" in path:
                return fake_projects
            return []

        from pipeline_check.core.checks.scm._platforms import (
            HttpGitLabSCMFetcher,
        )

        monkeypatch.setattr(HttpGitLabSCMFetcher, "fetch", fake_fetch)
        coords = enumerate_org_repos("mygroup", "gitlab")
        assert len(coords) == 1
        assert coords[0].platform == "gitlab"
        assert coords[0].owner == "mygroup/sub"
        assert coords[0].repo == "project"

    def test_bitbucket_enumerate(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_page: dict[str, object] = {
            "values": [
                {
                    "full_name": "ws/repo-a",
                    "links": {
                        "clone": [
                            {"name": "https", "href": "https://bitbucket.org/ws/repo-a.git"},
                        ],
                    },
                },
            ],
            "next": None,
        }

        def fake_fetch(
            self: object, path: str,
        ) -> dict[str, object]:
            return fake_page

        from pipeline_check.core.checks.scm._platforms import (
            HttpBitbucketSCMFetcher,
        )

        monkeypatch.setattr(HttpBitbucketSCMFetcher, "fetch", fake_fetch)
        coords = enumerate_org_repos("ws", "bitbucket")
        assert len(coords) == 1
        assert coords[0].platform == "bitbucket"
        assert coords[0].owner == "ws"
        assert coords[0].repo == "repo-a"

    def test_bitbucket_pagination(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        page1: dict[str, object] = {
            "values": [
                {"full_name": "ws/repo-1"},
            ],
            "next": "https://api.bitbucket.org/2.0/repositories/ws?pagelen=100&page=2",
        }
        page2: dict[str, object] = {
            "values": [
                {"full_name": "ws/repo-2"},
            ],
        }

        def fake_fetch(
            self: object, path: str,
        ) -> dict[str, object]:
            if "page=2" in path:
                return page2
            return page1

        from pipeline_check.core.checks.scm._platforms import (
            HttpBitbucketSCMFetcher,
        )

        monkeypatch.setattr(HttpBitbucketSCMFetcher, "fetch", fake_fetch)
        coords = enumerate_org_repos("ws", "bitbucket")
        assert len(coords) == 2
        assert {c.repo for c in coords} == {"repo-1", "repo-2"}


class TestFleetCliFromOrg:
    def test_repos_and_from_org_exclusive(self, tmp_path: Path) -> None:
        repos_yml = tmp_path / "repos.yml"
        repos_yml.write_text("- acme/alpha\n", encoding="utf-8")
        result = CliRunner().invoke(
            fleet_cmd,
            [
                "--repos", str(repos_yml),
                "--from-org", "acme",
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_neither_repos_nor_from_org(self) -> None:
        result = CliRunner().invoke(fleet_cmd, ["--output-dir", "x"])
        assert result.exit_code != 0
        assert "Provide either" in result.output
