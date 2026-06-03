"""Tests for the ``fix-pr`` subcommand and its git / host plumbing."""
from __future__ import annotations

import subprocess

import pytest
from click.testing import CliRunner

from pipeline_check.cli import fix_pr_cmd
from pipeline_check.core import fix_pr

# ── pure helpers ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url,expected",
    [
        ("git@github.com:o/r.git", fix_pr.GITHUB),
        ("https://github.com/o/r.git", fix_pr.GITHUB),
        ("https://github.example.com/o/r", fix_pr.GITHUB),
        ("git@gitlab.com:o/r.git", fix_pr.GITLAB),
        ("https://gitlab.example.com/g/p.git", fix_pr.GITLAB),
        ("git@bitbucket.org:o/r.git", fix_pr.BITBUCKET),
        ("https://example.com/o/r.git", fix_pr.UNKNOWN),
        (None, fix_pr.UNKNOWN),
    ],
)
def test_detect_platform(url, expected):
    assert fix_pr.detect_platform(url) == expected


def test_default_title_singular_plural():
    assert "1 rule)" in fix_pr.default_title(["GHA-004"])
    assert "2 rules)" in fix_pr.default_title(["GHA-004", "GHA-001"])


def test_build_body_lists_checks_and_files():
    body = fix_pr.build_body(["GHA-004", "GHA-001"], 3, "safe")
    assert "3 files" in body
    assert "**safe**" in body
    assert "`GHA-004`" in body
    assert "`GHA-001`" in body


def test_gitlab_push_options():
    opts = fix_pr.gitlab_push_options("main", "my title")
    assert "merge_request.create" in opts
    assert "merge_request.target=main" in opts
    assert "merge_request.title=my title" in opts
    assert "merge_request.remove_source_branch" in opts


def test_dash_prefix_rejected():
    with pytest.raises(ValueError):
        fix_pr.branch_exists("--upload-pack=evil")
    with pytest.raises(ValueError):
        fix_pr.gitlab_push_options("--evil", "t")


# ── git-backed fixtures ─────────────────────────────────────────────────────


def _git(args, cwd):
    subprocess.run(
        ["git", *args], cwd=str(cwd), check=True,
        capture_output=True, text=True,
    )


def _git_out(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def _init_repo(tmp_path):
    """Init a git repo with a fixable GHA workflow, committed clean."""
    _git(["init"], tmp_path)
    _git(["config", "user.email", "test@example.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    _git(["config", "commit.gpgsign", "false"], tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    # No top-level permissions: triggers GHA-004 (a safe fixer).
    (wf / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu\n"
        "    steps:\n      - run: echo\n"
    )
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "initial"], tmp_path)
    return tmp_path


def _has_branch(name, cwd):
    return fix_pr.branch_exists(name, str(cwd))


# ── unique branch naming ────────────────────────────────────────────────────


def test_unique_branch_name_suffixes_on_collision(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert fix_pr.unique_branch_name("pipeline-check/autofix") == (
        "pipeline-check/autofix"
    )
    _git(["branch", "pipeline-check/autofix"], tmp_path)
    assert fix_pr.unique_branch_name("pipeline-check/autofix") == (
        "pipeline-check/autofix-2"
    )


# ── end-to-end command flows ────────────────────────────────────────────────


def test_fix_pr_no_push_commits_to_branch(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    base = _git_out(["rev-parse", "--abbrev-ref", "HEAD"], tmp_path)

    result = CliRunner().invoke(fix_pr_cmd, ["--no-push"])
    assert result.exit_code == 0, result.output

    # The autofix branch exists and carries the fix.
    assert _has_branch("pipeline-check/autofix", tmp_path)
    assert "permissions:" in (
        tmp_path / ".github" / "workflows" / "ci.yml"
    ).read_text()
    # HEAD is the new branch with the autofix commit.
    head = _git_out(["rev-parse", "--abbrev-ref", "HEAD"], tmp_path)
    assert head == "pipeline-check/autofix"
    msg = _git_out(["log", "-1", "--pretty=%s"], tmp_path)
    assert "apply pipeline-check autofixes" in msg
    assert base != head


def test_fix_pr_dry_run_touches_nothing(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    before = (tmp_path / ".github" / "workflows" / "ci.yml").read_text()

    result = CliRunner().invoke(fix_pr_cmd, ["--dry-run"])
    assert result.exit_code == 0, result.output
    assert "dry run" in result.output
    # No branch, file unchanged, still on the base branch.
    assert not _has_branch("pipeline-check/autofix", tmp_path)
    assert (
        tmp_path / ".github" / "workflows" / "ci.yml"
    ).read_text() == before


def test_fix_pr_refuses_dirty_tree(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scratch.txt").write_text("uncommitted")

    result = CliRunner().invoke(fix_pr_cmd, ["--no-push"])
    assert result.exit_code != 0
    assert "uncommitted changes" in result.output
    assert not _has_branch("pipeline-check/autofix", tmp_path)


def test_fix_pr_allow_dirty_only_stages_autofix(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scratch.txt").write_text("uncommitted")

    result = CliRunner().invoke(fix_pr_cmd, ["--no-push", "--allow-dirty"])
    assert result.exit_code == 0, result.output
    # The scratch file is NOT in the commit (only the workflow is).
    committed = _git_out(
        ["show", "--name-only", "--pretty=", "HEAD"], tmp_path,
    )
    assert "scratch.txt" not in committed
    assert "ci.yml" in committed


def test_fix_pr_nothing_to_scan(tmp_path, monkeypatch):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@e.com"], tmp_path)
    _git(["config", "user.name", "T"], tmp_path)
    (tmp_path / "README.md").write_text("hi")
    _git(["add", "-A"], tmp_path)
    _git(["config", "commit.gpgsign", "false"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(fix_pr_cmd, ["--no-push"])
    assert result.exit_code == 0, result.output
    assert "nothing to do" in result.output
    assert not _has_branch("pipeline-check/autofix", tmp_path)


def test_fix_pr_outside_git_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fix_pr_cmd, ["--no-push"])
    assert result.exit_code != 0
    assert "git repository" in result.output


def test_fix_pr_github_flow_calls_gh(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    calls = {}
    monkeypatch.setattr(
        fix_pr, "remote_url", lambda *a, **k: "git@github.com:o/r.git",
    )
    monkeypatch.setattr(fix_pr, "push", lambda *a, **k: calls.setdefault("push", (a, k)))
    monkeypatch.setattr(fix_pr, "gh_available", lambda *a, **k: True)

    def fake_pr(base, head, title, body, cwd="."):
        calls["pr"] = (base, head, title)
        return "https://github.com/o/r/pull/7"

    monkeypatch.setattr(fix_pr, "gh_create_pr", fake_pr)

    result = CliRunner().invoke(fix_pr_cmd, [])
    assert result.exit_code == 0, result.output
    assert "opened https://github.com/o/r/pull/7" in result.output
    assert "push" in calls
    assert calls["pr"][1] == "pipeline-check/autofix"


def test_fix_pr_gitlab_flow_uses_push_options(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    captured = {}
    monkeypatch.setattr(
        fix_pr, "remote_url", lambda *a, **k: "git@gitlab.com:g/p.git",
    )

    def fake_push(remote, branch, cwd=".", *, push_options=()):
        captured["options"] = push_options

    monkeypatch.setattr(fix_pr, "push", fake_push)

    result = CliRunner().invoke(fix_pr_cmd, [])
    assert result.exit_code == 0, result.output
    assert any(
        o.startswith("merge_request.create") for o in captured["options"]
    )
    assert any(
        o.startswith("merge_request.target=") for o in captured["options"]
    )
