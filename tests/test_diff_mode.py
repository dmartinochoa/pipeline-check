"""Tests for --diff-base (scanner.py scoping + diff.py git wrapper)."""
from __future__ import annotations

from unittest.mock import patch

from pipeline_check.core import diff as diff_mod
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.scanner import _filter_context_by_diff


def test_filter_context_drops_unchanged_workflows(tmp_path):
    changed = tmp_path / "changed.yml"
    unchanged = tmp_path / "unchanged.yml"
    for p in (changed, unchanged):
        p.write_text("on: push\njobs: {}\n")

    ctx = GitHubContext(
        workflows=[
            Workflow(path=str(changed), data={"on": "push"}),
            Workflow(path=str(unchanged), data={"on": "push"}),
        ]
    )

    with patch.object(diff_mod, "changed_files", return_value={str(changed)}):
        _filter_context_by_diff(ctx, base_ref="origin/main", provider="github")

    assert [w.path for w in ctx.workflows] == [str(changed)]


def test_filter_context_no_op_when_git_unavailable(tmp_path):
    ctx = GitHubContext(workflows=[Workflow(path="a.yml", data={})])
    with patch.object(diff_mod, "changed_files", return_value=None):
        _filter_context_by_diff(ctx, base_ref="origin/main", provider="github")
    # Unchanged — over-scanning beats under-scanning in CI.
    assert len(ctx.workflows) == 1


def test_changed_files_returns_none_when_git_missing(tmp_path, monkeypatch):
    """If `git` isn't on PATH the helper returns None without raising."""
    def _boom(*a, **kw):
        raise FileNotFoundError
    monkeypatch.setattr(diff_mod.subprocess, "run", _boom)
    assert diff_mod.changed_files("origin/main", cwd=tmp_path) is None


def test_filter_paths_intersects_with_allowed():
    paths = ["a/b.yml", "a/c.yml"]
    assert diff_mod.filter_paths(paths, {"a/b.yml"}) == ["a/b.yml"]
    # None means "no filter"
    assert diff_mod.filter_paths(paths, None) == paths
