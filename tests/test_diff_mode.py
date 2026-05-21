"""Tests for --diff-base (scanner.py scoping + diff.py git wrapper)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

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


# ──────────────────────────────────────────────────────────────────────
# Argument-injection (CWE-88) defense
#
# ``base_ref`` and ``ref`` / ``path`` flow into git as positional
# arguments composed via f-string. If the caller's value starts with
# ``-`` git parses it as an option, e.g. ``git diff --output=PATH``
# writes the diff to a chosen file. The helper layer must reject
# leading-dash inputs uniformly so a misuse from any surface (CLI,
# library import, config-file driven) is blocked.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("ref", [
    "--output=/tmp/pwned",
    "--exec=evilcmd",
    "--upload-pack=/bin/sh",
    "-anything",
])
def test_changed_files_rejects_dash_prefixed_ref(ref, tmp_path):
    """A ``--diff-base`` whose value starts with ``-`` would be parsed
    by git as a flag rather than a positional rev. Reject loudly."""
    with pytest.raises(ValueError, match="cannot start with '-'"):
        diff_mod.changed_files(ref, cwd=tmp_path)


@pytest.mark.parametrize("ref,path", [
    ("--output=/tmp/x", "file.json"),
    ("origin/main", "--exec=evilcmd"),
    ("-foo", "bar"),
])
def test_git_show_rejects_dash_prefixed_inputs(ref, path, tmp_path):
    """Same shape as ``changed_files`` but for the ``git show REF:PATH``
    composition. Both halves of the colon-split must be guarded."""
    with pytest.raises(ValueError, match="cannot start with '-'"):
        diff_mod.git_show(ref, path, cwd=tmp_path)


def test_changed_files_uses_end_of_options(monkeypatch, tmp_path):
    """``--end-of-options`` precedes the user-controlled ref so even an
    internal regression that forgot the leading-dash check can't
    smuggle a flag past git's positional-arg cutoff."""
    captured: list[list[str]] = []

    def _capture(cmd, **_kw):
        captured.append(list(cmd))

        class _R:
            returncode = 1  # short-circuit; we only care about argv shape
            stdout = ""
            stderr = ""
        return _R()

    monkeypatch.setattr(diff_mod.subprocess, "run", _capture)
    diff_mod.changed_files("origin/main", cwd=tmp_path)
    assert captured, "expected subprocess.run to be invoked"
    argv = captured[0]
    assert "--end-of-options" in argv
    # The separator must come *before* the ref token so the cutoff is
    # in effect when git parses the rev.
    assert argv.index("--end-of-options") < argv.index("origin/main...HEAD")
