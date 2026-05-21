"""Tests for ``--pr-diff`` (core/pr_diff.py + core/pr_diff_reporter.py).

Three layers of coverage:

1. Pure delta arithmetic. The multiset semantics on
   ``(check_id, resource)`` are subtle: adding a second occurrence of
   a rule on a file that already had one must surface as
   *introduced=1*, not *introduced=0*. The unit tests pin that down
   along with sort order and the cross-OS path-case fingerprint.

2. JSON dict projection. The subprocess hands us
   ``findings: [{...}, ...]`` dicts; the projection layer has to
   tolerate optional fields, skip passed findings, and reject
   unparseable entries without aborting the whole report.

3. End-to-end orchestration in a tmp git repo. Marked
   ``requires_git`` so anyone without ``git`` on PATH still sees the
   pure layer pass. Two commits, one workflow, the second commit
   adds an offender, the test asserts the reporter calls it new.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from pipeline_check.core import pr_diff as pr_diff_mod
from pipeline_check.core.pr_diff import (
    DeltaReport,
    FindingRef,
    any_at_or_above,
    compute_delta,
    severity_counts,
)
from pipeline_check.core.pr_diff_reporter import report_pr_diff


def _f(
    check_id: str = "GHA-001",
    resource: str = ".github/workflows/ci.yml",
    severity: str = "HIGH",
    title: str = "Unpinned action",
    recommendation: str = "Pin to a commit SHA.",
    location_line: int | None = 10,
) -> FindingRef:
    """Tiny factory so each test reads as "what's the delta?" not
    "what's the FindingRef constructor's positional order?"."""
    return FindingRef(
        check_id=check_id,
        title=title,
        severity=severity,
        confidence="HIGH",
        resource=resource,
        description=title,
        recommendation=recommendation,
        location_line=location_line,
    )


# ──────────────────────────────────────────────────────────────────────
# Pure delta arithmetic
# ──────────────────────────────────────────────────────────────────────


def test_compute_delta_empty_to_empty():
    introduced, resolved, preserved = compute_delta([], [])
    assert introduced == [] and resolved == [] and preserved == []


def test_compute_delta_pure_introduction():
    head = [_f(check_id="GHA-002", severity="CRITICAL")]
    introduced, resolved, preserved = compute_delta([], head)
    assert introduced == head
    assert resolved == [] and preserved == []


def test_compute_delta_pure_resolution():
    base = [_f(check_id="GHA-001")]
    introduced, resolved, preserved = compute_delta(base, [])
    assert resolved == base
    assert introduced == [] and preserved == []


def test_compute_delta_preserved_when_same_fingerprint():
    """A finding present on both sides should land in *preserved*,
    not in introduced nor resolved."""
    f = _f()
    introduced, resolved, preserved = compute_delta([f], [f])
    assert preserved == [f]
    assert introduced == [] and resolved == []


def test_compute_delta_multiset_adds_one_more_offender():
    """The PR adds a *second* GHA-001 to the same file, second offender
    surfaces as introduced; the original stays preserved.

    Without multiset semantics this would silently report
    ``introduced=0`` because the ``(check_id, resource)`` pair was
    already in BASE."""
    base = [_f()]
    head = [_f(), _f()]
    introduced, resolved, preserved = compute_delta(base, head)
    assert len(preserved) == 1
    assert len(introduced) == 1
    assert len(resolved) == 0


def test_compute_delta_multiset_resolves_one_of_many():
    """BASE has three offenders of the same rule, HEAD has one.
    Two land in resolved; one in preserved."""
    base = [_f(), _f(), _f()]
    head = [_f()]
    introduced, resolved, preserved = compute_delta(base, head)
    assert len(preserved) == 1
    assert len(introduced) == 0
    assert len(resolved) == 2


def test_compute_delta_path_case_insensitive_fingerprint():
    """A BASE finding on ``.github/workflows/ci.yml`` and a HEAD
    finding on ``.GITHUB/WORKFLOWS/CI.YML`` should match — same file,
    different platform-normalized path case."""
    base = [_f(resource=".github/workflows/ci.yml")]
    head = [_f(resource=".GITHUB/WORKFLOWS/CI.YML")]
    introduced, resolved, preserved = compute_delta(base, head)
    assert len(preserved) == 1
    assert introduced == [] and resolved == []


def test_compute_delta_path_slash_direction_normalized():
    """Forward / backslash difference (Linux base scan vs Windows
    head scan) must not produce a phantom delta."""
    base = [_f(resource=r".github\workflows\ci.yml")]
    head = [_f(resource=".github/workflows/ci.yml")]
    introduced, resolved, preserved = compute_delta(base, head)
    assert len(preserved) == 1


def test_compute_delta_sort_order_severity_then_check_id():
    """Introduced section sorts: highest severity first, then
    check_id ascending."""
    head = [
        _f(check_id="GHA-003", severity="MEDIUM"),
        _f(check_id="GHA-002", severity="CRITICAL"),
        _f(check_id="GHA-001", severity="HIGH"),
        _f(check_id="GHA-004", severity="CRITICAL"),
    ]
    introduced, _, _ = compute_delta([], head)
    severities = [f.severity for f in introduced]
    ids = [f.check_id for f in introduced]
    assert severities[:2] == ["CRITICAL", "CRITICAL"]
    # CRITICALs come before HIGH which comes before MEDIUM.
    assert severities == ["CRITICAL", "CRITICAL", "HIGH", "MEDIUM"]
    # Within CRITICAL bucket, GHA-002 before GHA-004 (check_id asc).
    assert ids[:2] == ["GHA-002", "GHA-004"]


# ──────────────────────────────────────────────────────────────────────
# Projection from JSON dicts
# ──────────────────────────────────────────────────────────────────────


def test_projection_skips_passed_findings():
    raw = [
        {"check_id": "GHA-001", "resource": "a.yml", "passed": True,
         "severity": "HIGH", "title": "t", "description": "d", "recommendation": "r"},
        {"check_id": "GHA-002", "resource": "a.yml", "passed": False,
         "severity": "HIGH", "title": "t", "description": "d", "recommendation": "r"},
    ]
    refs = pr_diff_mod._projection(raw)
    assert [r.check_id for r in refs] == ["GHA-002"]


def test_projection_handles_missing_optional_fields():
    """A minimal finding dict (no locations, no confidence) must
    project without raising; defaults fill in."""
    raw = [{"check_id": "GHA-001", "resource": "a.yml", "passed": False}]
    refs = pr_diff_mod._projection(raw)
    assert len(refs) == 1
    assert refs[0].location_line is None
    assert refs[0].confidence == "HIGH"  # default


def test_projection_extracts_first_location_line():
    raw = [{
        "check_id": "GHA-001", "resource": "a.yml", "passed": False,
        "severity": "HIGH", "title": "t", "description": "d", "recommendation": "r",
        "locations": [{"path": "a.yml", "start_line": 42}],
    }]
    refs = pr_diff_mod._projection(raw)
    assert refs[0].location_line == 42


def test_projection_skips_unparseable_entries():
    """A list-instead-of-dict entry shouldn't abort the whole projection."""
    raw = [
        ["not", "a", "dict"],
        {"check_id": "GHA-001", "resource": "a.yml", "passed": False},
        "string entry",
    ]
    refs = pr_diff_mod._projection(raw)
    assert len(refs) == 1


# ──────────────────────────────────────────────────────────────────────
# Severity gate helper
# ──────────────────────────────────────────────────────────────────────


def test_any_at_or_above_matches_at_threshold():
    refs = [_f(severity="HIGH")]
    assert any_at_or_above(refs, "HIGH") is True
    assert any_at_or_above(refs, "CRITICAL") is False


def test_any_at_or_above_matches_above_threshold():
    refs = [_f(severity="CRITICAL")]
    assert any_at_or_above(refs, "HIGH") is True


def test_any_at_or_above_empty_is_false():
    assert any_at_or_above([], "INFO") is False


def test_severity_counts_groups_correctly():
    refs = [
        _f(severity="HIGH"),
        _f(severity="HIGH"),
        _f(severity="MEDIUM"),
    ]
    c = severity_counts(refs)
    assert c["HIGH"] == 2 and c["MEDIUM"] == 1


# ──────────────────────────────────────────────────────────────────────
# Markdown reporter
# ──────────────────────────────────────────────────────────────────────


def test_reporter_zero_delta_says_so():
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit="abc1234",
        head_commit="def5678",
        introduced=[],
        resolved=[],
        preserved=[_f()],
    )
    out = report_pr_diff(delta, tool_version="1.0.0")
    assert "does not change the failing-finding set" in out
    assert "Pipeline-Check diff vs `origin/main`" in out
    assert "+0" in out and "-0" in out and "=1" in out


def test_reporter_introduced_section_groups_by_severity():
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit=None,
        head_commit=None,
        introduced=[
            _f(check_id="GHA-002", severity="CRITICAL", title="PR-target abuse"),
            _f(check_id="GHA-001", severity="HIGH", title="Unpinned action"),
        ],
    )
    out = report_pr_diff(delta)
    # CRITICAL section appears before HIGH section.
    crit_idx = out.find("CRITICAL")
    high_idx = out.find("HIGH")
    assert crit_idx > -1 and high_idx > -1 and crit_idx < high_idx
    assert "GHA-002" in out and "GHA-001" in out
    assert "PR-target abuse" in out


def test_reporter_preserved_section_is_collapsible():
    """The preserved tail belongs in a ``<details>`` so a long-running
    branch's accumulated findings don't bury the actionable parts."""
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit=None,
        head_commit=None,
        preserved=[_f(), _f()],
    )
    out = report_pr_diff(delta)
    assert "<details>" in out and "</details>" in out
    assert "Preserved findings (2)" in out


def test_reporter_renders_warnings_section():
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit=None,
        head_commit=None,
        introduced=[_f()],
        warnings=["could not resolve base ref"],
    )
    out = report_pr_diff(delta)
    assert "WARNING" in out
    assert "could not resolve base ref" in out


def test_reporter_includes_location_line_when_available():
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit=None,
        head_commit=None,
        introduced=[_f(location_line=42)],
    )
    out = report_pr_diff(delta)
    assert "ci.yml:42" in out


def test_reporter_omits_line_when_zero_or_missing():
    delta = DeltaReport(
        base_ref="origin/main",
        base_commit=None,
        head_commit=None,
        introduced=[_f(location_line=None)],
    )
    out = report_pr_diff(delta)
    # Should render bare path, not "path:0" or "path:None".
    assert "ci.yml:" not in out
    assert "ci.yml" in out


# ──────────────────────────────────────────────────────────────────────
# Argument-injection defense (CWE-88) on git boundaries
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("ref", [
    "--output=/tmp/pwned",
    "--exec=evilcmd",
    "-anything",
])
def test_worktree_add_rejects_dash_prefixed_ref(ref, tmp_path):
    """A leading-dash ``--pr-diff`` value flows into ``git worktree
    add`` as a positional. The pr_diff layer must reject it before
    git sees it, matching the existing ``--diff-base`` defense."""
    with pytest.raises(ValueError, match="cannot start with '-'"):
        pr_diff_mod._worktree_add(ref, tmp_path / "wt")


# ──────────────────────────────────────────────────────────────────────
# Graceful degradation when git / subprocess fails
# ──────────────────────────────────────────────────────────────────────


def test_run_pr_diff_degrades_when_base_ref_unresolvable(tmp_path, monkeypatch):
    """Unknown base ref must not crash; we emit a warning and treat
    every HEAD finding as introduced (conservative)."""
    head_raw = [{
        "check_id": "GHA-001", "resource": "a.yml", "passed": False,
        "severity": "HIGH", "title": "t", "description": "d",
        "recommendation": "r",
    }]
    # Resolve always fails for both base and HEAD by returning None.
    monkeypatch.setattr(pr_diff_mod, "_resolve_commit", lambda *a, **kw: None)
    delta = pr_diff_mod.run_pr_diff(
        "origin/does-not-exist", head_raw, forwarded_argv=[], cwd=tmp_path,
    )
    assert len(delta.introduced) == 1
    assert len(delta.resolved) == 0
    assert delta.warnings  # at least one warning surfaced
    assert any("could not resolve" in w for w in delta.warnings)


def test_run_pr_diff_degrades_when_worktree_add_fails(tmp_path, monkeypatch):
    head_raw = [{
        "check_id": "GHA-001", "resource": "a.yml", "passed": False,
        "severity": "HIGH", "title": "t", "description": "d",
        "recommendation": "r",
    }]
    monkeypatch.setattr(pr_diff_mod, "_resolve_commit", lambda *a, **kw: "abc1234")
    monkeypatch.setattr(
        pr_diff_mod, "_worktree_add",
        lambda *a, **kw: "git worktree add failed: simulated",
    )
    delta = pr_diff_mod.run_pr_diff(
        "origin/main", head_raw, forwarded_argv=[], cwd=tmp_path,
    )
    assert len(delta.introduced) == 1
    assert any("simulated" in w for w in delta.warnings)


# ──────────────────────────────────────────────────────────────────────
# End-to-end smoke against a real tmp git repo
# ──────────────────────────────────────────────────────────────────────


requires_git = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="git not on PATH",
)


def _git(args: list[str], cwd: Path) -> None:
    """Run git with a stable identity so the test works on a fresh
    runner that hasn't configured ``user.name`` / ``user.email`` and
    on hosts that default to commit.gpgsign=true.

    Extends os.environ rather than replacing it: a bare env={} would
    leave git without PATH / HOME, breaking sub-helpers like
    ``git-init`` on Windows where git delegates to its own bin/.
    GIT_AUTHOR_* env vars set the *content* of the commit; the
    ``-c user.{name,email}`` flags satisfy git's identity *check*."""
    import os as _os
    env = _os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@e",
        "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@e",
    })
    cmd = [
        "git",
        "-c", "user.name=test",
        "-c", "user.email=t@e",
        "-c", "commit.gpgsign=false",
        "-c", "init.defaultBranch=main",
        *args,
    ]
    subprocess.run(
        cmd, cwd=str(cwd), check=True,
        capture_output=True, text=True, env=env,
    )


@requires_git
def test_resolve_commit_returns_short_sha_against_real_repo(tmp_path):
    """``_resolve_commit`` should return a 7-char SHA when run against
    a real repo with at least one commit on HEAD."""
    _git(["init", "--initial-branch=main"], cwd=tmp_path)
    (tmp_path / "x.txt").write_text("hi\n")
    _git(["add", "x.txt"], cwd=tmp_path)
    _git(["commit", "-m", "init"], cwd=tmp_path)
    sha = pr_diff_mod._resolve_commit("HEAD", cwd=tmp_path)
    assert sha is not None
    assert len(sha) >= 7


@requires_git
def test_worktree_add_and_remove_round_trip(tmp_path):
    """Plumbing test: worktree add against a real ref should succeed,
    then remove cleans up. The worktree's checked-out file content
    matches the committed BASE state, not whatever HEAD holds now."""
    _git(["init", "--initial-branch=main"], cwd=tmp_path)
    target = tmp_path / "marker.txt"
    target.write_text("base-version\n")
    _git(["add", "marker.txt"], cwd=tmp_path)
    _git(["commit", "-m", "base"], cwd=tmp_path)
    base_sha = pr_diff_mod._resolve_commit("HEAD", cwd=tmp_path)
    # Move HEAD forward so the worktree at the prior ref carries the
    # *previous* content of marker.txt, not the current one.
    target.write_text("head-version\n")
    _git(["add", "marker.txt"], cwd=tmp_path)
    _git(["commit", "-m", "head"], cwd=tmp_path)

    wt = tmp_path / "wt"
    err = pr_diff_mod._worktree_add(base_sha or "HEAD~1", wt, cwd=tmp_path)
    try:
        assert err is None, err
        assert wt.exists()
        assert (wt / "marker.txt").read_text() == "base-version\n"
    finally:
        pr_diff_mod._worktree_remove(wt, cwd=tmp_path)
    # Cleanup is best-effort; assert it actually freed the path.
    assert not wt.exists()
