"""Tests for the GitLab ``include:`` cross-document resolver.

The resolver merges local-include files into the parent pipeline so
cross-job rules (TAINT-008 ``extends:`` taint, GL-002 script
injection, etc.) see jobs and variables defined in included files.

The original ``include:`` block is preserved in the merged data so
include-pinning rules (GL-005, GL-011, GL-030) continue to fire on
the original directive.
"""
from __future__ import annotations

from pathlib import Path

from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks


def _findings(ctx: GitLabContext) -> list:
    return list(GitLabPipelineChecks(ctx).run())


def _by_id(findings, check_id):
    for f in findings:
        if f.check_id == check_id:
            return f
    raise AssertionError(f"{check_id!r} not in findings")


class TestLocalIncludeMerging:
    def test_bare_string_include_pulls_in_jobs(self, tmp_path: Path):
        (tmp_path / "shared.yml").write_text(
            ".base:\n"
            "  variables:\n"
            "    SHARED_VAR: from-include\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: shared.yml\n"
            "build:\n"
            "  extends: .base\n"
            "  script:\n"
            "    - echo $SHARED_VAR\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        assert len(ctx.pipelines) == 1
        # The hidden ``.base`` template is now visible in the merged data.
        assert ".base" in ctx.pipelines[0].data
        # And the parent's job is still there.
        assert "build" in ctx.pipelines[0].data
        # The original ``include:`` block is preserved so GL-005 / GL-011
        # / GL-030 still see the directive.
        assert ctx.pipelines[0].data["include"] == "shared.yml"

    def test_local_dict_form(self, tmp_path: Path):
        (tmp_path / "shared.yml").write_text(
            ".base:\n  variables: {X: 1}\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n  - local: shared.yml\n"
            "build:\n  extends: .base\n  script: [echo $X]\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        assert ".base" in ctx.pipelines[0].data

    def test_parent_wins_on_conflict(self, tmp_path: Path):
        """If both files define the same top-level key, the parent
        keeps its definition. This matches GitLab's "consumer
        overrides include" semantics for jobs."""
        (tmp_path / "shared.yml").write_text(
            "build:\n  script: [from-include]\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: shared.yml\n"
            "build:\n  script: [from-parent]\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        assert ctx.pipelines[0].data["build"]["script"] == ["from-parent"]

    def test_transitive_includes_resolved(self, tmp_path: Path):
        (tmp_path / "level2.yml").write_text(
            ".deep:\n  variables: {Y: 2}\n"
        )
        (tmp_path / "level1.yml").write_text(
            "include: level2.yml\n"
            ".mid:\n  extends: .deep\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: level1.yml\n"
            "build:\n  extends: .mid\n  script: [echo $Y]\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        # Both intermediate and leaf templates are merged into root.
        assert ".mid" in ctx.pipelines[0].data
        assert ".deep" in ctx.pipelines[0].data


class TestIncludeCycleDetection:
    def test_self_referential_cycle(self, tmp_path: Path):
        (tmp_path / "loop.yml").write_text(
            "include: loop.yml\n"
            ".x: {variables: {Z: 1}}\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: loop.yml\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        # First include resolves; the recursive self-reference is cut off
        # with a cycle warning. The resolver doesn't crash.
        assert ".x" in ctx.pipelines[0].data
        assert any("cycle detected" in w for w in ctx.warnings)

    def test_two_file_mutual_cycle(self, tmp_path: Path):
        (tmp_path / "a.yml").write_text("include: b.yml\n.a-template: {}\n")
        (tmp_path / "b.yml").write_text("include: a.yml\n.b-template: {}\n")
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: a.yml\nbuild: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        # Both templates pulled in once before the cycle's caught.
        assert ".a-template" in ctx.pipelines[0].data
        assert ".b-template" in ctx.pipelines[0].data
        assert any("cycle detected" in w for w in ctx.warnings)


class TestUnsupportedIncludeForms:
    def test_remote_include_warns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n  - remote: 'https://example.com/ci.yml'\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        # The scan continues; the remote isn't fetched.
        assert "build" in ctx.pipelines[0].data
        assert any("remote" in w and "not supported" in w for w in ctx.warnings)

    def test_project_include_warns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n"
            "  - project: 'group/proj'\n"
            "    ref: main\n"
            "    file: '/templates/Build.yml'\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        assert any(
            "project" in w and "not supported" in w for w in ctx.warnings
        )

    def test_missing_file_warns(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: does-not-exist.yml\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        assert any("not found" in w for w in ctx.warnings)


class TestPathTraversalProtection:
    """A malicious ``.gitlab-ci.yml`` checked into an untrusted repo
    must not be able to make the scanner read arbitrary host files.
    The resolver rejects any include whose resolved path escapes the
    scan root."""

    def test_dotdot_traversal_rejected(self, tmp_path: Path):
        # Layout:
        #   tmp_path/repo/.gitlab-ci.yml  (the scan target)
        #   tmp_path/secret.txt            (outside the repo)
        repo = tmp_path / "repo"
        repo.mkdir()
        (tmp_path / "secret.yml").write_text(".secret-template: {}\n")
        (repo / ".gitlab-ci.yml").write_text(
            "include: ../secret.yml\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(repo / ".gitlab-ci.yml")
        # Scan root is the repo dir; the include resolves above it.
        assert any("escapes scan root" in w for w in ctx.warnings)
        # And the secret template was NOT merged in.
        assert ".secret-template" not in ctx.pipelines[0].data

    def test_in_bound_dotdot_allowed(self, tmp_path: Path):
        """A ``..`` segment that resolves back inside the scan root
        is fine. Authors sometimes write ``../shared/build.yml`` to
        navigate within a monorepo."""
        repo = tmp_path
        (repo / "shared").mkdir()
        (repo / "shared" / "build.yml").write_text(".base: {}\n")
        (repo / "ci").mkdir()
        (repo / "ci" / ".gitlab-ci.yml").write_text(
            "include: ../shared/build.yml\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(repo)
        # No "escapes scan root" warning; the include resolves into
        # ``shared/`` which is under the scan root.
        assert not any("escapes scan root" in w for w in ctx.warnings)
        # And the merge happened.
        # The from_path call walks every .gitlab-ci.yml under the
        # directory; pick the one we wrote.
        ours = next(p for p in ctx.pipelines if p.path.endswith(".gitlab-ci.yml"))
        assert ".base" in ours.data

    def test_leading_slash_anchored_to_scan_root(self, tmp_path: Path):
        """A ``/``-prefixed path resolves against the scan root, not
        against the current file's directory. Matches GitLab's
        "full path relative to the repository root" semantics."""
        repo = tmp_path
        (repo / "templates").mkdir()
        (repo / "templates" / "shared.yml").write_text(".base: {}\n")
        (repo / "ci").mkdir()
        (repo / "ci" / ".gitlab-ci.yml").write_text(
            "include: /templates/shared.yml\n"
            "build: {script: [echo]}\n"
        )
        ctx = GitLabContext.from_path(repo)
        ours = next(p for p in ctx.pipelines if p.path.endswith(".gitlab-ci.yml"))
        # The leading-slash path resolved correctly against the scan
        # root; the template was merged in.
        assert ".base" in ours.data
        assert not any("escapes scan root" in w for w in ctx.warnings)


class TestTaintAcrossIncludes:
    """The original detection-power case: TAINT-008 walks ``extends:``
    chains and only fires when the tainted template is reachable. With
    include resolution, a hidden template in an included file becomes
    reachable and the rule fires across the boundary."""

    def test_taint_008_fires_when_template_in_include(self, tmp_path: Path):
        (tmp_path / "templates.yml").write_text(
            ".base:\n"
            "  variables:\n"
            "    TITLE: $CI_COMMIT_TITLE\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include: templates.yml\n"
            "build:\n"
            "  extends: .base\n"
            "  script:\n"
            "    - echo Building $TITLE\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        findings = _findings(ctx)
        taint = _by_id(findings, "TAINT-008")
        assert not taint.passed, (
            "TAINT-008 should fire when the tainted template lives in an "
            "included file and the parent's extends: pulls it in"
        )

    def test_taint_008_silent_without_resolution(self, tmp_path: Path):
        """Without the include resolver, the same scenario would slip
        past TAINT-008 because the hidden template isn't visible. We
        prove the resolver matters by checking the negative case: when
        the parent doesn't include the templates file, TAINT-008
        passes (no template, no chain, no taint)."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n"
            "  extends: .base\n"  # .base undefined in this doc
            "  script:\n"
            "    - echo Building $TITLE\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        findings = _findings(ctx)
        taint = _by_id(findings, "TAINT-008")
        assert taint.passed
