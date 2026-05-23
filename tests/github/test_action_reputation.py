"""Per-rule tests for the GHA-04x action-reputation pack
(GHA-041 single-maintainer / GHA-042 very-young repo / GHA-043
low-star + sensitive permission / GHA-047 fresh referenced ref) and
the underlying ``_action_reputation`` fetcher.

The reputation rules read ``ctx.action_metadata``, which is
populated by the ``--resolve-remote`` path in production. The tests
construct an in-memory metadata dict so they exercise the rule
logic without touching the network. A separate test class drives
the fetcher itself with a fake ``SCMFetcher``.
"""
from __future__ import annotations

import textwrap
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.github._action_reputation import (
    ActionMetadataFetcher,
    ActionRepoMetadata,
    collect_referenced_action_refs,
    collect_referenced_actions,
    populate_action_metadata,
)
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks


def _ctx_with_metadata(
    yaml_text: str,
    metadata: dict[str, ActionRepoMetadata] | None = None,
    path: str = "wf.yml",
) -> GitHubContext:
    text = textwrap.dedent(yaml_text)
    data = yaml.safe_load(text)
    if data is None:
        data = {}
    # Carry the raw text on the synthesized Workflow so rules that
    # inspect the pre-parse layer (currently just GHA-095) operate
    # the same way they do against on-disk workflow files.
    ctx = GitHubContext([Workflow(path=path, data=data, raw_text=text)])
    if metadata:
        ctx.action_metadata = dict(metadata)
    return ctx


def _run(ctx: GitHubContext, check_id: str) -> Any:
    for f in WorkflowChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(f"{check_id!r} not produced")


def _meta(
    owner: str, repo: str,
    contributor_count: int | None = None,
    created_at: str | None = None,
    stargazers_count: int | None = None,
    owner_type: str | None = None,
    archived: bool = False,
    fork: bool = False,
    ref_committed_at: dict[str, str | None] | None = None,
    sha_membership: dict[str, bool] | None = None,
    branch_head_shas: frozenset[str] | None = None,
    tag_shas: dict[str, str | None] | None = None,
) -> tuple[str, ActionRepoMetadata]:
    return f"{owner.lower()}/{repo.lower()}", ActionRepoMetadata(
        owner=owner, repo=repo,
        contributor_count=contributor_count,
        created_at=created_at,
        stargazers_count=stargazers_count,
        owner_type=owner_type,
        archived=archived,
        fork=fork,
        ref_committed_at=ref_committed_at,
        sha_membership=sha_membership,
        branch_head_shas=branch_head_shas,
        tag_shas=tag_shas,
    )


def _iso_days_ago(days: int) -> str:
    dt = datetime.now(tz=UTC) - timedelta(days=days)
    # Strip microseconds; GitHub serializes seconds-precision.
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── GHA-041: single-maintainer action ──────────────────────────────


class TestGHA041:
    def test_fires_when_action_has_one_contributor(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: solo/widget@v1
        """
        k, m = _meta("solo", "widget", contributor_count=1)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "solo/widget" in f.description

    def test_passes_when_action_has_multiple_contributors(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: well/maintained@v1
        """
        k, m = _meta("well", "maintained", contributor_count=2)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        """No metadata = opt-in flag is off (or fetch failed). The
        rule should pass and surface the discovery nudge."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: solo/widget@v1
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-041")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_dedups_repeated_action_refs(self):
        """An action used by every job should produce a single match,
        not one per occurrence."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: solo/widget@v1
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: solo/widget@v1
              - uses: solo/widget@v1
        """
        k, m = _meta("solo", "widget", contributor_count=1)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert not f.passed
        # The description should mention the action once.
        assert f.description.count("solo/widget") == 1

    def test_ignores_local_action_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
        """
        # No metadata entry for the local action; rule should pass.
        ctx = _ctx_with_metadata(wf, {})
        # Force non-empty metadata so we exercise the live-rule path
        # rather than the "no metadata" fast-path; a sentinel meta
        # for an unrelated repo is enough.
        k, m = _meta("unrelated", "repo", contributor_count=5)
        ctx.action_metadata = {k: m}
        f = _run(ctx, "GHA-041")
        assert f.passed

    def test_fires_on_reusable_workflow_callee(self):
        """The rule walks ``jobs.<id>.uses:`` (reusable workflows)
        as well as ``steps[].uses:`` — a single-maintainer callee
        is just as much a supply-chain risk as a single-maintainer
        step action."""
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: solo/shared/.github/workflows/release.yml@v1
        """
        k, m = _meta("solo", "shared", contributor_count=1)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert not f.passed
        assert "solo/shared" in f.description

    def test_contributor_count_zero_treated_as_single_maintainer(self):
        """A repo with zero (anonymous-only) contributors is at
        least as risky as a one-contributor repo. The rule fires
        on ``<= 1``."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: nascent/repo@v1
        """
        k, m = _meta("nascent", "repo", contributor_count=0)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert not f.passed

    def test_mixed_actions_only_single_maintainer_ones_fire(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: solo/widget@v1
        """
        k1, m1 = _meta("actions", "checkout", contributor_count=42)
        k2, m2 = _meta("solo", "widget", contributor_count=1)
        f = _run(_ctx_with_metadata(wf, {k1: m1, k2: m2}), "GHA-041")
        assert not f.passed
        assert "solo/widget" in f.description
        assert "actions/checkout" not in f.description

    def test_skips_action_without_contributor_count(self):
        """``contributor_count is None`` means the contributors fetch
        failed for this specific action. The rule should not fire on
        a slot with no data."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: solo/widget@v1
        """
        k, m = _meta("solo", "widget", contributor_count=None)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-041")
        assert f.passed


# ── GHA-042: very-young action repo ────────────────────────────────


class TestGHA042:
    def test_fires_when_repo_is_younger_than_threshold(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: typo/checkout@v1
        """
        k, m = _meta("typo", "checkout", created_at=_iso_days_ago(15))
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "typo/checkout" in f.description

    def test_passes_when_repo_is_older_than_threshold(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: trusted/action@v1
        """
        k, m = _meta("trusted", "action", created_at=_iso_days_ago(500))
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: typo/checkout@v1
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-042")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_handles_malformed_timestamp_gracefully(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: weird/timestamp@v1
        """
        k, m = _meta("weird", "timestamp", created_at="not-a-date")
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert f.passed

    def test_accepts_plus_zero_offset_timestamp(self):
        """GitHub usually sends ``Z`` suffix but older fixtures use
        ``+00:00``. Both must parse."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: typo/checkout@v1
        """
        dt = datetime.now(tz=UTC) - timedelta(days=10)
        ts = dt.replace(microsecond=0).isoformat()  # ends in +00:00
        k, m = _meta("typo", "checkout", created_at=ts)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert not f.passed

    def test_boundary_threshold_exact_age_passes(self, monkeypatch):
        """A repo whose age in days equals ``MIN_AGE_DAYS`` passes
        (rule uses ``< MIN_AGE_DAYS``, not ``<=``).

        Freezes the rule's clock via ``_now()`` so the boundary day
        count is unambiguous instead of riding on a wall-clock race
        between the test's ``datetime.now`` and the rule's.
        """
        from pipeline_check.core.checks.github.rules import (
            gha042_young_action_repo,
        )
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: borderline/action@v1
        """
        frozen_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        monkeypatch.setattr(
            gha042_young_action_repo, "_now", lambda: frozen_now,
        )
        created = frozen_now - timedelta(
            days=gha042_young_action_repo.MIN_AGE_DAYS,
        )
        ts = created.isoformat().replace("+00:00", "Z")
        k, m = _meta("borderline", "action", created_at=ts)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert f.passed


# ── GHA-043: low-star + sensitive permission ───────────────────────


class TestGHA043:
    def test_fires_on_low_stars_with_contents_write(self):
        wf = """
        name: ci
        on: push
        permissions:
          contents: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=3)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "obscure/action" in f.description
        assert "contents" in f.description

    def test_fires_on_low_stars_with_id_token_write(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=5)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert not f.passed

    def test_passes_on_low_stars_without_sensitive_permission(self):
        wf = """
        name: ci
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=2)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert f.passed

    def test_passes_on_high_stars_with_sensitive_permission(self):
        wf = """
        name: ci
        on: push
        permissions:
          contents: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        k, m = _meta("actions", "checkout", stargazers_count=6000)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert f.passed

    def test_write_all_treated_as_every_sensitive_scope(self):
        wf = """
        name: ci
        on: push
        permissions: write-all
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=1)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert not f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = """
        name: ci
        on: push
        permissions:
          contents: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: obscure/action@v1
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-043")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_job_level_permissions_win_over_workflow_top_level(self):
        """A workflow with broad top-level permissions but a narrowed
        per-job block should not fire on that job (the per-job block
        is the effective permissions)."""
        wf = """
        name: ci
        on: push
        permissions: write-all
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=1)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert f.passed

    def test_exactly_at_star_threshold_passes(self):
        """Boundary: a repo with exactly ``MAX_STARS`` stars passes
        (rule uses ``< MAX_STARS``, not ``<=``)."""
        from pipeline_check.core.checks.github.rules import (
            gha043_low_star_sensitive_permission,
        )
        wf = """
        name: ci
        on: push
        permissions:
          contents: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: borderline/action@v1
        """
        k, m = _meta(
            "borderline", "action",
            stargazers_count=(
                gha043_low_star_sensitive_permission.MAX_STARS
            ),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert f.passed

    def test_inherited_permissions_for_reusable_callee(self):
        """When a resolved reusable callee declares no permissions
        of its own, the rule sees the caller's inherited block as
        the effective permissions. Catches the case where a callee
        appears to have ``permissions: None`` but is actually run
        with the caller's elevated scopes."""
        import textwrap

        import yaml as _yaml

        from pipeline_check.core.checks.github.base import (
            GitHubContext,
            Workflow,
        )
        from pipeline_check.core.checks.github.workflows import (
            WorkflowChecks,
        )
        callee_text = """
        on: workflow_call
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: obscure/action@v1
        """
        data = _yaml.safe_load(textwrap.dedent(callee_text))
        # Synthesize the callee as if it had been pulled by the
        # remote-ref resolver — inherited_permissions carries the
        # caller's scope.
        wf = Workflow(
            path="resolved.yml", data=data,
            inherited_permissions={"contents": "write"},
        )
        ctx = GitHubContext([wf])
        k, m = _meta("obscure", "action", stargazers_count=1)
        ctx.action_metadata = {k: m}
        findings = {f.check_id: f for f in WorkflowChecks(ctx).run()}
        assert not findings["GHA-043"].passed

    def test_dedup_across_jobs_with_different_permissions(self):
        """An action referenced in two jobs (one with sensitive
        permission, one without) fires once for the sensitive-perm
        job, not twice."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: obscure/action@v1
          b:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: obscure/action@v1
        """
        k, m = _meta("obscure", "action", stargazers_count=2)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert not f.passed
        # Only the elevated-permission job is in the match list.
        assert f.description.count("obscure/action") == 1

    def test_fires_on_job_level_reusable_workflow_uses(self):
        """``jobs.<id>.uses:`` (reusable-workflow call) runs the
        callee with the caller's permissions inherited. A low-star
        callee in that slot is the same supply-chain shape as a
        step-level action and must be matched."""
        wf = """
        name: ci
        on: push
        permissions:
          contents: write
        jobs:
          call:
            uses: obscure/shared/.github/workflows/release.yml@v1
        """
        k, m = _meta("obscure", "shared", stargazers_count=3)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-043")
        assert not f.passed
        assert "obscure/shared" in f.description


# ── GHA-089: archived upstream repo ────────────────────────────────


class TestGHA089:
    def test_fires_when_action_repo_is_archived(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
        """
        k, m = _meta("legacy", "abandoned", archived=True)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-089")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "legacy/abandoned" in f.description

    def test_passes_when_action_repo_not_archived(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        k, m = _meta("actions", "checkout", archived=False)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-089")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-089")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_local_action_silent(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/local
        """
        # Local refs have no upstream; the rule doesn't even look at
        # them, so even with no metadata the description should NOT
        # mention an archived ref.
        f = _run(_ctx_with_metadata(wf, {}), "GHA-089")
        assert f.passed

    def test_fires_on_reusable_workflow_uses(self):
        # Job-level ``uses:`` (reusable workflow) is in scope: the
        # archived bit applies to the upstream repo regardless of
        # which file the consumer references inside it.
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: legacy/abandoned/.github/workflows/build.yml@v3
        """
        k, m = _meta("legacy", "abandoned", archived=True)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-089")
        assert not f.passed
        assert "legacy/abandoned" in f.description

    def test_multiple_archived_actions_aggregated(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned-a@v1
              - uses: legacy/abandoned-b@v2
              - uses: actions/checkout@v4
        """
        k1, m1 = _meta("legacy", "abandoned-a", archived=True)
        k2, m2 = _meta("legacy", "abandoned-b", archived=True)
        k3, m3 = _meta("actions", "checkout", archived=False)
        f = _run(
            _ctx_with_metadata(wf, {k1: m1, k2: m2, k3: m3}),
            "GHA-089",
        )
        assert not f.passed
        assert "2 action(s)" in f.description

    def test_dedup_same_action_referenced_twice(self):
        # The same archived action referenced by two jobs should
        # appear once in the finding description.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
        """
        k, m = _meta("legacy", "abandoned", archived=True)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-089")
        assert not f.passed
        assert "1 action(s)" in f.description

    def test_case_insensitive_metadata_lookup(self):
        # Upper-case in the workflow body still hits the lowercased
        # metadata key.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: LEGACY/Abandoned@v3
        """
        k, m = _meta("legacy", "abandoned", archived=True)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-089")
        assert not f.passed


# ── GHA-090: impostor-commit (SHA absent from claimed repo) ────────


_SHA_A = "a" * 40
_SHA_B = "b" * 40
_SHA_C = "c" * 40


class TestGHA090:
    def test_fires_when_sha_absent_from_repo(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
        """
        k, m = _meta(
            "actions", "checkout",
            sha_membership={_SHA_A: False},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-090")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "actions/checkout" in f.description

    def test_passes_when_sha_present_in_repo(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
        """
        k, m = _meta(
            "actions", "checkout",
            sha_membership={_SHA_A: True},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-090")
        assert f.passed

    def test_silent_on_tag_refs(self):
        # Tag / branch refs are not in scope; the rule only applies
        # to 40-char SHA pins.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        k, m = _meta(
            "actions", "checkout",
            sha_membership=None,
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-090")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-090")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_passes_silently_when_every_probe_failed(self):
        # All-False shape is rate-limit / network noise, not
        # impostor-commit. Pass silently with a nudge.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
              - uses: actions/setup-node@{_SHA_B}
        """
        k1, m1 = _meta(
            "actions", "checkout",
            sha_membership={_SHA_A: False},
        )
        k2, m2 = _meta(
            "actions", "setup-node",
            sha_membership={_SHA_B: False},
        )
        f = _run(_ctx_with_metadata(wf, {k1: m1, k2: m2}), "GHA-090")
        assert f.passed
        assert "rate-limit" in f.description

    def test_fires_when_some_probes_confirm_membership(self):
        # One impostor among several confirmed SHAs is the actual
        # attack shape and should fire.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
              - uses: actions/setup-node@{_SHA_B}
        """
        k1, m1 = _meta(
            "actions", "checkout",
            sha_membership={_SHA_A: False},
        )
        k2, m2 = _meta(
            "actions", "setup-node",
            sha_membership={_SHA_B: True},
        )
        f = _run(_ctx_with_metadata(wf, {k1: m1, k2: m2}), "GHA-090")
        assert not f.passed
        assert "actions/checkout" in f.description
        assert "setup-node" not in f.description

    def test_dedups_same_action_sha_referenced_twice(self):
        # Same impostor SHA referenced from two jobs should appear
        # once in the finding description.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}
              - uses: actions/setup-node@{_SHA_C}
        """
        k1, m1 = _meta(
            "actions", "checkout",
            sha_membership={_SHA_A: False},
        )
        k2, m2 = _meta(
            "actions", "setup-node",
            sha_membership={_SHA_C: True},
        )
        f = _run(_ctx_with_metadata(wf, {k1: m1, k2: m2}), "GHA-090")
        assert not f.passed
        assert "1 SHA-pinned" in f.description

    def test_fires_on_reusable_workflow_sha_pin(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          call:
            uses: dangerous/fork/.github/workflows/build.yml@{_SHA_A}
        """
        k, m = _meta(
            "dangerous", "fork",
            sha_membership={_SHA_A: False},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-090")
        assert not f.passed
        assert "dangerous/fork" in f.description


# ── GHA-091: repojacking (404 on /repos/{o}/{r}) ───────────────────


class TestGHA091:
    def test_fires_when_action_repo_is_missing(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
              - uses: actions/checkout@v4
        """
        ctx = _ctx_with_metadata(wf)
        # Some succeeded, one failed -> the failure is a real signal.
        ctx.action_fetch_failures = {"legacy/abandoned"}
        k, m = _meta("actions", "checkout")
        ctx.action_metadata = {k: m}
        f = _run(ctx, "GHA-091")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "legacy/abandoned" in f.description

    def test_passes_when_every_action_fetched_cleanly(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        ctx = _ctx_with_metadata(wf)
        k, m = _meta("actions", "checkout")
        ctx.action_metadata = {k: m}
        ctx.action_fetch_failures = set()
        f = _run(ctx, "GHA-091")
        assert f.passed

    def test_passes_silently_when_resolver_off(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
        """
        f = _run(_ctx_with_metadata(wf), "GHA-091")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_passes_silently_when_every_fetch_failed(self):
        # Unanimous-failure shape is rate-limit / network noise.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
        """
        ctx = _ctx_with_metadata(wf)
        ctx.action_metadata = {}
        ctx.action_fetch_failures = {
            "actions/checkout", "actions/setup-node",
        }
        f = _run(ctx, "GHA-091")
        assert f.passed
        assert "rate-limit" in f.description

    def test_single_action_with_only_failure_still_fires(self):
        # When only one action is referenced and it 404s, treat as
        # real (the unanimous-failure heuristic only kicks in with
        # >= 2 actions, since a peer is needed for "every" to mean
        # anything).
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned@v3
        """
        ctx = _ctx_with_metadata(wf)
        ctx.action_metadata = {}
        ctx.action_fetch_failures = {"legacy/abandoned"}
        f = _run(ctx, "GHA-091")
        assert not f.passed
        assert "legacy/abandoned" in f.description

    def test_fires_on_reusable_workflow_uses(self):
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: legacy/abandoned/.github/workflows/build.yml@v3
        """
        ctx = _ctx_with_metadata(wf)
        ctx.action_fetch_failures = {"legacy/abandoned"}
        # Add a successful peer so the unanimous heuristic doesn't
        # bypass.
        k, m = _meta("actions", "checkout")
        ctx.action_metadata = {k: m}
        f = _run(ctx, "GHA-091")
        assert not f.passed
        assert "legacy/abandoned" in f.description

    def test_local_action_silent(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
        """
        ctx = _ctx_with_metadata(wf)
        # Even with an unrelated failure, the rule should not flag a
        # local action.
        ctx.action_metadata = {}
        ctx.action_fetch_failures = {"some/other"}
        f = _run(ctx, "GHA-091")
        assert f.passed

    def test_multiple_failures_aggregated(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: legacy/abandoned-a@v1
              - uses: legacy/abandoned-b@v2
              - uses: actions/checkout@v4
        """
        ctx = _ctx_with_metadata(wf)
        ctx.action_fetch_failures = {
            "legacy/abandoned-a", "legacy/abandoned-b",
        }
        k, m = _meta("actions", "checkout")
        ctx.action_metadata = {k: m}
        f = _run(ctx, "GHA-091")
        assert not f.passed
        assert "2 action(s)" in f.description

    def test_case_insensitive_lookup(self):
        # Workflow body upper-cased; failure set lower-cased.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: LEGACY/Abandoned@v3
        """
        ctx = _ctx_with_metadata(wf)
        ctx.action_fetch_failures = {"legacy/abandoned"}
        k, m = _meta("actions", "checkout")
        ctx.action_metadata = {k: m}
        f = _run(ctx, "GHA-091")
        assert not f.passed


# ── GHA-094: stale-action-refs (SHA = branch tip) ──────────────────


class TestGHA094:
    def test_fires_when_sha_is_branch_tip(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_A}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "vendor/action" in f.description

    def test_passes_when_sha_below_branch_tip(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        # Branch tip is a different SHA; pinned SHA is below it.
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_B}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert f.passed

    def test_silent_on_tag_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@v4
        """
        # Tag-pinned action. Even if branch_head_shas is populated
        # with random SHAs, the rule shouldn't fire on @v4.
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_A, _SHA_B}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-094")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_passes_silently_when_branch_head_shas_none(self):
        # action_metadata has the action but branch_head_shas was not
        # populated (e.g. no SHA-shaped refs at the time the fetch
        # decided). Treat as "not probed."
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=None,
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_case_insensitive_match(self):
        # Workflow body has uppercase hex; the snapshot is lower-cased.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A.upper()}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_A}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert not f.passed

    def test_fires_on_reusable_workflow_sha_pin(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          call:
            uses: vendor/action/.github/workflows/build.yml@{_SHA_A}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_A}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert not f.passed

    def test_dedups_same_sha_referenced_twice(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset({_SHA_A}),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        assert not f.passed
        assert "1 SHA-pinned" in f.description

    def test_empty_branch_head_set_passes(self):
        # branch_head_shas is the empty frozenset means "lookup ran,
        # repo has no branches" (rare but legal). The pinned SHA is
        # by definition not a tip.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/action@{_SHA_A}
        """
        k, m = _meta(
            "vendor", "action",
            branch_head_shas=frozenset(),
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-094")
        # Even with no probes returning True, the rule needs the
        # field populated (not None) to fire / pass meaningfully.
        # Empty set means "no tips, no stale refs." Pass.
        assert f.passed


# ── GHA-095: ref-version-mismatch (SHA pin vs # vX.Y.Z comment) ────


class TestGHA095:
    def test_fires_when_sha_does_not_match_comment_tag(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
        """
        # Comment claims v4.1.1; tag actually resolves to _SHA_B.
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_B},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "actions/checkout" in f.description
        assert "v4.1.1" in f.description

    def test_passes_when_sha_matches_comment_tag(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_A},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed

    def test_passes_silently_when_tag_does_not_resolve(self):
        """A comment naming a tag the upstream repo doesn't carry
        (deleted tag, internal alias, 404) should pass — the rule
        treats unverifiable comments as benign, not as an FP source."""
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # internal-alias-q4
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_A},  # Different tag, not the comment's.
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_passes_silently_when_no_action_metadata(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-095")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_passes_silently_when_tag_shas_none(self):
        # action_metadata has the entry but tag_shas wasn't populated
        # (no version comments at the time the fetch decided).
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
        """
        k, m = _meta("actions", "checkout", tag_shas=None)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_normalizes_v_prefix_swap(self):
        """A comment ``# 4.1.1`` should match against an upstream
        ``v4.1.1`` tag and vice versa."""
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # 4.1.1
        """
        # Upstream tag is the v-prefixed form; lookup should swap.
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_A},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed

    def test_normalizes_v_prefix_swap_drift_fires(self):
        # Same prefix-swap path but the SHA still drifts; mismatch
        # should fire after the alternate lookup.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"4": _SHA_B},  # comment is v4, upstream key is 4
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert not f.passed

    def test_silent_on_tag_pinned_uses(self):
        # No SHA pin -> the rule's parser yields nothing. Even if
        # tag_shas is populated, no findings fire.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4  # v4.1.1
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_B},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        # Passes silently — no SHA-pin + comment site for the rule
        # to probe.
        assert f.passed

    def test_silent_when_comment_has_no_version_token(self):
        # Comment is generic prose, no version-shaped token. The
        # parser skips the line, rule passes silently.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # pinned by security team
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_B},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed

    def test_silent_when_workflow_has_no_raw_text(self):
        # Resolver-synthesized workflows carry no raw text; the rule
        # should pass without firing on them.
        ctx = GitHubContext([
            Workflow(
                path="composite:foo/bar@deadbeef",
                data={"jobs": {}},
                source_ref="composite:foo/bar@deadbeef",
                raw_text=None,
            ),
        ])
        ctx.action_metadata = {
            "foo/bar": ActionRepoMetadata(
                owner="foo", repo="bar",
                tag_shas={"v1": _SHA_A},
            ),
        }
        f = _run(ctx, "GHA-095")
        assert f.passed
        assert "synthesized" in f.description

    def test_fires_on_reusable_workflow_with_comment(self):
        # Job-level ``uses:`` to a reusable workflow with a SHA pin
        # and version comment. Parser handles the subpath syntax.
        wf = f"""
        name: ci
        on: push
        jobs:
          call:
            uses: org/repo/.github/workflows/build.yml@{_SHA_A}  # v2.0.0
        """
        k, m = _meta(
            "org", "repo",
            tag_shas={"v2.0.0": _SHA_B},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert not f.passed
        assert "org/repo" in f.description

    def test_case_insensitive_sha_match(self):
        # Workflow body has uppercase hex; tag_shas snapshot is
        # lower-cased. Match should still detect agreement.
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A.upper()}  # v4.1.1
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_A},  # lower-case match
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert f.passed

    def test_dedups_same_sha_referenced_twice(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{_SHA_A}  # v4.1.1
        """
        k, m = _meta(
            "actions", "checkout",
            tag_shas={"v4.1.1": _SHA_B},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-095")
        assert not f.passed
        assert "1 SHA-pinned" in f.description


# ── _version_comments.iter_version_comment_refs ────────────────────


class TestIterVersionCommentRefs:
    def test_picks_up_plain_v_prefixed_tag(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: actions/checkout@"
            f"{_SHA_A}  # v4.1.1\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert len(refs) == 1
        assert refs[0].owner == "actions"
        assert refs[0].repo == "checkout"
        assert refs[0].sha == _SHA_A
        assert refs[0].comment_tag == "v4.1.1"

    def test_picks_up_unprefixed_tag(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: vendor/widget@"
            f"{_SHA_B}  # 1.2.3\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert refs[0].comment_tag == "1.2.3"

    def test_picks_up_tag_inside_richer_comment(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: vendor/widget@"
            f"{_SHA_B}  # pin v4 (Renovate)\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert refs[0].comment_tag == "v4"

    def test_picks_up_prerelease_tag(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: vendor/widget@"
            f"{_SHA_B}  # v1.0.0-beta.2\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert refs[0].comment_tag == "v1.0.0-beta.2"

    def test_skips_line_without_version_token(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: vendor/widget@"
            f"{_SHA_A}  # pinned by security team\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert refs == []

    def test_skips_line_without_sha_pin(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = "      - uses: vendor/widget@v4  # v4.1.1\n"
        refs = list(iter_version_comment_refs(text))
        assert refs == []

    def test_skips_local_and_docker_uses(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: ./.github/actions/build  # v1\n"
            "      - uses: docker://node:18  # latest\n"
        )
        assert list(iter_version_comment_refs(text)) == []

    def test_handles_reusable_workflow_subpath(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      uses: org/repo/.github/workflows/build.yml@"
            f"{_SHA_A}  # v2\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert len(refs) == 1
        assert refs[0].owner == "org"
        assert refs[0].repo == "repo"
        assert refs[0].comment_tag == "v2"

    def test_handles_quoted_uses_value(self):
        from pipeline_check.core.checks.github._version_comments import (
            iter_version_comment_refs,
        )
        text = (
            "      - uses: \"actions/checkout@"
            f"{_SHA_A}\"  # v4.1.1\n"
        )
        refs = list(iter_version_comment_refs(text))
        assert len(refs) == 1
        assert refs[0].comment_tag == "v4.1.1"

    def test_extracts_against_word_boundary(self):
        # The extractor is anchored on left side so ``av4`` doesn't
        # produce ``v4``. Trailing characters are absorbed into the
        # pre-release group, which is fine — a spurious tag lookup
        # just returns ``None`` from the API and the rule passes
        # silently, no FP source.
        from pipeline_check.core.checks.github._version_comments import (
            _extract_version_token,
        )
        # Left-boundary protected: ``av4`` carries no version token.
        assert _extract_version_token("av4") is None
        # Pre-release absorption is by design; documented permissive.
        assert _extract_version_token("branch-v4-fix") == "v4-fix"

    def test_tag_alternates_v_prefix(self):
        from pipeline_check.core.checks.github._version_comments import (
            tag_alternates,
        )
        assert list(tag_alternates("v4")) == ["v4", "4"]
        assert list(tag_alternates("4.1")) == ["4.1", "v4.1"]
        # Tag that isn't strictly version-shaped (no alternative).
        assert list(tag_alternates("nightly")) == ["nightly"]


# ── _version_comments.collect_referenced_action_version_comments ───


class TestCollectReferencedActionVersionComments:
    def test_aggregates_across_workflows(self):
        from pipeline_check.core.checks.github._version_comments import (
            collect_referenced_action_version_comments,
        )
        wf_a = Workflow(
            path="a.yml", data={},
            raw_text=(
                "      - uses: actions/checkout@"
                f"{_SHA_A}  # v4.1.1\n"
                "      - uses: actions/setup-node@"
                f"{_SHA_B}  # v3\n"
            ),
        )
        wf_b = Workflow(
            path="b.yml", data={},
            raw_text=(
                "      - uses: actions/checkout@"
                f"{_SHA_C}  # v4.1.2\n"
            ),
        )
        ctx = GitHubContext([wf_a, wf_b])
        out = collect_referenced_action_version_comments(ctx)
        assert out == {
            ("actions", "checkout"): {"v4.1.1", "v4.1.2"},
            ("actions", "setup-node"): {"v3"},
        }

    def test_skips_workflow_without_raw_text(self):
        from pipeline_check.core.checks.github._version_comments import (
            collect_referenced_action_version_comments,
        )
        wf = Workflow(path="composite:x", data={}, raw_text=None)
        ctx = GitHubContext([wf])
        assert collect_referenced_action_version_comments(ctx) == {}


# ── _action_reputation.fetch_tag_shas ──────────────────────────────


class TestFetchTagShas:
    def test_extracts_sha_from_commits_payload(self):
        raw = FakeRawFetcher({
            "repos/acme/widget/commits/v4.1.1": {
                "sha": _SHA_A,
                "commit": {"committer": {"date": "2026-05-01T00:00:00Z"}},
            },
        })
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", {"v4.1.1"},
        )
        assert out == {"v4.1.1": _SHA_A}

    def test_missing_payload_yields_none(self):
        raw = FakeRawFetcher({})
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", {"v4.1.1"},
        )
        assert out == {"v4.1.1": None}

    def test_handles_malformed_payload(self):
        raw = FakeRawFetcher({
            "repos/acme/widget/commits/v4.1.1": "not-a-dict",
        })
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", {"v4.1.1"},
        )
        assert out == {"v4.1.1": None}

    def test_empty_set_returns_empty_dict(self):
        raw = FakeRawFetcher({})
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", set(),
        )
        assert out == {}
        assert raw.calls == []

    def test_lowercases_returned_sha(self):
        raw = FakeRawFetcher({
            "repos/acme/widget/commits/v1": {"sha": _SHA_A.upper()},
        })
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", {"v1"},
        )
        assert out == {"v1": _SHA_A}

    def test_skips_empty_string_tags(self):
        raw = FakeRawFetcher({})
        out = ActionMetadataFetcher(raw).fetch_tag_shas(
            "acme", "widget", {""},
        )
        assert out == {}
        assert raw.calls == []


# ── _action_reputation.fetch_branch_heads ──────────────────────────


class TestFetchBranchHeads:
    def test_returns_set_of_tip_shas(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(
            FakeRawFetcher({
                "repos/o/r/branches?per_page=100": [
                    {"name": "main", "commit": {"sha": _SHA_A}},
                    {"name": "dev", "commit": {"sha": _SHA_B}},
                ],
            })
        )
        result = fetcher.fetch_branch_heads("o", "r")
        assert result == frozenset({_SHA_A, _SHA_B})

    def test_returns_none_when_fetch_fails(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(FakeRawFetcher({}))
        result = fetcher.fetch_branch_heads("o", "r")
        assert result is None

    def test_skips_short_or_malformed_shas(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(
            FakeRawFetcher({
                "repos/o/r/branches?per_page=100": [
                    {"name": "main", "commit": {"sha": _SHA_A}},
                    {"name": "weird", "commit": {"sha": "short"}},
                    {"name": "broken", "commit": "not-a-dict"},
                    {"name": "missing-commit"},
                ],
            })
        )
        result = fetcher.fetch_branch_heads("o", "r")
        assert result == frozenset({_SHA_A})

    def test_lowercases_returned_shas(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(
            FakeRawFetcher({
                "repos/o/r/branches?per_page=100": [
                    {"name": "main", "commit": {"sha": _SHA_A.upper()}},
                ],
            })
        )
        result = fetcher.fetch_branch_heads("o", "r")
        assert result == frozenset({_SHA_A})


# ── _action_reputation.fetch_sha_membership ────────────────────────


class TestFetchShaMembership:
    def test_present_sha_returns_true(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(
            FakeRawFetcher({
                f"repos/o/r/commits/{_SHA_A}": {"sha": _SHA_A},
            })
        )
        result = fetcher.fetch_sha_membership("o", "r", {_SHA_A})
        assert result == {_SHA_A: True}

    def test_absent_sha_returns_false(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        # No mapping for the SHA -> FakeRawFetcher returns None ->
        # the fetcher records the SHA as not-present.
        fetcher = ActionMetadataFetcher(FakeRawFetcher({}))
        result = fetcher.fetch_sha_membership("o", "r", {_SHA_A})
        assert result == {_SHA_A: False}

    def test_mixed_shas(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(
            FakeRawFetcher({
                f"repos/o/r/commits/{_SHA_A}": {"sha": _SHA_A},
            })
        )
        result = fetcher.fetch_sha_membership(
            "o", "r", {_SHA_A, _SHA_B},
        )
        assert result == {_SHA_A: True, _SHA_B: False}

    def test_empty_set_returns_empty_dict(self):
        from pipeline_check.core.checks.github._action_reputation import (
            ActionMetadataFetcher,
        )

        fetcher = ActionMetadataFetcher(FakeRawFetcher({}))
        result = fetcher.fetch_sha_membership("o", "r", set())
        assert result == {}


# ── GHA-047: freshly-committed referenced ref ──────────────────────


class TestGHA047:
    def test_fires_when_referenced_ref_is_fresh(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1.2.3
        """
        k, m = _meta(
            "vendor", "widget",
            ref_committed_at={"v1.2.3": _iso_days_ago(2)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "vendor/widget@v1.2.3" in f.description

    def test_passes_when_referenced_ref_is_older_than_threshold(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1.2.3
        """
        k, m = _meta(
            "vendor", "widget",
            ref_committed_at={"v1.2.3": _iso_days_ago(60)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed

    def test_passes_silently_when_metadata_empty(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1.2.3
        """
        f = _run(_ctx_with_metadata(wf, {}), "GHA-047")
        assert f.passed
        assert "resolve-remote" in f.description

    def test_trusted_publisher_skipped_by_default(self):
        """``actions/checkout@v4`` legitimately gets retagged on every
        release of the upstream first-party action; firing on those
        would drown the rule. The default trusted-publisher allowlist
        suppresses ``actions``, ``aws-actions``, etc."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        k, m = _meta(
            "actions", "checkout",
            ref_committed_at={"v4": _iso_days_ago(1)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed

    def test_trusted_publisher_sha_pin_opts_back_in(self):
        """A 40-char SHA pin on a trusted publisher is the documented
        escape hatch for opting back into freshness gating. The
        floating-tag bypass exists to absorb noise from legitimate
        retags; a SHA pin doesn't move under retag and the caller is
        signaling they want the cooldown check on this specific ref."""
        sha = "0123456789abcdef0123456789abcdef01234567"
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{sha}
        """
        k, m = _meta(
            "actions", "checkout",
            ref_committed_at={sha: _iso_days_ago(1)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert not f.passed
        assert sha in f.description

    def test_per_ref_lookup_missing_passes_silently(self):
        """When the action metadata is present but the specific ``@ref``
        the workflow uses wasn't looked up (or came back with no date),
        the rule should not fire on that slot — same "unknown = pass"
        convention as the other reputation rules."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v9.9.9
        """
        k, m = _meta(
            "vendor", "widget",
            # Workflow asks about v9.9.9 but metadata only carries v1.0.0.
            ref_committed_at={"v1.0.0": _iso_days_ago(2)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed

    def test_per_ref_lookup_with_none_value_passes_silently(self):
        """An entry shaped ``{"v1": None}`` means the lookup ran but the
        API didn't carry a usable date. Treat as unknown."""
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1
        """
        k, m = _meta("vendor", "widget", ref_committed_at={"v1": None})
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed

    def test_dedups_repeated_ref_across_jobs(self):
        """An ``@ref`` referenced from multiple jobs counts once."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1.2.3
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1.2.3
        """
        k, m = _meta(
            "vendor", "widget",
            ref_committed_at={"v1.2.3": _iso_days_ago(2)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert not f.passed
        assert f.description.count("vendor/widget@v1.2.3") == 1

    def test_two_refs_to_same_action_evaluated_independently(self):
        """A workflow that pins one ref of an action to a fresh commit
        and another to an old one fires only on the fresh ref."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1
              - uses: vendor/widget@deadbeef
        """
        k, m = _meta(
            "vendor", "widget",
            ref_committed_at={
                "v1": _iso_days_ago(2),
                "deadbeef": _iso_days_ago(400),
            },
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert not f.passed
        assert "vendor/widget@v1" in f.description
        assert "vendor/widget@deadbeef" not in f.description

    def test_fires_on_reusable_workflow_callee_ref(self):
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: vendor/shared/.github/workflows/release.yml@v1
        """
        k, m = _meta(
            "vendor", "shared",
            ref_committed_at={"v1": _iso_days_ago(2)},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert not f.passed
        assert "vendor/shared@v1" in f.description

    def test_handles_malformed_timestamp_gracefully(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1
        """
        k, m = _meta(
            "vendor", "widget",
            ref_committed_at={"v1": "not-a-date"},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed

    def test_boundary_threshold_exact_age_passes(self):
        """A ref whose age in days equals ``MIN_REF_AGE_DAYS`` passes
        (rule uses ``< MIN_REF_AGE_DAYS``, not ``<=``). Subtract an
        extra second so the seconds-truncated timestamp is
        unambiguously older than the threshold after a few ms of test
        execution."""
        from pipeline_check.core.checks.github.rules import (
            gha047_fresh_action_ref,
        )
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@v1
        """
        dt = datetime.now(tz=UTC) - timedelta(
            days=gha047_fresh_action_ref.MIN_REF_AGE_DAYS,
            seconds=1,
        )
        ts = dt.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z",
        )
        k, m = _meta(
            "vendor", "widget", ref_committed_at={"v1": ts},
        )
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-047")
        assert f.passed


# ── _action_reputation: collect / populate / fetcher projection ────


class FakeRawFetcher:
    """Plain in-memory mapping from API path → JSON body. Mirrors
    the SCMFetcher shape; the projection layer
    (:class:`ActionMetadataFetcher`) sits on top so the test here
    drives the wrapper directly."""

    def __init__(self, mapping: dict[str, Any]):
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


class TestCollectReferencedActions:
    def test_collects_distinct_step_uses(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        ctx = _ctx_with_metadata(wf)
        seen = collect_referenced_actions(ctx)
        assert seen == {
            ("actions", "checkout"),
            ("actions", "setup-node"),
        }

    def test_collects_reusable_workflow_uses(self):
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: org/repo/.github/workflows/release.yml@v1
        """
        ctx = _ctx_with_metadata(wf)
        seen = collect_referenced_actions(ctx)
        assert seen == {("org", "repo")}

    def test_ignores_local_and_docker_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
              - uses: docker://ghcr.io/foo/bar:1.2.3
        """
        ctx = _ctx_with_metadata(wf)
        assert collect_referenced_actions(ctx) == set()

    def test_lowercases_owner_and_repo(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: Actions/Checkout@v4
        """
        ctx = _ctx_with_metadata(wf)
        seen = collect_referenced_actions(ctx)
        assert seen == {("actions", "checkout")}


class TestActionMetadataFetcher:
    def test_projects_repo_meta_into_dataclass(self):
        raw = FakeRawFetcher({
            "repos/acme/widget": {
                "owner": {"type": "User"},
                "created_at": "2024-01-15T00:00:00Z",
                "stargazers_count": 42,
                "archived": False,
                "fork": False,
            },
            "repos/acme/widget/contributors?per_page=2&anon=false": [
                {"login": "alice"},
            ],
        })
        meta = ActionMetadataFetcher(raw).fetch("acme", "widget")
        assert meta is not None
        assert meta.owner_type == "User"
        assert meta.created_at == "2024-01-15T00:00:00Z"
        assert meta.stargazers_count == 42
        assert meta.contributor_count == 1

    def test_returns_none_when_repo_meta_missing(self):
        raw = FakeRawFetcher({})
        assert ActionMetadataFetcher(raw).fetch("acme", "widget") is None

    def test_contributor_count_absent_when_endpoint_404s(self):
        """The contributors endpoint can 403/404 on certain action
        repos. Repo meta should still come back; contributor_count
        is just None."""
        raw = FakeRawFetcher({
            "repos/acme/widget": {
                "owner": {"type": "Organization"},
                "stargazers_count": 100,
            },
        })
        meta = ActionMetadataFetcher(raw).fetch("acme", "widget")
        assert meta is not None
        assert meta.contributor_count is None
        assert meta.stargazers_count == 100

    def test_contributor_count_zero_for_empty_list(self):
        raw = FakeRawFetcher({
            "repos/acme/widget": {"stargazers_count": 0},
            "repos/acme/widget/contributors?per_page=2&anon=false": [],
        })
        meta = ActionMetadataFetcher(raw).fetch("acme", "widget")
        assert meta is not None
        assert meta.contributor_count == 0


class TestFetchRefDates:
    def test_extracts_committer_date_from_commits_endpoint(self):
        raw = FakeRawFetcher({
            "repos/acme/widget/commits/v1": {
                "sha": "deadbeef" * 5,
                "commit": {
                    "committer": {"date": "2026-05-01T12:00:00Z"},
                    "author": {"date": "2024-01-01T00:00:00Z"},
                },
            },
        })
        out = ActionMetadataFetcher(raw).fetch_ref_dates(
            "acme", "widget", {"v1"},
        )
        assert out == {"v1": "2026-05-01T12:00:00Z"}

    def test_missing_payload_yields_none(self):
        raw = FakeRawFetcher({})
        out = ActionMetadataFetcher(raw).fetch_ref_dates(
            "acme", "widget", {"v1"},
        )
        assert out == {"v1": None}

    def test_handles_malformed_payload_without_raising(self):
        """A non-dict response (HTML error page, garbage) lands as
        ``None`` rather than crashing the populate pass."""
        raw = FakeRawFetcher({
            "repos/acme/widget/commits/v1": "not-json",
        })
        out = ActionMetadataFetcher(raw).fetch_ref_dates(
            "acme", "widget", {"v1"},
        )
        assert out == {"v1": None}

    def test_skips_empty_string_refs(self):
        """Defensive: a refs set containing the empty string (impossible
        through the normal collector but cheap to guard) should not
        produce a request."""
        raw = FakeRawFetcher({})
        out = ActionMetadataFetcher(raw).fetch_ref_dates(
            "acme", "widget", {""},
        )
        assert out == {}
        assert raw.calls == []


class TestCollectReferencedActionRefs:
    def test_groups_refs_per_action(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v3
              - uses: actions/checkout@v4
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: vendor/widget@deadbeef
        """
        ctx = _ctx_with_metadata(wf)
        out = collect_referenced_action_refs(ctx)
        assert out == {
            ("actions", "checkout"): {"v3", "v4"},
            ("vendor", "widget"): {"deadbeef"},
        }

    def test_ignores_local_and_docker_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
              - uses: docker://ghcr.io/foo/bar:1.2.3
        """
        ctx = _ctx_with_metadata(wf)
        assert collect_referenced_action_refs(ctx) == {}

    def test_collects_reusable_workflow_callee_ref(self):
        wf = """
        name: ci
        on: push
        jobs:
          call:
            uses: org/repo/.github/workflows/release.yml@v1
        """
        ctx = _ctx_with_metadata(wf)
        assert collect_referenced_action_refs(ctx) == {
            ("org", "repo"): {"v1"},
        }


class TestPopulateActionMetadata:
    def test_populates_metadata_on_ctx_for_each_referenced_action(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: acme/widget@v1
        """
        ctx = _ctx_with_metadata(wf)
        raw = FakeRawFetcher({
            "repos/acme/widget": {
                "owner": {"type": "User"},
                "stargazers_count": 7,
                "created_at": "2024-06-01T00:00:00Z",
            },
            "repos/acme/widget/contributors?per_page=2&anon=false": [
                {"login": "solo"},
            ],
        })
        populate_action_metadata(ctx, ActionMetadataFetcher(raw))
        assert "acme/widget" in ctx.action_metadata
        assert ctx.action_metadata["acme/widget"].stargazers_count == 7

    def test_failed_fetch_records_warning(self):
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: private/repo@v1
        """
        ctx = _ctx_with_metadata(wf)
        raw = FakeRawFetcher({})  # all fetches return None
        populate_action_metadata(ctx, ActionMetadataFetcher(raw))
        assert ctx.action_metadata == {}
        assert any("action reputation" in w for w in ctx.warnings)

    def test_populates_ref_committed_at_for_referenced_refs(self):
        """The per-ref date fetch should fold its results into the
        assembled :class:`ActionRepoMetadata`. Two distinct refs to the
        same action produce two entries in ``ref_committed_at``."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: acme/widget@v1
              - uses: acme/widget@deadbeef
        """
        ctx = _ctx_with_metadata(wf)
        raw = FakeRawFetcher({
            "repos/acme/widget": {
                "owner": {"type": "Organization"},
                "stargazers_count": 7,
                "created_at": "2024-06-01T00:00:00Z",
            },
            "repos/acme/widget/contributors?per_page=2&anon=false": [
                {"login": "alice"},
            ],
            "repos/acme/widget/commits/v1": {
                "commit": {"committer": {"date": "2026-05-01T12:00:00Z"}},
            },
            "repos/acme/widget/commits/deadbeef": {
                "commit": {"committer": {"date": "2024-01-15T00:00:00Z"}},
            },
        })
        populate_action_metadata(ctx, ActionMetadataFetcher(raw))
        meta = ctx.action_metadata["acme/widget"]
        assert meta.ref_committed_at == {
            "v1": "2026-05-01T12:00:00Z",
            "deadbeef": "2024-01-15T00:00:00Z",
        }

    def test_ref_committed_at_is_dict_with_none_when_lookup_empty(self):
        """An action referenced with an ``@ref`` whose commits endpoint
        returns nothing should leave the slot as ``{"v1": None}`` —
        distinct from the whole-slot ``None`` (meaning "no refs to
        look up")."""
        wf = """
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: acme/widget@v1
        """
        ctx = _ctx_with_metadata(wf)
        raw = FakeRawFetcher({
            "repos/acme/widget": {"stargazers_count": 1},
            # No commits/v1 entry — the per-ref date comes back None.
        })
        populate_action_metadata(ctx, ActionMetadataFetcher(raw))
        meta = ctx.action_metadata["acme/widget"]
        assert meta.ref_committed_at == {"v1": None}
