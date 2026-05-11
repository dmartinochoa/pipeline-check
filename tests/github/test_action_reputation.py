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
from datetime import datetime, timedelta, timezone
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
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    if data is None:
        data = {}
    ctx = GitHubContext([Workflow(path=path, data=data)])
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
    )


def _iso_days_ago(days: int) -> str:
    dt = datetime.now(tz=timezone.utc) - timedelta(days=days)
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
        dt = datetime.now(tz=timezone.utc) - timedelta(days=10)
        ts = dt.replace(microsecond=0).isoformat()  # ends in +00:00
        k, m = _meta("typo", "checkout", created_at=ts)
        f = _run(_ctx_with_metadata(wf, {k: m}), "GHA-042")
        assert not f.passed

    def test_boundary_threshold_exact_age_passes(self):
        """A repo whose age in days equals ``MIN_AGE_DAYS`` passes
        (rule uses ``< MIN_AGE_DAYS``, not ``<=``).

        Subtract an extra second so the seconds-truncated
        ``created_at`` timestamp is unambiguously older than the
        threshold even after a few milliseconds of test execution
        time. Without the nudge, the assertion is flaky around
        midnight-UTC clock boundaries: ``datetime.now`` advances
        between the ``_iso_days_ago`` call and the rule's own
        ``datetime.now`` lookup, occasionally tipping the age
        computation below the threshold.
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
        dt = datetime.now(tz=timezone.utc) - timedelta(
            days=gha042_young_action_repo.MIN_AGE_DAYS,
            seconds=1,
        )
        ts = dt.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z",
        )
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
        dt = datetime.now(tz=timezone.utc) - timedelta(
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
