"""Per-rule tests for the GHA-04x action-reputation pack
(GHA-041 single-maintainer / GHA-042 very-young repo / GHA-043
low-star + sensitive permission) and the underlying
``_action_reputation`` fetcher.

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
) -> tuple[str, ActionRepoMetadata]:
    return f"{owner.lower()}/{repo.lower()}", ActionRepoMetadata(
        owner=owner, repo=repo,
        contributor_count=contributor_count,
        created_at=created_at,
        stargazers_count=stargazers_count,
        owner_type=owner_type,
        archived=archived,
        fork=fork,
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
