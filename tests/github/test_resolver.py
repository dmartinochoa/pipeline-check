"""Tests for the GHA reusable-workflow resolver.

Uses a :class:`FakeFetcher` so the test suite never touches the
network. The fetcher protocol is the seam that lets us swap an HTTP
client for an in-memory map.
"""
from __future__ import annotations

import textwrap

from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.resolver import (
    DiskFetcher,
    FileSystemCache,
    Resolver,
    _cache_filename,
)


class FakeFetcher:
    """In-memory fetcher used by the resolver tests.

    Maps ``(owner, repo, ref, path) -> bytes``. Anything not in the
    map returns ``None`` (which the resolver treats as "could not
    fetch, record warning, keep going").
    """

    def __init__(self, mapping: dict[tuple[str, str, str, str], bytes]):
        self.mapping = mapping
        self.calls: list[tuple[str, str, str, str]] = []

    def fetch(self, owner: str, repo: str, ref: str, path: str) -> bytes | None:
        self.calls.append((owner, repo, ref, path))
        return self.mapping.get((owner, repo, ref, path))


def _wf(path: str, body: str) -> Workflow:
    """Synthesize a parsed Workflow from a YAML snippet."""
    import yaml
    return Workflow(path=path, data=yaml.safe_load(textwrap.dedent(body)))


def _ctx(workflows: list[Workflow]) -> GitHubContext:
    return GitHubContext(workflows)


# A dummy 40-char SHA used in pinned ``uses:`` refs.
_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


CALLER_BODY = f"""
on: push
jobs:
  call-release:
    uses: myorg/shared/.github/workflows/release.yml@{_SHA}
    secrets: inherit
"""

CALLEE_BODY = """
on: workflow_call
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: echo "release"
"""


class TestResolverHappyPath:
    def test_fetches_and_appends_callee(self):
        ctx = _ctx([_wf(".github/workflows/main.yml", CALLER_BODY)])
        fetcher = FakeFetcher({
            ("myorg", "shared", _SHA, ".github/workflows/release.yml"):
                CALLEE_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        # Original caller plus the resolved callee.
        assert len(ctx.workflows) == 2
        callee = ctx.workflows[1]
        assert callee.source_ref == (
            f"myorg/shared/.github/workflows/release.yml@{_SHA}"
        )
        assert callee.caller_path == ".github/workflows/main.yml"
        assert callee.inherits_secrets is True

    def test_resolved_callee_inherits_caller_permissions(self):
        body = f"""
        on: push
        permissions:
          contents: read
        jobs:
          call:
            uses: myorg/shared/.github/workflows/release.yml@{_SHA}
        """
        ctx = _ctx([_wf("main.yml", body)])
        fetcher = FakeFetcher({
            ("myorg", "shared", _SHA, ".github/workflows/release.yml"):
                CALLEE_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        assert ctx.workflows[1].inherited_permissions == {"contents": "read"}


class TestResolverUnpinned:
    def test_unpinned_remote_ref_is_skipped_with_warning(self):
        body = """
        on: push
        jobs:
          call:
            uses: myorg/shared/.github/workflows/release.yml@main
        """
        ctx = _ctx([_wf("main.yml", body)])
        fetcher = FakeFetcher({})
        Resolver(fetcher=fetcher).resolve(ctx)
        # No fetch attempted.
        assert fetcher.calls == []
        # Warning surfaced on the context.
        assert any("unpinned" in w for w in ctx.warnings)


class TestResolverFailures:
    def test_fetch_failure_records_warning_no_crash(self):
        ctx = _ctx([_wf("main.yml", CALLER_BODY)])
        fetcher = FakeFetcher({})  # empty map: every fetch returns None
        Resolver(fetcher=fetcher).resolve(ctx)
        assert len(ctx.workflows) == 1  # nothing appended
        assert any("could not fetch" in w for w in ctx.warnings)

    def test_malformed_yaml_recorded_no_crash(self):
        ctx = _ctx([_wf("main.yml", CALLER_BODY)])
        fetcher = FakeFetcher({
            ("myorg", "shared", _SHA, ".github/workflows/release.yml"):
                b": this is :: not yaml",
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        assert len(ctx.workflows) == 1
        assert any("YAML parse error" in w for w in ctx.warnings)


class TestResolverDepth:
    def test_depth_cap_stops_at_max(self):
        # caller -> A -> B -> C; max_depth=2 should stop before C.
        a_body = f"""
        on: workflow_call
        jobs:
          j: {{uses: myorg/repo/.github/workflows/b.yml@{_SHA}}}
        """
        b_body = f"""
        on: workflow_call
        jobs:
          j: {{uses: myorg/repo/.github/workflows/c.yml@{_SHA}}}
        """
        c_body = """
        on: workflow_call
        jobs:
          j:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        caller_body = f"""
        on: push
        jobs:
          j: {{uses: myorg/repo/.github/workflows/a.yml@{_SHA}}}
        """
        ctx = _ctx([_wf("main.yml", caller_body)])
        fetcher = FakeFetcher({
            ("myorg", "repo", _SHA, ".github/workflows/a.yml"): a_body.encode("utf-8"),
            ("myorg", "repo", _SHA, ".github/workflows/b.yml"): b_body.encode("utf-8"),
            ("myorg", "repo", _SHA, ".github/workflows/c.yml"): c_body.encode("utf-8"),
        })
        Resolver(fetcher=fetcher, max_depth=2).resolve(ctx)
        # Original + a + b. C is past the cap.
        paths = [wf.path for wf in ctx.workflows]
        assert any("a.yml" in p for p in paths)
        assert any("b.yml" in p for p in paths)
        assert not any("c.yml" in p for p in paths)


class TestResolverCycle:
    def test_cycle_detection_stops_revisits(self):
        # a -> b -> a (cycle).
        a_body = f"""
        on: workflow_call
        jobs:
          j: {{uses: myorg/repo/.github/workflows/b.yml@{_SHA}}}
        """
        b_body = f"""
        on: workflow_call
        jobs:
          j: {{uses: myorg/repo/.github/workflows/a.yml@{_SHA}}}
        """
        caller_body = f"""
        on: push
        jobs:
          j: {{uses: myorg/repo/.github/workflows/a.yml@{_SHA}}}
        """
        ctx = _ctx([_wf("main.yml", caller_body)])
        fetcher = FakeFetcher({
            ("myorg", "repo", _SHA, ".github/workflows/a.yml"): a_body.encode("utf-8"),
            ("myorg", "repo", _SHA, ".github/workflows/b.yml"): b_body.encode("utf-8"),
        })
        Resolver(fetcher=fetcher, max_depth=10).resolve(ctx)
        # Each callee fetched exactly once.
        a_calls = [c for c in fetcher.calls if c[3].endswith("a.yml")]
        b_calls = [c for c in fetcher.calls if c[3].endswith("b.yml")]
        assert len(a_calls) == 1
        assert len(b_calls) == 1


class TestResolverDedup:
    def test_two_callers_same_callee_fetches_once(self):
        body = f"""
        on: push
        jobs:
          j: {{uses: myorg/shared/.github/workflows/release.yml@{_SHA}}}
        """
        ctx = _ctx([
            _wf("a.yml", body),
            _wf("b.yml", body),
        ])
        fetcher = FakeFetcher({
            ("myorg", "shared", _SHA, ".github/workflows/release.yml"):
                CALLEE_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        # Only one fetch even though two callers reference it.
        assert len(fetcher.calls) == 1


class TestSecretsInherit:
    def test_explicit_secrets_map_does_not_set_inherit_flag(self):
        body = f"""
        on: push
        jobs:
          j:
            uses: myorg/shared/.github/workflows/release.yml@{_SHA}
            secrets:
              MY_SECRET: ${{{{ secrets.SHARED_SECRET }}}}
        """
        ctx = _ctx([_wf("main.yml", body)])
        fetcher = FakeFetcher({
            ("myorg", "shared", _SHA, ".github/workflows/release.yml"):
                CALLEE_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        callee = ctx.workflows[1]
        assert callee.inherits_secrets is False
        assert "MY_SECRET" in callee.inherited_secret_names


# ── Composite-action resolution ──────────────────────────────────────


# A composite action body, as it would live at action.yml in a third-party repo.
COMPOSITE_ACTION_BODY = """
name: My Composite
description: Demonstrates composite-action resolution.
runs:
  using: composite
  steps:
    - uses: actions/checkout@v3
    - run: curl -sL https://example.com/install.sh | bash
      shell: bash
    - run: echo "AWS_ACCESS_KEY_ID=AKIAZ3MHALF2TESTHIJK" >> $GITHUB_ENV
      shell: bash
"""

JS_ACTION_BODY = """
name: JS Action
runs:
  using: node20
  main: dist/index.js
"""

DOCKER_ACTION_BODY = """
name: Docker Action
runs:
  using: docker
  image: Dockerfile
"""

CALLER_WITH_COMPOSITE_USE = f"""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
      - uses: thirdparty/composite@{_SHA}
"""


class TestResolverCompositeAction:
    def test_fetches_composite_action_yml_and_synthesizes_workflow(self):
        ctx = _ctx([_wf(".github/workflows/main.yml", CALLER_WITH_COMPOSITE_USE)])
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yml"):
                COMPOSITE_ACTION_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        # Composite body appended as a synthesized workflow.
        assert len(ctx.workflows) == 2
        composite = ctx.workflows[1]
        assert composite.source_ref == f"composite:thirdparty/composite@{_SHA}"
        assert composite.caller_path == ".github/workflows/main.yml"
        # Synthetic single-job structure with the composite's steps.
        jobs = composite.data["jobs"]
        assert "__composite__" in jobs
        assert len(jobs["__composite__"]["steps"]) == 3

    def test_falls_back_to_action_yaml_when_action_yml_missing(self):
        ctx = _ctx([_wf("main.yml", CALLER_WITH_COMPOSITE_USE)])
        # Only the .yaml variant exists.
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yaml"):
                COMPOSITE_ACTION_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        assert len(ctx.workflows) == 2

    def test_subpath_action_uses_subdir_action_yml(self):
        # uses: actions/setup-node/lib@<sha> -> fetch lib/action.yml
        body = f"""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node/lib@{_SHA}
        """
        ctx = _ctx([_wf("main.yml", body)])
        fetcher = FakeFetcher({
            ("actions", "setup-node", _SHA, "lib/action.yml"):
                COMPOSITE_ACTION_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        # Confirm we asked for lib/action.yml first.
        assert ("actions", "setup-node", _SHA, "lib/action.yml") in fetcher.calls

    def test_javascript_action_fetched_but_not_synthesized(self):
        ctx = _ctx([_wf("main.yml", CALLER_WITH_COMPOSITE_USE)])
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yml"):
                JS_ACTION_BODY.encode("utf-8"),
        })
        r = Resolver(fetcher=fetcher)
        r.resolve(ctx)
        # Fetched and parsed but not synthesized — a JS action's
        # bytecode isn't analyzable from its action.yml.
        assert len(ctx.workflows) == 1
        assert r.stats.non_composite_actions_skipped == 1
        assert r.stats.composite_actions_resolved == 0

    def test_docker_action_fetched_but_not_synthesized(self):
        ctx = _ctx([_wf("main.yml", CALLER_WITH_COMPOSITE_USE)])
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yml"):
                DOCKER_ACTION_BODY.encode("utf-8"),
        })
        r = Resolver(fetcher=fetcher)
        r.resolve(ctx)
        assert len(ctx.workflows) == 1
        assert r.stats.non_composite_actions_skipped == 1

    def test_unpinned_action_ref_skipped_with_warning(self):
        body = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: thirdparty/composite@v1
        """
        ctx = _ctx([_wf("main.yml", body)])
        fetcher = FakeFetcher({})
        Resolver(fetcher=fetcher).resolve(ctx)
        # Unpinned: no fetch, warning surfaces same skipped-unpinned message.
        assert fetcher.calls == []
        assert any("unpinned" in w for w in ctx.warnings)

    def test_composite_steps_run_through_existing_rule_pack(self):
        """The synthesized composite workflow should be visible to the
        existing rule pack so issues hidden inside a third-party
        composite show up exactly as if the caller wrote them inline."""
        from pipeline_check.core.checks.github.workflows import WorkflowChecks

        ctx = _ctx([_wf(".github/workflows/main.yml", CALLER_WITH_COMPOSITE_USE)])
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yml"):
                COMPOSITE_ACTION_BODY.encode("utf-8"),
        })
        Resolver(fetcher=fetcher).resolve(ctx)
        findings = WorkflowChecks(ctx).run()
        # GHA-001 fires on the composite body's unpinned ``actions/checkout@v3``.
        gha001 = [f for f in findings if f.check_id == "GHA-001" and not f.passed]
        assert any(
            "composite:thirdparty/composite" in f.resource for f in gha001
        ), "GHA-001 should fire on the composite's unpinned actions/checkout@v3"
        # GHA-016 (curl-pipe) fires on the composite's run step.
        gha016 = [f for f in findings if f.check_id == "GHA-016" and not f.passed]
        assert any(
            "composite:thirdparty/composite" in f.resource for f in gha016
        ), "GHA-016 should fire on the composite's curl-pipe payload"

    def test_resolver_stats_count_composite_resolutions(self):
        ctx = _ctx([_wf("main.yml", CALLER_WITH_COMPOSITE_USE)])
        fetcher = FakeFetcher({
            ("thirdparty", "composite", _SHA, "action.yml"):
                COMPOSITE_ACTION_BODY.encode("utf-8"),
        })
        r = Resolver(fetcher=fetcher)
        r.resolve(ctx)
        assert r.stats.composite_actions_resolved == 1
        # The summary line shows up in ctx.warnings.
        assert any(
            "composite action" in w for w in ctx.warnings
        )


# ── Cache ────────────────────────────────────────────────────────────


class TestFileSystemCache:
    def test_round_trip(self, tmp_path):
        c = FileSystemCache(tmp_path)
        c.put("o", "r", "ref1", "p.yml", b"hello")
        assert c.get("o", "r", "ref1", "p.yml") == b"hello"

    def test_disabled_short_circuits_both_directions(self, tmp_path):
        c = FileSystemCache(tmp_path, enabled=False)
        c.put("o", "r", "ref1", "p.yml", b"hello")
        assert c.get("o", "r", "ref1", "p.yml") is None

    def test_filename_collapses_long_paths(self):
        # Deeply nested workflow paths must not blow Windows' 260-char
        # filename ceiling — the path component is sha256-truncated.
        long_path = "a/" * 200 + "release.yml"
        name = _cache_filename("o", "r", "ref1", long_path)
        # 16-char hash + literal prefix + ext keeps us well under 100.
        assert len(name) < 80


# ── DiskFetcher ──────────────────────────────────────────────────────


class TestDiskFetcher:
    def test_returns_bytes_when_file_exists(self, tmp_path):
        target = tmp_path / "myorg" / "shared" / ".github" / "workflows"
        target.mkdir(parents=True)
        wf = target / "release.yml"
        wf.write_bytes(b"on: workflow_call\njobs: {}")
        f = DiskFetcher([tmp_path])
        assert f.fetch("myorg", "shared", "v1", ".github/workflows/release.yml") == (
            b"on: workflow_call\njobs: {}"
        )

    def test_returns_none_when_missing(self, tmp_path):
        f = DiskFetcher([tmp_path])
        assert f.fetch("o", "r", "v1", ".github/workflows/missing.yml") is None
