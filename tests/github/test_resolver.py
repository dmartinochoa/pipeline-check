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
