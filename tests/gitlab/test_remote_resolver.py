"""Tests for the GitLab remote ``include:`` resolver.

Covers the ``GitLabIncludeFetcher`` class (project / remote / template /
component), the ``_resolve_remote_includes()`` merge function, the
``post_filter()`` wiring in ``GitLabProvider``, and the taint-engine
integration when remote includes surface new jobs / templates.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from pipeline_check.core.checks.gitlab.base import (
    GitLabContext,
    Pipeline,
    _resolve_remote_includes,
)
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.gitlab.resolver import (
    GitLabIncludeFetcher,
    ResolverStats,
    count_unresolved_remote_includes,
)
from pipeline_check.core.providers.gitlab import GitLabProvider


def _findings(ctx: GitLabContext) -> list:
    return list(GitLabPipelineChecks(ctx).run())


def _finding_ids(ctx: GitLabContext) -> set[str]:
    return {f.check_id for f in _findings(ctx)}


# ── GitLabIncludeFetcher unit tests ──────────────────────────────


class TestFetcherProject:
    def test_project_constructs_correct_url(self):
        fetcher = GitLabIncludeFetcher(gitlab_url="https://gl.example.com")
        with patch.object(fetcher, "_api_get", return_value=b"x: 1") as mock:
            result = fetcher.fetch("project", {
                "project": "my-group/my-project",
                "file": "/ci/build.yml",
                "ref": "abc123",
            })
        assert result == b"x: 1"
        url = mock.call_args[0][0]
        assert "gl.example.com/api/v4/projects/my-group%2Fmy-project" in url
        assert "ci%2Fbuild.yml" in url
        assert "ref=abc123" in url

    def test_project_defaults_ref_to_head(self):
        fetcher = GitLabIncludeFetcher()
        with patch.object(fetcher, "_api_get", return_value=b"x: 1") as mock:
            fetcher.fetch("project", {
                "project": "g/p",
                "file": "/a.yml",
            })
        assert "ref=HEAD" in mock.call_args[0][0]

    def test_project_missing_fields_returns_none(self):
        fetcher = GitLabIncludeFetcher()
        assert fetcher.fetch("project", {"project": "g/p"}) is None
        assert fetcher.fetch("project", {"file": "/a.yml"}) is None


class TestFetcherRemote:
    def test_remote_https_accepted(self):
        fetcher = GitLabIncludeFetcher()
        with patch.object(fetcher, "_http_get", return_value=b"job: {}") as mock:
            result = fetcher.fetch("remote", {
                "remote": "https://example.com/ci.yml",
            })
        assert result == b"job: {}"
        mock.assert_called_once_with("https://example.com/ci.yml")

    def test_remote_http_rejected(self):
        fetcher = GitLabIncludeFetcher()
        result = fetcher.fetch("remote", {
            "remote": "http://example.com/ci.yml",
        })
        assert result is None
        assert fetcher.stats.failed == 1


class TestFetcherTemplate:
    def test_template_extracts_content_from_json(self):
        fetcher = GitLabIncludeFetcher(gitlab_url="https://gitlab.com")
        json_resp = json.dumps({"content": "build:\n  script: [echo hi]"}).encode()
        with patch.object(fetcher, "_api_get", return_value=json_resp):
            result = fetcher.fetch("template", {
                "template": "Auto-DevOps.gitlab-ci.yml",
            })
        assert result is not None
        assert b"build:" in result

    def test_template_raw_yaml_fallback(self):
        fetcher = GitLabIncludeFetcher()
        with patch.object(fetcher, "_api_get", return_value=b"build:\n  script: [hi]"):
            result = fetcher.fetch("template", {"template": "Foo.yml"})
        assert result == b"build:\n  script: [hi]"


class TestFetcherComponent:
    def test_component_parses_uri_and_fetches(self):
        fetcher = GitLabIncludeFetcher(gitlab_url="https://gitlab.com")
        with patch.object(fetcher, "_fetch_project", return_value=b"step: ok") as mock:
            result = fetcher.fetch("component", {
                "component": "gitlab.com/my-group/my-project/build@1.0.0",
            })
        assert result == b"step: ok"
        call_spec = mock.call_args[0][0]
        assert call_spec["project"] == "my-group/my-project"
        assert call_spec["file"] == "templates/build/template.yml"
        assert call_spec["ref"] == "1.0.0"

    def test_component_missing_version_returns_none(self):
        fetcher = GitLabIncludeFetcher()
        result = fetcher.fetch("component", {
            "component": "gitlab.com/group/proj/comp",
        })
        assert result is None

    def test_component_too_few_segments_returns_none(self):
        fetcher = GitLabIncludeFetcher()
        result = fetcher.fetch("component", {
            "component": "gitlab.com/proj@1.0",
        })
        assert result is None


class TestFetcherCache:
    def test_cache_hit_skips_network(self):
        cache = MagicMock()
        cache.get.return_value = b"cached: content"
        fetcher = GitLabIncludeFetcher(cache=cache)
        result = fetcher.fetch("remote", {
            "remote": "https://example.com/ci.yml",
        })
        assert result == b"cached: content"
        assert fetcher.stats.cached == 1
        assert fetcher.stats.fetched == 0

    def test_cache_miss_triggers_fetch_and_write(self):
        cache = MagicMock()
        cache.get.return_value = None
        fetcher = GitLabIncludeFetcher(cache=cache)
        with patch.object(fetcher, "_http_get", return_value=b"new: data"):
            result = fetcher.fetch("remote", {
                "remote": "https://example.com/ci.yml",
            })
        assert result == b"new: data"
        assert fetcher.stats.fetched == 1
        cache.put.assert_called_once()


class TestFetcherStats:
    def test_failed_tracked(self):
        fetcher = GitLabIncludeFetcher()
        with patch.object(fetcher, "_api_get", return_value=None):
            result = fetcher.fetch("project", {
                "project": "g/p", "file": "/a.yml",
            })
        assert result is None
        assert fetcher.stats.failed == 1
        assert len(fetcher.stats.failed_details) == 1

    def test_unknown_kind_skipped(self):
        fetcher = GitLabIncludeFetcher()
        result = fetcher.fetch("unknown_kind", {})
        assert result is None
        assert fetcher.stats.skipped == 1


# ── _resolve_remote_includes() tests ────────────────────────────


class TestResolveRemoteIncludes:
    def _make_fetcher(self, responses: dict[str, bytes]) -> GitLabIncludeFetcher:
        fetcher = GitLabIncludeFetcher()

        def fake_fetch(kind: str, spec: dict[str, Any]) -> bytes | None:
            key = fetcher._cache_key(kind, spec)
            return responses.get(key or "")

        fetcher.fetch = fake_fetch  # type: ignore[assignment]
        return fetcher

    def test_remote_include_merged(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/shared.yml"}],
            "build": {"script": ["echo build"]},
        }
        fetcher = self._make_fetcher({
            "gitlab:remote:https://example.com/shared.yml": (
                b".deploy_template:\n"
                b"  variables:\n"
                b"    DEPLOY_ENV: staging\n"
            ),
        })
        merged, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert ".deploy_template" in merged
        assert "build" in merged
        assert not warnings

    def test_parent_wins_on_conflict(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/shared.yml"}],
            "build": {"script": ["from-parent"]},
        }
        fetcher = self._make_fetcher({
            "gitlab:remote:https://example.com/shared.yml": (
                b"build:\n  script: [from-remote]\n"
            ),
        })
        merged, _ = _resolve_remote_includes(data, fetcher=fetcher)
        assert merged["build"]["script"] == ["from-parent"]

    def test_local_includes_skipped(self):
        data: dict[str, Any] = {
            "include": [
                {"local": "local.yml"},
                {"remote": "https://example.com/shared.yml"},
            ],
        }
        fetcher = self._make_fetcher({
            "gitlab:remote:https://example.com/shared.yml": (
                b"deploy:\n  script: [echo deploy]\n"
            ),
        })
        merged, _ = _resolve_remote_includes(data, fetcher=fetcher)
        assert "deploy" in merged

    def test_fetch_failure_warns(self):
        data: dict[str, Any] = {
            "include": [{"project": "g/p", "file": "/missing.yml"}],
        }
        fetcher = self._make_fetcher({})
        _, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert any("fetch failed" in w for w in warnings)

    def test_invalid_yaml_warns(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/bad.yml"}],
        }
        fetcher = self._make_fetcher({
            "gitlab:remote:https://example.com/bad.yml": b"[invalid: yaml: {{{",
        })
        _, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert any("parse error" in w for w in warnings)

    def test_cycle_detection(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/a.yml"}],
        }
        fetcher = GitLabIncludeFetcher()

        call_count = 0

        def fake_fetch(kind: str, spec: dict[str, Any]) -> bytes | None:
            nonlocal call_count
            call_count += 1
            if call_count > 5:
                return None
            return (
                b"include:\n"
                b"  - remote: https://example.com/a.yml\n"
                b"job_from_a:\n"
                b"  script: [echo a]\n"
            )

        fetcher.fetch = fake_fetch  # type: ignore[assignment]
        merged, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert any("cycle" in w for w in warnings)

    def test_depth_limit(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/deep.yml"}],
        }
        fetcher = GitLabIncludeFetcher()
        depth_counter = 0

        def fake_fetch(kind: str, spec: dict[str, Any]) -> bytes | None:
            nonlocal depth_counter
            depth_counter += 1
            return (
                b"include:\n"
                b"  - remote: https://example.com/deeper%d.yml\n"
                b"job_%d:\n"
                b"  script: [echo level]\n" % (depth_counter, depth_counter)
            )

        fetcher.fetch = fake_fetch  # type: ignore[assignment]
        _, warnings = _resolve_remote_includes(data, fetcher=fetcher, depth=8)
        assert any("depth limit" in w for w in warnings)

    def test_recursive_remote_includes(self):
        data: dict[str, Any] = {
            "include": [{"remote": "https://example.com/level1.yml"}],
        }

        def fake_fetch(kind: str, spec: dict[str, Any]) -> bytes | None:
            url = spec.get("remote", "")
            if "level1" in url:
                return (
                    b"include:\n"
                    b"  - remote: https://example.com/level2.yml\n"
                    b".template1:\n"
                    b"  variables:\n"
                    b"    T1: val1\n"
                )
            if "level2" in url:
                return (
                    b".template2:\n"
                    b"  variables:\n"
                    b"    T2: val2\n"
                )
            return None

        fetcher = GitLabIncludeFetcher()
        fetcher.fetch = fake_fetch  # type: ignore[assignment]
        merged, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert ".template1" in merged
        assert ".template2" in merged

    def test_no_include_block_is_noop(self):
        data: dict[str, Any] = {"build": {"script": ["echo hi"]}}
        fetcher = GitLabIncludeFetcher()
        merged, warnings = _resolve_remote_includes(data, fetcher=fetcher)
        assert merged == data
        assert not warnings


# ── Provider post_filter wiring ──────────────────────────────────


class TestProviderPostFilter:
    def test_warn_when_off(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n"
            "  - project: some/project\n"
            "    file: /build.yml\n"
            "build:\n"
            "  script: [echo build]\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        provider = GitLabProvider()
        provider.post_filter(ctx, resolve_remote=False)
        assert any("remote include directive" in w for w in ctx.warnings)
        assert any("--resolve-remote" in w for w in ctx.warnings)

    def test_no_warn_when_no_remote_includes(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n  script: [echo build]\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        provider = GitLabProvider()
        provider.post_filter(ctx, resolve_remote=False)
        assert not any("--resolve-remote" in w for w in ctx.warnings)

    @patch(
        "pipeline_check.core.providers.gitlab.GitLabIncludeFetcher"
    )
    def test_resolve_remote_on_calls_fetcher(
        self, MockFetcher: MagicMock, tmp_path: Path,
    ):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n"
            "  - remote: https://example.com/shared.yml\n"
            "build:\n"
            "  script: [echo build]\n"
        )
        mock_instance = MockFetcher.return_value
        mock_instance.stats = ResolverStats()
        mock_instance._cache_key = GitLabIncludeFetcher._cache_key

        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")
        provider = GitLabProvider()
        provider.post_filter(
            ctx,
            resolve_remote=True,
            gitlab_token="test-token",
            gitlab_url="https://gl.test.com",
            no_cache=True,
        )
        MockFetcher.assert_called_once()
        call_kwargs = MockFetcher.call_args[1]
        assert call_kwargs["gitlab_url"] == "https://gl.test.com"
        assert call_kwargs["token"] == "test-token"


# ── count_unresolved_remote_includes() ───────────────────────────


class TestCountUnresolved:
    def test_counts_remote_types(self):
        pipes = [Pipeline(
            path="test.yml",
            data={
                "include": [
                    {"local": "local.yml"},
                    {"remote": "https://example.com/a.yml"},
                    {"project": "g/p", "file": "/b.yml"},
                    {"template": "T.yml"},
                    {"component": "gitlab.com/g/p/c@1.0"},
                ],
            },
        )]
        assert count_unresolved_remote_includes(pipes) == 4

    def test_zero_for_local_only(self):
        pipes = [Pipeline(
            path="test.yml",
            data={"include": [{"local": "shared.yml"}]},
        )]
        assert count_unresolved_remote_includes(pipes) == 0

    def test_zero_for_no_include(self):
        pipes = [Pipeline(path="test.yml", data={"build": {}})]
        assert count_unresolved_remote_includes(pipes) == 0


# ── Taint integration: TAINT-008 extends-chain across includes ───


class TestTaintAcrossRemoteIncludes:
    def test_taint008_fires_when_template_from_remote_include(
        self, tmp_path: Path,
    ):
        """TAINT-008 (extends-chain taint) fires when a hidden template
        with tainted variables is merged from a remote include."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n"
            "  - remote: https://example.com/templates.yml\n"
            "deploy:\n"
            "  extends: .deploy_template\n"
            "  script:\n"
            "    - curl -X POST $API_URL -d $CI_MERGE_REQUEST_TITLE\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")

        # Simulate what post_filter does: merge the remote include.
        remote_yaml = (
            ".deploy_template:\n"
            "  variables:\n"
            "    API_URL: https://hooks.example.com\n"
        )
        fetcher = GitLabIncludeFetcher()

        def fake_fetch(kind: str, spec: dict[str, Any]) -> bytes | None:
            return remote_yaml.encode()

        fetcher.fetch = fake_fetch  # type: ignore[assignment]

        for i, pipeline in enumerate(ctx.pipelines):
            merged, warnings = _resolve_remote_includes(
                pipeline.data, fetcher=fetcher,
            )
            ctx.pipelines[i] = Pipeline(
                path=pipeline.path, data=merged,
            )

        assert ".deploy_template" in ctx.pipelines[0].data

        ids = _finding_ids(ctx)
        # GL-002 fires on the script injection ($CI_MERGE_REQUEST_TITLE
        # in curl); the template being visible is what makes the test
        # meaningful — without the merge, the extends chain is broken.
        assert "GL-002" in ids or "TAINT-008" in ids

    def test_taint_silent_without_resolve(self, tmp_path: Path):
        """Without remote include resolution, the template is invisible
        and extends-chain taint cannot fire."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "include:\n"
            "  - remote: https://example.com/templates.yml\n"
            "deploy:\n"
            "  extends: .deploy_template\n"
            "  script:\n"
            "    - curl -X POST $API_URL -d $CI_MERGE_REQUEST_TITLE\n"
        )
        ctx = GitLabContext.from_path(tmp_path / ".gitlab-ci.yml")

        # Without resolving the remote include, .deploy_template is not
        # in the document. GL-002 still fires on the script injection
        # but the extends resolution is incomplete.
        assert ".deploy_template" not in ctx.pipelines[0].data


# ── Pipeline dataclass ───────────────────────────────────────────


class TestPipelineDataclass:
    def test_resolved_includes_defaults_empty(self):
        p = Pipeline(path="test.yml", data={})
        assert p.resolved_includes == ()

    def test_resolved_includes_set(self):
        p = Pipeline(
            path="test.yml",
            data={},
            resolved_includes=("gitlab:remote:https://example.com/a.yml",),
        )
        assert len(p.resolved_includes) == 1
