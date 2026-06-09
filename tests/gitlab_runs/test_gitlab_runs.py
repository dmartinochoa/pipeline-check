"""GLRUN-* GitLab run-forensics tests (in-memory fetcher, no network)."""
from __future__ import annotations

import urllib.parse
from typing import Any

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.gitlab_runs.base import (
    DEFAULT_PIPELINE_LIMIT,
    GitLabRunsContext,
)
from pipeline_check.core.checks.gitlab_runs.checks import GitLabRunsChecks

_PROJECT = "group/project"
_ENCODED = urllib.parse.quote(_PROJECT, safe="")
_PIPELINES_PATH = f"projects/{_ENCODED}/pipelines?per_page={DEFAULT_PIPELINE_LIMIT}"


class FakeFetcher:
    """In-memory ``path -> json`` map; anything else returns ``None``."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


def _pipeline(pid: int, source: str, *, ref: str = "topic") -> dict:
    return {
        "id": pid, "status": "success", "ref": ref,
        "sha": "0" * 40, "source": source,
        "web_url": f"https://gitlab.com/group/project/-/pipelines/{pid}",
        "created_at": "2026-01-01T00:00:00Z",
        "user": {"username": "alice"},
    }


def _ctx(*pipelines: dict) -> GitLabRunsContext:
    fetcher = FakeFetcher({_PIPELINES_PATH: list(pipelines)})
    return GitLabRunsContext.for_project(_PROJECT, fetcher)


def _findings(ctx: GitLabRunsContext) -> list:
    return GitLabRunsChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


# ── Context load ─────────────────────────────────────────────────────────

class TestContextLoad:
    def test_parses_pipeline_metadata(self):
        ctx = _ctx(_pipeline(1, "push"), _pipeline(2, "merge_request_event"))
        assert len(ctx.pipelines) == 2
        assert ctx.pipelines[1].from_merge_request is True
        assert ctx.pipelines[0].from_merge_request is False

    def test_missing_payload_degrades_with_warning(self):
        ctx = GitLabRunsContext.for_project(_PROJECT, FakeFetcher({}))
        assert ctx.pipelines == []
        assert any("could not fetch" in w for w in ctx.warnings)

    def test_non_list_payload_degrades(self):
        # GitLab error bodies are dicts ({"message": "404"}), not lists.
        ctx = GitLabRunsContext.for_project(
            _PROJECT, FakeFetcher({_PIPELINES_PATH: {"message": "404"}}),
        )
        assert ctx.pipelines == []
        assert ctx.warnings

    def test_project_is_url_encoded_in_fetch_path(self):
        fetcher = FakeFetcher({_PIPELINES_PATH: []})
        GitLabRunsContext.for_project(_PROJECT, fetcher)
        assert any("group%2Fproject" in c for c in fetcher.calls)


# ── GLRUN-001 ──────────────────────────────────────────────────────────────

class TestGLRun001:
    def test_fires_on_merge_request_pipeline(self):
        ctx = _ctx(_pipeline(1, "push"), _pipeline(2, "merge_request_event"))
        out = [f for f in _for(_findings(ctx), "GLRUN-001") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.MEDIUM
        assert "merge_request_event=1" in out[0].description

    def test_counts_external_pr_event_too(self):
        ctx = _ctx(
            _pipeline(1, "merge_request_event"),
            _pipeline(2, "external_pull_request_event"),
        )
        out = [f for f in _for(_findings(ctx), "GLRUN-001") if not f.passed]
        assert len(out) == 1
        assert "external_pull_request_event=1" in out[0].description

    def test_passes_when_no_merge_request_pipelines(self):
        ctx = _ctx(_pipeline(1, "push"), _pipeline(2, "schedule"))
        glrun = _for(_findings(ctx), "GLRUN-001")
        assert glrun and all(f.passed for f in glrun)
        assert "No merge-request pipelines" in glrun[0].description

    def test_passes_on_empty_history(self):
        ctx = _ctx()
        glrun = _for(_findings(ctx), "GLRUN-001")
        assert glrun and all(f.passed for f in glrun)


# ── Provider wiring ──────────────────────────────────────────────────────

class TestProvider:
    def test_requires_scm_repo(self):
        from pipeline_check.core.providers.gitlab_runs import GitLabRunsProvider
        with pytest.raises(ValueError, match="requires --scm-repo"):
            GitLabRunsProvider().build_context(scm_repo=None)

    def test_registered_in_provider_registry(self):
        from pipeline_check.core import providers
        assert "gitlab_runs" in providers.available()
        assert providers.get("gitlab_runs").NAME == "gitlab_runs"

    def test_owasp_mapping(self):
        from pipeline_check.core.standards.registry import resolve_for_check
        controls = {c.control_id for c in resolve_for_check("GLRUN-001")}
        assert "CICD-SEC-4" in controls

    def test_glrun002_owasp_mapping(self):
        from pipeline_check.core.standards.registry import resolve_for_check
        controls = {c.control_id for c in resolve_for_check("GLRUN-002")}
        assert "CICD-SEC-4" in controls


# ── GLRUN-002: fork-origin resolution (deep pass) ─────────────────────────

def _mrs_path() -> str:
    return (
        f"projects/{_ENCODED}/merge_requests"
        f"?per_page=100&order_by=updated_at&scope=all"
    )


def _mr(iid: int, *, fork: bool) -> dict:
    # A fork MR has a different source than target project.
    return {
        "iid": iid, "source_project_id": 99 if fork else 1,
        "target_project_id": 1,
    }


def _mr_pipelines_path(iid: int) -> str:
    return f"projects/{_ENCODED}/merge_requests/{iid}/pipelines"


def _ctx_forks(pipelines, mrs, mr_pipelines) -> GitLabRunsContext:
    mapping: dict[str, Any] = {_PIPELINES_PATH: list(pipelines)}
    mapping[_mrs_path()] = list(mrs)
    for iid, pls in mr_pipelines.items():
        mapping[_mr_pipelines_path(iid)] = list(pls)
    return GitLabRunsContext.for_project(
        _PROJECT, FakeFetcher(mapping), resolve_forks=True,
    )


class TestGLRun002:
    def test_skip_note_when_forks_not_resolved(self):
        ctx = _ctx(_pipeline(1, "merge_request_event"))
        assert ctx.forks_resolved is False
        glrun = _for(_findings(ctx), "GLRUN-002")
        assert glrun and all(f.passed for f in glrun)
        assert "not enabled" in glrun[0].description

    def test_fires_on_fork_mr_pipeline(self):
        ctx = _ctx_forks(
            [_pipeline(1, "merge_request_event")],
            [_mr(7, fork=True)],
            {7: [_pipeline(50, "merge_request_event", ref="refs/merge-requests/7/head")]},
        )
        assert ctx.forks_resolved is True
        failing = [f for f in _for(_findings(ctx), "GLRUN-002") if not f.passed]
        assert len(failing) == 1
        assert failing[0].severity == Severity.HIGH
        assert "#pipeline/50" in failing[0].resource

    def test_passes_when_mrs_are_not_forks(self):
        ctx = _ctx_forks(
            [_pipeline(1, "merge_request_event")],
            [_mr(7, fork=False)],
            {},
        )
        glrun = _for(_findings(ctx), "GLRUN-002")
        assert glrun and all(f.passed for f in glrun)
        assert "No fork merge-request pipelines" in glrun[0].description

    def test_only_fork_mrs_pull_pipelines(self):
        ctx = _ctx_forks(
            [],
            [_mr(1, fork=False), _mr(2, fork=True)],
            {2: [_pipeline(60, "merge_request_event")]},
        )
        assert len(ctx.fork_pipelines) == 1
        assert ctx.fork_pipelines[0].pipeline_id == 60

    def test_missing_mr_list_degrades(self):
        # MR list endpoint returns nothing -> no forks, no crash.
        mapping = {_PIPELINES_PATH: [_pipeline(1, "merge_request_event")]}
        ctx = GitLabRunsContext.for_project(
            _PROJECT, FakeFetcher(mapping), resolve_forks=True,
        )
        assert ctx.forks_resolved is True
        assert ctx.fork_pipelines == []
