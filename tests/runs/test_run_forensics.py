"""Tests for the run-history forensics provider (RUN-*).

Uses an in-memory fetcher (the same shape as the SCM ``FakeSCMFetcher``)
so the suite never touches the network or relies on disk fixtures (the
``?per_page=`` query in the run-list path is not a portable filename).
"""
from __future__ import annotations

from typing import Any

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.runs.base import DEFAULT_RUN_LIMIT, RunsContext
from pipeline_check.core.checks.runs.checks import RunsChecks

_RUNS_PATH = f"repos/owner/r/actions/runs?per_page={DEFAULT_RUN_LIMIT}"


class FakeFetcher:
    """In-memory ``path -> body`` map; anything else returns ``None``."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


def _run(rid: int, event: str, *, fork: bool = False, name: str = "ci") -> dict:
    head = "fork/r" if fork else "owner/r"
    return {
        "id": rid, "name": name, "event": event, "status": "completed",
        "conclusion": "success", "head_branch": "topic",
        "actor": {"login": "alice"},
        "head_repository": {"full_name": head, "fork": fork},
        "repository": {"full_name": "owner/r"}, "run_attempt": 1,
        "html_url": f"https://github.com/owner/r/actions/runs/{rid}",
        "created_at": "2026-01-01T00:00:00Z",
    }


def _ctx(*runs: dict, total: int | None = None) -> RunsContext:
    payload = {
        "total_count": total if total is not None else len(runs),
        "workflow_runs": list(runs),
    }
    return RunsContext.for_repo("owner", "r", FakeFetcher({_RUNS_PATH: payload}))


def _findings(ctx: RunsContext) -> list:
    return RunsChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


# ── Context load ─────────────────────────────────────────────────────────

class TestContextLoad:
    def test_parses_run_metadata(self):
        ctx = _ctx(_run(1, "push"))
        assert len(ctx.runs) == 1
        assert ctx.runs[0].event == "push"
        assert ctx.runs[0].run_id == 1

    def test_missing_payload_degrades_with_warning(self):
        # Fetcher returns None (no token / 404 / network error).
        ctx = RunsContext.for_repo("owner", "r", FakeFetcher({}))
        assert ctx.runs == []
        assert ctx.warnings and "could not fetch" in ctx.warnings[0]

    def test_fork_detected_via_flag(self):
        ctx = _ctx(_run(1, "pull_request_target", fork=True))
        assert ctx.runs[0].from_fork is True

    def test_fork_detected_via_fullname_mismatch(self):
        # ``fork`` flag absent but head repo differs from base.
        entry = _run(1, "pull_request_target", fork=False)
        entry["head_repository"] = {"full_name": "someone/else", "fork": False}
        ctx = _ctx(entry)
        assert ctx.runs[0].from_fork is True

    def test_truncation_warning_when_total_exceeds_fetched(self):
        ctx = _ctx(_run(1, "push"), total=500)
        assert any("most recent" in w for w in ctx.warnings)


# ── RUN-001: fork PR on a privileged trigger ─────────────────────────────

class TestRun001:
    def test_fires_on_fork_privileged_run(self):
        ctx = _ctx(_run(1, "pull_request_target", fork=True))
        failing = [f for f in _for(_findings(ctx), "RUN-001") if not f.passed]
        assert len(failing) == 1
        f = failing[0]
        assert f.severity == Severity.HIGH
        assert "#run/1" in f.resource
        assert "fork" in f.description.lower()

    def test_one_finding_per_offending_run(self):
        ctx = _ctx(
            _run(1, "pull_request_target", fork=True),
            _run(2, "workflow_run", fork=True),
        )
        failing = [f for f in _for(_findings(ctx), "RUN-001") if not f.passed]
        assert {f.resource for f in failing} == {
            "github:owner/r#run/1", "github:owner/r#run/2",
        }

    def test_passes_when_privileged_but_not_fork(self):
        ctx = _ctx(_run(1, "pull_request_target", fork=False))
        run001 = _for(_findings(ctx), "RUN-001")
        assert run001 and all(f.passed for f in run001)

    def test_passes_when_fork_but_unprivileged_trigger(self):
        # A normal fork ``pull_request`` runs in the fork's own context
        # with no base-repo secrets, so it is not RUN-001.
        ctx = _ctx(_run(1, "pull_request", fork=True))
        run001 = _for(_findings(ctx), "RUN-001")
        assert run001 and all(f.passed for f in run001)


# ── RUN-002: privileged trigger exercised ────────────────────────────────

class TestRun002:
    def test_fires_and_counts_by_event(self):
        ctx = _ctx(
            _run(1, "pull_request_target", fork=False),
            _run(2, "workflow_run", fork=False),
            _run(3, "push"),
        )
        failing = [f for f in _for(_findings(ctx), "RUN-002") if not f.passed]
        assert len(failing) == 1
        assert failing[0].severity == Severity.MEDIUM
        assert "pull_request_target=1" in failing[0].description
        assert "workflow_run=1" in failing[0].description

    def test_passes_when_no_privileged_triggers(self):
        ctx = _ctx(_run(1, "push"), _run(2, "pull_request"))
        run002 = _for(_findings(ctx), "RUN-002")
        assert run002 and all(f.passed for f in run002)


# ── Standards mapping ────────────────────────────────────────────────────

class TestControls:
    def test_run_rules_map_to_owasp_ppe(self):
        # Controls are attached by the Scanner via resolve_for_check (the
        # orchestrator only sets rule metadata), so verify the mapping at
        # the resolver the scanner uses.
        from pipeline_check.core.standards.registry import resolve_for_check
        for cid in ("RUN-001", "RUN-002"):
            controls = {c.control_id for c in resolve_for_check(cid)}
            assert "CICD-SEC-4" in controls, cid


# ── Provider wiring ──────────────────────────────────────────────────────

class TestProvider:
    def test_requires_scm_repo(self):
        from pipeline_check.core.providers.runs import RunsProvider
        with pytest.raises(ValueError, match="requires --scm-repo"):
            RunsProvider().build_context(scm_repo=None)

    def test_rejects_repo_without_slash(self):
        from pipeline_check.core.providers.runs import RunsProvider
        with pytest.raises(ValueError):
            RunsProvider().build_context(scm_repo="noslash")

    def test_registered_in_provider_registry(self):
        from pipeline_check.core import providers
        assert "runs" in providers.available()
        assert providers.get("runs").NAME == "runs"
