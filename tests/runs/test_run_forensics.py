"""Tests for the run-history forensics provider (RUN-*).

Uses an in-memory fetcher (the same shape as the SCM ``FakeSCMFetcher``)
so the suite never touches the network or relies on disk fixtures (the
``?per_page=`` query in the run-list path is not a portable filename).
"""
from __future__ import annotations

import io
import zipfile
from typing import Any

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.runs.base import DEFAULT_RUN_LIMIT, RunsContext
from pipeline_check.core.checks.runs.checks import RunsChecks

_RUNS_PATH = f"repos/owner/r/actions/runs?per_page={DEFAULT_RUN_LIMIT}"
# A realistically-shaped (fake) leaked GitHub classic PAT: ghp_ + 36 chars.
_LEAKED_TOKEN = "ghp_016d8d1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"


class FakeFetcher:
    """In-memory ``path -> body`` map; anything else returns ``None``.

    ``blobs`` is the binary side (``fetch_bytes``) used for the run-logs
    ZIP endpoint; a fetcher without ``blobs`` still has ``fetch_bytes``
    so the duck-typed check in the context succeeds.
    """

    def __init__(
        self, mapping: dict[str, Any], blobs: dict[str, bytes] | None = None,
    ) -> None:
        self.mapping = mapping
        self.blobs = blobs or {}
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)

    def fetch_bytes(self, path: str, **_: Any) -> bytes | None:
        self.calls.append(path)
        return self.blobs.get(path)


def _log_zip(text: str, name: str = "1_build.txt") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, text)
    return buf.getvalue()


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


# ── RUN-003: leaked secret in run logs (--audit-runs-logs) ───────────────

class TestRun003LogScan:
    def _ctx_with_log(self, run: dict, log_text: str) -> RunsContext:
        payload = {"total_count": 1, "workflow_runs": [run]}
        blobs = {f"repos/owner/r/actions/runs/{run['id']}/logs": _log_zip(log_text)}
        return RunsContext.for_repo(
            "owner", "r", FakeFetcher({_RUNS_PATH: payload}, blobs),
            scan_logs=True,
        )

    def test_passes_with_skip_note_when_logs_not_scanned(self):
        # Default metadata-only run must not imply the logs were checked.
        ctx = _ctx(_run(1, "pull_request_target", fork=True))
        assert ctx.logs_scanned is False
        run003 = _for(_findings(ctx), "RUN-003")
        assert run003 and all(f.passed for f in run003)
        assert "not enabled" in run003[0].description

    def test_fires_on_leaked_secret_and_redacts(self):
        run = _run(1, "pull_request_target", fork=True)
        ctx = self._ctx_with_log(run, f"step\nexport T={_LEAKED_TOKEN}\nok\n")
        assert ctx.logs_scanned is True
        failing = [f for f in _for(_findings(ctx), "RUN-003") if not f.passed]
        assert len(failing) == 1
        f = failing[0]
        assert f.severity == Severity.HIGH
        assert "#run/1" in f.resource
        assert "github_token" in f.description
        # The raw secret value must never appear in output.
        assert _LEAKED_TOKEN not in f.description

    def test_passes_when_scanned_logs_are_clean(self):
        run = _run(1, "pull_request_target", fork=False)
        ctx = self._ctx_with_log(run, "step\nbuilding the project\nall good\n")
        run003 = _for(_findings(ctx), "RUN-003")
        assert run003 and all(f.passed for f in run003)
        assert "No secret-shaped" in run003[0].description

    def test_only_privileged_runs_have_logs_fetched(self):
        run = _run(1, "push")  # not a privileged trigger
        payload = {"total_count": 1, "workflow_runs": [run]}
        blobs = {"repos/owner/r/actions/runs/1/logs": _log_zip(f"T={_LEAKED_TOKEN}")}
        fetcher = FakeFetcher({_RUNS_PATH: payload}, blobs)
        ctx = RunsContext.for_repo("owner", "r", fetcher, scan_logs=True)
        assert not any("/logs" in c for c in fetcher.calls)
        assert ctx.log_leaks == {}

    def test_corrupt_zip_degrades_without_crashing(self):
        run = _run(1, "pull_request_target", fork=True)
        payload = {"total_count": 1, "workflow_runs": [run]}
        blobs = {"repos/owner/r/actions/runs/1/logs": b"this is not a zip file"}
        ctx = RunsContext.for_repo(
            "owner", "r", FakeFetcher({_RUNS_PATH: payload}, blobs),
            scan_logs=True,
        )
        assert ctx.log_leaks == {}  # corrupt archive -> no leaks, no raise

    def test_graceful_when_fetcher_cannot_download(self):
        # A fetcher without ``fetch_bytes`` (e.g. an offline fixture
        # fetcher) skips log scanning with a warning instead of crashing.
        class NoBytes:
            def fetch(self, path: str) -> Any:
                if "runs?per_page" in path:
                    return {"total_count": 1, "workflow_runs": [
                        _run(1, "pull_request_target", fork=True),
                    ]}
                return None

        ctx = RunsContext.for_repo("owner", "r", NoBytes(), scan_logs=True)
        assert ctx.logs_scanned is True
        assert ctx.log_leaks == {}
        assert any("cannot" in w for w in ctx.warnings)


# ── RUN-004: fork run minted a cloud OIDC token (--audit-runs-logs) ──────────

# A log line that exercises GitHub Actions OIDC token minting.
_OIDC_LOG = (
    "Run actions/github-script@v7\n"
    "Requesting token from https://token.actions.githubusercontent.com/...\n"
    "Assuming role via AssumeRoleWithWebIdentity\n"
)


class TestRun004ForkOidcMint:
    def _ctx_with_log(self, run: dict, log_text: str) -> RunsContext:
        payload = {"total_count": 1, "workflow_runs": [run]}
        blobs = {f"repos/owner/r/actions/runs/{run['id']}/logs": _log_zip(log_text)}
        return RunsContext.for_repo(
            "owner", "r", FakeFetcher({_RUNS_PATH: payload}, blobs),
            scan_logs=True,
        )

    def test_passes_with_skip_note_when_logs_not_scanned(self):
        ctx = _ctx(_run(1, "pull_request_target", fork=True))
        assert ctx.logs_scanned is False
        run004 = _for(_findings(ctx), "RUN-004")
        assert run004 and all(f.passed for f in run004)
        assert "not enabled" in run004[0].description

    def test_fires_on_fork_run_that_minted_oidc(self):
        run = _run(1, "pull_request_target", fork=True)
        ctx = self._ctx_with_log(run, _OIDC_LOG)
        assert ctx.oidc_mint_runs == {1}
        failing = [f for f in _for(_findings(ctx), "RUN-004") if not f.passed]
        assert len(failing) == 1
        f = failing[0]
        assert f.severity == Severity.HIGH
        assert "#run/1" in f.resource
        assert "OIDC" in f.description and "fork" in f.description.lower()

    def test_does_not_fire_on_non_fork_oidc_mint(self):
        # A trusted-branch privileged run using OIDC normally is not a finding.
        run = _run(1, "workflow_run", fork=False)
        ctx = self._ctx_with_log(run, _OIDC_LOG)
        assert ctx.oidc_mint_runs == {1}  # detected...
        run004 = _for(_findings(ctx), "RUN-004")
        assert run004 and all(f.passed for f in run004)  # ...but scoped to forks
        assert "No fork-originated run" in run004[0].description

    def test_passes_when_fork_run_did_not_mint_oidc(self):
        run = _run(1, "pull_request_target", fork=True)
        ctx = self._ctx_with_log(run, "step\nbuilding the project\nall good\n")
        assert ctx.oidc_mint_runs == set()
        run004 = _for(_findings(ctx), "RUN-004")
        assert run004 and all(f.passed for f in run004)

    def test_aws_and_gcp_markers_also_detected(self):
        for marker in ("AssumeRoleWithWebIdentity", "workloadIdentityPools",
                       "ACTIONS_ID_TOKEN_REQUEST_URL"):
            run = _run(1, "pull_request_target", fork=True)
            ctx = self._ctx_with_log(run, f"step\n{marker}\n")
            assert ctx.oidc_mint_runs == {1}, marker


# ── RUN-005: fork run on a self-hosted runner (--audit-runs-logs) ────────────

def _jobs(*label_lists: list[str]) -> dict:
    return {
        "total_count": len(label_lists),
        "jobs": [
            {"name": f"job{i}", "labels": labels}
            for i, labels in enumerate(label_lists)
        ],
    }


class TestRun005SelfHostedForkRun:
    def _ctx(self, run: dict, jobs: dict | None) -> RunsContext:
        mapping: dict = {_RUNS_PATH: {"total_count": 1, "workflow_runs": [run]}}
        if jobs is not None:
            mapping[f"repos/owner/r/actions/runs/{run['id']}/jobs"] = jobs
        return RunsContext.for_repo(
            "owner", "r", FakeFetcher(mapping), scan_logs=True,
        )

    def test_passes_with_skip_note_when_not_audited(self):
        # Default metadata-only run must not imply job runners were checked.
        ctx = _ctx(_run(1, "pull_request", fork=True))
        assert ctx.logs_scanned is False
        run005 = _for(_findings(ctx), "RUN-005")
        assert run005 and all(f.passed for f in run005)
        assert "not enabled" in run005[0].description

    def test_fires_on_fork_run_on_self_hosted_runner(self):
        # A plain (unprivileged) fork pull_request on a self-hosted runner:
        # untrusted code on your infra, independent of RUN-001's privileged set.
        run = _run(1, "pull_request", fork=True)
        ctx = self._ctx(run, _jobs(["self-hosted", "linux", "x64"]))
        assert ctx.self_hosted_runs == {1: "self-hosted, linux, x64"}
        failing = [f for f in _for(_findings(ctx), "RUN-005") if not f.passed]
        assert len(failing) == 1
        f = failing[0]
        assert f.severity == Severity.HIGH
        assert "#run/1" in f.resource
        assert "self-hosted" in f.description

    def test_does_not_fire_on_github_hosted_runner(self):
        run = _run(1, "pull_request", fork=True)
        ctx = self._ctx(run, _jobs(["ubuntu-latest"]))
        assert ctx.self_hosted_runs == {}
        run005 = _for(_findings(ctx), "RUN-005")
        assert run005 and all(f.passed for f in run005)
        assert "No fork-originated run" in run005[0].description

    def test_non_fork_run_jobs_not_fetched(self):
        run = _run(1, "push", fork=False)
        mapping = {
            _RUNS_PATH: {"total_count": 1, "workflow_runs": [run]},
            "repos/owner/r/actions/runs/1/jobs": _jobs(["self-hosted"]),
        }
        fetcher = FakeFetcher(mapping)
        ctx = RunsContext.for_repo("owner", "r", fetcher, scan_logs=True)
        assert not any("/jobs" in c for c in fetcher.calls)
        assert ctx.self_hosted_runs == {}

    def test_missing_jobs_payload_degrades_without_crashing(self):
        run = _run(1, "pull_request", fork=True)
        ctx = self._ctx(run, None)  # jobs endpoint returns None
        assert ctx.self_hosted_runs == {}
        run005 = _for(_findings(ctx), "RUN-005")
        assert run005 and all(f.passed for f in run005)
