"""Unit tests for the SCM posture provider and rule pack.

Uses a :class:`FakeSCMFetcher` so the suite never touches the
network. The fetcher protocol is the seam that lets us swap an
HTTP client for an in-memory map.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.scm.base import (
    SCMContext,
    SCMRepoSnapshot,
)
from pipeline_check.core.checks.scm.posture import SCMPostureChecks


class FakeSCMFetcher:
    """In-memory fetcher: ``path -> body``. Anything not in the map
    returns ``None`` (which the context records as a warning and the
    rule pack reads as 'feature unavailable')."""

    def __init__(self, mapping: dict[str, dict[str, Any] | list[Any]]):
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> dict[str, Any] | list[Any] | None:
        self.calls.append(path)
        return self.mapping.get(path)


def _findings(snapshot: SCMRepoSnapshot) -> list[Any]:
    return SCMPostureChecks(SCMContext(repos=[snapshot])).run()


def _by_id(findings: list[Any], check_id: str) -> Any:
    return next(f for f in findings if f.check_id == check_id)


# ── SCM-001: branch protection presence ─────────────────────────────


class TestSCM001:
    def test_missing_protection_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-001")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "no protection rule" in f.description

    def test_present_protection_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-001")
        assert f.passed

    def test_resource_uses_repo_handle(self):
        snap = SCMRepoSnapshot(owner="octocat", name="hello-world")
        f = _by_id(_findings(snap), "SCM-001")
        assert f.resource == "github:octocat/hello-world"


# ── SCM-002: required reviews ───────────────────────────────────────


class TestSCM002:
    def test_zero_required_reviews_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-002")
        assert not f.passed
        assert "does not require" in f.description

    def test_at_least_one_review_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-002")
        assert f.passed
        assert "2 approving review" in f.description

    def test_no_protection_at_all_passes_silently(self):
        """SCM-001 owns the no-protection-rule case; SCM-002 should
        not double-report."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-002")
        assert f.passed
        assert "See SCM-001" in f.description

    def test_missing_required_pull_request_reviews_block_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_status_checks": {"strict": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-002")
        assert not f.passed


# ── SCM-003: code scanning enabled ──────────────────────────────────


class TestSCM003:
    def test_disabled_default_setup_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={"state": "not-configured"},
        )
        f = _by_id(_findings(snap), "SCM-003")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_unavailable_endpoint_fails(self):
        """A 404 / 403 lands as ``code_scanning_default_setup=None``
        which the rule treats as 'not configured'."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup=None,
        )
        f = _by_id(_findings(snap), "SCM-003")
        assert not f.passed
        assert "unavailable" in f.description

    def test_configured_state_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={"state": "configured"},
        )
        f = _by_id(_findings(snap), "SCM-003")
        assert f.passed


# ── Context hydration ───────────────────────────────────────────────


class TestSCMContextHydration:
    def test_for_repo_calls_expected_endpoints(self):
        fetcher = FakeSCMFetcher({
            "repos/octocat/hello-world": {"default_branch": "main"},
            "repos/octocat/hello-world/branches/main/protection": {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
            "repos/octocat/hello-world/code-scanning/default-setup": {
                "state": "configured",
            },
        })
        ctx = SCMContext.for_repo("octocat", "hello-world", fetcher)
        assert len(ctx.repos) == 1
        snap = ctx.repos[0]
        assert snap.repo_meta == {"default_branch": "main"}
        assert isinstance(snap.default_branch_protection, dict)
        assert isinstance(snap.code_scanning_default_setup, dict)
        # All three endpoints hit.
        assert "repos/octocat/hello-world" in fetcher.calls
        assert any(
            c.endswith("/branches/main/protection") for c in fetcher.calls
        )

    def test_meta_failure_records_warning_keeps_going(self):
        # Empty map: every fetch returns None.
        ctx = SCMContext.for_repo("o", "r", FakeSCMFetcher({}))
        assert ctx.repos[0].repo_meta is None
        assert any("could not fetch" in w for w in ctx.warnings)

    def test_uses_main_when_default_branch_missing(self):
        """A token with limited scopes can return repo_meta without
        ``default_branch``; the context falls back to 'main' so the
        protection probe still has an endpoint to hit."""
        fetcher = FakeSCMFetcher({
            "repos/o/r": {},
            "repos/o/r/branches/main/protection": {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].default_branch_protection is not None


# ── Provider integration ────────────────────────────────────────────


class TestSCMProvider:
    def test_provider_registered(self):
        from pipeline_check.core.providers import get
        assert get("scm") is not None

    def test_build_context_validates_repo_format(self):
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        with pytest.raises(ValueError, match="owner/name"):
            SCMProvider().build_context(
                scm_platform="github", scm_repo="invalid",
            )

    def test_build_context_rejects_unsupported_platform(self):
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        with pytest.raises(ValueError, match="Unsupported"):
            SCMProvider().build_context(
                scm_platform="bitbucket", scm_repo="o/r",
            )

    def test_inventory_emits_repo_component(self):
        from pipeline_check.core.providers.scm import SCMProvider
        snap = SCMRepoSnapshot(
            owner="octocat", name="hello-world",
            repo_meta={"default_branch": "main", "private": False,
                       "visibility": "public"},
            default_branch_protection={"x": 1},
            code_scanning_default_setup={"state": "configured"},
        )
        ctx = SCMContext(repos=[snap])
        items = SCMProvider().inventory(ctx)
        assert len(items) == 1
        assert items[0].type == "scm_repository"
        assert items[0].identifier == "octocat/hello-world"
        assert items[0].metadata["branch_protection_enabled"] is True
        assert items[0].metadata["code_scanning_default_enabled"] is True
