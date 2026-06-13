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


# ── SCM-002 exploit_example backfill ────────────────────────────────


class TestSCM002Backfill:
    def test_carries_exploit_example_from_rule(self):
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
        assert f.exploit_example is not None
        assert "self-approve" in f.exploit_example


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


# ── SCM-004: secret scanning ────────────────────────────────────────


class TestSCM004:
    def test_enabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-004")
        assert f.passed

    def test_disabled_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "disabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-004")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_missing_block_fails_with_scope_note(self):
        """Token without admin scope → security_and_analysis omitted.
        Rule fails but the description hints at the scope-omission
        case so the user can distinguish it from a real disable."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
        )
        f = _by_id(_findings(snap), "SCM-004")
        assert not f.passed
        assert "admin" in f.description.lower()


# ── SCM-005: Dependabot security updates ────────────────────────────


class TestSCM005:
    def test_enabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "dependabot_security_updates": {"status": "enabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-005")
        assert f.passed

    def test_disabled_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "dependabot_security_updates": {"status": "disabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-005")
        assert not f.passed
        assert f.severity == Severity.MEDIUM


# ── SCM-006: signed commits ─────────────────────────────────────────


class TestSCM006:
    def test_required_signatures_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_signatures": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-006")
        assert f.passed

    def test_unsigned_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_signatures": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-006")
        assert not f.passed

    def test_missing_field_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={},
        )
        f = _by_id(_findings(snap), "SCM-006")
        assert not f.passed

    def test_no_protection_passes_silently(self):
        """SCM-001 owns the no-protection-rule case."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-006")
        assert f.passed
        assert "See SCM-001" in f.description


# ── SCM-007: force-push allowed ─────────────────────────────────────


class TestSCM007:
    def test_force_push_blocked_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "allow_force_pushes": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-007")
        assert f.passed

    def test_force_push_allowed_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "allow_force_pushes": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-007")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_no_protection_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-007")
        assert f.passed


# ── SCM-008: required status checks ─────────────────────────────────


class TestSCM008:
    def test_with_contexts_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["build", "test"],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-008")
        assert f.passed
        assert "build" in f.description

    def test_with_new_checks_shape_passes(self):
        """GitHub's newer ``checks`` shape (per-check app id) should
        also count as a required-status-check signal."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_status_checks": {
                    "strict": False,
                    "checks": [
                        {"context": "build", "app_id": 42},
                        {"context": "scan", "app_id": 99},
                    ],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-008")
        assert f.passed

    def test_empty_contexts_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_status_checks": {"strict": False, "contexts": []},
            },
        )
        f = _by_id(_findings(snap), "SCM-008")
        assert not f.passed

    def test_missing_block_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={},
        )
        f = _by_id(_findings(snap), "SCM-008")
        assert not f.passed


# ── SCM-009: deletions allowed ──────────────────────────────────────


class TestSCM009:
    def test_deletions_blocked_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "allow_deletions": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-009")
        assert f.passed

    def test_deletions_allowed_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "allow_deletions": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-009")
        assert not f.passed
        assert f.severity == Severity.HIGH


# ── SCM-010: admin bypass ───────────────────────────────────────────


class TestSCM010:
    def test_enforce_admins_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "enforce_admins": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-010")
        assert f.passed

    def test_admin_bypass_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "enforce_admins": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-010")
        assert not f.passed
        assert "advisory" in f.description.lower()

    def test_legacy_bool_shape_supported(self):
        """Older API responses (and hand-written fixtures) sometimes
        carry ``enforce_admins: true`` as a bare boolean instead of
        the nested ``{"enabled": true}`` shape."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={"enforce_admins": True},
        )
        f = _by_id(_findings(snap), "SCM-010")
        assert f.passed


# ── SCM-011: CODEOWNERS reviews ─────────────────────────────────────


class TestSCM011:
    def test_required_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "require_code_owner_reviews": True,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-011")
        assert f.passed

    def test_not_required_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "require_code_owner_reviews": False,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-011")
        assert not f.passed

    def test_no_protection_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-011")
        assert f.passed
        assert "See SCM-001" in f.description


# ── SCM-012: stale review dismissal ─────────────────────────────────


class TestSCM012:
    def test_dismiss_stale_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": True,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-012")
        assert f.passed

    def test_keep_stale_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": False,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-012")
        assert not f.passed
        assert "force-push" in f.description.lower()


# ── SCM-013: conversation resolution ────────────────────────────────


class TestSCM013:
    def test_required_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_conversation_resolution": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-013")
        assert f.passed

    def test_not_required_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_conversation_resolution": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-013")
        assert not f.passed
        assert f.severity == Severity.LOW


# ── SCM-014: last-push approval ─────────────────────────────────────


class TestSCM014:
    def test_required_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "require_last_push_approval": True,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-014")
        assert f.passed

    def test_not_required_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "require_last_push_approval": False,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-014")
        assert not f.passed


# ── SCM-015: secret-scanning push protection ────────────────────────


class TestSCM015:
    def test_enabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-015")
        assert f.passed

    def test_disabled_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning_push_protection": {"status": "disabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-015")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_missing_block_fails_with_scope_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
        )
        f = _by_id(_findings(snap), "SCM-015")
        assert not f.passed
        assert "admin" in f.description.lower()


# ── SCM-016: private vulnerability reporting ────────────────────────


class TestSCM016:
    def test_enabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "private_vulnerability_reporting": {"status": "enabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-016")
        assert f.passed

    def test_disabled_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "security_and_analysis": {
                    "private_vulnerability_reporting": {"status": "disabled"},
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-016")
        assert not f.passed
        assert f.severity == Severity.LOW


# ── SCM-017: CODEOWNERS file presence ───────────────────────────────


class TestSCM017:
    def test_present_at_github_dir_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            codeowners_path=".github/CODEOWNERS",
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed
        assert ".github/CODEOWNERS" in f.description

    def test_present_at_root_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            codeowners_path="CODEOWNERS",
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed

    def test_present_at_docs_dir_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            codeowners_path="docs/CODEOWNERS",
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed

    def test_absent_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            codeowners_path=None,
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert not f.passed
        assert f.severity == Severity.MEDIUM
        assert "CODEOWNERS" in f.description

    def test_empty_repo_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 0},
            default_branch_protection=None,
            codeowners_path=None,
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed
        assert "empty" in f.description.lower()

    def test_archived_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main", "size": 1024, "archived": True,
            },
            codeowners_path=None,
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed

    def test_meta_unavailable_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta=None,
            codeowners_path=None,
        )
        f = _by_id(_findings(snap), "SCM-017")
        assert f.passed
        assert "unavailable" in f.description.lower()


# ── SCM-018: PR review bypass allowance ─────────────────────────────


class TestSCM018:
    def test_no_bypass_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {
                        "users": [], "teams": [], "apps": [],
                    },
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert f.passed
        assert f.severity == Severity.MEDIUM

    def test_users_in_bypass_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {
                        "users": [{"login": "alice"}],
                        "teams": [], "apps": [],
                    },
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert not f.passed
        assert "1 user(s)" in f.description

    def test_teams_and_apps_in_bypass_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "bypass_pull_request_allowances": {
                        "users": [],
                        "teams": [{"slug": "ops"}, {"slug": "release"}],
                        "apps": [{"slug": "renovate"}],
                    },
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert not f.passed
        assert "2 team(s)" in f.description
        assert "1 app(s)" in f.description

    def test_missing_bypass_block_passes(self):
        """A protection rule without the bypass field at all is the
        default GitHub posture (no bypass list); pass silently."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert f.passed

    def test_no_protection_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert f.passed
        assert "See SCM-001" in f.description

    def test_no_required_reviews_block_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_status_checks": {"strict": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert f.passed
        assert "See SCM-002" in f.description

    def test_malformed_bypass_payload_doesnt_crash(self):
        """``bypass_pull_request_allowances`` value is a string
        instead of a dict (malformed API response). Rule should
        pass silently rather than raise; this is the FP/FN guard
        pattern shared by the rest of the SCM pack."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": "malformed",
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert f.passed

    def test_non_list_user_slot_treated_as_empty(self):
        """``users`` value isn't a list (could be ``null`` or a
        dict on malformed responses). Treat as zero, don't crash."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "bypass_pull_request_allowances": {
                        "users": None,
                        "teams": "not-a-list",
                        "apps": [{"slug": "ok-bot"}],
                    },
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-018")
        assert not f.passed
        assert "1 app(s)" in f.description
        # The malformed user / teams slots don't crash and don't
        # appear in the count.
        assert "user(s)" not in f.description
        assert "team(s)" not in f.description


# ── SCM-019: push restrictions allowlist (individual users) ─────────


class TestSCM019:
    def test_no_restrictions_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert f.passed
        assert "no push-restriction" in f.description.lower()

    def test_teams_and_apps_only_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "restrictions": {
                    "users": [],
                    "teams": [{"slug": "ops"}],
                    "apps": [{"slug": "release-bot"}],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert f.passed
        assert "teams / apps only" in f.description

    def test_individual_users_fail(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "restrictions": {
                    "users": [{"login": "alice"}, {"login": "bob"}],
                    "teams": [], "apps": [],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert not f.passed
        assert f.severity == Severity.LOW
        assert "@alice" in f.description
        assert "@bob" in f.description

    def test_large_user_list_truncates(self):
        users = [{"login": f"u{i}"} for i in range(10)]
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "restrictions": {
                    "users": users, "teams": [], "apps": [],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert not f.passed
        assert "10 individual user(s)" in f.description
        assert "+5 more" in f.description

    def test_bare_string_user_entries_accepted(self):
        """Fixture writers sometimes shortcut a user entry to a bare
        login string; the rule should handle that the same way."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "restrictions": {
                    "users": ["alice"],
                    "teams": [], "apps": [],
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert not f.passed
        assert "@alice" in f.description

    def test_no_protection_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-019")
        assert f.passed
        assert "See SCM-001" in f.description


# ── security_feature_state helper ───────────────────────────────────


class TestSecurityFeatureState:
    def test_returns_status_when_present(self):
        from pipeline_check.core.checks.scm.base import (
            security_feature_state,
        )
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                },
            },
        )
        assert security_feature_state(snap, "secret_scanning") == "enabled"

    def test_none_when_block_missing(self):
        from pipeline_check.core.checks.scm.base import (
            security_feature_state,
        )
        snap = SCMRepoSnapshot(owner="o", name="r", repo_meta={})
        assert security_feature_state(snap, "secret_scanning") is None

    def test_none_when_meta_missing(self):
        from pipeline_check.core.checks.scm.base import (
            security_feature_state,
        )
        snap = SCMRepoSnapshot(owner="o", name="r", repo_meta=None)
        assert security_feature_state(snap, "secret_scanning") is None


# ── FP/FN regression: empty / archived / disabled / unavailable ─────


class TestEmptyRepoFPGuard:
    """A brand-new repo with no commits has no default branch to
    protect. Without the empty-repo guard, every branch-protection
    rule (SCM-001 + cascades) fires misleadingly."""

    def test_scm001_passes_on_empty_repo(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 0},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-001")
        assert f.passed
        assert "empty" in f.description.lower()

    def test_non_empty_repo_with_no_protection_still_fails_scm001(self):
        """Sanity: the empty-repo guard must not over-suppress.
        A repo with size > 0 (real commits) and no protection rule
        is the SCM-001 happy-path FAIL case."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-001")
        assert not f.passed

    def test_size_zero_with_protection_present_still_fires_normal_path(
        self,
    ):
        """The empty-repo guard requires both signals: size==0 AND
        no protection. A repo with a protection rule already in
        place isn't empty even if reported size is 0 (edge case
        with template repos)."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 0},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-001")
        assert f.passed  # has protection -> passes the original way


class TestArchivedRepoFPGuard:
    """GitHub auto-disables Dependabot, secret scanning, push
    protection, code scanning, and private vuln reporting on
    archived repos. Without the archived-repo guard, every
    security_and_analysis-driven rule FPs on every archived repo."""

    def _archived(self, **overrides: Any) -> SCMRepoSnapshot:
        meta: dict[str, Any] = {
            "default_branch": "main",
            "archived": True,
            "size": 100,
        }
        meta.update(overrides.pop("repo_meta_extra", {}))
        return SCMRepoSnapshot(owner="o", name="r", repo_meta=meta, **overrides)

    def test_scm003_skips_on_archived(self):
        f = _by_id(_findings(self._archived()), "SCM-003")
        assert f.passed
        assert "archived" in f.description.lower()

    def test_scm004_skips_on_archived(self):
        f = _by_id(_findings(self._archived()), "SCM-004")
        assert f.passed
        assert "archived" in f.description.lower()

    def test_scm005_skips_on_archived(self):
        f = _by_id(_findings(self._archived()), "SCM-005")
        assert f.passed
        assert "archived" in f.description.lower()

    def test_scm015_skips_on_archived(self):
        f = _by_id(_findings(self._archived()), "SCM-015")
        assert f.passed

    def test_scm016_skips_on_archived(self):
        f = _by_id(_findings(self._archived()), "SCM-016")
        assert f.passed

    def test_branch_protection_rules_still_evaluate_on_archived(self):
        """Branch-protection rules (SCM-001/002/006/...) still
        evaluate on archived repos — the audit-trail signal stays
        meaningful even when the repo is read-only."""
        snap = self._archived(default_branch_protection=None)
        f = _by_id(_findings(snap), "SCM-001")
        # SCM-001 still fires if there's no protection rule, even
        # though the repo is archived.
        assert not f.passed


class TestDisabledRepoFPGuard:
    """Same skip behavior as archived for security_and_analysis
    rules — disabled repos are inaccessible and feature state is
    moot."""

    def test_scm005_skips_on_disabled(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "disabled": True, "size": 100},
        )
        f = _by_id(_findings(snap), "SCM-005")
        assert f.passed
        assert "disabled" in f.description.lower()


class TestRepoMetaUnavailableFPGuard:
    """When the repo metadata fetch itself failed, downstream
    probes can't resolve the default branch name. The for_repo
    helper now skips the protection probe entirely; SCM-001 emits
    a passed-with-explanation finding so the user sees the
    metadata gap rather than a false 'no protection rule' fail."""

    def test_for_repo_skips_protection_probe_when_meta_fails(self):
        # FakeFetcher returns None for the repo-meta call (no entry
        # in the mapping) and would also return None for protection
        # if probed; the test asserts the probe was NOT made.
        fetcher = FakeSCMFetcher({})
        ctx = SCMContext.for_repo("o", "r", fetcher)
        # Only the meta call should have hit the fetcher.
        assert fetcher.calls == ["repos/o/r"]
        assert ctx.repos[0].repo_meta is None
        assert ctx.repos[0].default_branch_protection is None

    def test_scm001_passes_with_unavailable_note_when_meta_missing(self):
        snap = SCMRepoSnapshot(owner="o", name="r", repo_meta=None)
        f = _by_id(_findings(snap), "SCM-001")
        assert f.passed
        assert "unavailable" in f.description.lower()

    def test_unknown_default_branch_name_doesnt_fp_protection_check(self):
        """End-to-end: a repo whose default branch is ``trunk`` (not
        ``main``) and whose meta fetch failed should NOT cause
        SCM-001 to FP by probing ``branches/main/protection``. The
        for_repo flow now skips the probe entirely."""
        # Simulate: meta fetch fails, but main/protection would
        # succeed if probed. Verify the snapshot's protection field
        # ends up None (no probe), not the bogus "main" data.
        fetcher = FakeSCMFetcher({
            "repos/o/r/branches/main/protection": {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 99,
                },
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        # Meta call was attempted and failed; main/protection was
        # NOT attempted because we don't know the default branch.
        assert "repos/o/r/branches/main/protection" not in fetcher.calls
        assert ctx.repos[0].default_branch_protection is None


# ── Standards mapping integration ───────────────────────────────────


class TestStandardsMapping:
    def test_scm_rules_map_to_cis_supply_chain(self):
        from pipeline_check.core.standards import resolve_for_check
        for cid in ("SCM-001", "SCM-002", "SCM-003", "SCM-004",
                    "SCM-005", "SCM-006", "SCM-007", "SCM-008",
                    "SCM-009", "SCM-010", "SCM-011", "SCM-012",
                    "SCM-013", "SCM-014", "SCM-015", "SCM-016",
                    "SCM-017", "SCM-018", "SCM-019"):
            stds = {r.standard for r in resolve_for_check(cid)}
            assert "cis_supply_chain" in stds, (
                f"{cid} missing cis_supply_chain mapping"
            )

    def test_scm_rules_map_to_openssf_scorecard(self):
        from pipeline_check.core.standards import resolve_for_check
        # SCM-004 (secret scanning), SCM-015 (push protection),
        # SCM-016 (private vuln reporting), SCM-018 (bypass list) and
        # SCM-019 (push-restriction allowlist) have no direct
        # Scorecard equivalents; SCM-017 maps to Code-Review (the
        # CODEOWNERS-file signal is one of Scorecard's evidences).
        for cid in ("SCM-001", "SCM-002", "SCM-003", "SCM-005",
                    "SCM-006", "SCM-007", "SCM-008", "SCM-009",
                    "SCM-010", "SCM-011", "SCM-012", "SCM-013",
                    "SCM-014", "SCM-017"):
            stds = {r.standard for r in resolve_for_check(cid)}
            assert "openssf_scorecard" in stds, (
                f"{cid} missing openssf_scorecard mapping"
            )


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

    def test_for_repo_probes_codeowners_locations(self):
        """The hydration flow probes the three canonical CODEOWNERS
        paths and records the first hit on the snapshot."""
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/contents/.github/CODEOWNERS": {
                "type": "file", "name": "CODEOWNERS",
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].codeowners_path == ".github/CODEOWNERS"

    def test_for_repo_falls_through_to_root_codeowners(self):
        """When ``.github/CODEOWNERS`` is absent the probe continues
        to ``CODEOWNERS`` at the repo root."""
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/contents/CODEOWNERS": {
                "type": "file", "name": "CODEOWNERS",
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].codeowners_path == "CODEOWNERS"

    def test_for_repo_falls_through_to_docs_codeowners(self):
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/contents/docs/CODEOWNERS": {
                "type": "file", "name": "CODEOWNERS",
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].codeowners_path == "docs/CODEOWNERS"

    def test_for_repo_codeowners_none_when_all_paths_404(self):
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].codeowners_path is None
        # All three were probed.
        for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            assert f"repos/o/r/contents/{p}" in fetcher.calls

    def test_for_repo_codeowners_ignored_when_not_a_file(self):
        """A 200 response with ``type != "file"`` (e.g., directory
        listing) should not count as a CODEOWNERS file."""
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/contents/.github/CODEOWNERS": {"type": "dir"},
            "repos/o/r/contents/CODEOWNERS": {
                "type": "file", "name": "CODEOWNERS",
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert ctx.repos[0].codeowners_path == "CODEOWNERS"

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


# ── Whole-pack integration sweeps ───────────────────────────────────


class TestWholePackBehavior:
    """End-to-end integration sweeps: run every SCM rule against
    representative snapshots and assert the global pass/fail
    pattern. Catches drift where a new rule lands without
    contributing to the cascade or where a guard incorrectly
    cross-suppresses unrelated rules."""

    def test_fully_locked_down_snapshot_passes_everything(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "size": 1024,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                    "dependabot_security_updates": {"status": "enabled"},
                    "private_vulnerability_reporting": {"status": "enabled"},
                },
            },
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                    "require_code_owner_reviews": True,
                    "dismiss_stale_reviews": True,
                    "require_last_push_approval": True,
                },
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["build", "scan"],
                },
                "required_signatures": {"enabled": True},
                "required_conversation_resolution": {"enabled": True},
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            },
            code_scanning_default_setup={
                "state": "configured",
                "query_suite": "extended",
                "schedule": "weekly",
                "languages": ["python"],
            },
            codeowners_path=".github/CODEOWNERS",
            repo_languages={"Python": 100000},
        )
        findings = _findings(snap)
        failures = [f.check_id for f in findings if not f.passed]
        assert failures == [], (
            f"Fully-locked snapshot should pass every rule, but "
            f"these failed: {failures}"
        )

    def test_fully_unprotected_snapshot_fires_only_top_level_rules(
        self,
    ):
        """When SCM-001 fires, the cascade rules (SCM-002, -006, -007,
        -008, -009, -010, -011, -012, -013, -014) should pass silently
        with the 'see SCM-001' deferral. Without that, a single root
        cause produces ~10 duplicate failures."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 1024},
            default_branch_protection=None,
            code_scanning_default_setup=None,
        )
        findings = _findings(snap)
        failures = sorted(f.check_id for f in findings if not f.passed)
        # Branch-protection root cause + the 5 security-feature
        # rules that are independent of branch protection +
        # SCM-017 (CODEOWNERS file presence, independent of
        # protection).
        assert failures == [
            "SCM-001", "SCM-003", "SCM-004", "SCM-005",
            "SCM-015", "SCM-016", "SCM-017",
        ]

    def test_archived_snapshot_only_branch_protection_fires(self):
        """Archived repos auto-disable security_and_analysis features;
        only branch-protection rules should produce failures."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main", "archived": True, "size": 1024,
            },
            default_branch_protection=None,
        )
        findings = _findings(snap)
        failures = sorted(f.check_id for f in findings if not f.passed)
        # SCM-001 still fires (audit-trail signal); the security
        # feature rules (SCM-003/4/5/15/16) skip with archived note.
        assert failures == ["SCM-001"]

    def test_empty_repo_passes_everything(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "size": 0},
            default_branch_protection=None,
            code_scanning_default_setup=None,
        )
        findings = _findings(snap)
        # Empty repo has nothing to scan; security-feature rules
        # may still fire (a fresh repo can have secret scanning
        # enabled before the first commit), but branch-protection
        # rules pass via the empty-repo / cascade guards.
        protection_failures = [
            f.check_id for f in findings
            if not f.passed
            and f.check_id in {
                "SCM-001", "SCM-002", "SCM-006", "SCM-007", "SCM-008",
                "SCM-009", "SCM-010", "SCM-011", "SCM-012", "SCM-013",
                "SCM-014",
            }
        ]
        assert protection_failures == []

    def test_meta_unavailable_passes_all_protection_rules(self):
        """When repo metadata fetch failed, every branch-protection
        rule passes with a 'see SCM-001' or 'unavailable' note. This
        catches the FN where a token-scope failure looks like a
        clean repo."""
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta=None,
        )
        findings = _findings(snap)
        protection_ids = {
            "SCM-001", "SCM-002", "SCM-006", "SCM-007", "SCM-008",
            "SCM-009", "SCM-010", "SCM-011", "SCM-012", "SCM-013",
            "SCM-014",
        }
        protection_failures = [
            f.check_id for f in findings
            if not f.passed and f.check_id in protection_ids
        ]
        assert protection_failures == []

    def test_no_archived_label_leaks_into_unrelated_rules(self):
        """The archived guard should only suppress the security-
        feature rules; SCM-002 / -011 / -012 / -014 (review knobs
        on an existing protection rule) should still evaluate
        normally on an archived repo with a protection rule."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main", "archived": True, "size": 1024,
            },
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews": False,
                },
            },
        )
        findings = _findings(snap)
        # SCM-002 still fires (zero required reviews) on archived.
        scm002 = _by_id(findings, "SCM-002")
        assert not scm002.passed
        scm012 = _by_id(findings, "SCM-012")
        assert not scm012.passed


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
        """Unknown platform names still trip the explicit error. GitHub
        / GitLab / Bitbucket are all supported now; anything else
        falls through."""
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        with pytest.raises(ValueError, match="Unsupported"):
            SCMProvider().build_context(
                scm_platform="hg-cloud", scm_repo="o/r",
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


# ── SCM-020: default workflow token has write ──────────────────────


class TestSCM020:
    def test_write_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions={
                "default_workflow_permissions": "write",
                "can_approve_pull_request_reviews": False,
            },
        )
        f = _by_id(_findings(snap), "SCM-020")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_read_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions={
                "default_workflow_permissions": "read",
            },
        )
        f = _by_id(_findings(snap), "SCM-020")
        assert f.passed

    def test_missing_endpoint_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions=None,
        )
        f = _by_id(_findings(snap), "SCM-020")
        assert f.passed
        assert "admin" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            actions_workflow_permissions=None,
        )
        f = _by_id(_findings(snap), "SCM-020")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_repo_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            actions_workflow_permissions={
                "default_workflow_permissions": "write",
            },
        )
        f = _by_id(_findings(snap), "SCM-020")
        assert f.passed
        assert "archived" in f.description


# ── SCM-021: actions can self-approve PRs ──────────────────────────


class TestSCM021:
    def test_self_approval_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions={
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-021")
        assert not f.passed

    def test_no_self_approval_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions={
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
        )
        f = _by_id(_findings(snap), "SCM-021")
        assert f.passed

    def test_missing_field_passes(self):
        # ``can_approve_pull_request_reviews`` absent is treated as
        # not-enabled (GitHub's default).
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_workflow_permissions={
                "default_workflow_permissions": "read",
            },
        )
        f = _by_id(_findings(snap), "SCM-021")
        assert f.passed


# ── SCM-022: allowed_actions = all ─────────────────────────────────


class TestSCM022:
    def test_all_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_permissions={
                "enabled": True,
                "allowed_actions": "all",
            },
        )
        f = _by_id(_findings(snap), "SCM-022")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_selected_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_permissions={
                "enabled": True,
                "allowed_actions": "selected",
            },
        )
        f = _by_id(_findings(snap), "SCM-022")
        assert f.passed

    def test_local_only_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_permissions={
                "enabled": True,
                "allowed_actions": "local_only",
            },
        )
        f = _by_id(_findings(snap), "SCM-022")
        assert f.passed

    def test_disabled_actions_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            actions_permissions={"enabled": False},
        )
        f = _by_id(_findings(snap), "SCM-022")
        assert f.passed
        assert "disabled" in f.description.lower()


# ── SCM-023: environment required reviewers ────────────────────────


class TestSCM023:
    def test_environment_without_reviewers_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "protection_rules": [
                            {"type": "wait_timer", "wait_timer": 0},
                        ],
                        "deployment_branch_policy": None,
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-023")
        assert not f.passed
        assert "production" in f.description

    def test_environment_with_reviewers_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "protection_rules": [
                            {
                                "type": "required_reviewers",
                                "reviewers": [
                                    {"type": "Team", "reviewer": {"name": "sec"}},
                                ],
                            },
                        ],
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-023")
        assert f.passed

    def test_no_environments_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={"total_count": 0, "environments": []},
        )
        f = _by_id(_findings(snap), "SCM-023")
        assert f.passed
        assert "No deployment environments" in f.description

    def test_summary_lists_failing_environments(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 2,
                "environments": [
                    {"name": "production", "protection_rules": []},
                    {
                        "name": "staging",
                        "protection_rules": [
                            {"type": "required_reviewers", "reviewers": []},
                        ],
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-023")
        assert not f.passed
        assert "production" in f.description
        assert "staging" not in f.description


# ── SCM-024: environment deployment-branch policy ──────────────────


class TestSCM024:
    def test_null_branch_policy_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "protection_rules": [],
                        "deployment_branch_policy": None,
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-024")
        assert not f.passed
        assert "production" in f.description

    def test_protected_branches_policy_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "deployment_branch_policy": {
                            "protected_branches": True,
                            "custom_branch_policies": False,
                        },
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-024")
        assert f.passed

    def test_custom_policies_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "deployment_branch_policy": {
                            "protected_branches": False,
                            "custom_branch_policies": True,
                        },
                    },
                ],
            },
        )
        f = _by_id(_findings(snap), "SCM-024")
        assert f.passed

    def test_no_environments_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            environments={"total_count": 0, "environments": []},
        )
        f = _by_id(_findings(snap), "SCM-024")
        assert f.passed


# ── SCM-025: deploy keys with write access ─────────────────────────


class TestSCM025:
    def test_write_key_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=[
                {
                    "id": 42, "title": "ci-runner-prod",
                    "key": "ssh-ed25519 AAAA...",
                    "read_only": False,
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert not f.passed
        assert "ci-runner-prod" in f.description
        assert f.severity == Severity.HIGH

    def test_read_only_keys_pass(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=[
                {"id": 1, "title": "docs-clone", "read_only": True},
                {"id": 2, "title": "monitoring-clone", "read_only": True},
            ],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert f.passed
        assert "2 deploy key(s) are read-only" in f.description

    def test_no_keys_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=[],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert f.passed
        assert "No deploy keys" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=None,
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert f.passed
        assert "admin" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            deploy_keys=[{"id": 1, "title": "x", "read_only": False}],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            deploy_keys=[{"id": 1, "title": "x", "read_only": False}],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert f.passed
        assert "archived" in f.description

    def test_unnamed_key_in_summary(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=[
                {"id": 7, "read_only": False},  # no title
            ],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert not f.passed
        assert "key:7" in f.description

    def test_mixed_keys_summary_lists_only_writable(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            deploy_keys=[
                {"id": 1, "title": "safe-clone", "read_only": True},
                {"id": 2, "title": "release-bot", "read_only": False},
            ],
        )
        f = _by_id(_findings(snap), "SCM-025")
        assert not f.passed
        assert "release-bot" in f.description
        assert "safe-clone" not in f.description


# ── SCM-026: webhook ships events insecurely ───────────────────────


class TestSCM026:
    def test_http_url_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "name": "web", "active": True,
                    "events": ["push"],
                    "config": {
                        "url": "http://hooks.example.com/in",
                        "secret": "********",
                        "insecure_ssl": "0",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert not f.passed
        assert "plain-HTTP" in f.description

    def test_insecure_ssl_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {
                        "url": "https://hooks.example.com/in",
                        "secret": "********",
                        "insecure_ssl": "1",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert not f.passed
        assert "insecure_ssl" in f.description

    def test_missing_secret_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {
                        "url": "https://hooks.example.com/in",
                        "secret": None,
                        "insecure_ssl": "0",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert not f.passed
        assert "no shared secret" in f.description

    def test_secure_webhook_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {
                        "url": "https://hooks.example.com/in",
                        "secret": "********",
                        "insecure_ssl": "0",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert f.passed
        assert "1 webhook(s) ship events securely" in f.description

    def test_inactive_webhook_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "active": False,
                    "config": {
                        "url": "http://hooks.example.com/in",
                        "secret": None,
                        "insecure_ssl": "1",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        # Disabled webhook doesn't fire — not the rule's surface.
        assert f.passed

    def test_no_webhooks_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert f.passed
        assert "No webhooks" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=None,
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert f.passed
        assert "admin" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {"url": "http://x", "secret": None,
                               "insecure_ssl": "1"},
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {"url": "http://x", "secret": None,
                               "insecure_ssl": "1"},
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert f.passed
        assert "archived" in f.description

    def test_summary_lists_all_failure_modes_per_hook(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[
                {
                    "id": 1, "active": True,
                    "config": {
                        "url": "http://hooks.example.com/in",
                        "secret": None,
                        "insecure_ssl": "1",
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert not f.passed
        # All three issues should be listed for the single hook.
        assert "plain-HTTP" in f.description
        assert "insecure_ssl" in f.description
        assert "no shared secret" in f.description

    def test_malformed_config_block_flagged(self):
        # If the API somehow returned a missing / non-dict config we
        # still want the rule to fail loudly rather than silently pass.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            webhooks=[{"id": 1, "active": True}],
        )
        f = _by_id(_findings(snap), "SCM-026")
        assert not f.passed
        assert "malformed config" in f.description


# ── SCM-027: outside collaborator with elevated permissions ────────


class TestSCM027:
    def test_write_outside_collab_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "ex-contractor",
                    "permissions": {
                        "admin": False, "maintain": False,
                        "push": True, "triage": True, "pull": True,
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert not f.passed
        assert "ex-contractor:push" in f.description
        assert f.severity == Severity.HIGH

    def test_admin_outside_collab_fails_with_admin_label(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "audit-firm",
                    "permissions": {
                        "admin": True, "maintain": True, "push": True,
                        "triage": True, "pull": True,
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert not f.passed
        # ``admin`` is the most-elevated tier; report it, not push.
        assert "audit-firm:admin" in f.description

    def test_maintain_outside_collab_fails_with_maintain_label(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "consultant",
                    "permissions": {
                        "admin": False, "maintain": True, "push": True,
                        "triage": True, "pull": True,
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert not f.passed
        assert "consultant:maintain" in f.description

    def test_read_only_outside_collab_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "doc-reviewer",
                    "permissions": {
                        "admin": False, "maintain": False,
                        "push": False, "triage": False, "pull": True,
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "1 outside collaborator(s) are read-only" in f.description

    def test_triage_only_passes(self):
        # Triage is a read-tier (label / close issues; no push). Pass.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "triager",
                    "permissions": {
                        "admin": False, "maintain": False,
                        "push": False, "triage": True, "pull": True,
                    },
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed

    def test_no_outside_collabs_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "No outside collaborators" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=None,
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "admin" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            outside_collaborators=[
                {"login": "x", "permissions": {"admin": True}},
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            outside_collaborators=[
                {"login": "x", "permissions": {"admin": True}},
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "archived" in f.description

    def test_truncation_note_when_full_page(self):
        # Exactly 100 entries → potential pagination boundary;
        # the rule appends an audit-prompt note.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": f"user{i}",
                    "permissions": {"pull": True},
                }
                for i in range(100)
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert f.passed
        assert "100 entries" in f.description

    def test_summary_lists_only_elevated(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            outside_collaborators=[
                {
                    "login": "reader",
                    "permissions": {"pull": True},
                },
                {
                    "login": "pusher",
                    "permissions": {"push": True, "pull": True},
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-027")
        assert not f.passed
        assert "pusher:push" in f.description
        assert "reader" not in f.description


# ── SCM-028: private repo allows forking ───────────────────────────


class TestSCM028:
    def test_private_with_forking_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "private": True,
                "allow_forking": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert not f.passed
        assert "pull_request_target" in f.description
        assert f.severity == Severity.MEDIUM

    def test_private_no_forking_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "private": True,
                "allow_forking": False,
            },
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed
        assert "disables forking" in f.description

    def test_public_repo_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "private": False,
                "allow_forking": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed
        assert "public" in f.description

    def test_missing_private_field_treated_as_public(self):
        # GitHub omits ``private`` from public-repo responses
        # under some token scopes; the rule's safe default is to
        # treat the absence as 'not provably private' → pass.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main", "allow_forking": True},
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed

    def test_missing_repo_meta_passes_with_note(self):
        snap = SCMRepoSnapshot(owner="o", name="r", repo_meta=None)
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed
        assert "unavailable" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"private": True, "allow_forking": True},
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "archived": True,
                "private": True,
                "allow_forking": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-028")
        assert f.passed
        assert "archived" in f.description


# ── SCM-029: ruleset in evaluate / disabled mode ────────────────────


class TestSCM029:
    def test_evaluate_mode_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default-branch-protection",
                    "target": "branch", "enforcement": "evaluate",
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert not f.passed
        assert "default-branch-protection" in f.description
        assert "evaluate" in f.description

    def test_disabled_mode_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 2, "name": "signed-commits",
                    "target": "branch", "enforcement": "disabled",
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert not f.passed
        assert "disabled" in f.description

    def test_active_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default-branch-protection",
                    "target": "branch", "enforcement": "active",
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert f.passed
        assert "1 ruleset(s) are actively enforced" in f.description

    def test_mixed_only_flags_non_active(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "good-ruleset",
                    "enforcement": "active",
                },
                {
                    "id": 2, "name": "stuck-in-eval",
                    "enforcement": "evaluate",
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert not f.passed
        assert "stuck-in-eval" in f.description
        assert "good-ruleset" not in f.description

    def test_no_rulesets_passes(self):
        # Empty list — legacy branch protection (SCM-001..010)
        # carries the governance load.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert f.passed
        assert "No repository rulesets" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=None,
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert f.passed
        assert "admin" in f.description

    def test_unnamed_ruleset_shows_id(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {"id": 42, "enforcement": "evaluate"},  # no name
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert not f.passed
        assert "ruleset:42" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            rulesets=[
                {"id": 1, "name": "x", "enforcement": "evaluate"},
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            rulesets=[
                {"id": 1, "name": "x", "enforcement": "evaluate"},
            ],
        )
        f = _by_id(_findings(snap), "SCM-029")
        assert f.passed
        assert "archived" in f.description


# ── SCM-030: ruleset bypass actor with bypass_mode "always" ────────


class TestSCM030:
    def test_always_bypass_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "bypass_actors": [
                        {
                            "actor_id": 5,
                            "actor_type": "RepositoryRole",
                            "bypass_mode": "always",
                        },
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert not f.passed
        assert "RepositoryRole:5" in f.description
        assert f.severity == Severity.HIGH

    def test_pull_request_bypass_passes(self):
        # ``pull_request`` mode requires a PR thread; the audit
        # trail makes this a non-issue.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "bypass_actors": [
                        {
                            "actor_id": 5,
                            "actor_type": "RepositoryRole",
                            "bypass_mode": "pull_request",
                        },
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed

    def test_integration_always_bypass_passes(self):
        # GitHub App ``always`` bypass is auditable via the App's
        # invocation channel; the rule's documented escape hatch.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "bypass_actors": [
                        {
                            "actor_id": 12345,
                            "actor_type": "Integration",
                            "bypass_mode": "always",
                        },
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed

    def test_no_bypass_actors_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "bypass_actors": [],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed
        assert "No active ruleset configures" in f.description

    def test_non_active_ruleset_skipped(self):
        # SCM-029 owns the not-enforced case; SCM-030 ignores
        # non-active rulesets since their bypass list doesn't
        # affect runtime behavior.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "evaluating",
                    "enforcement": "evaluate",
                    "bypass_actors": [
                        {
                            "actor_id": 5,
                            "actor_type": "RepositoryRole",
                            "bypass_mode": "always",
                        },
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed

    def test_team_always_bypass_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "bypass_actors": [
                        {
                            "actor_id": 42,
                            "actor_type": "Team",
                            "bypass_mode": "always",
                        },
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert not f.passed
        assert "Team:42" in f.description

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed
        assert "No repository rulesets" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=None,
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed
        assert "admin" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            rulesets=[
                {
                    "id": 1, "name": "x", "enforcement": "active",
                    "bypass_actors": [
                        {"actor_type": "Team", "actor_id": 1,
                         "bypass_mode": "always"},
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            rulesets=[
                {
                    "id": 1, "name": "x", "enforcement": "active",
                    "bypass_actors": [
                        {"actor_type": "Team", "actor_id": 1,
                         "bypass_mode": "always"},
                    ],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert f.passed
        assert "archived" in f.description

    def test_detail_unavailable_does_not_silently_pass(self):
        # The per-ruleset detail fetch failed (403 / 404 / timeout)
        # for an active ruleset, so ``bypass_actors`` was never
        # populated. The rule must NOT treat that as a clean
        # bypass list — it should surface the gap so the operator
        # knows posture wasn't fully evaluated.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "default",
                    "enforcement": "active",
                    "_detail_unavailable": True,
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        # Passes (we can't prove a fail), but the description
        # names the unavailability so the operator can fix it.
        assert f.passed
        assert "unavailable" in f.description.lower()
        assert "default" in f.description

    def test_detail_unavailable_combines_with_real_offender(self):
        # One active ruleset has detail unavailable; a second
        # active ruleset has a real always-bypass. The rule must
        # fail on the offender AND note the gap.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "with-bad-bypass",
                    "enforcement": "active",
                    "bypass_actors": [
                        {"actor_type": "Team", "actor_id": 42,
                         "bypass_mode": "always"},
                    ],
                },
                {
                    "id": 2, "name": "unmeasurable",
                    "enforcement": "active",
                    "_detail_unavailable": True,
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-030")
        assert not f.passed
        assert "with-bad-bypass" in f.description
        assert "unmeasurable" in f.description.lower() or \
               "1 ruleset(s) had their detail endpoint" in f.description


# ── SCM-031: auto-merge enabled ─────────────────────────────────────


class TestSCM031:
    def test_auto_merge_enabled_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "allow_auto_merge": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-031")
        assert not f.passed
        assert "Auto-merge is enabled" in f.description
        assert f.severity == Severity.MEDIUM

    def test_auto_merge_disabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "default_branch": "main",
                "allow_auto_merge": False,
            },
        )
        f = _by_id(_findings(snap), "SCM-031")
        assert f.passed
        assert "disabled" in f.description

    def test_missing_field_treated_as_disabled(self):
        # GitHub's default for ``allow_auto_merge`` is false; an
        # absent field should pass.
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
        )
        f = _by_id(_findings(snap), "SCM-031")
        assert f.passed

    def test_missing_repo_meta_passes_with_note(self):
        snap = SCMRepoSnapshot(owner="o", name="r", repo_meta=None)
        f = _by_id(_findings(snap), "SCM-031")
        assert f.passed
        assert "unavailable" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"allow_auto_merge": True},
        )
        f = _by_id(_findings(snap), "SCM-031")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={
                "archived": True,
                "allow_auto_merge": True,
            },
        )
        f = _by_id(_findings(snap), "SCM-031")
        assert f.passed
        assert "archived" in f.description


# ── SCM-032: active ruleset doesn't require PR review ───────────────


def _active_ruleset(
    rules: list,
    *,
    name: str = "rs",
    rs_id: int = 1,
    ref_includes: tuple[str, ...] = ("~DEFAULT_BRANCH",),
    ref_excludes: tuple[str, ...] = (),
) -> dict:
    """Helper: active branch-target ruleset with the given rules
    block. Defaults to a ``conditions.ref_name.include`` of
    ``~DEFAULT_BRANCH`` so per-rule-type checks see the ruleset as
    protecting the default branch. Pass ``ref_includes`` /
    ``ref_excludes`` to build a scoped-away ruleset for the
    "rulesets exist but don't target default" test cases."""
    return {
        "id": rs_id, "name": name, "enforcement": "active",
        "target": "branch",
        "conditions": {"ref_name": {
            "include": list(ref_includes),
            "exclude": list(ref_excludes),
        }},
        "rules": rules,
    }


class TestSCM032:
    def test_active_ruleset_without_pr_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "required_signatures"}], name="signing-only",
            )],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert not f.passed
        assert "signing-only" in f.description
        assert f.severity == Severity.HIGH

    def test_pr_rule_with_one_review_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "pull_request",
                  "parameters": {"required_approving_review_count": 1}}],
                name="default",
            )],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed

    def test_pr_rule_with_zero_reviews_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "pull_request",
                  "parameters": {"required_approving_review_count": 0}}],
                name="weak",
            )],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert not f.passed

    def test_pr_rule_without_parameters_block_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "pull_request"}], name="legacy",
            )],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed

    def test_non_active_ruleset_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "evaluating",
                    "enforcement": "evaluate",
                    "rules": [],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed
        assert "legacy branch-protection" in f.description

    def test_endpoint_unavailable_passes_with_note(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=None,
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed
        assert "admin" in f.description

    def test_detail_unavailable_surfaces(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {
                    "id": 1, "name": "could-not-fetch-detail",
                    "enforcement": "active",
                    "_detail_unavailable": True,
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed
        assert "unavailable" in f.description.lower()
        assert "could-not-fetch-detail" in f.description

    def test_non_github_platform_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            rulesets=[
                {
                    "id": 1, "name": "x", "enforcement": "active",
                    "rules": [],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed
        assert "gitlab" in f.description.lower()

    def test_archived_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"archived": True},
            rulesets=[
                {
                    "id": 1, "name": "x", "enforcement": "active",
                    "rules": [],
                },
            ],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert f.passed
        assert "archived" in f.description


# ── SCM-033..040: ruleset rule-type coverage ────────────────────────


class TestSCM033StatusChecks:
    def test_no_status_checks_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "pull_request",
                 "parameters": {"required_approving_review_count": 1}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_status_checks_with_contexts_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "ci/build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert f.passed

    def test_status_checks_empty_contexts_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": []}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert not f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert f.passed
        assert "SCM-008" in f.description

    def test_non_active_ruleset_skipped(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[{"id": 1, "name": "rs", "enforcement": "evaluate",
                       "rules": []}],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert f.passed


class TestSCM034ForcePush:
    def test_no_non_fast_forward_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "pull_request"}])],
        )
        f = _by_id(_findings(snap), "SCM-034")
        assert not f.passed

    def test_non_fast_forward_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "non_fast_forward"}])],
        )
        f = _by_id(_findings(snap), "SCM-034")
        assert f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-034")
        assert f.passed
        assert "SCM-007" in f.description


class TestSCM035Deletion:
    def test_no_deletion_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "non_fast_forward"}])],
        )
        f = _by_id(_findings(snap), "SCM-035")
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_deletion_rule_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "deletion"}])],
        )
        f = _by_id(_findings(snap), "SCM-035")
        assert f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-035")
        assert f.passed
        assert "SCM-009" in f.description


class TestSCM036SignedCommits:
    def test_no_signatures_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "non_fast_forward"}])],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert not f.passed

    def test_required_signatures_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "required_signatures"}])],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert f.passed
        assert "SCM-006" in f.description


class TestSCM037StaleReviewDismissal:
    def test_pr_rule_without_dismissal_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "pull_request",
                 "parameters": {
                     "required_approving_review_count": 1,
                     "dismiss_stale_reviews_on_push": False,
                 }},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert not f.passed

    def test_pr_rule_with_dismissal_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "pull_request",
                 "parameters": {
                     "required_approving_review_count": 1,
                     "dismiss_stale_reviews_on_push": True,
                 }},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert f.passed

    def test_no_pr_rule_skipped(self):
        # If there's no ``pull_request`` rule at all, SCM-032
        # owns the failure surface; SCM-037 should not double-
        # report.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "required_signatures"}])],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert f.passed

    def test_pr_rule_no_params_block_fails(self):
        # GitHub's default for dismiss_stale_reviews_on_push is
        # false; a bare ``pull_request`` rule should still fail.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "pull_request"}])],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert not f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert f.passed
        assert "SCM-012" in f.description


class TestSCM038LinearHistory:
    def test_no_linear_history_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "non_fast_forward"}])],
        )
        f = _by_id(_findings(snap), "SCM-038")
        assert not f.passed

    def test_required_linear_history_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "required_linear_history"}])],
        )
        f = _by_id(_findings(snap), "SCM-038")
        assert f.passed

    def test_no_rulesets_passes(self):
        # Linear history has no legacy branch-protection analog, so
        # the rule is silent (passing) when no rulesets exist —
        # absence here means "gate doesn't exist", not "gate carried
        # elsewhere". The description must say so.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-038")
        assert f.passed
        assert "no legacy branch-protection" in f.description.lower()


class TestSCM039RequiredWorkflows:
    def test_no_workflows_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert not f.passed

    def test_workflows_rule_with_entries_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "workflows",
                 "parameters": {"workflows": [
                     {"repository_id": 1,
                      "path": ".github/workflows/scan.yml",
                      "ref": "refs/heads/main"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert f.passed

    def test_workflows_rule_empty_list_fails(self):
        # An empty ``workflows`` list documents the gate without
        # filling it — treated the same as no rule.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "workflows",
                 "parameters": {"workflows": []}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert not f.passed

    def test_workflows_rule_no_params_fails(self):
        # Bare ``workflows`` with no params is malformed; treat as
        # not-satisfied (don't crash, don't pass).
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "workflows"}])],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert not f.passed

    def test_no_rulesets_passes(self):
        # Required workflows has no legacy branch-protection
        # analog; absence-not-coverage language must be present.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert f.passed
        assert "no legacy branch-protection" in f.description.lower()


class TestSCM040CodeScanning:
    def test_no_code_scanning_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert not f.passed

    def test_code_scanning_rule_with_tools_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "code_scanning",
                 "parameters": {"code_scanning_tools": [
                     {"tool": "CodeQL",
                      "security_alerts_threshold": "high_or_higher",
                      "alerts_threshold": "errors"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert f.passed

    def test_code_scanning_rule_empty_list_fails(self):
        # Empty ``code_scanning_tools`` documents the gate without
        # filling it — same as no rule.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "code_scanning",
                 "parameters": {"code_scanning_tools": []}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert not f.passed

    def test_code_scanning_rule_no_params_fails(self):
        # Bare ``code_scanning`` with no params is malformed.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "code_scanning"}])],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert not f.passed

    def test_no_rulesets_passes(self):
        # Code-scanning gating has no legacy BP analog;
        # absence-not-coverage language is required.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert f.passed
        assert "no legacy branch-protection" in f.description.lower()


class TestSCM041RequiredDeployments:
    def test_no_deployments_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert not f.passed

    def test_required_deployments_rule_with_envs_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_deployments",
                 "parameters": {
                     "required_deployment_environments": ["staging"],
                 }},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert f.passed

    def test_required_deployments_empty_list_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_deployments",
                 "parameters": {"required_deployment_environments": []}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert not f.passed

    def test_required_deployments_no_params_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "required_deployments"}])],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert not f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert f.passed
        assert "no legacy branch-protection" in f.description.lower()


class TestSCM042MergeQueue:
    def test_no_merge_queue_rule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-042")
        assert not f.passed

    def test_merge_queue_rule_present_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "merge_queue"}])],
        )
        f = _by_id(_findings(snap), "SCM-042")
        assert f.passed

    def test_no_rulesets_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[],
        )
        f = _by_id(_findings(snap), "SCM-042")
        assert f.passed
        assert "no legacy branch-protection" in f.description.lower()


# ── SCM-043: tag-ruleset signed commits ─────────────────────────────


def _active_tag_ruleset(
    rules: list,
    *,
    name: str = "tags",
    rs_id: int = 99,
) -> dict:
    return {
        "id": rs_id, "name": name, "enforcement": "active",
        "target": "tag",
        "conditions": {"ref_name": {
            "include": ["refs/tags/v*"],
            "exclude": [],
        }},
        "rules": rules,
    }


class TestSCM043TagSigning:
    def test_tag_ruleset_without_signing_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_tag_ruleset([{"type": "deletion"}])],
        )
        f = _by_id(_findings(snap), "SCM-043")
        assert not f.passed
        assert "tags" in f.description

    def test_tag_ruleset_with_signing_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_tag_ruleset(
                [{"type": "required_signatures"}],
            )],
        )
        f = _by_id(_findings(snap), "SCM-043")
        assert f.passed

    def test_no_tag_rulesets_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset([{"type": "required_signatures"}])],
        )
        f = _by_id(_findings(snap), "SCM-043")
        assert f.passed
        assert "no active tag-targeted rulesets" in f.description.lower()

    def test_branch_ruleset_does_not_count(self):
        """A branch-targeted ruleset with signed_commits does NOT
        satisfy the tag-signing requirement: tag pushes don't
        traverse the branch ruleset."""
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[
                _active_ruleset([{"type": "required_signatures"}]),
                _active_tag_ruleset([{"type": "deletion"}]),
            ],
        )
        f = _by_id(_findings(snap), "SCM-043")
        assert not f.passed

    def test_rulesets_none_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=None,
        )
        f = _by_id(_findings(snap), "SCM-043")
        assert f.passed
        assert "unavailable" in f.description


# ── SCM-044: required_signatures admin bypass ───────────────────────


class TestSCM044AdminBypassSigning:
    def test_signing_without_admin_enforcement_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_signatures": {"enabled": True},
                "enforce_admins": {"enabled": False},
            },
        )
        f = _by_id(_findings(snap), "SCM-044")
        assert not f.passed
        assert "enforce_admins" in f.description

    def test_signing_with_admin_enforcement_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_signatures": {"enabled": True},
                "enforce_admins": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-044")
        assert f.passed

    def test_no_signing_requirement_defers_to_scm006(self):
        """When signed_commits isn't required at all, SCM-006 owns
        the failure; SCM-044 should pass silently."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
            },
        )
        f = _by_id(_findings(snap), "SCM-044")
        assert f.passed
        assert "SCM-006" in f.description

    def test_no_protection_defers_to_scm001(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection=None,
        )
        f = _by_id(_findings(snap), "SCM-044")
        assert f.passed
        assert "SCM-001" in f.description

    def test_enforce_admins_missing_field_fails(self):
        """GitHub omits the enforce_admins block when admins are not
        included; treat missing same as disabled."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            default_branch_protection={
                "required_signatures": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-044")
        assert not f.passed


# ── SCM-045: code scanning query suite ──────────────────────────────


class TestSCM045QuerySuite:
    def test_default_suite_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "query_suite": "default",
            },
        )
        f = _by_id(_findings(snap), "SCM-045")
        assert not f.passed
        assert f.severity == Severity.LOW

    def test_extended_suite_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "query_suite": "extended",
            },
        )
        f = _by_id(_findings(snap), "SCM-045")
        assert f.passed

    def test_not_configured_defers_to_scm003(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={"state": "not-configured"},
        )
        f = _by_id(_findings(snap), "SCM-045")
        assert f.passed
        assert "SCM-003" in f.description

    def test_setup_missing_defers_to_scm003(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup=None,
        )
        f = _by_id(_findings(snap), "SCM-045")
        assert f.passed


# ── SCM-046: code scanning paused ───────────────────────────────────


class TestSCM046Paused:
    def test_no_schedule_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "schedule": None,
            },
        )
        f = _by_id(_findings(snap), "SCM-046")
        assert not f.passed
        assert "schedule" in f.description.lower()

    def test_weekly_schedule_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "schedule": "weekly",
            },
        )
        f = _by_id(_findings(snap), "SCM-046")
        assert f.passed

    def test_schedule_as_block_passes(self):
        """Newer API shape wraps the schedule in a sub-object."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "schedule": {"frequency": "daily"},
            },
        )
        f = _by_id(_findings(snap), "SCM-046")
        assert f.passed

    def test_none_string_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "schedule": "none",
            },
        )
        f = _by_id(_findings(snap), "SCM-046")
        assert not f.passed

    def test_not_configured_defers_to_scm003(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={"state": "not-configured"},
        )
        f = _by_id(_findings(snap), "SCM-046")
        assert f.passed


# ── SCM-047: repo language not covered ──────────────────────────────


class TestSCM047LanguageCoverage:
    def test_python_repo_with_python_scanning_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["python"],
            },
            repo_languages={"Python": 100000},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed

    def test_python_repo_without_python_scanning_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["go"],
            },
            repo_languages={"Python": 100000},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert not f.passed
        assert "Python" in f.description

    def test_tiny_language_share_ignored(self):
        """A <5% share doesn't trigger a finding."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["python"],
            },
            # 100 bytes of Ruby in a 10000-byte Python repo = 1%, ignored.
            repo_languages={"Python": 9900, "Ruby": 100},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed

    def test_unsupported_language_ignored(self):
        """Shell isn't CodeQL-supported; absence from scanning doesn't
        trigger a finding."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["python"],
            },
            repo_languages={"Python": 50000, "Shell": 50000},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed

    def test_java_and_kotlin_collapse_to_same_codeql_id(self):
        """Java and Kotlin both map to ``java-kotlin``; one in
        scanning satisfies both."""
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["java-kotlin"],
            },
            repo_languages={"Java": 50000, "Kotlin": 50000},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed

    def test_languages_endpoint_unavailable_passes_silently(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={
                "state": "configured",
                "languages": ["python"],
            },
            repo_languages=None,
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed
        assert "unavailable" in f.description.lower()

    def test_scanning_not_configured_defers(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            code_scanning_default_setup={"state": "not-configured"},
            repo_languages={"Python": 100000},
        )
        f = _by_id(_findings(snap), "SCM-047")
        assert f.passed


# ── Default-branch scoping: rulesets exist but scope away from main ──
#
# Every per-rule-type rule in SCM-032..040 used to iterate "active"
# rulesets without checking whether ``conditions.ref_name`` actually
# targets the default branch. A ruleset scoped to ``refs/tags/*`` or
# ``refs/heads/release/**`` with the right rule type silently passed
# the per-rule-type check while the default branch had no
# ruleset-level coverage at all. The refactor narrows iteration to
# ``active_rulesets_targeting_default(snapshot)`` and surfaces the
# new "scoped away from default" shape as an explicit failure.
#
# Each rule's scoped-away message names the gap and (for SCM-032..037)
# points to the legacy SCM-NNN that still carries the default-branch
# gate; SCM-038..040 have no legacy analog so the description names
# the absent default-branch coverage directly.


class TestRulesetScopedAwayFromDefault:
    @staticmethod
    def _scoped_away_ruleset(rules: list) -> dict:
        """Active ruleset that targets release/** instead of main."""
        return _active_ruleset(
            rules,
            name="release-only",
            ref_includes=("refs/heads/release/**",),
        )

    def test_scm032_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "pull_request",
                 "parameters": {"required_approving_review_count": 2}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-032")
        assert not f.passed
        assert "release-only" in f.description
        assert "refs/heads/main" in f.description
        assert "SCM-002" in f.description

    def test_scm033_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "required_status_checks",
                 "parameters": {"required_status_checks": [
                     {"context": "build"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-033")
        assert not f.passed
        assert "SCM-008" in f.description

    def test_scm034_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "non_fast_forward"},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-034")
        assert not f.passed
        assert "SCM-007" in f.description

    def test_scm035_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "deletion"},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-035")
        assert not f.passed
        assert "SCM-009" in f.description

    def test_scm036_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "required_signatures"},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert not f.passed
        assert "SCM-006" in f.description

    def test_scm037_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "pull_request",
                 "parameters": {
                     "required_approving_review_count": 1,
                     "dismiss_stale_reviews_on_push": True,
                 }},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-037")
        assert not f.passed
        assert "SCM-012" in f.description

    def test_scm038_scoped_away_fails(self):
        # SCM-038..040 have no legacy BP analog — the failure
        # description names absent default-branch coverage rather
        # than a legacy carrier.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "required_linear_history"},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-038")
        assert not f.passed
        assert "no legacy branch-protection" in f.description.lower()

    def test_scm039_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "workflows",
                 "parameters": {"workflows": [
                     {"repository_id": 1,
                      "path": ".github/workflows/scan.yml",
                      "ref": "refs/heads/main"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-039")
        assert not f.passed
        assert "no legacy branch-protection" in f.description.lower()

    def test_scm040_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "code_scanning",
                 "parameters": {"code_scanning_tools": [
                     {"tool": "CodeQL",
                      "security_alerts_threshold": "high_or_higher",
                      "alerts_threshold": "errors"},
                 ]}},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-040")
        assert not f.passed
        assert "no legacy branch-protection" in f.description.lower()

    def test_scm041_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "required_deployments",
                 "parameters": {
                     "required_deployment_environments": ["staging"],
                 }},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-041")
        assert not f.passed
        assert "no legacy branch-protection" in f.description.lower()

    def test_scm042_scoped_away_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[self._scoped_away_ruleset([
                {"type": "merge_queue"},
            ])],
        )
        f = _by_id(_findings(snap), "SCM-042")
        assert not f.passed
        assert "no legacy branch-protection" in f.description.lower()

    def test_excluded_default_branch_is_scoped_away(self):
        # ~ALL include but default branch in exclude list — same
        # outcome as a scope-elsewhere include: default branch isn't
        # covered.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "required_signatures"}],
                name="all-except-main",
                ref_includes=("~ALL",),
                ref_excludes=("refs/heads/main",),
            )],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert not f.passed
        assert "all-except-main" in f.description

    def test_tag_target_ruleset_is_scoped_away(self):
        # target == "tag" means the ruleset never applies to
        # branches; same effect as scope-elsewhere include.
        rs = _active_ruleset(
            [{"type": "required_signatures"}], name="tags-only",
        )
        rs["target"] = "tag"
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[rs],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert not f.passed
        assert "tags-only" in f.description

    def test_glob_matching_default_branch_passes(self):
        # ``refs/heads/**`` matches the default branch; the rule
        # should treat this ruleset as targeting default.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[_active_ruleset(
                [{"type": "required_signatures"}],
                name="all-branches",
                ref_includes=("refs/heads/**",),
            )],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert f.passed

    def test_exact_default_branch_ref_passes(self):
        # An explicit ``refs/heads/<default>`` include also matches.
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "trunk"},
            rulesets=[_active_ruleset(
                [{"type": "required_signatures"}],
                name="trunk-only",
                ref_includes=("refs/heads/trunk",),
            )],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert f.passed

    def test_scoped_away_with_unavailable_still_fails(self):
        # Combined case: one scoped-away ruleset AND one with the
        # detail endpoint unavailable. The scoped-away ruleset must
        # still surface as a failure; the unavailable one rides as
        # an "Additionally..." mention rather than being silently
        # dropped.
        unavail = {
            "id": 99, "name": "needs-admin", "enforcement": "active",
            "target": "branch", "_detail_unavailable": True,
        }
        snap = SCMRepoSnapshot(
            owner="o", name="r", repo_meta={"default_branch": "main"},
            rulesets=[
                self._scoped_away_ruleset([{"type": "required_signatures"}]),
                unavail,
            ],
        )
        f = _by_id(_findings(snap), "SCM-036")
        assert not f.passed
        assert "release-only" in f.description
        assert "needs-admin" not in f.description  # labels not enumerated for unavail
        assert "Additionally" in f.description
        assert "detail-endpoint errors" in f.description


# ── Snapshot hydration: from_repo wires the new endpoints ──────────


class TestSnapshotActionsEndpoints:
    def test_for_repo_calls_new_endpoints(self):
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main", "private": True},
            "repos/o/r/branches/main/protection": {},
            "repos/o/r/code-scanning/default-setup": {"state": "configured"},
            "repos/o/r/actions/permissions": {
                "enabled": True, "allowed_actions": "selected",
            },
            "repos/o/r/actions/permissions/workflow": {
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
            "repos/o/r/environments": {
                "total_count": 1,
                "environments": [
                    {"name": "production", "protection_rules": []},
                ],
            },
            "repos/o/r/keys": [
                {"id": 1, "title": "ci", "read_only": True},
            ],
            "repos/o/r/hooks": [
                {
                    "id": 1, "name": "web", "active": True,
                    "config": {
                        "url": "https://hooks.example.com/in",
                        "secret": "********",
                        "insecure_ssl": "0",
                    },
                },
            ],
            "repos/o/r/collaborators?affiliation=outside&per_page=100": [
                {"login": "outside-dev", "permissions": {"pull": True}},
            ],
            "repos/o/r/rulesets?per_page=100": [
                {"id": 1, "name": "default-branch-protection",
                 "target": "branch", "enforcement": "active"},
            ],
            "repos/o/r/rulesets/1": {
                "id": 1, "name": "default-branch-protection",
                "target": "branch", "enforcement": "active",
                "bypass_actors": [],
                "rules": [],
            },
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        snap = ctx.repos[0]
        assert snap.actions_permissions == {
            "enabled": True, "allowed_actions": "selected",
        }
        assert snap.actions_workflow_permissions == {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }
        assert isinstance(snap.environments, dict)
        assert snap.environments["total_count"] == 1
        assert snap.deploy_keys == [
            {"id": 1, "title": "ci", "read_only": True},
        ]
        assert isinstance(snap.webhooks, list)
        assert len(snap.webhooks) == 1
        assert snap.outside_collaborators == [
            {"login": "outside-dev", "permissions": {"pull": True}},
        ]
        assert isinstance(snap.rulesets, list)
        assert len(snap.rulesets) == 1
        # Active ruleset's detail body got merged in.
        assert snap.rulesets[0]["bypass_actors"] == []
        # Each new endpoint was hit exactly once.
        for path in (
            "repos/o/r/actions/permissions",
            "repos/o/r/actions/permissions/workflow",
            "repos/o/r/environments",
            "repos/o/r/keys",
            "repos/o/r/hooks",
            "repos/o/r/collaborators?affiliation=outside&per_page=100",
            "repos/o/r/rulesets?per_page=100",
            "repos/o/r/rulesets/1",
        ):
            assert path in fetcher.calls

    def test_for_repo_marks_active_ruleset_when_detail_fetch_fails(self):
        # The list endpoint returns an active ruleset, but the
        # per-id detail endpoint is missing from the fixture (→
        # the FakeSCMFetcher returns None → represents a 403/404
        # / timeout from GitHub). The loader must mark the
        # ruleset entry with ``_detail_unavailable: True`` so
        # SCM-030 can distinguish "couldn't measure" from "clean".
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/rulesets?per_page=100": [
                {"id": 7, "name": "active-but-403-on-detail",
                 "enforcement": "active"},
            ],
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        snap = ctx.repos[0]
        assert isinstance(snap.rulesets, list)
        assert snap.rulesets[0]["_detail_unavailable"] is True

    def test_for_repo_warns_when_rulesets_at_page_cap(self):
        # Exactly 100 rulesets came back → potential pagination
        # boundary; the context warnings list must mention it so
        # the operator audits manually.
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
            "repos/o/r/rulesets?per_page=100": [
                {"id": i, "name": f"rs{i}", "enforcement": "disabled"}
                for i in range(100)
            ],
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        assert any(
            "rulesets returned" in w and "100" in w
            for w in ctx.warnings
        )

    def test_for_repo_silent_when_actions_endpoints_404(self):
        # Endpoints unavailable (typical for tokens without admin
        # scope): the corresponding snapshot slots stay None and the
        # context still hydrates.
        fetcher = FakeSCMFetcher({
            "repos/o/r": {"default_branch": "main"},
        })
        ctx = SCMContext.for_repo("o", "r", fetcher)
        snap = ctx.repos[0]
        assert snap.actions_permissions is None
        assert snap.actions_workflow_permissions is None
        assert snap.environments is None
        assert snap.deploy_keys is None
        assert snap.webhooks is None
        assert snap.outside_collaborators is None
        assert snap.rulesets is None


# ── Direct tests for the ruleset partition helpers ─────────────────
#
# Every per-rule-type rule in SCM-032..040 funnels through
# ``active_rulesets_targeting_default`` and ``ruleset_targets_default_branch``.
# These tests pin the helper contract directly so a regression in the
# partition shape surfaces without having to chase it through one of
# the rule-specific tests.


class TestMatchesDefaultBranchRef:
    def test_all_wildcard_matches(self):
        from pipeline_check.core.checks.scm.base import (
            _matches_default_branch_ref,
        )
        assert _matches_default_branch_ref("~ALL", "main") is True

    def test_default_branch_token_matches(self):
        from pipeline_check.core.checks.scm.base import (
            _matches_default_branch_ref,
        )
        assert _matches_default_branch_ref("~DEFAULT_BRANCH", "trunk") is True

    def test_exact_ref_matches(self):
        from pipeline_check.core.checks.scm.base import (
            _matches_default_branch_ref,
        )
        assert _matches_default_branch_ref("refs/heads/main", "main") is True
        assert _matches_default_branch_ref("refs/heads/develop", "main") is False

    def test_fnmatch_glob_matches(self):
        from pipeline_check.core.checks.scm.base import (
            _matches_default_branch_ref,
        )
        assert _matches_default_branch_ref("refs/heads/**", "main") is True
        assert _matches_default_branch_ref("refs/heads/m*", "main") is True
        assert _matches_default_branch_ref("refs/heads/release/**", "main") is False


class TestRulesetTargetsDefaultBranch:
    def test_unset_target_treated_as_branch(self):
        from pipeline_check.core.checks.scm.base import (
            ruleset_targets_default_branch,
        )
        rs = {
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        }
        assert ruleset_targets_default_branch(rs, "main") is True

    def test_tag_target_returns_false(self):
        from pipeline_check.core.checks.scm.base import (
            ruleset_targets_default_branch,
        )
        rs = {
            "target": "tag",
            "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
        }
        assert ruleset_targets_default_branch(rs, "main") is False

    def test_push_target_returns_false(self):
        from pipeline_check.core.checks.scm.base import (
            ruleset_targets_default_branch,
        )
        rs = {
            "target": "push",
            "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
        }
        assert ruleset_targets_default_branch(rs, "main") is False

    def test_exclude_shadows_default(self):
        from pipeline_check.core.checks.scm.base import (
            ruleset_targets_default_branch,
        )
        rs = {
            "target": "branch",
            "conditions": {"ref_name": {
                "include": ["~ALL"],
                "exclude": ["refs/heads/main"],
            }},
        }
        assert ruleset_targets_default_branch(rs, "main") is False

    def test_missing_conditions_returns_false(self):
        from pipeline_check.core.checks.scm.base import (
            ruleset_targets_default_branch,
        )
        # Without a populated ref_name include the partition can't
        # prove default-branch coverage; treat as scoped-away rather
        # than silent-pass.
        assert ruleset_targets_default_branch({"target": "branch"}, "main") is False
        assert ruleset_targets_default_branch(
            {"target": "branch", "conditions": {"ref_name": {"include": []}}},
            "main",
        ) is False


class TestActiveRulesetsTargetingDefault:
    def test_partitions_into_three_buckets(self):
        from pipeline_check.core.checks.scm.base import (
            active_rulesets_targeting_default,
        )
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                _active_ruleset([], name="targets-main"),
                _active_ruleset([], name="release-only",
                                ref_includes=("refs/heads/release/**",)),
                {"id": 99, "name": "unavail", "enforcement": "active",
                 "target": "branch", "_detail_unavailable": True},
            ],
        )
        targeting, unavailable, scoped_away = (
            active_rulesets_targeting_default(snap)
        )
        assert [rs["name"] for rs in targeting] == ["targets-main"]
        assert [rs["name"] for rs in unavailable] == ["unavail"]
        assert [rs["name"] for rs in scoped_away] == ["release-only"]

    def test_filters_non_active_rulesets(self):
        from pipeline_check.core.checks.scm.base import (
            active_rulesets_targeting_default,
        )
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {"id": 1, "name": "evaluating", "enforcement": "evaluate",
                 "target": "branch",
                 "conditions": {"ref_name": {"include": ["~ALL"]}}},
                {"id": 2, "name": "disabled", "enforcement": "disabled",
                 "target": "branch",
                 "conditions": {"ref_name": {"include": ["~ALL"]}}},
            ],
        )
        targeting, unavailable, scoped_away = (
            active_rulesets_targeting_default(snap)
        )
        assert targeting == [] and unavailable == [] and scoped_away == []

    def test_push_target_dropped_entirely(self):
        # Push rulesets fire on every push but use a different rule
        # shape (file-size / path / extension filters) that can't
        # carry SCM-032..040 rule types. They must not surface as
        # scoped-away or the per-rule-type failure message would
        # claim "doesn't target the default branch" for a ruleset
        # that does.
        from pipeline_check.core.checks.scm.base import (
            active_rulesets_targeting_default,
        )
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=[
                {"id": 1, "name": "push-only", "enforcement": "active",
                 "target": "push",
                 "conditions": {"ref_name": {"include": ["~ALL"]}}},
            ],
        )
        targeting, unavailable, scoped_away = (
            active_rulesets_targeting_default(snap)
        )
        assert targeting == [] and unavailable == [] and scoped_away == []

    def test_returns_empty_when_rulesets_is_none(self):
        from pipeline_check.core.checks.scm.base import (
            active_rulesets_targeting_default,
        )
        snap = SCMRepoSnapshot(
            owner="o", name="r",
            repo_meta={"default_branch": "main"},
            rulesets=None,
        )
        assert active_rulesets_targeting_default(snap) == ([], [], [])


# ── SCM-048..055: firing tests for the newest rules (no coverage gate
#    runs on the SCM pack, so these slipped in without a Test<ID> class) ─


class TestSCM048:
    def test_all_repos_visibility_fails(self):
        snap = SCMRepoSnapshot(
            owner="acme", name="r",
            codespace_secrets=[{"name": "PROD_DB_PASSWORD", "visibility": "all"}],
        )
        f = _by_id(_findings(snap), "SCM-048")
        assert not f.passed
        assert f.severity == Severity.HIGH
        assert "PROD_DB_PASSWORD" in f.description

    def test_selected_visibility_passes(self):
        snap = SCMRepoSnapshot(
            owner="acme", name="r",
            codespace_secrets=[{"name": "PROD", "visibility": "selected"}],
        )
        assert _by_id(_findings(snap), "SCM-048").passed

    def test_no_secrets_passes(self):
        snap = SCMRepoSnapshot(owner="acme", name="r", codespace_secrets=[])
        assert _by_id(_findings(snap), "SCM-048").passed


class TestSCM049:
    def test_classic_pat_fails(self):
        snap = SCMRepoSnapshot(owner="o", name="r", token_type="classic")
        f = _by_id(_findings(snap), "SCM-049")
        assert not f.passed
        assert f.severity == Severity.MEDIUM

    def test_fine_grained_passes(self):
        snap = SCMRepoSnapshot(owner="o", name="r", token_type="fine-grained")
        assert _by_id(_findings(snap), "SCM-049").passed


class TestSCM050:
    def test_prevent_secrets_off_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_push_rule": {"prevent_secrets": False}},
        )
        f = _by_id(_findings(snap), "SCM-050")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_prevent_secrets_on_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_push_rule": {"prevent_secrets": True}},
        )
        assert _by_id(_findings(snap), "SCM-050").passed


class TestSCM051:
    def test_committer_check_off_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_push_rule": {"commit_committer_check": False}},
        )
        assert not _by_id(_findings(snap), "SCM-051").passed

    def test_committer_check_on_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_push_rule": {"commit_committer_check": True}},
        )
        assert _by_id(_findings(snap), "SCM-051").passed


class TestSCM052:
    def test_unresolved_discussions_allowed_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_project": {
                "only_allow_merge_if_all_discussions_are_resolved": False,
            }},
        )
        assert not _by_id(_findings(snap), "SCM-052").passed

    def test_resolution_required_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_project": {
                "only_allow_merge_if_all_discussions_are_resolved": True,
            }},
        )
        assert _by_id(_findings(snap), "SCM-052").passed


class TestSCM053:
    def test_author_self_approval_allowed_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_project": {"merge_requests_author_approval": True}},
        )
        f = _by_id(_findings(snap), "SCM-053")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_author_self_approval_disabled_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="gitlab",
            repo_meta={"_gitlab_project": {"merge_requests_author_approval": False}},
        )
        assert _by_id(_findings(snap), "SCM-053").passed


class TestSCM054:
    def test_private_repo_public_forks_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="bitbucket",
            repo_meta={"_bitbucket_repo": {
                "is_private": True, "fork_policy": "allow_forks",
            }},
        )
        f = _by_id(_findings(snap), "SCM-054")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_no_forks_policy_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="bitbucket",
            repo_meta={"_bitbucket_repo": {
                "is_private": True, "fork_policy": "no_forks",
            }},
        )
        assert _by_id(_findings(snap), "SCM-054").passed

    def test_public_repo_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="bitbucket",
            repo_meta={"_bitbucket_repo": {
                "is_private": False, "fork_policy": "allow_forks",
            }},
        )
        assert _by_id(_findings(snap), "SCM-054").passed


class TestSCM055:
    def test_no_write_side_restriction_fails(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="bitbucket",
            default_branch_protection={
                "allow_force_pushes": {"enabled": True},
                "allow_deletions": {"enabled": True},
            },
        )
        f = _by_id(_findings(snap), "SCM-055")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_force_push_restricted_passes(self):
        snap = SCMRepoSnapshot(
            owner="o", name="r", platform="bitbucket",
            default_branch_protection={
                "allow_force_pushes": {"enabled": False},
            },
        )
        assert _by_id(_findings(snap), "SCM-055").passed


# ── Org-wide fan-out: SCMContext.for_org ────────────────────────────


def _org_findings(ctx: SCMContext) -> list[Any]:
    return SCMPostureChecks(ctx).run()


class TestOrgFanout:
    _REPOS_PAGE = "orgs/acme/repos?per_page=100&page=1&type=all"

    def _fake(self) -> FakeSCMFetcher:
        # Two live repos + one archived (must be skipped). Each live repo
        # has metadata but no branch protection (404 -> None), so SCM-001
        # fires for each.
        return FakeSCMFetcher({
            self._REPOS_PAGE: [
                {"name": "alpha", "full_name": "acme/alpha", "archived": False},
                {"name": "beta", "full_name": "acme/beta", "archived": False},
                {"name": "old", "full_name": "acme/old", "archived": True},
            ],
            "repos/acme/alpha": {"default_branch": "main"},
            "repos/acme/beta": {"default_branch": "main"},
        })

    def test_enumerates_all_non_archived_repos(self):
        ctx = SCMContext.for_org("acme", self._fake())
        names = {snap.name for snap in ctx.repos}
        assert names == {"alpha", "beta"}  # archived "old" skipped
        assert ctx.files_scanned == 2

    def test_runs_per_repo_pack_across_org(self):
        ctx = SCMContext.for_org("acme", self._fake())
        findings = _org_findings(ctx)
        scm001 = [f for f in findings if f.check_id == "SCM-001"]
        # One SCM-001 finding per repo, both failing (no protection).
        resources = {f.resource for f in scm001 if not f.passed}
        assert resources == {"github:acme/alpha", "github:acme/beta"}

    def test_empty_org_degrades_with_warning(self):
        ctx = SCMContext.for_org("acme", FakeSCMFetcher({self._REPOS_PAGE: []}))
        assert ctx.repos == []
        assert ctx.files_skipped == 1
        assert any("enumerated no repositories" in w for w in ctx.warnings)

    def test_enumeration_unavailable_degrades(self):
        # Token lacks scope -> the repos endpoint returns None, not a list.
        ctx = SCMContext.for_org("acme", FakeSCMFetcher({}))
        assert ctx.repos == []
        assert ctx.warnings

    def test_paginates_past_first_full_page(self):
        page1 = [
            {"name": f"r{i}", "full_name": f"acme/r{i}", "archived": False}
            for i in range(100)
        ]
        mapping: dict[str, Any] = {
            "orgs/acme/repos?per_page=100&page=1&type=all": page1,
            "orgs/acme/repos?per_page=100&page=2&type=all": [
                {"name": "last", "full_name": "acme/last", "archived": False},
            ],
        }
        for i in range(100):
            mapping[f"repos/acme/r{i}"] = {"default_branch": "main"}
        mapping["repos/acme/last"] = {"default_branch": "main"}
        ctx = SCMContext.for_org("acme", FakeSCMFetcher(mapping))
        assert len(ctx.repos) == 101
        assert any(snap.name == "last" for snap in ctx.repos)

    def test_include_glob_filters_repos(self):
        ctx = SCMContext.for_org(
            "acme", self._fake(), include=("al*",),
        )
        assert {snap.name for snap in ctx.repos} == {"alpha"}

    def test_exclude_glob_filters_repos(self):
        ctx = SCMContext.for_org(
            "acme", self._fake(), exclude=("beta",),
        )
        assert {snap.name for snap in ctx.repos} == {"alpha"}

    def test_filters_to_empty_records_warning(self):
        ctx = SCMContext.for_org(
            "acme", self._fake(), include=("nomatch*",),
        )
        assert ctx.repos == []
        assert any("filtered out" in w for w in ctx.warnings)

    def test_max_repos_caps_and_warns(self):
        ctx = SCMContext.for_org("acme", self._fake(), max_repos=1)
        assert len(ctx.repos) == 1
        assert any("capping the fan-out" in w for w in ctx.warnings)

    def test_repo_order_is_deterministic_under_concurrency(self):
        # Snapshots build concurrently, but executor.map preserves the
        # enumeration order so the repos list is deterministic.
        for _ in range(3):
            ctx = SCMContext.for_org("acme", self._fake())
            assert [snap.name for snap in ctx.repos] == ["alpha", "beta"]
