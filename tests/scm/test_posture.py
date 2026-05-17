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
            code_scanning_default_setup={"state": "configured"},
            codeowners_path=".github/CODEOWNERS",
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
            "repos/o/r/rulesets": [
                {"id": 1, "name": "default-branch-protection",
                 "target": "branch", "enforcement": "active"},
            ],
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
        # Each new endpoint was hit exactly once.
        for path in (
            "repos/o/r/actions/permissions",
            "repos/o/r/actions/permissions/workflow",
            "repos/o/r/environments",
            "repos/o/r/keys",
            "repos/o/r/hooks",
            "repos/o/r/collaborators?affiliation=outside&per_page=100",
            "repos/o/r/rulesets",
        ):
            assert path in fetcher.calls

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
