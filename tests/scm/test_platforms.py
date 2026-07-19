"""GitLab + Bitbucket platform parity tests for the SCM provider.

The same SCM rule pack runs against three platforms. GitHub-specific
rules pass silently on the other platforms; the universal subset
(SCM-001 / -002 / -006 / -007 / -008 / -009 / -017) reads from
normalized slots populated by the platform-specific hydrator.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.scm._platforms import (
    bitbucket_context_for_org,
    bitbucket_context_for_repo,
    gitlab_context_for_org,
    gitlab_context_for_repo,
)
from pipeline_check.core.checks.scm.posture import SCMPostureChecks


class FakeFetcher:
    """In-memory fetcher: ``path -> body``."""

    def __init__(self, mapping: dict[str, Any]):
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


def _findings_by_id(ctx) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in SCMPostureChecks(ctx).run():
        out[f.check_id] = f
    return out


# ── GitLab ─────────────────────────────────────────────────────────


class TestGitLabHydration:
    def test_for_repo_populates_normalized_protection_slot(self):
        f = FakeFetcher({
            "projects/group%2Fproject": {
                "default_branch": "main",
                "approvals_before_merge": 2,
                "only_allow_merge_if_pipeline_succeeds": True,
                "visibility": "private",
                "statistics": {"repository_size": 4096},
            },
            "projects/group%2Fproject/protected_branches": [
                {
                    "name": "main",
                    "allow_force_push": False,
                },
            ],
            "projects/group%2Fproject/push_rule": {
                "reject_unsigned_commits": True,
            },
            "projects/group%2Fproject/repository/files/"
            ".gitlab%2FCODEOWNERS?ref=main": {
                "file_path": ".gitlab/CODEOWNERS",
            },
        })
        ctx = gitlab_context_for_repo("group/project", f)
        assert len(ctx.repos) == 1
        snap = ctx.repos[0]
        assert snap.platform == "gitlab"
        assert snap.owner == "group"
        assert snap.name == "project"
        assert snap.codeowners_path == ".gitlab/CODEOWNERS"
        proto = snap.default_branch_protection
        assert isinstance(proto, dict)
        assert proto["required_pull_request_reviews"][
            "required_approving_review_count"
        ] == 2
        assert proto["required_signatures"]["enabled"] is True
        assert proto["allow_force_pushes"]["enabled"] is False
        assert proto["required_status_checks"]["contexts"] == ["pipeline"]

    def test_unprotected_default_branch_fires_scm001(self):
        f = FakeFetcher({
            "projects/group%2Fproject": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/group%2Fproject/protected_branches": [],
        })
        ctx = gitlab_context_for_repo("group/project", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-001"].passed

    def test_protected_default_branch_passes_scm001(self):
        f = FakeFetcher({
            "projects/group%2Fproject": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
                "approvals_before_merge": 1,
            },
            "projects/group%2Fproject/protected_branches": [
                {"name": "main", "allow_force_push": False},
            ],
            "projects/group%2Fproject/push_rule": {},
        })
        ctx = gitlab_context_for_repo("group/project", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-001"].passed
        assert findings["SCM-002"].passed
        assert findings["SCM-007"].passed
        # GitHub-only rules skip with a clear note.
        assert findings["SCM-003"].passed
        assert "GitHub-specific" in findings["SCM-003"].description

    def test_resource_handle_uses_platform_prefix(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-001"].resource == "gitlab:g/p"

    def test_meta_fetch_failure_records_warning(self):
        f = FakeFetcher({})
        ctx = gitlab_context_for_repo("g/p", f)
        assert any("GitLab" in w for w in ctx.warnings)
        assert ctx.repos[0].repo_meta is None

    def test_universal_rules_all_fire_or_pass_correctly_on_gitlab(self):
        """End-to-end: every universal rule (SCM-001/002/006/007/008/
        009/017) emits the expected pass-state on a fully-protected
        GitLab snapshot. Catches regressions where a universal rule
        accidentally depends on a GitHub-only slot."""
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 4096},
                "approvals_before_merge": 2,
                "only_allow_merge_if_pipeline_succeeds": True,
            },
            "projects/g%2Fp/protected_branches": [
                {"name": "main", "allow_force_push": False},
            ],
            "projects/g%2Fp/push_rule": {
                "reject_unsigned_commits": True,
            },
            "projects/g%2Fp/repository/files/CODEOWNERS?ref=main": {
                "file_path": "CODEOWNERS",
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        for cid in (
            "SCM-001", "SCM-002", "SCM-006", "SCM-007",
            "SCM-008", "SCM-009", "SCM-017",
        ):
            assert findings[cid].passed, (
                f"{cid} should pass on fully-protected GitLab repo, "
                f"got {findings[cid].description}"
            )

    def test_scm006_fires_when_push_rules_unset_on_gitlab(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
                "approvals_before_merge": 1,
            },
            "projects/g%2Fp/protected_branches": [
                {"name": "main", "allow_force_push": False},
            ],
            "projects/g%2Fp/push_rule": {
                "reject_unsigned_commits": False,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-006"].passed

    def test_scm017_fires_when_no_codeowners_on_gitlab(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [
                {"name": "main", "allow_force_push": False},
            ],
            "projects/g%2Fp/push_rule": {},
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-017"].passed

    def test_gitlab_codeowners_prefers_gitlab_path_over_github_path(self):
        """When both ``.gitlab/CODEOWNERS`` and ``.github/CODEOWNERS``
        exist, the platform-preferred path wins."""
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/repository/files/.gitlab%2FCODEOWNERS"
            "?ref=main": {"file_path": ".gitlab/CODEOWNERS"},
            "projects/g%2Fp/repository/files/.github%2FCODEOWNERS"
            "?ref=main": {"file_path": ".github/CODEOWNERS"},
        })
        ctx = gitlab_context_for_repo("g/p", f)
        assert ctx.repos[0].codeowners_path == ".gitlab/CODEOWNERS"

    def test_nested_subgroup_path(self):
        """GitLab supports nested subgroups (``a/b/c/repo``). The
        rule pack treats everything before the last ``/`` as the
        owner."""
        f = FakeFetcher({
            "projects/a%2Fb%2Fc%2Frepo": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/a%2Fb%2Fc%2Frepo/protected_branches": [
                {"name": "main", "allow_force_push": False},
            ],
            "projects/a%2Fb%2Fc%2Frepo/push_rule": {},
        })
        ctx = gitlab_context_for_repo("a/b/c/repo", f)
        snap = ctx.repos[0]
        assert snap.owner == "a/b/c"
        assert snap.name == "repo"


# ── Bitbucket ──────────────────────────────────────────────────────


class TestBitbucketHydration:
    def test_for_repo_populates_normalized_protection_slot(self):
        f = FakeFetcher({
            "repositories/acme/widget": {
                "mainbranch": {"name": "main"},
                "size": 4096,
                "is_private": True,
            },
            "repositories/acme/widget/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main",
                        "value": 2,
                    },
                    {"kind": "force", "pattern": "main"},
                    {"kind": "delete", "pattern": "main"},
                    {
                        "kind": "require_passing_builds_to_merge",
                        "pattern": "main",
                    },
                ],
            },
            "repositories/acme/widget/src/main/CODEOWNERS"
            "?format=meta": {
                "path": "CODEOWNERS",
                "type": "commit_file",
            },
        })
        ctx = bitbucket_context_for_repo("acme", "widget", f)
        snap = ctx.repos[0]
        assert snap.platform == "bitbucket"
        assert snap.owner == "acme"
        assert snap.name == "widget"
        assert snap.codeowners_path == "CODEOWNERS"
        proto = snap.default_branch_protection
        assert isinstance(proto, dict)
        assert proto["required_pull_request_reviews"][
            "required_approving_review_count"
        ] == 2
        # ``force`` / ``delete`` restrictions present => those
        # actions are disallowed (the SCM-007 / SCM-009 happy path).
        assert proto["allow_force_pushes"]["enabled"] is False
        assert proto["allow_deletions"]["enabled"] is False
        assert proto["required_status_checks"]["contexts"] == ["pipeline"]

    def test_no_restrictions_fires_scm001(self):
        f = FakeFetcher({
            "repositories/acme/widget": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/acme/widget/branch-restrictions": {
                "values": [],
            },
        })
        ctx = bitbucket_context_for_repo("acme", "widget", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-001"].passed

    def test_force_restriction_absent_means_force_allowed(self):
        f = FakeFetcher({
            "repositories/acme/widget": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/acme/widget/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main",
                        "value": 1,
                    },
                ],
            },
        })
        ctx = bitbucket_context_for_repo("acme", "widget", f)
        findings = _findings_by_id(ctx)
        # SCM-007 fires when allow_force_pushes is True. With no
        # ``force`` restriction in the branch-restrictions list,
        # force push is allowed → rule fires.
        assert not findings["SCM-007"].passed

    def test_resource_handle_uses_platform_prefix(self):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/w/r/branch-restrictions": {"values": []},
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-001"].resource == "bitbucket:w/r"

    def test_meta_fetch_failure_records_warning(self):
        f = FakeFetcher({})
        ctx = bitbucket_context_for_repo("w", "r", f)
        assert any("Bitbucket" in s for s in ctx.warnings)
        assert ctx.repos[0].repo_meta is None

    def test_universal_rules_all_fire_or_pass_correctly_on_bitbucket(
        self,
    ):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 4096,
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main", "value": 2,
                    },
                    {"kind": "force", "pattern": "main"},
                    {"kind": "delete", "pattern": "main"},
                    {
                        "kind": "require_passing_builds_to_merge",
                        "pattern": "main",
                    },
                ],
            },
            "repositories/w/r/src/main/CODEOWNERS?format=meta": {
                "path": "CODEOWNERS",
                "type": "commit_file",
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        for cid in (
            "SCM-001", "SCM-002", "SCM-007",
            "SCM-008", "SCM-009", "SCM-017",
        ):
            assert findings[cid].passed, (
                f"{cid} should pass on fully-protected Bitbucket repo "
                f"({findings[cid].description})"
            )
        # SCM-006 always fires on Bitbucket — the platform has no
        # per-branch signed-commit enforcement. Document that.
        assert not findings["SCM-006"].passed

    def test_bitbucket_codeowners_prefers_bitbucket_path(self):
        """``.bitbucket/CODEOWNERS`` is the platform-preferred path
        and wins over the generic ``CODEOWNERS``."""
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/w/r/branch-restrictions": {"values": []},
            "repositories/w/r/src/main/.bitbucket/CODEOWNERS"
            "?format=meta": {
                "path": ".bitbucket/CODEOWNERS",
                "type": "commit_file",
            },
            "repositories/w/r/src/main/CODEOWNERS?format=meta": {
                "path": "CODEOWNERS",
                "type": "commit_file",
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        assert ctx.repos[0].codeowners_path == ".bitbucket/CODEOWNERS"

    def test_restrictions_on_non_default_branch_dont_apply(self):
        """A restriction whose pattern is ``develop`` doesn't protect
        ``main``; SCM-001 should still fire because no restriction
        covers the default branch."""
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "develop",
                        "value": 2,
                    },
                ],
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-001"].passed

    def test_wildcard_pattern_matches_default_branch(self):
        """A restriction with pattern ``*`` covers every branch
        including the default."""
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "*",
                        "value": 1,
                    },
                ],
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-001"].passed

    def test_github_only_rules_skip_with_note(self):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main",
                        "value": 1,
                    },
                    {"kind": "force", "pattern": "main"},
                    {"kind": "delete", "pattern": "main"},
                ],
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        for gh_only in (
            "SCM-003", "SCM-004", "SCM-005", "SCM-010",
            "SCM-011", "SCM-012", "SCM-013", "SCM-014",
            "SCM-015", "SCM-016", "SCM-018", "SCM-019",
        ):
            assert findings[gh_only].passed, (
                f"{gh_only} should skip on bitbucket"
            )
            assert "GitHub-specific" in findings[gh_only].description


# ── GitLab-specific rule pack (SCM-050..053) ───────────────────────


class TestGitLabSpecificRules:
    def test_scm050_passes_when_prevent_secrets_enabled(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/push_rule": {
                "prevent_secrets": True,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-050"].passed

    def test_scm050_fires_when_prevent_secrets_disabled(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/push_rule": {
                "prevent_secrets": False,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-050"].passed

    def test_scm050_passes_silently_on_ce(self):
        """GitLab CE returns 404 on /push_rule. The rule passes with
        an unavailability note rather than firing on absence."""
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            # push_rule key intentionally absent => FakeFetcher
            # returns None => looks like a 404 to the rule.
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-050"].passed
        assert "unavailable" in findings["SCM-050"].description.lower()

    def test_scm051_fires_when_committer_check_disabled(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/push_rule": {
                "commit_committer_check": False,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-051"].passed

    def test_scm052_fires_when_discussions_not_required(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
                "only_allow_merge_if_all_discussions_are_resolved": False,
            },
            "projects/g%2Fp/protected_branches": [],
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-052"].passed

    def test_scm052_passes_when_discussions_required(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
                "only_allow_merge_if_all_discussions_are_resolved": True,
            },
            "projects/g%2Fp/protected_branches": [],
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-052"].passed

    def test_scm053_fires_when_author_self_approval_allowed(self):
        # merge_requests_author_approval lives on the /approvals
        # endpoint, NOT the project payload (2026-07 audit, SCM-053).
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/approvals": {
                "merge_requests_author_approval": True,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-053"].passed

    def test_scm053_passes_when_author_self_approval_blocked(self):
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
            },
            "projects/g%2Fp/protected_branches": [],
            "projects/g%2Fp/approvals": {
                "merge_requests_author_approval": False,
            },
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-053"].passed

    def test_scm053_passes_when_approvals_endpoint_unavailable(self):
        # No /approvals response (token lacks scope, endpoint failed):
        # pass with an "unavailable" note rather than a silent false
        # negative. Crucially, a value on the project payload must NOT
        # be read as the setting.
        f = FakeFetcher({
            "projects/g%2Fp": {
                "default_branch": "main",
                "statistics": {"repository_size": 1024},
                "merge_requests_author_approval": True,
            },
            "projects/g%2Fp/protected_branches": [],
        })
        ctx = gitlab_context_for_repo("g/p", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-053"].passed
        assert "unavailable" in findings["SCM-053"].description.lower()

    def test_gitlab_only_rules_skip_with_note_on_github(self):
        """SCM-050..053 should pass with a skip note on GitHub
        snapshots, mirroring the GitHub-only routing pattern."""
        from pipeline_check.core.checks.scm.base import (
            SCMContext,
            SCMRepoSnapshot,
        )
        from pipeline_check.core.checks.scm.posture import SCMPostureChecks
        snap = SCMRepoSnapshot(owner="o", name="r", platform="github")
        ctx = SCMContext(repos=[snap])
        findings = {f.check_id: f for f in SCMPostureChecks(ctx).run()}
        for gl_only in ("SCM-050", "SCM-051", "SCM-052", "SCM-053"):
            assert findings[gl_only].passed
            assert "GitLab-specific" in findings[gl_only].description


# ── Bitbucket-specific rule pack (SCM-054..055) ────────────────────


class TestBitbucketSpecificRules:
    def test_scm054_fires_when_private_allows_public_forks(self):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": True,
                "fork_policy": "allow_forks",
            },
            "repositories/w/r/branch-restrictions": {"values": []},
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-054"].passed

    def test_scm054_passes_when_private_blocks_forks(self):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": True,
                "fork_policy": "no_forks",
            },
            "repositories/w/r/branch-restrictions": {"values": []},
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-054"].passed

    def test_scm054_passes_when_private_restricts_to_workspace(self):
        """``no_public_forks`` keeps forks inside the workspace's
        privacy boundary, which is the safe posture."""
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": True,
                "fork_policy": "no_public_forks",
            },
            "repositories/w/r/branch-restrictions": {"values": []},
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-054"].passed

    def test_scm054_passes_on_public_repo(self):
        """Public source repos can't be made *more* visible by
        forks, so fork_policy is not load-bearing for confidentiality.
        """
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": False,
                "fork_policy": "allow_forks",
            },
            "repositories/w/r/branch-restrictions": {"values": []},
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-054"].passed

    def test_scm055_fires_when_only_merge_side_restrictions(self):
        """A repo with require_approvals + require_passing_builds
        but no push/force/delete kind leaves direct pushes unguarded.
        """
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": True,
                "fork_policy": "no_forks",
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main",
                        "value": 2,
                    },
                    {
                        "kind": "require_passing_builds_to_merge",
                        "pattern": "main",
                    },
                ],
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert not findings["SCM-055"].passed

    def test_scm055_passes_when_force_kind_present(self):
        f = FakeFetcher({
            "repositories/w/r": {
                "mainbranch": {"name": "main"},
                "size": 1024,
                "is_private": True,
                "fork_policy": "no_forks",
            },
            "repositories/w/r/branch-restrictions": {
                "values": [
                    {
                        "kind": "require_approvals_to_merge",
                        "pattern": "main",
                        "value": 1,
                    },
                    {"kind": "force", "pattern": "main"},
                ],
            },
        })
        ctx = bitbucket_context_for_repo("w", "r", f)
        findings = _findings_by_id(ctx)
        assert findings["SCM-055"].passed

    def test_bitbucket_only_rules_skip_with_note_on_github(self):
        from pipeline_check.core.checks.scm.base import (
            SCMContext,
            SCMRepoSnapshot,
        )
        from pipeline_check.core.checks.scm.posture import SCMPostureChecks
        snap = SCMRepoSnapshot(owner="o", name="r", platform="github")
        ctx = SCMContext(repos=[snap])
        findings = {f.check_id: f for f in SCMPostureChecks(ctx).run()}
        for bb_only in ("SCM-054", "SCM-055"):
            assert findings[bb_only].passed
            assert "Bitbucket-specific" in findings[bb_only].description


# ── End-to-end provider routing ────────────────────────────────────


class TestSCMProviderPlatformRouting:
    def test_unknown_platform_raises_value_error(self):
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        provider = SCMProvider()
        with pytest.raises(ValueError, match="Supported: github"):
            provider.build_context(
                scm_platform="hg-cloud", scm_repo="o/r",
            )

    def test_github_route_returns_github_snapshot(self, tmp_path):
        """Fixture-mode GitHub flow still works after the platform
        routing was added."""
        from pipeline_check.core.providers.scm import SCMProvider
        # Empty fixture dir: every fetch returns None; the snapshot
        # still has platform="github".
        provider = SCMProvider()
        ctx = provider.build_context(
            scm_platform="github", scm_repo="o/r",
            scm_fixture_dir=str(tmp_path),
        )
        assert ctx.repos[0].platform == "github"

    def test_missing_platform_raises(self):
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        provider = SCMProvider()
        with pytest.raises(ValueError, match="--scm-platform"):
            provider.build_context(scm_repo="o/r")

    def test_missing_repo_raises(self):
        import pytest

        from pipeline_check.core.providers.scm import SCMProvider
        provider = SCMProvider()
        with pytest.raises(ValueError, match="--scm-repo"):
            provider.build_context(scm_platform="github")


# ── GitLab org fan-out ─────────────────────────────────────────────


_GL_PROJECTS = (
    "groups/acme/projects?per_page=100&page=1&include_subgroups=true"
)


def _gl_org_fetcher() -> FakeFetcher:
    # Two live projects + one archived (skipped). Per-project metadata is
    # omitted, so each degrades to a named gitlab snapshot.
    return FakeFetcher({
        _GL_PROJECTS: [
            {"path_with_namespace": "acme/alpha", "archived": False},
            {"path_with_namespace": "acme/beta", "archived": False},
            {"path_with_namespace": "acme/old", "archived": True},
        ],
    })


class TestGitLabOrgFanout:
    def test_enumerates_non_archived_projects(self):
        ctx = gitlab_context_for_org("acme", _gl_org_fetcher())
        assert {s.name for s in ctx.repos} == {"alpha", "beta"}
        assert all(s.platform == "gitlab" for s in ctx.repos)

    def test_include_glob_filters(self):
        ctx = gitlab_context_for_org(
            "acme", _gl_org_fetcher(), include=("al*",),
        )
        assert {s.name for s in ctx.repos} == {"alpha"}

    def test_max_repos_caps_and_warns(self):
        ctx = gitlab_context_for_org("acme", _gl_org_fetcher(), max_repos=1)
        assert len(ctx.repos) == 1
        assert any("capping the fan-out" in w for w in ctx.warnings)

    def test_empty_group_degrades_with_warning(self):
        ctx = gitlab_context_for_org("acme", FakeFetcher({_GL_PROJECTS: []}))
        assert ctx.repos == []
        assert any("no projects for GitLab group" in w for w in ctx.warnings)


# ── Bitbucket org fan-out ──────────────────────────────────────────


_BB_REPOS = "repositories/acme?pagelen=100"


def _bb_org_fetcher() -> FakeFetcher:
    return FakeFetcher({
        _BB_REPOS: {
            "values": [
                {"full_name": "acme/widget"},
                {"full_name": "acme/gadget"},
            ],
        },
    })


class TestBitbucketOrgFanout:
    def test_enumerates_workspace_repos(self):
        ctx = bitbucket_context_for_org("acme", _bb_org_fetcher())
        assert {s.name for s in ctx.repos} == {"widget", "gadget"}
        assert all(s.platform == "bitbucket" for s in ctx.repos)

    def test_exclude_glob_filters(self):
        ctx = bitbucket_context_for_org(
            "acme", _bb_org_fetcher(), exclude=("gadget",),
        )
        assert {s.name for s in ctx.repos} == {"widget"}

    def test_empty_workspace_degrades_with_warning(self):
        ctx = bitbucket_context_for_org(
            "acme", FakeFetcher({_BB_REPOS: {"values": []}}),
        )
        assert ctx.repos == []
        assert any(
            "no repositories for Bitbucket workspace" in w
            for w in ctx.warnings
        )

    def test_paginates_via_next_cursor(self):
        f = FakeFetcher({
            _BB_REPOS: {
                "values": [{"full_name": "acme/r1"}],
                "next": "https://api.bitbucket.org/2.0/repositories/acme"
                        "?pagelen=100&page=2",
            },
            "repositories/acme?pagelen=100&page=2": {
                "values": [{"full_name": "acme/r2"}],
            },
        })
        ctx = bitbucket_context_for_org("acme", f)
        assert {s.name for s in ctx.repos} == {"r1", "r2"}
