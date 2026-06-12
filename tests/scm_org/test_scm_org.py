"""ORG-* GitHub org-governance tests (in-memory fetcher, no network)."""
from __future__ import annotations

from typing import Any

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.scm_org.base import SCMOrgContext
from pipeline_check.core.checks.scm_org.checks import SCMOrgChecks

_ORG = "acme"
_ORG_PATH = f"orgs/{_ORG}"


class FakeFetcher:
    """In-memory ``path -> json`` map; anything else returns ``None``."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


def _ctx(org_meta: dict | None) -> SCMOrgContext:
    mapping = {_ORG_PATH: org_meta} if org_meta is not None else {}
    return SCMOrgContext.for_org(_ORG, FakeFetcher(mapping))


def _findings(ctx: SCMOrgContext) -> list:
    return SCMOrgChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


# ── Context load ──────────────────────────────────────────────────────────

class TestContextLoad:
    def test_fetches_org_endpoint(self):
        fetcher = FakeFetcher({_ORG_PATH: {"login": "acme"}})
        ctx = SCMOrgContext.for_org(_ORG, fetcher)
        assert ctx.org_meta == {"login": "acme"}
        assert ctx.files_scanned == 1
        assert _ORG_PATH in fetcher.calls

    def test_missing_org_degrades_with_warning(self):
        ctx = _ctx(None)
        assert ctx.org_meta is None
        assert ctx.files_skipped == 1
        assert any("could not fetch" in w for w in ctx.warnings)

    def test_non_dict_payload_degrades(self):
        # A GitHub error body for an org is a dict, but a stray list/str
        # must not crash the loader.
        ctx = SCMOrgContext.for_org(_ORG, FakeFetcher({_ORG_PATH: ["x"]}))
        assert ctx.org_meta is None
        assert ctx.warnings


# ── ORG-001: two-factor requirement ───────────────────────────────────────

class TestOrg001:
    def test_fires_when_2fa_not_required(self):
        ctx = _ctx({"two_factor_requirement_enabled": False})
        out = [f for f in _for(_findings(ctx), "ORG-001") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH
        assert "does not require two-factor" in out[0].description
        assert out[0].resource == "github:org/acme"

    def test_passes_when_2fa_required(self):
        ctx = _ctx({"two_factor_requirement_enabled": True})
        out = _for(_findings(ctx), "ORG-001")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_field_absent(self):
        # A low-scope token can't read the field; never fire on absence.
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-001")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description

    def test_passes_with_note_when_org_unavailable(self):
        ctx = _ctx(None)
        out = _for(_findings(ctx), "ORG-001")
        assert out and all(f.passed for f in out)


# ── ORG-002: default member repository permission ─────────────────────────

class TestOrg002:
    @pytest.mark.parametrize("perm", ["write", "admin"])
    def test_fires_on_broad_default_permission(self, perm):
        ctx = _ctx({"default_repository_permission": perm})
        out = [f for f in _for(_findings(ctx), "ORG-002") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH
        assert perm in out[0].description

    @pytest.mark.parametrize("perm", ["read", "none"])
    def test_passes_on_least_privilege_default(self, perm):
        ctx = _ctx({"default_repository_permission": perm})
        out = _for(_findings(ctx), "ORG-002")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-002")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description


# ── ORG-007: private-repository forking policy ────────────────────────────

class TestOrg007:
    def test_fires_when_forking_allowed(self):
        ctx = _ctx({"members_can_fork_private_repositories": True})
        out = [f for f in _for(_findings(ctx), "ORG-007") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.MEDIUM
        assert "forking of private" in out[0].description
        assert out[0].resource == "github:org/acme"

    def test_passes_when_forking_disallowed(self):
        ctx = _ctx({"members_can_fork_private_repositories": False})
        out = _for(_findings(ctx), "ORG-007")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-007")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description

    def test_passes_with_note_when_org_unavailable(self):
        ctx = _ctx(None)
        out = _for(_findings(ctx), "ORG-007")
        assert out and all(f.passed for f in out)


# ── ORG-008: member public-repository creation ────────────────────────────

class TestOrg008:
    def test_fires_when_members_can_create_public(self):
        ctx = _ctx({"members_can_create_public_repositories": True})
        out = [f for f in _for(_findings(ctx), "ORG-008") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.MEDIUM
        assert "create public" in out[0].description
        assert out[0].resource == "github:org/acme"

    def test_passes_when_public_creation_restricted(self):
        ctx = _ctx({"members_can_create_public_repositories": False})
        out = _for(_findings(ctx), "ORG-008")
        assert out and all(f.passed for f in out)

    def test_passes_when_repo_creation_disabled(self):
        # Public flag is moot when members can't create any repo.
        ctx = _ctx({
            "members_can_create_repositories": False,
            "members_can_create_public_repositories": True,
        })
        out = _for(_findings(ctx), "ORG-008")
        assert out and all(f.passed for f in out)
        assert "not let members create" in out[0].description

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-008")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description


# ── ORG-010: new-repo secret-scanning push-protection default ─────────────

class TestOrg010:
    def test_fires_when_scanning_on_but_push_protection_off(self):
        ctx = _ctx({
            "secret_scanning_enabled_for_new_repositories": True,
            "secret_scanning_push_protection_enabled_for_new_repositories": False,
        })
        out = [f for f in _for(_findings(ctx), "ORG-010") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.MEDIUM
        assert "push protection" in out[0].description
        assert out[0].resource == "github:org/acme"

    def test_passes_when_both_enabled(self):
        ctx = _ctx({
            "secret_scanning_enabled_for_new_repositories": True,
            "secret_scanning_push_protection_enabled_for_new_repositories": True,
        })
        out = _for(_findings(ctx), "ORG-010")
        assert out and all(f.passed for f in out)

    def test_passes_when_scanning_off(self):
        # Push-protection default is moot (and plan-dependent) when scanning
        # itself is off for new repos; don't false-positive on free plans.
        ctx = _ctx({
            "secret_scanning_enabled_for_new_repositories": False,
            "secret_scanning_push_protection_enabled_for_new_repositories": False,
        })
        out = _for(_findings(ctx), "ORG-010")
        assert out and all(f.passed for f in out)
        assert "does not enable secret scanning" in out[0].description

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-010")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description


# ── ORG-012: new-repo Dependabot security-updates default ─────────────────

class TestOrg012:
    def test_fires_when_alerts_on_but_updates_off(self):
        ctx = _ctx({
            "dependabot_alerts_enabled_for_new_repositories": True,
            "dependabot_security_updates_enabled_for_new_repositories": False,
        })
        out = [f for f in _for(_findings(ctx), "ORG-012") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.LOW
        assert "security updates" in out[0].description
        assert out[0].resource == "github:org/acme"

    def test_passes_when_both_enabled(self):
        ctx = _ctx({
            "dependabot_alerts_enabled_for_new_repositories": True,
            "dependabot_security_updates_enabled_for_new_repositories": True,
        })
        out = _for(_findings(ctx), "ORG-012")
        assert out and all(f.passed for f in out)

    def test_passes_when_alerts_off(self):
        ctx = _ctx({
            "dependabot_alerts_enabled_for_new_repositories": False,
            "dependabot_security_updates_enabled_for_new_repositories": False,
        })
        out = _for(_findings(ctx), "ORG-012")
        assert out and all(f.passed for f in out)
        assert "does not enable Dependabot alerts" in out[0].description

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx({"login": "acme"})
        out = _for(_findings(ctx), "ORG-012")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description


_PERMS_PATH = f"orgs/{_ORG}/actions/permissions"
_WORKFLOW_PATH = f"orgs/{_ORG}/actions/permissions/workflow"
_SECRETS_PATH = f"orgs/{_ORG}/actions/secrets"
_RUNNER_GROUPS_PATH = f"orgs/{_ORG}/actions/runner-groups"
_HOOKS_PATH = f"orgs/{_ORG}/hooks"
_RULESETS_PATH = f"orgs/{_ORG}/rulesets"


def _ctx_actions(
    permissions: dict | None = None,
    workflow: dict | None = None,
    secrets: dict | None = None,
    runner_groups: dict | None = None,
) -> SCMOrgContext:
    mapping: dict[str, Any] = {_ORG_PATH: {"login": _ORG}}
    if permissions is not None:
        mapping[_PERMS_PATH] = permissions
    if workflow is not None:
        mapping[_WORKFLOW_PATH] = workflow
    if secrets is not None:
        mapping[_SECRETS_PATH] = secrets
    if runner_groups is not None:
        mapping[_RUNNER_GROUPS_PATH] = runner_groups
    return SCMOrgContext.for_org(_ORG, FakeFetcher(mapping))


def _ctx_hooks(hooks: list | None) -> SCMOrgContext:
    mapping: dict[str, Any] = {_ORG_PATH: {"login": _ORG}}
    if hooks is not None:
        mapping[_HOOKS_PATH] = hooks
    return SCMOrgContext.for_org(_ORG, FakeFetcher(mapping))


def _ctx_rulesets(rulesets: list | None) -> SCMOrgContext:
    mapping: dict[str, Any] = {_ORG_PATH: {"login": _ORG}}
    if rulesets is not None:
        mapping[_RULESETS_PATH] = rulesets
    return SCMOrgContext.for_org(_ORG, FakeFetcher(mapping))


# ── ORG-003: Actions allow-list ───────────────────────────────────────────

class TestOrg003:
    def test_fires_when_any_action_allowed(self):
        ctx = _ctx_actions(
            {"enabled_repositories": "all", "allowed_actions": "all"},
        )
        out = [f for f in _for(_findings(ctx), "ORG-003") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH

    @pytest.mark.parametrize("allowed", ["selected", "local_only"])
    def test_passes_when_restricted(self, allowed):
        ctx = _ctx_actions(
            {"enabled_repositories": "all", "allowed_actions": allowed},
        )
        out = _for(_findings(ctx), "ORG-003")
        assert out and all(f.passed for f in out)

    def test_passes_when_actions_disabled(self):
        ctx = _ctx_actions(
            {"enabled_repositories": "none", "allowed_actions": "all"},
        )
        out = _for(_findings(ctx), "ORG-003")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_actions(permissions=None)
        out = _for(_findings(ctx), "ORG-003")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── ORG-004: default workflow token permissions ───────────────────────────

class TestOrg004:
    def test_fires_when_default_is_write(self):
        ctx = _ctx_actions(workflow={"default_workflow_permissions": "write"})
        out = [f for f in _for(_findings(ctx), "ORG-004") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH

    def test_passes_when_default_is_read(self):
        ctx = _ctx_actions(workflow={"default_workflow_permissions": "read"})
        out = _for(_findings(ctx), "ORG-004")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_actions(workflow=None)
        out = _for(_findings(ctx), "ORG-004")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── ORG-005: Actions can approve PRs ──────────────────────────────────────

class TestOrg005:
    def test_fires_when_actions_can_approve(self):
        ctx = _ctx_actions(
            workflow={"can_approve_pull_request_reviews": True},
        )
        out = [f for f in _for(_findings(ctx), "ORG-005") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH

    def test_passes_when_actions_cannot_approve(self):
        ctx = _ctx_actions(
            workflow={"can_approve_pull_request_reviews": False},
        )
        out = _for(_findings(ctx), "ORG-005")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_field_absent(self):
        ctx = _ctx_actions(workflow={"default_workflow_permissions": "read"})
        out = _for(_findings(ctx), "ORG-005")
        assert out and all(f.passed for f in out)
        assert "cannot read" in out[0].description


# ── ORG-006: org Actions secret scoped to all repos ───────────────────────

class TestOrg006:
    def test_fires_on_all_repo_secret(self):
        ctx = _ctx_actions(secrets={"total_count": 2, "secrets": [
            {"name": "NPM_TOKEN", "visibility": "all"},
            {"name": "SCOPED", "visibility": "selected"},
        ]})
        out = [f for f in _for(_findings(ctx), "ORG-006") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH
        assert "NPM_TOKEN" in out[0].description
        assert "SCOPED" not in out[0].description  # only all-repo ones named

    @pytest.mark.parametrize("vis", ["selected", "private"])
    def test_passes_when_secrets_scoped(self, vis):
        ctx = _ctx_actions(secrets={"secrets": [{"name": "X", "visibility": vis}]})
        out = _for(_findings(ctx), "ORG-006")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_actions(secrets=None)
        out = _for(_findings(ctx), "ORG-006")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── ORG-009: runner group available to public repos ───────────────────────

class TestOrg009:
    def test_fires_on_public_runner_group(self):
        ctx = _ctx_actions(runner_groups={"total_count": 2, "runner_groups": [
            {"name": "build", "allows_public_repositories": True},
            {"name": "private-only", "allows_public_repositories": False},
        ]})
        out = [f for f in _for(_findings(ctx), "ORG-009") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH
        assert "build" in out[0].description
        assert "private-only" not in out[0].description  # only public ones named

    def test_passes_when_no_public_group(self):
        ctx = _ctx_actions(runner_groups={"runner_groups": [
            {"name": "default", "allows_public_repositories": False},
        ]})
        out = _for(_findings(ctx), "ORG-009")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_actions(runner_groups=None)
        out = _for(_findings(ctx), "ORG-009")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── ORG-011: org webhook insecure transport ───────────────────────────────

class TestOrg011:
    def test_fires_on_http_url(self):
        ctx = _ctx_hooks([
            {"id": 1, "active": True, "config": {"url": "http://hook.example/gh"}},
            {"id": 2, "active": True, "config": {"url": "https://safe.example/gh"}},
        ])
        out = [f for f in _for(_findings(ctx), "ORG-011") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH
        assert "http://hook.example/gh" in out[0].description
        assert "safe.example" not in out[0].description  # only offenders named

    def test_fires_on_insecure_ssl(self):
        ctx = _ctx_hooks([
            {"id": 3, "active": True,
             "config": {"url": "https://hook.example/gh", "insecure_ssl": "1"}},
        ])
        out = [f for f in _for(_findings(ctx), "ORG-011") if not f.passed]
        assert len(out) == 1
        assert "TLS verification disabled" in out[0].description

    def test_skips_inactive_hook(self):
        ctx = _ctx_hooks([
            {"id": 4, "active": False, "config": {"url": "http://hook.example/gh"}},
        ])
        out = _for(_findings(ctx), "ORG-011")
        assert out and all(f.passed for f in out)

    def test_passes_when_all_secure(self):
        ctx = _ctx_hooks([
            {"id": 5, "active": True,
             "config": {"url": "https://hook.example/gh", "insecure_ssl": "0"}},
        ])
        out = _for(_findings(ctx), "ORG-011")
        assert out and all(f.passed for f in out)

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_hooks(None)
        out = _for(_findings(ctx), "ORG-011")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── ORG-013: org ruleset not enforced ─────────────────────────────────────

class TestOrg013:
    @pytest.mark.parametrize("mode", ["evaluate", "disabled"])
    def test_fires_on_non_active_ruleset(self, mode):
        ctx = _ctx_rulesets([
            {"id": 1, "name": "main-protection", "enforcement": mode},
            {"id": 2, "name": "active-one", "enforcement": "active"},
        ])
        out = [f for f in _for(_findings(ctx), "ORG-013") if not f.passed]
        assert len(out) == 1
        assert out[0].severity == Severity.MEDIUM
        assert "main-protection" in out[0].description
        assert mode in out[0].description
        assert "active-one" not in out[0].description  # only offenders named

    def test_passes_when_all_active(self):
        ctx = _ctx_rulesets([
            {"id": 3, "name": "p", "enforcement": "active"},
        ])
        out = _for(_findings(ctx), "ORG-013")
        assert out and all(f.passed for f in out)

    def test_passes_when_no_rulesets(self):
        ctx = _ctx_rulesets([])
        out = _for(_findings(ctx), "ORG-013")
        assert out and all(f.passed for f in out)
        assert "no org-level rulesets" in out[0].description

    def test_passes_with_note_when_unavailable(self):
        ctx = _ctx_rulesets(None)
        out = _for(_findings(ctx), "ORG-013")
        assert out and all(f.passed for f in out)
        assert "not available" in out[0].description


# ── Provider wiring ───────────────────────────────────────────────────────

class TestProvider:
    def test_requires_scm_org(self):
        from pipeline_check.core.providers.scm_org import SCMOrgProvider
        with pytest.raises(ValueError, match="requires --scm-org"):
            SCMOrgProvider().build_context(scm_org=None)

    def test_rejects_slash_in_org(self):
        from pipeline_check.core.providers.scm_org import SCMOrgProvider
        with pytest.raises(ValueError, match="bare"):
            SCMOrgProvider().build_context(scm_org="owner/repo")

    def test_registered_in_provider_registry(self):
        from pipeline_check.core import providers
        assert "scm_org" in providers.available()
        assert providers.get("scm_org").NAME == "scm_org"

    def test_owasp_mappings(self):
        from pipeline_check.core.standards.registry import resolve_for_check
        expected = {
            "ORG-001": "CICD-SEC-2", "ORG-002": "CICD-SEC-2",
            "ORG-003": "CICD-SEC-3", "ORG-004": "CICD-SEC-2",
            "ORG-005": "CICD-SEC-1", "ORG-006": "CICD-SEC-2",
            "ORG-007": "CICD-SEC-2", "ORG-008": "CICD-SEC-2",
            "ORG-009": "CICD-SEC-4", "ORG-010": "CICD-SEC-6",
            "ORG-011": "CICD-SEC-6", "ORG-012": "CICD-SEC-3",
            "ORG-013": "CICD-SEC-1",
        }
        for cid, ctrl in expected.items():
            controls = {c.control_id for c in resolve_for_check(cid)}
            assert ctrl in controls
