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


_PERMS_PATH = f"orgs/{_ORG}/actions/permissions"
_WORKFLOW_PATH = f"orgs/{_ORG}/actions/permissions/workflow"
_SECRETS_PATH = f"orgs/{_ORG}/actions/secrets"


def _ctx_actions(
    permissions: dict | None = None,
    workflow: dict | None = None,
    secrets: dict | None = None,
) -> SCMOrgContext:
    mapping: dict[str, Any] = {_ORG_PATH: {"login": _ORG}}
    if permissions is not None:
        mapping[_PERMS_PATH] = permissions
    if workflow is not None:
        mapping[_WORKFLOW_PATH] = workflow
    if secrets is not None:
        mapping[_SECRETS_PATH] = secrets
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
        }
        for cid, ctrl in expected.items():
            controls = {c.control_id for c in resolve_for_check(cid)}
            assert ctrl in controls
