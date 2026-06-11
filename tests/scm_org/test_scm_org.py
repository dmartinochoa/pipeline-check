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
        for cid in ("ORG-001", "ORG-002"):
            controls = {c.control_id for c in resolve_for_check(cid)}
            assert "CICD-SEC-2" in controls
