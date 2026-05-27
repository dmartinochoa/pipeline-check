"""Tests for ENTRA-001, ENTRA-002, and ENTRA-003 rules."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    entra001_sp_admin_role as entra001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    entra002_app_long_credential as entra002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    entra003_sp_password_cred as entra003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _role_assignment(role_def_id: str, principal_id: str = "sp-1",
                     principal_type: str = "ServicePrincipal"):
    obj = MagicMock()
    obj.role_definition_id = role_def_id
    obj.principal_id = principal_id
    obj.principal_type = principal_type
    return obj


def _role_definition(role_name: str):
    obj = MagicMock()
    obj.role_name = role_name
    return obj


# -----------------------------------------------------------------------
# ENTRA-001  Service principal assigned Global Administrator
# -----------------------------------------------------------------------

class TestEntra001:
    def test_global_admin_sp_fails(self, make_catalog):
        assignment = _role_assignment("rd-1", principal_id="sp-bad")
        role_def = _role_definition("Global Administrator")
        catalog = make_catalog(**{
            "authorization:role_assignments": [assignment],
            "authorization:role_definitions": {"rd-1": role_def},
        })
        findings = entra001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ENTRA-001"
        assert "sp-bad" in findings[0].resource

    def test_company_administrator_alias_fails(self, make_catalog):
        assignment = _role_assignment("rd-2", principal_id="sp-legacy")
        role_def = _role_definition("Company Administrator")
        catalog = make_catalog(**{
            "authorization:role_assignments": [assignment],
            "authorization:role_definitions": {"rd-2": role_def},
        })
        findings = entra001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_non_admin_role_no_findings(self, make_catalog):
        assignment = _role_assignment("rd-3", principal_id="sp-ok")
        role_def = _role_definition("Reader")
        catalog = make_catalog(**{
            "authorization:role_assignments": [assignment],
            "authorization:role_definitions": {"rd-3": role_def},
        })
        findings = entra001.check(catalog)
        assert findings == []

    def test_user_principal_type_skipped(self, make_catalog):
        assignment = _role_assignment(
            "rd-4", principal_id="user-1", principal_type="User",
        )
        role_def = _role_definition("Global Administrator")
        catalog = make_catalog(**{
            "authorization:role_assignments": [assignment],
            "authorization:role_definitions": {"rd-4": role_def},
        })
        findings = entra001.check(catalog)
        assert findings == []

    def test_empty_assignments(self, make_catalog):
        catalog = make_catalog(**{
            "authorization:role_assignments": [],
            "authorization:role_definitions": {},
        })
        findings = entra001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# ENTRA-002  App registration credential valid beyond 180 days
# -----------------------------------------------------------------------

class TestEntra002:
    def test_long_lived_secret_fails(self, make_catalog):
        now = datetime.now(tz=UTC)
        app = {
            "displayName": "my-app",
            "appId": "app-1",
            "passwordCredentials": [{
                "startDateTime": now.isoformat(),
                "endDateTime": (now + timedelta(days=365)).isoformat(),
            }],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:applications": [app]})
        findings = entra002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ENTRA-002"

    def test_short_lived_secret_passes(self, make_catalog):
        now = datetime.now(tz=UTC)
        app = {
            "displayName": "good-app",
            "appId": "app-2",
            "passwordCredentials": [{
                "startDateTime": now.isoformat(),
                "endDateTime": (now + timedelta(days=90)).isoformat(),
            }],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:applications": [app]})
        findings = entra002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_exactly_180_days_passes(self, make_catalog):
        now = datetime.now(tz=UTC)
        app = {
            "displayName": "boundary-app",
            "appId": "app-3",
            "passwordCredentials": [{
                "startDateTime": now.isoformat(),
                "endDateTime": (now + timedelta(days=180)).isoformat(),
            }],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:applications": [app]})
        findings = entra002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_key_credential_also_checked(self, make_catalog):
        now = datetime.now(tz=UTC)
        app = {
            "displayName": "cert-app",
            "appId": "app-4",
            "passwordCredentials": [],
            "keyCredentials": [{
                "startDateTime": now.isoformat(),
                "endDateTime": (now + timedelta(days=400)).isoformat(),
            }],
        }
        catalog = make_catalog(**{"entra:applications": [app]})
        findings = entra002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_applications_empty(self, make_catalog):
        catalog = make_catalog(**{"entra:applications": []})
        findings = entra002.check(catalog)
        assert findings == []

    def test_z_suffix_iso_format(self, make_catalog):
        """Z suffix on ISO dates is handled correctly."""
        app = {
            "displayName": "z-app",
            "appId": "app-5",
            "passwordCredentials": [{
                "startDateTime": "2026-01-01T00:00:00Z",
                "endDateTime": "2026-12-31T00:00:00Z",
            }],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:applications": [app]})
        findings = entra002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False  # 364 days > 180


# -----------------------------------------------------------------------
# ENTRA-003  Service principal uses password credential
# -----------------------------------------------------------------------

class TestEntra003:
    def test_password_credential_fails(self, make_catalog):
        sp = {
            "displayName": "ci-sp",
            "id": "sp-1",
            "appId": "app-1",
            "passwordCredentials": [{"keyId": "k1"}],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:service_principals": [sp]})
        findings = entra003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ENTRA-003"

    def test_certificate_only_passes(self, make_catalog):
        sp = {
            "displayName": "cert-sp",
            "id": "sp-2",
            "appId": "app-2",
            "passwordCredentials": [],
            "keyCredentials": [{"keyId": "k2"}],
        }
        catalog = make_catalog(**{"entra:service_principals": [sp]})
        findings = entra003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_both_password_and_cert_fails(self, make_catalog):
        sp = {
            "displayName": "both-sp",
            "id": "sp-3",
            "appId": "app-3",
            "passwordCredentials": [{"keyId": "k3"}],
            "keyCredentials": [{"keyId": "k4"}],
        }
        catalog = make_catalog(**{"entra:service_principals": [sp]})
        findings = entra003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_credentials_skipped(self, make_catalog):
        sp = {
            "displayName": "no-cred-sp",
            "id": "sp-4",
            "appId": "app-4",
            "passwordCredentials": [],
            "keyCredentials": [],
        }
        catalog = make_catalog(**{"entra:service_principals": [sp]})
        findings = entra003.check(catalog)
        assert findings == []

    def test_empty_service_principals(self, make_catalog):
        catalog = make_catalog(**{"entra:service_principals": []})
        findings = entra003.check(catalog)
        assert findings == []
