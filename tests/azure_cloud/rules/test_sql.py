"""Tests for AZSQL-001..005 SQL Server rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    azsql001_tde_cmk as azsql001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azsql002_auditing as azsql002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azsql003_public_access as azsql003,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azsql004_aad_admin as azsql004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azsql005_threat_detection as azsql005,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _sql_entry(
    name: str = "sqlsrv1",
    *,
    key_id: str | None = None,
    auditing_state: str = "Disabled",
    public_network_access: str = "Enabled",
    ad_admin: object | None = None,
    threat_state: str = "Disabled",
) -> dict:
    server = MagicMock()
    server.name = name
    server.key_id = key_id
    server.public_network_access = public_network_access

    auditing = MagicMock()
    auditing.state = auditing_state

    threat = MagicMock()
    threat.state = threat_state

    return {
        "server": server,
        "auditing": auditing,
        "threat_detection": threat,
        "ad_admin": ad_admin,
    }


# -----------------------------------------------------------------------
# AZSQL-001  SQL Server TDE does not use a customer-managed key
# -----------------------------------------------------------------------

class TestAzsql001:
    def test_service_managed_key_fails(self, make_catalog):
        entry = _sql_entry(key_id=None)
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZSQL-001"

    def test_cmk_passes(self, make_catalog):
        entry = _sql_entry(
            key_id="https://myvault.vault.azure.net/keys/mykey/abc123",
        )
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_non_vault_key_id_fails(self, make_catalog):
        entry = _sql_entry(key_id="ServiceManaged")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_servers(self, make_catalog):
        catalog = make_catalog(**{"sql:servers": []})
        findings = azsql001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZSQL-002  SQL Server auditing not enabled
# -----------------------------------------------------------------------

class TestAzsql002:
    def test_auditing_disabled_fails(self, make_catalog):
        entry = _sql_entry(auditing_state="Disabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZSQL-002"

    def test_auditing_enabled_passes(self, make_catalog):
        entry = _sql_entry(auditing_state="Enabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_auditing_object_fails(self, make_catalog):
        entry = _sql_entry()
        entry["auditing"] = None
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_servers(self, make_catalog):
        catalog = make_catalog(**{"sql:servers": []})
        findings = azsql002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZSQL-003  SQL Server allows public network access
# -----------------------------------------------------------------------

class TestAzsql003:
    def test_public_access_enabled_fails(self, make_catalog):
        entry = _sql_entry(public_network_access="Enabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZSQL-003"

    def test_public_access_disabled_passes(self, make_catalog):
        entry = _sql_entry(public_network_access="Disabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_servers(self, make_catalog):
        catalog = make_catalog(**{"sql:servers": []})
        findings = azsql003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZSQL-004  SQL Server has no Azure AD administrator configured
# -----------------------------------------------------------------------

class TestAzsql004:
    def test_no_ad_admin_fails(self, make_catalog):
        entry = _sql_entry(ad_admin=None)
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZSQL-004"

    def test_ad_admin_configured_passes(self, make_catalog):
        admin = MagicMock()
        admin.login = "admin@company.com"
        entry = _sql_entry(ad_admin=admin)
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_servers(self, make_catalog):
        catalog = make_catalog(**{"sql:servers": []})
        findings = azsql004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZSQL-005  SQL Server advanced threat protection not enabled
# -----------------------------------------------------------------------

class TestAzsql005:
    def test_threat_disabled_fails(self, make_catalog):
        entry = _sql_entry(threat_state="Disabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZSQL-005"

    def test_threat_enabled_passes(self, make_catalog):
        entry = _sql_entry(threat_state="Enabled")
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_threat_object_fails(self, make_catalog):
        entry = _sql_entry()
        entry["threat_detection"] = None
        catalog = make_catalog(**{"sql:servers": [entry]})
        findings = azsql005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_servers(self, make_catalog):
        catalog = make_catalog(**{"sql:servers": []})
        findings = azsql005.check(catalog)
        assert findings == []
