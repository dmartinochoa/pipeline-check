"""Tests for AKV-001, AKV-002, and AKV-003 rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    akv001_soft_delete as akv001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    akv002_purge_protection as akv002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    akv003_network_acl as akv003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _key_vault(
    name: str = "kv1",
    soft_delete: bool | None = True,
    purge_protection: bool | None = True,
    default_action: str = "Deny",
) -> MagicMock:
    vault = MagicMock()
    vault.name = name
    vault.properties.enable_soft_delete = soft_delete
    vault.properties.enable_purge_protection = purge_protection
    vault.properties.network_acls.default_action = default_action
    return vault


# -----------------------------------------------------------------------
# AKV-001  Key Vault soft delete not enabled
# -----------------------------------------------------------------------

class TestAkv001:
    def test_soft_delete_disabled_fails(self, make_catalog):
        vault = _key_vault(soft_delete=False)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-001"

    def test_soft_delete_enabled_passes(self, make_catalog):
        vault = _key_vault(soft_delete=True)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_soft_delete_none_defaults_to_true(self, make_catalog):
        """When enable_soft_delete is None, rule defaults to True (pass)."""
        vault = _key_vault(soft_delete=None)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-002  Key Vault purge protection not enabled
# -----------------------------------------------------------------------

class TestAkv002:
    def test_purge_protection_disabled_fails(self, make_catalog):
        vault = _key_vault(purge_protection=False)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-002"

    def test_purge_protection_enabled_passes(self, make_catalog):
        vault = _key_vault(purge_protection=True)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_purge_protection_none_fails(self, make_catalog):
        """When enable_purge_protection is None, bool(None) is False."""
        vault = _key_vault(purge_protection=None)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-003  Key Vault allows access from all networks
# -----------------------------------------------------------------------

class TestAkv003:
    def test_allow_default_action_fails(self, make_catalog):
        vault = _key_vault(default_action="Allow")
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-003"

    def test_deny_default_action_passes(self, make_catalog):
        vault = _key_vault(default_action="Deny")
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_network_acls_defaults_to_allow(self, make_catalog):
        """Vault with no network_acls attribute defaults to Allow (fail)."""
        vault = MagicMock()
        vault.name = "bare-kv"
        vault.properties.network_acls = None
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_properties_defaults_to_fail(self, make_catalog):
        """Vault with properties=None falls through to fail."""
        vault = MagicMock()
        vault.name = "no-props-kv"
        vault.properties = None
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv003.check(catalog)
        assert findings == []
